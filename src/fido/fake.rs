//! A software FIDO2 authenticator, for tests.
//!
//! [`FakeFido`] implements [`HidTransport`] but instead of replaying a fixed
//! script it parses the CTAP2 `getAssertion` request and produces a real
//! Ed25519 assertion over `authData || clientDataHash`. That lets the whole
//! agent path — CTAPHID framing, CBOR, signature assembly and verification —
//! run against a device that actually signs, with no hardware.

use super::ctaphid::{CTAPHID_CANCEL, CTAPHID_CBOR, CTAPHID_INIT, CTAPHID_KEEPALIVE};
use crate::protocol::Report;
use crate::transport::{HidTransport, TransportError};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use signature::Signer;
use ssh_key::private::Ed25519Keypair;
use std::collections::VecDeque;
use std::time::Duration;

/// The channel id a [`FakeFido`] allocates.
const FAKE_CID: u32 = 0x0A0B_0C0D;

/// A fake Ed25519 FIDO2 authenticator holding one credential.
pub struct FakeFido {
    pair: Ed25519Keypair,
    application: String,
    key_handle: Vec<u8>,
    flags: u8,
    counter: u32,
    require_touch: bool,
    cid: u32,
    out: VecDeque<Report>,
    incoming: Vec<u8>,
    /// The command and total length of a message still awaiting
    /// continuation packets.
    pending: Option<(u8, usize)>,
    /// Never reply to a getAssertion; see [`FakeFido::never_touched`].
    never_touched: bool,
    /// A request is outstanding and waiting for a touch that never comes.
    waiting: bool,
    cancelled: bool,
}

impl FakeFido {
    /// Build an authenticator whose credential lives in `application` under
    /// `key_handle` and whose signatures report `flags`.
    pub fn new(seed: &[u8; 32], application: &str, key_handle: &[u8], flags: u8) -> Self {
        FakeFido {
            pair: Ed25519Keypair::from_seed(seed),
            application: application.to_owned(),
            key_handle: key_handle.to_vec(),
            flags,
            counter: 1,
            require_touch: false,
            cid: FAKE_CID,
            out: VecDeque::new(),
            incoming: Vec::new(),
            pending: None,
            never_touched: false,
            waiting: false,
            cancelled: false,
        }
    }

    /// Make the authenticator wait for a touch that never comes: it answers
    /// every read with an `UPNEEDED` keepalive until it is cancelled.
    pub fn never_touched(mut self) -> Self {
        self.never_touched = true;
        self
    }

    /// Whether the host sent `CTAPHID_CANCEL`.
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// How many getAssertion requests the device received.
    pub fn requests(&self) -> u32 {
        self.counter - 1
    }

    /// Make the authenticator send a keepalive (as if waiting for a touch)
    /// before its reply.
    pub fn with_touch(mut self) -> Self {
        self.require_touch = true;
        self
    }

    /// The 32-byte Ed25519 public key of the credential.
    pub fn public(&self) -> [u8; 32] {
        self.pair.public.0
    }

    /// The credential's application string.
    pub fn application(&self) -> &str {
        &self.application
    }

    /// The credential's key handle.
    pub fn key_handle(&self) -> &[u8] {
        &self.key_handle
    }

    fn handle(&mut self, report: &Report) {
        let cid = u32::from_be_bytes(report[..4].try_into().expect("slice of four"));
        let cmd = report[4];
        // Bit 7 marks an initialization packet, as a real device checks.
        if cmd & 0x80 == 0 {
            let Some((cmd, total)) = self.pending else {
                return; // a stray continuation; a real device ignores it
            };
            let remaining = total - self.incoming.len();
            let chunk = remaining.min(59);
            self.incoming.extend_from_slice(&report[5..5 + chunk]);
            if self.incoming.len() == total {
                self.pending = None;
                let message = std::mem::take(&mut self.incoming);
                self.process(cmd, &message);
            }
            return;
        }
        match cmd {
            CTAPHID_INIT => self.reply_init(cid, &report[7..15]),
            CTAPHID_CANCEL => {
                self.cancelled = true;
                self.waiting = false;
                self.out.clear();
            }
            CTAPHID_CBOR => {
                let bcnt = ((report[5] as usize) << 8) | report[6] as usize;
                self.incoming.clear();
                let head = bcnt.min(57);
                self.incoming.extend_from_slice(&report[7..7 + head]);
                if bcnt <= 57 {
                    let message = std::mem::take(&mut self.incoming);
                    self.process(cmd, &message);
                } else {
                    self.pending = Some((cmd, bcnt));
                }
            }
            _ => self.push_message(self.cid, super::ctaphid::CTAPHID_ERROR, &[0x01]),
        }
    }

    fn reply_init(&mut self, request_cid: u32, nonce: &[u8]) {
        self.cid = FAKE_CID;
        let mut payload = Vec::new();
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&FAKE_CID.to_be_bytes());
        payload.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x01]);
        self.push_message(request_cid, CTAPHID_INIT, &payload);
    }

    fn process(&mut self, cmd: u8, message: &[u8]) {
        let (rp_id, client_data_hash) = match parse_request(message) {
            Some(parts) => parts,
            None => {
                self.push_message(self.cid, cmd, &[0x12]); // CTAP2_ERR_INVALID_CBOR
                return;
            }
        };
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let signature: ssh_key::Signature = self.pair.try_sign(&signed).expect("ed25519 signs");
        self.counter += 1;

        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        e.map(2)
            .and_then(|e| e.u8(2))
            .and_then(|e| e.bytes(&auth_data))
            .and_then(|e| e.u8(3))
            .and_then(|e| e.bytes(signature.as_bytes()))
            .expect("vec write");

        let mut reply = vec![0x00]; // CTAP1_ERR_SUCCESS
        reply.extend_from_slice(&cbor);
        if self.require_touch {
            self.push_message(self.cid, CTAPHID_KEEPALIVE, &[0x02]);
        }
        if self.never_touched {
            self.waiting = true;
        } else {
            self.push_message(self.cid, CTAPHID_CBOR, &reply);
        }
    }

    fn push_message(&mut self, cid: u32, cmd: u8, payload: &[u8]) {
        let mut first = [0u8; 64];
        first[..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = cmd;
        first[5] = (payload.len() >> 8) as u8;
        first[6] = payload.len() as u8;
        let head = payload.len().min(57);
        first[7..7 + head].copy_from_slice(&payload[..head]);
        self.out.push_back(first);

        let mut offset = head;
        let mut seq = 0u8;
        while offset < payload.len() {
            let mut packet = [0u8; 64];
            packet[..4].copy_from_slice(&cid.to_be_bytes());
            packet[4] = seq;
            let n = (payload.len() - offset).min(59);
            packet[5..5 + n].copy_from_slice(&payload[offset..offset + n]);
            self.out.push_back(packet);
            offset += n;
            seq = seq.wrapping_add(1);
        }
    }
}

/// Pull `rpId` (key 1) and `clientDataHash` (key 2) out of a getAssertion
/// request.
fn parse_request(message: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut d = Decoder::new(message);
    let pairs = d.map().ok()??;
    let mut rp_id = None;
    let mut client_data_hash = None;
    for _ in 0..pairs {
        match d.u8().ok()? {
            1 => rp_id = Some(d.str().ok()?.to_owned()),
            2 => client_data_hash = Some(d.bytes().ok()?.to_vec()),
            _ => d.skip().ok()?,
        }
    }
    Some((rp_id?, client_data_hash?))
}

impl HidTransport for FakeFido {
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        self.handle(report);
        Ok(())
    }

    fn read_report(&mut self, _timeout: Duration) -> Result<Option<Report>, TransportError> {
        if let Some(report) = self.out.pop_front() {
            return Ok(Some(report));
        }
        // A device left waiting for a touch keeps sending keepalives.
        if self.waiting {
            self.push_message(self.cid, CTAPHID_KEEPALIVE, &[0x02]);
            return Ok(self.out.pop_front());
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido::ctap::{Assertion, get_assertion};
    use crate::fido::ctaphid::CtapHid;

    #[test]
    fn fake_signs_a_valid_assertion() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01);
        let public = device.public();
        let mut hid = CtapHid::new(device);
        let hash: [u8; 32] = Sha256::digest(b"hello").into();
        let assertion: Assertion =
            get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {}).unwrap();
        assert_eq!(assertion.flags, 0x01);
        assert_eq!(assertion.counter, 1);
        assert_eq!(assertion.signature.len(), 64);

        // The assertion verifies against the credential's public key.
        use ed25519_dalek::Verifier;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        let mut signed = assertion.auth_data.clone();
        signed.extend_from_slice(&hash);
        let sig = ed25519_dalek::Signature::from_slice(&assertion.signature).unwrap();
        key.verify(&signed, &sig).unwrap();
    }

    /// A key that is never touched is asked once, cancelled when the touch
    /// timeout runs out, and never sent the request a second time.
    #[test]
    fn an_untouched_key_is_cancelled_not_asked_again() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01).never_touched();
        let mut hid = CtapHid::new(device).with_touch_timeout(Duration::from_millis(50));
        let hash: [u8; 32] = Sha256::digest(b"hello").into();
        let prompts = std::cell::Cell::new(0);
        let result = get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {
            prompts.set(prompts.get() + 1)
        });
        assert!(
            matches!(result, Err(crate::fido::FidoError::Timeout)),
            "{result:?}"
        );
        assert_eq!(prompts.get(), 1);
        let device = hid.into_transport();
        assert!(device.cancelled());
        assert_eq!(device.requests(), 1);
    }
}
