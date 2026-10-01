//! The CTAP2 `authenticatorGetAssertion` command (0x02).
//!
//! The assertion signature covers `authenticatorData || clientDataHash`, and
//! `authenticatorData` is `SHA256(rpId) || flags || signCount || extensions`.
//! That is exactly the blob OpenSSH's `sk-` key types sign, once the SSH
//! agent passes `clientDataHash = SHA256(message)` and `rpId = application`.

use super::FidoError;
use super::ctap_status;
use super::ctaphid::{CTAPHID_CBOR, CtapHid};
use super::pin::PinProtocol;
use crate::transport::HidTransport;
use minicbor::{Decoder, Encoder};

/// The CTAP2 command byte of `authenticatorGetAssertion`, which precedes the
/// CBOR parameters in a `CTAPHID_CBOR` message.
pub const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;

/// A successful `getAssertion` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// `authenticatorData`: `SHA256(rpId) || flags || signCount || ...`.
    pub auth_data: Vec<u8>,
    /// The signature bytes: DER ECDSA, or 64 raw bytes for Ed25519.
    pub signature: Vec<u8>,
    /// `authenticatorData` flags.
    pub flags: u8,
    /// The signature counter from `authenticatorData`.
    pub counter: u32,
}

/// A PIN token from [`super::pin::pin_token`] authorising a getAssertion,
/// with the protocol it was obtained under.
#[derive(Debug, Clone, Copy)]
pub struct PinAuth<'a> {
    pub protocol: PinProtocol,
    pub token: &'a [u8],
}

/// Ask the authenticator to sign `client_data_hash` with `key_handle`.
///
/// `up` sets the `up` option, so a key enrolled with user presence required
/// waits for a touch. `on_presence` is called once when the device asks.
pub fn get_assertion<T: HidTransport>(
    hid: &mut CtapHid<T>,
    rp_id: &str,
    client_data_hash: &[u8; 32],
    key_handle: &[u8],
    up: bool,
    on_presence: &dyn Fn(),
) -> Result<Assertion, FidoError> {
    get_assertion_with_pin(
        hid,
        rp_id,
        client_data_hash,
        key_handle,
        up,
        None,
        on_presence,
    )
}

/// [`get_assertion`], authorised by a PIN token when `pin` is given, as a
/// credential enrolled with user verification required needs.
pub fn get_assertion_with_pin<T: HidTransport>(
    hid: &mut CtapHid<T>,
    rp_id: &str,
    client_data_hash: &[u8; 32],
    key_handle: &[u8],
    up: bool,
    pin: Option<PinAuth>,
    on_presence: &dyn Fn(),
) -> Result<Assertion, FidoError> {
    let request = encode_request_with_pin(rp_id, client_data_hash, key_handle, up, pin)?;
    let reply = hid.transact(CTAPHID_CBOR, &request, on_presence)?;
    let (&status, cbor) = reply
        .split_first()
        .ok_or(FidoError::Protocol("empty CTAP reply"))?;
    if let Some(error) = ctap_status(status) {
        return Err(error);
    }
    parse_assertion(cbor)
}

#[cfg(test)]
fn encode_request(
    rp_id: &str,
    client_data_hash: &[u8; 32],
    key_handle: &[u8],
    up: bool,
) -> Result<Vec<u8>, FidoError> {
    encode_request_with_pin(rp_id, client_data_hash, key_handle, up, None)
}

/// The request: `rpId` (1), `clientDataHash` (2), `allowList` (3), options
/// (5) and, with a PIN token, `pinUvAuthParam` (6) and `pinUvAuthProtocol`
/// (7), in CTAP2 canonical key order.
fn encode_request_with_pin(
    rp_id: &str,
    client_data_hash: &[u8; 32],
    key_handle: &[u8],
    up: bool,
    pin: Option<PinAuth>,
) -> Result<Vec<u8>, FidoError> {
    let mut buffer = vec![AUTHENTICATOR_GET_ASSERTION];
    let mut e = Encoder::new(&mut buffer);
    e.map(if pin.is_some() { 6 } else { 4 })
        .and_then(|e| e.u8(1))
        .and_then(|e| e.str(rp_id))
        .and_then(|e| e.u8(2))
        .and_then(|e| e.bytes(client_data_hash))
        .and_then(|e| e.u8(3))
        .and_then(|e| e.array(1))
        // A PublicKeyCredentialDescriptor has text keys, in CTAP2 canonical
        // order (shorter first): "id", then "type".
        .and_then(|e| e.map(2))
        .and_then(|e| e.str("id"))
        .and_then(|e| e.bytes(key_handle))
        .and_then(|e| e.str("type"))
        .and_then(|e| e.str("public-key"))
        .and_then(|e| e.u8(5))
        .and_then(|e| e.map(1))
        .and_then(|e| e.str("up"))
        .and_then(|e| e.bool(up))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    if let Some(pin) = pin {
        let param = pin.protocol.authenticate(pin.token, client_data_hash);
        e.u8(6)
            .and_then(|e| e.bytes(&param))
            .and_then(|e| e.u8(7))
            .and_then(|e| e.u8(pin.protocol.number()))
            .map_err(|e| FidoError::Cbor(e.to_string()))?;
    }
    Ok(buffer)
}

fn parse_assertion(cbor: &[u8]) -> Result<Assertion, FidoError> {
    let mut d = Decoder::new(cbor);
    let pairs = d
        .map()
        .map_err(cbor_error)?
        .ok_or(FidoError::Protocol("indefinite CTAP reply"))?;
    let mut auth_data = None;
    let mut signature = None;
    for _ in 0..pairs {
        let key = d.u8().map_err(cbor_error)?;
        match key {
            2 => auth_data = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            3 => signature = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    let auth_data = auth_data.ok_or(FidoError::Protocol("assertion without authData"))?;
    let signature = signature.ok_or(FidoError::Protocol("assertion without signature"))?;
    if auth_data.len() < 37 {
        return Err(FidoError::Protocol("short authenticator data"));
    }
    let flags = auth_data[32];
    let counter = u32::from_be_bytes(auth_data[33..37].try_into().expect("slice of four"));
    Ok(Assertion {
        auth_data,
        signature,
        flags,
        counter,
    })
}

fn cbor_error(e: minicbor::decode::Error) -> FidoError {
    FidoError::Cbor(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido::ctaphid::CTAPHID_INIT;
    use crate::fido::fake::FakeFido;
    use crate::protocol::Report;
    use crate::transport::TransportError;
    use minicbor::Decoder;
    use sha2::{Digest, Sha256};
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::time::Duration;

    /// `SHA256(rpId) || flags || signCount || extra`, with a dummy hash.
    fn auth_data(flags: u8, counter: u32, extra: &[u8]) -> Vec<u8> {
        let mut out = vec![0x11u8; 32];
        out.push(flags);
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(extra);
        out
    }

    /// One entry of a getAssertion reply map.
    enum Entry<'a> {
        Bytes(u8, &'a [u8]),
        /// A key whose value the parser should skip: a nested map.
        Skipped(u8),
    }

    /// Encode a getAssertion reply map from `entries`, in order.
    fn reply(entries: &[Entry]) -> Vec<u8> {
        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        e.map(entries.len() as u64).unwrap();
        for entry in entries {
            match entry {
                Entry::Bytes(key, value) => e.u8(*key).unwrap().bytes(value).unwrap(),
                Entry::Skipped(key) => e
                    .u8(*key)
                    .unwrap()
                    .map(1)
                    .unwrap()
                    .str("id")
                    .unwrap()
                    .bytes(&[9u8; 4])
                    .unwrap(),
            };
        }
        cbor
    }

    #[test]
    fn request_has_the_expected_shape() {
        let request = encode_request("ssh:", &[0xAB; 32], &[0x01, 0x02], true).unwrap();
        let (&command, params) = request.split_first().unwrap();
        assert_eq!(command, AUTHENTICATOR_GET_ASSERTION);
        let mut d = Decoder::new(params);
        assert_eq!(d.map().unwrap(), Some(4));
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "ssh:");
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.bytes().unwrap(), &[0xAB; 32]);
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.array().unwrap(), Some(1));
        assert_eq!(d.map().unwrap(), Some(2));
        assert_eq!(d.str().unwrap(), "id");
        assert_eq!(d.bytes().unwrap(), &[0x01, 0x02]);
        assert_eq!(d.str().unwrap(), "type");
        assert_eq!(d.str().unwrap(), "public-key");
        assert_eq!(d.u8().unwrap(), 5);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.str().unwrap(), "up");
        assert!(d.bool().unwrap());
    }

    /// The request byte for byte: command, CTAP2 canonical key order and
    /// definite lengths throughout.
    #[test]
    fn request_matches_canonical_bytes() {
        let request = encode_request("ssh:", &[0xAB; 32], &[0x01, 0x02], true).unwrap();
        let expected = [
            "02",                     // authenticatorGetAssertion
            "a4",                     // map(4)
            "01",                     // 1: rpId
            "647373683a",             // "ssh:"
            "02",                     // 2: clientDataHash
            "5820",                   // bytes(32)
            &"ab".repeat(32),         //
            "03",                     // 3: allowList
            "81",                     // array(1)
            "a2",                     // map(2)
            "626964",                 // "id"
            "420102",                 // h'0102'
            "6474797065",             // "type"
            "6a7075626c69632d6b6579", // "public-key"
            "05",                     // 5: options
            "a1",                     // map(1)
            "627570",                 // "up"
            "f5",                     // true
        ]
        .concat();
        assert_eq!(hex::encode(&request), expected);
    }

    /// With a PIN token, `pinUvAuthParam` (6) and `pinUvAuthProtocol` (7)
    /// follow the options. The HMACs were computed with Python's `hmac`.
    #[test]
    fn request_with_pin_appends_auth_param_and_protocol() {
        let plain = encode_request("ssh:", &[0xAB; 32], &[0x01, 0x02], true).unwrap();
        let v1 = PinAuth {
            protocol: PinProtocol::V1,
            token: &[0x44; 16],
        };
        let request =
            encode_request_with_pin("ssh:", &[0xAB; 32], &[0x01, 0x02], true, Some(v1)).unwrap();
        let tail = [
            "06",                               // 6: pinUvAuthParam
            "50",                               // bytes(16)
            "a141371d466c448a797ed904ee2bed1f", // LEFT(HMAC(token, hash), 16)
            "07",                               // 7: pinUvAuthProtocol
            "01",                               // 1
        ]
        .concat();
        // Same request but for map(6) and the two entries at the end.
        assert_eq!(request[1], 0xa6);
        assert_eq!(request[2..plain.len()], plain[2..]);
        assert_eq!(hex::encode(&request[plain.len()..]), tail);

        let v2 = PinAuth {
            protocol: PinProtocol::V2,
            token: &[0x44; 32],
        };
        let request =
            encode_request_with_pin("ssh:", &[0xAB; 32], &[0x01, 0x02], true, Some(v2)).unwrap();
        let tail = [
            "06",
            "5820", // bytes(32)
            "cab2b06cb2b912ce02d7fbb852e77c73b660d27a2329dced213ad32e11de0a6f",
            "07",
            "02",
        ]
        .concat();
        assert_eq!(hex::encode(&request[plain.len()..]), tail);
    }

    #[test]
    fn request_without_up_sets_it_false() {
        let with = encode_request("ssh:", &[0xAB; 32], &[0x01, 0x02], true).unwrap();
        let without = encode_request("ssh:", &[0xAB; 32], &[0x01, 0x02], false).unwrap();
        assert_eq!(without.last(), Some(&0xf4));
        assert_eq!(with[..with.len() - 1], without[..without.len() - 1]);
    }

    /// Real key handles are long enough to need a two-byte length.
    #[test]
    fn request_carries_a_long_key_handle() {
        let handle: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let request = encode_request("ssh:", &[0xAB; 32], &handle, true).unwrap();
        let mut d = Decoder::new(&request[1..]);
        d.map().unwrap();
        d.u8().unwrap();
        d.str().unwrap();
        d.u8().unwrap();
        d.bytes().unwrap();
        d.u8().unwrap();
        d.array().unwrap();
        d.map().unwrap();
        d.str().unwrap(); // "id"
        let at = 1 + d.position(); // past the command byte
        assert_eq!(request[at..at + 2], [0x58, 0x80]);
        assert_eq!(d.bytes().unwrap(), handle.as_slice());
    }

    #[test]
    fn parses_a_reply_and_extracts_flags_and_counter() {
        let auth = auth_data(0x05, 7, &[]);
        let assertion = parse_assertion(&reply(&[
            Entry::Bytes(2, &auth),
            Entry::Bytes(3, &[0xDE; 64]),
        ]))
        .unwrap();
        assert_eq!(assertion.flags, 0x05);
        assert_eq!(assertion.counter, 7);
        assert_eq!(assertion.auth_data, auth);
        assert_eq!(assertion.signature, vec![0xDE; 64]);
    }

    #[test]
    fn the_counter_is_big_endian() {
        let auth = auth_data(0x01, 0x0102_0304, &[]);
        let assertion =
            parse_assertion(&reply(&[Entry::Bytes(2, &auth), Entry::Bytes(3, &[1])])).unwrap();
        assert_eq!(assertion.counter, 0x0102_0304);
    }

    /// Extension data after the counter is kept as part of what was signed.
    #[test]
    fn keeps_authenticator_data_extensions() {
        let auth = auth_data(0x81, 3, &[0xA0]);
        let assertion =
            parse_assertion(&reply(&[Entry::Bytes(2, &auth), Entry::Bytes(3, &[1])])).unwrap();
        assert_eq!(assertion.flags, 0x81);
        assert_eq!(assertion.counter, 3);
        assert_eq!(assertion.auth_data, auth);
    }

    /// The credential (1), user (4) and numberOfCredentials (5) entries are
    /// skipped wherever they appear.
    #[test]
    fn skips_other_reply_entries() {
        let auth = auth_data(0x01, 7, &[]);
        let assertion = parse_assertion(&reply(&[
            Entry::Skipped(1),
            Entry::Bytes(2, &auth),
            Entry::Skipped(4),
            Entry::Bytes(3, &[0xDE; 64]),
            Entry::Skipped(5),
        ]))
        .unwrap();
        assert_eq!(assertion.counter, 7);
        assert_eq!(assertion.signature, vec![0xDE; 64]);
    }

    #[test]
    fn rejects_a_reply_missing_a_field() {
        let auth = auth_data(0x01, 7, &[]);
        let no_auth = parse_assertion(&reply(&[Entry::Bytes(3, &[1])]));
        assert!(
            matches!(
                no_auth,
                Err(FidoError::Protocol("assertion without authData"))
            ),
            "{no_auth:?}"
        );
        let no_sig = parse_assertion(&reply(&[Entry::Bytes(2, &auth)]));
        assert!(
            matches!(
                no_sig,
                Err(FidoError::Protocol("assertion without signature"))
            ),
            "{no_sig:?}"
        );
    }

    #[test]
    fn rejects_short_authenticator_data() {
        let mut auth = auth_data(0x01, 7, &[]);
        auth.pop();
        let result = parse_assertion(&reply(&[Entry::Bytes(2, &auth), Entry::Bytes(3, &[1])]));
        assert!(
            matches!(result, Err(FidoError::Protocol("short authenticator data"))),
            "{result:?}"
        );
    }

    #[test]
    fn rejects_an_indefinite_map() {
        let result = parse_assertion(&[0xbf, 0xff]);
        assert!(
            matches!(result, Err(FidoError::Protocol("indefinite CTAP reply"))),
            "{result:?}"
        );
    }

    #[test]
    fn rejects_malformed_cbor() {
        let valid = reply(&[
            Entry::Bytes(2, &auth_data(0x01, 7, &[])),
            Entry::Bytes(3, &[1]),
        ]);
        let cases: [(&str, &[u8]); 4] = [
            ("empty", &[]),
            ("not a map", &[0x80]),
            ("truncated", &valid[..valid.len() - 1]),
            ("text key", &[0xa1, 0x61, b'x', 0x00]),
        ];
        for (name, cbor) in cases {
            let result = parse_assertion(cbor);
            assert!(
                matches!(result, Err(FidoError::Cbor(_))),
                "{name}: {result:?}"
            );
        }
    }

    /// The channel id a [`Canned`] device allocates.
    const CANNED_CID: u32 = 0x0102_0304;

    /// A device that allocates a channel, records the CTAP request it is
    /// sent, and answers it with a fixed CTAP reply.
    struct Canned {
        reply: Vec<u8>,
        request: Vec<u8>,
        expected: usize,
        out: VecDeque<Report>,
    }

    impl Canned {
        fn new(reply: &[u8]) -> Self {
            Canned {
                reply: reply.to_vec(),
                request: Vec::new(),
                expected: 0,
                out: VecDeque::new(),
            }
        }

        fn push(&mut self, cid: u32, cmd: u8, payload: &[u8]) {
            let mut first = [0u8; 64];
            first[..4].copy_from_slice(&cid.to_be_bytes());
            first[4] = cmd;
            first[5] = (payload.len() >> 8) as u8;
            first[6] = payload.len() as u8;
            let head = payload.len().min(57);
            first[7..7 + head].copy_from_slice(&payload[..head]);
            self.out.push_back(first);
            for (seq, chunk) in payload[head..].chunks(59).enumerate() {
                let mut packet = [0u8; 64];
                packet[..4].copy_from_slice(&cid.to_be_bytes());
                packet[4] = seq as u8;
                packet[5..5 + chunk.len()].copy_from_slice(chunk);
                self.out.push_back(packet);
            }
        }
    }

    impl HidTransport for Canned {
        fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            match report[4] {
                CTAPHID_INIT => {
                    let mut payload = report[7..15].to_vec(); // the nonce
                    payload.extend_from_slice(&CANNED_CID.to_be_bytes());
                    payload.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x04]);
                    self.push(cid, CTAPHID_INIT, &payload);
                }
                CTAPHID_CBOR => {
                    self.expected = ((report[5] as usize) << 8) | report[6] as usize;
                    let head = self.expected.min(57);
                    self.request = report[7..7 + head].to_vec();
                }
                _ => {
                    let remaining = self.expected - self.request.len();
                    self.request
                        .extend_from_slice(&report[5..5 + remaining.min(59)]);
                }
            }
            if report[4] != CTAPHID_INIT && self.request.len() == self.expected {
                let reply = self.reply.clone();
                self.push(CANNED_CID, CTAPHID_CBOR, &reply);
            }
            Ok(())
        }

        fn read_report(&mut self, _timeout: Duration) -> Result<Option<Report>, TransportError> {
            Ok(self.out.pop_front())
        }
    }

    fn assert_with_reply(reply: &[u8]) -> (Result<Assertion, FidoError>, Vec<u8>) {
        let mut hid = CtapHid::new(Canned::new(reply));
        let result = get_assertion(&mut hid, "ssh:", &[0xAB; 32], &[7u8; 64], true, &|| {});
        (result, hid.into_transport().request)
    }

    /// `get_assertion` sends exactly the encoded request, over several
    /// packets, and parses a successful reply.
    #[test]
    fn get_assertion_sends_the_request_and_parses_the_reply() {
        let auth = auth_data(0x01, 9, &[]);
        let mut ok = vec![0x00];
        ok.extend(reply(&[
            Entry::Bytes(2, &auth),
            Entry::Bytes(3, &[0xDE; 70]),
        ]));
        let (result, request) = assert_with_reply(&ok);
        let assertion = result.unwrap();
        assert_eq!(assertion.counter, 9);
        assert_eq!(assertion.signature, vec![0xDE; 70]);
        assert_eq!(
            request,
            encode_request("ssh:", &[0xAB; 32], &[7u8; 64], true).unwrap()
        );
    }

    #[test]
    fn get_assertion_rejects_an_empty_reply() {
        let (result, _) = assert_with_reply(&[]);
        assert!(
            matches!(result, Err(FidoError::Protocol("empty CTAP reply"))),
            "{result:?}"
        );
    }

    /// A failure status is reported without looking at what follows it.
    #[test]
    fn get_assertion_reports_a_failure_status() {
        let (result, _) = assert_with_reply(&[0x2e]);
        assert!(matches!(result, Err(FidoError::NoCredential)), "{result:?}");
        let (result, _) = assert_with_reply(&[0x27, 0xff]);
        assert!(matches!(result, Err(FidoError::Denied)), "{result:?}");
        let (result, _) = assert_with_reply(&[0x36]);
        assert!(matches!(result, Err(FidoError::PinRequired)), "{result:?}");
        let (result, _) = assert_with_reply(&[0x7f]);
        assert!(matches!(result, Err(FidoError::Ctap(0x7f))), "{result:?}");
    }

    /// Without `up` the authenticator answers at once: no presence prompt,
    /// and the UP flag is clear.
    #[test]
    fn get_assertion_without_up_skips_the_touch() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01).with_touch();
        let mut hid = CtapHid::new(device);
        let hash: [u8; 32] = Sha256::digest(b"hello").into();
        let prompts = Cell::new(0);
        let assertion = get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], false, &|| {
            prompts.set(prompts.get() + 1)
        })
        .unwrap();
        assert_eq!(assertion.flags & 0x01, 0);
        assert_eq!(prompts.get(), 0);
    }

    #[test]
    fn get_assertion_needs_the_enrolled_credential() {
        let hash = [0u8; 32];
        for (rp_id, handle) in [("ssh:other", &[1u8, 2, 3, 4][..]), ("ssh:", &[1, 2, 3, 5])] {
            let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01);
            let mut hid = CtapHid::new(device);
            let result = get_assertion(&mut hid, rp_id, &hash, handle, true, &|| {});
            assert!(
                matches!(result, Err(FidoError::NoCredential)),
                "{rp_id} {handle:?}: {result:?}"
            );
        }
    }

    #[test]
    fn the_counter_advances_between_assertions() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01);
        let mut hid = CtapHid::new(device);
        let hash = [0u8; 32];
        let first = get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {}).unwrap();
        let second = get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {}).unwrap();
        assert_eq!(second.counter, first.counter + 1);
    }
}
