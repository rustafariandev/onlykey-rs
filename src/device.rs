//! The two device operations the agent needs: fetching a public key and
//! signing a challenge, plus the connect handshake.

use crate::challenge::{Challenge, ChallengeSink};
use crate::identity::{Curve, EccSlot, KeyKind, KeySpec};
use crate::protocol::{self, DeviceStatus, Opcode, RSA_LENGTHS, RawPublicKey, Report, Response};
use crate::transport::{HidTransport, HidapiTransport, TransportError};
use sha2::{Digest, Sha256};
use ssh_key::HashAlg;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Firmware version whose challenge digits use five buttons instead of six.
const FIVE_BUTTON_FIRMWARE: &str = "v0.2-beta.8c";

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Protocol(#[from] protocol::ProtocolError),
    #[error(transparent)]
    Key(#[from] crate::keys::KeyError),
    #[error(transparent)]
    Spec(#[from] crate::identity::IdentityError),
    #[error("OnlyKey is locked; enter your PIN on the device first")]
    Locked,
    #[error("OnlyKey has no PIN set; initialise it with the OnlyKey app first")]
    Uninitialized,
    #[error("no response from OnlyKey within {0:?}")]
    NoResponse(Duration),
    #[error("OnlyKey reported: {0}")]
    Firmware(String),
    #[error("wrong challenge code entered on OnlyKey")]
    WrongChallenge,
    #[error("timed out waiting for confirmation on OnlyKey")]
    ConfirmationTimeout,
    #[error("data to sign is {len} bytes; the device accepts at most {max} bytes")]
    BlobTooLong { len: usize, max: usize },
    #[error("slot {slot} holds a {found} key, not the requested {requested}")]
    CurveMismatch {
        slot: EccSlot,
        requested: Curve,
        found: Curve,
    },
    #[error("RSA reply of {0} bytes is neither a 2048- nor a 4096-bit value")]
    RsaLength(usize),
}

/// How long to wait at each stage. Defaults follow the Python agent; tests
/// shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Keep retrying to open the device for this long.
    pub connect: Duration,
    /// Pause between open attempts.
    pub connect_retry: Duration,
    /// Single HID read poll.
    pub poll: Duration,
    /// Wait for the status reply after `OKSETTIME`.
    pub status: Duration,
    /// Wait for a public key.
    pub pubkey: Duration,
    /// Wait for the user to confirm and the device to sign.
    pub sign: Duration,
    /// Silence that ends a multi-report reply (RSA modulus or signature).
    pub gap: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_millis(2500),
            connect_retry: Duration::from_millis(250),
            poll: Duration::from_millis(100),
            status: Duration::from_millis(1000),
            pubkey: Duration::from_millis(1500),
            sign: Duration::from_secs(22),
            gap: Duration::from_millis(500),
        }
    }
}

/// The three button presses the device expects for `message`.
///
/// The device hashes the whole assembled message and picks bytes 0, 15 and 31.
pub fn challenge_digits(message: &[u8], firmware_version: &str) -> [u8; 3] {
    let digest = Sha256::digest(message);
    let buttons = if firmware_version == FIVE_BUTTON_FIRMWARE {
        5
    } else {
        6
    };
    [digest[0], digest[15], digest[31]].map(|b| b % buttons + 1)
}

/// An open, time-synchronised OnlyKey.
pub struct OnlyKey<T: HidTransport> {
    transport: T,
    status: DeviceStatus,
    timeouts: Timeouts,
}

impl OnlyKey<HidapiTransport> {
    /// Open the attached OnlyKey, retrying for [`Timeouts::connect`].
    pub fn open() -> Result<Self, DeviceError> {
        Self::open_with_timeouts(Timeouts::default())
    }

    pub fn open_with_timeouts(timeouts: Timeouts) -> Result<Self, DeviceError> {
        let deadline = Instant::now() + timeouts.connect;
        loop {
            match HidapiTransport::open() {
                Ok(transport) => return Self::handshake(transport, timeouts, epoch_now()),
                Err(e) if Instant::now() < deadline && e.is_retryable() => {
                    tracing::debug!(error = %e, "open failed, retrying");
                    std::thread::sleep(timeouts.connect_retry);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

fn epoch_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

impl<T: HidTransport> OnlyKey<T> {
    /// Send `OKSETTIME` (which also reports lock state and firmware version)
    /// over an already-open transport.
    pub fn handshake(
        mut transport: T,
        timeouts: Timeouts,
        epoch: u32,
    ) -> Result<Self, DeviceError> {
        transport.write_report(&protocol::settime_report(epoch))?;
        let status = match await_response(&mut transport, &timeouts, timeouts.status)? {
            Response::Status(status) => status,
            Response::DeviceError(text) => return Err(DeviceError::Firmware(text)),
            other => {
                tracing::warn!(?other, "unexpected reply to settime");
                DeviceStatus::Locked
            }
        };
        tracing::debug!(?status, "connected");
        Ok(OnlyKey {
            transport,
            status,
            timeouts,
        })
    }

    pub fn status(&self) -> &DeviceStatus {
        &self.status
    }

    /// Firmware version string, if the device is unlocked.
    pub fn firmware_version(&self) -> Option<&str> {
        match &self.status {
            DeviceStatus::Unlocked { version } => Some(version),
            _ => None,
        }
    }

    fn require_unlocked(&self) -> Result<&str, DeviceError> {
        match &self.status {
            DeviceStatus::Unlocked { version } => Ok(version),
            DeviceStatus::Locked => Err(DeviceError::Locked),
            DeviceStatus::Uninitialized => Err(DeviceError::Uninitialized),
        }
    }

    /// Ask the device for the public key of `key`: derived from the identity
    /// hash, or read from the stored slot.
    ///
    /// A stored ECC slot's key type is fixed when it is written, so the reply
    /// is checked against the requested curve and
    /// [`DeviceError::CurveMismatch`] names the curve the slot actually
    /// holds. An RSA modulus arrives as several reports; its length (256 or
    /// 512 bytes) is whatever the slot holds.
    pub fn public_key(&mut self, key: &KeySpec) -> Result<RawPublicKey, DeviceError> {
        self.require_unlocked()?;
        let hash = key.identity.derivation_hash();
        tracing::debug!(identity = %key.identity, key = %key.kind, hash = %hex::encode(hash), "requesting public key");
        self.transport.write_report(&protocol::getpubkey_report(
            key.pubkey_slot(),
            key.pubkey_tag(),
            &hash,
        ))?;
        match key.kind {
            KeyKind::StoredRsa(_) => {
                let modulus = self.await_data_all(self.timeouts.pubkey)?;
                if !RSA_LENGTHS.contains(&modulus.len()) {
                    return Err(DeviceError::RsaLength(modulus.len()));
                }
                Ok(RawPublicKey::Rsa(modulus))
            }
            KeyKind::StoredEcc { slot, curve } => {
                let report = self.await_data(self.timeouts.pubkey)?;
                let found = protocol::pubkey_report_curve(&report);
                if found != curve {
                    return Err(DeviceError::CurveMismatch {
                        slot,
                        requested: curve,
                        found,
                    });
                }
                Ok(protocol::parse_pubkey_report(curve, &report))
            }
            KeyKind::Derived(curve) => {
                let report = self.await_data(self.timeouts.pubkey)?;
                if curve == Curve::Ed25519 && report[32..].iter().any(|&b| b != 0) {
                    tracing::debug!("public key report carries non-zero tail bytes");
                }
                Ok(protocol::parse_pubkey_report(curve, &report))
            }
        }
    }

    /// Sign `blob` with `key`.
    ///
    /// Shows the challenge through `sink`, sends the request and waits for the
    /// user to confirm. Returns the raw signature: 64 bytes for an ECC key,
    /// the 256- or 512-byte PKCS#1 v1.5 block for RSA. `hash` only matters
    /// for RSA, where the token signs `hash(blob)`.
    pub fn sign(
        &mut self,
        key: &KeySpec,
        blob: &[u8],
        hash: HashAlg,
        subject: Option<String>,
        sink: &dyn ChallengeSink,
    ) -> Result<Vec<u8>, DeviceError> {
        let version = self.require_unlocked()?.to_owned();
        if let Some(max) = key.max_blob_len()
            && blob.len() > max
        {
            return Err(DeviceError::BlobTooLong {
                len: blob.len(),
                max,
            });
        }
        let message = key.sign_message(blob, hash)?;
        let reports = protocol::chunk_large_message(Opcode::Sign, key.sign_slot(), &message)?;

        let digits = challenge_digits(&message, &version);
        sink.present(&Challenge {
            digits,
            identity: key.identity.to_string(),
            source: key.source(),
            subject,
        });
        tracing::debug!(identity = %key.identity, key = %key.kind, blob_len = blob.len(), ?digits, "sending sign request");
        for report in &reports {
            self.transport.write_report(report)?;
        }
        if key.kind.is_rsa() {
            let sig = self.await_data_all(self.timeouts.sign)?;
            if !RSA_LENGTHS.contains(&sig.len()) {
                return Err(DeviceError::RsaLength(sig.len()));
            }
            Ok(sig)
        } else {
            Ok(self.await_data(self.timeouts.sign)?.to_vec())
        }
    }

    /// [`Self::public_key`] wrapped as an SSH public key whose comment is
    /// [`KeySpec::label`]: `<ssh://user@host|curve>` for a derived key, the
    /// same label the Python agent writes.
    pub fn ssh_public_key(&mut self, key: &KeySpec) -> Result<ssh_key::PublicKey, DeviceError> {
        let raw = self.public_key(key)?;
        Ok(crate::keys::public_key(&raw, &key.label())?)
    }

    /// [`Self::sign`] wrapped as an SSH signature, verified against
    /// `public_key` before it is returned. For RSA, `hash` selects
    /// `rsa-sha2-256` or `rsa-sha2-512`.
    pub fn ssh_sign(
        &mut self,
        key: &KeySpec,
        public_key: &ssh_key::PublicKey,
        data: &[u8],
        hash: HashAlg,
        subject: Option<String>,
        sink: &dyn ChallengeSink,
    ) -> Result<ssh_key::Signature, DeviceError> {
        let raw = self.sign(key, data, hash, subject, sink)?;
        let sig = crate::keys::signature(&key.kind.signature_algorithm(hash), &raw)?;
        crate::keys::verify(public_key, data, &sig)?;
        Ok(sig)
    }

    /// Wait for a multi-report reply: the first report within `timeout`, then
    /// more until the token has been quiet for [`Timeouts::gap`].
    fn await_data_all(&mut self, timeout: Duration) -> Result<Vec<u8>, DeviceError> {
        let mut out = self.await_data(timeout)?.to_vec();
        loop {
            match await_response(&mut self.transport, &self.timeouts, self.timeouts.gap) {
                Ok(Response::Data(report)) => out.extend_from_slice(&report),
                Ok(Response::DeviceError(text)) => return Err(firmware_error(text)),
                Ok(Response::Status(_) | Response::Filler) | Err(DeviceError::NoResponse(_)) => {
                    return Ok(out);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Wait for a binary report, translating firmware errors.
    fn await_data(&mut self, timeout: Duration) -> Result<Report, DeviceError> {
        match await_response(&mut self.transport, &self.timeouts, timeout)? {
            Response::Data(report) => Ok(report),
            Response::DeviceError(text) => Err(firmware_error(text)),
            Response::Status(DeviceStatus::Locked) => Err(DeviceError::Locked),
            Response::Status(DeviceStatus::Uninitialized) => Err(DeviceError::Uninitialized),
            Response::Status(DeviceStatus::Unlocked { .. }) | Response::Filler => {
                Err(DeviceError::NoResponse(timeout))
            }
        }
    }

    /// Give the transport back, e.g. to close it.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Erase the transport type, e.g. to build an [`crate::agent::Opener`].
    pub fn boxed(self) -> OnlyKey<Box<dyn HidTransport>>
    where
        T: 'static,
    {
        let (transport, status, timeouts) = self.into_parts();
        OnlyKey::from_parts(Box::new(transport), status, timeouts)
    }

    /// Split into parts, e.g. to box the transport.
    pub fn into_parts(self) -> (T, DeviceStatus, Timeouts) {
        (self.transport, self.status, self.timeouts)
    }

    /// Reassemble from parts produced by [`Self::into_parts`].
    pub fn from_parts(transport: T, status: DeviceStatus, timeouts: Timeouts) -> Self {
        OnlyKey {
            transport,
            status,
            timeouts,
        }
    }
}

fn firmware_error(text: String) -> DeviceError {
    if text.contains("incorrect challenge") {
        DeviceError::WrongChallenge
    } else if text.starts_with("Timeout") {
        DeviceError::ConfirmationTimeout
    } else {
        DeviceError::Firmware(text)
    }
}

/// Read until a non-filler report arrives or `timeout` elapses.
fn await_response<T: HidTransport>(
    transport: &mut T,
    timeouts: &Timeouts,
    timeout: Duration,
) -> Result<Response, DeviceError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DeviceError::NoResponse(timeout));
        }
        let Some(report) = transport.read_report(remaining.min(timeouts.poll))? else {
            continue;
        };
        match protocol::classify_response(&report) {
            Response::Filler => continue,
            response => {
                tracing::trace!(report = %hex::encode(report), "report received");
                return Ok(response);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::RecordingSink;
    use crate::identity::{Identity, KeySource, RsaSlot, Slot};
    use crate::transport::fake::{ScriptedTransport, Step};

    fn rsa(slot: u8) -> KeySpec {
        KeySpec::rsa(
            "james@example.com".parse().unwrap(),
            RsaSlot::new(slot).unwrap(),
        )
    }

    fn derived(curve: Curve) -> KeySpec {
        KeySpec::derived("james@example.com".parse().unwrap(), curve)
    }

    fn stored(curve: Curve, slot: u8) -> KeySpec {
        KeySpec::stored(
            "james@example.com".parse().unwrap(),
            curve,
            EccSlot::new(slot).unwrap(),
        )
    }

    fn fast() -> Timeouts {
        Timeouts {
            connect: Duration::from_millis(10),
            connect_retry: Duration::from_millis(1),
            poll: Duration::from_millis(1),
            status: Duration::from_millis(50),
            pubkey: Duration::from_millis(50),
            sign: Duration::from_millis(50),
            gap: Duration::from_millis(20),
        }
    }

    fn text(s: &str) -> Report {
        let mut r = [0u8; 64];
        r[..s.len()].copy_from_slice(s.as_bytes());
        r
    }

    fn goldens() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/goldens.json")).unwrap()
    }

    #[test]
    fn challenge_digits_match_python() {
        for case in goldens()["challenges"].as_array().unwrap() {
            let payload = hex::decode(case["payload_hex"].as_str().unwrap()).unwrap();
            let want: Vec<u8> = case["digits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(challenge_digits(&payload, "v3.0.4-prodc").to_vec(), want);
            let want_8c: Vec<u8> = case["digits_8c"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(challenge_digits(&payload, "v0.2-beta.8c").to_vec(), want_8c);
        }
    }

    #[test]
    fn handshake_reads_status_after_settime() {
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1_700_000_000)),
            Step::Reply([0u8; 64]),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
        ]);
        let ok = OnlyKey::handshake(t, fast(), 1_700_000_000).unwrap();
        assert_eq!(ok.firmware_version(), Some("v3.0.4-prodc"));
        ok.into_transport().assert_done();
    }

    #[test]
    fn locked_device_refuses_operations() {
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("INITIALIZED")),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        assert!(matches!(
            ok.public_key(&derived(Curve::Ed25519)),
            Err(DeviceError::Locked)
        ));
        assert!(matches!(
            ok.sign(
                &derived(Curve::Ed25519),
                b"x",
                HashAlg::Sha512,
                None,
                &RecordingSink::default()
            ),
            Err(DeviceError::Locked)
        ));
    }

    #[test]
    fn derive_public_key_round_trip() {
        let id: Identity = "james@example.com".parse().unwrap();
        let mut key_report = [0u8; 64];
        key_report[..32].copy_from_slice(&[0x42; 32]);
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(132, 0x01, &id.derivation_hash())),
            Step::Timeout,
            Step::Reply(key_report),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        assert_eq!(
            ok.public_key(&derived(Curve::Ed25519)).unwrap(),
            RawPublicKey::Ed25519([0x42; 32])
        );
        ok.into_transport().assert_done();
    }

    #[test]
    fn stored_public_key_uses_slot_and_checks_curve() {
        let id: Identity = "james@example.com".parse().unwrap();
        let mut ed_report = [0u8; 64];
        ed_report[..32].copy_from_slice(&[0x42; 32]);
        let p256_report: Report = std::array::from_fn(|i| 0x37 ^ i as u8);
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(103, 0x01, &id.derivation_hash())),
            Step::Reply(ed_report),
            Step::ExpectWrite(protocol::getpubkey_report(104, 0x02, &id.derivation_hash())),
            Step::Reply(p256_report),
            // Asking for a P-256 key from the ed25519 slot is refused.
            Step::ExpectWrite(protocol::getpubkey_report(103, 0x02, &id.derivation_hash())),
            Step::Reply(ed_report),
            Step::ExpectWrite(protocol::getpubkey_report(104, 0x01, &id.derivation_hash())),
            Step::Reply(p256_report),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        assert_eq!(
            ok.public_key(&stored(Curve::Ed25519, 3)).unwrap(),
            RawPublicKey::Ed25519([0x42; 32])
        );
        assert_eq!(
            ok.public_key(&stored(Curve::NistP256, 4)).unwrap(),
            RawPublicKey::NistP256(p256_report)
        );
        let err = ok.public_key(&stored(Curve::NistP256, 3)).unwrap_err();
        assert!(
            matches!(
                err,
                DeviceError::CurveMismatch {
                    requested: Curve::NistP256,
                    found: Curve::Ed25519,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            err.to_string(),
            "slot ECC3 holds a ed25519 key, not the requested nistp256"
        );
        assert!(matches!(
            ok.public_key(&stored(Curve::Ed25519, 4)),
            Err(DeviceError::CurveMismatch {
                requested: Curve::Ed25519,
                found: Curve::NistP256,
                ..
            })
        ));
        ok.into_transport().assert_done();
    }

    #[test]
    fn sign_sends_chunks_and_presents_challenge() {
        let id: Identity = "james@example.com".parse().unwrap();
        let blob = vec![7u8; 100];
        let mut message = blob.clone();
        message.extend_from_slice(&id.derivation_hash());
        let chunks = protocol::chunk_large_message(Opcode::Sign, 201, &message).unwrap();
        let mut steps = vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
        ];
        steps.extend(chunks.iter().map(|c| Step::ExpectWrite(*c)));
        let mut sig = [0u8; 64];
        sig[..3].copy_from_slice(&[1, 2, 3]);
        steps.push(Step::Reply(sig));
        let mut ok = OnlyKey::handshake(ScriptedTransport::new(steps), fast(), 1).unwrap();
        let sink = RecordingSink::default();
        let got = ok
            .sign(
                &derived(Curve::Ed25519),
                &blob,
                HashAlg::Sha512,
                Some("test".into()),
                &sink,
            )
            .unwrap();
        assert_eq!(got, sig);
        let shown = sink.0.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].digits, challenge_digits(&message, "v3.0.4-prodc"));
        assert_eq!(shown[0].identity, "james@example.com");
        assert_eq!(shown[0].source, KeySource::Derived);
        ok.into_transport().assert_done();
    }

    #[test]
    fn stored_sign_sends_blob_alone_with_slot() {
        let g = goldens();
        let blob: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let chunks = protocol::chunk_large_message(Opcode::Sign, 103, &blob).unwrap();
        assert_eq!(chunks.len(), 2);
        let mut steps = vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
        ];
        steps.extend(chunks.iter().map(|c| Step::ExpectWrite(*c)));
        let sig: Report = std::array::from_fn(|i| 0x5A ^ i as u8);
        steps.push(Step::Reply(sig));
        let mut ok = OnlyKey::handshake(ScriptedTransport::new(steps), fast(), 1).unwrap();
        let sink = RecordingSink::default();
        let got = ok
            .sign(
                &stored(Curve::Ed25519, 3),
                &blob,
                HashAlg::Sha512,
                None,
                &sink,
            )
            .unwrap();
        assert_eq!(got, sig);
        let shown = sink.0.lock().unwrap();
        assert_eq!(shown.len(), 1);
        // The challenge is over the blob alone, as recorded from the Python agent.
        let want: Vec<u8> = g["challenges_ecc3"][0]["digits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(shown[0].digits.to_vec(), want);
        assert_eq!(
            shown[0].source,
            KeySource::Stored(Slot::Ecc(EccSlot::new(3).unwrap()))
        );
        ok.into_transport().assert_done();
    }

    fn numbered_reports(n: usize, seed: u8) -> Vec<Report> {
        (0..n)
            .map(|i| std::array::from_fn(|j| seed ^ (i as u8) ^ (j as u8)))
            .collect()
    }

    #[test]
    fn rsa_public_key_collects_reports_until_silence() {
        let id: Identity = "james@example.com".parse().unwrap();
        let hash = id.derivation_hash();
        let four = numbered_reports(4, 0x30);
        let eight = numbered_reports(8, 0x90);
        let mut steps = vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(1, 0x00, &hash)),
        ];
        steps.extend(four.iter().map(|r| Step::Reply(*r)));
        steps.push(Step::Timeout);
        steps.push(Step::ExpectWrite(protocol::getpubkey_report(
            2, 0x00, &hash,
        )));
        steps.extend(eight.iter().map(|r| Step::Reply(*r)));
        // A reply that is neither 256 nor 512 bytes is rejected.
        steps.push(Step::ExpectWrite(protocol::getpubkey_report(
            3, 0x00, &hash,
        )));
        steps.extend(four[..3].iter().map(|r| Step::Reply(*r)));
        steps.push(Step::ExpectWrite(protocol::getpubkey_report(
            4, 0x00, &hash,
        )));
        steps.push(Step::Reply(text(
            "Error no RSA Private Key set in this slot",
        )));
        let mut ok = OnlyKey::handshake(ScriptedTransport::new(steps), fast(), 1).unwrap();
        assert_eq!(
            ok.public_key(&rsa(1)).unwrap(),
            RawPublicKey::Rsa(four.concat())
        );
        assert_eq!(
            ok.public_key(&rsa(2)).unwrap(),
            RawPublicKey::Rsa(eight.concat())
        );
        assert!(matches!(
            ok.public_key(&rsa(3)),
            Err(DeviceError::RsaLength(192))
        ));
        assert!(matches!(
            ok.public_key(&rsa(4)),
            Err(DeviceError::Firmware(_))
        ));
        ok.into_transport().assert_done();
    }

    #[test]
    fn rsa_sign_sends_hash_and_collects_signature() {
        let g = goldens();
        let blob: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let digest = sha2::Sha512::digest(&blob);
        let chunks = protocol::chunk_large_message(Opcode::Sign, 1, &digest).unwrap();
        assert_eq!(chunks.len(), 2);
        let sig = numbered_reports(4, 0x77);
        let mut steps = vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
        ];
        steps.extend(chunks.iter().map(|c| Step::ExpectWrite(*c)));
        steps.push(Step::Timeout);
        steps.extend(sig.iter().map(|r| Step::Reply(*r)));
        let mut ok = OnlyKey::handshake(ScriptedTransport::new(steps), fast(), 1).unwrap();
        let sink = RecordingSink::default();
        let got = ok
            .sign(&rsa(1), &blob, HashAlg::Sha512, None, &sink)
            .unwrap();
        assert_eq!(got, sig.concat());
        let shown = sink.0.lock().unwrap();
        let want: Vec<u8> = g["challenges_rsa1"][1]["digits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(shown[0].digits.to_vec(), want);
        assert_eq!(
            shown[0].source,
            KeySource::Stored(Slot::Rsa(RsaSlot::new(1).unwrap()))
        );
        ok.into_transport().assert_done();
    }

    #[test]
    fn firmware_errors_are_translated() {
        let id: Identity = "james@example.com".parse().unwrap();
        type Check = fn(&DeviceError) -> bool;
        let cases: [(&str, Check); 3] = [
            ("Error incorrect challenge was entered", |e| {
                matches!(e, DeviceError::WrongChallenge)
            }),
            (
                "Timeout occured while waiting for confirmation on OnlyKey",
                |e| matches!(e, DeviceError::ConfirmationTimeout),
            ),
            ("Error no key set in this slot", |e| {
                matches!(e, DeviceError::Firmware(_))
            }),
        ];
        for (reply, check) in cases {
            let t = ScriptedTransport::new(vec![
                Step::ExpectWrite(protocol::settime_report(1)),
                Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
                Step::ExpectWrite(protocol::getpubkey_report(132, 0x02, &id.derivation_hash())),
                Step::Reply(text(reply)),
            ]);
            let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
            let err = ok.public_key(&derived(Curve::NistP256)).unwrap_err();
            assert!(check(&err), "{reply}: {err}");
        }
    }

    #[test]
    fn silence_times_out() {
        let id: Identity = "james@example.com".parse().unwrap();
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(132, 0x01, &id.derivation_hash())),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        assert!(matches!(
            ok.public_key(&derived(Curve::Ed25519)),
            Err(DeviceError::NoResponse(_))
        ));
    }

    #[test]
    fn sign_rejects_bad_blob_lengths() {
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        let sink = RecordingSink::default();
        assert!(matches!(
            ok.sign(
                &derived(Curve::Ed25519),
                &[0; 710],
                HashAlg::Sha256,
                None,
                &sink
            ),
            Err(DeviceError::BlobTooLong { len: 710, max: 709 })
        ));
        assert!(matches!(
            ok.sign(
                &stored(Curve::Ed25519, 3),
                &[0; 742],
                HashAlg::Sha256,
                None,
                &sink
            ),
            Err(DeviceError::BlobTooLong { len: 742, max: 741 })
        ));
        assert!(sink.0.lock().unwrap().is_empty());
    }
}
