//! The two device operations the agent needs: deriving a public key and
//! signing a challenge, plus the connect handshake.

use crate::challenge::{Challenge, ChallengeSink};
use crate::identity::{Curve, Identity};
use crate::protocol::{
    self, DeviceStatus, MAX_LARGE_PAYLOAD, Opcode, RawPublicKey, Report, Response,
};
use crate::transport::{HidTransport, HidapiTransport, TransportError};
use sha2::{Digest, Sha256};
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
    #[error("data to sign is {0} bytes; the device accepts at most {max} bytes", max = MAX_LARGE_PAYLOAD - 32)]
    BlobTooLong(usize),
    #[error(
        "nistp256 cannot sign a {0}-byte message: the firmware would treat it as a precomputed hash"
    )]
    AmbiguousBlobLength(usize),
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

    /// Ask the device for the public key it derives for `identity` on `curve`.
    pub fn derive_public_key(
        &mut self,
        identity: &Identity,
        curve: Curve,
    ) -> Result<RawPublicKey, DeviceError> {
        self.require_unlocked()?;
        let hash = identity.derivation_hash();
        tracing::debug!(%identity, %curve, hash = %hex::encode(hash), "requesting public key");
        self.transport
            .write_report(&protocol::getpubkey_report(curve, &hash))?;
        let report = self.await_data(self.timeouts.pubkey)?;
        let key = protocol::parse_pubkey_report(curve, &report);
        if curve == Curve::Ed25519 && report[32..].iter().any(|&b| b != 0) {
            tracing::debug!("public key report carries non-zero tail bytes");
        }
        Ok(key)
    }

    /// Sign `blob` with the key derived for `identity` on `curve`.
    ///
    /// Shows the challenge through `sink`, sends the request and waits for the
    /// user to confirm. Returns the raw 64-byte signature.
    pub fn sign(
        &mut self,
        identity: &Identity,
        curve: Curve,
        blob: &[u8],
        subject: Option<String>,
        sink: &dyn ChallengeSink,
    ) -> Result<[u8; 64], DeviceError> {
        let version = self.require_unlocked()?.to_owned();
        if blob.len() + 32 > MAX_LARGE_PAYLOAD {
            return Err(DeviceError::BlobTooLong(blob.len()));
        }
        if curve == Curve::NistP256 && (blob.len() == 32 || blob.len() == 64) {
            return Err(DeviceError::AmbiguousBlobLength(blob.len()));
        }
        let mut message = blob.to_vec();
        message.extend_from_slice(&identity.derivation_hash());
        let reports = protocol::chunk_large_message(Opcode::Sign, curve.sign_slot(), &message)?;

        let digits = challenge_digits(&message, &version);
        sink.present(&Challenge {
            digits,
            identity: identity.to_string(),
            subject,
        });
        tracing::debug!(%identity, %curve, blob_len = blob.len(), ?digits, "sending sign request");
        for report in &reports {
            self.transport.write_report(report)?;
        }
        let report = self.await_data(self.timeouts.sign)?;
        Ok(report)
    }

    /// [`Self::derive_public_key`] wrapped as an SSH public key whose comment
    /// is `<ssh://user@host|curve>`, the same label the Python agent writes.
    pub fn ssh_public_key(
        &mut self,
        identity: &Identity,
        curve: Curve,
    ) -> Result<ssh_key::PublicKey, DeviceError> {
        let raw = self.derive_public_key(identity, curve)?;
        Ok(crate::keys::public_key(&raw, &identity.label(curve))?)
    }

    /// [`Self::sign`] wrapped as an SSH signature, verified against
    /// `public_key` before it is returned.
    pub fn ssh_sign(
        &mut self,
        identity: &Identity,
        curve: Curve,
        public_key: &ssh_key::PublicKey,
        data: &[u8],
        subject: Option<String>,
        sink: &dyn ChallengeSink,
    ) -> Result<ssh_key::Signature, DeviceError> {
        let raw = self.sign(identity, curve, data, subject, sink)?;
        let sig = crate::keys::signature(curve, &raw)?;
        crate::keys::verify(public_key, data, &sig)?;
        Ok(sig)
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
            response => return Ok(response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::RecordingSink;
    use crate::transport::fake::{ScriptedTransport, Step};

    fn fast() -> Timeouts {
        Timeouts {
            connect: Duration::from_millis(10),
            connect_retry: Duration::from_millis(1),
            poll: Duration::from_millis(1),
            status: Duration::from_millis(50),
            pubkey: Duration::from_millis(50),
            sign: Duration::from_millis(50),
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
        let id: Identity = "james@example.com".parse().unwrap();
        assert!(matches!(
            ok.derive_public_key(&id, Curve::Ed25519),
            Err(DeviceError::Locked)
        ));
        assert!(matches!(
            ok.sign(&id, Curve::Ed25519, b"x", None, &RecordingSink::default()),
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
            Step::ExpectWrite(protocol::getpubkey_report(
                Curve::Ed25519,
                &id.derivation_hash(),
            )),
            Step::Timeout,
            Step::Reply(key_report),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        assert_eq!(
            ok.derive_public_key(&id, Curve::Ed25519).unwrap(),
            RawPublicKey::Ed25519([0x42; 32])
        );
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
            .sign(&id, Curve::Ed25519, &blob, Some("test".into()), &sink)
            .unwrap();
        assert_eq!(got, sig);
        let shown = sink.0.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].digits, challenge_digits(&message, "v3.0.4-prodc"));
        assert_eq!(shown[0].identity, "james@example.com");
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
                Step::ExpectWrite(protocol::getpubkey_report(
                    Curve::NistP256,
                    &id.derivation_hash(),
                )),
                Step::Reply(text(reply)),
            ]);
            let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
            let err = ok.derive_public_key(&id, Curve::NistP256).unwrap_err();
            assert!(check(&err), "{reply}: {err}");
        }
    }

    #[test]
    fn silence_times_out() {
        let id: Identity = "james@example.com".parse().unwrap();
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(
                Curve::Ed25519,
                &id.derivation_hash(),
            )),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        assert!(matches!(
            ok.derive_public_key(&id, Curve::Ed25519),
            Err(DeviceError::NoResponse(_))
        ));
    }

    #[test]
    fn sign_rejects_bad_blob_lengths() {
        let id: Identity = "james@example.com".parse().unwrap();
        let t = ScriptedTransport::new(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
        ]);
        let mut ok = OnlyKey::handshake(t, fast(), 1).unwrap();
        let sink = RecordingSink::default();
        assert!(matches!(
            ok.sign(&id, Curve::Ed25519, &[0; 737], None, &sink),
            Err(DeviceError::BlobTooLong(737))
        ));
        assert!(matches!(
            ok.sign(&id, Curve::NistP256, &[0; 64], None, &sink),
            Err(DeviceError::AmbiguousBlobLength(64))
        ));
        assert!(sink.0.lock().unwrap().is_empty());
    }
}
