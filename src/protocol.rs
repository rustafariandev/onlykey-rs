//! Raw OnlyKey HID report encoding and response classification.
//!
//! Every exchange with the device is a 64-byte report with no report ID.
//! Requests start with a four-byte `FF FF FF FF` header followed by an opcode,
//! an optional slot, an optional message field and a payload. Responses are
//! unsolicited input reports: either ASCII status text or binary data.

use crate::identity::Curve;
use thiserror::Error;

/// Size of every HID report, in both directions.
pub const REPORT_SIZE: usize = 64;
/// Header that opens every request report.
pub const HEADER: [u8; 4] = [0xFF; 4];
/// Payload bytes per report when a message is split across several reports.
pub const CHUNK_SIZE: usize = 57;
/// Largest message the firmware will reassemble. Its buffer is 768 bytes,
/// but it accepts a report only while the bytes already received fit
/// another full chunk, so at most 13 reports (741 bytes) get through and a
/// 14th is answered with "packets received exceeded size limit". Measured
/// on firmware v3.0.4-prodc and confirmed in `okcore.cpp`.
pub const MAX_LARGE_PAYLOAD: usize = 13 * CHUNK_SIZE;
/// Slot number meaning "derive the key from the payload hash".
pub const DERIVED_KEY_SLOT: u8 = 132;

/// A single HID report.
pub type Report = [u8; REPORT_SIZE];

/// Request opcodes the agent uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    SetTime = 0xE4,
    GetPubKey = 0xEC,
    Sign = 0xED,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("payload of {0} bytes does not fit in a single report")]
    PayloadTooLong(usize),
    #[error("message of {0} bytes exceeds the device buffer of {MAX_LARGE_PAYLOAD} bytes")]
    MessageTooLong(usize),
    #[error("message is empty")]
    EmptyMessage,
}

/// Build one request report: `FF FF FF FF | op | slot | field | payload`.
///
/// `slot` and `field` are only emitted when given, and the payload directly
/// follows whichever of them are present.
pub fn encode_report(
    op: Opcode,
    slot: Option<u8>,
    field: Option<u8>,
    payload: &[u8],
) -> Result<Report, ProtocolError> {
    let mut report = [0u8; REPORT_SIZE];
    report[..4].copy_from_slice(&HEADER);
    let mut pos = 4;
    report[pos] = op as u8;
    pos += 1;
    if let Some(slot) = slot {
        report[pos] = slot;
        pos += 1;
    }
    if let Some(field) = field {
        report[pos] = field;
        pos += 1;
    }
    if pos + payload.len() > REPORT_SIZE {
        return Err(ProtocolError::PayloadTooLong(payload.len()));
    }
    report[pos..pos + payload.len()].copy_from_slice(payload);
    Ok(report)
}

/// The `OKSETTIME` request. The firmware reads a four-byte big-endian epoch.
pub fn settime_report(epoch: u32) -> Report {
    encode_report(Opcode::SetTime, None, None, &epoch.to_be_bytes())
        .expect("4-byte payload always fits")
}

/// Modulus and signature lengths of the RSA keys the token can hold.
pub const RSA_LENGTHS: [usize; 2] = [256, 512];

/// The `OKGETPUBKEY` request: `slot` is 132 for a derived key, the ECC slot
/// (101 to 116) or the RSA slot (1 to 4) of a stored one; the payload is a
/// one-byte tag (the curve tag, or `0x00` for RSA) followed by the 32-byte
/// identity hash. The firmware only reads the payload when it derives, but
/// the Python agent sends it for stored keys too.
pub fn getpubkey_report(slot: u8, tag: u8, identity_hash: &[u8; 32]) -> Report {
    let mut payload = [0u8; 33];
    payload[0] = tag;
    payload[1..].copy_from_slice(identity_hash);
    encode_report(Opcode::GetPubKey, Some(slot), None, &payload)
        .expect("33-byte payload always fits")
}

/// Split a long message into reports of the form
/// `FF FF FF FF | op | slot | size | chunk(57)`.
///
/// Every report except the last carries size `0xFF` ("more follows"). The last
/// carries its real length, which the firmware requires to be in `1..=57`;
/// a full final chunk is therefore marked `57`, never `0xFF` and never `0`.
pub fn chunk_large_message(
    op: Opcode,
    slot: u8,
    message: &[u8],
) -> Result<Vec<Report>, ProtocolError> {
    if message.is_empty() {
        return Err(ProtocolError::EmptyMessage);
    }
    if message.len() > MAX_LARGE_PAYLOAD {
        return Err(ProtocolError::MessageTooLong(message.len()));
    }
    let chunks: Vec<&[u8]> = message.chunks(CHUNK_SIZE).collect();
    let last = chunks.len() - 1;
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let size = if i == last { chunk.len() as u8 } else { 0xFF };
            encode_report(op, Some(slot), Some(size), chunk)
        })
        .collect()
}

/// Lock state reported in reply to `OKSETTIME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    /// PIN entered; `version` is the firmware string, e.g. `v3.0.4-prodc`.
    Unlocked { version: String },
    /// PIN set but not entered.
    Locked,
    /// No PIN configured yet.
    Uninitialized,
}

/// What an input report means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// An empty or uniform report; ignore it and keep reading.
    Filler,
    Status(DeviceStatus),
    /// An ASCII error message from the firmware.
    DeviceError(String),
    /// Binary data (public key or signature).
    Data(Report),
}

/// Decode the ASCII portion of a report: bytes up to the first NUL.
fn ascii_text(report: &Report) -> Option<&str> {
    let end = report.iter().position(|&b| b == 0).unwrap_or(REPORT_SIZE);
    let text = &report[..end];
    if text.is_empty() || !text.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        return None;
    }
    std::str::from_utf8(text).ok()
}

/// Classify an input report.
pub fn classify_response(report: &Report) -> Response {
    if let Some(text) = ascii_text(report) {
        if text.starts_with("Error") || text.starts_with("Timeout") {
            return Response::DeviceError(text.trim().to_owned());
        }
        if text.contains("UNINITIALIZED") {
            return Response::Status(DeviceStatus::Uninitialized);
        }
        if text.contains("INITIALIZED") {
            return Response::Status(DeviceStatus::Locked);
        }
        if let Some(version) = text.strip_prefix("UNLOCKED") {
            return Response::Status(DeviceStatus::Unlocked {
                version: version.to_owned(),
            });
        }
    }
    if report[..REPORT_SIZE - 1].iter().all(|&b| b == report[0]) {
        return Response::Filler;
    }
    Response::Data(*report)
}

/// A public key as returned by the device, before SSH encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawPublicKey {
    Ed25519([u8; 32]),
    /// Uncompressed point without the SEC1 `0x04` tag: `X || Y`.
    NistP256([u8; 64]),
    /// RSA modulus, big-endian, 256 or 512 bytes. The exponent is always 65537.
    Rsa(Vec<u8>),
}

impl RawPublicKey {
    /// The ECC curve, or `None` for RSA.
    pub fn curve(&self) -> Option<Curve> {
        match self {
            RawPublicKey::Ed25519(_) => Some(Curve::Ed25519),
            RawPublicKey::NistP256(_) => Some(Curve::NistP256),
            RawPublicKey::Rsa(_) => None,
        }
    }
}

/// Which curve a public key report carries: 32 bytes for ed25519, 64 for
/// P-256, so a uniform tail means ed25519. This is the Python agent's test;
/// it matters for stored keys, whose type is fixed when the slot is written.
pub fn pubkey_report_curve(report: &Report) -> Curve {
    if report[32..].iter().all(|&b| b == report[32]) {
        Curve::Ed25519
    } else {
        Curve::NistP256
    }
}

/// Interpret an `OKGETPUBKEY` data report according to the curve requested.
///
/// The firmware writes only the key bytes and leaves the rest of the report
/// untouched, so the length is decided by the curve, not by the report content.
pub fn parse_pubkey_report(curve: Curve, report: &Report) -> RawPublicKey {
    match curve {
        Curve::Ed25519 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&report[..32]);
            RawPublicKey::Ed25519(key)
        }
        Curve::NistP256 => RawPublicKey::NistP256(*report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_from_hex(hex: &str) -> Report {
        let bytes = hex::decode(hex).unwrap();
        let mut report = [0u8; REPORT_SIZE];
        report.copy_from_slice(&bytes);
        report
    }

    fn goldens() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/goldens.json")).unwrap()
    }

    #[test]
    fn settime_matches_python() {
        let g = goldens();
        let want = report_from_hex(g["frames"]["settime_1700000000"].as_str().unwrap());
        assert_eq!(settime_report(1_700_000_000), want);
    }

    #[test]
    fn getpubkey_matches_python() {
        let g = goldens();
        let hash: [u8; 32] = hex::decode(g["identities"][0]["hash_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let want = report_from_hex(g["frames"]["getpubkey_ed25519"].as_str().unwrap());
        assert_eq!(getpubkey_report(DERIVED_KEY_SLOT, 0x01, &hash), want);
        let want = report_from_hex(g["frames"]["getpubkey_p256"].as_str().unwrap());
        assert_eq!(getpubkey_report(DERIVED_KEY_SLOT, 0x02, &hash), want);
    }

    #[test]
    fn rsa_slot_frames_match_python() {
        use sha2::Digest;
        let g = goldens();
        let hash: [u8; 32] = hex::decode(g["identities"][0]["hash_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let want = report_from_hex(g["frames"]["getpubkey_rsa1"].as_str().unwrap());
        assert_eq!(getpubkey_report(1, 0x00, &hash), want);
        // An RSA signature request carries the hash of the blob.
        let blob: Vec<u8> = (0..100).map(|i| i as u8).collect();
        for (name, digest) in [
            ("sha256_of_100", sha2::Sha256::digest(&blob).to_vec()),
            ("sha512_of_100", sha2::Sha512::digest(&blob).to_vec()),
        ] {
            let want: Vec<Report> = g["sign_frames_rsa1"][name]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| report_from_hex(f.as_str().unwrap()))
                .collect();
            assert_eq!(
                chunk_large_message(Opcode::Sign, 1, &digest).unwrap(),
                want,
                "{name}"
            );
        }
    }

    #[test]
    fn stored_slot_frames_match_python() {
        let g = goldens();
        let hash: [u8; 32] = hex::decode(g["identities"][0]["hash_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let want = report_from_hex(g["frames"]["getpubkey_ecc3_ed25519"].as_str().unwrap());
        assert_eq!(getpubkey_report(103, 0x01, &hash), want);
        let want = report_from_hex(g["frames"]["getpubkey_ecc3_p256"].as_str().unwrap());
        assert_eq!(getpubkey_report(103, 0x02, &hash), want);
        // A stored-key signature carries the blob alone, no identity hash.
        let blob: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let want: Vec<Report> = g["sign_frames_ecc3"]["100"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| report_from_hex(f.as_str().unwrap()))
            .collect();
        assert_eq!(chunk_large_message(Opcode::Sign, 103, &blob).unwrap(), want);
    }

    #[test]
    fn chunking_matches_python_for_non_multiples() {
        let g = goldens();
        for (len, frames) in g["sign_frames"].as_object().unwrap() {
            let n: usize = len.parse().unwrap();
            let message: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let got = chunk_large_message(Opcode::Sign, 201, &message).unwrap();
            let want: Vec<Report> = frames
                .as_array()
                .unwrap()
                .iter()
                .map(|f| report_from_hex(f.as_str().unwrap()))
                .collect();
            assert_eq!(got, want, "message length {n}");
        }
    }

    #[test]
    fn chunking_final_size_byte_is_never_ff_or_zero() {
        for n in [1usize, 56, 57, 58, 114, 115, 740, 741] {
            let message = vec![0xAB; n];
            let reports = chunk_large_message(Opcode::Sign, 202, &message).unwrap();
            assert_eq!(reports.len(), n.div_ceil(CHUNK_SIZE), "length {n}");
            for (i, r) in reports.iter().enumerate() {
                assert_eq!(&r[..4], &HEADER);
                assert_eq!(r[4], Opcode::Sign as u8);
                assert_eq!(r[5], 202);
                if i + 1 < reports.len() {
                    assert_eq!(r[6], 0xFF, "length {n}, report {i}");
                } else {
                    assert!((1..=57).contains(&r[6]), "length {n}: final size {}", r[6]);
                }
            }
            let reassembled: Vec<u8> = reports
                .iter()
                .map(|r| {
                    let take = if r[6] == 0xFF {
                        CHUNK_SIZE
                    } else {
                        r[6] as usize
                    };
                    &r[7..7 + take]
                })
                .collect::<Vec<_>>()
                .concat();
            assert_eq!(reassembled, message);
        }
    }

    #[test]
    fn chunking_rejects_bad_lengths() {
        assert_eq!(
            chunk_large_message(Opcode::Sign, 201, &[]),
            Err(ProtocolError::EmptyMessage)
        );
        assert_eq!(
            chunk_large_message(Opcode::Sign, 201, &[0; 742]),
            Err(ProtocolError::MessageTooLong(742))
        );
    }

    fn text_report(s: &str) -> Report {
        let mut r = [0u8; REPORT_SIZE];
        r[..s.len()].copy_from_slice(s.as_bytes());
        r
    }

    #[test]
    fn classifies_status_strings() {
        assert_eq!(
            classify_response(&text_report("UNLOCKEDv3.0.4-prodc")),
            Response::Status(DeviceStatus::Unlocked {
                version: "v3.0.4-prodc".into()
            })
        );
        assert_eq!(
            classify_response(&text_report("INITIALIZED")),
            Response::Status(DeviceStatus::Locked)
        );
        assert_eq!(
            classify_response(&text_report("UNINITIALIZED")),
            Response::Status(DeviceStatus::Uninitialized)
        );
        assert_eq!(
            classify_response(&text_report("Error incorrect challenge was entered")),
            Response::DeviceError("Error incorrect challenge was entered".into())
        );
        assert_eq!(
            classify_response(&text_report(
                "Timeout occured while waiting for confirmation on OnlyKey"
            )),
            Response::DeviceError(
                "Timeout occured while waiting for confirmation on OnlyKey".into()
            )
        );
    }

    #[test]
    fn classifies_filler_and_data() {
        assert_eq!(classify_response(&[0u8; 64]), Response::Filler);
        assert_eq!(classify_response(&[0xFFu8; 64]), Response::Filler);
        let mut uniform_but_last = [7u8; 64];
        uniform_but_last[63] = 9;
        assert_eq!(classify_response(&uniform_but_last), Response::Filler);
        let mut data = [0u8; 64];
        data[0] = 0x8A;
        data[31] = 0x5C;
        assert_eq!(classify_response(&data), Response::Data(data));
    }

    #[test]
    fn pubkey_report_parsed_by_curve() {
        let mut r = [0u8; 64];
        r[..32].copy_from_slice(&[1u8; 32]);
        assert_eq!(
            parse_pubkey_report(Curve::Ed25519, &r),
            RawPublicKey::Ed25519([1u8; 32])
        );
        assert_eq!(
            parse_pubkey_report(Curve::NistP256, &r),
            RawPublicKey::NistP256(r)
        );
        assert_eq!(pubkey_report_curve(&r), Curve::Ed25519);
        r[40] = 9;
        assert_eq!(pubkey_report_curve(&r), Curve::NistP256);
    }
}
