//! Driving a FIDO2 security key over its USB HID interface.
//!
//! This is a small, self-contained CTAP2 client: it only implements what is
//! needed to sign an SSH challenge with a key that was enrolled earlier. It
//! speaks the CTAPHID framing ([`ctaphid`]) and the CTAP2
//! `authenticatorGetAssertion` command ([`ctap`]) directly over a
//! [`HidTransport`](crate::transport::HidTransport). No C library is involved.
//!
//! The signature an authenticator returns for an SSH `sk-` key covers
//! `SHA256(application) || flags || counter || SHA256(message)`, exactly what a
//! CTAP2 assertion produces for `clientDataHash = SHA256(message)`. See
//! OpenSSH's `PROTOCOL.u2f`.

pub mod ctap;
pub mod ctaphid;
pub(crate) mod der;
pub mod fake;

use crate::transport::TransportError;
use ctaphid::MAX_MESSAGE;
use thiserror::Error;

pub use ctap::{Assertion, get_assertion};

#[derive(Debug, Error)]
pub enum FidoError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("no FIDO security key found; is one plugged in?")]
    NoDevice,
    #[error("security key HID error {0:#04x}")]
    Hid(u8),
    #[error("no response from the security key")]
    Timeout,
    #[error("the security key requires a PIN, which is not supported yet")]
    PinRequired,
    #[error("the security key requires user verification, which is not supported yet")]
    UvRequired,
    #[error("the security key denied the request (was it touched in time?)")]
    Denied,
    #[error("the security key does not support this operation")]
    Unsupported,
    #[error("the security key has no matching credential")]
    NoCredential,
    #[error("security key returned CTAP error {0:#04x}")]
    Ctap(u8),
    #[error("malformed CBOR from the security key: {0}")]
    Cbor(String),
    #[error("malformed reply from the security key: {0}")]
    Protocol(&'static str),
    #[error("reply of {0} bytes exceeds the {MAX_MESSAGE}-byte limit")]
    TooLarge(usize),
    #[error("unexpected CTAPHID message (cmd {cmd:#04x}, expected {expected:#04x})")]
    Unexpected { cmd: u8, expected: u8 },
    #[error("malformed ECDSA signature from the security key")]
    Signature,
}

/// Translate a CTAP status byte (the first byte of a CTAP2 reply) into an
/// error, or `None` on success.
pub(crate) fn ctap_status(status: u8) -> Option<FidoError> {
    if status == 0 {
        return None;
    }
    Some(match status {
        0x31 | 0x33 | 0x36 | 0x37 | 0x38 => FidoError::PinRequired,
        0x3f | 0x3c => FidoError::UvRequired,
        0x27 | 0x2f | 0x3a | 0x2d => FidoError::Denied,
        0x2e => FidoError::NoCredential,
        0x26 | 0x2b | 0x2c => FidoError::Unsupported,
        other => FidoError::Ctap(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctap_status_maps_each_code() {
        assert!(ctap_status(0x00).is_none());
        for code in [0x31, 0x33, 0x36, 0x37, 0x38] {
            assert!(
                matches!(ctap_status(code), Some(FidoError::PinRequired)),
                "{code:#04x}"
            );
        }
        for code in [0x3f, 0x3c] {
            assert!(
                matches!(ctap_status(code), Some(FidoError::UvRequired)),
                "{code:#04x}"
            );
        }
        for code in [0x27, 0x2f, 0x3a, 0x2d] {
            assert!(
                matches!(ctap_status(code), Some(FidoError::Denied)),
                "{code:#04x}"
            );
        }
        assert!(matches!(ctap_status(0x2e), Some(FidoError::NoCredential)));
        for code in [0x26, 0x2b, 0x2c] {
            assert!(
                matches!(ctap_status(code), Some(FidoError::Unsupported)),
                "{code:#04x}"
            );
        }
        for code in [0x01, 0x7f] {
            assert!(
                matches!(ctap_status(code), Some(FidoError::Ctap(c)) if c == code),
                "{code:#04x}"
            );
        }
    }
}
