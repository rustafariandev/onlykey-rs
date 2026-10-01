//! Driving a FIDO2 security key over its USB HID interface.
//!
//! This is a small, self-contained CTAP2 client: it only implements what is
//! needed to sign an SSH challenge with a key that was enrolled earlier. It
//! speaks the CTAPHID framing ([`ctaphid`]), the CTAP2
//! `authenticatorGetAssertion` command ([`ctap`]) and, for keys enrolled with
//! user verification required, `authenticatorClientPIN` ([`pin`]) directly
//! over a [`HidTransport`](crate::transport::HidTransport). No C library is
//! involved.
//!
//! The signature an authenticator returns for an SSH `sk-` key covers
//! `SHA256(application) || flags || counter || SHA256(message)`, exactly what a
//! CTAP2 assertion produces for `clientDataHash = SHA256(message)`. See
//! OpenSSH's `PROTOCOL.u2f`.

pub mod credman;
pub mod ctap;
pub mod ctaphid;
pub(crate) mod der;
pub mod fake;
pub mod pin;

use crate::transport::TransportError;
use ctaphid::MAX_MESSAGE;
use thiserror::Error;

pub use ctap::{Assertion, PinAuth, get_assertion, get_assertion_with_pin};
pub use pin::PinProtocol;

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
    #[error("the security key requires a PIN")]
    PinRequired,
    #[error("wrong PIN for the security key")]
    PinInvalid,
    #[error("a PIN must be 4 to 63 bytes long")]
    PinLength,
    #[error("the security key's PIN is blocked after too many wrong tries; it must be reset")]
    PinBlocked,
    #[error("too many wrong PINs; unplug and replug the security key to try again")]
    PinAuthBlocked,
    #[error("the security key rejected the PIN token (was it replugged?)")]
    PinAuthInvalid,
    #[error("the key needs a PIN, but none is set on the security key")]
    PinNotSet,
    #[error("PIN entry was cancelled")]
    PinCancelled,
    #[error("the key requires user verification (a PIN), but there is no way to ask for one")]
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
        0x31 => FidoError::PinInvalid,
        0x32 => FidoError::PinBlocked,
        0x33 => FidoError::PinAuthInvalid,
        0x34 => FidoError::PinAuthBlocked,
        0x35 => FidoError::PinNotSet,
        0x36..=0x38 => FidoError::PinRequired,
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
        assert!(matches!(ctap_status(0x31), Some(FidoError::PinInvalid)));
        assert!(matches!(ctap_status(0x32), Some(FidoError::PinBlocked)));
        assert!(matches!(ctap_status(0x33), Some(FidoError::PinAuthInvalid)));
        assert!(matches!(ctap_status(0x34), Some(FidoError::PinAuthBlocked)));
        assert!(matches!(ctap_status(0x35), Some(FidoError::PinNotSet)));
        for code in [0x36, 0x37, 0x38] {
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
