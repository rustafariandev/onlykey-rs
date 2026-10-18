//! Talk to an [OnlyKey](https://onlykey.io) hardware token to derive SSH keys
//! and sign with them. The `okagent` crate runs an SSH agent on top of this.
//!
//! The OnlyKey derives a key pair on the device from an identity string such
//! as `ferris@example.com`; the private key never leaves the token, and every
//! signature must be confirmed by entering a 3-digit challenge on its buttons.
//! Given the same identity and curve this crate derives exactly the same
//! public key as the Python `onlykey-agent`. Keys written into one of the
//! token's ECC or RSA slots with the OnlyKey app ("stored keys") can be used
//! the same way; see [`KeySpec::stored`] and [`KeySpec::rsa`].
//!
//! The [`fido`] module is a small pure-Rust CTAP2 client for FIDO
//! security-key SSH keys (`sk-ssh-ed25519@openssh.com` and
//! `sk-ecdsa-sha2-nistp256@openssh.com`): touch required, no C library
//! involved.
//!
//! # Deriving a key and signing
//!
//! ```no_run
//! use onlykey_agent::ssh_key::HashAlg;
//! use onlykey_agent::{Curve, KeySpec, OnlyKey, challenge::TtyPrompt};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = KeySpec::derived("ferris@example.com".parse()?, Curve::Ed25519);
//! let mut device = OnlyKey::open()?;           // finds the token, syncs its clock
//! let public = device.ssh_public_key(&key)?;
//! println!("{}", public.to_openssh()?);       // authorized_keys line
//!
//! // Prompts on the terminal, waits for the button presses, verifies the result.
//! // The hash only matters for RSA keys.
//! let sig = device.ssh_sign(&key, &public, b"hello", HashAlg::Sha512, None, &TtyPrompt)?;
//! assert_eq!(sig.algorithm(), onlykey_agent::ssh_key::Algorithm::Ed25519);
//!
//! // Keys the OnlyKey app wrote into slots ECC3 and RSA1, named after the same identity.
//! let stored = KeySpec::stored("ferris@example.com".parse()?, Curve::Ed25519, "ECC3".parse()?);
//! println!("{}", device.ssh_public_key(&stored)?.to_openssh()?);
//! let rsa = KeySpec::rsa("ferris@example.com".parse()?, "RSA1".parse()?);
//! println!("{}", device.ssh_public_key(&rsa)?.to_openssh()?);
//! # Ok(()) }
//! ```
//!
//! # Layers
//!
//! - [`protocol`]: encoding and classification of the raw 64-byte HID reports.
//! - [`transport`]: [`HidTransport`], the seam between protocol and USB stack;
//!   [`transport::HidapiTransport`] for hardware, and `transport::fake` for
//!   tests (with the `test-util` feature).
//! - [`device`]: [`OnlyKey`], the handshake and the two operations the agent
//!   needs, [`OnlyKey::public_key`] and [`OnlyKey::sign`].
//! - [`identity`], [`keys`]: identity parsing and hashing, curves and slots
//!   ([`KeySpec`]), SSH encoding.
//! - [`challenge`]: how the 3-digit challenge reaches the user.
//! - [`fido`]: the CTAPHID/CTAP2 client that signs with a FIDO authenticator
//!   when an `sk-` key is served.
//!
//! Any [`HidTransport`] implementation can stand in for the hardware, which is
//! how okagent's test suite drives the full agent with a fake token.

pub mod challenge;
pub mod device;
pub mod fido;
pub mod identity;
pub mod keys;
pub mod protocol;
pub mod transport;

pub use challenge::{Challenge, ChallengeSink, ConfirmRequest};
pub use device::{DeviceError, OnlyKey, Timeouts, challenge_digits};
pub use identity::{
    Curve, EccSlot, Identity, IdentityError, KeyKind, KeySource, KeySpec, RsaSlot, Slot,
};
pub use protocol::{DeviceStatus, RawPublicKey};
pub use transport::{HidTransport, TransportError};

/// Re-exported so callers can name [`ssh_key::PublicKey`] and
/// [`ssh_key::Signature`] without pinning the same version themselves.
pub use ssh_key;
