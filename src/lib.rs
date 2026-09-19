//! Talk to an [OnlyKey](https://onlykey.io) hardware token to derive SSH keys
//! and sign with them, and run an SSH agent on top of that.
//!
//! The OnlyKey derives a key pair on the device from an identity string such
//! as `james@example.com`; the private key never leaves the token, and every
//! signature must be confirmed by entering a 3-digit challenge on its buttons.
//! Given the same identity and curve this crate derives exactly the same
//! public key as the Python `onlykey-agent`.
//!
//! # Deriving a key and signing
//!
//! ```no_run
//! use onlykey_agent::{Curve, Identity, OnlyKey, challenge::TtyPrompt};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let identity: Identity = "james@example.com".parse()?;
//! let mut device = OnlyKey::open()?;           // finds the token, syncs its clock
//! let key = device.ssh_public_key(&identity, Curve::Ed25519)?;
//! println!("{}", key.to_openssh()?);          // authorized_keys line
//!
//! // Prompts on the terminal, waits for the button presses, verifies the result.
//! let sig = device.ssh_sign(&identity, Curve::Ed25519, &key, b"hello", None, &TtyPrompt)?;
//! assert_eq!(sig.algorithm(), onlykey_agent::ssh_key::Algorithm::Ed25519);
//! # Ok(()) }
//! ```
//!
//! # Running an agent
//!
//! ```no_run
//! use onlykey_agent::agent::{self, Agent, Entry, Opener};
//! use onlykey_agent::{Curve, OnlyKey, challenge::TtyPrompt};
//! use std::sync::{Arc, atomic::AtomicBool};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let entries = vec![Entry { identity: "james@example.com".parse()?, curve: Curve::Ed25519 }];
//! let opener: Opener = Arc::new(|| Ok(OnlyKey::open()?.boxed()));
//! let agent = Arc::new(Agent::new(entries, opener, Arc::new(TtyPrompt)));
//!
//! let path = agent::default_socket_path();
//! let (listener, _guard) = agent::bind_socket(&path)?;   // owner-only socket, unlinked on drop
//! println!("SSH_AUTH_SOCK={}", path.display());
//! agent::serve(listener, agent, Arc::new(AtomicBool::new(false)))?;
//! # Ok(()) }
//! ```
//!
//! # Layers
//!
//! - [`protocol`]: encoding and classification of the raw 64-byte HID reports.
//! - [`transport`]: [`HidTransport`], the seam between protocol and USB stack;
//!   [`transport::HidapiTransport`] for hardware, [`transport::fake`] for tests.
//! - [`device`]: [`OnlyKey`], the handshake and the two operations the agent
//!   needs, [`OnlyKey::derive_public_key`] and [`OnlyKey::sign`].
//! - [`identity`], [`keys`]: identity parsing and hashing, SSH encoding.
//! - [`challenge`]: how the 3-digit challenge reaches the user.
//! - [`agent`]: the SSH agent wire protocol and unix-socket server.
//!
//! Any [`HidTransport`] implementation can stand in for the hardware, which is
//! how the test suite drives the full agent with a fake token.

pub mod agent;
pub mod challenge;
pub mod device;
pub mod identity;
pub mod keys;
pub mod protocol;
pub mod transport;

pub use challenge::{Challenge, ChallengeSink};
pub use device::{DeviceError, OnlyKey, Timeouts, challenge_digits};
pub use identity::{Curve, Identity, IdentityError};
pub use protocol::{DeviceStatus, RawPublicKey};
pub use transport::{HidTransport, TransportError};

/// Re-exported so callers can name [`ssh_key::PublicKey`] and
/// [`ssh_key::Signature`] without pinning the same version themselves.
pub use ssh_key;
