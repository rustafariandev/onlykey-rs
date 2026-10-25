//! The SSH agent: [`ssh_agent_kit`]'s protocol and server, serving OnlyKey
//! keys ([`onlykey::OnlyKeyBackend`]) and FIDO security keys ([`sk`]).
//!
//! The kit's modules and main types are re-exported here, so callers can
//! write `agent::wire` or `agent::CertKey` without depending on the kit.
//!
//! A plain ed25519, RSA or ECDSA (nistp256/384/521) private key, or a DSA one
//! with the `dsa` feature, can also be loaded with `ssh-add FILE`; the agent
//! signs with it in memory, with no token and no challenge. The key types the
//! agent can load are pluggable: implement [`KeyDecoder`] and register it with
//! [`Agent::with_key_type`]. In-memory keys are signed by a
//! [`local::LocalKey`] implementation. [`Extension`] lets callers answer
//! protocol extension requests, the built-in [`destination`] support
//! verifies `session-bind@openssh.com` and enforces `ssh-add -h` destination
//! constraints, and `ssh-add -c` confirmation goes through the
//! [`ChallengeSink`](onlykey_agent::ChallengeSink).
//!
//! ```no_run
//! use okagent::agent::{self, Agent, Opener};
//! use onlykey_agent::{Curve, KeySpec, OnlyKey, challenge::TtyPrompt};
//! use std::sync::{Arc, atomic::AtomicBool};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let entries = vec![KeySpec::derived("ferris@example.com".parse()?, Curve::Ed25519)];
//! let opener: Opener = Arc::new(|| Ok(OnlyKey::open()?.boxed()));
//! let agent = Arc::new(Agent::new(entries, opener, Arc::new(TtyPrompt)));
//!
//! let path = agent::default_socket_path();
//! let (listener, _guard) = agent::bind_socket(&path)?;   // owner-only socket, unlinked on drop
//! println!("SSH_AUTH_SOCK={}", path.display());
//! agent::serve(listener, agent, Arc::new(AtomicBool::new(false)))?;
//! # Ok(()) }
//! ```

pub mod onlykey;
pub mod server;
pub mod sk;

pub use ssh_agent_kit::{
    backend, cert, client, destination, extension, keytype, local, policy, signer, wire,
};

pub use onlykey::{Device, OnlyKeyBackend, Opener};
pub use server::{Agent, AgentError, default_socket_path, ephemeral_socket_path};
#[cfg(windows)]
pub use server::{cygwin_socket_path, default_cygwin_socket_path, ephemeral_cygwin_socket_path};
pub use sk::{SkBackend, SkDecoder, SkKey, SkOpener};
#[cfg(feature = "dsa")]
pub use ssh_agent_kit::DsaLocalKey;
pub use ssh_agent_kit::{
    AssociatedCerts, BindError, CertError, CertKey, Connection, ConstraintError, ConstraintHop,
    DestinationConstraint, Extension, ExtensionContext, ExtensionReply, HostKeySpec,
    KeyDecodeError, KeyDecoder, KeyRegistry, Listener, SessionBinding, SignerRef, SocketError,
    SocketGuard, Userauth, bind_socket, serve,
};
#[cfg(windows)]
pub use ssh_agent_kit::{
    CygwinListener, CygwinStream, bind_cygwin_socket, connect_cygwin, pageant_pipe_name,
    serve_pageant_window,
};
pub use ssh_agent_kit::{
    EcdsaLocalKey, Ed25519LocalKey, LocalKey, LocalKeyError, LocalKeyRef, RsaLocalKey,
};

use std::sync::{Mutex, MutexGuard};

/// Lock `mutex`, carrying on if a thread panicked while holding it: each
/// value guarded in this module is left consistent between statements, so a
/// poisoned lock still holds usable state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}
