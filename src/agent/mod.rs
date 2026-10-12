//! The SSH agent: [`ssh_agent_kit`]'s protocol and server, serving OnlyKey
//! keys ([`onlykey::OnlyKeyBackend`]) and FIDO security keys ([`sk`]).
//!
//! The kit's modules and main types are re-exported here, so callers can
//! write `agent::wire` or `agent::CertKey` without depending on the kit.

pub mod onlykey;
pub mod server;
pub mod sk;

pub use ssh_agent_kit::{
    backend, cert, client, destination, extension, keytype, local, policy, signer, wire,
};

pub use onlykey::{Device, OnlyKeyBackend, Opener};
pub use server::{Agent, AgentError, default_socket_path, ephemeral_socket_path};
pub use sk::{SkBackend, SkDecoder, SkKey, SkOpener};
#[cfg(feature = "dsa")]
pub use ssh_agent_kit::DsaLocalKey;
pub use ssh_agent_kit::{
    AssociatedCerts, BindError, CertError, CertKey, Connection, ConstraintError, ConstraintHop,
    DestinationConstraint, Extension, ExtensionContext, ExtensionReply, HostKeySpec,
    KeyDecodeError, KeyDecoder, KeyRegistry, SessionBinding, SignerRef, SocketError, SocketGuard,
    Userauth, bind_socket, serve,
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
