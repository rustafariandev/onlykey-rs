//! The SSH agent: [`ssh_agent_kit`]'s protocol and server, serving OnlyKey
//! keys ([`onlykey::OnlyKeyBackend`]) and FIDO security keys ([`sk`]).
//!
//! The protocol modules are re-exported from the kit under their old names,
//! so `agent::wire`, `agent::cert` and the rest keep working.

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
