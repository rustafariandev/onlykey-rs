//! SSH agent protocol handling and the unix-socket server.

pub mod extension;
pub mod local;
pub mod server;
pub mod sk;
pub mod wire;

pub use extension::{Extension, ExtensionContext, ExtensionReply};
pub use local::{
    DsaLocalKey, EcdsaLocalKey, Ed25519LocalKey, LocalKey, LocalKeyError, LocalKeyRef,
};
pub use server::{
    Agent, Opener, SkOpener, SocketGuard, bind_socket, default_socket_path, ephemeral_socket_path,
    serve,
};
pub use sk::SkKey;
