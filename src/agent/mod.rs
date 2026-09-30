//! SSH agent protocol handling and the unix-socket server.

pub mod local;
pub mod server;
pub mod wire;

pub use local::{
    DsaLocalKey, EcdsaLocalKey, Ed25519LocalKey, LocalKey, LocalKeyError, LocalKeyRef,
};
pub use server::{
    Agent, Opener, SocketGuard, bind_socket, default_socket_path, ephemeral_socket_path, serve,
};
