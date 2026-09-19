//! SSH agent protocol handling and the unix-socket server.

pub mod server;
pub mod wire;

pub use server::{
    Agent, Entry, Opener, SocketGuard, bind_socket, default_socket_path, ephemeral_socket_path,
    serve,
};
