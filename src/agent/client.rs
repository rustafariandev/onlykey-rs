//! A minimal client of the SSH agent protocol, for adding keys to a running
//! agent (okagent's or OpenSSH's) the way `ssh-add` does.

use super::wire;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("cannot connect to the agent at {path}: {source}")]
    Connect { path: PathBuf, source: io::Error },
    #[error("agent connection failed: {0}")]
    Io(#[from] io::Error),
    #[error("bad reply from the agent: {0}")]
    Frame(#[from] wire::FrameError),
    #[error("the agent closed the connection without replying")]
    Closed,
    #[error("the agent refused the key")]
    Refused,
}

/// Add a key with `SSH2_AGENTC_ADD_IDENTITY`. `body` is what follows the
/// message type: the key type, the key and its comment.
pub fn add_identity(socket: &Path, body: &[u8]) -> Result<(), ClientError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| ClientError::Connect {
        path: socket.to_owned(),
        source,
    })?;
    let mut request = Vec::with_capacity(1 + body.len());
    request.push(wire::SSH2_AGENTC_ADD_IDENTITY);
    request.extend_from_slice(body);
    wire::write_frame(&mut stream, &request)?;
    match wire::read_frame(&mut stream)?.as_deref() {
        Some([wire::SSH_AGENT_SUCCESS]) => Ok(()),
        Some(_) => Err(ClientError::Refused),
        None => Err(ClientError::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, Opener, bind_socket, serve};
    use crate::challenge::RecordingSink;
    use crate::fido::credman::ResidentCredential;
    use crate::fido::pin::CosePublicKey;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A resident key added over a socket is served, and a malformed body
    /// is refused.
    #[test]
    fn adds_a_key_to_a_running_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let (listener, _guard) = bind_socket(&path).unwrap();
        let opener: Opener = Arc::new(|| panic!("OnlyKey must not be opened"));
        let agent = Arc::new(Agent::new(
            Vec::new(),
            opener,
            Arc::new(RecordingSink::default()),
        ));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = {
            let agent = Arc::clone(&agent);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || serve(listener, agent, shutdown))
        };

        let credential = ResidentCredential {
            rp_id: "ssh:okagent-test".into(),
            user_name: None,
            credential_id: vec![1, 2, 3],
            public_key: CosePublicKey::Ed25519([0x5A; 32]),
            cred_protect: None,
        };
        let (public, body) = crate::agent::sk::resident_key(&credential, true).unwrap();
        add_identity(&path, &body).unwrap();
        let served = agent.public_keys();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].key_data(), public.key_data());
        assert_eq!(served[0].comment(), "ssh:okagent-test");

        assert!(matches!(
            add_identity(&path, b"garbage"),
            Err(ClientError::Refused)
        ));
        assert!(matches!(
            add_identity(&dir.path().join("missing.sock"), &body),
            Err(ClientError::Connect { .. })
        ));

        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }
}
