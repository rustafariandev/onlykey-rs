//! SSH agent wire protocol: framing, the two requests this agent serves, and
//! their replies (draft-miller-ssh-agent).

use ssh_encoding::{Decode, Encode};
use ssh_key::{HashAlg, PublicKey, Signature};
use std::io::{self, Read, Write};
use thiserror::Error;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
/// Sign request flags asking for `rsa-sha2-256` / `rsa-sha2-512`.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// The hash a sign request asks for on an RSA key. `None` is plain
/// `ssh-rsa` (SHA-1), which the token cannot produce. When both flags are
/// set SHA-256 wins, as in OpenSSH's agent.
pub fn rsa_hash(flags: u32) -> Option<HashAlg> {
    if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        Some(HashAlg::Sha256)
    } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        Some(HashAlg::Sha512)
    } else {
        None
    }
}

/// Largest frame accepted from a client (OpenSSH uses the same bound).
pub const MAX_FRAME: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("empty request")]
    Empty,
    #[error("malformed request: {0}")]
    Malformed(#[from] ssh_encoding::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    FrameTooLarge(usize),
}

/// A decoded client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    RequestIdentities,
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Any message type this agent does not implement.
    Unsupported(u8),
}

/// Decode one request body (without its length prefix).
pub fn parse_request(body: &[u8]) -> Result<Request, WireError> {
    let (&kind, mut rest) = body.split_first().ok_or(WireError::Empty)?;
    match kind {
        SSH2_AGENTC_REQUEST_IDENTITIES => Ok(Request::RequestIdentities),
        SSH2_AGENTC_SIGN_REQUEST => {
            let key_blob = Vec::<u8>::decode(&mut rest)?;
            let data = Vec::<u8>::decode(&mut rest)?;
            let flags = u32::decode(&mut rest)?;
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            })
        }
        other => Ok(Request::Unsupported(other)),
    }
}

/// `SSH2_AGENT_IDENTITIES_ANSWER` listing `keys` with their comments.
pub fn identities_answer(keys: &[PublicKey]) -> Vec<u8> {
    let mut out = vec![SSH2_AGENT_IDENTITIES_ANSWER];
    (keys.len() as u32).encode(&mut out).expect("vec write");
    for key in keys {
        let blob = key.to_bytes().expect("vec write");
        blob.encode(&mut out).expect("vec write");
        key.comment().encode(&mut out).expect("vec write");
    }
    out
}

/// `SSH2_AGENT_SIGN_RESPONSE` carrying `sig`.
pub fn sign_response(sig: &Signature) -> Vec<u8> {
    let mut blob = Vec::new();
    sig.encode(&mut blob).expect("vec write");
    let mut out = vec![SSH2_AGENT_SIGN_RESPONSE];
    blob.encode(&mut out).expect("vec write");
    out
}

pub fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// Read one length-prefixed frame. `None` at a clean EOF.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::Wire(WireError::FrameTooLarge(len)));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one length-prefixed frame.
pub fn write_frame(writer: &mut impl Write, body: &[u8]) -> io::Result<()> {
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// Human-readable summary of what a sign request covers, for the challenge
/// prompt. Understands the userauth request blob and the SSHSIG format.
pub fn describe_data(data: &[u8]) -> Option<String> {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        let mut r = rest;
        let namespace = String::decode(&mut r).ok()?;
        return Some(format!("signature in namespace {namespace:?}"));
    }
    let mut r = data;
    let _session_id = Vec::<u8>::decode(&mut r).ok()?;
    let msg_type = u8::decode(&mut r).ok()?;
    if msg_type != 50 {
        return None;
    }
    let user = String::decode(&mut r).ok()?;
    let service = String::decode(&mut r).ok()?;
    let method = String::decode(&mut r).ok()?;
    if method != "publickey" {
        return None;
    }
    Some(format!("{service} login as {user:?}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rsa_hash_follows_flags() {
        use super::*;
        assert_eq!(rsa_hash(0), None);
        assert_eq!(rsa_hash(SSH_AGENT_RSA_SHA2_256), Some(HashAlg::Sha256));
        assert_eq!(rsa_hash(SSH_AGENT_RSA_SHA2_512), Some(HashAlg::Sha512));
        assert_eq!(rsa_hash(6), Some(HashAlg::Sha256));
    }

    use super::*;
    use ssh_key::public::{Ed25519PublicKey, KeyData};

    fn key(byte: u8, comment: &str) -> PublicKey {
        PublicKey::new(KeyData::Ed25519(Ed25519PublicKey([byte; 32])), comment)
    }

    #[test]
    fn parses_request_identities() {
        assert_eq!(parse_request(&[11]).unwrap(), Request::RequestIdentities);
    }

    #[test]
    fn parses_sign_request_with_flags() {
        let mut body = vec![13u8];
        b"KEY".as_slice().encode(&mut body).unwrap();
        b"DATA".as_slice().encode(&mut body).unwrap();
        4u32.encode(&mut body).unwrap();
        assert_eq!(
            parse_request(&body).unwrap(),
            Request::Sign {
                key_blob: b"KEY".to_vec(),
                data: b"DATA".to_vec(),
                flags: 4
            }
        );
        // Truncated flags are a malformed request.
        body.truncate(body.len() - 1);
        assert!(matches!(parse_request(&body), Err(WireError::Malformed(_))));
    }

    #[test]
    fn unknown_and_empty_requests() {
        assert_eq!(
            parse_request(&[27, 1, 2]).unwrap(),
            Request::Unsupported(27)
        );
        assert!(matches!(parse_request(&[]), Err(WireError::Empty)));
    }

    #[test]
    fn identities_answer_layout() {
        let keys = [key(1, "one"), key(2, "two")];
        let out = identities_answer(&keys);
        assert_eq!(out[0], 12);
        assert_eq!(&out[1..5], &2u32.to_be_bytes());
        let mut r = &out[5..];
        for k in &keys {
            let blob = Vec::<u8>::decode(&mut r).unwrap();
            assert_eq!(blob, k.to_bytes().unwrap());
            let comment = String::decode(&mut r).unwrap();
            assert_eq!(comment, k.comment());
        }
        assert!(r.is_empty());
        assert_eq!(identities_answer(&[]), vec![12, 0, 0, 0, 0]);
    }

    #[test]
    fn sign_response_wraps_signature_blob() {
        let sig = Signature::new(ssh_key::Algorithm::Ed25519, vec![9u8; 64]).unwrap();
        let out = sign_response(&sig);
        assert_eq!(out[0], 14);
        let mut r = &out[1..];
        let blob = Vec::<u8>::decode(&mut r).unwrap();
        assert!(r.is_empty());
        let mut b = blob.as_slice();
        assert_eq!(String::decode(&mut b).unwrap(), "ssh-ed25519");
        assert_eq!(Vec::<u8>::decode(&mut b).unwrap(), vec![9u8; 64]);
    }

    #[test]
    fn frames_round_trip_and_reject_oversize() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(buf, b"\x00\x00\x00\x05hello");
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_frame(&mut r).unwrap(), None);

        let huge = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert!(matches!(
            read_frame(&mut huge.as_slice()),
            Err(FrameError::Wire(WireError::FrameTooLarge(_)))
        ));
        assert!(read_frame(&mut b"\x00\x00\x00\x05hel".as_slice()).is_err());
    }

    #[test]
    fn describes_userauth_and_sshsig() {
        let mut blob = Vec::new();
        [1u8; 32].as_slice().encode(&mut blob).unwrap();
        50u8.encode(&mut blob).unwrap();
        "james".encode(&mut blob).unwrap();
        "ssh-connection".encode(&mut blob).unwrap();
        "publickey".encode(&mut blob).unwrap();
        assert_eq!(
            describe_data(&blob).unwrap(),
            "ssh-connection login as \"james\""
        );

        let mut sshsig = b"SSHSIG".to_vec();
        "git".encode(&mut sshsig).unwrap();
        assert_eq!(
            describe_data(&sshsig).unwrap(),
            "signature in namespace \"git\""
        );

        assert_eq!(describe_data(b"garbage"), None);
    }
}
