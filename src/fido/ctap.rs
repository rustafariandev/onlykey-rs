//! The CTAP2 `authenticatorGetAssertion` command (0x02).
//!
//! The assertion signature covers `authenticatorData || clientDataHash`, and
//! `authenticatorData` is `SHA256(rpId) || flags || signCount || extensions`.
//! That is exactly the blob OpenSSH's `sk-` key types sign, once the SSH
//! agent passes `clientDataHash = SHA256(message)` and `rpId = application`.

use super::FidoError;
use super::ctap_status;
use super::ctaphid::{CTAPHID_CBOR, CtapHid};
use crate::transport::HidTransport;
use minicbor::{Decoder, Encoder};

/// A successful `getAssertion` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// `authenticatorData`: `SHA256(rpId) || flags || signCount || ...`.
    pub auth_data: Vec<u8>,
    /// The signature bytes: DER ECDSA, or 64 raw bytes for Ed25519.
    pub signature: Vec<u8>,
    /// `authenticatorData` flags.
    pub flags: u8,
    /// The signature counter from `authenticatorData`.
    pub counter: u32,
}

/// Ask the authenticator to sign `client_data_hash` with `key_handle`.
///
/// `up` sets the `up` option, so a key enrolled with user presence required
/// waits for a touch. `on_presence` is called once when the device asks.
pub fn get_assertion<T: HidTransport>(
    hid: &mut CtapHid<T>,
    rp_id: &str,
    client_data_hash: &[u8; 32],
    key_handle: &[u8],
    up: bool,
    on_presence: &dyn Fn(),
) -> Result<Assertion, FidoError> {
    let request = encode_request(rp_id, client_data_hash, key_handle, up)?;
    let reply = hid.transact(CTAPHID_CBOR, &request, on_presence)?;
    let (&status, cbor) = reply
        .split_first()
        .ok_or(FidoError::Protocol("empty CTAP reply"))?;
    if let Some(error) = ctap_status(status) {
        return Err(error);
    }
    parse_assertion(cbor)
}

fn encode_request(
    rp_id: &str,
    client_data_hash: &[u8; 32],
    key_handle: &[u8],
    up: bool,
) -> Result<Vec<u8>, FidoError> {
    let mut buffer = Vec::new();
    let mut e = Encoder::new(&mut buffer);
    e.map(4)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.str(rp_id))
        .and_then(|e| e.u8(2))
        .and_then(|e| e.bytes(client_data_hash))
        .and_then(|e| e.u8(3))
        .and_then(|e| e.array(1))
        .and_then(|e| e.map(2))
        .and_then(|e| e.u8(1))
        .and_then(|e| e.str("public-key"))
        .and_then(|e| e.u8(2))
        .and_then(|e| e.bytes(key_handle))
        .and_then(|e| e.u8(5))
        .and_then(|e| e.map(1))
        .and_then(|e| e.str("up"))
        .and_then(|e| e.bool(up))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    Ok(buffer)
}

fn parse_assertion(cbor: &[u8]) -> Result<Assertion, FidoError> {
    let mut d = Decoder::new(cbor);
    let pairs = d
        .map()
        .map_err(cbor_error)?
        .ok_or(FidoError::Protocol("indefinite CTAP reply"))?;
    let mut auth_data = None;
    let mut signature = None;
    for _ in 0..pairs {
        let key = d.u8().map_err(cbor_error)?;
        match key {
            2 => auth_data = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            3 => signature = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    let auth_data = auth_data.ok_or(FidoError::Protocol("assertion without authData"))?;
    let signature = signature.ok_or(FidoError::Protocol("assertion without signature"))?;
    if auth_data.len() < 37 {
        return Err(FidoError::Protocol("short authenticator data"));
    }
    let flags = auth_data[32];
    let counter = u32::from_be_bytes(auth_data[33..37].try_into().expect("slice of four"));
    Ok(Assertion {
        auth_data,
        signature,
        flags,
        counter,
    })
}

fn cbor_error(e: minicbor::decode::Error) -> FidoError {
    FidoError::Cbor(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::Decoder;

    #[test]
    fn request_has_the_expected_shape() {
        let request = encode_request("ssh:", &[0xAB; 32], &[0x01, 0x02], true).unwrap();
        let mut d = Decoder::new(&request);
        assert_eq!(d.map().unwrap(), Some(4));
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "ssh:");
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.bytes().unwrap(), &[0xAB; 32]);
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.array().unwrap(), Some(1));
        assert_eq!(d.map().unwrap(), Some(2));
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "public-key");
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.bytes().unwrap(), &[0x01, 0x02]);
        assert_eq!(d.u8().unwrap(), 5);
        assert_eq!(d.map().unwrap(), Some(1));
        assert_eq!(d.str().unwrap(), "up");
        assert!(d.bool().unwrap());
    }

    #[test]
    fn parses_a_reply_and_extracts_flags_and_counter() {
        let mut auth_data = vec![0x11u8; 32];
        auth_data.push(0x05);
        auth_data.extend_from_slice(&7u32.to_be_bytes());
        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        e.map(2)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&auth_data)
            .unwrap()
            .u8(3)
            .unwrap()
            .bytes(&[0xDE; 64])
            .unwrap();
        let assertion = parse_assertion(&cbor).unwrap();
        assert_eq!(assertion.flags, 0x05);
        assert_eq!(assertion.counter, 7);
        assert_eq!(assertion.signature, vec![0xDE; 64]);
        // The credential entry (key 1) is skipped.
        let mut with_cred = Vec::new();
        let mut e = Encoder::new(&mut with_cred);
        e.map(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .str("public-key")
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&[9u8; 4])
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&auth_data)
            .unwrap()
            .u8(3)
            .unwrap()
            .bytes(&[0xDE; 64])
            .unwrap();
        assert_eq!(parse_assertion(&with_cred).unwrap().counter, 7);
    }
}
