//! CTAP2 `authenticatorCredentialManagement`: listing the resident
//! (discoverable) credentials an authenticator holds.
//!
//! `ssh-keygen -O resident` stores the key on the authenticator, and `ssh-add
//! -K` reads it back. OpenSSH's reading loses whether the key was enrolled
//! with `-O verify-required`; this module recovers it by asking for the
//! credential without a PIN: a credential that requires user verification
//! stays hidden from such a request. A reported credProtect level of 3 says
//! as much without asking, but a lower one is not taken on trust: a SoloKeys
//! Solo (firmware 4.1.5) reports level 1 for a credential it hides.
//!
//! Every enumeration starts with a PIN token from
//! [`super::pin::pin_token_interactive`]. CTAP2.1 authenticators answer
//! command 0x0A; CTAP2.1-preview ones the preview command 0x41, which takes
//! the same requests.

use super::FidoError;
use super::ctap::get_assertion;
use super::ctaphid::CtapHid;
use super::pin::{
    CosePublicKey, Info, PinProtocol, cbor_error, command, decode_cose_public_key, definite_map,
};
use crate::transport::HidTransport;
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

/// `authenticatorCredentialManagement` in CTAP2.1.
pub const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
/// The CTAP2.1-preview command byte for the same requests.
pub const CREDENTIAL_MANAGEMENT_PREVIEW: u8 = 0x41;

const ENUMERATE_RPS_BEGIN: u8 = 0x02;
const ENUMERATE_RPS_GET_NEXT: u8 = 0x03;
const ENUMERATE_CREDENTIALS_BEGIN: u8 = 0x04;
const ENUMERATE_CREDENTIALS_GET_NEXT: u8 = 0x05;

/// The credProtect level that hides a credential from requests without
/// user verification: `userVerificationRequired`.
pub const CRED_PROTECT_UV_REQUIRED: u8 = 3;

/// `CTAP1_ERR_INVALID_COMMAND`, as a device answers a command byte it does
/// not know.
const INVALID_COMMAND: u8 = 0x01;

/// A relying party with resident credentials: its ID and the SHA-256 of it.
type RelyingParty = (String, [u8; 32]);

/// A resident credential as credential management lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentCredential {
    /// The relying party, which for an SSH key is its application (`ssh:…`).
    pub rp_id: String,
    /// The user name it was enrolled for, if any.
    pub user_name: Option<String>,
    /// The credential ID, which is the SSH key handle.
    pub credential_id: Vec<u8>,
    pub public_key: CosePublicKey,
    /// The credProtect level, when the authenticator reports it.
    pub cred_protect: Option<u8>,
}

/// The credential management command byte `info` advertises, preferring
/// CTAP2.1's over the preview's; `None` when the authenticator has neither.
pub fn command_byte(info: &Info) -> Option<u8> {
    if info.cred_mgmt {
        Some(CREDENTIAL_MANAGEMENT)
    } else if info.cred_mgmt_preview {
        Some(CREDENTIAL_MANAGEMENT_PREVIEW)
    } else {
        None
    }
}

/// Every resident credential the authenticator holds, authorised by a PIN
/// token from `protocol`.
///
/// `info` picks the command byte. A CTAP2.1-preview key that lists
/// `credMgmt` but does not know 0x0A is asked again with 0x41.
pub fn enumerate<T: HidTransport>(
    hid: &mut CtapHid<T>,
    info: &Info,
    protocol: PinProtocol,
    token: &[u8],
) -> Result<Vec<ResidentCredential>, FidoError> {
    let cmd = command_byte(info).ok_or(FidoError::Unsupported)?;
    let rps = match enumerate_rps(hid, cmd, protocol, token) {
        Err(FidoError::Ctap(INVALID_COMMAND))
            if cmd == CREDENTIAL_MANAGEMENT
                && info.versions.iter().any(|v| v == "FIDO_2_1_PRE") =>
        {
            tracing::debug!("credential management 0x0A unknown; trying the preview command");
            return enumerate_with(hid, CREDENTIAL_MANAGEMENT_PREVIEW, protocol, token);
        }
        result => result?,
    };
    enumerate_credentials_of(hid, cmd, protocol, token, rps)
}

fn enumerate_with<T: HidTransport>(
    hid: &mut CtapHid<T>,
    cmd: u8,
    protocol: PinProtocol,
    token: &[u8],
) -> Result<Vec<ResidentCredential>, FidoError> {
    let rps = enumerate_rps(hid, cmd, protocol, token)?;
    enumerate_credentials_of(hid, cmd, protocol, token, rps)
}

fn enumerate_credentials_of<T: HidTransport>(
    hid: &mut CtapHid<T>,
    cmd: u8,
    protocol: PinProtocol,
    token: &[u8],
    rps: Vec<RelyingParty>,
) -> Result<Vec<ResidentCredential>, FidoError> {
    tracing::debug!(
        command = format!("{cmd:#04x}"),
        rps = rps.len(),
        "listed relying parties"
    );
    let mut credentials = Vec::new();
    for (rp_id, rp_id_hash) in rps {
        credentials.extend(enumerate_credentials(
            hid,
            cmd,
            protocol,
            token,
            &rp_id,
            &rp_id_hash,
        )?);
    }
    Ok(credentials)
}

/// Whether `credential` signs only for a verified user: a reported
/// credProtect level of 3, or else a silent, PIN-less getAssertion that
/// finds the credential hidden. No touch is needed.
pub fn needs_verification<T: HidTransport>(
    hid: &mut CtapHid<T>,
    credential: &ResidentCredential,
) -> Result<bool, FidoError> {
    if credential.cred_protect == Some(CRED_PROTECT_UV_REQUIRED) {
        return Ok(true);
    }
    let probe = get_assertion(
        hid,
        &credential.rp_id,
        &[0; 32],
        &credential.credential_id,
        false,
        &|| {},
    );
    tracing::debug!(
        rp = credential.rp_id,
        cred_protect = ?credential.cred_protect,
        found = probe.is_ok(),
        "probed for the credential without a PIN"
    );
    match probe {
        Ok(_) => Ok(false),
        Err(FidoError::NoCredential) => Ok(true),
        Err(e) => Err(e),
    }
}

/// The relying parties with resident credentials, with their RP ID hashes.
fn enumerate_rps<T: HidTransport>(
    hid: &mut CtapHid<T>,
    cmd: u8,
    protocol: PinProtocol,
    token: &[u8],
) -> Result<Vec<RelyingParty>, FidoError> {
    let first = match command(
        hid,
        &request(cmd, ENUMERATE_RPS_BEGIN, None, Some((protocol, token)))?,
    ) {
        // An authenticator with no resident credentials says so this way.
        Err(FidoError::NoCredential) => return Ok(Vec::new()),
        result => result?,
    };
    let (rp, total) = parse_rp(&first)?;
    let mut rps = vec![rp];
    for _ in 1..total.unwrap_or(1) {
        let next = command(hid, &request(cmd, ENUMERATE_RPS_GET_NEXT, None, None)?)?;
        rps.push(parse_rp(&next)?.0);
    }
    Ok(rps)
}

/// The resident credentials of one relying party.
fn enumerate_credentials<T: HidTransport>(
    hid: &mut CtapHid<T>,
    cmd: u8,
    protocol: PinProtocol,
    token: &[u8],
    rp_id: &str,
    rp_id_hash: &[u8; 32],
) -> Result<Vec<ResidentCredential>, FidoError> {
    let params = rp_params(rp_id_hash)?;
    let first = match command(
        hid,
        &request(
            cmd,
            ENUMERATE_CREDENTIALS_BEGIN,
            Some(&params),
            Some((protocol, token)),
        )?,
    ) {
        Err(FidoError::NoCredential) => return Ok(Vec::new()),
        result => result?,
    };
    let (credential, total) = parse_credential(&first, rp_id)?;
    let mut credentials = vec![credential];
    for _ in 1..total.unwrap_or(1) {
        let next = command(
            hid,
            &request(cmd, ENUMERATE_CREDENTIALS_GET_NEXT, None, None)?,
        )?;
        credentials.push(parse_credential(&next, rp_id)?.0);
    }
    Ok(credentials)
}

/// `subCommandParams` for enumerating one RP's credentials: `{1: rpIDHash}`.
fn rp_params(rp_id_hash: &[u8; 32]) -> Result<Vec<u8>, FidoError> {
    let mut params = Vec::new();
    Encoder::new(&mut params)
        .map(1)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.bytes(rp_id_hash))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    Ok(params)
}

/// A credential management request: `subCommand` (1), `subCommandParams`
/// (2, already encoded) and, when authorised, `pinUvAuthProtocol` (3) and
/// `pinUvAuthParam` (4) over `subCommand || subCommandParams`.
fn request(
    cmd: u8,
    sub_command: u8,
    params: Option<&[u8]>,
    auth: Option<(PinProtocol, &[u8])>,
) -> Result<Vec<u8>, FidoError> {
    let mut buffer = vec![cmd];
    let pairs = 1 + u64::from(params.is_some()) + if auth.is_some() { 2 } else { 0 };
    let mut e = Encoder::new(&mut buffer);
    e.map(pairs)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.u8(sub_command))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    if let Some(params) = params {
        e.u8(2).map_err(|e| FidoError::Cbor(e.to_string()))?;
        e.writer_mut().extend_from_slice(params);
    }
    if let Some((protocol, token)) = auth {
        let mut message = vec![sub_command];
        message.extend_from_slice(params.unwrap_or_default());
        let param = protocol.authenticate(token, &message);
        e.u8(3)
            .and_then(|e| e.u8(protocol.number()))
            .and_then(|e| e.u8(4))
            .and_then(|e| e.bytes(&param))
            .map_err(|e| FidoError::Cbor(e.to_string()))?;
    }
    Ok(buffer)
}

/// One relying party: `rp` (3) with its `id`, `rpIDHash` (4) and, in the
/// first reply, `totalRPs` (5).
fn parse_rp(cbor: &[u8]) -> Result<(RelyingParty, Option<u64>), FidoError> {
    let mut d = Decoder::new(cbor);
    let mut id = None;
    let mut hash = None;
    let mut total = None;
    for _ in 0..definite_map(&mut d)? {
        match d.u8().map_err(cbor_error)? {
            3 => {
                for _ in 0..definite_map(&mut d)? {
                    match d.str().map_err(cbor_error)? {
                        "id" => id = Some(d.str().map_err(cbor_error)?.to_owned()),
                        _ => d.skip().map_err(cbor_error)?,
                    }
                }
            }
            4 => {
                let bytes = d.bytes().map_err(cbor_error)?;
                hash = Some(
                    <[u8; 32]>::try_from(bytes)
                        .map_err(|_| FidoError::Protocol("bad RP ID hash length"))?,
                );
            }
            5 => total = Some(d.u64().map_err(cbor_error)?),
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    let id = id.ok_or(FidoError::Protocol("relying party without an id"))?;
    let hash = hash.unwrap_or_else(|| Sha256::digest(id.as_bytes()).into());
    Ok(((id, hash), total))
}

/// One credential: `user` (6), `credentialID` (7), `publicKey` (8),
/// `totalCredentials` (9, first reply only) and `credProtect` (10).
fn parse_credential(
    cbor: &[u8],
    rp_id: &str,
) -> Result<(ResidentCredential, Option<u64>), FidoError> {
    let mut d = Decoder::new(cbor);
    let mut user_name = None;
    let mut credential_id = None;
    let mut public_key = None;
    let mut total = None;
    let mut cred_protect = None;
    for _ in 0..definite_map(&mut d)? {
        match d.u8().map_err(cbor_error)? {
            6 => {
                for _ in 0..definite_map(&mut d)? {
                    match d.str().map_err(cbor_error)? {
                        "name" => user_name = Some(d.str().map_err(cbor_error)?.to_owned()),
                        _ => d.skip().map_err(cbor_error)?,
                    }
                }
            }
            7 => {
                for _ in 0..definite_map(&mut d)? {
                    match d.str().map_err(cbor_error)? {
                        "id" => credential_id = Some(d.bytes().map_err(cbor_error)?.to_vec()),
                        _ => d.skip().map_err(cbor_error)?,
                    }
                }
            }
            8 => public_key = Some(decode_cose_public_key(&mut d)?),
            9 => total = Some(d.u64().map_err(cbor_error)?),
            10 => {
                let level = d.u64().map_err(cbor_error)?;
                cred_protect = Some(u8::try_from(level).unwrap_or(u8::MAX));
            }
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    let credential = ResidentCredential {
        rp_id: rp_id.to_owned(),
        user_name,
        credential_id: credential_id
            .ok_or(FidoError::Protocol("resident credential without an id"))?,
        public_key: public_key.ok_or(FidoError::Protocol(
            "resident credential without a public key",
        ))?,
        cred_protect,
    };
    Ok((credential, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_byte_prefers_ctap_2_1() {
        let mut info = Info::default();
        assert_eq!(command_byte(&info), None);
        info.cred_mgmt_preview = true;
        assert_eq!(command_byte(&info), Some(CREDENTIAL_MANAGEMENT_PREVIEW));
        info.cred_mgmt = true;
        assert_eq!(command_byte(&info), Some(CREDENTIAL_MANAGEMENT));
    }

    /// The authorised `enumerateCredentialsBegin`, byte for byte, with the
    /// HMAC computed with Python's `hmac` over `04 || a1 01 58 20 <hash>`.
    #[test]
    fn enumerate_credentials_begin_matches_canonical_bytes() {
        let params = rp_params(&[0x11; 32]).unwrap();
        let request = request(
            CREDENTIAL_MANAGEMENT,
            ENUMERATE_CREDENTIALS_BEGIN,
            Some(&params),
            Some((PinProtocol::V1, &[0x44; 16])),
        )
        .unwrap();
        let expected = [
            "0a", // authenticatorCredentialManagement
            "a4", // map(4)
            "01",
            "04", // subCommand: enumerateCredentialsBegin
            "02",
            "a1",
            "01",
            "5820",
            &"11".repeat(32), // {1: rpIDHash}
            "03",
            "01", // pinUvAuthProtocol 1
            "04",
            "50",
            ENUMERATE_CREDENTIALS_HMAC, // pinUvAuthParam
        ]
        .concat();
        assert_eq!(hex::encode(request), expected);
    }

    const ENUMERATE_CREDENTIALS_HMAC: &str = "7e50f2976a659bf7bac25af367ced8e3";

    #[test]
    fn get_next_requests_carry_only_the_subcommand() {
        let request = request(
            CREDENTIAL_MANAGEMENT_PREVIEW,
            ENUMERATE_RPS_GET_NEXT,
            None,
            None,
        )
        .unwrap();
        assert_eq!(hex::encode(request), "41a10103");
    }

    fn rp_reply(id: &str, total: Option<u64>) -> Vec<u8> {
        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        e.map(if total.is_some() { 3 } else { 2 })
            .and_then(|e| e.u8(3))
            .and_then(|e| e.map(1))
            .and_then(|e| e.str("id"))
            .and_then(|e| e.str(id))
            .and_then(|e| e.u8(4))
            .and_then(|e| e.bytes(&Sha256::digest(id.as_bytes())))
            .unwrap();
        if let Some(total) = total {
            e.u8(5).and_then(|e| e.u64(total)).unwrap();
        }
        cbor
    }

    #[test]
    fn parses_relying_parties() {
        let ((id, hash), total) = parse_rp(&rp_reply("ssh:okagent-test", Some(2))).unwrap();
        assert_eq!(id, "ssh:okagent-test");
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(b"ssh:okagent-test")));
        assert_eq!(total, Some(2));
        assert_eq!(parse_rp(&rp_reply("ssh:", None)).unwrap().1, None);
    }

    /// A credential reply with an Ed25519 or P-256 key, with or without
    /// `totalCredentials` and `credProtect`.
    pub(crate) fn credential_reply(
        key: &CosePublicKey,
        total: Option<u64>,
        cred_protect: Option<u8>,
    ) -> Vec<u8> {
        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        let pairs = 3 + u64::from(total.is_some()) + u64::from(cred_protect.is_some());
        e.map(pairs)
            .and_then(|e| e.u8(6))
            .and_then(|e| e.map(2))
            .and_then(|e| e.str("id"))
            .and_then(|e| e.bytes(&[0; 32]))
            .and_then(|e| e.str("name"))
            .and_then(|e| e.str("openssh"))
            .and_then(|e| e.u8(7))
            .and_then(|e| e.map(2))
            .and_then(|e| e.str("id"))
            .and_then(|e| e.bytes(&[0xC1; 48]))
            .and_then(|e| e.str("type"))
            .and_then(|e| e.str("public-key"))
            .and_then(|e| e.u8(8))
            .unwrap();
        match key {
            CosePublicKey::Ed25519(x) => {
                e.map(4)
                    .and_then(|e| e.i8(1))
                    .and_then(|e| e.i8(1))
                    .and_then(|e| e.i8(3))
                    .and_then(|e| e.i8(-8))
                    .and_then(|e| e.i8(-1))
                    .and_then(|e| e.i8(6))
                    .and_then(|e| e.i8(-2))
                    .and_then(|e| e.bytes(x))
                    .unwrap();
            }
            CosePublicKey::P256(key) => super::super::pin::encode_cose_key(&mut e, key).unwrap(),
        }
        if let Some(total) = total {
            e.u8(9).and_then(|e| e.u64(total)).unwrap();
        }
        if let Some(level) = cred_protect {
            e.u8(10).and_then(|e| e.u8(level)).unwrap();
        }
        cbor
    }

    use crate::fido::fake::FakeFido;
    use crate::fido::pin::{self, get_info};

    /// List the fake's resident credentials with its PIN, as the command
    /// does, and say whether the one found needs verification.
    fn list(device: FakeFido) -> (Vec<ResidentCredential>, bool, FakeFido) {
        let mut hid = CtapHid::new(device);
        let info = get_info(&mut hid).unwrap();
        let protocol = info.protocol().unwrap();
        let token = pin::pin_token(&mut hid, protocol, "1234", None).unwrap();
        let credentials = enumerate(&mut hid, &info, protocol, &token).unwrap();
        let verify = needs_verification(&mut hid, &credentials[0]).unwrap();
        (credentials, verify, hid.into_transport())
    }

    fn resident_fake(cred_protect: u8) -> FakeFido {
        FakeFido::new(&[0x42; 32], "ssh:okagent-test-uv", &[9, 8, 7], 0x01)
            .with_pin("1234", 8, &[1])
            .resident("openssh", cred_protect)
    }

    #[test]
    fn lists_a_resident_credential_requiring_verification() {
        let device = resident_fake(CRED_PROTECT_UV_REQUIRED);
        let public = device.public();
        let (credentials, verify, _) = list(device);
        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];
        assert_eq!(credential.rp_id, "ssh:okagent-test-uv");
        assert_eq!(credential.user_name.as_deref(), Some("openssh"));
        assert_eq!(credential.credential_id, [9, 8, 7]);
        assert_eq!(credential.public_key, CosePublicKey::Ed25519(public));
        assert_eq!(credential.cred_protect, Some(3));
        assert!(verify);
    }

    /// Without a reported level, a silent probe without a PIN finds the
    /// credential hidden, which means it needs verification.
    #[test]
    fn a_hidden_credential_is_found_by_the_probe() {
        let (credentials, verify, _) =
            list(resident_fake(CRED_PROTECT_UV_REQUIRED).without_cred_protect_in_listings());
        assert_eq!(credentials[0].cred_protect, None);
        assert!(verify);
        let (_, verify, _) = list(resident_fake(1).without_cred_protect_in_listings());
        assert!(!verify);
    }

    #[test]
    fn a_lower_cred_protect_level_needs_no_verification() {
        let (credentials, verify, device) = list(resident_fake(1));
        assert_eq!(credentials[0].cred_protect, Some(1));
        assert!(!verify);
        // The probe found it, without asking for a touch.
        assert_eq!(device.requests(), 1);
    }

    /// A Solo reports level 1 for a credential it hides; the probe is
    /// believed over the reported level.
    #[test]
    fn a_misreported_level_is_corrected_by_the_probe() {
        let (credentials, verify, _) =
            list(resident_fake(CRED_PROTECT_UV_REQUIRED).reporting_cred_protect(1));
        assert_eq!(credentials[0].cred_protect, Some(1));
        assert!(verify);
    }

    /// A reported level 3 needs no probe.
    #[test]
    fn a_reported_level_three_is_trusted() {
        let (_, verify, device) = list(resident_fake(CRED_PROTECT_UV_REQUIRED));
        assert!(verify);
        assert_eq!(device.requests(), 0);
    }

    /// A preview key that lists `credMgmt` but knows only 0x41 is asked
    /// again with the preview command.
    #[test]
    fn falls_back_to_the_preview_command() {
        let (credentials, _, _) =
            list(resident_fake(CRED_PROTECT_UV_REQUIRED).credential_management_preview_only());
        assert_eq!(credentials.len(), 1);
    }

    #[test]
    fn enumeration_needs_a_valid_token() {
        let mut hid = CtapHid::new(resident_fake(3));
        let info = get_info(&mut hid).unwrap();
        let result = enumerate(&mut hid, &info, PinProtocol::V1, &[0; 32]);
        assert!(
            matches!(result, Err(FidoError::PinAuthInvalid)),
            "{result:?}"
        );
    }

    #[test]
    fn parses_credentials_with_either_key_type() {
        let ed = CosePublicKey::Ed25519([0x5A; 32]);
        let (credential, total) =
            parse_credential(&credential_reply(&ed, Some(1), Some(3)), "ssh:x").unwrap();
        assert_eq!(credential.rp_id, "ssh:x");
        assert_eq!(credential.user_name.as_deref(), Some("openssh"));
        assert_eq!(credential.credential_id, vec![0xC1; 48]);
        assert_eq!(credential.public_key, ed);
        assert_eq!(credential.cred_protect, Some(3));
        assert_eq!(total, Some(1));

        let p256 = CosePublicKey::P256(
            p256::SecretKey::from_slice(&[0x22; 32])
                .unwrap()
                .public_key(),
        );
        let (credential, total) =
            parse_credential(&credential_reply(&p256, None, None), "ssh:").unwrap();
        assert_eq!(credential.public_key, p256);
        assert_eq!(credential.cred_protect, None);
        assert_eq!(total, None);
    }
}
