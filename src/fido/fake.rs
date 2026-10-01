//! A software FIDO2 authenticator, for tests.
//!
//! [`FakeFido`] implements [`HidTransport`] but instead of replaying a fixed
//! script it parses the CTAP2 `getAssertion` request and produces a real
//! Ed25519 assertion over `authData || clientDataHash`. That lets the whole
//! agent path — CTAPHID framing, CBOR, signature assembly and verification —
//! run against a device that actually signs, with no hardware.
//!
//! With [`FakeFido::with_pin`] it also answers `authenticatorGetInfo` and the
//! `authenticatorClientPIN` subcommands the agent uses, under both PIN/UV
//! auth protocols, and checks `pinUvAuthParam` on getAssertion. With
//! [`FakeFido::resident`] its credential is a resident one, listed by
//! credential management.

use super::credman::{CREDENTIAL_MANAGEMENT, CREDENTIAL_MANAGEMENT_PREVIEW};
use super::ctap::AUTHENTICATOR_GET_ASSERTION;
use super::ctaphid::{CTAPHID_CANCEL, CTAPHID_CBOR, CTAPHID_INIT, CTAPHID_KEEPALIVE};
use super::pin::{
    self, AUTHENTICATOR_CLIENT_PIN, AUTHENTICATOR_GET_INFO, GET_KEY_AGREEMENT, GET_PIN_TOKEN,
    GET_RETRIES, PinProtocol,
};
use crate::protocol::Report;
use crate::transport::{HidTransport, TransportError};
use minicbor::{Decoder, Encoder};
use p256::SecretKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use signature::Signer;
use ssh_key::private::Ed25519Keypair;
use std::collections::VecDeque;
use std::time::Duration;

/// The channel id a [`FakeFido`] allocates.
const FAKE_CID: u32 = 0x0A0B_0C0D;

/// The `authenticatorData` flag set when the user was verified.
const FLAG_UV: u8 = 0x04;
/// Tries a PIN gets back after a correct entry.
const PIN_RETRIES: u8 = 8;
/// Wrong PINs in a row after which the device wants to be replugged.
const WRONG_PINS_BEFORE_REPLUG: u8 = 3;

/// The PIN state of a [`FakeFido`] built with [`FakeFido::with_pin`].
struct PinState {
    pin: String,
    retries: u8,
    wrong_in_a_row: u8,
    protocols: Vec<u8>,
    key_agreement: SecretKey,
    /// The token handed out by the last good getPINToken.
    token: Option<(PinProtocol, Vec<u8>)>,
    token_requests: u32,
}

/// A fake Ed25519 FIDO2 authenticator holding one credential.
pub struct FakeFido {
    pair: Ed25519Keypair,
    application: String,
    key_handle: Vec<u8>,
    flags: u8,
    counter: u32,
    require_touch: bool,
    cid: u32,
    out: VecDeque<Report>,
    incoming: Vec<u8>,
    /// The command and total length of a message still awaiting
    /// continuation packets.
    pending: Option<(u8, usize)>,
    /// Never reply to a getAssertion; see [`FakeFido::never_touched`].
    never_touched: bool,
    /// A request is outstanding and waiting for a touch that never comes.
    waiting: bool,
    cancelled: bool,
    pin: Option<PinState>,
    id: Option<String>,
    resident: Option<Resident>,
}

/// The resident side of a [`FakeFido`] built with [`FakeFido::resident`].
struct Resident {
    user_name: String,
    cred_protect: u8,
    /// The level credential management lists; `None` leaves it out.
    reported_cred_protect: Option<u8>,
    /// Lists `credMgmt` but answers only the preview command 0x41, as a
    /// CTAP2.1-preview key might.
    preview_only: bool,
}

impl FakeFido {
    /// Build an authenticator whose credential lives in `application` under
    /// `key_handle` and whose signatures report `flags`.
    pub fn new(seed: &[u8; 32], application: &str, key_handle: &[u8], flags: u8) -> Self {
        FakeFido {
            pair: Ed25519Keypair::from_seed(seed),
            application: application.to_owned(),
            key_handle: key_handle.to_vec(),
            flags,
            counter: 1,
            require_touch: false,
            cid: FAKE_CID,
            out: VecDeque::new(),
            incoming: Vec::new(),
            pending: None,
            never_touched: false,
            waiting: false,
            cancelled: false,
            pin: None,
            id: None,
            resident: None,
        }
    }

    /// Give the authenticator a PIN with `retries` tries left, spoken over
    /// PIN/UV auth `protocols` (as getInfo lists them). A getAssertion
    /// carrying a valid `pinUvAuthParam` reports the user verified.
    pub fn with_pin(mut self, pin: &str, retries: u8, protocols: &[u8]) -> Self {
        self.pin = Some(PinState {
            pin: pin.to_owned(),
            retries,
            wrong_in_a_row: 0,
            protocols: protocols.to_vec(),
            key_agreement: SecretKey::random(&mut OsRng),
            token: None,
            token_requests: 0,
        });
        self
    }

    /// Make the credential a resident one enrolled for `user_name` with
    /// credProtect `cred_protect`, listed by credential management. Level 3
    /// hides it from any getAssertion without a valid PIN token.
    pub fn resident(mut self, user_name: &str, cred_protect: u8) -> Self {
        self.resident = Some(Resident {
            user_name: user_name.to_owned(),
            cred_protect,
            reported_cred_protect: Some(cred_protect),
            preview_only: false,
        });
        self
    }

    /// Leave credProtect out of credential listings, as some
    /// CTAP2.1-preview authenticators do.
    pub fn without_cred_protect_in_listings(mut self) -> Self {
        if let Some(resident) = &mut self.resident {
            resident.reported_cred_protect = None;
        }
        self
    }

    /// List credProtect as `level` whatever the credential's real level, as
    /// a SoloKeys Solo (firmware 4.1.5) lists level 1 for a credential it
    /// hides.
    pub fn reporting_cred_protect(mut self, level: u8) -> Self {
        if let Some(resident) = &mut self.resident {
            resident.reported_cred_protect = Some(level);
        }
        self
    }

    /// Answer credential management only on the preview command 0x41,
    /// while still listing `credMgmt`.
    pub fn credential_management_preview_only(mut self) -> Self {
        if let Some(resident) = &mut self.resident {
            resident.preview_only = true;
        }
        self
    }

    /// Report `id` as the transport's identity, as a device path would be.
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_owned());
        self
    }

    /// PIN tries left, if the device has a PIN.
    pub fn pin_retries(&self) -> Option<u8> {
        self.pin.as_ref().map(|p| p.retries)
    }

    /// How many getPINToken requests the device received.
    pub fn pin_token_requests(&self) -> u32 {
        self.pin.as_ref().map_or(0, |p| p.token_requests)
    }

    /// Forget the PIN token, as a device does when it is replugged.
    pub fn power_cycle(&mut self) {
        if let Some(state) = &mut self.pin {
            state.token = None;
            state.wrong_in_a_row = 0;
            state.key_agreement = SecretKey::random(&mut OsRng);
        }
    }

    /// Make the authenticator wait for a touch that never comes: it answers
    /// every read with an `UPNEEDED` keepalive until it is cancelled.
    pub fn never_touched(mut self) -> Self {
        self.never_touched = true;
        self
    }

    /// Whether the host sent `CTAPHID_CANCEL`.
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// How many getAssertion requests the device received.
    pub fn requests(&self) -> u32 {
        self.counter - 1
    }

    /// Make the authenticator send a keepalive (as if waiting for a touch)
    /// before its reply.
    pub fn with_touch(mut self) -> Self {
        self.require_touch = true;
        self
    }

    /// The 32-byte Ed25519 public key of the credential.
    pub fn public(&self) -> [u8; 32] {
        self.pair.public.0
    }

    /// The credential's application string.
    pub fn application(&self) -> &str {
        &self.application
    }

    /// The credential's key handle.
    pub fn key_handle(&self) -> &[u8] {
        &self.key_handle
    }

    fn handle(&mut self, report: &Report) {
        let cid = u32::from_be_bytes(report[..4].try_into().expect("slice of four"));
        let cmd = report[4];
        // Bit 7 marks an initialization packet, as a real device checks.
        if cmd & 0x80 == 0 {
            let Some((cmd, total)) = self.pending else {
                return; // a stray continuation; a real device ignores it
            };
            let remaining = total - self.incoming.len();
            let chunk = remaining.min(59);
            self.incoming.extend_from_slice(&report[5..5 + chunk]);
            if self.incoming.len() == total {
                self.pending = None;
                let message = std::mem::take(&mut self.incoming);
                self.process(cmd, &message);
            }
            return;
        }
        match cmd {
            CTAPHID_INIT => self.reply_init(cid, &report[7..15]),
            CTAPHID_CANCEL => {
                self.cancelled = true;
                self.waiting = false;
                self.out.clear();
            }
            CTAPHID_CBOR => {
                let bcnt = ((report[5] as usize) << 8) | report[6] as usize;
                self.incoming.clear();
                let head = bcnt.min(57);
                self.incoming.extend_from_slice(&report[7..7 + head]);
                if bcnt <= 57 {
                    let message = std::mem::take(&mut self.incoming);
                    self.process(cmd, &message);
                } else {
                    self.pending = Some((cmd, bcnt));
                }
            }
            _ => self.push_message(self.cid, super::ctaphid::CTAPHID_ERROR, &[0x01]),
        }
    }

    fn reply_init(&mut self, request_cid: u32, nonce: &[u8]) {
        self.cid = FAKE_CID;
        let mut payload = Vec::new();
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&FAKE_CID.to_be_bytes());
        payload.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x01]);
        self.push_message(request_cid, CTAPHID_INIT, &payload);
    }

    fn process(&mut self, cmd: u8, message: &[u8]) {
        // A CTAP2 message is a command byte, then that command's CBOR.
        match message.split_first() {
            Some((&AUTHENTICATOR_GET_ASSERTION, params)) => self.get_assertion(cmd, params),
            Some((&AUTHENTICATOR_GET_INFO, _)) => {
                let reply = self.get_info();
                self.push_message(self.cid, cmd, &reply);
            }
            Some((&AUTHENTICATOR_CLIENT_PIN, params)) if self.pin.is_some() => {
                let reply = self.client_pin(params);
                self.push_message(self.cid, cmd, &reply);
            }
            Some((&command @ (CREDENTIAL_MANAGEMENT | CREDENTIAL_MANAGEMENT_PREVIEW), params))
                if self.resident.is_some() =>
            {
                let preview_only = self.resident.as_ref().is_some_and(|r| r.preview_only);
                let reply = if preview_only && command == CREDENTIAL_MANAGEMENT {
                    vec![0x01] // CTAP1_ERR_INVALID_COMMAND
                } else {
                    self.credential_management(params)
                };
                self.push_message(self.cid, cmd, &reply);
            }
            _ => self.push_message(self.cid, cmd, &[0x01]), // CTAP1_ERR_INVALID_COMMAND
        }
    }

    /// `authenticatorGetInfo`: the version, the `clientPin` option and the
    /// PIN protocols.
    fn get_info(&self) -> Vec<u8> {
        let mut reply = vec![0x00];
        let mut e = Encoder::new(&mut reply);
        let entries = if self.pin.is_some() { 3 } else { 1 };
        let resident = self.resident.is_some();
        e.map(entries)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.array(if resident { 2 } else { 1 }))
            .and_then(|e| e.str("FIDO_2_0"))
            .expect("vec write");
        if resident {
            e.str("FIDO_2_1_PRE").expect("vec write");
        }
        if let Some(state) = &self.pin {
            e.u8(4)
                .and_then(|e| e.map(if resident { 2 } else { 1 }))
                .and_then(|e| e.str("clientPin"))
                .and_then(|e| e.bool(true))
                .expect("vec write");
            if resident {
                e.str("credMgmt")
                    .and_then(|e| e.bool(true))
                    .expect("vec write");
            }
            e.u8(6)
                .and_then(|e| e.array(state.protocols.len() as u64))
                .expect("vec write");
            for &protocol in &state.protocols {
                e.u8(protocol).expect("vec write");
            }
        }
        reply
    }

    /// `authenticatorClientPIN`: getRetries, getKeyAgreement and getPINToken.
    fn client_pin(&mut self, params: &[u8]) -> Vec<u8> {
        let Some(request) = parse_client_pin(params) else {
            return vec![0x12]; // CTAP2_ERR_INVALID_CBOR
        };
        let state = self.pin.as_mut().expect("checked by the caller");
        let protocol = match request.protocol {
            1 if state.protocols.contains(&1) => PinProtocol::V1,
            2 if state.protocols.contains(&2) => PinProtocol::V2,
            _ => return vec![0x02], // CTAP1_ERR_INVALID_PARAMETER
        };
        let mut reply = vec![0x00];
        let mut e = Encoder::new(&mut reply);
        match request.sub_command {
            GET_RETRIES => {
                e.map(1)
                    .and_then(|e| e.u8(3))
                    .and_then(|e| e.u8(state.retries))
                    .expect("vec write");
            }
            GET_KEY_AGREEMENT => {
                e.map(1).and_then(|e| e.u8(1)).expect("vec write");
                pin::encode_cose_key(&mut e, &state.key_agreement.public_key()).expect("vec write");
            }
            GET_PIN_TOKEN => {
                state.token_requests += 1;
                if state.retries == 0 {
                    return vec![0x32]; // CTAP2_ERR_PIN_BLOCKED
                }
                if state.wrong_in_a_row >= WRONG_PINS_BEFORE_REPLUG {
                    return vec![0x34]; // CTAP2_ERR_PIN_AUTH_BLOCKED
                }
                let (Some(platform), Some(pin_hash_enc)) =
                    (request.key_agreement, request.pin_hash_enc)
                else {
                    return vec![0x14]; // CTAP2_ERR_MISSING_PARAMETER
                };
                let secret = pin::shared_secret(protocol, &state.key_agreement, &platform);
                // A device makes a fresh key agreement key after each try.
                state.key_agreement = SecretKey::random(&mut OsRng);
                let expected = &Sha256::digest(state.pin.as_bytes())[..16];
                let matches = protocol
                    .decrypt(&secret, &pin_hash_enc)
                    .is_ok_and(|given| given.as_slice() == expected);
                if !matches {
                    state.retries -= 1;
                    state.wrong_in_a_row += 1;
                    return if state.retries == 0 {
                        vec![0x32] // CTAP2_ERR_PIN_BLOCKED
                    } else if state.wrong_in_a_row >= WRONG_PINS_BEFORE_REPLUG {
                        vec![0x34] // CTAP2_ERR_PIN_AUTH_BLOCKED
                    } else {
                        vec![0x31] // CTAP2_ERR_PIN_INVALID
                    };
                }
                state.retries = PIN_RETRIES;
                state.wrong_in_a_row = 0;
                let mut token = vec![0u8; 32];
                OsRng.fill_bytes(&mut token);
                let encrypted = protocol.encrypt(&secret, &token).expect("whole blocks");
                state.token = Some((protocol, token));
                e.map(1)
                    .and_then(|e| e.u8(2))
                    .and_then(|e| e.bytes(&encrypted))
                    .expect("vec write");
            }
            _ => return vec![0x3e], // CTAP2_ERR_INVALID_SUBCOMMAND
        }
        reply
    }

    /// `authenticatorCredentialManagement`: enumerate the one RP and its one
    /// credential. The Begin subcommands need a valid `pinUvAuthParam`.
    fn credential_management(&mut self, params: &[u8]) -> Vec<u8> {
        let Some(request) = parse_credential_management(params) else {
            return vec![0x12]; // CTAP2_ERR_INVALID_CBOR
        };
        let resident = self.resident.as_ref().expect("checked by the caller");
        let rp_id_hash = Sha256::digest(self.application.as_bytes());
        if matches!(request.sub_command, 0x02 | 0x04) {
            let token = self.pin.as_ref().and_then(|p| p.token.as_ref());
            let mut message = vec![request.sub_command];
            message.extend_from_slice(&request.params);
            let authorised = match (token, request.auth) {
                (Some((p, token)), Some((protocol, param))) => {
                    p.number() == protocol && p.authenticate(token, &message) == param
                }
                _ => false,
            };
            if !authorised {
                return vec![0x33]; // CTAP2_ERR_PIN_AUTH_INVALID
            }
        }
        let mut reply = vec![0x00];
        let mut e = Encoder::new(&mut reply);
        match request.sub_command {
            // enumerateRPsBegin: {3: rp, 4: rpIDHash, 5: totalRPs}
            0x02 => {
                e.map(3)
                    .and_then(|e| e.u8(3))
                    .and_then(|e| e.map(1))
                    .and_then(|e| e.str("id"))
                    .and_then(|e| e.str(&self.application))
                    .and_then(|e| e.u8(4))
                    .and_then(|e| e.bytes(&rp_id_hash))
                    .and_then(|e| e.u8(5))
                    .and_then(|e| e.u8(1))
                    .expect("vec write");
            }
            // enumerateCredentialsBegin: {6: user, 7: credentialID,
            // 8: publicKey, 9: totalCredentials, 10: credProtect}
            0x04 => {
                let mut wanted = Decoder::new(&request.params);
                let asked = wanted
                    .map()
                    .ok()
                    .and_then(|_| wanted.u8().ok())
                    .and_then(|_| wanted.bytes().ok());
                if asked != Some(rp_id_hash.as_slice()) {
                    return vec![0x2e]; // CTAP2_ERR_NO_CREDENTIALS
                }
                let pairs = if resident.reported_cred_protect.is_some() {
                    5
                } else {
                    4
                };
                e.map(pairs)
                    .and_then(|e| e.u8(6))
                    .and_then(|e| e.map(2))
                    .and_then(|e| e.str("id"))
                    .and_then(|e| e.bytes(&[0; 32]))
                    .and_then(|e| e.str("name"))
                    .and_then(|e| e.str(&resident.user_name))
                    .and_then(|e| e.u8(7))
                    .and_then(|e| e.map(2))
                    .and_then(|e| e.str("id"))
                    .and_then(|e| e.bytes(&self.key_handle))
                    .and_then(|e| e.str("type"))
                    .and_then(|e| e.str("public-key"))
                    // An Ed25519 COSE_Key: {1: OKP, 3: EdDSA, -1: Ed25519, -2: x}
                    .and_then(|e| e.u8(8))
                    .and_then(|e| e.map(4))
                    .and_then(|e| e.i8(1))
                    .and_then(|e| e.i8(1))
                    .and_then(|e| e.i8(3))
                    .and_then(|e| e.i8(-8))
                    .and_then(|e| e.i8(-1))
                    .and_then(|e| e.i8(6))
                    .and_then(|e| e.i8(-2))
                    .and_then(|e| e.bytes(&self.pair.public.0))
                    .and_then(|e| e.u8(9))
                    .and_then(|e| e.u8(1))
                    .expect("vec write");
                if let Some(level) = resident.reported_cred_protect {
                    e.u8(10).and_then(|e| e.u8(level)).expect("vec write");
                }
            }
            _ => return vec![0x3e], // CTAP2_ERR_INVALID_SUBCOMMAND
        }
        reply
    }

    fn get_assertion(&mut self, cmd: u8, params: &[u8]) {
        let Some(request) = parse_request(params) else {
            self.push_message(self.cid, cmd, &[0x12]); // CTAP2_ERR_INVALID_CBOR
            return;
        };
        if request.rp_id != self.application || !request.key_handles.contains(&self.key_handle) {
            self.push_message(self.cid, cmd, &[0x2e]); // CTAP2_ERR_NO_CREDENTIALS
            return;
        }
        // A valid pinUvAuthParam verifies the user; a bad one is refused.
        // A credential that requires verification hides from requests
        // without one, as credProtect level 3 makes a real device do.
        let hidden = self
            .resident
            .as_ref()
            .is_some_and(|r| r.cred_protect == super::credman::CRED_PROTECT_UV_REQUIRED);
        if hidden && request.pin_auth.is_none() {
            self.push_message(self.cid, cmd, &[0x2e]); // CTAP2_ERR_NO_CREDENTIALS
            return;
        }
        let mut verified = false;
        if let Some((param, protocol)) = &request.pin_auth {
            let token = self.pin.as_ref().and_then(|p| p.token.as_ref());
            match token {
                Some((p, token))
                    if p.number() == *protocol
                        && p.authenticate(token, &request.client_data_hash) == *param =>
                {
                    verified = true;
                }
                _ => {
                    self.push_message(self.cid, cmd, &[0x33]); // CTAP2_ERR_PIN_AUTH_INVALID
                    return;
                }
            }
        }
        let mut auth_data = Sha256::digest(request.rp_id.as_bytes()).to_vec();
        // Without `up`, the device answers at once and reports no presence.
        let mut flags = if request.up {
            self.flags
        } else {
            self.flags & !0x01
        };
        flags = if verified {
            flags | FLAG_UV
        } else {
            flags & !FLAG_UV
        };
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&request.client_data_hash);
        let signature: ssh_key::Signature = self.pair.try_sign(&signed).expect("ed25519 signs");
        self.counter += 1;

        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        e.map(2)
            .and_then(|e| e.u8(2))
            .and_then(|e| e.bytes(&auth_data))
            .and_then(|e| e.u8(3))
            .and_then(|e| e.bytes(signature.as_bytes()))
            .expect("vec write");

        let mut reply = vec![0x00]; // CTAP1_ERR_SUCCESS
        reply.extend_from_slice(&cbor);
        if request.up && self.require_touch {
            self.push_message(self.cid, CTAPHID_KEEPALIVE, &[0x02]);
        }
        if request.up && self.never_touched {
            self.waiting = true;
        } else {
            self.push_message(self.cid, CTAPHID_CBOR, &reply);
        }
    }

    fn push_message(&mut self, cid: u32, cmd: u8, payload: &[u8]) {
        let mut first = [0u8; 64];
        first[..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = cmd;
        first[5] = (payload.len() >> 8) as u8;
        first[6] = payload.len() as u8;
        let head = payload.len().min(57);
        first[7..7 + head].copy_from_slice(&payload[..head]);
        self.out.push_back(first);

        let mut offset = head;
        let mut seq = 0u8;
        while offset < payload.len() {
            let mut packet = [0u8; 64];
            packet[..4].copy_from_slice(&cid.to_be_bytes());
            packet[4] = seq;
            let n = (payload.len() - offset).min(59);
            packet[5..5 + n].copy_from_slice(&payload[offset..offset + n]);
            self.out.push_back(packet);
            offset += n;
            seq = seq.wrapping_add(1);
        }
    }
}

/// The parts of a getAssertion request the fake acts on.
struct Request {
    rp_id: String,
    client_data_hash: Vec<u8>,
    key_handles: Vec<Vec<u8>>,
    up: bool,
    /// `pinUvAuthParam` and `pinUvAuthProtocol`, when both are given.
    pin_auth: Option<(Vec<u8>, u8)>,
}

/// The parts of an `authenticatorCredentialManagement` request the fake
/// acts on: the subcommand, its parameters as sent, and the protocol and
/// `pinUvAuthParam`.
struct CredentialManagementRequest {
    sub_command: u8,
    params: Vec<u8>,
    auth: Option<(u8, Vec<u8>)>,
}

fn parse_credential_management(message: &[u8]) -> Option<CredentialManagementRequest> {
    let mut d = Decoder::new(message);
    let mut sub_command = None;
    let mut params = Vec::new();
    let mut protocol = None;
    let mut param = None;
    for _ in 0..d.map().ok()?? {
        match d.u8().ok()? {
            1 => sub_command = Some(d.u8().ok()?),
            2 => {
                let start = d.position();
                d.skip().ok()?;
                params = message[start..d.position()].to_vec();
            }
            3 => protocol = Some(d.u8().ok()?),
            4 => param = Some(d.bytes().ok()?.to_vec()),
            _ => d.skip().ok()?,
        }
    }
    Some(CredentialManagementRequest {
        sub_command: sub_command?,
        params,
        auth: protocol.zip(param),
    })
}

/// The parts of an `authenticatorClientPIN` request the fake acts on.
struct ClientPinRequest {
    protocol: u8,
    sub_command: u8,
    key_agreement: Option<p256::PublicKey>,
    pin_hash_enc: Option<Vec<u8>>,
}

fn parse_client_pin(message: &[u8]) -> Option<ClientPinRequest> {
    let mut d = Decoder::new(message);
    let mut protocol = None;
    let mut sub_command = None;
    let mut key_agreement = None;
    let mut pin_hash_enc = None;
    for _ in 0..d.map().ok()?? {
        match d.u8().ok()? {
            1 => protocol = Some(d.u8().ok()?),
            2 => sub_command = Some(d.u8().ok()?),
            3 => key_agreement = Some(pin::decode_cose_key(&mut d).ok()?),
            6 => pin_hash_enc = Some(d.bytes().ok()?.to_vec()),
            _ => d.skip().ok()?,
        }
    }
    Some(ClientPinRequest {
        protocol: protocol?,
        sub_command: sub_command?,
        key_agreement,
        pin_hash_enc,
    })
}

/// Decode a getAssertion request: `rpId` (1), `clientDataHash` (2), the
/// `allowList` (3) of `{"id", "type"}` descriptors, and the `up` option (5),
/// which defaults to true. Descriptors with any other shape are refused, as a
/// real authenticator refuses them.
fn parse_request(message: &[u8]) -> Option<Request> {
    let mut d = Decoder::new(message);
    let pairs = d.map().ok()??;
    let mut rp_id = None;
    let mut client_data_hash = None;
    let mut key_handles = Vec::new();
    let mut up = true;
    let mut pin_param = None;
    let mut pin_protocol = None;
    for _ in 0..pairs {
        match d.u8().ok()? {
            1 => rp_id = Some(d.str().ok()?.to_owned()),
            2 => client_data_hash = Some(d.bytes().ok()?.to_vec()),
            3 => {
                for _ in 0..d.array().ok()?? {
                    let mut id = None;
                    let mut kind = None;
                    for _ in 0..d.map().ok()?? {
                        match d.str().ok()? {
                            "id" => id = Some(d.bytes().ok()?.to_vec()),
                            "type" => kind = Some(d.str().ok()?.to_owned()),
                            _ => d.skip().ok()?,
                        }
                    }
                    if kind? == "public-key" {
                        key_handles.push(id?);
                    }
                }
            }
            5 => {
                for _ in 0..d.map().ok()?? {
                    match d.str().ok()? {
                        "up" => up = d.bool().ok()?,
                        _ => d.skip().ok()?,
                    }
                }
            }
            6 => pin_param = Some(d.bytes().ok()?.to_vec()),
            7 => pin_protocol = Some(d.u8().ok()?),
            _ => d.skip().ok()?,
        }
    }
    Some(Request {
        rp_id: rp_id?,
        client_data_hash: client_data_hash?,
        key_handles,
        up,
        pin_auth: pin_param.zip(pin_protocol),
    })
}

impl HidTransport for FakeFido {
    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        self.handle(report);
        Ok(())
    }

    fn read_report(&mut self, _timeout: Duration) -> Result<Option<Report>, TransportError> {
        if let Some(report) = self.out.pop_front() {
            return Ok(Some(report));
        }
        // A device left waiting for a touch keeps sending keepalives.
        if self.waiting {
            self.push_message(self.cid, CTAPHID_KEEPALIVE, &[0x02]);
            return Ok(self.out.pop_front());
        }
        Ok(None)
    }
}

/// A [`FakeFido`] shared between openings, so that its state (retries, a
/// PIN token) carries over from one signature to the next as a real
/// device's does.
impl HidTransport for std::sync::Arc<std::sync::Mutex<FakeFido>> {
    fn id(&self) -> Option<String> {
        self.lock().unwrap().id()
    }

    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        self.lock().unwrap().write_report(report)
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<Report>, TransportError> {
        self.lock().unwrap().read_report(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido::ctap::{Assertion, get_assertion};
    use crate::fido::ctaphid::CtapHid;

    #[test]
    fn fake_signs_a_valid_assertion() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01);
        let public = device.public();
        let mut hid = CtapHid::new(device);
        let hash: [u8; 32] = Sha256::digest(b"hello").into();
        let assertion: Assertion =
            get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {}).unwrap();
        assert_eq!(assertion.flags, 0x01);
        assert_eq!(assertion.counter, 1);
        assert_eq!(assertion.signature.len(), 64);

        // The assertion verifies against the credential's public key.
        use ed25519_dalek::Verifier;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        let mut signed = assertion.auth_data.clone();
        signed.extend_from_slice(&hash);
        let sig = ed25519_dalek::Signature::from_slice(&assertion.signature).unwrap();
        key.verify(&signed, &sig).unwrap();
    }

    /// The PIN client and the fake agree under both protocols: the token
    /// authorises a getAssertion, which then reports the user verified.
    #[test]
    fn a_pin_token_verifies_the_user() {
        use crate::fido::ctap::{PinAuth, get_assertion_with_pin};
        use crate::fido::pin;
        for protocols in [&[1u8][..], &[1, 2], &[2]] {
            let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01)
                .with_pin("1234", 8, protocols);
            let mut hid = CtapHid::new(device);
            let info = pin::get_info(&mut hid).unwrap();
            assert_eq!(info.client_pin, Some(true));
            let protocol = info.protocol().unwrap();
            assert_eq!(protocol.number(), *protocols.iter().max().unwrap());
            assert_eq!(pin::retries(&mut hid, protocol).unwrap(), 8);
            let token = pin::pin_token(&mut hid, protocol, "1234", None).unwrap();
            let hash: [u8; 32] = Sha256::digest(b"hello").into();
            let auth = PinAuth {
                protocol,
                token: &token,
            };
            let assertion = get_assertion_with_pin(
                &mut hid,
                "ssh:",
                &hash,
                &[1, 2, 3, 4],
                true,
                Some(auth),
                &|| {},
            )
            .unwrap();
            assert_eq!(assertion.flags, 0x01 | FLAG_UV);
            // Without the token the user is not verified.
            let assertion =
                get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {}).unwrap();
            assert_eq!(assertion.flags, 0x01);
        }
    }

    /// Wrong PINs cost tries; three in a row want a replug, and a stale
    /// token is refused.
    #[test]
    fn wrong_pins_count_down_and_stale_tokens_are_refused() {
        use crate::fido::ctap::{PinAuth, get_assertion_with_pin};
        use crate::fido::{FidoError, pin};
        let device =
            FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01).with_pin("1234", 8, &[1]);
        let mut hid = CtapHid::new(device);
        let v1 = PinProtocol::V1;
        assert!(matches!(
            pin::pin_token(&mut hid, v1, "0000", None),
            Err(FidoError::PinInvalid)
        ));
        assert_eq!(pin::retries(&mut hid, v1).unwrap(), 7);
        // Too short never reaches the device.
        assert!(matches!(
            pin::pin_token(&mut hid, v1, "12", None),
            Err(FidoError::PinLength)
        ));
        assert_eq!(pin::retries(&mut hid, v1).unwrap(), 7);
        let token = pin::pin_token(&mut hid, v1, "1234", None).unwrap();
        assert_eq!(pin::retries(&mut hid, v1).unwrap(), 8);

        hid.transport_mut().power_cycle();
        let hash = [0u8; 32];
        let auth = PinAuth {
            protocol: v1,
            token: &token,
        };
        let stale = get_assertion_with_pin(
            &mut hid,
            "ssh:",
            &hash,
            &[1, 2, 3, 4],
            true,
            Some(auth),
            &|| {},
        );
        assert!(matches!(stale, Err(FidoError::PinAuthInvalid)), "{stale:?}");

        assert!(matches!(
            pin::pin_token(&mut hid, v1, "0000", None),
            Err(FidoError::PinInvalid)
        ));
        assert!(matches!(
            pin::pin_token(&mut hid, v1, "0000", None),
            Err(FidoError::PinInvalid)
        ));
        assert!(matches!(
            pin::pin_token(&mut hid, v1, "0000", None),
            Err(FidoError::PinAuthBlocked)
        ));
        // Even the right PIN waits for a replug.
        assert!(matches!(
            pin::pin_token(&mut hid, v1, "1234", None),
            Err(FidoError::PinAuthBlocked)
        ));
        assert_eq!(hid.transport().pin_retries(), Some(5));
    }

    /// A key that is never touched is asked once, cancelled when the touch
    /// timeout runs out, and never sent the request a second time.
    #[test]
    fn an_untouched_key_is_cancelled_not_asked_again() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3, 4], 0x01).never_touched();
        let mut hid = CtapHid::new(device).with_touch_timeout(Duration::from_millis(50));
        let hash: [u8; 32] = Sha256::digest(b"hello").into();
        let prompts = std::cell::Cell::new(0);
        let result = get_assertion(&mut hid, "ssh:", &hash, &[1, 2, 3, 4], true, &|| {
            prompts.set(prompts.get() + 1)
        });
        assert!(
            matches!(result, Err(crate::fido::FidoError::Timeout)),
            "{result:?}"
        );
        assert_eq!(prompts.get(), 1);
        let device = hid.into_transport();
        assert!(device.cancelled());
        assert_eq!(device.requests(), 1);
    }
}
