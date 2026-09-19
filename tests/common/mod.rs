//! A fake OnlyKey that really signs, so the whole agent path can run without
//! hardware. Derived keys come deterministically from the identity hash;
//! slot ECC3 holds an ed25519 key, ECC4 a P-256 key and RSA1 a 2048-bit RSA
//! key; every other slot is empty.

use onlykey_agent::device::{OnlyKey, Timeouts};
use onlykey_agent::identity::Curve;
use onlykey_agent::protocol::{HEADER, Opcode, REPORT_SIZE, Report};
use onlykey_agent::transport::{HidTransport, TransportError};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};
use signature::Signer;
use signature::hazmat::PrehashSigner;
use std::collections::VecDeque;
use std::time::Duration;

pub const STORED_RSA_SLOT: u8 = 1;

fn rsa_key() -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("rsa2048.pem")).expect("test key")
}

pub const FIRMWARE: &str = "UNLOCKEDv3.0.4-prodc";

pub fn fast_timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_millis(10),
        connect_retry: Duration::from_millis(1),
        poll: Duration::from_millis(1),
        status: Duration::from_millis(100),
        pubkey: Duration::from_millis(100),
        sign: Duration::from_millis(100),
        gap: Duration::from_millis(20),
    }
}

fn seed(tag: u8, hash: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"fake-onlykey");
    h.update([tag]);
    h.update(hash);
    h.finalize().into()
}

fn ed25519_key(hash: &[u8]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&seed(1, hash))
}

fn p256_key(hash: &[u8]) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&seed(2, hash)).expect("seed is a valid scalar")
}

/// Like the firmware: a 32-byte payload is a ready-made digest, anything
/// else is hashed with SHA-256 first.
fn p256_sign(key: &p256::ecdsa::SigningKey, payload: &[u8]) -> [u8; 64] {
    let sig: p256::ecdsa::Signature = if payload.len() == 32 {
        key.sign_prehash(payload).expect("prehash sign")
    } else {
        key.sign(payload)
    };
    sig.to_bytes().into()
}

pub const STORED_ED25519_SLOT: u8 = 103;
pub const STORED_P256_SLOT: u8 = 104;

/// Key type of a stored slot, if the fake has one there.
fn stored_curve(slot: u8) -> Option<Curve> {
    match slot {
        STORED_ED25519_SLOT => Some(Curve::Ed25519),
        STORED_P256_SLOT => Some(Curve::NistP256),
        _ => None,
    }
}

#[derive(Default)]
pub struct SigningFake {
    replies: VecDeque<Report>,
    assembling: Option<(u8, Vec<u8>)>,
}

impl SigningFake {
    pub fn open() -> OnlyKey<Box<dyn HidTransport>> {
        let transport: Box<dyn HidTransport> = Box::new(SigningFake::default());
        OnlyKey::handshake(transport, fast_timeouts(), 1).expect("fake handshake")
    }

    fn reply(&mut self, data: &[u8]) {
        let mut r = [0u8; REPORT_SIZE];
        r[..data.len()].copy_from_slice(data);
        self.replies.push_back(r);
    }

    /// The token sends long values as consecutive full reports.
    fn reply_long(&mut self, data: &[u8]) {
        assert_eq!(data.len() % REPORT_SIZE, 0);
        for chunk in data.chunks(REPORT_SIZE) {
            self.reply(chunk);
        }
    }

    fn finish_sign(&mut self, slot: u8, message: Vec<u8>) {
        let sig: [u8; 64] = match (slot, stored_curve(slot)) {
            (201, _) => {
                let (blob, hash) = message.split_at(message.len() - 32);
                ed25519_key(hash).sign(blob).to_bytes()
            }
            (202, _) => {
                let (blob, hash) = message.split_at(message.len() - 32);
                p256_sign(&p256_key(hash), blob)
            }
            // A stored key signs the message as sent: no identity hash.
            (_, Some(Curve::Ed25519)) => ed25519_key(&[slot]).sign(&message).to_bytes(),
            (_, Some(Curve::NistP256)) => p256_sign(&p256_key(&[slot]), &message),
            (101..=116, None) => {
                self.reply(b"Error no ECC Private Key set in this slot");
                return;
            }
            // An RSA slot is handed the hash and applies PKCS#1 v1.5 itself.
            (STORED_RSA_SLOT, _) => {
                let sig = match message.len() {
                    32 => rsa_key().sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &message),
                    64 => rsa_key().sign(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), &message),
                    n => panic!("RSA sign payload of {n} bytes is not a hash"),
                }
                .expect("rsa sign");
                self.reply_long(&sig);
                return;
            }
            (1..=4, _) => {
                self.reply(b"Error no RSA Private Key set in this slot");
                return;
            }
            (other, _) => panic!("unexpected sign slot {other}"),
        };
        self.reply(&sig);
    }

    fn reply_pubkey(&mut self, curve: Curve, hash: &[u8]) {
        match curve {
            Curve::Ed25519 => self.reply(&ed25519_key(hash).verifying_key().to_bytes()),
            Curve::NistP256 => {
                let point = p256_key(hash).verifying_key().to_encoded_point(false);
                self.reply(&point.as_bytes()[1..]);
            }
        }
    }
}

impl HidTransport for SigningFake {
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        assert_eq!(&report[..4], &HEADER, "bad header");
        match report[4] {
            x if x == Opcode::SetTime as u8 => self.reply(FIRMWARE.as_bytes()),
            x if x == Opcode::GetPubKey as u8 => {
                let slot = report[5];
                let hash = &report[7..39];
                let tag = report[6];
                assert!(tag <= 2, "unexpected curve tag {tag}");
                match (slot, stored_curve(slot)) {
                    (STORED_RSA_SLOT, _) => {
                        assert_eq!(tag, 0, "RSA requests carry tag 0");
                        self.reply_long(&rsa_key().n().to_bytes_be());
                    }
                    (1..=4, _) => self.reply(b"Error no RSA Private Key set in this slot"),
                    (132, _) => {
                        let curve = if tag == 1 {
                            Curve::Ed25519
                        } else {
                            Curve::NistP256
                        };
                        self.reply_pubkey(curve, hash);
                    }
                    // The slot's own type wins; the request's curve tag is ignored.
                    (_, Some(curve)) => self.reply_pubkey(curve, &[slot]),
                    (101..=116, None) => self.reply(b"Error no ECC Private Key set in this slot"),
                    (other, _) => panic!("unexpected pubkey slot {other}"),
                }
            }
            x if x == Opcode::Sign as u8 => {
                let slot = report[5];
                let size = report[6];
                let (_, mut buf) = self.assembling.take().unwrap_or((slot, Vec::new()));
                if size == 0xFF {
                    buf.extend_from_slice(&report[7..64]);
                    self.assembling = Some((slot, buf));
                } else {
                    assert!((1..=57).contains(&size), "final size byte {size}");
                    buf.extend_from_slice(&report[7..7 + size as usize]);
                    self.finish_sign(slot, buf);
                }
            }
            op => panic!("unexpected opcode {op:#x}"),
        }
        Ok(())
    }

    fn read_report(&mut self, _timeout: Duration) -> Result<Option<Report>, TransportError> {
        Ok(self.replies.pop_front())
    }
}
