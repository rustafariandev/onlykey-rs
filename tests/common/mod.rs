//! A fake OnlyKey that really signs, so the whole agent path can run without
//! hardware. Keys are derived deterministically from the identity hash.

use onlykey_agent::device::{OnlyKey, Timeouts};
use onlykey_agent::protocol::{HEADER, Opcode, REPORT_SIZE, Report};
use onlykey_agent::transport::{HidTransport, TransportError};
use sha2::{Digest, Sha256};
use signature::Signer;
use std::collections::VecDeque;
use std::time::Duration;

pub const FIRMWARE: &str = "UNLOCKEDv3.0.4-prodc";

pub fn fast_timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_millis(10),
        connect_retry: Duration::from_millis(1),
        poll: Duration::from_millis(1),
        status: Duration::from_millis(100),
        pubkey: Duration::from_millis(100),
        sign: Duration::from_millis(100),
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

    fn finish_sign(&mut self, slot: u8, message: Vec<u8>) {
        let (blob, hash) = message.split_at(message.len() - 32);
        let sig: [u8; 64] = match slot {
            201 => ed25519_key(hash).sign(blob).to_bytes(),
            202 => {
                let sig: p256::ecdsa::Signature = p256_key(hash).sign(blob);
                sig.to_bytes().into()
            }
            other => panic!("unexpected sign slot {other}"),
        };
        self.reply(&sig);
    }
}

impl HidTransport for SigningFake {
    fn write_report(&mut self, report: &Report) -> Result<(), TransportError> {
        assert_eq!(&report[..4], &HEADER, "bad header");
        match report[4] {
            x if x == Opcode::SetTime as u8 => self.reply(FIRMWARE.as_bytes()),
            x if x == Opcode::GetPubKey as u8 => {
                assert_eq!(report[5], 132, "derived-key slot");
                let hash = &report[7..39];
                match report[6] {
                    1 => self.reply(&ed25519_key(hash).verifying_key().to_bytes()),
                    2 => {
                        let point = p256_key(hash).verifying_key().to_encoded_point(false);
                        self.reply(&point.as_bytes()[1..]);
                    }
                    tag => panic!("unexpected curve tag {tag}"),
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
