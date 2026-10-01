//! CTAPHID: the 64-byte HID framing that carries CTAP messages.
//!
//! A message longer than 57 bytes is split into a first packet and one or
//! more continuation packets. Every packet starts with a four-byte channel
//! id. A message the device is still working on may be interleaved with
//! `KEEPALIVE` packets, which is how a touch request is surfaced.

use super::FidoError;
use crate::protocol::Report;
use crate::transport::HidTransport;
use rand_core::{OsRng, RngCore};
use std::time::{Duration, Instant};

/// The channel id used before a channel has been allocated.
pub const CID_BROADCAST: u32 = 0xFFFF_FFFF;

const PACKET_SIZE: usize = 64;
const INIT_DATA: usize = PACKET_SIZE - 7;
const CONT_DATA: usize = PACKET_SIZE - 5;

/// Largest CTAPHID message (57 + 128 * 59), as in the specification.
pub const MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA;

/// Bit 7 of the command byte marks an initialization packet; a
/// continuation packet carries a sequence number there instead.
const TYPE_INIT: u8 = 0x80;

pub const CTAPHID_MSG: u8 = TYPE_INIT | 0x03;
pub const CTAPHID_INIT: u8 = TYPE_INIT | 0x06;
pub const CTAPHID_CBOR: u8 = TYPE_INIT | 0x10;
pub const CTAPHID_CANCEL: u8 = TYPE_INIT | 0x11;
pub const CTAPHID_KEEPALIVE: u8 = TYPE_INIT | 0x3B;
pub const CTAPHID_ERROR: u8 = TYPE_INIT | 0x3F;

/// `KEEPALIVE` status: the authenticator is waiting for a touch.
const STATUS_UPNEEDED: u8 = 0x02;

/// How long one read waits before the loop checks its deadlines again.
const POLL: Duration = Duration::from_millis(100);
/// How long a device may take to send anything at all after a request. USB
/// HID does not drop reports and CTAPHID has no retransmission, so silence is
/// waited out rather than answered with a resend: an OnlyKey takes ~350 ms
/// to start on a getAssertion, and a resend would start a second one.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a device may go quiet between packets once it has answered. The
/// specification suggests a keepalive every 100 ms; an OnlyKey leaves ~260 ms.
const PACKET_GAP: Duration = Duration::from_secs(2);
/// How long to wait in all once the device has started working on a request
/// (sending keepalives), typically for a touch.
const TOUCH_TIMEOUT: Duration = Duration::from_secs(30);

/// A CTAPHID channel bound to an open transport.
pub struct CtapHid<T: HidTransport> {
    transport: T,
    cid: u32,
    touch_timeout: Duration,
}

impl<T: HidTransport> CtapHid<T> {
    /// Wrap an open transport. No bytes are sent until the first message.
    pub fn new(transport: T) -> Self {
        CtapHid {
            transport,
            cid: CID_BROADCAST,
            touch_timeout: TOUCH_TIMEOUT,
        }
    }

    /// Change how long to wait once the device has started working on a
    /// request, typically for a touch. Defaults to 30 seconds.
    pub fn with_touch_timeout(mut self, timeout: Duration) -> Self {
        self.touch_timeout = timeout;
        self
    }

    /// Take the transport back.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// The channel id in use, or [`CID_BROADCAST`] before the handshake.
    pub fn channel(&self) -> u32 {
        self.cid
    }

    /// Allocate a channel with `CTAPHID_INIT`. Called automatically by
    /// [`Self::transact`].
    pub fn init(&mut self) -> Result<(), FidoError> {
        self.cid = CID_BROADCAST;
        let nonce = nonce()?;
        self.send(CTAPHID_INIT, &nonce)?;
        let reply = self.receive(CTAPHID_INIT, &|| {})?;
        if reply.len() < 17 || reply[..8] != nonce {
            return Err(FidoError::Protocol("bad CTAPHID_INIT reply"));
        }
        self.cid = u32::from_be_bytes(reply[8..12].try_into().expect("slice of four"));
        Ok(())
    }

    /// Send one message and wait for its reply. `on_presence` is called once
    /// if the device asks the user to touch it.
    ///
    /// The request is sent once. A device that says nothing for
    /// [`RESPONSE_TIMEOUT`], goes quiet for [`PACKET_GAP`] after it has
    /// answered, or is not touched in time gets a `CTAPHID_CANCEL`, and the
    /// call fails with [`FidoError::Timeout`].
    pub fn transact(
        &mut self,
        cmd: u8,
        payload: &[u8],
        on_presence: &dyn Fn(),
    ) -> Result<Vec<u8>, FidoError> {
        if self.cid == CID_BROADCAST {
            self.init()?;
        }
        self.send(cmd, payload)?;
        self.receive(cmd, on_presence)
    }

    /// Write `payload` as one message for `cmd` on the current channel.
    fn send(&mut self, cmd: u8, payload: &[u8]) -> Result<(), FidoError> {
        for packet in &self.frame(cmd, payload)? {
            self.transport.write_report(packet)?;
        }
        Ok(())
    }

    /// Split `payload` into packets for `cmd` on the current channel.
    fn frame(&self, cmd: u8, payload: &[u8]) -> Result<Vec<Report>, FidoError> {
        if payload.len() > MAX_MESSAGE {
            return Err(FidoError::TooLarge(payload.len()));
        }
        let mut packets = Vec::new();
        let mut first = [0u8; PACKET_SIZE];
        first[..4].copy_from_slice(&self.cid.to_be_bytes());
        first[4] = cmd;
        first[5] = (payload.len() >> 8) as u8;
        first[6] = payload.len() as u8;
        let head = payload.len().min(INIT_DATA);
        first[7..7 + head].copy_from_slice(&payload[..head]);
        packets.push(first);

        let mut offset = head;
        let mut seq = 0u8;
        while offset < payload.len() {
            let mut packet = [0u8; PACKET_SIZE];
            packet[..4].copy_from_slice(&self.cid.to_be_bytes());
            packet[4] = seq;
            let chunk = (payload.len() - offset).min(CONT_DATA);
            packet[5..5 + chunk].copy_from_slice(&payload[offset..offset + chunk]);
            packets.push(packet);
            offset += chunk;
            seq = seq.wrapping_add(1);
        }
        Ok(packets)
    }

    /// Wait for the reply to `expected`, ignoring packets from other
    /// channels. Silence past the deadline, or the touch timeout once the
    /// device is busy, cancels the request.
    fn receive(&mut self, expected: u8, on_presence: &dyn Fn()) -> Result<Vec<u8>, FidoError> {
        let mut deadline = Instant::now() + RESPONSE_TIMEOUT;
        // Set by the first keepalive and never extended, so a device that
        // keeps sending keepalives cannot hold the caller forever.
        let mut busy_until: Option<Instant> = None;
        let mut notified = false;
        loop {
            let now = Instant::now();
            if now >= deadline || busy_until.is_some_and(|at| now >= at) {
                // There is no request to abandon before a channel exists.
                if expected != CTAPHID_INIT {
                    self.cancel();
                }
                return Err(FidoError::Timeout);
            }
            let wait = POLL.min(deadline - now);
            let Some(packet) = self.transport.read_report(wait)? else {
                continue;
            };
            let cid = u32::from_be_bytes(packet[..4].try_into().expect("slice of four"));
            if cid != self.cid {
                continue;
            }
            match packet[4] {
                CTAPHID_KEEPALIVE => {
                    if packet[7] == STATUS_UPNEEDED && !notified {
                        notified = true;
                        on_presence();
                    }
                    // The device is working on it; keep listening, but only
                    // for so long in all.
                    let now = Instant::now();
                    busy_until.get_or_insert(now + self.touch_timeout);
                    deadline = now + PACKET_GAP;
                }
                CTAPHID_ERROR => return Err(FidoError::Hid(packet[7])),
                cmd if cmd == expected => {
                    return self.read_message(&packet);
                }
                cmd => return Err(FidoError::Unexpected { cmd, expected }),
            }
        }
    }

    /// Abandon the request in progress. Best effort: the call is already
    /// failing, so a write error here changes nothing.
    fn cancel(&mut self) {
        if let Ok(packets) = self.frame(CTAPHID_CANCEL, &[]) {
            for packet in &packets {
                if self.transport.write_report(packet).is_err() {
                    return;
                }
            }
        }
    }

    /// Collect a first packet plus its continuations into one message.
    fn read_message(&mut self, first: &Report) -> Result<Vec<u8>, FidoError> {
        let len = ((first[5] as usize) << 8) | first[6] as usize;
        if len > MAX_MESSAGE {
            return Err(FidoError::TooLarge(len));
        }
        let mut out = Vec::with_capacity(len);
        let head = len.min(INIT_DATA);
        out.extend_from_slice(&first[7..7 + head]);

        // Continuations follow promptly; keepalives are not expected here.
        let deadline = Instant::now() + PACKET_GAP;
        let mut seq = 0u8;
        while out.len() < len {
            let now = Instant::now();
            if now >= deadline {
                return Err(FidoError::Timeout);
            }
            let wait = POLL.min(deadline - now);
            let Some(packet) = self.transport.read_report(wait)? else {
                continue;
            };
            let cid = u32::from_be_bytes(packet[..4].try_into().expect("slice of four"));
            if cid != self.cid {
                continue;
            }
            if packet[4] != seq {
                return Err(FidoError::Protocol("out-of-order continuation"));
            }
            let remaining = len - out.len();
            let chunk = remaining.min(CONT_DATA);
            out.extend_from_slice(&packet[5..5 + chunk]);
            seq = seq.wrapping_add(1);
        }
        Ok(out)
    }
}

/// Eight random bytes, echoed back by the device, as CTAPHID asks.
fn nonce() -> Result<[u8; 8], FidoError> {
    let mut nonce = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| FidoError::Protocol("no system randomness for the CTAPHID nonce"))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::fake::{ScriptedTransport, Step};

    fn cbor_reply(cid: u32, payload: &[u8]) -> Vec<Report> {
        let mut packets = Vec::new();
        let mut first = [0u8; 64];
        first[..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = CTAPHID_CBOR;
        first[5] = (payload.len() >> 8) as u8;
        first[6] = payload.len() as u8;
        let head = payload.len().min(INIT_DATA);
        first[7..7 + head].copy_from_slice(&payload[..head]);
        packets.push(first);
        let mut offset = head;
        let mut seq = 0u8;
        while offset < payload.len() {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&cid.to_be_bytes());
            p[4] = seq;
            let n = (payload.len() - offset).min(CONT_DATA);
            p[5..5 + n].copy_from_slice(&payload[offset..offset + n]);
            packets.push(p);
            offset += n;
            seq += 1;
        }
        packets
    }

    #[test]
    fn frames_short_and_long_messages() {
        let hid = CtapHid::new(ScriptedTransport::new(vec![]));
        let short = hid.frame(CTAPHID_CBOR, &[1, 2, 3]).unwrap();
        assert_eq!(short.len(), 1);
        assert_eq!(short[0][4], CTAPHID_CBOR);
        assert_eq!(short[0][5], 0);
        assert_eq!(short[0][6], 3);
        assert_eq!(&short[0][7..10], &[1, 2, 3]);

        let long = hid.frame(CTAPHID_CBOR, &[7u8; 120]).unwrap();
        assert_eq!(long.len(), 3); // 57 + 59 + 4
        assert_eq!(long[0][5..7], [0, 120]);
        assert_eq!(long[1][4], 0);
        assert_eq!(long[2][4], 1);
    }

    #[test]
    fn reassembles_a_reply_split_over_packets() {
        let payload: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let mut steps = vec![Step::ExpectWrite({
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&1u32.to_be_bytes());
            p[4] = CTAPHID_CBOR;
            p[5] = 0;
            p[6] = 3;
            p[7..10].copy_from_slice(&[9, 9, 9]);
            p
        })];
        steps.extend(cbor_reply(1, &payload).into_iter().map(Step::Reply));
        let mut hid = CtapHid::new(ScriptedTransport::new(steps));
        hid.cid = 1; // pretend the channel is already allocated
        let got = hid.transact(CTAPHID_CBOR, &[9, 9, 9], &|| {}).unwrap();
        assert_eq!(got, payload);
    }

    /// Commands go out with the initialization bit set, as the CTAPHID
    /// specification numbers them.
    #[test]
    fn command_bytes_carry_the_init_bit() {
        for cmd in [
            CTAPHID_MSG,
            CTAPHID_INIT,
            CTAPHID_CBOR,
            CTAPHID_CANCEL,
            CTAPHID_KEEPALIVE,
            CTAPHID_ERROR,
        ] {
            assert_eq!(cmd & TYPE_INIT, TYPE_INIT, "{cmd:#04x}");
        }
        assert_eq!(CTAPHID_INIT, 0x86);
        assert_eq!(CTAPHID_CBOR, 0x90);
        assert_eq!(CTAPHID_KEEPALIVE, 0xBB);
    }

    /// A device that replies on a schedule, measured from the first write,
    /// and records every write.
    struct Paced {
        replies: std::collections::VecDeque<(Duration, Report)>,
        writes: Vec<Report>,
        started: Option<Instant>,
    }

    impl HidTransport for Paced {
        fn write_report(
            &mut self,
            report: &Report,
        ) -> Result<(), crate::transport::TransportError> {
            self.started.get_or_insert_with(Instant::now);
            self.writes.push(*report);
            Ok(())
        }

        fn read_report(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<Report>, crate::transport::TransportError> {
            let (Some(started), Some(&(at, report))) = (self.started, self.replies.front()) else {
                std::thread::sleep(timeout);
                return Ok(None);
            };
            let due = started + at;
            let now = Instant::now();
            if due > now + timeout {
                std::thread::sleep(timeout);
                return Ok(None);
            }
            std::thread::sleep(due.saturating_duration_since(now));
            self.replies.pop_front();
            Ok(Some(report))
        }
    }

    /// An OnlyKey's timing, measured on hardware: nothing for ~340 ms, two
    /// keepalives, then ~260 ms more before the reply. The request is sent
    /// once and the reply is received; nothing is resent or cancelled.
    #[test]
    fn a_slow_device_is_waited_for_not_resent() {
        let packet = |cmd: u8, byte: u8| {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&1u32.to_be_bytes());
            p[4] = cmd;
            p[6] = 1;
            p[7] = byte;
            p
        };
        let transport = Paced {
            replies: [
                (
                    Duration::from_millis(340),
                    packet(CTAPHID_KEEPALIVE, STATUS_UPNEEDED),
                ),
                (Duration::from_millis(341), packet(CTAPHID_KEEPALIVE, 0x01)),
                (Duration::from_millis(600), packet(CTAPHID_CBOR, 0x00)),
            ]
            .into(),
            writes: Vec::new(),
            started: None,
        };
        let mut hid = CtapHid::new(transport);
        hid.cid = 1;
        let prompts = std::cell::Cell::new(0);
        let reply = hid.transact(CTAPHID_CBOR, &[0x42], &|| prompts.set(prompts.get() + 1));
        assert_eq!(reply.unwrap(), vec![0x00]);
        assert_eq!(prompts.get(), 1);
        let writes = hid.into_transport().writes;
        assert_eq!(writes.len(), 1, "the request was resent or cancelled");
        assert_eq!(writes[0], packet(CTAPHID_CBOR, 0x42));
    }

    /// After a keepalive, the request is not resent: when the touch timeout
    /// runs out the host sends `CTAPHID_CANCEL` once and gives up.
    #[test]
    fn a_touch_timeout_cancels_instead_of_resending() {
        let request = {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&1u32.to_be_bytes());
            p[4] = CTAPHID_CBOR;
            p[6] = 1;
            p[7] = 0x42;
            p
        };
        let keepalive = {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&1u32.to_be_bytes());
            p[4] = CTAPHID_KEEPALIVE;
            p[6] = 1;
            p[7] = STATUS_UPNEEDED;
            p
        };
        let cancel = {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&1u32.to_be_bytes());
            p[4] = CTAPHID_CANCEL;
            p
        };
        let transport = ScriptedTransport::new(vec![
            Step::ExpectWrite(request),
            Step::Reply(keepalive),
            Step::ExpectWrite(cancel),
        ]);
        let mut hid = CtapHid::new(transport).with_touch_timeout(Duration::ZERO);
        hid.cid = 1;
        let prompts = std::cell::Cell::new(0);
        let result = hid.transact(CTAPHID_CBOR, &[0x42], &|| prompts.set(prompts.get() + 1));
        assert!(matches!(result, Err(FidoError::Timeout)), "{result:?}");
        assert_eq!(prompts.get(), 1);
        hid.into_transport().assert_done();
    }
}
