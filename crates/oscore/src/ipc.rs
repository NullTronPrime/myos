//! Pure shared-memory message passing for Phase 2.6.
//!
//! `memfd_create` + `mmap` (already dispatched) supply the shared bytes; this
//! module supplies the discipline for using them. `MsgRing` is the host-
//! testable queue behind a shared ring: bounded, drop-oldest so a stalled
//! consumer cannot exhaust the producer, with counters so loss is visible.
//! `ShmHeader` is the agreed layout of the first 32 bytes of the shared
//! region, so a Rust host and a C guest (`guest/window_server.c` clients)
//! can rendezvous without sharing code.

use std::collections::VecDeque;

/// Magic word at the start of a shared IPC region (`"MIPC"`).
pub const SHM_MAGIC: u32 = 0x4350_494d;
/// Layout version of the header below.
pub const SHM_VERSION: u32 = 1;
/// Byte size of the shared header.
pub const HEADER_LEN: usize = 32;
/// Largest single message accepted, so one sender cannot claim the ring.
pub const MAX_MSG: usize = 4096;

/// Header of a shared ring region, little-endian on the wire:
///
/// ```text
/// 0..4   magic  (SHM_MAGIC)
/// 4..8   version (SHM_VERSION)
/// 8..12  capacity in bytes (payload area, excluding this header)
/// 12..16 used bytes currently queued
/// 16..24 messages ever pushed
/// 24..28 messages ever dropped (ring full)
/// 28..32 reserved (zero)
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ShmHeader {
    pub capacity: u32,
    pub used: u32,
    pub pushed: u64,
    pub dropped: u32,
}

impl ShmHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&SHM_MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&SHM_VERSION.to_le_bytes());
        out[8..12].copy_from_slice(&self.capacity.to_le_bytes());
        out[12..16].copy_from_slice(&self.used.to_le_bytes());
        out[16..24].copy_from_slice(&self.pushed.to_le_bytes());
        out[24..28].copy_from_slice(&self.dropped.to_le_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < HEADER_LEN {
            return None;
        }
        if u32::from_le_bytes(b[0..4].try_into().ok()?) != SHM_MAGIC {
            return None;
        }
        if u32::from_le_bytes(b[4..8].try_into().ok()?) != SHM_VERSION {
            return None;
        }
        Some(ShmHeader {
            capacity: u32::from_le_bytes(b[8..12].try_into().ok()?),
            used: u32::from_le_bytes(b[12..16].try_into().ok()?),
            pushed: u64::from_le_bytes(b[16..24].try_into().ok()?),
            dropped: u32::from_le_bytes(b[24..28].try_into().ok()?),
        })
    }
}

/// A bounded message queue with drop-oldest overflow.
///
/// Ordering is FIFO. When a push would exceed `cap_bytes`, the oldest
/// messages are discarded until it fits (or the message itself exceeds the
/// cap, in which case it is refused). Every discard increments `dropped`,
/// so a consumer that polls `dropped` can notice loss.
#[derive(Clone, Debug, Default)]
pub struct MsgRing {
    queue: VecDeque<Vec<u8>>,
    used_bytes: usize,
    cap_bytes: usize,
    pushed: u64,
    dropped: u64,
}

impl MsgRing {
    /// Builds a ring holding at most `cap_bytes` of payload.
    pub fn new(cap_bytes: usize) -> Self {
        MsgRing {
            queue: VecDeque::new(),
            used_bytes: 0,
            cap_bytes,
            pushed: 0,
            dropped: 0,
        }
    }

    /// Queues a message. Returns false only when the message alone exceeds
    /// the capacity; otherwise it is always accepted, evicting the oldest
    /// messages first.
    pub fn push(&mut self, msg: &[u8]) -> bool {
        if msg.len() > MAX_MSG || msg.len() > self.cap_bytes {
            return false;
        }
        while !self.queue.is_empty() && self.used_bytes + msg.len() > self.cap_bytes {
            if let Some(old) = self.queue.pop_front() {
                self.used_bytes -= old.len();
                self.dropped += 1;
            }
        }
        self.used_bytes += msg.len();
        self.queue.push_back(msg.to_vec());
        self.pushed += 1;
        true
    }

    /// Removes the oldest message.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let m = self.queue.pop_front()?;
        self.used_bytes -= m.len();
        Some(m)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Payload bytes currently queued.
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    /// Messages ever accepted.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    /// Messages discarded to make room.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Current header view of this ring, for publishing into shared memory.
    pub fn header(&self) -> ShmHeader {
        ShmHeader {
            capacity: self.cap_bytes.min(u32::MAX as usize) as u32,
            used: self.used_bytes.min(u32::MAX as usize) as u32,
            pushed: self.pushed,
            dropped: self.dropped.min(u32::MAX as u64) as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_and_rejects_garbage() {
        let h = ShmHeader {
            capacity: 65536,
            used: 30,
            pushed: 7,
            dropped: 1,
        };
        assert_eq!(ShmHeader::decode(&h.encode()), Some(h));
        assert_eq!(ShmHeader::decode(&[0u8; 8]), None);
        let mut bad = h.encode();
        bad[0] ^= 0xff;
        assert_eq!(ShmHeader::decode(&bad), None);
        let mut bad_ver = h.encode();
        bad_ver[4] ^= 0xff;
        assert_eq!(ShmHeader::decode(&bad_ver), None);
    }

    #[test]
    fn fifo_order_is_preserved() {
        let mut r = MsgRing::new(1024);
        assert!(r.push(b"a"));
        assert!(r.push(b"bc"));
        assert_eq!(r.len(), 2);
        assert_eq!(r.pop(), Some(b"a".to_vec()));
        assert_eq!(r.pop(), Some(b"bc".to_vec()));
        assert_eq!(r.pop(), None);
        assert!(r.is_empty());
    }

    #[test]
    fn overflow_evicts_oldest_and_counts_loss() {
        let mut r = MsgRing::new(4);
        assert!(r.push(b"ab"));
        assert!(r.push(b"cd"));
        assert_eq!(r.dropped(), 0);
        assert!(r.push(b"ef"));
        assert_eq!(r.dropped(), 1, "one message evicted");
        assert_eq!(r.pop(), Some(b"cd".to_vec()));
        assert_eq!(r.pop(), Some(b"ef".to_vec()));
        assert_eq!(r.pushed(), 3);
    }

    #[test]
    fn oversized_messages_are_refused() {
        let mut r = MsgRing::new(4);
        assert!(!r.push(b"abcde"), "larger than the ring itself");
        assert!(r.is_empty());
        assert_eq!(r.dropped(), 0, "refusals are not drops");
    }

    #[test]
    fn header_tracks_usage() {
        let mut r = MsgRing::new(100);
        r.push(b"hello");
        let h = r.header();
        assert_eq!(h.used, 5);
        assert_eq!(h.pushed, 1);
        assert_eq!(ShmHeader::decode(&h.encode()), Some(h));
    }
}
