//! Query mode 2: queries and replies as Channel messages on a Link, as `channel.py`. The
//! framing is that of `pigeonhole_protocols`' `transport::reticulum_rs`.
//!
//! Every message is one [`Frame`] of MSGTYPE [`MSGTYPE`]: a request id (u16, big endian), the
//! piece index (u8), the piece count (u8), then that piece of the query or reply bytes. A
//! message is cut into at most 255 pieces of at most [`PIECE`] bytes. A reply carries its
//! query's request id.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use reticulum::channel::Message;
use reticulum::error::RnsError;

pub const MSGTYPE: u16 = 0x5048;
/// A message's first byte: a read or a write query, as they begin, or a replica path followed
/// by that path's request bytes.
pub const PEEK: u8 = 2;
pub const SYNC: u8 = 3;
pub const FORWARD: u8 = 4;
pub const PUSHED: u8 = 5;
pub const MAX_PIECES: usize = 255;
const HEADER: usize = 4;
/// The Link MDU at the 500 byte MTU Reticulum-rs links run at, less Channel's 6 byte
/// envelope and the frame header.
pub const PIECE: usize = crate::wire::LINK_MDU - 6 - HEADER;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub request_id: u16,
    pub index: u8,
    pub count: u8,
    pub data: Vec<u8>,
}

impl Message for Frame {
    fn unpack(b: &[u8], message_type: u16) -> Result<Self, RnsError> {
        if message_type != MSGTYPE || b.len() < HEADER {
            return Err(RnsError::ChannelError);
        }
        Ok(Frame { request_id: u16::from_be_bytes([b[0], b[1]]), index: b[2], count: b[3], data: b[HEADER..].to_vec() })
    }

    fn pack(&self) -> Vec<u8> {
        [&self.request_id.to_be_bytes()[..], &[self.index, self.count], &self.data].concat()
    }

    fn message_type(&self) -> u16 {
        MSGTYPE
    }
}

/// Cuts `data` into the frames of request `request_id`; empty data is one empty piece. `None`
/// past [`MAX_PIECES`] pieces.
pub fn split(request_id: u16, data: &[u8]) -> Option<Vec<Frame>> {
    let count = data.len().div_ceil(PIECE).max(1);
    (count <= MAX_PIECES).then(|| {
        (0..count)
            .map(|i| Frame {
                request_id,
                index: i as u8,
                count: count as u8,
                data: data[(i * PIECE).min(data.len())..((i + 1) * PIECE).min(data.len())].to_vec(),
            })
            .collect()
    })
}

/// Collects pieces by request id. A piece whose count differs from the request's first
/// piece, or whose index is out of range, drops the request; a request not complete within
/// 60 seconds is dropped.
/// When a request's first piece came, its piece count, and its pieces by index.
type Pending = (Instant, u8, BTreeMap<u8, Vec<u8>>);

#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<u16, Pending>,
}

impl Reassembler {
    pub fn feed(&mut self, f: Frame) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.pending.retain(|_, (t, _, _)| now.duration_since(*t) < REASSEMBLY_TIMEOUT);
        if f.count == 0 || f.index >= f.count {
            self.pending.remove(&f.request_id);
            return None;
        }
        let (_, count, pieces) = self.pending.entry(f.request_id).or_insert_with(|| (now, f.count, BTreeMap::new()));
        if *count != f.count {
            self.pending.remove(&f.request_id);
            return None;
        }
        pieces.entry(f.index).or_insert(f.data);
        if pieces.len() < *count as usize {
            return None;
        }
        let (_, _, pieces) = self.pending.remove(&f.request_id)?;
        Some(pieces.into_values().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_reassemble_out_of_order_with_duplicates() {
        let data: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let mut frames = split(9, &data).unwrap();
        assert_eq!(frames.len(), 5);
        frames.reverse();
        frames.insert(1, frames[0].clone());
        let mut r = Reassembler::default();
        let out: Vec<_> = frames.into_iter().filter_map(|f| r.feed(f)).collect();
        assert_eq!(out, vec![data]);
        assert!(split(1, &vec![0; 255 * PIECE + 1]).is_none());
        assert_eq!(split(1, &[]).unwrap()[0].count, 1);
        assert_eq!(PIECE, 421);
        let f = Frame { request_id: 0x0102, index: 3, count: 4, data: vec![9] };
        assert_eq!(f.pack(), [1, 2, 3, 4, 9]);
        assert_eq!(Frame::unpack(&f.pack(), MSGTYPE).unwrap(), f);
    }

    #[test]
    fn mismatched_count_drops_request() {
        let mut r = Reassembler::default();
        assert_eq!(r.feed(Frame { request_id: 1, index: 0, count: 2, data: vec![1] }), None);
        assert_eq!(r.feed(Frame { request_id: 1, index: 1, count: 3, data: vec![2] }), None);
        assert_eq!(r.feed(Frame { request_id: 1, index: 1, count: 2, data: vec![2] }), None);
    }
}
