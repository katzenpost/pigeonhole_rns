//! Push, as `push.py`: a client on a Link subscribes to the Box IDs it waits for, and the
//! replica pushes each box down that Link when it stores it, from a client, a replica or the
//! bridge. The wire format is in the README, under Push.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::wire::{self, BoxId, Reply};

/// Mode 2 ops, after the replica paths' 2 to 5.
pub const SUBSCRIBE: u8 = 6;
pub const UNSUBSCRIBE: u8 = 7;
/// Box IDs one Link may wait for, and the longest a subscription lasts, in seconds.
pub const LIMIT: usize = 256;
pub const MAX_TTL: u16 = 3600;

pub fn decode_ids(data: &[u8]) -> Option<Vec<BoxId>> {
    data.len().is_multiple_of(wire::BOX_ID_SIZE)
        .then(|| data.chunks(wire::BOX_ID_SIZE).map(|c| c.try_into().unwrap()).collect())
}

/// A subscribe's ttl in seconds and Box IDs.
pub fn decode_subscribe(data: &[u8]) -> Option<(u16, Vec<BoxId>)> {
    let ttl = u16::from_be_bytes(data.get(..2)?.try_into().unwrap());
    Some((ttl, decode_ids(&data[2..])?))
}

pub fn encode_subscribe_reply(taken: u16, ttl: u16) -> Vec<u8> {
    [&[wire::SUCCESS][..], &taken.to_be_bytes(), &ttl.to_be_bytes()].concat()
}

pub fn encode_push(box_id: &BoxId, r: &Reply) -> Vec<u8> {
    [&box_id[..], &wire::encode_reply(r)].concat()
}

/// Box IDs each Link waits for, each until its expiry. A push takes the Box ID off every Link
/// waiting for it, since a box is written once.
pub struct Subscriptions<K> {
    links: HashMap<K, HashMap<BoxId, Instant>>,
    limit: usize,
}

impl<K: Eq + Hash + Clone> Subscriptions<K> {
    pub fn new(limit: usize) -> Self {
        Subscriptions { links: HashMap::new(), limit }
    }

    /// Subscribes `ids` in order until the Link waits for the limit; one it already waits for
    /// is renewed. Returns how many were taken and the ttl granted: `ttl` capped at
    /// [`MAX_TTL`], 0 asking for it.
    pub fn subscribe(&mut self, link: &K, ttl: u16, ids: &[BoxId], now: Instant) -> (u16, u16) {
        let ttl = if ttl == 0 { MAX_TTL } else { ttl.min(MAX_TTL) };
        let subs = self.links.entry(link.clone()).or_default();
        subs.retain(|_, t| *t > now);
        let mut taken = 0;
        for b in ids {
            if !subs.contains_key(b) && subs.len() >= self.limit {
                break;
            }
            subs.insert(*b, now + Duration::from_secs(ttl.into()));
            taken += 1;
        }
        (taken, ttl)
    }

    /// Drops `ids` from the Link, or every one when none are named.
    pub fn unsubscribe(&mut self, link: &K, ids: &[BoxId]) {
        if let Some(subs) = self.links.get_mut(link) {
            if ids.is_empty() {
                subs.clear();
            }
            for b in ids {
                subs.remove(b);
            }
        }
    }

    pub fn drop_link(&mut self, link: &K) {
        self.links.remove(link);
    }

    /// The Links waiting for `box_id`, which no longer wait for it.
    pub fn take(&mut self, box_id: &BoxId, now: Instant) -> Vec<K> {
        self.links.iter_mut().filter_map(|(k, s)| s.remove(box_id).is_some_and(|t| t > now).then(|| k.clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_expiry_and_take() {
        let t0 = Instant::now();
        let mut s = Subscriptions::new(3);
        let [a, b, c, d] = [[0u8; 32], [1; 32], [2; 32], [3; 32]];
        assert_eq!(s.subscribe(&1, 10, &[a, b], t0), (2, 10));
        // Past the limit the rest are refused, a renewal still taken; ttl 0 asks for the most.
        assert_eq!(s.subscribe(&1, 0, &[a, c, d], t0), (2, MAX_TTL));
        assert_eq!(s.subscribe(&1, 9000, &[b], t0), (1, MAX_TTL));
        assert_eq!(s.subscribe(&2, 5, &[a], t0), (1, 5));
        let mut got = s.take(&a, t0);
        got.sort();
        assert_eq!(got, [1, 2]);
        assert!(s.take(&a, t0).is_empty());
        let later = t0 + Duration::from_secs(MAX_TTL as u64 + 1);
        assert!(s.take(&b, later).is_empty() && s.take(&c, later).is_empty());
        // Expired ones no longer count toward the limit.
        assert_eq!(s.subscribe(&1, 10, &[a, b, c], later), (3, 10));
        s.unsubscribe(&1, &[a]);
        assert!(s.take(&a, later).is_empty());
        assert_eq!(s.take(&b, later), [1]);
        s.unsubscribe(&1, &[]);
        assert!(s.take(&c, later).is_empty());
        s.subscribe(&1, 10, &[d], later);
        s.drop_link(&1);
        assert!(s.take(&d, later).is_empty());
    }

    #[test]
    fn wire() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let sub = [&[1, 0x2c][..], &a, &b].concat();
        assert_eq!(decode_subscribe(&sub), Some((300, vec![a, b])));
        assert_eq!(decode_subscribe(b""), None);
        assert_eq!(decode_subscribe(&[0, 1, 5]), None);
        assert_eq!(encode_subscribe_reply(2, 300), [0, 0, 2, 1, 0x2c]);
        assert_eq!(encode_push(&a, &Reply::code(wire::TOMBSTONE)), [&a[..], &[11]].concat());
    }
}
