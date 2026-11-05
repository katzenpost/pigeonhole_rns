//! The replica's decisions, free of Reticulum so they can be tested in process: a port of
//! `engine.py`. Membership, placement, the entry path, forwarding, handoff, sync, the read walk
//! and the bridge.
//!
//! In open mode every replica stores every box: a new box goes to every replica heard, and
//! replicas that meet sync the boxes the other lacks. Closed mode, for a future mesh whose
//! replicas authenticate out of band, shards: two owners per box by rendezvous hashing, and
//! stand-ins hand off and drop.
//!
//! A bridge is a replica like any other, and also writes boxes into the mixnet it serves:
//! every box, or with forward on-request only those a client wrote to it. A box pulled from a
//! mixnet keeps that mixnet as its origin and is never written back there. Bridges serving the
//! same mixnet ask each other before writing, so each box goes to each mixnet once, barring
//! retries.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hpqc::bacap::MessageBoxIndex;
use sha2::{Digest, Sha256};

use crate::store::{Dst, Store};
use crate::wire::{self, BoxId, Query, Reply};

/// A pseudo destination for the local Katzenpost replica on a bridge node.
pub const BRIDGE: &[u8] = b"bridge";
/// Owners per box in closed mode.
pub const K: usize = 2;
const EPOCH_SECONDS: f64 = 7.0 * 24.0 * 3600.0;
/// Katzenpost replicas count epochs from 2017-06-01 UTC; a bridged box must fall in the same
/// epoch on both sides.
const EPOCH_BASE: f64 = 1496275200.0;
const BACKOFF_BASE: f64 = 5.0;
const BACKOFF_CAP: f64 = 600.0;
/// A bridge that is not first in a box's order among the bridges of its mixnet waits this many
/// retries for one of them to write the box before it does.
const TWIN_WAIT: u32 = 3;
const LOW: BoxId = [0; 32];
const HIGH: BoxId = [0xff; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Open,
    Closed,
}

pub fn epoch_at(now: f64) -> i64 {
    ((now - EPOCH_BASE) / EPOCH_SECONDS).floor() as i64
}

pub fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

/// Rendezvous hashing: a replica's score for a box, lowest first.
pub fn score(identity: &[u8], box_id: &BoxId) -> [u8; 32] {
    Sha256::new().chain_update(identity).chain_update(box_id).finalize().into()
}

/// What the engine needs from the network. `request` returns the reply bytes, or `None` when
/// the replica did not answer.
pub trait Net: Sync {
    /// A write to a replica, path `forward` with the origin prefixed when it has one, or to
    /// the local Katzenpost replica for [`BRIDGE`]; the reply code.
    fn deliver(&self, dst: &[u8], box_id: &BoxId, sig: &[u8], ct: &[u8], origin: &[u8]) -> impl Future<Output = Option<u8>> + Send;
    fn request(&self, dst: &[u8], path: &str, data: Vec<u8>) -> impl Future<Output = Option<Vec<u8>>> + Send;
    /// A read from the local Katzenpost replica; `None` without a bridge.
    fn bridge_read(&self, box_id: &BoxId) -> impl Future<Output = Option<Reply>> + Send;
}

async fn peek(net: &impl Net, dst: &[u8], box_id: &BoxId) -> Option<Reply> {
    wire::decode_reply(&net.request(dst, "peek", wire::encode_read(box_id)).await?)
}

fn found(r: &Option<Reply>) -> bool {
    matches!(r, Some(r) if r.code == wire::SUCCESS || r.code == wire::TOMBSTONE)
}

#[derive(Clone)]
struct Peer {
    identity: Vec<u8>,
    bridge: bool,
    mixnet: Vec<u8>,
}

pub struct Engine {
    pub store: Store,
    pub self_dest: Dst,
    pub mode: Mode,
    pub is_bridge: bool,
    /// On a bridge, the id of its mixnet.
    pub mixnet: Vec<u8>,
    /// On a bridge, whether every box goes into the mixnet, or only those clients write here.
    pub forward_all: bool,
    box_ciphertext_size: Option<usize>,
    peers: Mutex<HashMap<Dst, Peer>>,
    synced: Mutex<HashSet<Dst>>,
    /// A fixed time for tests; the wall clock when `None`.
    pub clock: Mutex<Option<f64>>,
}

type Result<T> = rusqlite::Result<T>;

impl Engine {
    pub fn new(
        store: Store,
        self_dest: [u8; 16],
        self_identity: [u8; 16],
        box_ciphertext_size: Option<usize>,
        is_bridge: bool,
        mode: Mode,
    ) -> Engine {
        let mixnet = if is_bridge { wire::mixnet_id("") } else { Vec::new() };
        let me = Peer { identity: self_identity.to_vec(), bridge: is_bridge, mixnet: mixnet.clone() };
        Engine {
            store,
            self_dest: self_dest.to_vec(),
            mode,
            is_bridge,
            mixnet,
            forward_all: true,
            box_ciphertext_size,
            peers: Mutex::new(HashMap::from([(self_dest.to_vec(), me)])),
            synced: Mutex::default(),
            clock: Mutex::new(None),
        }
    }

    /// On a bridge: the mixnet it serves, and whether it writes every box into it.
    pub fn bridging(mut self, mixnet: Vec<u8>, forward_all: bool) -> Engine {
        if self.is_bridge {
            self.peers.get_mut().unwrap().get_mut(&self.self_dest).unwrap().mixnet = mixnet.clone();
            self.mixnet = mixnet;
        }
        self.forward_all = forward_all;
        self
    }

    fn now(&self) -> f64 {
        self.clock.lock().unwrap().unwrap_or_else(unix_now)
    }

    // ---- membership ----

    /// Records an announce. A changed identity for a known destination is ignored, so the
    /// first key seen is the one kept.
    pub fn heard(&self, dest: &[u8], identity: &[u8], bridge: bool, mixnet: &[u8]) -> bool {
        let mut peers = self.peers.lock().unwrap();
        if peers.get(dest).is_some_and(|p| p.identity != identity) {
            return false;
        }
        let mixnet = if bridge { mixnet.to_vec() } else { Vec::new() };
        peers.insert(dest.to_vec(), Peer { identity: identity.to_vec(), bridge, mixnet });
        true
    }

    pub fn peers(&self) -> Vec<Dst> {
        self.peers.lock().unwrap().keys().filter(|d| **d != self.self_dest).cloned().collect()
    }

    pub fn peer_of(&self, identity: &[u8]) -> Option<Dst> {
        let peers = self.peers.lock().unwrap();
        peers.iter().find(|(d, p)| p.identity == identity && **d != self.self_dest).map(|(d, _)| d.clone())
    }

    /// `replicas` heard, in the box's order.
    fn order(&self, box_id: &BoxId, replicas: impl IntoIterator<Item = Dst>) -> Vec<Dst> {
        let peers = self.peers.lock().unwrap();
        let mut v: Vec<_> = replicas
            .into_iter()
            .filter_map(|d| peers.get(&d).map(|p| (score(&p.identity, box_id), d)))
            .collect();
        v.sort();
        v.into_iter().map(|(_, d)| d).collect()
    }

    fn owners(&self, box_id: &BoxId) -> Vec<Dst> {
        let all: Vec<_> = self.peers.lock().unwrap().keys().cloned().collect();
        self.order(box_id, all).into_iter().take(K).collect()
    }

    fn targets(&self, box_id: &BoxId, reachable: &[Dst]) -> Vec<Dst> {
        let cands = reachable.iter().cloned().chain([self.self_dest.clone()]).collect::<HashSet<_>>();
        self.order(box_id, cands).into_iter().take(K).collect()
    }

    fn heard_in(&self, reachable: &[Dst]) -> Vec<Dst> {
        let peers = self.peers.lock().unwrap();
        reachable.iter().filter(|d| peers.contains_key(*d) && **d != self.self_dest).cloned().collect()
    }

    /// Where a newly stored box is sent: in open mode every reachable replica heard, in closed
    /// mode the first K in its order and a bridge; and on a bridge its mixnet, unless the box
    /// came from there or the bridge forwards on request and no client wrote it here. Never
    /// back to the replica it came from.
    fn forwards(&self, box_id: &BoxId, reachable: &[Dst], sender: Option<&Dst>, origin: &[u8], client: bool) -> Vec<Dst> {
        let mut dsts = match self.mode {
            Mode::Open => self.heard_in(reachable),
            Mode::Closed => [self.targets(box_id, reachable), self.bridge_targets(box_id, reachable)].concat(),
        };
        if self.to_mixnet(origin, client) {
            dsts.push(BRIDGE.to_vec());
        }
        let mut seen = HashSet::new();
        dsts.retain(|d| *d != self.self_dest && Some(d) != sender && seen.insert(d.clone()));
        dsts
    }

    fn to_mixnet(&self, origin: &[u8], client: bool) -> bool {
        self.is_bridge && origin != self.mixnet && (self.forward_all || client)
    }

    /// Reachable bridges serving this bridge's mixnet.
    fn twins(&self, reachable: &[Dst]) -> Vec<Dst> {
        let peers = self.peers.lock().unwrap();
        let mut v = self.bridges_locked(&peers, reachable);
        v.retain(|d| peers[d].mixnet == self.mixnet);
        v
    }

    fn bridges_locked(&self, peers: &HashMap<Dst, Peer>, reachable: &[Dst]) -> Vec<Dst> {
        reachable
            .iter()
            .filter(|d| **d != self.self_dest && peers.get(*d).is_some_and(|p| p.bridge))
            .cloned()
            .collect()
    }

    fn bridges(&self, reachable: &[Dst]) -> Vec<Dst> {
        self.bridges_locked(&self.peers.lock().unwrap(), reachable)
    }

    /// In closed mode, where a box held by a replica that is not a bridge goes so that it
    /// reaches the mixnet: the first reachable bridge in the box's order. The mixnet never
    /// pulls from the mesh, so every holder sends, and all pick the same bridge.
    fn bridge_targets(&self, box_id: &BoxId, reachable: &[Dst]) -> Vec<Dst> {
        if self.is_bridge || self.mode == Mode::Open {
            return vec![];
        }
        self.order(box_id, self.bridges(reachable)).into_iter().take(1).collect()
    }

    fn is_bridge_dst(&self, dst: &[u8]) -> bool {
        dst == BRIDGE || self.peers.lock().unwrap().get(dst).is_some_and(|p| p.bridge)
    }

    // ---- verification and the entry path ----

    pub fn verify(&self, q: &Query) -> u8 {
        let Query::Write { box_id, signature, ciphertext } = q else {
            return wire::INVALID_PAYLOAD;
        };
        if !ciphertext.is_empty() && self.box_ciphertext_size.is_some_and(|n| n != ciphertext.len()) {
            return wire::INVALID_PAYLOAD;
        }
        match MessageBoxIndex::verify_box(box_id, ciphertext, signature) {
            Ok(()) => wire::SUCCESS,
            Err(_) => wire::INVALID_SIGNATURE,
        }
    }

    /// Verify, store, and enqueue forwards. A box already held enqueues nothing, so a forward
    /// is never passed on twice. A write from no known replica is a client's.
    fn accept(&self, q: &Query, reachable: &[Dst], sender: Option<&Dst>, origin: &[u8]) -> Result<u8> {
        let code = self.verify(q);
        let Query::Write { box_id, signature, ciphertext } = q else { unreachable!() };
        if code != wire::SUCCESS {
            return Ok(code);
        }
        let dsts = self.forwards(box_id, reachable, sender, origin, sender.is_none());
        self.store.put(box_id, signature, ciphertext, epoch_at(self.now()), &dsts, origin)
    }

    pub fn handle_write(&self, data: &[u8], reachable: &[Dst], sender: Option<&Dst>) -> Vec<u8> {
        self.write_from(data, reachable, sender, b"")
    }

    /// A write prefixed with the mixnet the box came from. The origin is kept only from a
    /// known replica.
    pub fn handle_forward(&self, data: &[u8], reachable: &[Dst], sender: Option<&Dst>) -> Vec<u8> {
        let (origin, q) = data.split_at(wire::MIXNET_ID_SIZE.min(data.len()));
        self.write_from(q, reachable, sender, if sender.is_some() { origin } else { b"" })
    }

    fn write_from(&self, data: &[u8], reachable: &[Dst], sender: Option<&Dst>, origin: &[u8]) -> Vec<u8> {
        let code = match wire::decode_query(data) {
            Some(q @ Query::Write { .. }) => self.accept(&q, reachable, sender, origin).unwrap_or_else(|e| {
                log::error!("pigeonhole: store: {e}");
                4 // DATABASE_FAILURE
            }),
            _ => wire::INVALID_PAYLOAD,
        };
        vec![code]
    }

    /// A bridge of the same mixnet asking whether this one wrote a box, or its tombstone, into
    /// the mixnet, or pulled it from there: 1 or 0.
    pub fn handle_pushed(&self, data: &[u8]) -> Result<Vec<u8>> {
        let Some(box_id) = data.get(..32).and_then(|b| BoxId::try_from(b).ok()) else {
            return Ok(vec![0]);
        };
        let tomb = &data[32..] == b"\x01";
        let done = match self.store.get(&box_id)? {
            Some(b) if b.is_tombstone() == tomb => {
                self.store.acked(&box_id)?.contains(BRIDGE) || (self.is_bridge && b.origin == self.mixnet)
            }
            _ => false,
        };
        Ok(vec![done as u8])
    }

    // ---- reads ----

    fn local(&self, box_id: &BoxId) -> Result<Option<Reply>> {
        Ok(self.store.get(box_id)?.map(|b| {
            if b.is_tombstone() {
                Reply::code(wire::TOMBSTONE)
            } else {
                Reply { code: wire::SUCCESS, found: Some((b.signature, b.payload)) }
            }
        }))
    }

    fn read_query(data: &[u8]) -> Option<BoxId> {
        match wire::decode_query(data) {
            Some(Query::Read(b)) => Some(b),
            _ => None,
        }
    }

    /// On a bridge, a read from its mixnet; what it finds is stored with the mixnet as origin.
    async fn pull(&self, box_id: &BoxId, reachable: &[Dst], net: &impl Net) -> Result<Option<Reply>> {
        let r = if self.is_bridge { net.bridge_read(box_id).await } else { None };
        if !found(&r) {
            return Ok(None);
        }
        self.adopt(box_id, r.as_ref().unwrap(), reachable, &self.mixnet.clone())?;
        Ok(r)
    }

    /// A replica asking a replica: this store only, plus the mixnet on a bridge, which stores
    /// what it pulls. Never walks, so replicas cannot chase each other.
    pub async fn handle_peek(&self, data: &[u8], reachable: &[Dst], net: &impl Net) -> Result<Vec<u8>> {
        let Some(box_id) = Self::read_query(data) else {
            return Ok(vec![wire::INVALID_PAYLOAD]);
        };
        let mut r = self.local(&box_id)?;
        if r.is_none() {
            r = self.pull(&box_id, reachable, net).await?;
        }
        Ok(wire::encode_reply(&r.unwrap_or(Reply::code(wire::NOT_FOUND))))
    }

    /// A client asking its entry replica: this store, then every reachable replica in the
    /// box's order, bridges asking their mixnets, then this replica's own mixnet. A box found
    /// on a bridge is stored by that bridge, with its origin, and reaches this replica from
    /// there.
    pub async fn handle_read(&self, data: &[u8], reachable: &[Dst], net: &impl Net) -> Result<Vec<u8>> {
        let Some(box_id) = Self::read_query(data) else {
            return Ok(vec![wire::INVALID_PAYLOAD]);
        };
        let mut r = self.local(&box_id)?;
        let mut adopt = false;
        if r.is_none() {
            for dst in self.order(&box_id, self.heard_in(reachable)) {
                let got = peek(net, &dst, &box_id).await;
                if found(&got) {
                    adopt = !self.is_bridge_dst(&dst);
                    r = got;
                    break;
                }
            }
        }
        if r.is_none() {
            r = self.pull(&box_id, reachable, net).await?;
        }
        let Some(r) = r else {
            return Ok(vec![wire::NOT_FOUND]);
        };
        if adopt && self.store.get(&box_id)?.is_none() {
            self.adopt(&box_id, &r, reachable, b"")?;
        }
        Ok(wire::encode_reply(&r))
    }

    /// A box fetched for a reader is stored and forwarded like a write, so the next reader
    /// finds it on the mesh.
    fn adopt(&self, box_id: &BoxId, r: &Reply, reachable: &[Dst], origin: &[u8]) -> Result<()> {
        if let Some((sig, ct)) = &r.found {
            let q = Query::Write { box_id: *box_id, signature: sig.clone(), ciphertext: ct.clone() };
            if self.verify(&q) == wire::SUCCESS {
                let dsts = self.forwards(box_id, reachable, None, origin, false);
                self.store.put(box_id, sig, ct, epoch_at(self.now()), &dsts, origin)?;
            }
        }
        Ok(())
    }

    // ---- forwarding and handoff ----

    /// Attempts every due forward whose destination is reachable. Before writing into its
    /// mixnet, a bridge asks the others serving it: one has written the box, and this one
    /// acknowledges it as written, or this one is first in the box's order among them, or has
    /// waited TWIN_WAIT retries, and writes it. Returns how many were acknowledged.
    pub async fn forward_due(&self, reachable: &[Dst], net: &impl Net) -> Result<usize> {
        let now = self.now();
        let mut done = 0;
        for (box_id, dst, attempts) in self.store.due(now)? {
            if dst != BRIDGE && !reachable.contains(&dst) {
                continue;
            }
            let Some(b) = self.store.get(&box_id)? else {
                self.store.forget(&box_id, &dst)?;
                continue;
            };
            let twins = if dst == BRIDGE { self.twins(reachable) } else { vec![] };
            let mut code = None;
            let mut twin_wrote = false;
            for t in &twins {
                let q = [&box_id[..], &[b.is_tombstone() as u8]].concat();
                if net.request(t, "pushed", q).await.as_deref() == Some(&[1]) {
                    twin_wrote = true;
                    break;
                }
            }
            if twin_wrote {
                code = Some(wire::SUCCESS);
            } else if twins.is_empty()
                || attempts >= TWIN_WAIT
                || self.order(&box_id, twins.into_iter().chain([self.self_dest.clone()])).first() == Some(&self.self_dest)
            {
                code = net.deliver(&dst, &box_id, &b.signature, &b.payload, &b.origin).await;
            }
            match code {
                Some(c) if wire::stored(c) => {
                    self.store.ack(&box_id, &dst)?;
                    done += 1;
                }
                Some(wire::INVALID_SIGNATURE | wire::INVALID_BOX_ID | wire::INVALID_PAYLOAD) => {
                    self.store.forget(&box_id, &dst)?
                }
                _ => {
                    let delay = BACKOFF_CAP.min(BACKOFF_BASE * 2f64.powi(attempts.min(10) as i32));
                    self.store.backoff(&box_id, &dst, now + delay)?;
                }
            }
        }
        Ok(done)
    }

    /// For every held box: on a bridge forwarding all, enqueue to its mixnet if not written
    /// there yet and not from there; in closed mode, enqueue to a bridge if none has taken it
    /// yet. Open mode stops there. In closed mode, for one whose owners, in this replica's
    /// view, do not include it: enqueue to owners not yet acknowledged, and drop the copy once
    /// both owners and the bridge, if one is queued, have acknowledged. Tombstones are never
    /// dropped. Returns how many copies were dropped.
    pub fn handoff(&self, reachable: &[Dst]) -> Result<usize> {
        let mut dropped = 0;
        for box_id in self.store.box_ids()? {
            let acked = self.store.acked(&box_id)?;
            let mut queued = self.store.queued(&box_id)?;
            if self.is_bridge
                && self.forward_all
                && !acked.contains(BRIDGE)
                && !queued.contains(BRIDGE)
                && self.store.get(&box_id)?.is_some_and(|b| b.origin != self.mixnet)
            {
                self.store.enqueue(&box_id, BRIDGE)?;
                queued.insert(BRIDGE.to_vec());
            }
            if !acked.iter().chain(&queued).any(|d| self.is_bridge_dst(d)) {
                for b in self.bridge_targets(&box_id, reachable) {
                    self.store.enqueue(&box_id, &b)?;
                    queued.insert(b);
                }
            }
            if self.mode == Mode::Open {
                continue;
            }
            let owners = self.owners(&box_id);
            if owners.contains(&self.self_dest) {
                continue;
            }
            for o in &owners {
                if reachable.contains(o) && !acked.contains(o) && !queued.contains(o) {
                    self.store.enqueue(&box_id, o)?;
                    queued.insert(o.clone());
                }
            }
            if self.store.get(&box_id)?.is_none_or(|b| b.is_tombstone()) {
                continue;
            }
            if owners.len() == K && owners.iter().all(|o| acked.contains(o)) && queued.is_empty() {
                self.store.drop_box(&box_id)?;
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    // ---- sync, open mode ----

    /// Syncs with each reachable replica not synced with since this replica started or last
    /// found it unreachable. Returns how many synced.
    pub async fn sync(&self, reachable: &[Dst], net: &impl Net) -> Result<usize> {
        if self.mode != Mode::Open {
            return Ok(0);
        }
        let reachable: HashSet<Dst> = self.heard_in(reachable).into_iter().collect();
        let todo: Vec<Dst> = {
            let mut synced = self.synced.lock().unwrap();
            synced.retain(|d| reachable.contains(d));
            reachable.difference(&synced).cloned().collect()
        };
        let mut done = 0;
        for dst in todo {
            if self.sync_with(&dst, net).await? {
                self.synced.lock().unwrap().insert(dst);
                done += 1;
            }
        }
        Ok(done)
    }

    /// Walks the Box ID space a page at a time: sends this store's page, the peer enqueues
    /// what this store lacks and answers with its own, and this store enqueues what the peer
    /// lacks.
    async fn sync_with(&self, dst: &Dst, net: &impl Net) -> Result<bool> {
        let mut cursor = LOW;
        while cursor != HIGH {
            let mine = self.store.entries(&cursor, &HIGH, wire::SYNC_PAGE)?;
            let hi = if mine.len() == wire::SYNC_PAGE { mine[mine.len() - 1].0 } else { HIGH };
            let q = wire::encode_sync(&[cursor, hi].concat(), &mine);
            let Some(raw) = net.request(dst, "sync", q).await else {
                return Ok(false);
            };
            let Some((top, theirs)) = wire::decode_sync(&raw, wire::BOX_ID_SIZE) else {
                return Ok(false);
            };
            let top: BoxId = top.try_into().unwrap();
            if !(cursor < top && top <= hi) || theirs.iter().any(|(b, _)| !(cursor < *b && *b <= top)) {
                return Ok(false);
            }
            let mine: Vec<_> = mine.into_iter().filter(|(b, _)| *b <= top).collect();
            self.push_missing(dst, &mine, &theirs)?;
            cursor = top;
        }
        Ok(true)
    }

    /// Answers a sync page with this store's page over the same range, cut short if full, and
    /// enqueues to the sender what it lacks there. An unidentified sender gets the answer but
    /// no pushes.
    pub fn handle_sync(&self, data: &[u8], sender: Option<&Dst>) -> Result<Vec<u8>> {
        let Some((head, theirs)) = wire::decode_sync(data, 2 * wire::BOX_ID_SIZE) else {
            return Ok(Vec::new());
        };
        let cursor: BoxId = head[..32].try_into().unwrap();
        let hi: BoxId = head[32..].try_into().unwrap();
        if self.mode != Mode::Open || cursor >= hi {
            return Ok(Vec::new());
        }
        let mine = self.store.entries(&cursor, &hi, wire::SYNC_PAGE)?;
        let top = if mine.len() == wire::SYNC_PAGE { mine[mine.len() - 1].0 } else { hi };
        if let Some(s) = sender {
            self.push_missing(s, &mine, &theirs)?;
        }
        Ok(wire::encode_sync(&top, &mine))
    }

    /// Enqueues to `dst` each of `mine` it lacks, or holds as a box where this store holds the
    /// tombstone.
    fn push_missing(&self, dst: &[u8], mine: &[(BoxId, bool)], theirs: &[(BoxId, bool)]) -> Result<()> {
        // shortcut: the receiver stores a push at its own epoch, so a sync across an epoch
        // boundary can keep a box an epoch longer; carry the epoch in replica writes if it matters.
        let have: HashMap<_, _> = theirs.iter().copied().collect();
        for (b, tomb) in mine {
            if have.get(b).is_none_or(|their_tomb| *tomb && !their_tomb) {
                self.store.enqueue(b, dst)?;
            }
        }
        Ok(())
    }

    pub fn gc(&self) -> Result<usize> {
        let cur = epoch_at(self.now());
        self.store.sweep(&[cur, cur - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpqc::bacap::{MessageBoxIndex, WriteCap};
    use hpqc::rand_core::UnwrapErr;
    use std::sync::Arc;

    const BOX: usize = 100;
    const CTX: &[u8] = b"pigeonhole context";

    fn d(s: &[u8; 2]) -> [u8; 16] {
        s.repeat(8).try_into().unwrap()
    }

    fn ident(dest: &[u8]) -> Vec<u8> {
        [b"I", dest].concat()[..16].to_vec()
    }

    fn engine(dir: &std::path::Path, name: &str, me: [u8; 16], peers: &[[u8; 16]], mode: Mode, bridge: bool) -> Engine {
        let e = Engine::new(
            Store::open(&dir.join(format!("{name}.sqlite"))).unwrap(),
            me,
            ident(&me).try_into().unwrap(),
            Some(BOX + 4 + 16),
            bridge,
            mode,
        );
        *e.clock.lock().unwrap() = Some(1000.0);
        for p in peers {
            e.heard(p, &ident(p), false, b"");
        }
        e
    }

    /// A sealed box: its ID, signature and ciphertext, an empty ciphertext for a tombstone.
    fn seal(tomb: bool) -> (BoxId, Vec<u8>, Vec<u8>) {
        seal_with(&WriteCap::generate(&mut UnwrapErr(getrandom::SysRng)), tomb)
    }

    fn seal_with(wc: &WriteCap, tomb: bool) -> (BoxId, Vec<u8>, Vec<u8>) {
        let rc = wc.read_cap().to_bytes();
        let pos = wc.position_at(&MessageBoxIndex::from_bytes(&rc[32..]).unwrap()).unwrap();
        if tomb {
            let (b, s) = pos.tombstone(CTX).unwrap();
            return (b, s.to_vec(), vec![]);
        }
        let mut padded = vec![0, 0, 0, 2, b'y', b'o'];
        padded.resize(BOX + 4, 0);
        let (b, ct, s) = pos.encrypt(CTX, &padded).unwrap();
        (b, s.to_vec(), ct)
    }

    /// A Katzenpost replica behind a bridge socket: write once, a tombstone replaces a box,
    /// and every write logged as (box id, tombstone).
    #[derive(Default)]
    struct Mixnet {
        boxes: HashMap<BoxId, (Vec<u8>, Vec<u8>)>,
        writes: Vec<(BoxId, bool)>,
    }

    impl Mixnet {
        fn count(&self, b: &BoxId, tomb: bool) -> usize {
            self.writes.iter().filter(|w| **w == (*b, tomb)).count()
        }
    }

    type MixnetRef = Arc<Mutex<Mixnet>>;

    /// Replicas in one process that all reach each other: requests go to the engine they
    /// name, and a bridge's mixnet is its entry in `mixnets`.
    #[derive(Default, Clone)]
    struct Mesh {
        engines: Arc<Mutex<HashMap<Dst, Arc<Engine>>>>,
        mixnets: Arc<Mutex<HashMap<Dst, MixnetRef>>>,
        from: Dst,
    }

    impl Mesh {
        fn get(&self, dst: &[u8]) -> Option<Arc<Engine>> {
            self.engines.lock().unwrap().get(dst).cloned()
        }
        fn at(&self, from: &[u8]) -> Mesh {
            Mesh { from: from.to_vec(), ..self.clone() }
        }
        fn mixnet(&self) -> Option<MixnetRef> {
            self.mixnets.lock().unwrap().get(&self.from).cloned()
        }
    }

    impl Net for Mesh {
        async fn deliver(&self, dst: &[u8], box_id: &BoxId, sig: &[u8], ct: &[u8], origin: &[u8]) -> Option<u8> {
            if dst == BRIDGE {
                let mx = self.mixnet()?;
                let mut mx = mx.lock().unwrap();
                mx.writes.push((*box_id, ct.is_empty()));
                let cur = mx.boxes.get(box_id).cloned();
                if let Some(cur) = cur.filter(|c| c.1.is_empty() || !ct.is_empty()) {
                    return Some(if cur == (sig.to_vec(), ct.to_vec()) { wire::SUCCESS } else { wire::ALREADY_EXISTS });
                }
                mx.boxes.insert(*box_id, (sig.to_vec(), ct.to_vec()));
                return Some(wire::SUCCESS);
            }
            let e = self.get(dst)?;
            let all = e.peers();
            let q = wire::encode_write(box_id, sig, ct);
            let r = if origin.is_empty() {
                e.handle_write(&q, &all, Some(&self.from))
            } else {
                e.handle_forward(&[origin, &q].concat(), &all, Some(&self.from))
            };
            r.first().copied()
        }
        async fn request(&self, dst: &[u8], path: &str, data: Vec<u8>) -> Option<Vec<u8>> {
            let e = self.get(dst)?;
            let at = self.at(dst);
            match path {
                "sync" => e.handle_sync(&data, Some(&self.from)).ok(),
                "peek" => e.handle_peek(&data, &e.peers(), &at).await.ok(),
                "pushed" => e.handle_pushed(&data).ok(),
                _ => None,
            }
        }
        async fn bridge_read(&self, box_id: &BoxId) -> Option<Reply> {
            let mx = self.mixnet()?;
            let got = mx.lock().unwrap().boxes.get(box_id).cloned();
            Some(match got {
                None => Reply::code(wire::NOT_FOUND),
                Some((_, ct)) if ct.is_empty() => Reply::code(wire::TOMBSTONE),
                Some(f) => Reply { code: wire::SUCCESS, found: Some(f) },
            })
        }
    }

    #[tokio::test]
    async fn write_verifies_stores_and_forwards_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (me, peers) = (d(b"me"), [d(b"r2"), d(b"r3"), d(b"r4")]);
        let e = engine(dir.path(), "e", me, &peers, Mode::Closed, false);
        let reach: Vec<Dst> = peers.iter().map(|p| p.to_vec()).collect();
        let (b, s, c) = seal(false);
        assert_eq!(e.handle_write(&wire::encode_write(&b, &s, &c), &reach, None), [wire::SUCCESS]);
        let targets: HashSet<_> = e.store.due(0.0).unwrap().into_iter().map(|(_, d, _)| d).collect();
        let mut want: HashSet<_> = e.targets(&b, &reach).into_iter().collect();
        want.remove(&me[..]);
        assert_eq!(targets, want);
        let mut bad = s.clone();
        bad[0] ^= 1;
        assert_eq!(e.handle_write(&wire::encode_write(&b, &bad, &c), &[], None), [wire::INVALID_SIGNATURE]);
        assert_eq!(e.handle_write(&wire::encode_write(&b, &s, &c[1..]), &[], None), [wire::INVALID_PAYLOAD]);
    }

    #[tokio::test]
    async fn open_write_goes_to_every_replica_but_the_sender() {
        let dir = tempfile::tempdir().unwrap();
        let peers = [d(b"r2"), d(b"r3"), d(b"r4")];
        let e = engine(dir.path(), "e", d(b"me"), &peers, Mode::Open, false);
        let reach: Vec<Dst> = peers.iter().map(|p| p.to_vec()).collect();
        let (b, s, c) = seal(false);
        e.handle_write(&wire::encode_write(&b, &s, &c), &reach, Some(&reach[0]));
        let mut got: Vec<_> = e.store.due(0.0).unwrap().into_iter().map(|(_, d, _)| d).collect();
        got.sort();
        assert_eq!(got, reach[1..].to_vec());
        // Held already: nothing passed on again.
        e.store.ack(&b, &reach[1]).unwrap();
        e.store.ack(&b, &reach[2]).unwrap();
        e.handle_write(&wire::encode_write(&b, &s, &c), &reach, None);
        assert!(e.store.due(0.0).unwrap().is_empty());
    }

    #[tokio::test]
    async fn forward_acks_and_backs_off() {
        let dir = tempfile::tempdir().unwrap();
        let mesh = Mesh::default();
        let (a, b) = (d(b"aa"), d(b"bb"));
        let ea = Arc::new(engine(dir.path(), "a", a, &[b], Mode::Open, false));
        let (bx, s, c) = seal(false);
        ea.handle_write(&wire::encode_write(&bx, &s, &c), &[b.to_vec()], None);
        let net = Mesh { from: a.to_vec(), ..mesh.clone() };
        // b is not up yet: backoff.
        assert_eq!(ea.forward_due(&[b.to_vec()], &net).await.unwrap(), 0);
        assert!(ea.store.due(1000.0).unwrap().is_empty());
        assert_eq!(ea.store.due(1005.0).unwrap().len(), 1);
        let eb = Arc::new(engine(dir.path(), "b", b, &[a], Mode::Open, false));
        mesh.engines.lock().unwrap().insert(b.to_vec(), eb.clone());
        *ea.clock.lock().unwrap() = Some(1006.0);
        assert_eq!(ea.forward_due(&[b.to_vec()], &net).await.unwrap(), 1);
        assert!(eb.store.get(&bx).unwrap().is_some());
        assert!(eb.store.due(0.0).unwrap().is_empty(), "never sent back to its sender");
    }

    #[tokio::test]
    async fn open_sync_pages_both_ways_tombstones_win_and_reads_walk() {
        let dir = tempfile::tempdir().unwrap();
        let mesh = Mesh::default();
        let (a, b) = (d(b"aa"), d(b"bb"));
        let ea = Arc::new(engine(dir.path(), "a", a, &[b], Mode::Open, false));
        let eb = Arc::new(engine(dir.path(), "b", b, &[a], Mode::Open, false));
        mesh.engines.lock().unwrap().insert(a.to_vec(), ea.clone());
        mesh.engines.lock().unwrap().insert(b.to_vec(), eb.clone());
        // More than a page on each side, written while the two had not met.
        let mut boxes = vec![];
        for i in 0..300 {
            let (bx, s, c) = seal(i % 3 == 0);
            let on = if i % 2 == 0 { &ea } else { &eb };
            on.handle_write(&wire::encode_write(&bx, &s, &c), &[], None);
            boxes.push(bx);
        }
        // A box on a, its tombstone on b.
        let (bx, s, c) = seal(false);
        ea.handle_write(&wire::encode_write(&bx, &s, &c), &[], None);
        eb.store.put(&bx, &[0; 64], b"", 0, &[], b"").unwrap();
        let (na, nb) = (Mesh { from: a.to_vec(), ..mesh.clone() }, Mesh { from: b.to_vec(), ..mesh.clone() });
        assert_eq!(ea.sync(&[b.to_vec()], &na).await.unwrap(), 1);
        assert_eq!(ea.sync(&[b.to_vec()], &na).await.unwrap(), 0, "synced once until unreachable");
        // The tombstone does not verify here (a fake signature), so it is refused, not stored.
        ea.forward_due(&[b.to_vec()], &na).await.unwrap();
        eb.forward_due(&[a.to_vec()], &nb).await.unwrap();
        for bx in &boxes {
            assert!(ea.store.get(bx).unwrap().is_some() && eb.store.get(bx).unwrap().is_some());
        }
        assert!(eb.store.get(&bx).unwrap().unwrap().is_tombstone());
        // A box only b holds is found by a read at a, and adopted.
        let (only, s, c) = seal(false);
        eb.store.put(&only, &s, &c, 0, &[], b"").unwrap();
        let r = ea.handle_read(&wire::encode_read(&only), &[b.to_vec()], &na).await.unwrap();
        assert_eq!(wire::decode_reply(&r).unwrap().found, Some((s, c)));
        assert!(ea.store.get(&only).unwrap().is_some());
        let miss = ea.handle_read(&wire::encode_read(&[3; 32]), &[b.to_vec()], &na).await.unwrap();
        assert_eq!(miss, [wire::NOT_FOUND]);
        // Unreachable then back: synced again.
        assert_eq!(ea.sync(&[], &na).await.unwrap(), 0);
        assert_eq!(ea.sync(&[b.to_vec()], &na).await.unwrap(), 1);
    }

    #[test]
    fn sync_refuses_out_of_range_reply_and_closed_mode() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path(), "e", d(b"me"), &[], Mode::Closed, false);
        assert!(e.handle_sync(&wire::encode_sync(&[[0; 32], [0xff; 32]].concat(), &[]), None).unwrap().is_empty());
        let e = engine(dir.path(), "o", d(b"me"), &[], Mode::Open, false);
        assert!(e.handle_sync(&wire::encode_sync(&[[9; 32], [1; 32]].concat(), &[]), None).unwrap().is_empty());
        assert_eq!(e.handle_sync(&wire::encode_sync(&[[0; 32], [0xff; 32]].concat(), &[]), None).unwrap(), [0xff; 32]);
    }

    #[tokio::test]
    async fn closed_handoff_drops_only_after_both_owners_ack_and_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let (me, peers) = (d(b"me"), [d(b"r2"), d(b"r3"), d(b"r4")]);
        let e = engine(dir.path(), "e", me, &peers, Mode::Closed, false);
        let reach: Vec<Dst> = peers.iter().map(|p| p.to_vec()).collect();
        // A box this replica does not own.
        let (b, s, c) = loop {
            let x = seal(false);
            if !e.owners(&x.0).contains(&me.to_vec()) {
                break x;
            }
        };
        e.store.put(&b, &s, &c, 0, &[], b"").unwrap();
        assert_eq!(e.handoff(&reach).unwrap(), 0);
        let owners = e.owners(&b);
        assert_eq!(e.store.queued(&b).unwrap(), owners.iter().cloned().collect());
        e.store.ack(&b, &owners[0]).unwrap();
        assert_eq!(e.handoff(&reach).unwrap(), 0);
        e.store.ack(&b, &owners[1]).unwrap();
        assert_eq!(e.handoff(&reach).unwrap(), 1);
        assert!(e.store.get(&b).unwrap().is_none());

        // With a bridge heard, the box also waits for the bridge.
        let br = d(b"br");
        e.heard(&br, &ident(&br), true, &wire::mixnet_id(""));
        let (b, s, c) = loop {
            let x = seal(false);
            if !e.owners(&x.0).contains(&me.to_vec()) {
                break x;
            }
        };
        e.store.put(&b, &s, &c, 0, &[], b"").unwrap();
        let reach: Vec<Dst> = reach.into_iter().chain([br.to_vec()]).collect();
        e.handoff(&reach).unwrap();
        let owners = e.owners(&b);
        assert!(e.store.queued(&b).unwrap().contains(&br[..]) || owners.contains(&br.to_vec()));
        for o in &owners {
            e.store.ack(&b, o).unwrap();
        }
        if !owners.contains(&br.to_vec()) {
            assert_eq!(e.handoff(&reach).unwrap(), 0, "the bridge has not acked");
            e.store.ack(&b, &br).unwrap();
        }
        assert_eq!(e.handoff(&reach).unwrap(), 1);
    }

    #[test]
    fn open_bridge_replica_pushes_to_mixnet_and_gc() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path(), "e", d(b"me"), &[], Mode::Open, true);
        let (b, s, c) = seal(false);
        e.handle_write(&wire::encode_write(&b, &s, &c), &[], None);
        assert_eq!(e.store.queued(&b).unwrap(), HashSet::from([BRIDGE.to_vec()]));
        *e.clock.lock().unwrap() = Some(1000.0 + 3.0 * EPOCH_SECONDS);
        assert_eq!(e.gc().unwrap(), 1);
        assert_eq!(epoch_at(EPOCH_BASE + 3.0 * EPOCH_SECONDS + 5.0), 3);
    }

    /// A node's name, and for a bridge its mixnet's name and the mixnet.
    type Node<'a> = (&'a [u8; 2], Option<(&'a str, &'a MixnetRef)>);

    /// Open mesh replicas that all reach each other, a node with a mixnet its bridge.
    struct Bridged {
        mesh: Mesh,
        nodes: Vec<Dst>,
    }

    impl Bridged {
        fn new(dir: &std::path::Path, nodes: &[Node]) -> Bridged {
            let mesh = Mesh::default();
            let ids: Vec<Dst> = nodes.iter().map(|(n, _)| d(n).to_vec()).collect();
            for (n, mx) in nodes {
                let me = d(n);
                let mut e = engine(dir, &hex::encode(n), me, &[], Mode::Open, mx.is_some());
                if let Some((name, mx)) = mx {
                    e = e.bridging(wire::mixnet_id(name), true);
                    mesh.mixnets.lock().unwrap().insert(me.to_vec(), (*mx).clone());
                }
                for (m, mmx) in nodes {
                    if m != n {
                        let mid = mmx.map(|(name, _)| wire::mixnet_id(name)).unwrap_or_default();
                        e.heard(&d(m), &ident(&d(m)), mmx.is_some(), &mid);
                    }
                }
                mesh.engines.lock().unwrap().insert(me.to_vec(), Arc::new(e));
            }
            Bridged { mesh, nodes: ids }
        }

        fn e(&self, n: &[u8; 2]) -> Arc<Engine> {
            self.mesh.get(&d(n)).unwrap()
        }

        fn reach(&self, n: &[u8]) -> Vec<Dst> {
            self.nodes.iter().filter(|m| m[..] != *n).cloned().collect()
        }

        async fn run(&self, rounds: usize) {
            for _ in 0..rounds {
                for n in &self.nodes {
                    let (e, net, reach) = (self.mesh.get(n).unwrap(), self.mesh.at(n), self.reach(n));
                    e.handoff(&reach).unwrap();
                    e.sync(&reach, &net).await.unwrap();
                    e.forward_due(&reach, &net).await.unwrap();
                }
                for n in &self.nodes {
                    let e = self.mesh.get(n).unwrap();
                    let t = e.clock.lock().unwrap().unwrap() + 700.0;
                    *e.clock.lock().unwrap() = Some(t);
                }
            }
        }

        async fn read(&self, n: &[u8; 2], b: &BoxId) -> Reply {
            let raw = self.e(n).handle_read(&wire::encode_read(b), &self.reach(&d(n)), &self.mesh.at(&d(n))).await.unwrap();
            wire::decode_reply(&raw).unwrap()
        }

        fn write(&self, n: &[u8; 2], (b, s, c): &(BoxId, Vec<u8>, Vec<u8>)) -> u8 {
            self.e(n).handle_write(&wire::encode_write(b, s, c), &self.reach(&d(n)), None)[0]
        }
    }

    fn cap() -> WriteCap {
        WriteCap::generate(&mut UnwrapErr(getrandom::SysRng))
    }

    #[tokio::test]
    async fn two_mixnets_are_linked_without_loops() {
        let dir = tempfile::tempdir().unwrap();
        let (mxa, mxb): (MixnetRef, MixnetRef) = Default::default();
        let m = Bridged::new(dir.path(), &[(b"aa", Some(("A", &mxa))), (b"bb", Some(("B", &mxb))), (b"rr", None)]);
        let caps = [cap(), cap(), cap()];
        // Written on mixnet A, read on the mesh: pulled by bridge a.
        let b1 = seal_with(&caps[0], false);
        mxa.lock().unwrap().boxes.insert(b1.0, (b1.1.clone(), b1.2.clone()));
        assert_eq!(m.read(b"rr", &b1.0).await.found, Some((b1.1.clone(), b1.2.clone())));
        assert_eq!(m.e(b"aa").store.get(&b1.0).unwrap().unwrap().origin, wire::mixnet_id("A"));
        // Written on mixnet B, read at bridge a, which finds it through bridge b.
        let b2 = seal_with(&caps[1], false);
        mxb.lock().unwrap().boxes.insert(b2.0, (b2.1.clone(), b2.2.clone()));
        assert_eq!(m.read(b"aa", &b2.0).await.code, wire::SUCCESS);
        // Written by a mesh client.
        let b3 = seal_with(&caps[2], false);
        assert_eq!(m.write(b"rr", &b3), wire::SUCCESS);
        m.run(4).await;
        for n in [b"aa", b"bb", b"rr"] {
            assert_eq!(m.e(n).store.get(&b1.0).unwrap().unwrap().origin, wire::mixnet_id("A"));
            assert_eq!(m.e(n).store.get(&b2.0).unwrap().unwrap().origin, wire::mixnet_id("B"));
            assert!(m.e(n).store.get(&b3.0).unwrap().unwrap().origin.is_empty());
        }
        let sorted = |mx: &MixnetRef| {
            let mut w = mx.lock().unwrap().writes.clone();
            w.sort();
            w
        };
        let mut want_a = vec![(b2.0, false), (b3.0, false)];
        want_a.sort();
        let mut want_b = vec![(b1.0, false), (b3.0, false)];
        want_b.sort();
        assert_eq!(sorted(&mxa), want_a, "nothing written back to its origin");
        assert_eq!(sorted(&mxb), want_b);
        // A tombstone written on the mesh replaces the box in both mixnets, once each.
        let t1 = seal_with(&caps[0], true);
        assert_eq!(m.write(b"bb", &t1), wire::SUCCESS);
        m.run(4).await;
        for mx in [&mxa, &mxb] {
            assert_eq!(mx.lock().unwrap().boxes[&b1.0], (t1.1.clone(), vec![]));
            assert_eq!(mx.lock().unwrap().count(&b1.0, true), 1);
        }
        let before = (sorted(&mxa), sorted(&mxb));
        m.run(6).await;
        assert_eq!((sorted(&mxa), sorted(&mxb)), before, "no loop");
    }

    #[tokio::test]
    async fn two_bridges_to_one_mixnet_write_each_box_once() {
        let dir = tempfile::tempdir().unwrap();
        let mx: MixnetRef = Default::default();
        let m = Bridged::new(dir.path(), &[(b"a1", Some(("A", &mx))), (b"a2", Some(("A", &mx))), (b"rr", None)]);
        let caps: Vec<_> = (0..6).map(|_| cap()).collect();
        let boxes: Vec<_> = caps.iter().map(|c| seal_with(c, false)).collect();
        for (i, b) in boxes.iter().enumerate() {
            assert_eq!(m.write([b"rr", b"a1", b"a2"][i % 3], b), wire::SUCCESS);
        }
        let t0 = seal_with(&caps[0], true);
        m.write(b"rr", &t0);
        let pulled = seal(false);
        mx.lock().unwrap().boxes.insert(pulled.0, (pulled.1.clone(), pulled.2.clone()));
        assert_eq!(m.read(b"rr", &pulled.0).await.code, wire::SUCCESS);
        m.run(4).await;
        let mx = mx.lock().unwrap();
        for b in &boxes[1..] {
            assert_eq!(mx.boxes[&b.0], (b.1.clone(), b.2.clone()));
            assert_eq!(mx.count(&b.0, false), 1);
        }
        assert_eq!(mx.boxes[&t0.0], (t0.1.clone(), vec![]));
        assert_eq!(mx.count(&t0.0, true), 1);
        assert!(mx.count(&boxes[0].0, false) <= 1, "the box before its tombstone, at most once");
        assert_eq!(mx.count(&pulled.0, false), 0);
        for n in [b"a1", b"a2"] {
            assert!(!m.e(n).store.queued(&pulled.0).unwrap().contains(BRIDGE));
        }
    }
}
