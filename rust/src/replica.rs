//! The replica daemon, as `replica.py`: one Reticulum destination whose Link requests and
//! Channel messages are client reads and writes and the replica paths `peek`, `sync`,
//! `forward` and `pushed`, which it also asks other replicas in either mode, subscribe and
//! unsubscribe, pushes of boxes to the Links subscribed to them, and tasks for forwarding,
//! handoff and sync, garbage collection and announcing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use reticulum_id::{Fingerprint, PrivateBlob};
use reticulum_link::LinkId;
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio::time::sleep;

use crate::bridge::Bridge;
use crate::channel;
use crate::config;
use crate::engine::{BRIDGE, Engine, Net as EngineNet};
use crate::net::{self, Answer, Cmd, Event, How, Net};
use crate::push::{self, Subscriptions};
use crate::store::{Dst, Store};
use crate::wire::{self, BoxId, Reply};

// Channel mode's limits: workers per Link, queries waiting per Link, and handlers running at
// once across the replica.
const CHANNEL_WORKERS: usize = 2;
const CHANNEL_QUEUE: usize = 16;
const CHANNEL_HANDLERS: usize = 32;
const FORWARD_INTERVAL: Duration = Duration::from_secs(2);
const HANDOFF_INTERVAL: Duration = Duration::from_secs(30);
/// The longest wait between GC runs, so a clock jump is caught within it.
const GC_INTERVAL: Duration = Duration::from_secs(3600);
/// Before subscribing again to the Katzenpost replica after its stream ends.
const STREAM_RETRY: Duration = Duration::from_secs(5);
// Announce flags: bridge, serves mode 2, serves the replica paths in mode 2, no Link requests,
// serves push.
const BRIDGE_FLAG: u8 = 1;
const FLAGS: u8 = 2 | 4 | 16;
const PATHS_FLAG: u8 = 4;
const NO_REQUESTS_FLAG: u8 = 8;

pub struct Options {
    pub config_dir: PathBuf,
    pub storage: PathBuf,
    /// Box ciphertext sizes taken, any when empty.
    pub box_sizes: Vec<usize>,
    pub bridge_socket: Option<PathBuf>,
    pub mixnet: String,
    pub forward_all: bool,
    pub announce_interval: Duration,
    /// Seconds in a replica epoch.
    pub epoch_seconds: f64,
    pub max_storage_bytes: u64,
    pub min_free_storage_bytes: u64,
}

/// A Link's queries waiting for its workers: how each is answered, its sender, the query.
type Queue = mpsc::Sender<(Answer, Option<Fingerprint>, Vec<u8>)>;

pub struct Replica {
    engine: Engine,
    net: Net,
    bridge: Option<Bridge>,
    /// Forwards keep a connection of their own, so reads filling the pool cannot delay them.
    bridge_writes: Option<Bridge>,
    handlers: Semaphore,
    /// Wakes the forwarder when a write, forward or sync queues forwards.
    kick: Notify,
    /// Each replica's announce flags.
    flags: StdMutex<HashMap<Dst, u8>>,
    subs: StdMutex<Subscriptions<LinkId>>,
    /// Each Link's next push id.
    push_ids: StdMutex<HashMap<LinkId, u16>>,
    queues: StdMutex<HashMap<LinkId, Queue>>,
}

impl EngineNet for Replica {
    async fn deliver(&self, dst: &[u8], box_id: &BoxId, sig: &[u8], ct: &[u8], origin: &[u8]) -> Option<u8> {
        if dst == BRIDGE {
            return self.bridge_writes.as_ref()?.write(box_id, sig, ct).await;
        }
        let q = wire::encode_write(box_id, sig, ct);
        let r = if origin.is_empty() {
            self.ask(dst, "write", &q, &q).await
        } else {
            let data = [origin, &q].concat();
            self.ask(dst, "forward", &data, &[&[channel::FORWARD][..], &data].concat()).await
        };
        r?.first().copied()
    }

    async fn request(&self, dst: &[u8], path: &str, data: Vec<u8>) -> Option<Vec<u8>> {
        let (path, op) = match path {
            "peek" => ("peek", channel::PEEK),
            "sync" => ("sync", channel::SYNC),
            "forward" => ("forward", channel::FORWARD),
            "pushed" => ("pushed", channel::PUSHED),
            _ => return None,
        };
        self.ask(dst, path, &data, &[&[op][..], &data].concat()).await
    }

    async fn bridge_read(&self, box_id: &BoxId) -> Option<Reply> {
        self.bridge.as_ref()?.read(box_id).await
    }
}

/// The replica's identity, kept in the 64 byte file RNS writes and reads.
fn identity(path: &Path) -> std::io::Result<PrivateBlob> {
    if let Ok(b) = std::fs::read(path) {
        return b.try_into().map_err(|_| std::io::Error::other("bad identity file"));
    }
    let mut blob = [0u8; 64];
    OsRng.fill_bytes(&mut blob);
    std::fs::write(path, blob)?;
    Ok(blob)
}

impl Replica {
    /// Asks `dst` the mode 2 message `msg` when it serves the replica paths there, and the Link
    /// request `path` with `data` when it does not or mode 2 fails, unless it serves no Link
    /// requests.
    async fn ask(&self, dst: &[u8], path: &'static str, data: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        let flags = self.flags.lock().unwrap().get(dst).copied().unwrap_or(0);
        if flags & PATHS_FLAG != 0 {
            let r = self.net.query(dst, How::Channel(msg.to_vec())).await;
            if r.is_some() || flags & NO_REQUESTS_FLAG != 0 {
                return r;
            }
        }
        if flags & NO_REQUESTS_FLAG != 0 {
            return None;
        }
        self.net.query(dst, How::Request(path, data.to_vec())).await
    }

    fn reachable(&self) -> Vec<Dst> {
        let flags = self.flags.lock().unwrap();
        let can = |f: u8| f & PATHS_FLAG != 0 || f & NO_REQUESTS_FLAG == 0;
        self.engine.peers().into_iter().filter(|d| flags.get(d).is_some_and(|f| can(*f))).collect()
    }

    /// The message's first byte picks the handler, a read or a write query or a replica path,
    /// whose sender is the replica the Link identified as.
    async fn on_message(&self, msg: &[u8], sender: Option<Dst>, link: &LinkId) -> Vec<u8> {
        let (reach, e, s) = (self.reachable(), &self.engine, sender.as_ref());
        let body = msg.get(1..).unwrap_or_default();
        let r = match msg.first() {
            Some(&wire::READ) => e.handle_read(msg, &reach, self).await,
            Some(&wire::WRITE) => Ok(e.handle_write(msg, &reach, s)),
            Some(&channel::PEEK) => e.handle_peek(body, &reach, self).await,
            Some(&channel::SYNC) => e.handle_sync(body, s),
            Some(&channel::FORWARD) => Ok(e.handle_forward(body, &reach, s)),
            Some(&channel::PUSHED) => e.handle_pushed(body),
            Some(&push::SUBSCRIBE) => Ok(self.subscribe(link, body)),
            Some(&push::UNSUBSCRIBE) => Ok(match push::decode_ids(body) {
                Some(ids) => {
                    self.subs.lock().unwrap().unsubscribe(link, &ids);
                    vec![wire::SUCCESS]
                }
                None => vec![wire::INVALID_PAYLOAD],
            }),
            _ => Ok(vec![wire::INVALID_PAYLOAD]),
        };
        if matches!(msg.first(), Some(&wire::WRITE | &channel::SYNC | &channel::FORWARD)) {
            self.kick.notify_one();
        }
        r.unwrap_or_else(|err| {
            log::error!("pigeonhole: store: {err}");
            vec![4] // DATABASE_FAILURE
        })
    }

    /// Subscribes the Link, then pushes at once what is already held.
    fn subscribe(&self, link: &LinkId, body: &[u8]) -> Vec<u8> {
        let Some((ttl, ids)) = push::decode_subscribe(body) else {
            return vec![wire::INVALID_PAYLOAD];
        };
        let (taken, ttl) = self.subs.lock().unwrap().subscribe(link, ttl, &ids, Instant::now());
        for b in &ids[..taken as usize] {
            if matches!(self.engine.store.get(b), Ok(Some(_))) {
                self.stored(b);
            }
        }
        push::encode_subscribe_reply(taken, ttl)
    }

    /// Pushes a box just stored to the Links waiting for it.
    fn stored(&self, box_id: &BoxId) {
        let links = self.subs.lock().unwrap().take(box_id, Instant::now());
        if links.is_empty() {
            return;
        }
        let Ok(Some(r)) = self.engine.local(box_id) else {
            return;
        };
        let msg = push::encode_push(box_id, &r);
        let mut ids = self.push_ids.lock().unwrap();
        for link in links {
            let id = ids.entry(link).or_default();
            self.net.send(Cmd::Reply { link, answer: Answer::Push(*id), data: msg.clone() });
            *id = id.wrapping_add(1);
        }
    }

    /// A query on `link`, to its queue of CHANNEL_QUEUE served by CHANNEL_WORKERS workers, at
    /// most CHANNEL_HANDLERS handling at once across the replica. A query arriving to a full
    /// queue is dropped; its client times out and asks again.
    fn accept(self: &Arc<Self>, link: LinkId, sender: Option<Fingerprint>, answer: Answer, data: Vec<u8>) {
        let mut queues = self.queues.lock().unwrap();
        let q = queues.entry(link).or_insert_with(|| {
            let (tx, rx) = mpsc::channel::<(Answer, Option<Fingerprint>, Vec<u8>)>(CHANNEL_QUEUE);
            let rx = Arc::new(Mutex::new(rx));
            for _ in 0..CHANNEL_WORKERS {
                let (r, rx) = (self.clone(), rx.clone());
                tokio::spawn(async move {
                    loop {
                        let Some((answer, sender, q)) = rx.lock().await.recv().await else {
                            return;
                        };
                        let sender = sender.and_then(|i| r.engine.peer_of(&i));
                        let data = {
                            let _permit = r.handlers.acquire().await;
                            r.on_message(&q, sender, &link).await
                        };
                        r.net.send(Cmd::Reply { link, answer, data });
                    }
                });
            }
            tx
        });
        if q.try_send((answer, sender, data)).is_err() {
            log::warn!("pigeonhole: query queue full on a link, query dropped");
        }
    }

    /// Announces of other replicas: flags, then for a bridge the id of its mixnet.
    fn heard(&self, dest: Dst, identity: Fingerprint, data: &[u8]) {
        let flags = data.first().copied().unwrap_or(0);
        let bridge = flags & BRIDGE_FLAG != 0;
        let mixnet = match data.get(1..1 + wire::MIXNET_ID_SIZE) {
            Some(m) if bridge => m.to_vec(),
            _ => wire::mixnet_id(""),
        };
        if self.engine.heard(&dest, &identity, bridge, &mixnet) {
            self.flags.lock().unwrap().insert(dest, flags);
        } else {
            log::warn!("pigeonhole: ignoring announce with a changed key for {}", hex::encode(dest));
        }
    }

    fn closed(&self, link: &LinkId) {
        self.queues.lock().unwrap().remove(link);
        self.push_ids.lock().unwrap().remove(link);
        self.subs.lock().unwrap().drop_link(link);
    }
}

pub async fn run(o: Options) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&o.storage)?;
    let blob = identity(&o.storage.join("identity"))?;
    let cfg_path = o.config_dir.join("config");
    let cfg = config::parse(&std::fs::read_to_string(&cfg_path).map_err(|e| format!("{}: {e}", cfg_path.display()))?);
    let (net, mut events) = net::start(blob, &cfg.ifaces, cfg.transport)?;
    let self_dest = net.dest;

    let bridge = o.bridge_socket.as_ref().map(|p| Bridge::new(p.clone(), 8));
    let bridge_writes = o.bridge_socket.as_ref().map(|p| Bridge::new(p.clone(), 1));
    let mut engine = Engine::new(
        Store::open_limited(&o.storage.join("boxes.sqlite"), o.max_storage_bytes, o.min_free_storage_bytes)?,
        self_dest,
        net.identity,
        o.box_sizes.clone(),
        bridge.is_some(),
    )
    .bridging(wire::mixnet_id(&o.mixnet), o.forward_all);
    engine.epoch_seconds = o.epoch_seconds;
    let (stored_tx, mut stored_rx) = mpsc::unbounded_channel();
    engine.on_stored = Some(stored_tx);
    if bridge.is_some() && o.epoch_seconds != crate::engine::EPOCH_SECONDS {
        log::warn!(
            "pigeonhole: replica epoch {}s differs from Katzenpost's {}s; bridged boxes expire out of step",
            o.epoch_seconds,
            crate::engine::EPOCH_SECONDS
        );
    }
    let r = Arc::new(Replica {
        engine,
        net,
        bridge,
        bridge_writes,
        handlers: Semaphore::new(CHANNEL_HANDLERS),
        kick: Notify::new(),
        flags: StdMutex::default(),
        subs: StdMutex::new(Subscriptions::new(push::LIMIT)),
        push_ids: StdMutex::default(),
        queues: StdMutex::default(),
    });

    let rr = r.clone();
    tokio::spawn(async move {
        while let Some(e) = events.recv().await {
            match e {
                Event::Heard { dest, identity, app_data } => rr.heard(dest.to_vec(), identity, &app_data),
                Event::Message { link, sender, answer, data } => rr.accept(link, sender, answer, data),
                Event::Closed(link) => rr.closed(&link),
            }
        }
    });

    let rr = r.clone();
    tokio::spawn(async move {
        while let Some(b) = stored_rx.recv().await {
            rr.stored(&b);
        }
    });

    let mut app_data = vec![FLAGS | if r.bridge.is_some() { BRIDGE_FLAG } else { 0 }];
    if r.bridge.is_some() {
        app_data.extend_from_slice(&r.engine.mixnet);
    }
    let (rr, every) = (r.clone(), o.announce_interval);
    tokio::spawn(async move {
        loop {
            rr.net.send(Cmd::Announce(app_data.clone()));
            sleep(every).await;
        }
    });
    let rr = r.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sleep(FORWARD_INTERVAL) => {}
                _ = rr.kick.notified() => {}
            }
            let reach = rr.reachable();
            if let Err(e) = rr.engine.forward_due(&reach, &*rr).await {
                log::error!("pigeonhole: forwarder: {e}");
            }
        }
    });
    let rr = r.clone();
    tokio::spawn(async move {
        loop {
            sleep(HANDOFF_INTERVAL).await;
            let reach = rr.reachable();
            if let Err(e) = rr.engine.handoff() {
                log::error!("pigeonhole: handoff: {e}");
            }
            if let Err(e) = rr.engine.sync(&reach, &*rr).await {
                log::error!("pigeonhole: sync: {e}");
            }
        }
    });
    let rr = r.clone();
    tokio::spawn(async move {
        // Once at start, then just past each replica epoch boundary.
        loop {
            match rr.engine.gc() {
                Ok(0) => {}
                Ok(n) => log::info!("pigeonhole: gc dropped {n} boxes older than replica epoch {}", rr.engine.epoch() - 1),
                Err(e) => log::error!("pigeonhole: gc: {e}"),
            }
            sleep(GC_INTERVAL.min(Duration::from_secs_f64(rr.engine.till_next_epoch() + 1.0))).await;
        }
    });

    // Each box the Katzenpost replica announces; when the stream ends, subscribe again from the
    // last epoch seen. Boxes announced again are already held and go nowhere.
    if r.bridge.is_some() {
        let rr = r.clone();
        tokio::spawn(async move {
            let mut since = 0;
            loop {
                let (tx, mut rx) = mpsc::channel(64);
                let rb = rr.clone();
                let reader = tokio::task::spawn_blocking(move || rb.bridge.as_ref().unwrap().stream(since, &tx));
                while let Some((epoch, q)) = rx.recv().await {
                    since = since.max(epoch);
                    let reach = rr.reachable();
                    match rr.engine.announced(&q, &reach) {
                        Ok(wire::SUCCESS) => rr.kick.notify_one(),
                        Ok(_) => {}
                        Err(e) => log::error!("pigeonhole: store: {e}"),
                    }
                }
                if let Ok(Err(e)) = reader.await {
                    log::debug!("pigeonhole: bridge stream: {e}");
                }
                sleep(STREAM_RETRY).await;
            }
        });
    }

    log::info!("pigeonhole: replica {} up{}", hex::encode(self_dest), if r.bridge.is_some() { ", bridge" } else { "" });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    // Closes the Links this replica opened, as the stack thread ends.
    r.net.send(Cmd::Shutdown);
    sleep(Duration::from_millis(200)).await;
    Ok(())
}
