//! The replica daemon, as `replica.py` but serving query mode 2 alone: one Reticulum
//! destination whose Channel messages are client reads and writes and the replica paths
//! `peek`, `sync`, `forward` and `pushed`, which it also asks other replicas, falling back to
//! Link requests through Python RNS with feature `reticulum-py`, subscribe and unsubscribe,
//! pushes of boxes to the Links subscribed to them, and tasks for forwarding, handoff and
//! sync, garbage collection and announcing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::destination::link::{Link, LinkEvent, LinkId, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{TimerConfig, Transport, TransportConfig};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio::time::{interval, sleep, timeout};

use crate::bridge::Bridge;
use crate::channel::{self, Frame, Reassembler};
use crate::config::{self, Iface};
use crate::engine::{BRIDGE, Engine, Net};
use crate::mesh::{self, Mesh};
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
/// RNS's Link stale time; Reticulum-rs defaults to 10 seconds, shorter than a Python peer's
/// keepalive on a slow link.
const LINK_STALE: Duration = Duration::from_secs(720);
// Announce flags: bridge, serves mode 2, serves the replica paths in mode 2, no Link requests,
// serves push.
const BRIDGE_FLAG: u8 = 1;
const FLAGS: u8 = 2 | 4 | 8 | 16;
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
    /// With feature `reticulum-py`: the config directory of the Python Reticulum instance that
    /// reaches replicas not serving the replica paths in mode 2.
    pub py_config: Option<PathBuf>,
}

pub struct Replica {
    engine: Engine,
    mesh: Mesh,
    t: Arc<Transport>,
    bridge: Option<Bridge>,
    /// Forwards keep a connection of their own, so reads filling the pool cannot delay them.
    bridge_writes: Option<Bridge>,
    handlers: Semaphore,
    /// Wakes the forwarder when a write, forward or sync queues forwards.
    kick: Notify,
    /// Each replica's announce flags.
    flags: StdMutex<HashMap<Dst, u8>>,
    subs: StdMutex<Subscriptions<LinkId>>,
    /// Each Link's push queue, drained by a task of its own.
    pushers: StdMutex<HashMap<LinkId, mpsc::Sender<Vec<u8>>>>,
    #[cfg(feature = "reticulum-py")]
    py: Option<crate::pyfallback::PyLinks>,
}

impl Net for Replica {
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
        let op = match path {
            "peek" => channel::PEEK,
            "sync" => channel::SYNC,
            "forward" => channel::FORWARD,
            "pushed" => channel::PUSHED,
            _ => return None,
        };
        self.ask(dst, path, &data, &[&[op][..], &data].concat()).await
    }

    async fn bridge_read(&self, box_id: &BoxId) -> Option<Reply> {
        self.bridge.as_ref()?.read(box_id).await
    }
}

/// The replica's identity, kept in the 64 byte file RNS writes and reads.
fn identity(path: &Path) -> std::io::Result<PrivateIdentity> {
    if let Ok(b) = std::fs::read(path) {
        return PrivateIdentity::new_from_hex_string(&hex::encode(b))
            .map_err(|_| std::io::Error::other("bad identity file"));
    }
    let id = PrivateIdentity::new_from_rand(OsRng);
    std::fs::write(path, hex::decode(id.to_hex_string()).unwrap())?;
    Ok(id)
}

impl Replica {
    fn has_fallback(&self) -> bool {
        #[cfg(feature = "reticulum-py")]
        return self.py.is_some();
        #[cfg(not(feature = "reticulum-py"))]
        false
    }

    /// Asks `dst` the mode 2 message `msg` when it serves the replica paths there, and the Link
    /// request `path` with `data` through Python RNS when it does not or mode 2 fails, unless it
    /// serves no Link requests.
    async fn ask(&self, dst: &[u8], path: &str, data: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        let flags = self.flags.lock().unwrap().get(dst).copied().unwrap_or(0);
        if flags & PATHS_FLAG != 0 {
            let r = self.mesh.query(dst, msg).await;
            if r.is_some() || flags & NO_REQUESTS_FLAG != 0 {
                return r;
            }
        }
        #[cfg(feature = "reticulum-py")]
        if let Some(py) = &self.py
            && flags & NO_REQUESTS_FLAG == 0
        {
            return py.request(dst, path, data).await;
        }
        let _ = (path, data);
        None
    }

    async fn reachable(&self) -> Vec<Dst> {
        let flags = self.flags.lock().unwrap().clone();
        let can = |f: u8| f & PATHS_FLAG != 0 || (self.has_fallback() && f & NO_REQUESTS_FLAG == 0);
        let mut out = Vec::new();
        for d in self.engine.peers() {
            if let Ok(a) = d.as_slice().try_into()
                && flags.get(&d).is_some_and(|f| can(*f))
                && self.t.knows_destination(&AddressHash::new(a)).await
            {
                out.push(d);
            }
        }
        out
    }

    /// The message's first byte picks the handler, a read or a write query or a replica path,
    /// whose sender is the replica the Link identified as.
    async fn on_message(&self, msg: &[u8], sender: Option<Dst>, link: &LinkId) -> Vec<u8> {
        let (reach, e, s) = (self.reachable().await, &self.engine, sender.as_ref());
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
        let pushers = self.pushers.lock().unwrap();
        for l in links {
            if let Some(tx) = pushers.get(&l)
                && tx.try_send(msg.clone()).is_err()
            {
                log::warn!("pigeonhole: push queue full on a link, push dropped");
            }
        }
    }

    /// Mode 2 on one Link: CHANNEL_WORKERS handlers taking queries from a queue of
    /// CHANNEL_QUEUE, and at most CHANNEL_HANDLERS handling at once across the replica. A
    /// query arriving to a full queue is dropped; its client times out and asks again.
    async fn serve_channel(self: Arc<Self>, link: Arc<Mutex<Link>>) {
        let Ok((ch, mut rx)) = self.t.mk_channel::<Frame>(link.clone()).await else {
            return;
        };
        let ch = Arc::new(ch);
        let link_id = *link.lock().await.id();
        // Pushes go on a task of their own, as they wait for the Channel window.
        let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(push::LIMIT);
        self.pushers.lock().unwrap().insert(link_id, ptx);
        let (pch, plink) = (ch.clone(), link.clone());
        tokio::spawn(async move {
            let mut push_id: u16 = 0;
            while let Some(msg) = prx.recv().await {
                if let Some(frames) = channel::split(push_id, &msg) {
                    let frames: Vec<Frame> =
                        frames.into_iter().map(|f| Frame { msgtype: channel::PUSH_MSGTYPE, ..f }).collect();
                    let _ = timeout(mesh::QUERY_TIMEOUT, mesh::send_frames(&pch, &plink, &frames)).await;
                }
                push_id = push_id.wrapping_add(1);
            }
        });
        let (qtx, qrx) = mpsc::channel::<(u16, Vec<u8>)>(CHANNEL_QUEUE);
        let qrx = Arc::new(Mutex::new(qrx));
        for _ in 0..CHANNEL_WORKERS {
            let (r, qrx, ch, link) = (self.clone(), qrx.clone(), ch.clone(), link.clone());
            tokio::spawn(async move {
                loop {
                    let Some((rid, q)) = qrx.lock().await.recv().await else {
                        return;
                    };
                    let id = link.lock().await.remote_identity().map(|i| i.address_hash);
                    let sender = id.and_then(|i| r.engine.peer_of(i.as_slice()));
                    let reply = {
                        let _permit = r.handlers.acquire().await;
                        r.on_message(&q, sender, &link_id).await
                    };
                    if let Some(frames) = channel::split(rid, &reply) {
                        let _ = timeout(mesh::QUERY_TIMEOUT, mesh::send_frames(&ch, &link, &frames)).await;
                    }
                }
            });
        }
        let mut reasm = Reassembler::default();
        let mut tick = interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Ok(f) if f.msgtype == channel::MSGTYPE => {
                        let rid = f.request_id;
                        if let Some(q) = reasm.feed(f)
                            && qtx.try_send((rid, q)).is_err()
                        {
                            log::warn!("pigeonhole: channel queue full on a link, query dropped");
                        }
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                },
                // shortcut: Reticulum-rs keeps a closed Link's Channel tasks; ours end here.
                _ = tick.tick() => if link.lock().await.status() == LinkStatus::Closed {
                    break;
                },
            }
        }
        // Ends the push task too.
        self.pushers.lock().unwrap().remove(&link_id);
        self.subs.lock().unwrap().drop_link(&link_id);
    }
}

/// A TCP server interface, as Reticulum-rs's but with TCP_NODELAY on each connection, as
/// Python RNS sets: without it a reply waits for the delayed ACK of the proof before it.
fn tcp_server(addr: String, m: Arc<Mutex<reticulum::iface::InterfaceManager>>) {
    tokio::spawn(async move {
        let l = loop {
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => break l,
                Err(e) => {
                    log::warn!("pigeonhole: listen on {addr}: {e}");
                    sleep(Duration::from_secs(5)).await
                }
            }
        };
        loop {
            if let Ok((s, peer)) = l.accept().await {
                let _ = s.set_nodelay(true);
                m.lock().await.spawn(TcpClient::new_from_stream(peer.to_string(), s), TcpClient::spawn);
            }
        }
    });
}

pub async fn run(o: Options) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&o.storage)?;
    let me = identity(&o.storage.join("identity"))?;
    #[cfg(feature = "reticulum-py")]
    let py = match &o.py_config {
        Some(dir) => Some(crate::pyfallback::PyLinks::start(dir, &o.storage.join("identity")).map_err(|e| format!("python: {e}"))?),
        None => None,
    };
    #[cfg(not(feature = "reticulum-py"))]
    if o.py_config.is_some() {
        return Err("--py-config needs the reticulum-py feature".into());
    }
    let cfg_path = o.config_dir.join("config");
    let cfg = config::parse(&std::fs::read_to_string(&cfg_path).map_err(|e| format!("{}: {e}", cfg_path.display()))?);
    let timers = TimerConfig { in_link_stale: LINK_STALE, out_link_stale: LINK_STALE, ..Default::default() };
    // shortcut: Reticulum-rs at the pinned revision keeps the transport header on the last hop
    // to a Python node, which drops the packet, so relaying would draw traffic it cannot
    // deliver; boxes still cross this replica, stored and forwarded. Relay again once fixed.
    if cfg.transport {
        log::info!("pigeonhole: enable_transport ignored, this replica does not relay");
    }
    let mut t = Transport::new(TransportConfig::new("replica", &me).set_retransmit(false).set_timer_config(timers));
    {
        let m = t.iface_manager();
        let mut m = m.lock().await;
        for i in &cfg.ifaces {
            match i {
                Iface::TcpServer(a) => {
                    tcp_server(a.clone(), t.iface_manager());
                    continue;
                }
                Iface::TcpClient(a) => m.spawn(TcpClient::new(a.as_str()), TcpClient::spawn),
                Iface::Udp { listen, forward } => {
                    m.spawn(UdpInterface::new(listen.as_str(), forward.as_deref(), false), UdpInterface::spawn)
                }
            };
        }
    }
    let name = DestinationName::new("pigeonhole", "replica");
    let dest = t.add_destination(me.clone(), name).await;
    let self_dest = dest.lock().await.desc.address_hash;
    let t = Arc::new(t);

    let bridge = o.bridge_socket.as_ref().map(|p| Bridge::new(p.clone(), 8));
    let bridge_writes = o.bridge_socket.as_ref().map(|p| Bridge::new(p.clone(), 1));
    let mut engine = Engine::new(
        Store::open_limited(&o.storage.join("boxes.sqlite"), o.max_storage_bytes, o.min_free_storage_bytes)?,
        self_dest.as_slice().try_into().unwrap(),
        me.address_hash().as_slice().try_into().unwrap(),
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
        mesh: Mesh::new(t.clone(), me),
        t: t.clone(),
        bridge,
        bridge_writes,
        handlers: Semaphore::new(CHANNEL_HANDLERS),
        kick: Notify::new(),
        flags: StdMutex::default(),
        subs: StdMutex::new(Subscriptions::new(push::LIMIT)),
        pushers: StdMutex::default(),
        #[cfg(feature = "reticulum-py")]
        py,
    });

    // Announces of other replicas: flags, then for a bridge the id of its mixnet.
    let mut announces = t.recv_announces().await;
    let rr = r.clone();
    tokio::spawn(async move {
        loop {
            let a = match announces.recv().await {
                Ok(a) => a,
                Err(RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            let desc = a.destination.lock().await.desc;
            if desc.name.hash.as_slice()[..10] != name.hash.as_slice()[..10] || desc.address_hash == self_dest {
                continue;
            }
            let data = a.app_data.as_slice();
            let flags = data.first().copied().unwrap_or(0);
            let bridge = flags & BRIDGE_FLAG != 0;
            let mixnet = match data.get(1..1 + wire::MIXNET_ID_SIZE) {
                Some(m) if bridge => m.to_vec(),
                _ => wire::mixnet_id(""),
            };
            let dest = desc.address_hash.as_slice().to_vec();
            if rr.engine.heard(&dest, desc.identity.address_hash.as_slice(), bridge, &mixnet) {
                rr.mesh.heard(desc);
                rr.flags.lock().unwrap().insert(dest, flags);
            } else {
                log::warn!("pigeonhole: ignoring announce with a changed key for {}", desc.address_hash);
            }
        }
    });

    let rr = r.clone();
    tokio::spawn(async move {
        while let Some(b) = stored_rx.recv().await {
            rr.stored(&b);
        }
    });

    // Mode 2 on every Link opened to this replica.
    let mut events = t.in_link_events();
    let rr = r.clone();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(e) if matches!(e.event, LinkEvent::Activated) => {
                    if let Some(link) = rr.t.find_in_link(&e.id).await {
                        tokio::spawn(rr.clone().serve_channel(link));
                    }
                }
                Err(RecvError::Closed) => return,
                _ => {}
            }
        }
    });

    let mut app_data = vec![FLAGS | if r.bridge.is_some() { BRIDGE_FLAG } else { 0 }];
    if r.bridge.is_some() {
        app_data.extend_from_slice(&r.engine.mixnet);
    }
    let (rr, every) = (r.clone(), o.announce_interval);
    tokio::spawn(async move {
        loop {
            rr.t.send_announce(&dest, Some(&app_data)).await;
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
            let reach = rr.reachable().await;
            if let Err(e) = rr.engine.forward_due(&reach, &*rr).await {
                log::error!("pigeonhole: forwarder: {e}");
            }
        }
    });
    let rr = r.clone();
    tokio::spawn(async move {
        loop {
            sleep(HANDOFF_INTERVAL).await;
            let reach = rr.reachable().await;
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

    log::info!("pigeonhole: replica {self_dest} up{}", if r.bridge.is_some() { ", bridge" } else { "" });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    // A Link being opened holds its slot up to 20 seconds; shutdown does not wait for it.
    let _ = timeout(Duration::from_secs(2), r.mesh.close_all()).await;
    Ok(())
}
