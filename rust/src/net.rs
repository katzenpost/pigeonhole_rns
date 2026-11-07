//! The replica's Reticulum stack, on berlinmesh/reticulum: one thread owns the router, the
//! endpoint answering Links opened to this replica, the driver of the Links it opens to other
//! replicas, and a Channel on each Link. Interface drivers and the replica's [`Cmd`]s feed it
//! through one queue; it answers with [`Event`]s and query replies. Nothing of the stack is
//! shared, so no lock is held across an `.await` and no event can be lost to a lagging
//! receiver (rust/quint).
//!
//! The library's endpoint and link driver carry Link requests and Resources but leave
//! Channel to the caller: a CHANNEL packet is handed to them as NONE context to decrypt, and
//! one sent goes out as NONE and has its context byte set to CHANNEL here. The context byte
//! is outside the Token, so both stay valid; packet hashes, and so proofs, are taken of the
//! packet as it is on the wire.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::ToSocketAddrs;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use reticulum_announce::{
    AnnounceBuild, build_random_hash, compute_destination_hash, compute_name_hash, encode_announce,
    parse_and_verify_announce_scratch,
};
use reticulum_channel::{Rx, Tx, TxEvent, Verdict};
use reticulum_client::linkdrv::{LinkDrv, LinkEvent, LinkOut, Route};
use reticulum_client::reqresp::RequestKind;
use reticulum_endpoint::{
    Endpoint, EndpointEvent, EndpointOut, Event as EpEvent, LinkPolicy, ProofStrategy, RequestAllow,
    RequestContext, msgpack_bin,
};
use reticulum_id::rustcrypto::RustCryptoSigner;
use reticulum_id::{Fingerprint, PrivateBlob, PublicBlob, Signer, fingerprint};
use reticulum_iface::{IfaceEvent, IfaceId, IfaceIdAlloc, Interface, SendOutcome, wall_ms};
use reticulum_ip_iface::{TcpServer, TcpServerConfig, TcpUplink, TcpUplinkConfig, UdpConfig, UdpDriver};
use reticulum_link::{LinkId, rns_packet_hash};
use reticulum_msgpack::{Decoder, Encoder};
use reticulum_packet::{Header, PacketType, context};
use reticulum_router::{CoreEvent, IfaceMode, IfaceOut, LocalAnnounce, Router};
use tokio::sync::{mpsc as tmpsc, oneshot};

use crate::channel::{self, Frame, Reassembler};
use crate::config::Iface;

pub type DestHash = [u8; 16];

/// The longest a query to another replica waits for its reply, and a mode 1 query from a
/// client for its handler.
pub const QUERY_TIMEOUT_MS: u64 = 60_000;
const ESTABLISH_TIMEOUT_MS: u64 = 20_000;
const TICK_MS: u64 = 250;
/// The longest the thread sleeps with nothing to do, so a Channel resend is not late by more.
const POLL: Duration = Duration::from_millis(20);
/// Unproved envelopes per Channel (the window never passes 5), early ones held, and the
/// largest envelope kept for either.
const TX_SLOTS: usize = 8;
const RX_HELD: usize = 16;
const ENV_CAP: usize = 512;
/// Frames waiting for a Channel's window; a message that would pass this is dropped.
const QUEUE_FRAMES: usize = 2048;
const MAX_LINKS: usize = 512;
/// The Link request paths, and the mode 2 op each is as a message; read and write queries
/// begin with their own op.
const PATHS: [(&str, Option<u8>); 8] = [
    ("read", None),
    ("write", None),
    ("peek", Some(channel::PEEK)),
    ("sync", Some(channel::SYNC)),
    ("forward", Some(channel::FORWARD)),
    ("pushed", Some(channel::PUSHED)),
    ("subscribe", Some(crate::push::SUBSCRIBE)),
    ("unsubscribe", Some(crate::push::UNSUBSCRIBE)),
];

/// How a query is answered: on the Channel under its request id, or as the response to Link
/// request `request_id`.
#[derive(Clone, Copy, Debug)]
pub enum Answer {
    Channel(u16),
    Request([u8; 16]),
    /// A push, under the Link's own push count.
    Push(u16),
}

/// How a query to another replica is asked: a mode 2 message, or Link request `path`.
pub enum How {
    Channel(Vec<u8>),
    Request(&'static str, Vec<u8>),
}

pub enum Cmd {
    /// Announce with this app data, now and in answer to path requests.
    Announce(Vec<u8>),
    Reply { link: LinkId, answer: Answer, data: Vec<u8> },
    Query { dest: DestHash, how: How, reply: oneshot::Sender<Option<Vec<u8>>> },
    Shutdown,
}

pub enum Event {
    /// A `pigeonhole.replica` announce, of the destination with that identity hash.
    Heard { dest: DestHash, identity: Fingerprint, app_data: Vec<u8> },
    /// A query on a Link to this replica, as a mode 2 message, from the identity the Link
    /// identified as.
    Message { link: LinkId, sender: Option<Fingerprint>, answer: Answer, data: Vec<u8> },
    Closed(LinkId),
}

enum Msg {
    Iface(IfaceEvent),
    Cmd(Cmd),
}

/// The replica's side of the stack thread.
pub struct Net {
    tx: Sender<Msg>,
    pub dest: DestHash,
    pub identity: Fingerprint,
}

impl Net {
    pub fn send(&self, c: Cmd) {
        let _ = self.tx.send(Msg::Cmd(c));
    }

    /// Asks the replica at `dest`; `None` when it did not answer within [`QUERY_TIMEOUT_MS`].
    pub async fn query(&self, dest: &[u8], how: How) -> Option<Vec<u8>> {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Query { dest: dest.try_into().ok()?, how, reply });
        rx.await.ok().flatten()
    }
}

/// The interfaces, the one sink every part of the stack sends through. With `tap` on, the next
/// packet sent has its hash kept, and its context byte set to CHANNEL first if `channel`.
#[derive(Default)]
struct Ifaces {
    h: HashMap<IfaceId, Box<dyn Interface>>,
    tap: bool,
    channel: bool,
    tapped: Option<[u8; 32]>,
}

/// Where a packet's context byte is: the last of its header.
fn context_at(raw: &[u8]) -> Option<usize> {
    let (_, payload) = Header::decode(raw).ok()?;
    (raw.len() - payload.len()).checked_sub(1)
}

fn with_context(raw: &[u8], ctx: u8) -> Option<Vec<u8>> {
    let mut p = raw.to_vec();
    p[context_at(raw)?] = ctx;
    Some(p)
}

impl Ifaces {
    fn put(&mut self, iface: IfaceId, raw: &[u8]) -> bool {
        let rewritten;
        let mut raw = raw;
        if self.tap {
            self.tap = false;
            if self.channel {
                let Some(p) = with_context(raw, context::CHANNEL) else { return false };
                rewritten = p;
                raw = &rewritten;
            }
            self.tapped = rns_packet_hash(raw).ok();
        }
        self.h.get_mut(&iface).is_some_and(|h| matches!(h.send(raw), SendOutcome::Queued | SendOutcome::Discarded))
    }
}

impl IfaceOut for Ifaces {
    fn send(&mut self, iface: IfaceId, raw: &[u8]) -> bool {
        self.put(iface, raw)
    }
    fn mode(&self, _: IfaceId) -> IfaceMode {
        IfaceMode::Full
    }
    fn bitrate(&self, iface: IfaceId) -> u64 {
        self.h.get(&iface).map_or(reticulum_iface::BITRATE_GUESS, |h| h.bitrate())
    }
    fn is_up(&self, iface: IfaceId) -> bool {
        self.h.get(&iface).is_some_and(|h| h.is_up())
    }
}

impl LinkOut for Ifaces {
    fn send(&mut self, iface: IfaceId, raw: &[u8]) -> bool {
        self.put(iface, raw)
    }
}

impl EndpointOut for Ifaces {
    fn send(&mut self, iface: IfaceId, raw: &[u8]) -> bool {
        self.put(iface, raw)
    }
}

/// The Channel on one Link: its send window and receive order, frames waiting for the window,
/// and the pieces of messages being reassembled.
struct Chan {
    /// A Link this replica opened.
    out: bool,
    rtt: u32,
    tx: Box<Tx<TX_SLOTS, ENV_CAP>>,
    rx: Box<Rx<RX_HELD, ENV_CAP>>,
    queue: VecDeque<(u16, Vec<u8>)>,
    reasm: Reassembler,
    /// On a Link this replica opened: the query each request id answers.
    replies: HashMap<u16, u64>,
    next_id: u16,
}

impl Chan {
    fn new(out: bool, rtt: u32) -> Chan {
        Chan {
            out,
            rtt,
            tx: Box::new(Tx::new(rtt)),
            rx: Box::new(Rx::new()),
            queue: VecDeque::new(),
            reasm: Reassembler::default(),
            replies: HashMap::new(),
            next_id: 0,
        }
    }

    fn enqueue(&mut self, msgtype: u16, rid: u16, data: &[u8]) -> bool {
        let Some(frames) = channel::split(rid, data) else { return false };
        if self.queue.len() + frames.len() > QUEUE_FRAMES {
            return false;
        }
        self.queue.extend(frames.into_iter().map(|f| (msgtype, f.pack())));
        true
    }
}

/// Link requests answered later: the handlers hand each to the replica and answer from
/// `ready` when the request is fed in again.
/// A Link request handed on: its Link, request id, query and sender.
type Deferral = (LinkId, [u8; 16], Vec<u8>, Option<Fingerprint>);

#[derive(Default)]
struct Deferred {
    ready: HashMap<[u8; 16], Vec<u8>>,
    new: Vec<Deferral>,
}

struct Query {
    dest: DestHash,
    how: Option<How>,
    reply: oneshot::Sender<Option<Vec<u8>>>,
    deadline: u64,
    link: Option<LinkId>,
}

struct Announcer {
    signer: RustCryptoSigner,
    public: PublicBlob,
    name_hash: [u8; 10],
    app_data: Arc<Mutex<Vec<u8>>>,
}

impl Announcer {
    fn build(&self, now_ms: u64) -> Option<Vec<u8>> {
        let app_data = self.app_data.lock().unwrap().clone();
        let mut rand5 = [0u8; 5];
        OsRng.try_fill_bytes(&mut rand5).ok()?;
        let random_hash = build_random_hash(&rand5, now_ms / 1000);
        let mut buf = vec![0u8; 256 + app_data.len()];
        let build = AnnounceBuild {
            public: &self.public,
            name_hash: &self.name_hash,
            random_hash: &random_hash,
            app_data: &app_data,
            ratchet: None,
        };
        let n = encode_announce(&self.signer, &build, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }
}

/// `msgpack([request_id, bin(data)])`, a Link request's response.
fn response_envelope(request_id: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; data.len() + 32];
    let mut e = Encoder::new(&mut buf);
    let ok = e.write_array_header(2).is_ok() && e.write_bin(request_id).is_ok() && e.write_bin(data).is_ok();
    let n = e.position();
    buf.truncate(if ok { n } else { 0 });
    buf
}

fn rng(buf: &mut [u8]) -> bool {
    OsRng.try_fill_bytes(buf).is_ok()
}

struct Core {
    router: Router,
    ep: Endpoint,
    ld: LinkDrv,
    io: Ifaces,
    chans: HashMap<LinkId, Chan>,
    deferred: Arc<Mutex<Deferred>>,
    /// Single packet Link requests awaiting the replica's answer, to feed in again with it.
    raws: HashMap<[u8; 16], (IfaceId, Vec<u8>, u64)>,
    queries: HashMap<u64, Query>,
    next_query: u64,
    /// Queries waiting for a Link being opened.
    waiting: HashMap<DestHash, Vec<u64>>,
    events: tmpsc::UnboundedSender<Event>,
    announcer: Announcer,
    me: DestHash,
    /// The frame being fed in: its interface, bytes and context, while it is.
    feeding: Option<(IfaceId, Vec<u8>, u8)>,
}

/// Starts the stack from the replica's identity and the config's interfaces.
pub fn start(
    blob: PrivateBlob,
    ifaces: &[Iface],
    transport: bool,
) -> io::Result<(Net, tmpsc::UnboundedReceiver<Event>)> {
    let signer = RustCryptoSigner::from_private_blob(&blob).map_err(|_| io::Error::other("bad identity"))?;
    let public = signer.public_blob();
    let name_hash = compute_name_hash("pigeonhole.replica");
    let me = compute_destination_hash(&name_hash, &public);
    let identity = fingerprint(&public);

    let mut router = Router::new(identity);
    router.set_transport_enabled(transport);
    router.mix_rng_entropy(OsRng.next_u64());
    let app_data: Arc<Mutex<Vec<u8>>> = Arc::default();
    let answering = Announcer {
        signer: RustCryptoSigner::from_private_blob(&blob).map_err(|_| io::Error::other("bad identity"))?,
        public,
        name_hash,
        app_data: app_data.clone(),
    };
    router.register_local_destination(me, LocalAnnounce::Producer(Box::new(move |now| answering.build(now))));

    let mut ep = Endpoint::new(Box::new(rng));
    ep.set_max_links(MAX_LINKS);
    ep.register(me, &blob, LinkPolicy::AcceptAll, ProofStrategy::ProveNone)
        .map_err(|e| io::Error::other(format!("endpoint: {e:?}")))?;
    let deferred: Arc<Mutex<Deferred>> = Arc::default();
    for (path, op) in PATHS {
        let d = deferred.clone();
        let handler = Box::new(move |c: &RequestContext<'_>| {
            let mut d = d.lock().unwrap();
            if let Some(r) = d.ready.remove(&c.request_id) {
                return Some(msgpack_bin(&r));
            }
            let data = c.data.and_then(|b| Decoder::new(b).read_bytes().ok()).unwrap_or_default();
            let msg = match op {
                Some(op) => [&[op][..], data].concat(),
                None => data.to_vec(),
            };
            d.new.push((c.link_id, c.request_id, msg, c.remote_identity));
            None
        });
        ep.register_request_handler(&me, path, RequestAllow::All, handler)
            .map_err(|e| io::Error::other(format!("endpoint: {e:?}")))?;
    }
    let mut ld = LinkDrv::new(&blob, public, Box::new(rng)).map_err(|e| io::Error::other(format!("{e:?}")))?;
    ld.set_request_timeout(QUERY_TIMEOUT_MS);
    ld.set_establishment_timeout(ESTABLISH_TIMEOUT_MS);

    let (tx, rx) = mpsc::channel();
    let (events, events_rx) = tmpsc::unbounded_channel();
    let (iface_tx, iface_rx) = mpsc::sync_channel::<IfaceEvent>(4096);
    let fwd = tx.clone();
    std::thread::Builder::new().name("rns-ifaces".into()).spawn(move || {
        for e in iface_rx {
            if fwd.send(Msg::Iface(e)).is_err() {
                return;
            }
        }
    })?;
    let drivers = spawn_drivers(ifaces, iface_tx);
    let core = Core {
        router,
        ep,
        ld,
        io: Ifaces::default(),
        chans: HashMap::new(),
        deferred,
        raws: HashMap::new(),
        queries: HashMap::new(),
        next_query: 0,
        waiting: HashMap::new(),
        events,
        announcer: Announcer { signer, public, name_hash, app_data },
        me,
        feeding: None,
    };
    std::thread::Builder::new().name("rns-core".into()).spawn(move || {
        let _drivers = drivers;
        core.run(rx)
    })?;
    Ok((Net { tx, dest: me, identity }, events_rx))
}

/// The interface drivers, kept for as long as the stack runs; dropping one shuts it down.
fn spawn_drivers(ifaces: &[Iface], tx: SyncSender<IfaceEvent>) -> Vec<Box<dyn Send>> {
    let alloc = IfaceIdAlloc::new();
    let mut out: Vec<Box<dyn Send>> = Vec::new();
    let addr = |a: &str| a.to_socket_addrs().ok().and_then(|mut i| i.next());
    for i in ifaces {
        let r: io::Result<Box<dyn Send>> = match i {
            Iface::TcpServer(a) => match addr(a) {
                Some(s) => TcpServer::spawn(TcpServerConfig::new(s), &alloc, tx.clone()).map(|d| Box::new(d) as _),
                None => Err(io::Error::other(format!("bad address {a}"))),
            },
            Iface::TcpClient(a) => match a.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse().ok()?))) {
                Some((h, p)) => TcpUplink::spawn(TcpUplinkConfig::new(h, p), &alloc, tx.clone()).map(|d| Box::new(d) as _),
                None => Err(io::Error::other(format!("bad address {a}"))),
            },
            Iface::Udp { listen, forward } => match (addr(listen), forward.as_deref().and_then(addr)) {
                (Some(l), Some(f)) => UdpDriver::spawn(UdpConfig::new(l, f), &alloc, tx.clone()).map(|d| Box::new(d) as _),
                _ => Err(io::Error::other(format!("UDP interface on {listen} needs forward_ip and forward_port"))),
            },
        };
        match r {
            Ok(d) => out.push(d),
            Err(e) => log::warn!("pigeonhole: interface {i:?}: {e}"),
        }
    }
    out
}

impl Core {
    fn run(mut self, rx: Receiver<Msg>) {
        let mut last_tick = 0;
        loop {
            match rx.recv_timeout(POLL) {
                Ok(Msg::Iface(e)) => self.iface(e),
                Ok(Msg::Cmd(Cmd::Shutdown)) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(Msg::Cmd(c)) => self.command(c),
                Err(RecvTimeoutError::Timeout) => {}
            }
            let now = wall_ms();
            if now.saturating_sub(last_tick) >= TICK_MS {
                last_tick = now;
                self.tick(now);
            }
            self.pump(now);
        }
        self.ld.close_all(&mut self.io);
    }

    fn iface(&mut self, e: IfaceEvent) {
        let now = wall_ms();
        match e {
            IfaceEvent::Up { iface, parent } => {
                let id = iface.id();
                self.io.h.insert(id, iface);
                self.router.handle(CoreEvent::Iface(reticulum_router::IfaceEvent::Up { iface: id.into(), parent }), now, &mut self.io);
                // Whoever is behind a new interface hears this replica at once.
                if let Some(raw) = self.announcer.build(now) {
                    self.io.put(id, &raw);
                }
            }
            IfaceEvent::Frame { id, packet } => self.frame(id, packet, now),
            IfaceEvent::Down { id } => {
                self.router.handle(CoreEvent::Iface(reticulum_router::IfaceEvent::Down { id }), now, &mut self.io);
                self.io.h.remove(&id);
            }
        }
    }

    fn frame(&mut self, id: IfaceId, packet: Vec<u8>, now: u64) {
        let Ok((hdr, payload)) = Header::decode(&packet) else {
            return self.router.handle(CoreEvent::Iface(reticulum_router::IfaceEvent::Frame { id, packet }), now, &mut self.io);
        };
        let dest = hdr.destination_hash;
        if hdr.packet_type == PacketType::Announce {
            self.heard(&packet);
            return self.router.handle(CoreEvent::Iface(reticulum_router::IfaceEvent::Frame { id, packet }), now, &mut self.io);
        }
        // A proof of a Channel envelope sent: canon proves every link packet explicitly, the
        // packet's hash and then the signature.
        // shortcut: the signature is not checked, the peer's Link key being the library's;
        // one forged by a node on the path settles an envelope it could have dropped anyway.
        if hdr.packet_type == PacketType::Proof
            && hdr.context_byte == context::NONE
            && let Some(ch) = self.chans.get_mut(&dest)
            && let Some(h) = payload.get(..32)
        {
            ch.tx.proved(h.try_into().unwrap());
        }
        let ctx = hdr.context_byte;
        let fed = if ctx == context::CHANNEL && hdr.packet_type == PacketType::Data {
            match with_context(&packet, context::NONE) {
                Some(p) => p,
                None => return,
            }
        } else {
            packet.clone()
        };
        if self.ep.wants(&dest) {
            self.feeding = Some((id, packet, ctx));
            self.ep.handle(EndpointEvent::Frame { iface: id, raw: &fed }, now, &mut self.io);
            self.drain(now);
        } else if self.ld.wants(&dest) {
            self.feeding = Some((id, packet, ctx));
            self.ld.handle_frame(id, &fed, now, &mut self.io);
            self.drain(now);
        } else {
            self.router.handle(CoreEvent::Iface(reticulum_router::IfaceEvent::Frame { id, packet }), now, &mut self.io);
        }
        self.feeding = None;
    }

    fn heard(&mut self, packet: &[u8]) {
        let mut scratch = [0u8; 1024];
        let Ok(a) = parse_and_verify_announce_scratch::<RustCryptoSigner>(packet, &mut scratch) else {
            return;
        };
        let dest = a.header.destination_hash;
        if a.name_hash == self.announcer.name_hash && dest != self.me {
            let _ = self.events.send(Event::Heard { dest, identity: fingerprint(&a.public), app_data: a.app_data.to_vec() });
        }
    }

    fn command(&mut self, c: Cmd) {
        let now = wall_ms();
        match c {
            Cmd::Announce(app_data) => {
                *self.announcer.app_data.lock().unwrap() = app_data;
                if let Some(raw) = self.announcer.build(now) {
                    self.router.broadcast_announce(&raw, now, &mut self.io);
                }
            }
            Cmd::Reply { link, answer, data } => self.reply(link, answer, data, now),
            Cmd::Query { dest, how, reply } => {
                let qid = self.next_query;
                self.next_query += 1;
                let q = Query { dest, how: Some(how), reply, deadline: now + QUERY_TIMEOUT_MS, link: None };
                self.queries.insert(qid, q);
                match self.ld.link_for_dest(&dest) {
                    Some(l) if self.chans.contains_key(&l) => self.issue(qid, l, now),
                    Some(_) => self.waiting.entry(dest).or_default().push(qid),
                    None => {
                        self.waiting.entry(dest).or_default().push(qid);
                        self.establish(dest, now);
                    }
                }
            }
            Cmd::Shutdown => {}
        }
        self.drain(now);
    }

    fn reply(&mut self, link: LinkId, answer: Answer, data: Vec<u8>, now: u64) {
        let (msgtype, rid) = match answer {
            Answer::Channel(rid) => (channel::MSGTYPE, rid),
            Answer::Push(id) => (channel::PUSH_MSGTYPE, id),
            Answer::Request(rid) => {
                if let Some((iface, raw, _)) = self.raws.remove(&rid) {
                    self.deferred.lock().unwrap().ready.insert(rid, data);
                    self.ep.handle(EndpointEvent::Frame { iface, raw: &raw }, now, &mut self.io);
                    self.deferred.lock().unwrap().ready.remove(&rid);
                    return;
                }
                // A request that came as a Resource: its response, a write's code, fits a packet.
                let env = response_envelope(&rid, &data);
                if env.len() > reticulum_link::link_mdu(500) || !self.ep.send_data_on_link(&link, &env, context::RESPONSE, &mut self.io) {
                    log::warn!("pigeonhole: response of {} bytes to a resource request dropped", data.len());
                }
                return;
            }
        };
        if let Some(ch) = self.chans.get_mut(&link)
            && !ch.enqueue(msgtype, rid, &data)
        {
            log::warn!("pigeonhole: channel queue full on a link, message dropped");
        }
    }

    fn route(&self, dest: &DestHash) -> Option<Route> {
        let p = self.router.path(dest)?;
        let iface = self.router.iface_for_slot(p.iface)?;
        Some(Route { iface, next_hop: (p.next_hop != *dest).then_some(p.next_hop) })
    }

    fn establish(&mut self, dest: DestHash, now: u64) {
        let (Some(public), Some(route)) = (self.router.recall_public(&dest).copied(), self.route(&dest)) else {
            self.router.request_path(&dest, now, &mut self.io);
            return self.fail_waiting(&dest);
        };
        if let Err(e) = self.ld.establish(dest, &public, route, now, &mut self.io) {
            log::debug!("pigeonhole: link to {}: {e:?}", hex::encode(dest));
            self.fail_waiting(&dest);
        }
    }

    fn fail_waiting(&mut self, dest: &DestHash) {
        for qid in self.waiting.remove(dest).unwrap_or_default() {
            self.finish(qid, None);
        }
    }

    fn finish(&mut self, qid: u64, r: Option<Vec<u8>>) {
        if let Some(q) = self.queries.remove(&qid) {
            let _ = q.reply.send(r);
        }
    }

    /// Asks query `qid` on the Link `link`, now active.
    fn issue(&mut self, qid: u64, link: LinkId, now: u64) {
        let Some(q) = self.queries.get_mut(&qid) else { return };
        q.link = Some(link);
        let ok = match q.how.take() {
            Some(How::Channel(msg)) => self.chans.get_mut(&link).is_some_and(|ch| {
                let rid = ch.next_id;
                ch.next_id = ch.next_id.wrapping_add(1);
                ch.replies.insert(rid, qid);
                ch.enqueue(channel::MSGTYPE, rid, &msg)
            }),
            Some(How::Request(path, data)) => self
                .ld
                .send_request(&link, qid, path, Some(&msgpack_bin(&data)), RequestKind::Page, now, &mut self.io)
                .is_some(),
            None => false,
        };
        if !ok {
            self.finish(qid, None);
        }
    }

    fn close(&mut self, link: LinkId) {
        match self.chans.get(&link) {
            Some(ch) if ch.out => self.ld.close(&link, &mut self.io),
            _ => {
                self.ep.teardown_link(&link, &mut self.io);
            }
        }
    }

    /// Sends `env` on the Channel of `link`, returning the hash of the packet it went in.
    fn seal(&mut self, link: &LinkId, out: bool, env: &[u8]) -> Option<[u8; 32]> {
        (self.io.tap, self.io.channel, self.io.tapped) = (true, out, None);
        let sent = if out {
            self.ld.send_link_data(link, env, &mut self.io).is_some()
        } else {
            self.ep.send_data_on_link(link, env, context::CHANNEL, &mut self.io)
        };
        self.io.tap = false;
        if sent { self.io.tapped.take() } else { None }
    }

    /// Resends what is due and sends what the windows allow.
    fn pump(&mut self, now: u64) {
        let links: Vec<LinkId> = self.chans.keys().copied().collect();
        for l in links {
            while let Some(ch) = self.chans.get_mut(&l) {
                let (out, rtt) = (ch.out, ch.rtt);
                match ch.tx.poll(now, rtt) {
                    TxEvent::Idle => break,
                    TxEvent::Teardown => {
                        log::warn!("pigeonhole: channel envelope unproved after {} sends, link closed", reticulum_channel::MAX_TRIES);
                        self.close(l);
                        break;
                    }
                    TxEvent::Resend { seq, envelope } => {
                        let env = envelope.to_vec();
                        match self.seal(&l, out, &env) {
                            Some(h) => self.chans.get_mut(&l).unwrap().tx.resent(seq, h),
                            None => break,
                        }
                    }
                }
            }
            while let Some(ch) = self.chans.get_mut(&l) {
                if !ch.tx.ready() {
                    break;
                }
                let Some((msgtype, frame)) = ch.queue.front() else { break };
                let mut env = [0u8; ENV_CAP];
                let Some(n) = reticulum_channel::encode(*msgtype, ch.tx.next_sequence(), frame, &mut env) else {
                    ch.queue.pop_front();
                    continue;
                };
                let (out, rtt) = (ch.out, ch.rtt);
                let Some(h) = self.seal(&l, out, &env[..n]) else { break };
                let ch = self.chans.get_mut(&l).unwrap();
                ch.tx.sent(&env[..n], h, now, rtt);
                ch.queue.pop_front();
            }
        }
        self.drain(now);
    }

    fn tick(&mut self, now: u64) {
        self.router.handle(CoreEvent::Tick, now, &mut self.io);
        self.ep.handle(EndpointEvent::Tick, now, &mut self.io);
        self.ld.tick(now, &mut self.io);
        // A Link that failed a query is opened afresh next time.
        let late: Vec<u64> = self.queries.iter().filter(|(_, q)| q.deadline <= now).map(|(k, _)| *k).collect();
        for qid in late {
            if let Some(q) = self.queries.remove(&qid) {
                if let Some(l) = q.link {
                    self.close(l);
                }
                if let Some(w) = self.waiting.get_mut(&q.dest) {
                    w.retain(|x| *x != qid);
                }
                let _ = q.reply.send(None);
            }
        }
        self.raws.retain(|_, (_, _, at)| now.saturating_sub(*at) < QUERY_TIMEOUT_MS);
        self.drain(now);
    }

    /// Handles what the endpoint and the link driver have to say.
    fn drain(&mut self, now: u64) {
        while let Some(e) = self.ep.poll_event() {
            match e {
                EpEvent::LinkEstablished { link_id, rtt_ms, .. } => {
                    self.chans.insert(link_id, Chan::new(false, rtt_ms));
                }
                EpEvent::LinkClosed { link_id, .. } => {
                    self.chans.remove(&link_id);
                    let _ = self.events.send(Event::Closed(link_id));
                }
                EpEvent::Data { link_id, data, .. } => self.envelope(link_id, &data),
                _ => {}
            }
        }
        let new = std::mem::take(&mut self.deferred.lock().unwrap().new);
        for (link, rid, data, sender) in new {
            if let Some((iface, raw, context::REQUEST)) = &self.feeding {
                self.raws.insert(rid, (*iface, raw.clone(), now));
            }
            let _ = self.events.send(Event::Message { link, sender, answer: Answer::Request(rid), data });
        }
        while let Some(e) = self.ld.poll_event() {
            match e {
                LinkEvent::Established { link_id, dest } => {
                    self.ld.send_identify(&link_id, now, &mut self.io);
                    self.chans.insert(link_id, Chan::new(true, self.ld.rtt_ms(&link_id).unwrap_or(0)));
                    for qid in self.waiting.remove(&dest).unwrap_or_default() {
                        self.issue(qid, link_id, now);
                    }
                }
                LinkEvent::Closed { link_id, dest, reason } => {
                    log::debug!("pigeonhole: link to {} closed: {reason:?}", hex::encode(dest));
                    self.chans.remove(&link_id);
                    self.fail_waiting(&dest);
                    let gone: Vec<u64> =
                        self.queries.iter().filter(|(_, q)| q.link == Some(link_id)).map(|(k, _)| *k).collect();
                    for qid in gone {
                        self.finish(qid, None);
                    }
                }
                LinkEvent::Response { api_request_id, content, .. } => self.finish(api_request_id, Some(content)),
                LinkEvent::RequestFailed { api_request_id, reason } => {
                    log::debug!("pigeonhole: request failed: {reason}");
                    self.finish(api_request_id, None)
                }
                LinkEvent::InboundData { link_id, plaintext, .. } => self.envelope(link_id, &plaintext),
                LinkEvent::Notice(n) => log::debug!("pigeonhole: {n}"),
                _ => {}
            }
        }
    }

    /// A packet's plaintext, on a Link with a Channel: an envelope when the packet being fed
    /// was a CHANNEL one. It is proved unless the Channel refused it.
    fn envelope(&mut self, link: LinkId, data: &[u8]) {
        let raw = match &self.feeding {
            Some((_, raw, context::CHANNEL)) => raw.clone(),
            _ => return,
        };
        let Some(env) = reticulum_channel::decode(data) else { return };
        let Some(ch) = self.chans.get_mut(&link) else { return };
        let verdict = ch.rx.receive(&env);
        let out = ch.out;
        let mut msgs = Vec::new();
        if verdict == Verdict::Deliver {
            msgs.push((env.msgtype, env.payload.to_vec()));
            let mut buf = [0u8; ENV_CAP];
            while let Some((t, n)) = ch.rx.take_ready(&mut buf) {
                msgs.push((t, buf[..n].to_vec()));
            }
        }
        if verdict.prove() {
            if out {
                if let Ok(h) = rns_packet_hash(&raw) {
                    self.ld.send_delivery_proof(&link, &h, &mut self.io);
                }
            } else {
                self.ep.prove_packet(&link, &raw, &mut self.io);
            }
        }
        for (t, m) in msgs {
            let Some(f) = Frame::unpack(&m, t) else { continue };
            if f.msgtype != channel::MSGTYPE {
                continue;
            }
            let rid = f.request_id;
            let Some(ch) = self.chans.get_mut(&link) else { return };
            let Some(data) = ch.reasm.feed(f) else { continue };
            if ch.out {
                if let Some(qid) = ch.replies.remove(&rid) {
                    self.finish(qid, Some(data));
                }
            } else {
                let sender = self.ep.link_remote_identity(&link);
                let _ = self.events.send(Event::Message { link, sender, answer: Answer::Channel(rid), data });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_byte_and_response_envelope() {
        // HEADER_1 data packet: flags, hops, 16 byte destination, context, payload.
        let raw = [&[0u8, 0][..], &[7; 16], &[0], b"abc"].concat();
        assert_eq!(context_at(&raw), Some(18));
        let ch = with_context(&raw, context::CHANNEL).unwrap();
        assert_eq!(ch[18], 0x0e);
        assert_eq!(&ch[19..], b"abc");
        let env = response_envelope(&[1; 16], b"hi");
        assert_eq!(env, [&[0x92, 0xc4, 16][..], &[1; 16], &[0xc4, 2], b"hi"].concat());
        let bin = msgpack_bin(b"query");
        assert_eq!(Decoder::new(&bin).read_bytes().unwrap(), b"query");
    }
}
