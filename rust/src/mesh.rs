//! Queries to other replicas in mode 2: one Link per replica, identified with this replica's
//! identity so the peer knows a forward's sender, and a Channel on it carrying the queries and
//! replies as [`Frame`]s under request ids. The Link is opened on demand and again when lost.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use reticulum::channel::Channel;
use reticulum::destination::DestinationDesc;
use reticulum::destination::link::{Link, LinkStatus};
use reticulum::error::RnsError;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;
use tokio::sync::{Mutex, broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

use crate::channel::{self, Frame, Reassembler};

const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(20);
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(60);

type Replies = Arc<StdMutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>;
type Slot = Arc<Mutex<Option<Arc<Conn>>>>;

struct Conn {
    link: Arc<Mutex<Link>>,
    channel: Channel<Frame>,
    replies: Replies,
    reader: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub struct Mesh {
    t: Arc<Transport>,
    me: PrivateIdentity,
    descs: StdMutex<HashMap<AddressHash, DestinationDesc>>,
    conns: StdMutex<HashMap<AddressHash, Slot>>,
    next_id: AtomicU16,
}

/// Sends `frames` on `ch`, waiting for the Channel's window; false once the Link closes.
pub async fn send_frames(ch: &Channel<Frame>, link: &Mutex<Link>, frames: &[Frame]) -> bool {
    for f in frames {
        loop {
            match ch.send(f).await {
                Ok(_) => break,
                Err(RnsError::LinkNotReady) if link.lock().await.status() != LinkStatus::Closed => {
                    sleep(Duration::from_millis(10)).await
                }
                Err(_) => return false,
            }
        }
    }
    true
}

impl Mesh {
    pub fn new(t: Arc<Transport>, me: PrivateIdentity) -> Mesh {
        Mesh { t, me, descs: StdMutex::default(), conns: StdMutex::default(), next_id: AtomicU16::new(0) }
    }

    /// Remembers how to reach a replica heard announcing.
    pub fn heard(&self, desc: DestinationDesc) {
        self.descs.lock().unwrap().insert(desc.address_hash, desc);
    }

    /// Sends one mode 2 message to the replica at `dest` and returns its reply, or `None` when
    /// it did not answer.
    pub async fn query(&self, dest: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
        let dest = AddressHash::new(dest.try_into().ok()?);
        let frames = channel::split(self.next_id.fetch_add(1, Ordering::Relaxed), msg)?;
        let rid = frames[0].request_id;
        let conn = self.conn(dest).await?;
        let (tx, rx) = oneshot::channel();
        conn.replies.lock().unwrap().insert(rid, tx);
        let got = timeout(QUERY_TIMEOUT, async {
            if !send_frames(&conn.channel, &conn.link, &frames).await {
                return None;
            }
            rx.await.ok()
        })
        .await
        .ok()
        .flatten();
        conn.replies.lock().unwrap().remove(&rid);
        if got.is_none() {
            // A Link that failed a query is opened afresh next time.
            let slot = self.conns.lock().unwrap().get(&dest).cloned();
            if let Some(slot) = slot {
                let mut slot = slot.lock().await;
                if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                    slot.take();
                    self.close(&conn.link).await;
                }
            }
        }
        got
    }

    /// Reticulum-rs's `link_close` finds out-links by destination, not by Link id, so it closes
    /// none; marking ours closed makes `Transport::link` open a new one and drop this one.
    async fn close(&self, link: &Mutex<Link>) {
        link.lock().await.set_status(LinkStatus::Closed);
    }

    async fn conn(&self, dest: AddressHash) -> Option<Arc<Conn>> {
        let slot = self.conns.lock().unwrap().entry(dest).or_default().clone();
        let mut slot = slot.lock().await;
        if let Some(c) = slot.as_ref() {
            if c.link.lock().await.status() == LinkStatus::Active {
                return Some(c.clone());
            }
            let c = slot.take().unwrap();
            self.close(&c.link).await;
        }
        let desc = *self.descs.lock().unwrap().get(&dest)?;
        let link = self.t.link(desc).await;
        let deadline = Instant::now() + ESTABLISH_TIMEOUT;
        loop {
            // Not in the match: its guard would live through the arms, and close() locks again.
            let status = link.lock().await.status();
            match status {
                LinkStatus::Active => break,
                LinkStatus::Closed => return None,
                _ if Instant::now() > deadline => {
                    self.close(&link).await;
                    return None;
                }
                _ => {}
            }
            sleep(Duration::from_millis(20)).await;
        }
        let identify = link.lock().await.identify(&self.me).ok()?;
        self.t.send_packet(identify).await;
        let Ok((ch, mut rx)) = self.t.mk_channel::<Frame>(link.clone()).await else {
            self.close(&link).await;
            return None;
        };
        let replies: Replies = Arc::default();
        let r = replies.clone();
        let reader = tokio::spawn(async move {
            let mut reasm = Reassembler::default();
            loop {
                match rx.recv().await {
                    Ok(f) => {
                        let rid = f.request_id;
                        if let Some(data) = reasm.feed(f)
                            && let Some(tx) = r.lock().unwrap().remove(&rid)
                        {
                            let _ = tx.send(data);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => log::warn!("pigeonhole: dropped {n} frames"),
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        let c = Arc::new(Conn { link, channel: ch, replies, reader });
        *slot = Some(c.clone());
        Some(c)
    }

    pub async fn close_all(&self) {
        let slots: Vec<_> = self.conns.lock().unwrap().values().cloned().collect();
        for s in slots {
            if let Some(c) = s.lock().await.take() {
                self.close(&c.link).await;
            }
        }
    }
}
