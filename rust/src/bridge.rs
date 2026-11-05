//! The mesh side of a bridge, as `bridge.py`: a client of the Katzenpost replica's bridge
//! socket on the same host, speaking the same read and write messages.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::wire::{self, BoxId, Reply};

/// Up to `conns` connections, each carrying one query at a time, so a slow read proxied to
/// other shards does not hold up the rest. The Katzenpost replica serves each connection on
/// its own goroutine.
pub struct Bridge {
    path: PathBuf,
    timeout: Duration,
    idle: Arc<Mutex<Vec<UnixStream>>>,
    slots: Semaphore,
}

impl Bridge {
    pub fn new(path: PathBuf, conns: usize) -> Bridge {
        Bridge { path, timeout: Duration::from_secs(120), idle: Arc::default(), slots: Semaphore::new(conns) }
    }

    async fn exchange(&self, payload: Vec<u8>) -> Option<Vec<u8>> {
        let _slot = self.slots.acquire().await.ok()?;
        let (path, timeout, idle) = (self.path.clone(), self.timeout, self.idle.clone());
        tokio::task::spawn_blocking(move || {
            let reused = idle.lock().unwrap().pop();
            // An idle connection the replica has closed fails once; then a new one is tried.
            for s in [reused, None] {
                let was_reused = s.is_some();
                let mut s = match s {
                    Some(s) => s,
                    None => {
                        let s = UnixStream::connect(&path).ok()?;
                        s.set_read_timeout(Some(timeout)).ok()?;
                        s.set_write_timeout(Some(timeout)).ok()?;
                        s
                    }
                };
                match wire::write_frame(&mut s, &payload).and_then(|_| wire::read_frame(&mut s)) {
                    Ok(raw) => {
                        idle.lock().unwrap().push(s);
                        return Some(raw);
                    }
                    Err(e) if was_reused && !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                    Err(_) => return None,
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }

    pub async fn write(&self, box_id: &BoxId, sig: &[u8], ct: &[u8]) -> Option<u8> {
        self.exchange(wire::encode_write(box_id, sig, ct)).await?.first().copied()
    }

    pub async fn read(&self, box_id: &BoxId) -> Option<Reply> {
        wire::decode_reply(&self.exchange(wire::encode_read(box_id)).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// A Katzenpost replica stand-in: answers every read NOT_FOUND and every write SUCCESS,
    /// counting connections, and can drop them all.
    fn fake(path: &std::path::Path) -> Arc<Mutex<Vec<UnixStream>>> {
        let l = UnixListener::bind(path).unwrap();
        let conns: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
        let c = conns.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                c.lock().unwrap().push(s.try_clone().unwrap());
                std::thread::spawn(move || {
                    while let Ok(q) = wire::read_frame(&mut s) {
                        let code = if q[0] == wire::READ { wire::NOT_FOUND } else { wire::SUCCESS };
                        if wire::write_frame(&mut s, &[code]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        conns
    }

    #[tokio::test]
    async fn bounded_reused_and_reconnects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.sock");
        let conns = fake(&path);
        let b = Arc::new(Bridge::new(path, 2));
        let mut tasks = vec![];
        for i in 0..20 {
            let b = b.clone();
            tasks.push(tokio::spawn(async move { b.write(&[i; 32], &[0; 64], b"ct").await }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), Some(wire::SUCCESS));
        }
        assert!(conns.lock().unwrap().len() <= 2);
        for s in conns.lock().unwrap().drain(..) {
            s.shutdown(std::net::Shutdown::Both).unwrap();
        }
        assert_eq!(b.read(&[1; 32]).await, Some(Reply::code(wire::NOT_FOUND)));
    }
}
