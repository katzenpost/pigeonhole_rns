//! The SQLite store of `store.py`, same schema and file: boxes, the forward queue and the
//! acknowledgements, so that storing a box and enqueueing its forwards is one commit.
//!
//! `max_bytes` bounds the database and its WAL on disk, and `min_free_bytes` is the free
//! space kept on its filesystem; zero disables either. When a new box would pass a limit the
//! oldest boxes are evicted, tombstones last, and only when nothing is left to evict is the
//! write refused.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Result, params};

use crate::wire::{self, BoxId};

/// Boxes evicted per round when a storage limit is hit, before measuring again.
const EVICT_BATCH: usize = 64;
/// Eviction frees this share of a limit beyond it, so the next writes do not hit it again.
const HEADROOM: f64 = 1.0 / 16.0;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS boxes (
    box_id    BLOB PRIMARY KEY,
    epoch     INTEGER NOT NULL,
    signature BLOB NOT NULL,
    payload   BLOB NOT NULL,
    origin    BLOB NOT NULL DEFAULT x''
);
CREATE INDEX IF NOT EXISTS boxes_epoch ON boxes(epoch);
CREATE TABLE IF NOT EXISTS acks (
    box_id  BLOB NOT NULL,
    dst     BLOB NOT NULL,
    PRIMARY KEY (box_id, dst)
);
CREATE TABLE IF NOT EXISTS queue (
    box_id   BLOB NOT NULL,
    dst      BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try REAL NOT NULL,
    PRIMARY KEY (box_id, dst)
);";

/// A forward destination: a replica's destination hash, or [`crate::engine::BRIDGE`].
pub type Dst = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Box {
    pub epoch: i64,
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
    /// The mixnet a box was pulled from, empty for one written on the mesh.
    pub origin: Vec<u8>,
}

impl Box {
    pub fn is_tombstone(&self) -> bool {
        self.payload.is_empty()
    }
}

pub struct Store {
    db: Mutex<Connection>,
    path: PathBuf,
    pub max_bytes: u64,
    pub min_free_bytes: u64,
}

fn id(b: Vec<u8>) -> BoxId {
    b.try_into().unwrap_or([0; 32])
}

impl Store {
    #[cfg(test)]
    pub fn open(path: &Path) -> Result<Store> {
        Store::open_limited(path, 0, 0)
    }

    pub fn open_limited(path: &Path, max_bytes: u64, min_free_bytes: u64) -> Result<Store> {
        let db = Connection::open(path)?;
        // Incremental auto vacuum lets eviction hand pages back to the filesystem.
        db.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        // Needs about the store's size free; without it eviction still reuses pages.
        if db.query_row("PRAGMA auto_vacuum", [], |r| r.get::<_, i64>(0))? != 2
            && let Err(e) = db.execute_batch("VACUUM")
        {
            log::warn!("pigeonhole: could not vacuum {} for auto vacuum: {e}", path.display());
        }
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        // The WAL counts against max_bytes, so it is checkpointed within half the headroom.
        let page: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let wal_pages =
            if max_bytes > 0 { ((max_bytes as f64 * HEADROOM / 2.0 / page as f64) as i64).clamp(16, 1000) } else { 1000 };
        db.pragma_update(None, "wal_autocheckpoint", wal_pages)?;
        db.pragma_update(None, "journal_size_limit", wal_pages * page)?;
        db.execute_batch(SCHEMA)?;
        if db.prepare("SELECT origin FROM boxes LIMIT 0").is_err() {
            db.execute("ALTER TABLE boxes ADD COLUMN origin BLOB NOT NULL DEFAULT x''", [])?;
        }
        Ok(Store { db: Mutex::new(db), path: path.to_path_buf(), max_bytes, min_free_bytes })
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap()
    }

    // ---- disk use ----

    /// The database and its WAL as they sit on disk.
    pub fn disk_bytes(&self) -> u64 {
        let wal = PathBuf::from(format!("{}-wal", self.path.display()));
        [&self.path, &wal].iter().filter_map(|p| std::fs::metadata(p).ok()).map(|m| m.len()).sum()
    }

    pub fn free_bytes(&self) -> u64 {
        let dir = std::path::absolute(&self.path).ok().and_then(|p| p.parent().map(Path::to_path_buf));
        let Some(dir) = dir.and_then(|d| std::ffi::CString::new(d.as_os_str().as_encoded_bytes()).ok()) else {
            return u64::MAX;
        };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a statvfs to fill.
        if unsafe { libc::statvfs(dir.as_ptr(), &mut st) } != 0 {
            return u64::MAX;
        }
        st.f_bavail as u64 * st.f_frsize as u64
    }

    fn full(&self, headroom: f64) -> bool {
        (self.max_bytes > 0 && self.disk_bytes() as f64 >= self.max_bytes as f64 * (1.0 - headroom))
            || (self.min_free_bytes > 0 && (self.free_bytes() as f64) < self.min_free_bytes as f64 * (1.0 + headroom))
    }

    fn compact(db: &Connection) -> Result<()> {
        // One page per row stepped.
        let mut st = db.prepare("PRAGMA incremental_vacuum")?;
        let mut rows = st.query([])?;
        while rows.next()?.is_some() {}
        db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
    }

    /// Evicts the oldest boxes, by epoch then arrival and tombstones last, until HEADROOM
    /// below every limit, sparing `keep`. False if still full.
    fn make_room(&self, db: &mut Connection, keep: &BoxId) -> Result<bool> {
        if !self.full(0.0) {
            return Ok(true);
        }
        let mut evicted = 0;
        loop {
            Self::compact(db)?;
            if !self.full(HEADROOM) {
                break;
            }
            let ids: Vec<Vec<u8>> = db
                .prepare("SELECT box_id FROM boxes WHERE box_id != ? ORDER BY length(payload) = 0, epoch, rowid LIMIT ?")?
                .query_map(params![&keep[..], EVICT_BATCH as i64], |r| r.get(0))?
                .collect::<Result<_>>()?;
            if ids.is_empty() {
                if !self.full(0.0) {
                    break;
                }
                log::error!(
                    "pigeonhole: storage full with nothing left to evict ({} bytes on disk, {} free)",
                    self.disk_bytes(),
                    self.free_bytes()
                );
                return Ok(false);
            }
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            for table in ["boxes", "acks", "queue"] {
                let mut st = tx.prepare(&format!("DELETE FROM {table} WHERE box_id = ?"))?;
                for b in &ids {
                    st.execute([b])?;
                }
            }
            tx.commit()?;
            evicted += ids.len();
        }
        if evicted > 0 {
            log::warn!(
                "pigeonhole: storage limit hit, evicted {evicted} oldest boxes ({} bytes on disk, {} free)",
                self.disk_bytes(),
                self.free_bytes()
            );
        }
        Ok(true)
    }

    pub fn get(&self, box_id: &BoxId) -> Result<Option<Box>> {
        self.db()
            .query_row(
                "SELECT epoch, signature, payload, origin FROM boxes WHERE box_id = ?",
                [&box_id[..]],
                |r| Ok(Box { epoch: r.get(0)?, signature: r.get(1)?, payload: r.get(2)?, origin: r.get(3)? }),
            )
            .optional()
    }

    /// Stores a box and enqueues forwards to `dsts` in one transaction. Write once: the same
    /// bytes again is success, different bytes is ALREADY_EXISTS, a tombstone replaces whatever
    /// is there, and a box never replaces a tombstone. A new box that finds no room after
    /// eviction is STORAGE_FULL. Returns a wire code.
    #[allow(clippy::too_many_arguments)]
    pub fn put(&self, box_id: &BoxId, signature: &[u8], payload: &[u8], epoch: i64, dsts: &[Dst], origin: &[u8]) -> Result<u8> {
        let mut db = self.db();
        let held = db.query_row("SELECT 1 FROM boxes WHERE box_id = ?", [&box_id[..]], |_| Ok(())).optional()?;
        if held.is_none() && !self.make_room(&mut db, box_id)? {
            return Ok(wire::STORAGE_FULL);
        }
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let cur: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row("SELECT signature, payload FROM boxes WHERE box_id = ?", [&box_id[..]], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if let Some((sig, cur_payload)) = cur {
            if cur_payload.is_empty() {
                return Ok(if payload.is_empty() { wire::SUCCESS } else { wire::ALREADY_EXISTS });
            }
            if !payload.is_empty() {
                let same = sig == signature && cur_payload == payload;
                return Ok(if same { wire::SUCCESS } else { wire::ALREADY_EXISTS });
            }
            // A tombstone replaces the box and the acks it had collected.
            tx.execute("DELETE FROM acks WHERE box_id = ?", [&box_id[..]])?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO boxes (box_id, epoch, signature, payload, origin) VALUES (?, ?, ?, ?, ?)",
            params![&box_id[..], epoch, signature, payload, origin],
        )?;
        for d in dsts {
            tx.execute(
                "INSERT OR IGNORE INTO queue (box_id, dst, attempts, next_try) VALUES (?, ?, 0, 0)",
                params![&box_id[..], d],
            )?;
        }
        tx.commit()?;
        Ok(wire::SUCCESS)
    }

    pub fn box_ids(&self) -> Result<Vec<BoxId>> {
        let db = self.db();
        let mut s = db.prepare("SELECT box_id FROM boxes")?;
        s.query_map([], |r| r.get(0).map(id))?.collect()
    }

    /// Box IDs in (after, upto], ascending, each with whether it is a tombstone.
    pub fn entries(&self, after: &BoxId, upto: &BoxId, limit: usize) -> Result<Vec<(BoxId, bool)>> {
        let db = self.db();
        let mut s = db.prepare(
            "SELECT box_id, length(payload) = 0 FROM boxes WHERE box_id > ? AND box_id <= ? ORDER BY box_id LIMIT ?",
        )?;
        s.query_map(params![&after[..], &upto[..], limit as i64], |r| Ok((id(r.get(0)?), r.get(1)?)))?
            .collect()
    }

    /// Deletes boxes of epochs other than `keep`, and their queue entries and acks.
    pub fn sweep(&self, keep: &[i64]) -> Result<usize> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let marks = vec!["?"; keep.len()].join(",");
        let n = tx.execute(&format!("DELETE FROM boxes WHERE epoch NOT IN ({marks})"), rusqlite::params_from_iter(keep))?;
        tx.execute("DELETE FROM acks WHERE box_id NOT IN (SELECT box_id FROM boxes)", [])?;
        tx.execute("DELETE FROM queue WHERE box_id NOT IN (SELECT box_id FROM boxes)", [])?;
        tx.commit()?;
        Self::compact(&db)?;
        Ok(n)
    }

    pub fn enqueue(&self, box_id: &BoxId, dst: &[u8]) -> Result<()> {
        self.db().execute(
            "INSERT OR IGNORE INTO queue (box_id, dst, attempts, next_try) VALUES (?, ?, 0, 0)",
            params![&box_id[..], dst],
        )?;
        Ok(())
    }

    pub fn due(&self, now: f64) -> Result<Vec<(BoxId, Dst, u32)>> {
        let db = self.db();
        let mut s = db.prepare("SELECT box_id, dst, attempts FROM queue WHERE next_try <= ? ORDER BY next_try")?;
        s.query_map([now], |r| Ok((id(r.get(0)?), r.get(1)?, r.get(2)?)))?.collect()
    }

    fn dsts(&self, sql: &str, box_id: &BoxId) -> Result<HashSet<Dst>> {
        let db = self.db();
        let mut s = db.prepare(sql)?;
        s.query_map([&box_id[..]], |r| r.get(0))?.collect()
    }

    pub fn queued(&self, box_id: &BoxId) -> Result<HashSet<Dst>> {
        self.dsts("SELECT dst FROM queue WHERE box_id = ?", box_id)
    }

    pub fn acked(&self, box_id: &BoxId) -> Result<HashSet<Dst>> {
        self.dsts("SELECT dst FROM acks WHERE box_id = ?", box_id)
    }

    pub fn ack(&self, box_id: &BoxId, dst: &[u8]) -> Result<()> {
        let mut db = self.db();
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM queue WHERE box_id = ? AND dst = ?", params![&box_id[..], dst])?;
        tx.execute("INSERT OR IGNORE INTO acks (box_id, dst) VALUES (?, ?)", params![&box_id[..], dst])?;
        tx.commit()
    }

    pub fn backoff(&self, box_id: &BoxId, dst: &[u8], next_try: f64) -> Result<()> {
        self.db().execute(
            "UPDATE queue SET attempts = attempts + 1, next_try = ? WHERE box_id = ? AND dst = ?",
            params![next_try, &box_id[..], dst],
        )?;
        Ok(())
    }

    pub fn forget(&self, box_id: &BoxId, dst: &[u8]) -> Result<()> {
        self.db().execute("DELETE FROM queue WHERE box_id = ? AND dst = ?", params![&box_id[..], dst])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_once_tombstone_final_and_atomic_enqueue() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("s.sqlite")).unwrap();
        let b = [5u8; 32];
        assert_eq!(s.put(&b, &[1; 64], b"ct", 7, &[b"r2".to_vec()], b"").unwrap(), wire::SUCCESS);
        assert_eq!(s.put(&b, &[1; 64], b"ct", 7, &[], b"").unwrap(), wire::SUCCESS);
        assert_eq!(s.put(&b, &[1; 64], b"xx", 7, &[], b"").unwrap(), wire::ALREADY_EXISTS);
        assert_eq!(s.queued(&b).unwrap(), HashSet::from([b"r2".to_vec()]));
        s.ack(&b, b"r2").unwrap();
        assert!(s.queued(&b).unwrap().is_empty());
        assert_eq!(s.put(&b, &[2; 64], b"", 7, &[], b"").unwrap(), wire::SUCCESS);
        assert!(s.get(&b).unwrap().unwrap().is_tombstone());
        assert!(s.acked(&b).unwrap().is_empty());
        assert_eq!(s.put(&b, &[1; 64], b"ct", 7, &[], b"").unwrap(), wire::ALREADY_EXISTS);
    }

    #[test]
    fn sweep_keeps_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("s.sqlite")).unwrap();
        for e in 0..4 {
            s.put(&[e as u8; 32], &[0; 64], b"x", e, &[b"d".to_vec()], b"mx").unwrap();
        }
        assert_eq!(s.sweep(&[3, 2]).unwrap(), 2);
        assert_eq!(s.get(&[3; 32]).unwrap().unwrap().origin, b"mx");
        assert_eq!(s.box_ids().unwrap().len(), 2);
        assert_eq!(s.due(1.0).unwrap().len(), 2);
        assert_eq!(s.entries(&[0; 32], &[0xff; 32], 1).unwrap(), vec![([2; 32], false)]);
    }

    fn rand(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        getrandom::fill(&mut v).unwrap();
        v
    }

    fn fill(s: &Store, n: usize, epoch: i64) -> Vec<BoxId> {
        (0..n)
            .filter_map(|_| {
                let b: BoxId = rand(32).try_into().unwrap();
                (s.put(&b, &rand(64), &rand(1000), epoch, &[], b"").unwrap() == wire::SUCCESS).then_some(b)
            })
            .collect()
    }

    #[test]
    fn quota_evicts_oldest_boxes_and_tombstones_last() {
        let dir = tempfile::tempdir().unwrap();
        let limit = 256 << 10;
        let s = Store::open_limited(&dir.path().join("s.sqlite"), limit, 0).unwrap();
        let tomb: BoxId = rand(32).try_into().unwrap();
        s.put(&tomb, &rand(64), b"", 1, &[], b"").unwrap();
        let old = fill(&s, 50, 1);
        s.enqueue(&old[0], b"r2").unwrap();
        let new = fill(&s, 1000, 2);
        assert_eq!(new.len(), 1000, "every write finds room");
        assert!(s.disk_bytes() < limit + (64 << 10));
        assert!(old.iter().all(|b| s.get(b).unwrap().is_none()), "the older epoch goes first");
        assert!(s.queued(&old[0]).unwrap().is_empty());
        assert!(s.get(&new[999]).unwrap().is_some() && s.get(&new[0]).unwrap().is_none(), "then the earliest arrivals");
        assert!(s.get(&tomb).unwrap().unwrap().is_tombstone(), "tombstones outlast boxes");
    }

    #[test]
    fn storage_full_only_when_nothing_can_be_evicted() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open_limited(&dir.path().join("s.sqlite"), 1, 0).unwrap();
        let b: BoxId = rand(32).try_into().unwrap();
        assert_eq!(s.put(&b, &rand(64), &rand(100), 1, &[], b"").unwrap(), wire::STORAGE_FULL);
        s.max_bytes = 0;
        let (sig, ct) = (rand(64), rand(100));
        assert_eq!(s.put(&b, &sig, &ct, 1, &[], b"").unwrap(), wire::SUCCESS);
        s.max_bytes = 1;
        assert_eq!(s.put(&b, &sig, &ct, 1, &[], b"").unwrap(), wire::SUCCESS, "a box held is not a new write");
        assert_eq!(s.put(&b, &rand(64), b"", 1, &[], b"").unwrap(), wire::SUCCESS, "nor is its tombstone");
    }

    #[test]
    fn min_free_evicts() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(&dir.path().join("s.sqlite")).unwrap();
        let ids = fill(&s, 10, 1);
        // More free space than the filesystem has: everything goes, and still no room.
        s.min_free_bytes = s.free_bytes() * 2;
        let b: BoxId = rand(32).try_into().unwrap();
        assert_eq!(s.put(&b, &rand(64), &rand(1000), 2, &[], b"").unwrap(), wire::STORAGE_FULL);
        assert!(ids.iter().all(|b| s.get(b).unwrap().is_none()));
        s.min_free_bytes = 1;
        assert_eq!(s.put(&b, &rand(64), &rand(1000), 2, &[], b"").unwrap(), wire::SUCCESS);
    }

    #[test]
    fn old_store_converts_to_incremental_vacuum() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("old.sqlite");
        Connection::open(&p).unwrap().execute_batch("CREATE TABLE t (x)").unwrap();
        let s = Store::open(&p).unwrap();
        assert_eq!(s.db().query_row("PRAGMA auto_vacuum", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
    }
}
