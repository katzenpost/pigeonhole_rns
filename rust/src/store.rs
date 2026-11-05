//! The SQLite store of `store.py`, same schema and file: boxes, the forward queue and the
//! acknowledgements that let a stand-in drop its copy, so that storing a box and enqueueing its
//! forwards is one commit.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Result, params};

use crate::wire::{self, BoxId};

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

pub struct Store(Mutex<Connection>);

fn id(b: Vec<u8>) -> BoxId {
    b.try_into().unwrap_or([0; 32])
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        if db.prepare("SELECT origin FROM boxes LIMIT 0").is_err() {
            db.execute("ALTER TABLE boxes ADD COLUMN origin BLOB NOT NULL DEFAULT x''", [])?;
        }
        Ok(Store(Mutex::new(db)))
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap()
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
    /// is there, and a box never replaces a tombstone. Returns a wire code.
    #[allow(clippy::too_many_arguments)]
    pub fn put(&self, box_id: &BoxId, signature: &[u8], payload: &[u8], epoch: i64, dsts: &[Dst], origin: &[u8]) -> Result<u8> {
        let mut db = self.db();
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

    pub fn drop_box(&self, box_id: &BoxId) -> Result<()> {
        let db = self.db();
        db.execute("DELETE FROM boxes WHERE box_id = ? AND length(payload) > 0", [&box_id[..]])?;
        db.execute("DELETE FROM acks WHERE box_id = ?", [&box_id[..]])?;
        Ok(())
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
        s.drop_box(&b).unwrap();
        assert!(s.get(&b).unwrap().is_some(), "a tombstone is never dropped");
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
}
