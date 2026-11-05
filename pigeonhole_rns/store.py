# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite store: boxes, the forward queue and the acknowledgements that let a
stand-in drop its copy, in one file so that storing a box and enqueueing its
forwards is one commit."""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple

import RNS

from . import wire

# Boxes evicted per round when a storage limit is hit, before measuring again.
EVICT_BATCH = 64
# Eviction frees this share of a limit beyond it, so the next writes do not hit it again.
HEADROOM = 1 / 16

SCHEMA = """
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
);
"""


@dataclass(frozen=True)
class Box:
    box_id: bytes
    epoch: int
    signature: bytes
    payload: bytes
    # The mixnet a box was pulled from, empty for one written on the mesh.
    origin: bytes = b""

    @property
    def is_tombstone(self) -> bool:
        return len(self.payload) == 0


class Store:
    """max_bytes bounds the database and its WAL on disk, and min_free_bytes
    is the free space kept on its filesystem; zero disables either. When a
    new box would pass a limit the oldest boxes are evicted, tombstones last,
    and only when nothing is left to evict is the write refused."""

    def __init__(self, path: str, max_bytes: int = 0, min_free_bytes: int = 0):
        self.path = path
        self.max_bytes = max_bytes
        self.min_free_bytes = min_free_bytes
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        with self._lock:
            # Incremental auto vacuum lets eviction hand pages back to the filesystem.
            self._db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            if self._db.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
                try:
                    self._db.execute("VACUUM")
                except sqlite3.OperationalError as e:
                    # Needs about the store's size free; without it eviction still reuses pages.
                    RNS.log("pigeonhole: could not vacuum %s for auto vacuum: %s" % (path, e), RNS.LOG_WARNING)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            # The WAL counts against max_bytes, so it is checkpointed within half the headroom.
            page = self._db.execute("PRAGMA page_size").fetchone()[0]
            wal_pages = min(1000, max(16, int(max_bytes * HEADROOM / 2 / page))) if max_bytes else 1000
            self._db.execute("PRAGMA wal_autocheckpoint=%d" % wal_pages)
            self._db.execute("PRAGMA journal_size_limit=%d" % (wal_pages * page))
            self._db.executescript(SCHEMA)
            if "origin" not in [r[1] for r in self._db.execute("PRAGMA table_info(boxes)")]:
                self._db.execute("ALTER TABLE boxes ADD COLUMN origin BLOB NOT NULL DEFAULT x''")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- disk use ----

    def disk_bytes(self) -> int:
        """The database and its WAL as they sit on disk."""
        return sum(os.path.getsize(self.path + ext) for ext in ("", "-wal") if os.path.exists(self.path + ext))

    def free_bytes(self) -> int:
        st = os.statvfs(os.path.dirname(os.path.abspath(self.path)))
        return st.f_bavail * st.f_frsize

    def full(self, headroom: float = 0.0) -> bool:
        return (self.max_bytes > 0 and self.disk_bytes() >= self.max_bytes * (1 - headroom)) or (
            self.min_free_bytes > 0 and self.free_bytes() < self.min_free_bytes * (1 + headroom)
        )

    def _compact(self) -> None:
        self._db.execute("PRAGMA incremental_vacuum").fetchall()  # one page per row stepped
        self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def make_room(self, keep: bytes = b"") -> bool:
        """Evicts the oldest boxes, by epoch then arrival and tombstones
        last, until HEADROOM below every limit. Returns False if still full."""
        with self._lock:
            if not self.full():
                return True
            evicted = 0
            while True:
                self._compact()
                if not self.full(HEADROOM):
                    break
                ids = [bytes(r[0]) for r in self._db.execute(
                    "SELECT box_id FROM boxes WHERE box_id != ? ORDER BY length(payload) = 0, epoch, rowid LIMIT ?",
                    (keep, EVICT_BATCH),
                )]
                if not ids:
                    if not self.full():
                        break
                    RNS.log("pigeonhole: storage full with nothing left to evict (%d bytes on disk, %d free)"
                            % (self.disk_bytes(), self.free_bytes()), RNS.LOG_ERROR)
                    return False
                self._delete(ids)
                evicted += len(ids)
            if evicted:
                RNS.log("pigeonhole: storage limit hit, evicted %d oldest boxes (%d bytes on disk, %d free)"
                        % (evicted, self.disk_bytes(), self.free_bytes()), RNS.LOG_WARNING)
            return True

    def _delete(self, ids: List[bytes]) -> None:
        marks = ",".join("?" for _ in ids)
        self._db.execute("BEGIN IMMEDIATE")
        for table in ("boxes", "acks", "queue"):
            self._db.execute("DELETE FROM %s WHERE box_id IN (%s)" % (table, marks), ids)
        self._db.execute("COMMIT")

    # ---- boxes ----

    def get(self, box_id: bytes) -> Optional[Box]:
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, signature, payload, origin FROM boxes WHERE box_id = ?", (box_id,)
            ).fetchone()
        if row is None:
            return None
        return Box(box_id, row[0], bytes(row[1]), bytes(row[2]), bytes(row[3]))

    def put(self, box_id: bytes, signature: bytes, payload: bytes, epoch: int, dsts: Iterable[bytes] = (), origin: bytes = b"") -> int:
        """Stores a box and enqueues forwards to dsts in one transaction.

        Write once: the same bytes again is success, different bytes is
        ALREADY_EXISTS, a tombstone replaces whatever is there, and a box
        never replaces a tombstone. A new box that finds no room after
        eviction is STORAGE_FULL. Returns a wire code."""
        with self._lock:
            if self.get(box_id) is None and not self.make_room(box_id):
                return wire.STORAGE_FULL
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT signature, payload FROM boxes WHERE box_id = ?", (box_id,)
                ).fetchone()
                if row is not None:
                    cur_sig, cur_payload = bytes(row[0]), bytes(row[1])
                    if len(cur_payload) == 0:
                        code = wire.SUCCESS if len(payload) == 0 else wire.ALREADY_EXISTS
                        self._db.execute("COMMIT")
                        return code
                    if len(payload) != 0:
                        code = wire.SUCCESS if (cur_sig == signature and cur_payload == payload) else wire.ALREADY_EXISTS
                        self._db.execute("COMMIT")
                        return code
                    # A tombstone replaces the box and the acks it had collected.
                    self._db.execute("DELETE FROM acks WHERE box_id = ?", (box_id,))
                self._db.execute(
                    "INSERT OR REPLACE INTO boxes (box_id, epoch, signature, payload, origin) VALUES (?, ?, ?, ?, ?)",
                    (box_id, epoch, signature, payload, origin),
                )
                for dst in dsts:
                    self._db.execute(
                        "INSERT OR IGNORE INTO queue (box_id, dst, attempts, next_try) VALUES (?, ?, 0, 0)",
                        (box_id, dst),
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return wire.SUCCESS

    def drop(self, box_id: bytes) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("DELETE FROM boxes WHERE box_id = ? AND length(payload) > 0", (box_id,))
            self._db.execute("DELETE FROM acks WHERE box_id = ?", (box_id,))
            self._db.execute("COMMIT")

    def box_ids(self) -> List[bytes]:
        with self._lock:
            return [bytes(r[0]) for r in self._db.execute("SELECT box_id FROM boxes")]

    def entries(self, after: bytes, upto: bytes, limit: int) -> List[Tuple[bytes, bool]]:
        """Box IDs in (after, upto], ascending, each with whether it is a tombstone."""
        with self._lock:
            rows = self._db.execute(
                "SELECT box_id, length(payload) = 0 FROM boxes WHERE box_id > ? AND box_id <= ? ORDER BY box_id LIMIT ?",
                (after, upto, limit),
            ).fetchall()
        return [(bytes(r[0]), bool(r[1])) for r in rows]

    def sweep(self, keep_epochs: Iterable[int]) -> int:
        keep = list(keep_epochs)
        marks = ",".join("?" for _ in keep)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            cur = self._db.execute("DELETE FROM boxes WHERE epoch NOT IN (%s)" % marks, keep)
            self._db.execute("DELETE FROM acks WHERE box_id NOT IN (SELECT box_id FROM boxes)")
            self._db.execute("DELETE FROM queue WHERE box_id NOT IN (SELECT box_id FROM boxes)")
            self._db.execute("COMMIT")
            self._compact()
            return cur.rowcount

    # ---- forward queue and acknowledgements ----

    def enqueue(self, box_id: bytes, dst: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO queue (box_id, dst, attempts, next_try) VALUES (?, ?, 0, 0)",
                (box_id, dst),
            )

    def due(self, now: float) -> List[Tuple[bytes, bytes, int]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT box_id, dst, attempts FROM queue WHERE next_try <= ? ORDER BY next_try", (now,)
            ).fetchall()
        return [(bytes(r[0]), bytes(r[1]), r[2]) for r in rows]

    def queued(self, box_id: bytes) -> Set[bytes]:
        with self._lock:
            rows = self._db.execute("SELECT dst FROM queue WHERE box_id = ?", (box_id,)).fetchall()
        return {bytes(r[0]) for r in rows}

    def ack(self, box_id: bytes, dst: bytes) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("DELETE FROM queue WHERE box_id = ? AND dst = ?", (box_id, dst))
            self._db.execute("INSERT OR IGNORE INTO acks (box_id, dst) VALUES (?, ?)", (box_id, dst))
            self._db.execute("COMMIT")

    def acked(self, box_id: bytes) -> Set[bytes]:
        with self._lock:
            rows = self._db.execute("SELECT dst FROM acks WHERE box_id = ?", (box_id,)).fetchall()
        return {bytes(r[0]) for r in rows}

    def backoff(self, box_id: bytes, dst: bytes, next_try: float) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE queue SET attempts = attempts + 1, next_try = ? WHERE box_id = ? AND dst = ?",
                (next_try, box_id, dst),
            )

    def forget(self, box_id: bytes, dst: bytes) -> None:
        with self._lock:
            self._db.execute("DELETE FROM queue WHERE box_id = ? AND dst = ?", (box_id, dst))
