# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Replica epochs, GC at their boundaries, and eviction at the storage limits."""
import os
import sqlite3

from pigeonhole_rns import wire
from pigeonhole_rns.engine import EPOCH_BASE, EPOCH_SECONDS, Engine, epoch_now
from pigeonhole_rns.store import Store

from test_engine import CT, IDS, ME, seal


def test_replica_epoch_matches_katzenpost():
    assert EPOCH_SECONDS == 7 * 24 * 3600
    # Katzenpost's ReplicaNow at 2026-11-05 00:00 UTC.
    assert epoch_now(1793836800) == (1793836800 - 1496275200) // 604800 == 492


def test_gc_keeps_current_and_previous_epoch_across_boundaries(tmp_path):
    clock = [EPOCH_BASE + 10 * 3600.0]
    e = Engine(Store(str(tmp_path / "e.sqlite")), ME, IDS[ME], box_ciphertext_sizes=(CT,), now=lambda: clock[0], epoch_seconds=3600)
    boxes = []
    for _ in range(2):
        _, box, sig, ct = seal()
        assert e.store.put(box, sig, ct, e.epoch()) == wire.SUCCESS
        boxes.append(box)
        clock[0] += e.till_next_epoch()
    # In epoch 12 the boxes from 10 and 11: the one from 10 goes at the boundary, not a second before.
    assert e.epoch() == 12
    clock[0] -= 1
    assert e.gc() == 0
    clock[0] += 1
    assert e.gc() == 1
    assert e.store.get(boxes[0]) is None and e.store.get(boxes[1]) is not None
    clock[0] += e.till_next_epoch()
    assert e.gc() == 1 and e.store.get(boxes[1]) is None


def fill(s, n, epoch=1, size=1000):
    ids = []
    for _ in range(n):
        b = os.urandom(32)
        if s.put(b, os.urandom(64), os.urandom(size), epoch) == wire.SUCCESS:
            ids.append(b)
    return ids


def test_quota_evicts_oldest_boxes_and_tombstones_last(tmp_path):
    limit = 256 << 10
    s = Store(str(tmp_path / "s.sqlite"), max_bytes=limit)
    tomb = os.urandom(32)
    s.put(tomb, os.urandom(64), b"", 1)
    old = fill(s, 50, epoch=1)
    s.enqueue(old[0], b"r2")
    new = fill(s, 1000, epoch=2)
    assert len(new) == 1000, "every write finds room"
    assert s.disk_bytes() < limit + (64 << 10)
    assert all(s.get(b) is None for b in old), "the older epoch goes first"
    assert s.queued(old[0]) == set()
    assert s.get(new[-1]) is not None and s.get(new[0]) is None, "then the earliest arrivals"
    assert s.get(tomb).is_tombstone, "tombstones outlast boxes"


def test_storage_full_only_when_nothing_can_be_evicted(tmp_path):
    s = Store(str(tmp_path / "s.sqlite"), max_bytes=1)
    assert s.put(os.urandom(32), os.urandom(64), os.urandom(100), 1) == wire.STORAGE_FULL
    s.max_bytes = 0
    box, sig, ct = os.urandom(32), os.urandom(64), os.urandom(100)
    assert s.put(box, sig, ct, 1) == wire.SUCCESS
    s.max_bytes = 1
    assert s.put(box, sig, ct, 1) == wire.SUCCESS, "a box already held is not a new write"
    assert s.put(box, os.urandom(64), b"", 1) == wire.SUCCESS, "nor is its tombstone"


def test_min_free_evicts(tmp_path, monkeypatch):
    s = Store(str(tmp_path / "s.sqlite"), min_free_bytes=100 << 20)
    ids = fill(s, 10)
    monkeypatch.setattr(s, "free_bytes", lambda: (50 << 20) + 64 * 1000 * len(s.box_ids()))
    assert s.put(os.urandom(32), os.urandom(64), os.urandom(1000), 2) == wire.STORAGE_FULL
    monkeypatch.setattr(s, "free_bytes", lambda: (100 << 20) - 1000 * len(s.box_ids()) + 5000)
    assert s.put(os.urandom(32), os.urandom(64), os.urandom(1000), 2) == wire.SUCCESS
    assert sum(s.get(b) is not None for b in ids) < 10


def test_old_store_converts_to_incremental_vacuum(tmp_path):
    p = str(tmp_path / "old.sqlite")
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE t (x)")
    db.commit()
    db.close()
    s = Store(p)
    assert s._db.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
