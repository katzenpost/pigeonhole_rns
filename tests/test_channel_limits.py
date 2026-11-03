# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Channel mode's limits on one replica: at most CHANNEL_WORKERS queries handled at once per
Link, at most CHANNEL_QUEUE waiting, the rest dropped, and the workers ending with the Link."""
import threading
import time
import types

import RNS

from pigeonhole_rns import channel, replica


class StubLink:
    status = RNS.Link.ACTIVE


def setup(monkeypatch, handlers=replica.CHANNEL_HANDLERS):
    accepted = {}
    monkeypatch.setattr(channel, "Endpoint", lambda link, on_message: accepted.setdefault("cb", on_message))
    running, peak, release = [0], [0], threading.Event()
    lock = threading.Lock()

    def on_frame_query(ep, rid, data):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        release.wait(5)
        with lock:
            running[0] -= 1

    me = types.SimpleNamespace(
        _stop=threading.Event(),
        _channel_handlers=threading.BoundedSemaphore(handlers),
        _on_frame_query=on_frame_query,
    )
    return me, accepted, running, peak, release


def test_per_link_workers_and_queue(monkeypatch):
    me, accepted, running, peak, release = setup(monkeypatch)
    link = StubLink()
    replica.Replica._on_link(me, link)
    cb = accepted["cb"]
    for i in range(replica.CHANNEL_WORKERS + replica.CHANNEL_QUEUE + 5):
        cb(None, i, b"\x00")
    time.sleep(0.3)
    assert running[0] == replica.CHANNEL_WORKERS, "two at once per link, the rest waiting"
    release.set()
    deadline = time.time() + 5
    while running[0] and time.time() < deadline:
        time.sleep(0.05)
    assert peak[0] == replica.CHANNEL_WORKERS
    link.status = RNS.Link.CLOSED
    time.sleep(1.5)
    me._stop.set()


def test_replica_wide_cap(monkeypatch):
    me, accepted, running, peak, release = setup(monkeypatch, handlers=3)
    links = [StubLink() for _ in range(4)]
    cbs = []
    for link in links:
        replica.Replica._on_link(me, link)
        cbs.append(accepted.pop("cb"))
    for cb in cbs:
        for i in range(replica.CHANNEL_WORKERS):
            cb(None, i, b"\x00")
    time.sleep(0.3)
    assert running[0] == 3, "no more than CHANNEL_HANDLERS across all links"
    release.set()
    me._stop.set()


def test_overflow_is_dropped(monkeypatch):
    me, accepted, running, peak, release = setup(monkeypatch)
    dropped = []
    monkeypatch.setattr(RNS, "log", lambda msg, level=None: dropped.append(msg))
    replica.Replica._on_link(me, StubLink())
    cb = accepted["cb"]
    for i in range(replica.CHANNEL_WORKERS + replica.CHANNEL_QUEUE + 3):
        cb(None, i, b"\x00")
        time.sleep(0.01)
    assert sum("queue full" in m for m in dropped) >= 3
    release.set()
    me._stop.set()
