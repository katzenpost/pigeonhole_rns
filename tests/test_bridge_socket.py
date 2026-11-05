# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""BridgeSocket against a fake Katzenpost bridge socket that, like
replica/bridge.go, serves each connection on its own thread, one query at a
time, and is slow on a read it must proxy to other shards."""

import os
import socket
import tempfile
import threading
import time

from pigeonhole_rns import wire
from pigeonhole_rns.bridge import BridgeSocket

SLOW = b"\xff" * 32
FAST = b"\x01" * 32
DELAY = 1.0


class FakeBridge:
    def __init__(self, path):
        self.l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.l.bind(path)
        self.l.listen()
        self.conns = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.l.accept()
            except OSError:
                return
            self.conns.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            while True:
                q = wire.decode_query(wire.read_frame(c))
                if q.kind == wire.READ and q.box_id == SLOW:
                    time.sleep(DELAY)
                wire.write_frame(c, wire.encode_reply(wire.NOT_FOUND if q.kind == wire.READ else wire.SUCCESS))
        except (OSError, EOFError, wire.WireError):
            c.close()

    def drop_all(self):
        for c in self.conns:
            c.shutdown(socket.SHUT_RDWR)
            c.close()

    def close(self):
        self.l.close()


def fake():
    # tmp_path can exceed the 108 byte AF_UNIX path limit.
    path = os.path.join(tempfile.mkdtemp(prefix="br"), "s")
    return FakeBridge(path), path


def test_slow_read_blocks_neither_reads_nor_writes():
    srv, path = fake()
    b = BridgeSocket(path)
    slow = threading.Thread(target=b.read, args=(SLOW,))
    slow.start()
    time.sleep(0.1)
    t0 = time.monotonic()
    assert b.read(FAST).code == wire.NOT_FOUND
    assert b.write(FAST, b"\x00" * 64, b"") == wire.SUCCESS
    assert time.monotonic() - t0 < DELAY / 2
    slow.join()
    b.close()
    srv.close()


def test_connections_are_bounded_and_reused():
    srv, path = fake()
    b = BridgeSocket(path, conns=2)
    ts = [threading.Thread(target=b.read, args=(SLOW,)) for _ in range(4)]
    t0 = time.monotonic()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert time.monotonic() - t0 >= 2 * DELAY
    assert len(srv.conns) == 2
    b.close()
    srv.close()


def test_reconnects_after_the_replica_drops_idle_connections():
    srv, path = fake()
    b = BridgeSocket(path)
    assert b.read(FAST).code == wire.NOT_FOUND
    srv.drop_all()
    assert b.read(FAST).code == wire.NOT_FOUND
    b.close()
    srv.close()
