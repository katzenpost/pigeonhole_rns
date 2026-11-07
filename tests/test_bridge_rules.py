# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Open mesh replicas, some of them bridges, driven in process, each bridge
writing to and reading from a fake mixnet over a real BridgeSocket."""

import os
import socket
import tempfile
import threading
import time

from hpqc.bacap.stateless import WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, wire
from pigeonhole_rns.bridge import BridgeSocket
from pigeonhole_rns.client import pad, position
from pigeonhole_rns.engine import BRIDGE, Engine
from pigeonhole_rns.store import Store

BOX = 100
CT = BOX + 4 + 16


class FakeMixnet:
    """A Katzenpost bridge socket in front of one store: write once, a
    tombstone replaces a box, and every write is logged as (box id,
    tombstone). A subscribed connection is announced every box held, then
    each one stored."""

    EPOCH = 2934

    def __init__(self, name):
        self.name = name
        self.boxes, self.writes, self.streams, self.since = {}, [], [], []
        self.mu = threading.Lock()
        # tmp_path can exceed the 108 byte AF_UNIX path limit.
        self.path = os.path.join(tempfile.mkdtemp(prefix="mx"), "s")
        self.l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.l.bind(self.path)
        self.l.listen()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.l.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            while True:
                raw = wire.read_frame(c)
                with self.mu:
                    if raw[0] == wire.SUBSCRIBE:
                        self.since.append(int.from_bytes(raw[1:], "big"))
                        for box_id in self.boxes:
                            self._announce(c, box_id)
                        self.streams.append(c)
                        return
                    q = wire.decode_query(raw)
                    wire.write_frame(c, self._read(q) if q.kind == wire.READ else self._write(q))
        except (OSError, EOFError, wire.WireError):
            c.close()

    def _read(self, q):
        got = self.boxes.get(q.box_id)
        if got is None:
            return wire.encode_reply(wire.NOT_FOUND)
        return wire.encode_reply(wire.TOMBSTONE) if got[1] == b"" else wire.encode_reply(wire.SUCCESS, *got)

    def _write(self, q):
        self.writes.append((q.box_id, q.ciphertext == b""))
        cur = self.boxes.get(q.box_id)
        if cur is not None and (cur[1] == b"" or q.ciphertext != b""):
            return wire.encode_reply(wire.SUCCESS if cur == (q.signature, q.ciphertext) else wire.ALREADY_EXISTS)
        self.put(q.box_id, q.signature, q.ciphertext)
        return wire.encode_reply(wire.SUCCESS)

    def put(self, box_id, sig, ct):
        """Stores a box, as a mixnet client's write would, and announces it."""
        self.boxes[box_id] = (sig, ct)
        for c in self.streams:
            self._announce(c, box_id)

    def _announce(self, c, box_id):
        sig, ct = self.boxes[box_id]
        wire.write_frame(c, self.EPOCH.to_bytes(8, "big") + box_id + sig + ct)

    def close(self):
        self.l.close()
        for c in self.streams:
            c.close()


class Mesh:
    """Replicas that all reach each other; a node with a mixnet is its bridge."""

    def __init__(self, tmp_path, nodes):
        self.clock = [1000.0]
        self.e, self.sock = {}, {}
        dest = {n: (n * 16)[:16].encode() for n in nodes}
        self.dest = dest
        self.name = {d: n for n, d in dest.items()}
        for n, mx in nodes.items():
            self.e[n] = Engine(Store(str(tmp_path / (n + ".sqlite"))), dest[n], b"I" + dest[n], box_ciphertext_sizes=(CT,),
                               is_bridge=mx is not None, now=lambda: self.clock[0],
                               mixnet=wire.mixnet_id(mx.name) if mx else b"")
            if mx:
                self.sock[n] = BridgeSocket(mx.path, conns=1)
        for n in nodes:
            for m, mx in nodes.items():
                if m != n:
                    self.e[n].heard(dest[m], b"I" + dest[m], mx is not None, wire.mixnet_id(mx.name) if mx else b"")

    def reach(self, n):
        return [d for m, d in self.dest.items() if m != n]

    def bridge_read(self, n):
        return self.sock[n].read if n in self.sock else None

    def run(self, rounds=4):
        for _ in range(rounds):
            for n, e in self.e.items():
                src = self.dest[n]
                e.handoff()
                e.sync(self.reach(n), lambda dst, q, src=src: self.e[self.name[dst]].handle_sync(q, src))
                e.forward_due(self.reach(n), lambda *a, n=n: self.deliver(n, *a), self.pushed)
            self.clock[0] += 700  # past the longest backoff

    def deliver(self, n, dst, box_id, sig, ct, origin):
        if dst == BRIDGE:
            return self.sock[n].write(box_id, sig, ct)
        m, q = self.name[dst], wire.encode_write(box_id, sig, ct)
        if origin:
            return self.e[m].handle_forward(origin + q, self.reach(m), self.dest[n])[0]
        return self.e[m].handle_write(q, self.reach(m), self.dest[n])[0]

    def pushed(self, dst, box_id, tomb):
        return self.e[self.name[dst]].handle_pushed(box_id + bytes([tomb])) == b"\x01"

    def peek(self, dst, box_id):
        m = self.name[dst]
        return wire.decode_reply(self.e[m].handle_peek(wire.encode_read(box_id), self.bridge_read(m), self.reach(m)))

    def read(self, n, box_id):
        return wire.decode_reply(self.e[n].handle_read(wire.encode_read(box_id), self.reach(n), self.peek, self.bridge_read(n)))

    def write(self, n, box_id, sig, ct):
        """A client's write to replica n."""
        return self.e[n].handle_write(wire.encode_write(box_id, sig, ct), self.reach(n))[0]

    def close(self):
        for s in self.sock.values():
            s.close()


def seal(cap, text, index=0):
    box, ct, sig = position(cap, index).encrypt(PIGEONHOLE_CTX, pad(text, BOX))
    return box, sig, ct


def tombstone(cap, index=0):
    tid, tsig = position(cap, index).tombstone(PIGEONHOLE_CTX)
    return tid, tsig, b""


def count(mx, box_id, tomb):
    return mx.writes.count((box_id, tomb))


def test_two_mixnets_are_linked_without_loops(tmp_path):
    mxa, mxb = FakeMixnet("A"), FakeMixnet("B")
    m = Mesh(tmp_path, {"a": mxa, "b": mxb, "r": None})
    caps = [WriteCap.generate() for _ in range(3)]

    # Written on mixnet A by a mixnet client, read on the mesh: pulled by bridge a.
    b1 = seal(caps[0], b"from A")
    mxa.boxes[b1[0]] = b1[1:]
    r = m.read("r", b1[0])
    assert r.code == wire.SUCCESS and r.ciphertext == b1[2]
    assert m.e["a"].store.get(b1[0]).origin == wire.mixnet_id("A")
    # Written on mixnet B, read at bridge a, which finds it through bridge b.
    b2 = seal(caps[1], b"from B")
    mxb.boxes[b2[0]] = b2[1:]
    assert m.read("a", b2[0]).code == wire.SUCCESS
    # Written by a mesh client.
    b3 = seal(caps[2], b"from the mesh")
    assert m.write("r", *b3) == wire.SUCCESS
    m.run()

    for n in "abr":
        assert m.e[n].store.get(b1[0]).origin == wire.mixnet_id("A")
        assert m.e[n].store.get(b2[0]).origin == wire.mixnet_id("B")
        assert m.e[n].store.get(b3[0]).origin == b""
    assert mxb.boxes[b1[0]] == b1[1:] and mxa.boxes[b2[0]] == b2[1:]
    assert mxa.boxes[b3[0]] == b3[1:] and mxb.boxes[b3[0]] == b3[1:]
    assert sorted(mxa.writes) == sorted([(b2[0], False), (b3[0], False)]), "nothing written back to its origin"
    assert sorted(mxb.writes) == sorted([(b1[0], False), (b3[0], False)])

    # An overwrite with other bytes is refused and goes nowhere; a tombstone replaces the box in both mixnets.
    other = seal(caps[1], b"other bytes")
    assert other[0] == b2[0] and m.write("r", *other) == wire.ALREADY_EXISTS
    t1 = tombstone(caps[0])
    assert m.write("b", *t1) == wire.SUCCESS
    m.run()
    assert mxa.boxes[b2[0]] == b2[1:] and mxb.boxes[b2[0]] == b2[1:]
    assert mxa.boxes[b1[0]] == (t1[1], b"") and mxb.boxes[b1[0]] == (t1[1], b"")
    assert count(mxa, b1[0], True) == 1 and count(mxb, b1[0], True) == 1
    for n in "abr":
        assert m.e[n].store.get(b1[0]).is_tombstone

    writes = (list(mxa.writes), list(mxb.writes))
    m.run(rounds=6)
    assert (mxa.writes, mxb.writes) == writes, "no loop"
    m.close()
    mxa.close()
    mxb.close()


def test_two_bridges_to_one_mixnet_write_each_box_once(tmp_path):
    mx = FakeMixnet("A")
    m = Mesh(tmp_path, {"a1": mx, "a2": mx, "r": None})
    caps = [WriteCap.generate() for _ in range(6)]
    boxes = [seal(c, b"%d" % i) for i, c in enumerate(caps)]
    for i, b in enumerate(boxes):
        assert m.write(("r", "a1", "a2")[i % 3], *b) == wire.SUCCESS
    t0 = tombstone(caps[0])
    m.write("r", *t0)
    pulled = seal(WriteCap.generate(), b"from A")
    mx.boxes[pulled[0]] = pulled[1:]
    assert m.read("r", pulled[0]).code == wire.SUCCESS
    m.run()

    for b in boxes[1:]:
        assert mx.boxes[b[0]] == b[1:]
        assert count(mx, b[0], False) == 1
    assert mx.boxes[t0[0]] == (t0[1], b"") and count(mx, t0[0], True) == 1
    assert count(mx, boxes[0][0], False) <= 1, "the box before its tombstone, at most once"
    assert count(mx, pulled[0], False) == 0
    for n in ("a1", "a2"):
        assert BRIDGE not in m.e[n].store.queued(pulled[0])
    m.close()
    mx.close()


def stream(sock, since, f):
    """Runs a stream on a thread of its own until it ends, as it does when its socket closes."""
    def run():
        try:
            sock.stream(since, f)
        except (OSError, EOFError):
            pass
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def wait_for(f, timeout=5.0):
    end = time.monotonic() + timeout
    while not f():
        assert time.monotonic() < end, "timed out"
        time.sleep(0.01)


def test_streamed_boxes_and_tombstones_cross_to_another_mixnet(tmp_path):
    mxa, mxb = FakeMixnet("A"), FakeMixnet("B")
    m = Mesh(tmp_path, {"a": mxa, "b": mxb, "r": None})
    pushed = []
    m.e["r"].on_stored = pushed.append
    caps = [WriteCap.generate() for _ in range(2)]
    before, after = seal(caps[0], b"held before"), seal(caps[1], b"written after")
    mxa.put(*before)
    for n in "ab":
        stream(m.sock[n], 0, lambda _, q, n=n: m.e[n].announced(q, m.reach(n)))
    wait_for(lambda: len(mxa.streams) == 1 and len(mxb.streams) == 1)
    mxa.put(*after)
    wait_for(lambda: all(m.e["a"].store.get(b[0]) for b in (before, after)))
    m.run()

    for b in (before, after):
        assert mxb.boxes[b[0]] == b[1:]
        for n in "abr":
            assert m.e[n].store.get(b[0]).origin == wire.mixnet_id("A")
    assert before[0] in pushed and after[0] in pushed

    t = tombstone(caps[0])
    mxa.put(*t)
    wait_for(lambda: m.e["a"].store.get(t[0]).is_tombstone)
    m.run()
    assert mxb.boxes[t[0]] == (t[1], b"")
    assert m.e["r"].store.get(t[0]).is_tombstone

    m.run(rounds=6)
    assert mxa.writes == [], "nothing written back to its origin"
    assert sorted(mxb.writes) == sorted([(before[0], False), (after[0], False), (t[0], True)])
    m.close()
    mxa.close()
    mxb.close()


def test_stream_ends_when_dropped_and_replays_on_resubscribe(tmp_path):
    mx = FakeMixnet("A")
    b = BridgeSocket(mx.path)
    box = seal(WriteCap.generate(), b"x")
    mx.put(*box)
    got = []
    t = stream(b, 0, lambda ep, q: got.append((ep, q.box_id, q.ciphertext)))
    wait_for(lambda: got)
    mx.streams.pop().shutdown(socket.SHUT_RDWR)
    t.join(5)
    assert not t.is_alive()
    assert got == [(FakeMixnet.EPOCH, box[0], box[2])]
    stream(b, FakeMixnet.EPOCH, lambda ep, q: got.append((ep, q.box_id, q.ciphertext)))
    wait_for(lambda: len(got) == 2)
    assert got[1] == got[0], "a box announced again"
    b.close()
    mx.close()


def test_replica_resubscribes_from_the_last_epoch_seen(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from pigeonhole_rns import replica

    monkeypatch.setattr(replica, "STREAM_RETRY", 0.05)
    mx = FakeMixnet("A")
    m = Mesh(tmp_path, {"a": mx, "r": None})
    stub = SimpleNamespace(bridge=m.sock["a"], engine=m.e["a"], _reachable=lambda: m.reach("a"),
                           _kick=threading.Event(), _stop=threading.Event())
    t = threading.Thread(target=replica.Replica._stream_loop, args=(stub,), daemon=True)
    t.start()
    wait_for(lambda: mx.streams)
    box = seal(WriteCap.generate(), b"x")
    mx.put(*box)
    wait_for(lambda: m.e["a"].store.get(box[0]) is not None)
    assert stub._kick.is_set()
    mx.streams.pop().shutdown(socket.SHUT_RDWR)
    wait_for(lambda: len(mx.since) == 2)
    assert mx.since == [0, FakeMixnet.EPOCH]
    stub._stop.set()
    m.close()
    t.join(5)
    assert not t.is_alive()
    mx.close()
