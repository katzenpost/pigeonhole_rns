# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Push: subscriptions, and the replica pushing boxes to the Links waiting for them as it
stores them, from a client, a replica or the bridge."""
import queue
import threading
import types

from hpqc.bacap.stateless import WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, channel, push, replica, wire
from pigeonhole_rns.client import pad, position
from pigeonhole_rns.engine import Engine
from pigeonhole_rns.store import Store

BOX = 100
ME, PEER = b"me" * 8, b"pe" * 8
L1, L2 = b"L1" * 8, b"L2" * 8


def seal(text=b"yo"):
    box, ct, sig = position(WriteCap.generate(), 0).encrypt(PIGEONHOLE_CTX, pad(text, BOX))
    return box, sig, ct


def test_subscriptions_limit_expiry_and_take():
    clock = [0.0]
    s = push.Subscriptions(limit=3, max_ttl=100, now=lambda: clock[0])
    a, b, c, d = (bytes([i]) * 32 for i in range(4))
    assert s.subscribe(L1, 10, [a, b]) == (2, 10)
    # Past the limit the rest are refused, a renewal still taken; ttl 0 asks for the most.
    assert s.subscribe(L1, 0, [a, c, d]) == (2, 100)
    assert s.subscribe(L1, 500, [b]) == (1, 100)
    assert s.subscribe(L2, 5, [a]) == (1, 5)
    assert sorted(s.take(a)) == [L1, L2] and s.take(a) == []
    clock[0] = 101
    assert s.take(b) == [] and s.take(c) == []
    # Expired ones no longer count toward the limit.
    assert s.subscribe(L1, 10, [a, b, c]) == (3, 10)
    s.unsubscribe(L1, [a])
    assert s.take(a) == [] and s.take(b) == [L1]
    s.unsubscribe(L1, [])
    assert s.take(c) == []
    s.subscribe(L1, 10, [d])
    s.drop(L1)
    assert s.take(d) == []


def test_wire():
    a, b = b"\x01" * 32, b"\x02" * 32
    assert push.encode_subscribe(300, [a, b]) == b"\x01\x2c" + a + b
    assert push.decode_subscribe(b"\x01\x2c" + a + b) == (300, [a, b])
    assert push.encode_subscribe_reply(2, 300) == b"\x00\x00\x02\x01\x2c"
    assert push.encode_push(a, wire.Reply(wire.TOMBSTONE)) == a + b"\x0b"
    for bad in (b"", b"\x00", b"\x00\x01" + a[:5]):
        try:
            push.decode_subscribe(bad)
            raise AssertionError(bad)
        except wire.WireError:
            pass
    assert channel.split(1, b"x", 10, channel.PushFrame)[0].pack() == b"\x00\x01\x00\x01x"
    assert channel.PushFrame.MSGTYPE == 0x5049


def node(tmp_path, is_bridge=False, bridge_read=None):
    """A replica without Reticulum: its Links are the queues of L1 and L2."""
    me = object.__new__(replica.Replica)
    me.engine = Engine(Store(str(tmp_path / "e.sqlite")), ME, b"I" + ME, box_ciphertext_sizes=(BOX + 20,), is_bridge=is_bridge)
    me.engine.heard(PEER, b"I" + PEER, False)
    me.clock = [0.0]
    me.subs = push.Subscriptions(limit=4, now=lambda: me.clock[0])
    me._pushers = {L1: queue.Queue(), L2: queue.Queue()}
    me.engine.on_stored = me._stored
    me.links = types.SimpleNamespace(peek=lambda d, b: None)
    me._bridge_read = lambda: bridge_read
    me._reachable = lambda: [PEER]
    me._kick = threading.Event()
    return me


def ask(me, link_id, data, identity=None):
    out = []
    ident = types.SimpleNamespace(hash=identity) if identity else None
    link = types.SimpleNamespace(link_id=link_id, get_remote_identity=lambda: ident)
    replica.Replica._on_frame_query(me, types.SimpleNamespace(link=link, send=lambda rid, r: out.append(r)), 7, data)
    return out[0]


def pushed(me, link_id):
    q, out = me._pushers[link_id], []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def sub(me, link_id, ids, ttl=60):
    return ask(me, link_id, bytes([push.SUBSCRIBE]) + push.encode_subscribe(ttl, ids))


def test_push_on_local_write_and_replicated_arrival(tmp_path):
    me = node(tmp_path)
    (b1, s1, c1), (b2, s2, c2) = seal(b"one"), seal(b"two")
    assert sub(me, L1, [b1, b2]) == push.encode_subscribe_reply(2, 60)
    assert sub(me, L2, [b1]) == push.encode_subscribe_reply(1, 60)
    # A client's write reaches both Links waiting for it, once.
    assert ask(me, b"C" * 16, wire.encode_write(b1, s1, c1)) == bytes([wire.SUCCESS])
    want = b1 + wire.encode_reply(wire.SUCCESS, s1, c1)
    assert pushed(me, L1) == [want] and pushed(me, L2) == [want]
    ask(me, b"C" * 16, wire.encode_write(b1, s1, c1))
    assert pushed(me, L1) == []
    # A forward from a replica too, with its origin.
    fwd = bytes([channel.PATH_OPS["forward"]]) + b"M" * 16 + wire.encode_write(b2, s2, c2)
    assert ask(me, b"P" * 16, fwd, identity=b"I" + PEER) == bytes([wire.SUCCESS])
    assert pushed(me, L1) == [b2 + wire.encode_reply(wire.SUCCESS, s2, c2)]


def test_held_box_pushed_at_subscribe_and_tombstones(tmp_path):
    me = node(tmp_path)
    cap = WriteCap.generate()
    pos = position(cap, 0)
    box, ct, sig = pos.encrypt(PIGEONHOLE_CTX, pad(b"held", BOX))
    ask(me, b"C" * 16, wire.encode_write(box, sig, ct))
    assert sub(me, L1, [box]) == push.encode_subscribe_reply(1, 60)
    assert pushed(me, L1) == [box + wire.encode_reply(wire.SUCCESS, sig, ct)]
    # The push took the subscription: a tombstone after it is not pushed.
    _, tsig = pos.tombstone(PIGEONHOLE_CTX)
    ask(me, b"C" * 16, wire.encode_write(box, tsig, b""))
    assert pushed(me, L1) == []
    # One subscribing now gets the tombstone, and a tombstone stored while waiting too.
    sub(me, L2, [box])
    assert pushed(me, L2) == [box + bytes([wire.TOMBSTONE])]
    pos1 = position(cap, 1)
    b1, s1 = pos1.tombstone(PIGEONHOLE_CTX)
    sub(me, L2, [b1])
    ask(me, b"C" * 16, wire.encode_write(b1, s1, b""))
    assert pushed(me, L2) == [b1 + bytes([wire.TOMBSTONE])]


def test_push_from_the_bridge(tmp_path):
    box, sig, ct = seal(b"mix")
    me = node(tmp_path, is_bridge=True, bridge_read=lambda b: wire.Reply(wire.SUCCESS, sig, ct) if b == box else None)
    sub(me, L1, [box])
    peek = bytes([channel.PATH_OPS["peek"]]) + wire.encode_read(box)
    assert ask(me, b"P" * 16, peek, identity=b"I" + PEER) == wire.encode_reply(wire.SUCCESS, sig, ct)
    assert pushed(me, L1) == [box + wire.encode_reply(wire.SUCCESS, sig, ct)]


def test_expiry_limit_unsubscribe_and_close(tmp_path):
    me = node(tmp_path)
    boxes = [seal(bytes([i])) for i in range(6)]
    ids = [b for b, _, _ in boxes]
    # The limit, 4 here: the rest are refused and never pushed.
    assert sub(me, L1, ids, ttl=10) == push.encode_subscribe_reply(4, 10)
    write = lambda i: ask(me, b"C" * 16, wire.encode_write(*boxes[i]))
    write(5)
    assert pushed(me, L1) == []
    # Expired: nothing pushed.
    me.clock[0] = 11
    write(0)
    assert pushed(me, L1) == []
    assert sub(me, L1, ids[1:3]) == push.encode_subscribe_reply(2, 60)
    assert ask(me, L1, bytes([push.UNSUBSCRIBE]) + ids[1]) == bytes([wire.SUCCESS])
    write(1)
    assert pushed(me, L1) == []
    me._on_closed(types.SimpleNamespace(link_id=L1))
    write(2)
    assert L1 not in me._pushers
    assert ask(me, L1, bytes([push.SUBSCRIBE]) + b"\x00") == bytes([wire.INVALID_PAYLOAD])
    assert ask(me, L1, bytes([push.UNSUBSCRIBE]) + b"\x00") == bytes([wire.INVALID_PAYLOAD])
