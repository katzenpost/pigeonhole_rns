# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica paths in query mode 2: replicas ask each other in mode 2 first and fall back
to Link requests, and a replica answers each path's op byte with that path's handler, knowing
the sender from the Link."""
import threading
import types

from hpqc.bacap.stateless import WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, channel, replica, rnsio, wire
from pigeonhole_rns.client import pad, position
from pigeonhole_rns.engine import Engine
from pigeonhole_rns.store import Store

BOX = 100
ME, PEER = b"me" * 8, b"pe" * 8


def links(monkeypatch, prefer_channel, channel_reply=b"\x00"):
    """Links whose mode 2 answers channel_reply and whose Link requests answer b"req"."""
    l = rnsio.Links(prefer_channel=prefer_channel)
    sent = []
    monkeypatch.setattr(l, "channel_request", lambda dest, data: sent.append(("ch", data)) or channel_reply)
    monkeypatch.setattr(l, "_request", lambda dest, path, data: sent.append(("req", path, data)) or b"req")
    monkeypatch.setattr(l, "_active", lambda dest: True)
    return l, sent


def test_replicas_ask_in_mode_2_first(monkeypatch):
    l, sent = links(monkeypatch, True)
    l.flags[PEER] = 2 | 4
    for path, op in channel.PATH_OPS.items():
        assert l.request(PEER, path, b"q") == b"\x00"
        assert sent.pop() == ("ch", bytes([op]) + b"q")
    assert l.request(PEER, "write", b"\x01w") == b"\x00" and sent.pop() == ("ch", b"\x01w")
    # A replica serving mode 2 but not the replica paths, or nothing announced: Link requests.
    l.flags[PEER] = 2
    assert l.request(PEER, "sync", b"q") == b"req" and sent == [("req", "sync", b"q")]
    sent.clear()
    assert l.request(b"py" * 8, "peek", b"q") == b"req" and sent == [("req", "peek", b"q")]


def test_falls_back_to_link_requests_when_mode_2_fails(monkeypatch):
    l, sent = links(monkeypatch, True, channel_reply=None)
    l.flags[PEER] = 2 | 4
    assert l.request(PEER, "forward", b"q") == b"req"
    assert sent == [("ch", bytes([channel.PATH_OPS["forward"]]) + b"q"), ("req", "forward", b"q")]
    # Not when no Link could be opened, nor to a replica serving no Link requests.
    sent.clear()
    monkeypatch.setattr(l, "_active", lambda dest: False)
    assert l.request(PEER, "forward", b"q") is None and [s[0] for s in sent] == ["ch"]
    monkeypatch.setattr(l, "_active", lambda dest: True)
    sent.clear()
    l.flags[PEER] = 2 | 4 | 8
    assert l.request(PEER, "forward", b"q") is None and [s[0] for s in sent] == ["ch"]


def test_a_mode_1_client_uses_mode_2_only_where_requests_are_not_served(monkeypatch):
    l, sent = links(monkeypatch, False)
    l.flags[PEER] = 2 | 4
    assert l.request(PEER, "write", b"\x01w") == b"req"
    l.flags[PEER] = 2 | 4 | 8
    assert l.request(PEER, "write", b"\x01w") == b"\x00"
    assert [s[0] for s in sent] == ["req", "ch"]


def test_announce_passes_the_flags():
    got = []
    h = rnsio.AnnounceHandler(lambda *a: got.append(a))
    h.received_announce(PEER, types.SimpleNamespace(hash=b"I" * 16), bytes([2 | 4 | 8]))
    h.received_announce(PEER, types.SimpleNamespace(hash=b"I" * 16), b"")
    assert [a[-1] for a in got] == [14, 0]


def node(tmp_path):
    e = Engine(Store(str(tmp_path / "e.sqlite")), ME, b"I" + ME, box_ciphertext_size=BOX + 20)
    e.heard(PEER, b"I" + PEER, False)
    me = types.SimpleNamespace(engine=e, links=types.SimpleNamespace(peek=lambda d, b: None), _bridge_read=lambda: None,
                               _reachable=lambda: [PEER], _kick=threading.Event())
    me._sender = lambda ident: replica.Replica._sender(me, ident)
    return me


def ask(me, data, identity=b"I" + PEER):
    out = []
    link = types.SimpleNamespace(get_remote_identity=lambda: types.SimpleNamespace(hash=identity) if identity else None)
    replica.Replica._on_frame_query(me, types.SimpleNamespace(link=link, send=lambda rid, r: out.append(r)), 7, data)
    return out[0]


def test_replica_paths_by_op_byte(tmp_path):
    me = node(tmp_path)
    box, ct, sig = position(WriteCap.generate(), 0).encrypt(PIGEONHOLE_CTX, pad(b"yo", BOX))
    w = wire.encode_write(box, sig, ct)
    # A write from the identified peer is not sent back to it.
    assert ask(me, w) == bytes([wire.SUCCESS])
    assert me.engine.store.queued(box) == set()
    assert ask(me, bytes([channel.PATH_OPS["peek"]]) + wire.encode_read(box)) == wire.encode_reply(wire.SUCCESS, sig, ct)
    page = ask(me, bytes([channel.PATH_OPS["sync"]]) + wire.encode_sync(bytes(32) + b"\xff" * 32, []))
    assert page == wire.encode_sync(b"\xff" * 32, [(box, 0)])
    assert ask(me, bytes([channel.PATH_OPS["pushed"]]) + box + b"\x00") == b"\x00"
    # A forward keeps its origin, from a known replica only.
    b2, ct2, sig2 = position(WriteCap.generate(), 0).encrypt(PIGEONHOLE_CTX, pad(b"mx", BOX))
    assert ask(me, bytes([channel.PATH_OPS["forward"]]) + b"M" * 16 + wire.encode_write(b2, sig2, ct2)) == b"\x00"
    assert me.engine.store.get(b2).origin == b"M" * 16
    # A client's write, from no identified replica, is forwarded to the peer.
    b3, ct3, sig3 = position(WriteCap.generate(), 0).encrypt(PIGEONHOLE_CTX, pad(b"c", BOX))
    assert ask(me, wire.encode_write(b3, sig3, ct3), identity=None) == b"\x00"
    assert me.engine.store.queued(b3) == {PEER}
    assert ask(me, b"\x09" + box) == bytes([wire.INVALID_PAYLOAD])
