# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Box payload profiles: replicas take the sizes their mesh is configured
with, and a bridge carries either to the Katzenpost side unchanged."""
import json
import os
import socket
import tempfile
import threading
import time

import pytest
import RNS
from hpqc.bacap.stateless import MessageBoxIndex, WriteCap
from RNS.vendor import umsgpack

from pigeonhole_rns import PIGEONHOLE_CTX, channel, wire
from pigeonhole_rns.bridge import BridgeSocket
from pigeonhole_rns.client import pad, position
from pigeonhole_rns.engine import BRIDGE, Engine
from pigeonhole_rns.store import Store

BIG, MESH = wire.BOX_PLAINTEXT_MIXNET, wire.BOX_PLAINTEXT_MESH
ME, R2 = b"me" * 8, b"r2" * 8


def seal(size, text=b"yo"):
    box, ct, sig = position(WriteCap.generate(), 0).encrypt(PIGEONHOLE_CTX, pad(text, size))
    return box, sig, ct


def engine(tmp_path, sizes, is_bridge=False, name="e"):
    logs = []
    e = Engine(Store(str(tmp_path / (name + ".sqlite"))), ME, b"I" + ME, is_bridge=is_bridge, log=logs.append,
               box_ciphertext_sizes=[n + wire.BOX_OVERHEAD for n in sizes])
    return e, logs


def write(e, box, sig, ct):
    return e.handle_write(wire.encode_write(box, sig, ct), [])[0]


def test_parse_box_sizes():
    assert wire.parse_box_sizes("1549") == (1549,)
    assert wire.parse_box_sizes("1549,400") == (1549, 400)
    assert wire.parse_box_sizes("0") == ()
    assert wire.parse_box_sizes("mesh,mixnet") == (256, 1549)
    assert wire.parse_box_sizes("mesh,1000") == (256, 1000)
    assert wire.parse_box_sizes(",".join(["100"] * wire.MAX_BOX_SIZES)) == (100,) * wire.MAX_BOX_SIZES
    for bad in ("0,400", "-1", "x", "", "Mesh", "1550", ",".join(["100"] * (wire.MAX_BOX_SIZES + 1))):
        with pytest.raises(ValueError):
            wire.parse_box_sizes(bad)


def test_every_replica_takes_the_mesh_and_mixnet_sizes():
    assert wire.ciphertext_sizes((MESH,)) == wire.ciphertext_sizes((MESH, BIG)) == (276, 1569)
    assert wire.ciphertext_sizes((1000, 100)) == (120, 276, 1020, 1569)
    assert wire.ciphertext_sizes(()) == ()


def test_ciphertext_sizes():
    assert len(seal(BIG)[2]) == 1569 and len(seal(MESH)[2]) == 276


def request(path, data):
    """A Link request's packed bytes, as RNS.Link.request makes them."""
    return umsgpack.packb([time.time(), RNS.Identity.truncated_hash(path.encode()), data])


def test_a_mesh_box_goes_in_one_link_packet():
    assert RNS.Link.MDU == 431 and MESH == 256
    piece = RNS.Link.MDU - 6 - channel.HEADER.size  # RNS Channel's envelope, then the frame head
    for size, fits in ((MESH, True), (MESH + 16, False)):
        box, sig, ct = seal(size)
        write = wire.encode_write(box, sig, ct)
        forward = wire.mixnet_id("x") + write
        assert (len(request("forward", forward)) <= RNS.Link.MDU) == fits
        assert len(channel.split(1, bytes([channel.PATH_OPS["forward"]]) + forward, piece)) == 1
        if fits:
            assert RNS.Link.MDU - len(request("write", write)) >= 16, "a client's write has headroom"
            assert len(channel.split(1, write, piece)) == 1
            reply = wire.encode_reply(wire.SUCCESS, sig, ct)
            assert len(umsgpack.packb([bytes(16), reply])) <= RNS.Link.MDU
            assert len(channel.split(1, reply, piece)) == 1


def test_both_profiles_are_stored_and_others_refused(tmp_path):
    e, logs = engine(tmp_path, (BIG, MESH))
    for size in (BIG, MESH):
        box, sig, ct = seal(size)
        assert write(e, box, sig, ct) == wire.SUCCESS
        assert e.store.get(box).payload == ct
    box, sig, ct = seal(999)
    assert write(e, box, sig, ct) == wire.INVALID_PAYLOAD
    assert e.store.get(box) is None
    assert logs == ["pigeonhole: box %s refused: ciphertext of 1019 bytes, this replica takes 276, 1569" % box.hex()[:16]]


def test_a_mesh_alone_refuses_the_mixnet_box(tmp_path):
    e, _ = engine(tmp_path, (MESH,))
    assert write(e, *seal(BIG)) == wire.INVALID_PAYLOAD
    assert write(e, *seal(MESH)) == wire.SUCCESS
    box, sig = position(WriteCap.generate(), 0).tombstone(PIGEONHOLE_CTX)
    assert write(e, box, sig, b"") == wire.SUCCESS, "a tombstone has no payload to size"


class StoringBridge:
    """A Katzenpost bridge socket keeping what it is written, as is."""

    def __init__(self):
        self.path = os.path.join(tempfile.mkdtemp(prefix="br"), "s")
        self.l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.l.bind(self.path)
        self.l.listen()
        self.boxes = {}
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
                q = wire.decode_query(wire.read_frame(c))
                if q.kind == wire.WRITE:
                    self.boxes[q.box_id] = (q.signature, q.ciphertext)
                    wire.write_frame(c, wire.encode_reply(wire.SUCCESS))
                elif q.box_id in self.boxes:
                    wire.write_frame(c, wire.encode_reply(wire.SUCCESS, *self.boxes[q.box_id]))
                else:
                    wire.write_frame(c, wire.encode_reply(wire.NOT_FOUND))
        except (OSError, EOFError, wire.WireError):
            c.close()


@pytest.mark.parametrize("sizes", [(MESH, BIG), ()], ids=["both", "any"])
def test_bridge_carries_either_size_unchanged(tmp_path, sizes):
    kp, e = StoringBridge(), engine(tmp_path, sizes, is_bridge=True)[0]
    sock = BridgeSocket(kp.path)
    sent = [seal(BIG, b"to the mixnet"), seal(MESH, b"to the mixnet")]
    for box, sig, ct in sent:
        assert write(e, box, sig, ct) == wire.SUCCESS
        assert e.store.queued(box) == {BRIDGE}
    e.forward_due([], lambda dst, b, s, c, o: sock.write(b, s, c))
    for box, sig, ct in sent:
        assert kp.boxes[box] == (sig, ct)
        assert MessageBoxIndex.verify_box(box, *kp.boxes[box][::-1])
        assert e.store.queued(box) == set()

    pulled = {}
    for size in (BIG, MESH):
        box, sig, ct = seal(size, b"from the mixnet")
        kp.boxes[box] = (sig, ct)
        pulled[box] = ct
    for box, ct in pulled.items():
        r = wire.decode_reply(e.handle_read(wire.encode_read(box), [], lambda d, b: None, bridge_read=sock.read))
        assert r.code == wire.SUCCESS and r.ciphertext == ct
        assert e.store.get(box).payload == ct
    sock.close()
    kp.l.close()


def test_mixed_sizes_in_one_store_and_across_replication(tmp_path):
    """Boxes of another mesh's size reach this one by replication; a replica
    stores and serves them beside its own, and refuses a size it does not list."""
    clock = [1000.0]
    a, b = (Engine(Store(str(tmp_path / (n + ".sqlite"))), d, b"I" + d, now=lambda: clock[0],
                   box_ciphertext_sizes=wire.ciphertext_sizes(sizes))
            for n, d, sizes in (("a", ME, (MESH, 1000)), ("b", R2, (MESH,))))
    a.heard(R2, b"I" + R2, False)
    b.heard(ME, b"I" + ME, False)
    eng, sender = {ME: a, R2: b}, {ME: R2, R2: ME}
    boxes = {size: seal(size) for size in (MESH, BIG, 1000)}
    for box, sig, ct in boxes.values():
        assert write(a, box, sig, ct) == wire.SUCCESS
    for box, sig, ct in boxes.values():
        r = wire.decode_reply(a.handle_peek(wire.encode_read(box)))
        assert (r.code, r.signature, r.ciphertext) == (wire.SUCCESS, sig, ct)

    def deliver(dst, box_id, s, c, o):
        return wire.decode_reply(eng[dst].handle_write(wire.encode_write(box_id, s, c), [], sender[dst], o)).code

    b.sync([ME], lambda dst, q: eng[dst].handle_sync(q, sender[dst]))
    a.sync([R2], lambda dst, q: eng[dst].handle_sync(q, sender[dst]))
    a.forward_due([R2], deliver)
    for size in (MESH, BIG):
        box, sig, ct = boxes[size]
        assert (b.store.get(box).signature, b.store.get(box).payload) == (sig, ct)
    assert b.store.get(boxes[1000][0]) is None, "1000 bytes is not on b's list"
    assert a.store.queued(boxes[1000][0]) == set(), "a refused box is not retried"



def test_mesh_is_pigeonhole_protocols_default():
    path = os.path.join(os.path.dirname(__file__), "..", "testdata", "pigeonhole_protocols_box_sizes.json")
    mesh = json.load(open(path))["mesh"]
    box, sig, ct = seal(MESH)
    assert (MESH, len(ct), len(wire.encode_write(box, sig, ct))) == (mesh["plaintext"], mesh["ciphertext"], mesh["write_query"])
