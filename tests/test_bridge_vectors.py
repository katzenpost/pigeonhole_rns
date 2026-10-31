# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The bridge socket vectors shared with the Katzenpost replica: the Go side
keeps a copy in replica/testdata and its test reads the same file."""

import json
import pathlib
import struct

import pytest

from pigeonhole_rns import wire

VECTORS = json.loads((pathlib.Path(__file__).parent.parent / "testdata" / "bridge_socket_vectors.json").read_text())


def frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


@pytest.mark.parametrize("v", VECTORS["queries"], ids=lambda v: v["name"])
def test_query(v):
    box_id = bytes.fromhex(v["box_id"])
    if v["kind"] == wire.READ:
        payload = wire.encode_read(box_id)
    else:
        payload = wire.encode_write(box_id, bytes.fromhex(v["signature"]), bytes.fromhex(v["ciphertext"]))
    assert payload.hex() == v["payload"]
    assert frame(payload).hex() == v["frame"]
    q = wire.decode_query(payload)
    assert (q.kind, q.box_id) == (v["kind"], box_id)
    if v["kind"] == wire.WRITE:
        assert (q.signature.hex(), q.ciphertext.hex()) == (v["signature"], v["ciphertext"])


@pytest.mark.parametrize("v", VECTORS["replies"], ids=lambda v: v["name"])
def test_reply(v):
    sig = bytes.fromhex(v["signature"]) if "signature" in v else None
    ct = bytes.fromhex(v["ciphertext"]) if "ciphertext" in v else None
    payload = wire.encode_reply(v["code"], sig, ct)
    assert payload.hex() == v["payload"]
    assert frame(payload).hex() == v["frame"]
    r = wire.decode_reply(payload)
    assert r.code == v["code"]
    assert (r.signature, r.ciphertext) == ((sig, ct) if sig is not None else (None, None))


@pytest.mark.parametrize("v", VECTORS["malformed"], ids=lambda v: v["name"])
def test_malformed(v):
    with pytest.raises(wire.WireError):
        wire.decode_query(bytes.fromhex(v["payload"]))


@pytest.mark.parametrize("v", VECTORS["boxes"], ids=lambda v: v["name"])
def test_box(v, tmp_path):
    """What a replica answers a write with: the engine's verification, the
    same rule the Katzenpost replica applies to a box the bridge pushes."""
    from pigeonhole_rns.engine import Engine
    from pigeonhole_rns.store import Store

    e = Engine(Store(str(tmp_path / "v.sqlite")), b"\x01" * 16, b"\x02" * 32, box_ciphertext_size=v["ciphertext_size"])
    q = wire.Query(wire.WRITE, bytes.fromhex(v["box_id"]), bytes.fromhex(v["signature"]), bytes.fromhex(v["ciphertext"]))
    assert e.verify(q) == v["expect"]
