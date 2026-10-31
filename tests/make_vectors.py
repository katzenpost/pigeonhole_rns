# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Write testdata/bridge_socket_vectors.json: the bridge socket's framing,
the reply codes, and what a replica decides about a box. The Katzenpost
replica keeps a copy in replica/testdata and tests it with the same file.

    python tests/make_vectors.py

The key material comes from a fixed seed, so the file regenerates the same
but for the AEAD, whose nonce is random; a regenerated file is a new file to
copy to both repositories.
"""

import hashlib
import json
import pathlib
import struct

from hpqc.bacap.stateless import WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, wire
from pigeonhole_rns.client import pad

OUT = pathlib.Path(__file__).parent.parent / "testdata" / "bridge_socket_vectors.json"
PLAINTEXT_SIZE = 100
CIPHERTEXT_SIZE = PLAINTEXT_SIZE + 4 + 16  # length prefix, AEAD tag


def seeded_rng(seed: bytes):
    counter = [0]

    def rng(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + struct.pack(">I", counter[0])).digest()
            counter[0] += 1
        return out[:n]

    return rng


def frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def flip(data: bytes, at: int) -> bytes:
    b = bytearray(data)
    b[at] ^= 0x01
    return bytes(b)


def main() -> None:
    box = bytes(range(1, 33))
    sig = bytes([0xA0 + i % 16 for i in range(64)])
    ct = b"a sealed box of some fixed size, 40 bytes"
    v = {
        "description": "Bridge socket between a Katzenpost replica and a Pigeonhole mesh replica: "
        "each message is a big endian u32 length then the payload. Queries: READ=0 | box_id(32); "
        "WRITE=1 | box_id(32) | signature(64) | ciphertext (empty for a tombstone). Replies: code(1) "
        "and, for a found box, signature(64) | ciphertext. Boxes: what a replica answers a write "
        "with, given the box ciphertext size.",
        "queries": [],
        "replies": [],
        "malformed": [],
        "boxes": [],
    }
    for name, payload, fields in [
        ("read", wire.encode_read(box), {"kind": wire.READ, "box_id": box.hex()}),
        ("write", wire.encode_write(box, sig, ct), {"kind": wire.WRITE, "box_id": box.hex(), "signature": sig.hex(), "ciphertext": ct.hex()}),
        ("tombstone", wire.encode_write(box, sig, b""), {"kind": wire.WRITE, "box_id": box.hex(), "signature": sig.hex(), "ciphertext": ""}),
    ]:
        v["queries"].append({"name": name, **fields, "payload": payload.hex(), "frame": frame(payload).hex()})
    for name, code, s, c in [
        ("found", wire.SUCCESS, sig, ct),
        ("stored", wire.SUCCESS, None, None),
        ("not_found", wire.NOT_FOUND, None, None),
        ("tombstone", wire.TOMBSTONE, None, None),
        ("already_exists", wire.ALREADY_EXISTS, None, None),
        ("invalid_payload", wire.INVALID_PAYLOAD, None, None),
    ]:
        payload = wire.encode_reply(code, s, c)
        e = {"name": name, "code": code, "payload": payload.hex(), "frame": frame(payload).hex()}
        if s is not None:
            e["signature"], e["ciphertext"] = s.hex(), c.hex()
        v["replies"].append(e)
    v["malformed"] = [
        {"name": "read_short", "payload": (bytes([wire.READ]) + box[:31]).hex()},
        {"name": "read_trailing", "payload": (bytes([wire.READ]) + box + b"x").hex()},
        {"name": "write_no_signature", "payload": (bytes([wire.WRITE]) + box + sig[:63]).hex()},
        {"name": "unknown_kind", "payload": (bytes([7]) + box).hex()},
    ]

    cap = WriteCap.generate(seeded_rng(b"pigeonhole bridge vectors"))
    pos = cap.start()
    box_id, ciphertext, signature = pos.encrypt(PIGEONHOLE_CTX, pad(b"a box for the bridge", PLAINTEXT_SIZE))
    assert len(ciphertext) == CIPHERTEXT_SIZE
    t_box_id, t_signature = pos.next().tombstone(PIGEONHOLE_CTX)
    # Any 32 bytes parse as an Ed25519 key on both sides; a Box ID that is no
    # key fails as a signature does. INVALID_BOX_ID is for a malformed length,
    # which the framing refuses first.
    not_a_key = bytes([0xFF]) * 32
    for name, b, s, c, expect in [
        ("valid", box_id, signature, ciphertext, wire.SUCCESS),
        ("tombstone", t_box_id, t_signature, b"", wire.SUCCESS),
        ("bad_signature", box_id, flip(signature, 0), ciphertext, wire.INVALID_SIGNATURE),
        ("tampered_ciphertext", box_id, signature, flip(ciphertext, 7), wire.INVALID_SIGNATURE),
        ("not_a_key", not_a_key, signature, ciphertext, wire.INVALID_SIGNATURE),
        ("wrong_size", box_id, signature, ciphertext[:-1], wire.INVALID_PAYLOAD),
    ]:
        v["boxes"].append({"name": name, "ciphertext_size": CIPHERTEXT_SIZE, "box_id": b.hex(), "signature": s.hex(), "ciphertext": c.hex(), "expect": expect})
    OUT.write_text(json.dumps(v, indent=1) + "\n")
    print("wrote", OUT, len(v["boxes"]), "boxes")


if __name__ == "__main__":
    main()
