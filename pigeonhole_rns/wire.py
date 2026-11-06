# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Query and reply encodings, shared by Reticulum requests and the bridge
socket.

A query is one byte, zero for a read and one for a write, the 32 byte Box
ID, and for a write the 64 byte signature and the ciphertext; a tombstone has
an empty ciphertext. A reply is one result byte, a Pigeonhole replica error
code, and for a found box the signature and ciphertext.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

import RNS
from RNS.vendor import umsgpack

READ = 0
WRITE = 1

BOX_ID_SIZE = 32
SIGNATURE_SIZE = 64

# Pigeonhole replica error codes, as in pigeonhole/errors.go.
SUCCESS = 0
NOT_FOUND = 1
INVALID_BOX_ID = 2
INVALID_SIGNATURE = 3
DATABASE_FAILURE = 4
INVALID_PAYLOAD = 5
STORAGE_FULL = 6
INTERNAL_ERROR = 7
INVALID_EPOCH = 8
REPLICATION_FAILED = 9
ALREADY_EXISTS = 10
TOMBSTONE = 11

# A bridge announces the mixnet it serves as the first 16 bytes of the SHA-256
# of a name its operator gives, such as the mixnet's PKI identity; bridges
# with the same id serve one mixnet. A replica forwarding a box pulled from a
# mixnet prefixes the write with that id, on path `forward`.
MIXNET_ID_SIZE = 16


def mixnet_id(name: str) -> bytes:
    return hashlib.sha256(name.encode()).digest()[:MIXNET_ID_SIZE]


# Box payload profiles: a replica takes boxes of several plaintext sizes at
# once. A client length prefixes the plaintext (4 bytes) and pads it to one,
# and the AEAD adds a 16 byte tag; Box ID and signature sizes never change.
# The mixnet's is fixed by its Sphinx geometry. The mesh's is the largest
# multiple of 16, as pigeonhole_protocols writes by default, whose write, and a replica's forward of it, go in one Link packet at
# Reticulum's 500 byte MTU in either query mode: request mode frames a query
# as msgpack [timestamp, path hash, data], more than Channel mode's envelope
# (msgtype, sequence, length), frame head and path byte.
BOX_OVERHEAD = 4 + 16
BOX_PLAINTEXT_MIXNET = 1549
REQUEST_OVERHEAD = len(umsgpack.packb([0.0, bytes(16), bytes(300)])) - 300
CHANNEL_OVERHEAD = 6 + 4 + 1
FORWARD_HEAD = MIXNET_ID_SIZE + 1 + BOX_ID_SIZE + SIGNATURE_SIZE
BOX_PLAINTEXT_MESH = (RNS.Link.MDU - max(REQUEST_OVERHEAD, CHANNEL_OVERHEAD) - FORWARD_HEAD - BOX_OVERHEAD) // 16 * 16
BOX_PROFILES = {"mesh": BOX_PLAINTEXT_MESH, "mixnet": BOX_PLAINTEXT_MIXNET}
MAX_BOX_SIZES = 8


def parse_box_sizes(text: str) -> tuple:
    """Plaintext sizes from a comma separated list of profile names and
    sizes, at most MAX_BOX_SIZES and none over the mixnet's; 0 alone, an
    empty tuple, for any size."""
    sizes = tuple(BOX_PROFILES[n] if n in BOX_PROFILES else int(n) for n in text.split(","))
    if sizes == (0,):
        return ()
    if len(sizes) > MAX_BOX_SIZES or any(not 0 < n <= BOX_PLAINTEXT_MIXNET for n in sizes):
        raise ValueError("at most %d box sizes, each from 1 to %d, or 0 alone for any" % (MAX_BOX_SIZES, BOX_PLAINTEXT_MIXNET))
    return sizes


def ciphertext_sizes(plain) -> tuple:
    """The ciphertext sizes a replica takes for plaintext sizes: those, and
    always the mesh's and the mixnet's, since boxes of either can arrive
    through a bridge or replication. Empty, any size, for none."""
    if not plain:
        return ()
    return tuple(sorted({n + BOX_OVERHEAD for n in (*plain, BOX_PLAINTEXT_MESH, BOX_PLAINTEXT_MIXNET)}))


# Codes that mean the receiver holds the box after a write.
STORED_CODES = frozenset((SUCCESS, ALREADY_EXISTS))


class WireError(ValueError):
    pass


@dataclass(frozen=True)
class Query:
    kind: int
    box_id: bytes
    signature: Optional[bytes] = None
    ciphertext: Optional[bytes] = None


@dataclass(frozen=True)
class Reply:
    code: int
    signature: Optional[bytes] = None
    ciphertext: Optional[bytes] = None


def encode_read(box_id: bytes) -> bytes:
    _check_box_id(box_id)
    return bytes([READ]) + box_id


def encode_write(box_id: bytes, signature: bytes, ciphertext: bytes) -> bytes:
    _check_box_id(box_id)
    if len(signature) != SIGNATURE_SIZE:
        raise WireError("signature must be 64 bytes")
    return bytes([WRITE]) + box_id + signature + ciphertext


def decode_query(data: bytes) -> Query:
    if len(data) < 1 + BOX_ID_SIZE:
        raise WireError("query too short")
    kind = data[0]
    box_id = bytes(data[1 : 1 + BOX_ID_SIZE])
    if kind == READ:
        if len(data) != 1 + BOX_ID_SIZE:
            raise WireError("read carries trailing bytes")
        return Query(READ, box_id)
    if kind == WRITE:
        rest = data[1 + BOX_ID_SIZE :]
        if len(rest) < SIGNATURE_SIZE:
            raise WireError("write lacks a signature")
        return Query(WRITE, box_id, bytes(rest[:SIGNATURE_SIZE]), bytes(rest[SIGNATURE_SIZE:]))
    raise WireError("unknown query type %d" % kind)


def encode_reply(code: int, signature: Optional[bytes] = None, ciphertext: Optional[bytes] = None) -> bytes:
    out = bytes([code])
    if code == SUCCESS and signature is not None:
        out += signature + (ciphertext or b"")
    return out


def decode_reply(data: bytes) -> Reply:
    if len(data) < 1:
        raise WireError("empty reply")
    code = data[0]
    if code == SUCCESS and len(data) > 1:
        rest = data[1:]
        if len(rest) < SIGNATURE_SIZE:
            raise WireError("found reply lacks a signature")
        return Reply(code, bytes(rest[:SIGNATURE_SIZE]), bytes(rest[SIGNATURE_SIZE:]))
    return Reply(code)


# A sync page is a head, two 32 byte Box IDs for a query (the range it
# covers, exclusive below, inclusive above) or one for a reply (where the
# reply's page ends), then up to SYNC_PAGE entries of a Box ID and a byte, 1
# for a tombstone.

SYNC_PAGE = 128


def encode_sync(head: bytes, entries) -> bytes:
    return head + b"".join(box_id + bytes([tomb]) for box_id, tomb in entries)


def decode_sync(data: bytes, head_len: int):
    body, step = data[head_len:], BOX_ID_SIZE + 1
    if len(data) < head_len or len(body) % step or len(body) // step > SYNC_PAGE:
        raise WireError("bad sync page")
    return bytes(data[:head_len]), [(bytes(body[i : i + BOX_ID_SIZE]), body[i + BOX_ID_SIZE] == 1) for i in range(0, len(body), step)]


# The bridge socket carries each message as a big endian u32 length prefix
# followed by the payload.

MAX_FRAME = 1 << 20


def write_frame(sock, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def read_frame(sock) -> bytes:
    hdr = _read_exact(sock, 4)
    (n,) = struct.unpack(">I", hdr)
    if n == 0 or n > MAX_FRAME:
        raise WireError("frame length %d out of range" % n)
    return _read_exact(sock, n)


def _read_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    return bytes(buf)


def _check_box_id(box_id: bytes) -> None:
    if len(box_id) != BOX_ID_SIZE:
        raise WireError("box id must be 32 bytes")
