# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A client: picks the nearest replica it has heard announce, keeps a Link
to it, reads and writes boxes, and remembers tombstones it has seen. BACAP
streams come from hpqc."""

from __future__ import annotations

import struct
import threading
import time
from typing import Dict, Optional, Set, Tuple

import RNS
from hpqc.bacap.stateless import ReadCap, WriteCap

from . import APP_NAME, ASPECT, PIGEONHOLE_CTX, rnsio, wire

AEAD_OVERHEAD = 16


def pad(plaintext: bytes, box_plaintext_size: int) -> bytes:
    """The Katzenpost padding: a four byte length, the data, zeros."""
    if len(plaintext) > box_plaintext_size:
        raise ValueError("message of %d bytes exceeds the box size %d" % (len(plaintext), box_plaintext_size))
    body = struct.pack(">I", len(plaintext)) + plaintext
    return body + bytes(box_plaintext_size + 4 - len(body))


def unpad(padded: bytes) -> bytes:
    (n,) = struct.unpack(">I", padded[:4])
    return padded[4 : 4 + n]


def position(cap, index: int):
    """The index-th box of a stream, counted from the capability's first."""
    start = cap.start()
    return start.advance_to(start.index.idx_64 + index)


class Client:
    def __init__(self, configdir: Optional[str], box_plaintext_size: int, loglevel: int = RNS.LOG_NOTICE, mode: str = "request"):
        """mode "request" sends queries as Link requests (mode 1); "channel" as
        Channel frames (mode 2), only to replicas announcing it."""
        if mode not in ("request", "channel"):
            raise ValueError("mode must be request or channel")
        self.mode = mode
        # Reticulum is one per process and only starts on the main thread; a caller that started it there is reused.
        self.reticulum = RNS.Reticulum.get_instance() or RNS.Reticulum(configdir=configdir, loglevel=loglevel)
        self.box_plaintext_size = box_plaintext_size
        self.replicas: Dict[bytes, Tuple[bytes, bool]] = {}
        self.tombstones: Set[bytes] = set()
        self.channel_replicas: Set[bytes] = set()
        self.links = rnsio.Links()
        self._mu = threading.Lock()
        RNS.Transport.register_announce_handler(rnsio.AnnounceHandler(self._on_announce))
        self._recall_replicas()

    def _recall_replicas(self) -> None:
        """Replicas this Reticulum instance heard announce before, with the flags of their
        last announce, so a client need not wait for the next one; a path is asked for each."""
        with RNS.Identity.known_destinations_lock:
            known = [(d, e[2], e[3]) for d, e in RNS.Identity.known_destinations.items()]
        for dest, public_key, app_data in known:
            identity_hash = RNS.Identity.truncated_hash(public_key)
            if RNS.Destination.hash(identity_hash, APP_NAME, ASPECT) != dest:
                continue
            flags = app_data[0] if app_data else 0
            self._on_announce(dest, identity_hash, bool(flags & 1), bool(flags & 2))
            if not RNS.Transport.has_path(dest):
                RNS.Transport.request_path(dest)

    def _on_announce(self, dest: bytes, identity_hash: bytes, bridge: bool, channel: bool = False, _mixnet: bytes = b"") -> None:
        with self._mu:
            cur = self.replicas.get(dest)
            if cur is not None and cur[0] != identity_hash:
                return
            self.replicas[dest] = (identity_hash, bridge)
            if channel:
                self.channel_replicas.add(dest)
            else:
                self.channel_replicas.discard(dest)

    def wait_for_replica(self, timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.entry() is not None:
                return True
            time.sleep(0.05)
        return False

    def entry(self) -> Optional[bytes]:
        with self._mu:
            dests = list(self.channel_replicas if self.mode == "channel" else self.replicas)
        cands = rnsio.reachable(dests)
        if not cands:
            return None
        return min(cands, key=rnsio.hops)

    # ---- boxes ----

    def write_box(self, box_id: bytes, signature: bytes, ciphertext: bytes, dest: Optional[bytes] = None) -> Optional[int]:
        dest = dest or self.entry()
        if dest is None:
            return None
        raw = self._query(dest, "write", wire.encode_write(box_id, signature, ciphertext))
        return None if raw is None else raw[0]

    def read_box(self, box_id: bytes, dest: Optional[bytes] = None, path: str = "read") -> Optional[wire.Reply]:
        if box_id in self.tombstones:
            return wire.Reply(wire.TOMBSTONE)
        dest = dest or self.entry()
        if dest is None:
            return None
        raw = self._query(dest, path, wire.encode_read(box_id))
        if raw is None:
            return None
        try:
            r = wire.decode_reply(raw)
        except wire.WireError:
            return None
        if r.code == wire.TOMBSTONE:
            self.tombstones.add(box_id)
        return r

    def _query(self, dest: bytes, path: str, data: bytes) -> Optional[bytes]:
        if self.mode == "channel" and path != "peek":
            return self.links.channel_request(dest, data)
        return self.links.request(dest, path, data)

    # ---- streams ----

    def write_message(self, cap: WriteCap, index: int, text: bytes) -> Tuple[bytes, Optional[int]]:
        pos = position(cap, index)
        box_id, ciphertext, signature = pos.encrypt(PIGEONHOLE_CTX, pad(text, self.box_plaintext_size))
        return box_id, self.write_box(box_id, signature, ciphertext)

    def delete_message(self, cap: WriteCap, index: int) -> Tuple[bytes, Optional[int]]:
        pos = position(cap, index)
        box_id, signature = pos.tombstone(PIGEONHOLE_CTX)
        return box_id, self.write_box(box_id, signature, b"")

    def read_message(self, cap: ReadCap, index: int) -> Tuple[int, Optional[bytes]]:
        """Returns (code, text). Text is set only when the box was found."""
        pos = position(cap, index)
        box_id = pos.box_id(PIGEONHOLE_CTX)
        r = self.read_box(box_id)
        if r is None:
            return wire.INTERNAL_ERROR, None
        if r.code != wire.SUCCESS:
            return r.code, None
        return wire.SUCCESS, unpad(pos.open(PIGEONHOLE_CTX, box_id, r.ciphertext or b"", r.signature or b""))

    def close(self) -> None:
        self.links.close()
