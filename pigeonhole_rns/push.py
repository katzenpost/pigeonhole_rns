# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Push: a client on a Link subscribes to the Box IDs it waits for, and the
replica pushes each box down that Link when it stores it, from a client, a
replica or the bridge. The wire format is in the README, under Push."""

from __future__ import annotations

import struct
import threading
import time
from typing import Callable, Dict, Hashable, List, Sequence, Tuple

from . import wire

# Mode 2 ops, after the replica paths' 2 to 5, and the Link request paths.
SUBSCRIBE = 6
UNSUBSCRIBE = 7
# Box IDs one Link may wait for, and the longest a subscription lasts, in seconds.
LIMIT = 256
MAX_TTL = 3600


def encode_subscribe(ttl: int, box_ids: Sequence[bytes]) -> bytes:
    return struct.pack(">H", ttl) + b"".join(box_ids)


def decode_subscribe(data: bytes) -> Tuple[int, List[bytes]]:
    if len(data) < 2 or (len(data) - 2) % wire.BOX_ID_SIZE:
        raise wire.WireError("bad subscribe")
    (ttl,) = struct.unpack(">H", data[:2])
    return ttl, decode_ids(data[2:])


def decode_ids(data: bytes) -> List[bytes]:
    if len(data) % wire.BOX_ID_SIZE:
        raise wire.WireError("bad box id list")
    return [bytes(data[i : i + wire.BOX_ID_SIZE]) for i in range(0, len(data), wire.BOX_ID_SIZE)]


def encode_subscribe_reply(taken: int, ttl: int) -> bytes:
    return struct.pack(">BHH", wire.SUCCESS, taken, ttl)


def encode_push(box_id: bytes, reply: wire.Reply) -> bytes:
    return box_id + wire.encode_reply(reply.code, reply.signature, reply.ciphertext)


class Subscriptions:
    """Box IDs each Link waits for, each until its expiry. A push takes the
    Box ID off every Link waiting for it, since a box is written once."""

    def __init__(self, limit: int = LIMIT, max_ttl: int = MAX_TTL, now: Callable[[], float] = time.monotonic):
        self.limit, self.max_ttl, self.now = limit, max_ttl, now
        self._lock = threading.Lock()
        self._links: Dict[Hashable, Dict[bytes, float]] = {}

    def subscribe(self, link: Hashable, ttl: int, box_ids: Sequence[bytes]) -> Tuple[int, int]:
        """Subscribes box_ids in order until the Link waits for limit; one
        it already waits for is renewed. Returns how many were taken and
        the ttl granted: ttl capped at max_ttl, 0 asking for max_ttl."""
        ttl = min(ttl or self.max_ttl, self.max_ttl)
        with self._lock:
            now = self.now()
            subs = {b: t for b, t in self._links.get(link, {}).items() if t > now}
            taken = 0
            for b in box_ids:
                if b not in subs and len(subs) >= self.limit:
                    break
                subs[b] = now + ttl
                taken += 1
            self._links[link] = subs
            return taken, ttl

    def unsubscribe(self, link: Hashable, box_ids: Sequence[bytes]) -> None:
        """Drops box_ids from the Link, or every one when none are named."""
        with self._lock:
            subs = self._links.get(link, {})
            if not box_ids:
                subs.clear()
            for b in box_ids:
                subs.pop(b, None)

    def drop(self, link: Hashable) -> None:
        with self._lock:
            self._links.pop(link, None)

    def take(self, box_id: bytes) -> List[Hashable]:
        """The Links waiting for box_id, which no longer wait for it."""
        with self._lock:
            now = self.now()
            return [link for link, subs in self._links.items() if subs.pop(box_id, 0) > now]
