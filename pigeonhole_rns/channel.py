# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Query mode 2: queries and replies as Channel messages on a Link, for
Reticulum stacks without Link requests or Resources.

Every message is one Frame of MSGTYPE 0x5048: a request id (u16, big
endian), the piece index (u8), the piece count (u8), then that piece of the
query or reply bytes of wire.py. A message is cut into at most 255 pieces of
at most Channel MDU minus 4 bytes. A reply carries its query's request id.

A message's first byte picks what it asks: 0 and 1 are a read and a write
query, as they begin; PATH_OPS are the replica to replica paths, followed by
that path's request bytes, and answered with that path's response bytes."""

from __future__ import annotations

import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

import RNS
from RNS.Channel import MessageBase

MSGTYPE = 0x5048
HEADER = struct.Struct(">HBB")
MAX_PIECES = 255
PATH_OPS = {"peek": 2, "sync": 3, "forward": 4, "pushed": 5}
REASSEMBLY_TIMEOUT = 60.0


class Frame(MessageBase):
    MSGTYPE = MSGTYPE

    def __init__(self, request_id: int = 0, index: int = 0, count: int = 1, data: bytes = b""):
        self.request_id, self.index, self.count, self.data = request_id, index, count, data

    def pack(self) -> bytes:
        return HEADER.pack(self.request_id, self.index, self.count) + self.data

    def unpack(self, raw: bytes) -> None:
        if len(raw) < HEADER.size:
            raise ValueError("frame too short")
        self.request_id, self.index, self.count = HEADER.unpack(raw[: HEADER.size])
        self.data = bytes(raw[HEADER.size :])


class PushFrame(Frame):
    """A piece of a push, framed as a query's; its request id is the replica's own."""

    MSGTYPE = 0x5049


def split(request_id: int, data: bytes, piece_size: int, cls=Frame) -> List[Frame]:
    if piece_size < 1:
        raise ValueError("piece size %d" % piece_size)
    count = max(1, -(-len(data) // piece_size))
    if count > MAX_PIECES:
        raise ValueError("%d bytes need %d pieces of %d" % (len(data), count, piece_size))
    return [cls(request_id, i, count, data[i * piece_size : (i + 1) * piece_size]) for i in range(count)]


class Reassembler:
    """Collects pieces by request id. A piece whose count differs from the
    request's first piece, or whose index is out of range, drops the request."""

    def __init__(self, timeout: float = REASSEMBLY_TIMEOUT, now: Callable[[], float] = time.monotonic):
        self.timeout = timeout
        self.now = now
        self._pending: Dict[int, Tuple[float, int, Dict[int, bytes]]] = {}

    def feed(self, f: Frame) -> Optional[bytes]:
        now = self.now()
        self._pending = {k: v for k, v in self._pending.items() if now - v[0] < self.timeout}
        if f.count == 0 or f.index >= f.count:
            self._pending.pop(f.request_id, None)
            return None
        started, count, pieces = self._pending.setdefault(f.request_id, (now, f.count, {}))
        if count != f.count:
            del self._pending[f.request_id]
            return None
        pieces.setdefault(f.index, f.data)
        if len(pieces) < count:
            return None
        del self._pending[f.request_id]
        return b"".join(pieces[i] for i in range(count))

    def __len__(self) -> int:
        return len(self._pending)


class Endpoint:
    """Mode 2 on one Link: calls on_message(endpoint, request_id, bytes) on Reticulum's
    thread for each reassembled message, and on_push(endpoint, bytes) for each push when
    given, and sends messages as frames."""

    def __init__(self, link: "RNS.Link", on_message: Callable[["Endpoint", int, bytes], None],
                 on_push: Optional[Callable[["Endpoint", bytes], None]] = None):
        self.link = link
        self.channel = link.get_channel()
        self.on_message = on_message
        self.on_push = on_push
        self.reassembler = Reassembler()
        self.pushes = Reassembler()
        self._send_lock = threading.Lock()
        self.channel.register_message_type(Frame)
        if on_push is not None:
            self.channel.register_message_type(PushFrame)
        self.channel.add_message_handler(self._on_frame)

    def _on_frame(self, msg) -> bool:
        if isinstance(msg, PushFrame):
            data = self.pushes.feed(msg)
            if data is not None and self.on_push is not None:
                self.on_push(self, data)
            return True
        if not isinstance(msg, Frame):
            return False
        data = self.reassembler.feed(msg)
        if data is not None:
            self.on_message(self, msg.request_id, data)
        return True

    def piece_size(self) -> int:
        return self.channel.mdu - HEADER.size

    def send(self, request_id: int, data: bytes, timeout: float = 60.0, cls=Frame) -> bool:
        """Sends every frame, waiting for the Channel window. Not on Reticulum's
        thread: delivery proofs that open the window arrive there."""
        frames = split(request_id, data, self.piece_size(), cls)
        deadline = time.time() + timeout
        with self._send_lock:
            try:
                for f in frames:
                    while not self.channel.is_ready_to_send():
                        if self.link.status == RNS.Link.CLOSED or time.time() > deadline:
                            return False
                        time.sleep(0.01)
                    self.channel.send(f)
            except Exception as e:
                # Once Transport culls a receipt still in the TX ring, RNS raises here on every
                # call; a new Link starts with a clean Channel (pigeonhole_rns/quint).
                RNS.log("pigeonhole: channel send: %s, closing the link" % e, RNS.LOG_WARNING)
                self.link.teardown()
                return False
        return True
