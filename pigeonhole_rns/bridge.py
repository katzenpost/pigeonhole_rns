# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The mesh side of a bridge: a client of the Katzenpost replica's bridge
socket on the same host, speaking the same read and write messages, and
subscribed to the boxes it stores."""

from __future__ import annotations

import socket
import threading
from typing import Callable, List, Optional

from . import wire


class BridgeSocket:
    """Up to conns connections, each carrying one query at a time, so a slow
    read proxied to other shards does not hold up the rest. The Katzenpost
    replica serves each connection on its own goroutine."""

    def __init__(self, path: str, timeout: float = 120.0, conns: int = 8):
        self.path = path
        self.timeout = timeout
        self._idle: List[socket.socket] = []
        self._slots = threading.BoundedSemaphore(conns)
        self._mu = threading.Lock()
        self._stream: Optional[socket.socket] = None

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.path)
        except OSError:
            s.close()
            raise
        return s

    def _exchange(self, payload: bytes) -> Optional[bytes]:
        with self._slots:
            with self._mu:
                s = self._idle.pop() if self._idle else None
            # An idle connection the replica has closed fails once; then a new one is tried.
            for reused in ((True, False) if s is not None else (False,)):
                try:
                    if s is None:
                        s = self._connect()
                    wire.write_frame(s, payload)
                    raw = wire.read_frame(s)
                except (OSError, EOFError, wire.WireError) as e:
                    if s is not None:
                        s.close()
                        s = None
                    if reused and not isinstance(e, socket.timeout):
                        continue
                    return None
                with self._mu:
                    self._idle.append(s)
                return raw
            return None

    def write(self, box_id: bytes, signature: bytes, ciphertext: bytes) -> Optional[int]:
        raw = self._exchange(wire.encode_write(box_id, signature, ciphertext))
        return None if raw is None else raw[0]

    def read(self, box_id: bytes) -> Optional[wire.Reply]:
        raw = self._exchange(wire.encode_read(box_id))
        if raw is None:
            return None
        try:
            return wire.decode_reply(raw)
        except wire.WireError:
            return None

    def stream(self, since_epoch: int, on_announce: Callable[[int, wire.Query], None]) -> None:
        """Subscribes on a connection of its own and calls on_announce with
        the replica epoch and box of each announce, every box stored in a
        kept epoch from since_epoch then each newly stored, until the stream
        ends with OSError, EOFError or WireError."""
        s = self._connect()
        s.settimeout(None)  # quiet while nothing is stored
        with self._mu:
            self._stream = s
        try:
            wire.write_frame(s, wire.encode_subscribe(since_epoch))
            while True:
                raw = wire.read_frame(s)
                try:
                    epoch, q = wire.decode_announce(raw)
                except wire.WireError:
                    continue
                on_announce(epoch, q)
        finally:
            with self._mu:
                self._stream = None
            s.close()

    def close(self) -> None:
        with self._mu:
            idle, self._idle = self._idle, []
            stream = self._stream
        for s in idle:
            s.close()
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
