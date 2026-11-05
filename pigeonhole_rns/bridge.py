# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The mesh side of a bridge: a client of the Katzenpost replica's bridge
socket on the same host, speaking the same read and write messages."""

from __future__ import annotations

import socket
import threading
from typing import List, Optional

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

    def close(self) -> None:
        with self._mu:
            idle, self._idle = self._idle, []
        for s in idle:
            s.close()
