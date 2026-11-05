# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Reticulum plumbing shared by the replica and the client: reaching a
replica destination, keeping a Link to it, and making a request on it."""

from __future__ import annotations

import threading
from typing import Dict, Optional

import RNS

from . import APP_NAME, ASPECT, ASPECT_FILTER, channel, wire


class AnnounceHandler:
    """Feeds replica announces to a callback (dest_hash, identity_hash, bridge,
    channel, mixnet, flags). App data is a flags byte, bit 0 bridge,
    bit 1 serves query mode 2, bit 2 serves the replica paths in mode 2 too and
    bit 3 serves no Link requests and bit 4 serves push, then for a bridge the id of its mixnet; a
    bridge announcing none serves the mixnet named by the empty string."""

    aspect_filter = ASPECT_FILTER

    def __init__(self, on_replica):
        self.on_replica = on_replica

    def received_announce(self, destination_hash, announced_identity, app_data):
        flags = app_data[0] if app_data else 0
        mixnet = b""
        if flags & 1:
            mixnet = bytes(app_data[1 : 1 + wire.MIXNET_ID_SIZE])
            if len(mixnet) != wire.MIXNET_ID_SIZE:
                mixnet = wire.mixnet_id("")
        self.on_replica(bytes(destination_hash), bytes(announced_identity.hash), bool(flags & 1), bool(flags & 2), mixnet, flags)


def reachable(dests) -> list:
    return [d for d in dests if RNS.Transport.has_path(d)]


def hops(dest: bytes) -> int:
    h = RNS.Transport.hops_to(dest)
    return 1 << 30 if h is None else h


class Links:
    """One Link per replica destination, opened on demand and reopened when
    lost. Callers on several threads have up to window queries in flight
    per Link at once, under a replica's per Link queue in mode 2; the Link
    API carries payloads over the MDU as Resources by itself."""

    def __init__(self, establish_timeout: float = 20.0, request_timeout: float = 60.0, identity: Optional[RNS.Identity] = None, window: int = 8,
                 prefer_channel: bool = False, on_push=None):
        """on_push(endpoint, bytes) gets each push on a Link this opened, in mode 2."""
        self.identity = identity
        self.on_push = on_push
        self.window = window
        self.establish_timeout = establish_timeout
        self.request_timeout = request_timeout
        self._links: Dict[bytes, RNS.Link] = {}
        self._locks: Dict[bytes, threading.Lock] = {}
        self._windows: Dict[bytes, threading.BoundedSemaphore] = {}
        self._mu = threading.Lock()
        self._endpoints: Dict[bytes, channel.Endpoint] = {}
        self._replies: Dict[int, list] = {}
        self._next_id = 0
        # Each replica's announce flags, and whether request() asks in mode 2 those serving it.
        self.flags: Dict[bytes, int] = {}
        self.prefer_channel = prefer_channel

    def _lock(self, dest: bytes) -> threading.Lock:
        with self._mu:
            return self._locks.setdefault(dest, threading.Lock())

    def _window(self, dest: bytes) -> threading.BoundedSemaphore:
        with self._mu:
            return self._windows.setdefault(dest, threading.BoundedSemaphore(self.window))

    def _open(self, dest: bytes) -> Optional[RNS.Link]:
        with self._lock(dest):
            return self._link(dest)

    def _link(self, dest: bytes) -> Optional[RNS.Link]:
        with self._mu:
            link = self._links.get(dest)
        if link is not None and link.status == RNS.Link.ACTIVE:
            return link
        identity = RNS.Identity.recall(dest)
        if identity is None:
            RNS.Transport.await_path(dest, self.establish_timeout)
            identity = RNS.Identity.recall(dest)
            if identity is None:
                return None
        destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, ASPECT)
        settled = threading.Event()
        link = RNS.Link(destination, established_callback=lambda _l: settled.set(), closed_callback=lambda _l: settled.set())
        settled.wait(self.establish_timeout)
        if link.status != RNS.Link.ACTIVE:
            link.teardown()
            return None
        if self.identity is not None:
            link.identify(self.identity)
        with self._mu:
            self._links[dest] = link
        return link

    def request(self, dest: bytes, path: str, data: bytes) -> Optional[bytes]:
        """Returns the reply bytes, or None when the replica did not answer. Asks in mode 2
        first when preferring it and the replica serves the path there (announce bit 1 for a
        read or write, bit 2 for a replica path), and as a Link request when mode 2 fails;
        a replica serving no Link requests (bit 3) only in mode 2."""
        flags = self.flags.get(dest, 0)
        op = channel.PATH_OPS.get(path)
        if flags & 8 or (self.prefer_channel and flags & (2 if op is None else 4)):
            raw = self.channel_request(dest, data if op is None else bytes([op]) + data)
            # No Link at all is no reason to try a request, which needs one too.
            if raw is not None or flags & 8 or not self._active(dest):
                return raw
        return self._request(dest, path, data)

    def _active(self, dest: bytes) -> bool:
        with self._mu:
            link = self._links.get(dest)
        return link is not None and link.status == RNS.Link.ACTIVE

    def _request(self, dest: bytes, path: str, data: bytes) -> Optional[bytes]:
        with self._window(dest):
            link = self._open(dest)
            if link is None:
                return None
            done = threading.Event()
            receipt = link.request(path, data, response_callback=lambda _r: done.set(), failed_callback=lambda _r: done.set(), timeout=self.request_timeout)
            if receipt is False or receipt is None:
                return None
            done.wait(self.request_timeout)
            if receipt.status != RNS.RequestReceipt.READY:
                return None
            resp = receipt.response
            return bytes(resp) if resp is not None else None

    def channel_request(self, dest: bytes, data: bytes) -> Optional[bytes]:
        """Query mode 2: the same bytes as request(), as Channel frames."""
        with self._window(dest):
            link = self._open(dest)
            if link is None:
                return None
            with self._mu:
                ep = self._endpoints.get(link.link_id)
                if ep is None:
                    self._endpoints = {k: e for k, e in self._endpoints.items() if e.link.status != RNS.Link.CLOSED}
                    ep = self._endpoints[link.link_id] = channel.Endpoint(link, self._on_reply, self.on_push)
                rid = self._next_id
                self._next_id = (rid + 1) & 0xFFFF
                slot = self._replies[rid] = [threading.Event(), None]
            try:
                if not ep.send(rid, data, self.request_timeout) or not slot[0].wait(self.request_timeout):
                    return None
                return slot[1]
            finally:
                with self._mu:
                    self._replies.pop(rid, None)

    def _on_reply(self, _ep, request_id: int, data: bytes) -> None:
        with self._mu:
            slot = self._replies.get(request_id)
        if slot is not None:
            slot[1] = data
            slot[0].set()

    def peek(self, dest: bytes, box_id: bytes) -> Optional[wire.Reply]:
        raw = self.request(dest, "peek", wire.encode_read(box_id))
        if raw is None:
            return None
        try:
            return wire.decode_reply(raw)
        except wire.WireError:
            return None

    def close(self) -> None:
        with self._mu:
            links = list(self._links.values())
            self._links.clear()
            self._endpoints.clear()
        for link in links:
            try:
                link.teardown()
            except Exception:
                pass
