# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica daemon: one Reticulum destination with request paths `write`
and `read` for clients and `peek`, `sync`, `forward` and `pushed` for other
replicas, the same queries and paths as Channel frames (mode 2), which it
asks other replicas in first, and threads for forwarding,
handoff, garbage collection and announcing."""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Optional

import RNS

from . import APP_NAME, ASPECT, channel, engine, rnsio, wire
from .bridge import BridgeSocket
from .store import Store



# Channel mode's limits: workers per Link, queries waiting per Link, and handlers running at once
# across the replica. Request mode handles one request at a time per Link.
CHANNEL_WORKERS = 2
CHANNEL_QUEUE = 16
CHANNEL_HANDLERS = 32

class Replica:
    def __init__(
        self,
        configdir: Optional[str],
        storage_dir: str,
        box_plaintext_size: int,
        bridge_socket: Optional[str] = None,
        announce_interval: float = 600.0,
        forward_interval: float = 2.0,
        handoff_interval: float = 30.0,
        mixnet: str = "",
        forward: str = engine.ALL,
        loglevel: int = RNS.LOG_NOTICE,
        epoch_period: float = engine.EPOCH_PERIOD,
        replica_epoch_epochs: int = engine.REPLICA_EPOCH_EPOCHS,
        max_storage_mib: int = 0,
        min_free_storage_mib: int = 500,
    ):
        os.makedirs(storage_dir, exist_ok=True)
        self.reticulum = RNS.Reticulum(configdir=configdir, loglevel=loglevel)
        identity_path = os.path.join(storage_dir, "identity")
        if os.path.exists(identity_path):
            self.identity = RNS.Identity.from_file(identity_path)
        else:
            self.identity = RNS.Identity()
            self.identity.to_file(identity_path)

        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT)
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.register_request_handler("write", response_generator=self._on_write, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("read", response_generator=self._on_read, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("peek", response_generator=self._on_peek, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("sync", response_generator=self._on_sync, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("forward", response_generator=self._on_forward, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("pushed", response_generator=self._on_pushed, allow=RNS.Destination.ALLOW_ALL)
        self.destination.set_link_established_callback(self._on_link)

        self.bridge = BridgeSocket(bridge_socket) if bridge_socket else None
        # Forwards keep a connection of their own, so reads filling the pool cannot delay them.
        self._bridge_writes = BridgeSocket(bridge_socket, conns=1) if bridge_socket else None
        # Box plaintext is length prefixed by the client and the AEAD adds a
        # tag. A size of zero accepts any, for a bridge that defers to the
        # mixnet replica's geometry check.
        ciphertext_size = box_plaintext_size + 4 + 16 if box_plaintext_size > 0 else None
        self.engine = engine.Engine(
            Store(os.path.join(storage_dir, "boxes.sqlite"), max_storage_mib << 20, min_free_storage_mib << 20),
            bytes(self.destination.hash),
            bytes(self.identity.hash),
            box_ciphertext_size=ciphertext_size,
            is_bridge=self.bridge is not None,
            mixnet=wire.mixnet_id(mixnet),
            forward=forward,
            epoch_seconds=epoch_period * replica_epoch_epochs,
        )
        if self.bridge is not None and self.engine.epoch_seconds != engine.EPOCH_SECONDS:
            RNS.log("pigeonhole: replica epoch %ds differs from Katzenpost's %ds; bridged boxes expire out of step"
                    % (self.engine.epoch_seconds, engine.EPOCH_SECONDS), RNS.LOG_WARNING)
        # Links identify, so a replica can tell a forward's sender and not send the box back.
        self.links = rnsio.Links(identity=self.identity, prefer_channel=True)
        self.announce_interval = announce_interval
        self.forward_interval = forward_interval
        self.handoff_interval = handoff_interval
        self._stop = threading.Event()
        # Set when a write, forward or sync may have queued forwards, so they go now and not on the next tick.
        self._kick = threading.Event()
        self._channel_handlers = threading.BoundedSemaphore(CHANNEL_HANDLERS)
        RNS.Transport.register_announce_handler(rnsio.AnnounceHandler(self._on_announce))

    # ---- announces ----

    def _on_announce(self, dest: bytes, identity_hash: bytes, bridge: bool, _channel: bool = False, mixnet: bytes = b"", flags: int = 0) -> None:
        if dest == self.engine.self_dest:
            return
        if self.engine.heard(dest, identity_hash, bridge, mixnet):
            self.links.flags[dest] = flags
            RNS.log("pigeonhole: replica %s%s" % (RNS.prettyhexrep(dest), " (bridge)" if bridge else ""), RNS.LOG_DEBUG)
        else:
            RNS.log("pigeonhole: ignoring announce with a changed key for %s" % RNS.prettyhexrep(dest), RNS.LOG_WARNING)

    def announce(self) -> None:
        self.destination.announce(app_data=bytes([(1 if self.bridge else 0) | 2 | 4]) + self.engine.mixnet)

    # ---- request handlers, called on Reticulum's threads ----

    def _reachable(self) -> list:
        return rnsio.reachable(d for d in self.engine.peers if d != self.engine.self_dest)

    def _sender(self, remote_identity) -> Optional[bytes]:
        return None if remote_identity is None else self.engine.peer_of(bytes(remote_identity.hash))

    def _on_write(self, path, data, request_id, link_id, remote_identity, requested_at):
        reply = self.engine.handle_write(bytes(data), self._reachable(), self._sender(remote_identity))
        self._kick.set()
        return reply

    def _on_sync(self, path, data, request_id, link_id, remote_identity, requested_at):
        reply = self.engine.handle_sync(bytes(data), self._sender(remote_identity))
        self._kick.set()
        return reply

    def _on_forward(self, path, data, request_id, link_id, remote_identity, requested_at):
        reply = self.engine.handle_forward(bytes(data), self._reachable(), self._sender(remote_identity))
        self._kick.set()
        return reply

    def _on_pushed(self, path, data, request_id, link_id, remote_identity, requested_at):
        return self.engine.handle_pushed(bytes(data))

    def _on_peek(self, path, data, request_id, link_id, remote_identity, requested_at):
        return self.engine.handle_peek(bytes(data), self._bridge_read(), self._reachable())

    def _on_read(self, path, data, request_id, link_id, remote_identity, requested_at):
        return self.engine.handle_read(bytes(data), self._reachable(), self.links.peek, self._bridge_read())

    def _on_link(self, link) -> None:
        # Handlers may block on peeks and on the reply's Channel window, so they run on worker
        # threads, not Reticulum's: CHANNEL_WORKERS per Link, taking queries from a queue of
        # CHANNEL_QUEUE, and at most CHANNEL_HANDLERS handling at once across the replica.
        # A query arriving to a full queue is dropped; its client times out and asks again.
        queries: "queue.Queue" = queue.Queue(maxsize=CHANNEL_QUEUE)

        def accept(ep, rid, data):
            try:
                queries.put_nowait((ep, rid, data))
            except queue.Full:
                RNS.log("pigeonhole: channel queue full on a link, query dropped", RNS.LOG_WARNING)

        def work():
            while not self._stop.is_set():
                try:
                    ep, rid, data = queries.get(timeout=1)
                except queue.Empty:
                    if link.status == RNS.Link.CLOSED:
                        return
                    continue
                with self._channel_handlers:
                    self._on_frame_query(ep, rid, data)

        channel.Endpoint(link, accept)
        for _ in range(CHANNEL_WORKERS):
            threading.Thread(target=work, daemon=True).start()

    def _on_frame_query(self, ep: channel.Endpoint, request_id: int, data: bytes) -> None:
        """Mode 2: the message's first byte picks the handler, a read or a write query or
        a replica path, whose sender is the replica the Link identified as."""
        op, sender = data[:1], self._sender(ep.link.get_remote_identity())
        if op == bytes([wire.READ]):
            reply = self.engine.handle_read(data, self._reachable(), self.links.peek, self._bridge_read())
        elif op == bytes([wire.WRITE]):
            reply = self.engine.handle_write(data, self._reachable(), sender)
        elif op == bytes([channel.PATH_OPS["peek"]]):
            reply = self.engine.handle_peek(data[1:], self._bridge_read(), self._reachable())
        elif op == bytes([channel.PATH_OPS["sync"]]):
            reply = self.engine.handle_sync(data[1:], sender)
        elif op == bytes([channel.PATH_OPS["forward"]]):
            reply = self.engine.handle_forward(data[1:], self._reachable(), sender)
        elif op == bytes([channel.PATH_OPS["pushed"]]):
            reply = self.engine.handle_pushed(data[1:])
        else:
            reply = wire.encode_reply(wire.INVALID_PAYLOAD)
        if op in (bytes([wire.WRITE]), bytes([channel.PATH_OPS["sync"]]), bytes([channel.PATH_OPS["forward"]])):
            self._kick.set()
        ep.send(request_id, reply)

    def _bridge_read(self):
        return self.bridge.read if self.bridge is not None else None

    # ---- workers ----

    def _deliver(self, dst: bytes, box_id: bytes, signature: bytes, payload: bytes, origin: bytes) -> Optional[int]:
        if dst == engine.BRIDGE:
            return self._bridge_writes.write(box_id, signature, payload) if self._bridge_writes is not None else None
        q = wire.encode_write(box_id, signature, payload)
        raw = self.links.request(dst, "forward", origin + q) if origin else self.links.request(dst, "write", q)
        return None if raw is None else raw[0]

    def _pushed(self, dst: bytes, box_id: bytes, tombstone: bool) -> Optional[bool]:
        raw = self.links.request(dst, "pushed", box_id + bytes([tombstone]))
        return None if raw is None else raw == b"\x01"

    def _forward_loop(self) -> None:
        while True:
            self._kick.wait(self.forward_interval)
            self._kick.clear()
            if self._stop.is_set():
                return
            try:
                self.engine.forward_due(self._reachable(), self._deliver, self._pushed)
            except Exception as e:
                RNS.log("pigeonhole: forwarder: %s" % e, RNS.LOG_ERROR)

    def _handoff_loop(self) -> None:
        while not self._stop.wait(self.handoff_interval):
            try:
                reachable = self._reachable()
                self.engine.handoff()
                self.engine.sync(reachable, lambda dst, q: self.links.request(dst, "sync", q))
            except Exception as e:
                RNS.log("pigeonhole: handoff: %s" % e, RNS.LOG_ERROR)

    def _gc_loop(self) -> None:
        # Once at start, then just past each replica epoch boundary; the hour cap survives clock jumps.
        while True:
            try:
                n = self.engine.gc()
                if n:
                    RNS.log("pigeonhole: gc dropped %d boxes older than replica epoch %d" % (n, self.engine.epoch() - 1), RNS.LOG_NOTICE)
            except Exception as e:
                RNS.log("pigeonhole: gc: %s" % e, RNS.LOG_ERROR)
            if self._stop.wait(min(3600.0, self.engine.till_next_epoch() + 1)):
                return

    def _announce_loop(self) -> None:
        while True:
            self.announce()
            if self._stop.wait(self.announce_interval):
                return

    def start(self) -> None:
        for fn in (self._announce_loop, self._forward_loop, self._handoff_loop, self._gc_loop):
            threading.Thread(target=fn, daemon=True).start()
        RNS.log("pigeonhole: replica %s up%s" % (RNS.prettyhexrep(self.destination.hash), ", bridge" if self.bridge else ""), RNS.LOG_NOTICE)

    def stop(self) -> None:
        self._stop.set()
        self._kick.set()
        self.links.close()
        if self.bridge is not None:
            self.bridge.close()
            self._bridge_writes.close()
        self.engine.store.close()

    def run_forever(self) -> None:
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
