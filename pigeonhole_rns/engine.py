# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica's decisions, free of Reticulum so they can be tested in
process: membership, placement, the entry path, forwarding, handoff, sync,
the read walk and the bridge.

In open mode every replica stores every box: a new box goes to every replica
heard, and replicas that meet sync the boxes the other lacks. Closed mode,
for a future mesh whose replicas authenticate out of band, shards: two
owners per box by rendezvous hashing, and stand-ins hand off and drop.

A bridge is a replica like any other, and also writes boxes into the
mixnet it serves: every box, or with forward on-request only those a client
wrote to it. A box pulled from a mixnet keeps that mixnet as its origin and
is never written back there. Bridges serving the same mixnet ask each other
before writing, so each box goes to each mixnet once, barring retries."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set

from hpqc.bacap.stateless import MessageBoxIndex

from . import placement, wire
from .store import Store

# A pseudo destination for the local Katzenpost replica on a bridge node.
BRIDGE = b"bridge"

EPOCH_SECONDS = 7 * 24 * 3600
# Katzenpost replicas count epochs from 2017-06-01 UTC; a bridged box must
# fall in the same epoch on both sides.
EPOCH_BASE = 1496275200

# Retry backoff for forwards, in seconds.
BACKOFF_BASE = 5.0
BACKOFF_CAP = 600.0

OPEN = "open"
CLOSED = "closed"

ALL = "all"
ON_REQUEST = "on-request"

# A bridge that is not first in a box's order among the bridges of its mixnet
# waits this many retries for one of them to write the box before it does.
TWIN_WAIT = 3

LOW, HIGH = bytes(32), b"\xff" * 32


def epoch_now(now: Optional[float] = None) -> int:
    return int(((time.time() if now is None else now) - EPOCH_BASE) // EPOCH_SECONDS)


@dataclass
class Peer:
    identity: bytes
    bridge: bool = False
    last_heard: float = 0.0
    mixnet: bytes = b""


# Callbacks the Reticulum layer supplies.
Deliver = Callable[[bytes, bytes, bytes, bytes, bytes], Optional[int]]  # (dst, box_id, sig, ct, origin) -> code or None
Request = Callable[[bytes, bytes], Optional[bytes]]  # (dst, sync query) -> reply or None
Peek = Callable[[bytes, bytes], Optional[wire.Reply]]  # (dst, box_id) -> reply or None on no answer
BridgeRead = Callable[[bytes], Optional[wire.Reply]]  # (box_id) -> reply or None
Pushed = Callable[[bytes, bytes, bool], Optional[bool]]  # (bridge dst, box_id, tombstone) -> in its mixnet, None on no answer


class Engine:
    def __init__(
        self,
        store: Store,
        self_dest: bytes,
        self_identity: bytes,
        box_ciphertext_size: Optional[int] = None,
        k: int = placement.K,
        is_bridge: bool = False,
        now: Callable[[], float] = time.time,
        mode: str = OPEN,
        mixnet: bytes = b"",
        forward: str = ALL,
    ):
        if mode not in (OPEN, CLOSED):
            raise ValueError("mode must be open or closed")
        if forward not in (ALL, ON_REQUEST):
            raise ValueError("forward must be all or on-request")
        self.mode = mode
        self.mixnet = (mixnet or wire.mixnet_id("")) if is_bridge else b""
        self.forward = forward
        self.synced: Set[bytes] = set()
        self.store = store
        self.self_dest = self_dest
        self.k = k
        self.is_bridge = is_bridge
        self.box_ciphertext_size = box_ciphertext_size
        self.now = now
        self.peers: Dict[bytes, Peer] = {self_dest: Peer(self_identity, is_bridge, mixnet=self.mixnet)}

    # ---- membership ----

    def heard(self, dest: bytes, identity: bytes, bridge: bool, mixnet: bytes = b"") -> bool:
        """Records an announce. A changed identity for a known destination
        is ignored, so the first key seen is the one kept."""
        cur = self.peers.get(dest)
        if cur is not None and cur.identity != identity:
            return False
        self.peers[dest] = Peer(identity, bridge, self.now(), mixnet if bridge else b"")
        return True

    def identity_of(self, dest: bytes) -> bytes:
        return self.peers[dest].identity

    def peer_of(self, identity: bytes) -> Optional[bytes]:
        return next((d for d, p in self.peers.items() if p.identity == identity and d != self.self_dest), None)

    def owners(self, box_id: bytes) -> List[bytes]:
        return placement.first(box_id, self.peers.keys(), self.identity_of, self.k)

    def targets(self, box_id: bytes, reachable: Iterable[bytes]) -> List[bytes]:
        cands = set(reachable) | {self.self_dest}
        return placement.first(box_id, cands, self.identity_of, self.k)

    def forwards(self, box_id: bytes, reachable: Iterable[bytes], sender: Optional[bytes] = None, origin: bytes = b"", client: bool = False) -> List[bytes]:
        """Where a newly stored box is sent: in open mode every reachable
        replica heard, in closed mode the first k in its order and a bridge;
        and on a bridge its mixnet, unless the box came from there or the
        bridge forwards on request and no client wrote it here. Never back
        to the replica it came from."""
        reachable = list(reachable)
        if self.mode == OPEN:
            dsts = [d for d in reachable if d in self.peers]
        else:
            dsts = self.targets(box_id, reachable) + self.bridge_targets(box_id, reachable)
        if self.to_mixnet(origin, client):
            dsts.append(BRIDGE)
        return list(dict.fromkeys(d for d in dsts if d not in (self.self_dest, sender)))

    def to_mixnet(self, origin: bytes, client: bool) -> bool:
        return self.is_bridge and origin != self.mixnet and (self.forward == ALL or client)

    def bridges(self, reachable: Iterable[bytes]) -> List[bytes]:
        return [d for d in reachable if d in self.peers and self.peers[d].bridge and d != self.self_dest]

    def twins(self, reachable: Iterable[bytes]) -> List[bytes]:
        """Reachable bridges serving this bridge's mixnet."""
        return [d for d in self.bridges(reachable) if self.peers[d].mixnet == self.mixnet]

    def bridge_targets(self, box_id: bytes, reachable: Iterable[bytes]) -> List[bytes]:
        """In closed mode, where a box held by a replica that is not a
        bridge goes so that it reaches the mixnet: the first reachable
        bridge in the box's order. The mixnet never pulls from the mesh, so
        every holder sends, and all pick the same bridge."""
        if self.is_bridge or self.mode == OPEN:
            return []
        return placement.order(box_id, self.bridges(reachable), self.identity_of)[:1]

    def is_bridge_dst(self, dst: bytes) -> bool:
        return dst == BRIDGE or (dst in self.peers and self.peers[dst].bridge)

    # ---- verification ----

    def verify(self, q: wire.Query) -> int:
        assert q.signature is not None and q.ciphertext is not None
        if len(q.ciphertext) != 0 and self.box_ciphertext_size is not None and len(q.ciphertext) != self.box_ciphertext_size:
            return wire.INVALID_PAYLOAD
        try:
            ok = MessageBoxIndex.verify_box(q.box_id, q.ciphertext, q.signature)
        except Exception:
            return wire.INVALID_BOX_ID
        return wire.SUCCESS if ok else wire.INVALID_SIGNATURE

    # ---- the entry path ----

    def accept(self, q: wire.Query, reachable: Iterable[bytes], sender: Optional[bytes] = None, origin: bytes = b"") -> int:
        """Verify, store, and enqueue forwards. A box already held enqueues
        nothing, so a forward is never passed on twice. A write from no
        known replica is a client's."""
        code = self.verify(q)
        if code != wire.SUCCESS:
            return code
        dsts = self.forwards(q.box_id, reachable, sender, origin, client=sender is None)
        return self.store.put(q.box_id, q.signature, q.ciphertext, epoch_now(self.now()), dsts, origin)

    def handle_forward(self, data: bytes, reachable: Iterable[bytes], sender: Optional[bytes]) -> bytes:
        """A write prefixed with the mixnet the box came from. The origin
        is kept only from a known replica."""
        origin = bytes(data[: wire.MIXNET_ID_SIZE]) if sender is not None else b""
        return self.handle_write(data[wire.MIXNET_ID_SIZE :], reachable, sender, origin)

    def handle_pushed(self, data: bytes) -> bytes:
        """A bridge of the same mixnet asking whether this one wrote a box,
        or its tombstone, into the mixnet, or pulled it from there: 1 or 0."""
        box = self.store.get(bytes(data[: wire.BOX_ID_SIZE]))
        tomb = data[wire.BOX_ID_SIZE :] == b"\x01"
        done = box is not None and box.is_tombstone == tomb and (
            BRIDGE in self.store.acked(box.box_id) or (self.is_bridge and box.origin == self.mixnet)
        )
        return b"\x01" if done else b"\x00"

    def handle_write(self, data: bytes, reachable: Iterable[bytes], sender: Optional[bytes] = None, origin: bytes = b"") -> bytes:
        try:
            q = wire.decode_query(data)
        except wire.WireError:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        if q.kind != wire.WRITE:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        return wire.encode_reply(self.accept(q, reachable, sender, origin))

    # ---- reads ----

    def local(self, box_id: bytes) -> Optional[wire.Reply]:
        box = self.store.get(box_id)
        if box is None:
            return None
        if box.is_tombstone:
            return wire.Reply(wire.TOMBSTONE)
        return wire.Reply(wire.SUCCESS, box.signature, box.payload)

    def handle_peek(self, data: bytes, bridge_read: Optional[BridgeRead] = None, reachable: Iterable[bytes] = ()) -> bytes:
        """A replica asking a replica: this store only, plus the mixnet on a
        bridge, which stores what it pulls. Never walks, so replicas cannot
        chase each other."""
        try:
            q = wire.decode_query(data)
        except wire.WireError:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        if q.kind != wire.READ:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        r = self.local(q.box_id)
        if r is None and self.is_bridge and bridge_read is not None:
            r = self._pull(q.box_id, bridge_read, reachable)
        if r is None:
            return wire.encode_reply(wire.NOT_FOUND)
        return wire.encode_reply(r.code, r.signature, r.ciphertext)

    def handle_read(self, data: bytes, reachable: Iterable[bytes], peek: Peek, bridge_read: Optional[BridgeRead] = None) -> bytes:
        """A client asking its entry replica: this store, then every reachable
        replica in the box's order, bridges asking their mixnets, then this
        replica's own mixnet. A box found on a bridge is stored by that
        bridge, with its origin, and reaches this replica from there."""
        try:
            q = wire.decode_query(data)
        except wire.WireError:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        if q.kind != wire.READ:
            return wire.encode_reply(wire.INVALID_PAYLOAD)
        reachable = list(reachable)
        r, adopt = self.local(q.box_id), False
        if r is None:
            for dst in placement.order(q.box_id, [d for d in reachable if d != self.self_dest and d in self.peers], self.identity_of):
                got = peek(dst, q.box_id)
                if got is not None and got.code in (wire.SUCCESS, wire.TOMBSTONE):
                    r, adopt = got, not self.peers[dst].bridge
                    break
        if r is None and self.is_bridge and bridge_read is not None:
            r = self._pull(q.box_id, bridge_read, reachable)
        if r is None:
            return wire.encode_reply(wire.NOT_FOUND)
        if adopt and self.store.get(q.box_id) is None:
            self._adopt(q.box_id, r, reachable)
        return wire.encode_reply(r.code, r.signature, r.ciphertext)

    def _pull(self, box_id: bytes, bridge_read: BridgeRead, reachable: Iterable[bytes]) -> Optional[wire.Reply]:
        got = bridge_read(box_id)
        if got is not None and got.code in (wire.SUCCESS, wire.TOMBSTONE):
            self._adopt(box_id, got, reachable, self.mixnet)
            return got
        return None

    def _adopt(self, box_id: bytes, r: wire.Reply, reachable: Iterable[bytes], origin: bytes = b"") -> None:
        """A box fetched for a reader is stored and forwarded like a write,
        so the next reader finds it on the mesh."""
        if r.code == wire.SUCCESS and r.signature is not None:
            q = wire.Query(wire.WRITE, box_id, r.signature, r.ciphertext or b"")
            if self.verify(q) == wire.SUCCESS:
                dsts = self.forwards(box_id, reachable, origin=origin)
                self.store.put(box_id, r.signature, r.ciphertext or b"", epoch_now(self.now()), dsts, origin)

    # ---- forwarding and handoff ----

    def forward_due(self, reachable: Iterable[bytes], deliver: Deliver, pushed: Optional[Pushed] = None) -> int:
        """Attempts every due forward whose destination is reachable.
        deliver returns the peer's reply code, or None when it did not
        answer. Before writing into its mixnet, a bridge asks the others
        serving it; one has written the box, and this one acknowledges it
        as written, or this one is first in the box's order among them, or
        has waited TWIN_WAIT retries, and writes it. Returns how many were
        acknowledged."""
        reachable = set(reachable)
        now = self.now()
        done = 0
        for box_id, dst, attempts in self.store.due(now):
            if dst != BRIDGE and dst not in reachable:
                continue
            box = self.store.get(box_id)
            if box is None:
                self.store.forget(box_id, dst)
                continue
            twins = self.twins(reachable) if dst == BRIDGE and pushed is not None else []
            if twins and any(pushed(t, box_id, box.is_tombstone) for t in twins):
                code = wire.SUCCESS
            elif twins and attempts < TWIN_WAIT and placement.order(box_id, twins + [self.self_dest], self.identity_of)[0] != self.self_dest:
                code = None
            else:
                code = deliver(dst, box_id, box.signature, box.payload, box.origin)
            if code is not None and code in wire.STORED_CODES:
                self.store.ack(box_id, dst)
                done += 1
            elif code is not None and code in (wire.INVALID_SIGNATURE, wire.INVALID_BOX_ID, wire.INVALID_PAYLOAD):
                self.store.forget(box_id, dst)
            else:
                delay = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** min(attempts, 10)))
                self.store.backoff(box_id, dst, now + delay)
        return done

    def handoff(self, reachable: Iterable[bytes]) -> int:
        """For every held box: on a bridge forwarding all, enqueue to its
        mixnet if not written there yet and not from there; in closed mode,
        enqueue to a bridge if none has taken it yet.
        Open mode stops there. In closed mode, for one whose owners, in this
        replica's view, do not include it: enqueue to owners not yet
        acknowledged, and drop the copy once both owners and the bridge, if
        one is queued, have acknowledged.
        Tombstones are never dropped. Returns how many copies were dropped."""
        reachable = set(reachable)
        dropped = 0
        for box_id in self.store.box_ids():
            acked = self.store.acked(box_id)
            queued = self.store.queued(box_id)
            if self.is_bridge and self.forward == ALL and BRIDGE not in acked | queued:
                box = self.store.get(box_id)
                if box is not None and box.origin != self.mixnet:
                    self.store.enqueue(box_id, BRIDGE)
                    queued.add(BRIDGE)
            if not any(self.is_bridge_dst(d) for d in acked | queued):
                for bdst in self.bridge_targets(box_id, reachable):
                    self.store.enqueue(box_id, bdst)
                    queued.add(bdst)
            if self.mode == OPEN:
                continue
            owners = self.owners(box_id)
            if self.self_dest in owners:
                continue
            for o in owners:
                if o in reachable and o not in acked and o not in queued:
                    self.store.enqueue(box_id, o)
                    queued.add(o)
            box = self.store.get(box_id)
            if box is None or box.is_tombstone:
                continue
            if len(owners) == self.k and all(o in acked for o in owners) and not queued:
                self.store.drop(box_id)
                dropped += 1
        return dropped

    # ---- sync, open mode ----

    def sync(self, reachable: Iterable[bytes], request: Request) -> int:
        """Syncs with each reachable replica not synced with since this
        replica started or last found it unreachable. Returns how many
        synced."""
        if self.mode != OPEN:
            return 0
        reachable = {d for d in reachable if d in self.peers and d != self.self_dest}
        self.synced &= reachable
        done = 0
        for dst in reachable - self.synced:
            if self._sync_with(dst, request):
                self.synced.add(dst)
                done += 1
        return done

    def _sync_with(self, dst: bytes, request: Request) -> bool:
        """Walks the Box ID space a page at a time: sends this store's page,
        the peer enqueues what this store lacks and answers with its own, and
        this store enqueues what the peer lacks."""
        cursor = LOW
        while cursor != HIGH:
            mine = self.store.entries(cursor, HIGH, wire.SYNC_PAGE)
            hi = mine[-1][0] if len(mine) == wire.SYNC_PAGE else HIGH
            raw = request(dst, wire.encode_sync(cursor + hi, mine))
            if raw is None:
                return False
            try:
                top, theirs = wire.decode_sync(raw, wire.BOX_ID_SIZE)
            except wire.WireError:
                return False
            if not cursor < top <= hi or any(not cursor < b <= top for b, _ in theirs):
                return False
            self._push_missing(dst, [e for e in mine if e[0] <= top], theirs)
            cursor = top
        return True

    def handle_sync(self, data: bytes, sender: Optional[bytes]) -> bytes:
        """Answers a sync page with this store's page over the same range,
        cut short if full, and enqueues to the sender what it lacks there.
        An unidentified sender gets the answer but no pushes."""
        try:
            head, theirs = wire.decode_sync(data, 2 * wire.BOX_ID_SIZE)
        except wire.WireError:
            return b""
        cursor, hi = head[: wire.BOX_ID_SIZE], head[wire.BOX_ID_SIZE :]
        if self.mode != OPEN or not cursor < hi:
            return b""
        mine = self.store.entries(cursor, hi, wire.SYNC_PAGE)
        top = mine[-1][0] if len(mine) == wire.SYNC_PAGE else hi
        if sender is not None:
            self._push_missing(sender, mine, theirs)
        return wire.encode_sync(top, mine)

    def _push_missing(self, dst: bytes, mine, theirs) -> None:
        """Enqueues to dst each of mine it lacks, or holds as a box where
        this store holds the tombstone."""
        # shortcut: the receiver stores a push at its own epoch, so a sync across an epoch
        # boundary can keep a box an epoch longer; carry the epoch in replica writes if it matters.
        have = dict(theirs)
        for box_id, tomb in mine:
            if box_id not in have or (tomb and not have[box_id]):
                self.store.enqueue(box_id, dst)

    def gc(self) -> int:
        cur = epoch_now(self.now())
        return self.store.sweep([cur, cur - 1])
