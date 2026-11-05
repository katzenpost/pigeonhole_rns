# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The replica's decisions, driven in process with fake peers."""
import os

from hpqc.bacap.stateless import WriteCap

from pigeonhole_rns import PIGEONHOLE_CTX, placement, wire
from pigeonhole_rns.client import pad, position
from pigeonhole_rns.engine import BRIDGE, CLOSED, OPEN, Engine
from pigeonhole_rns.store import Store

BOX = 100
CT = BOX + 4 + 16

ME, R2, R3, R4 = b"me" * 8, b"r2" * 8, b"r3" * 8, b"r4" * 8
IDS = {ME: b"I" + ME, R2: b"I" + R2, R3: b"I" + R3, R4: b"I" + R4}


# The tests below default to closed mode, which shards; the open mode tests are at the end.
def engine(tmp_path, is_bridge=False, peers=(R2, R3, R4), mode=CLOSED, me=ME, name="e"):
    clock = [1000.0]
    e = Engine(Store(str(tmp_path / (name + ".sqlite"))), me, IDS[me], box_ciphertext_size=CT, is_bridge=is_bridge, now=lambda: clock[0], mode=mode)
    e.clock = clock
    for p in peers:
        e.heard(p, IDS[p], False)
    return e


def seal(text=b"yo", index=0):
    cap = WriteCap.generate()
    pos = position(cap, index)
    box, ct, sig = pos.encrypt(PIGEONHOLE_CTX, pad(text, BOX))
    return cap, box, sig, ct


def test_order_is_shared_and_stable():
    box = os.urandom(32)
    a = placement.order(box, [ME, R2, R3], lambda d: IDS[d])
    b = placement.order(box, [R3, ME, R2], lambda d: IDS[d])
    assert a == b and set(a) == {ME, R2, R3}


def test_write_verifies_stores_and_forwards(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    reply = e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2, R3, R4])
    assert reply == bytes([wire.SUCCESS])
    targets = {d for _, d, _ in e.store.due(0)}
    assert targets == set(e.targets(box, [R2, R3, R4])) - {ME}
    assert len(targets) <= 2

    bad = bytearray(sig)
    bad[0] ^= 1
    assert e.handle_write(wire.encode_write(box, bytes(bad), ct), []) == bytes([wire.INVALID_SIGNATURE])
    assert e.handle_write(wire.encode_write(box, sig, ct[:-1]), []) == bytes([wire.INVALID_PAYLOAD])


def test_write_is_acknowledged_even_when_alone(tmp_path):
    e = engine(tmp_path, peers=())
    _, box, sig, ct = seal()
    assert e.handle_write(wire.encode_write(box, sig, ct), reachable=[]) == bytes([wire.SUCCESS])
    assert e.store.get(box) is not None
    assert e.store.due(0) == []


def test_read_walks_past_owners(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    holder = {R4: wire.Reply(wire.SUCCESS, sig, ct)}
    asked = []

    def peek(dst, b):
        asked.append(dst)
        return holder.get(dst, wire.Reply(wire.NOT_FOUND))

    reply = wire.decode_reply(e.handle_read(wire.encode_read(box), [R2, R3, R4], peek))
    assert reply.code == wire.SUCCESS and reply.ciphertext == ct
    assert asked == placement.order(box, [R2, R3, R4], e.identity_of)[: asked.index(R4) + 1]
    assert e.store.get(box) is not None, "a fetched box is adopted"


def test_read_prefers_tombstone_and_reports_miss(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    assert wire.decode_reply(e.handle_read(wire.encode_read(box), [R2], lambda d, b: wire.Reply(wire.TOMBSTONE))).code == wire.TOMBSTONE
    assert wire.decode_reply(e.handle_read(wire.encode_read(os.urandom(32)), [R2], lambda d, b: None)).code == wire.NOT_FOUND


def test_forward_acks_and_backs_off(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), [R2, R3, R4])
    targets = {d for _, d, _ in e.store.due(0)}
    answers = {t: wire.SUCCESS for t in targets}
    silent = next(iter(targets))
    answers[silent] = None
    e.forward_due(targets, lambda dst, b, s, c: answers[dst])
    assert e.store.acked(box) == targets - {silent}
    assert e.store.queued(box) == {silent}
    assert e.store.due(e.now()) == [], "the silent peer is backed off, not retried at once"


def test_handoff_then_drop_only_after_both_owners_ack(tmp_path):
    e = engine(tmp_path)
    _, box, sig, ct = seal()
    # Written while only this replica was reachable: no forwards queued.
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[])
    owners = e.owners(box)
    if ME in owners:
        return  # this replica owns it; nothing to hand off
    e.handoff(reachable=owners)
    assert e.store.queued(box) == set(owners)
    e.forward_due(owners, lambda dst, b, s, c: wire.SUCCESS if dst == owners[0] else None)
    e.handoff(reachable=owners)
    assert e.store.get(box) is not None, "one acknowledgement is not enough"
    e.clock[0] += 3600  # past the backoff of the owner that did not answer
    e.forward_due(owners, lambda dst, b, s, c: wire.ALREADY_EXISTS)
    assert e.handoff(reachable=owners) == 1
    assert e.store.get(box) is None


def test_bridge_push_and_pull(tmp_path):
    e = engine(tmp_path, is_bridge=True)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[])
    assert BRIDGE in e.store.queued(box)
    pushed = []
    e.forward_due([], lambda dst, b, s, c: pushed.append(dst) or wire.SUCCESS)
    assert pushed == [BRIDGE]

    _, other, osig, oct_ = seal(b"from the mixnet")
    mix = {other: wire.Reply(wire.SUCCESS, osig, oct_)}
    r = wire.decode_reply(e.handle_read(wire.encode_read(other), [], lambda d, b: None, bridge_read=lambda b: mix.get(b)))
    assert r.code == wire.SUCCESS and r.ciphertext == oct_
    assert e.store.get(other) is not None, "a pulled box lives on the mesh afterwards"
    assert wire.decode_reply(e.handle_peek(wire.encode_read(other))).code == wire.SUCCESS


R5 = b"r5" * 8
IDS[R5] = b"I" + R5


def engine_with_bridge(tmp_path):
    e = engine(tmp_path)
    e.heard(R5, IDS[R5], True)
    return e


def test_write_reaches_one_bridge_from_any_entry(tmp_path):
    e = engine_with_bridge(tmp_path)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2, R3, R4, R5])
    assert R5 in e.store.queued(box), "a non-bridge entry still sends to the bridge"
    assert e.store.queued(box) == (set(e.targets(box, [R2, R3, R4, R5])) - {ME}) | {R5}
    assert BRIDGE not in e.store.queued(box)


def test_no_bridge_reachable_queues_nothing_extra(tmp_path):
    e = engine_with_bridge(tmp_path)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2, R3, R4])
    assert e.store.queued(box) == set(e.targets(box, [R2, R3, R4])) - {ME}
    assert e.handoff(reachable=[R2, R3, R4]) == 0
    assert R5 not in e.store.queued(box)


def test_bridge_reachable_later_gets_the_box_once(tmp_path):
    e = engine_with_bridge(tmp_path)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2, R3, R4])
    e.handoff(reachable=[R2, R3, R4, R5])
    assert R5 in e.store.queued(box)
    e.forward_due([R2, R3, R4, R5], lambda dst, b, s, c: wire.SUCCESS)
    assert R5 in e.store.acked(box)
    e.handoff(reachable=[R2, R3, R4, R5])
    assert R5 not in e.store.queued(box), "a bridge that acknowledged is not sent to again"


def test_stand_in_keeps_copy_until_bridge_acks(tmp_path):
    e = engine_with_bridge(tmp_path)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[])
    owners = e.owners(box)
    if ME in owners:
        return
    e.handoff(reachable=set(owners) | {R5})
    assert e.store.queued(box) == set(owners) | {R5}
    e.forward_due(set(owners) | {R5}, lambda dst, b, s, c: wire.SUCCESS if dst != R5 else None)
    assert e.handoff(reachable=set(owners) | {R5}) == 0
    assert e.store.get(box) is not None, "both owners hold it, but the mixnet does not yet"
    e.clock[0] += 3600
    e.forward_due(set(owners) | {R5}, lambda dst, b, s, c: wire.SUCCESS)
    assert e.handoff(reachable=set(owners) | {R5}) == 1


def test_bridge_replica_keeps_copy_until_pushed(tmp_path):
    e = engine(tmp_path, is_bridge=True)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[])
    owners = e.owners(box)
    if ME in owners:
        return
    e.handoff(reachable=owners)
    e.forward_due(owners, lambda dst, b, s, c: wire.SUCCESS if dst != BRIDGE else None)
    assert e.handoff(reachable=owners) == 0
    e.clock[0] += 3600
    e.forward_due(owners, lambda dst, b, s, c: wire.SUCCESS)
    assert e.handoff(reachable=owners) == 1


# ---- open mode: every replica stores every box ----


def test_open_write_goes_to_every_replica_but_the_sender(tmp_path):
    e = engine(tmp_path, mode=OPEN)
    e.heard(R5, IDS[R5], True)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2, R3, R4, R5], sender=R3)
    assert e.store.queued(box) == {R2, R4, R5}
    e.forward_due([R2, R3, R4, R5], lambda dst, b, s, c: wire.SUCCESS)
    assert e.store.queued(box) == set()
    assert e.handoff(reachable=[R2, R3, R4, R5]) == 0
    assert e.store.get(box) is not None, "open mode never drops for placement"
    assert e.handle_write(wire.encode_write(box, sig, ct), [R2, R3, R4, R5], sender=R2) == bytes([wire.SUCCESS])
    assert e.store.queued(box) == set(), "a box already held is not passed on again"


def test_open_bridge_replica_pushes_to_mixnet(tmp_path):
    e = engine(tmp_path, is_bridge=True, mode=OPEN)
    _, box, sig, ct = seal()
    e.handle_write(wire.encode_write(box, sig, ct), reachable=[R2], sender=R2)
    assert e.store.queued(box) == {BRIDGE}


def pair(tmp_path, monkeypatch):
    """Two open replicas whose sync and forwards call each other in process."""
    monkeypatch.setattr(wire, "SYNC_PAGE", 2)
    a = engine(tmp_path, peers=(R2,), mode=OPEN, name="a")
    b = engine(tmp_path, peers=(ME,), mode=OPEN, me=R2, name="b")
    eng = {ME: a, R2: b}
    sender = {ME: R2, R2: ME}

    def request(dst, q):
        return eng[dst].handle_sync(q, sender[dst])

    def deliver_from(src):
        return lambda dst, box_id, s, c: wire.decode_reply(eng[dst].handle_write(wire.encode_write(box_id, s, c), [], src)).code

    def run():
        a.sync([R2], request)
        b.sync([ME], request)
        a.forward_due([R2], deliver_from(ME))
        b.forward_due([ME], deliver_from(R2))

    return a, b, run


def test_open_sync_pages_both_ways_and_tombstones_win(tmp_path, monkeypatch):
    a, b, run = pair(tmp_path, monkeypatch)
    boxes = [seal(b"%d" % i) for i in range(7)]
    for i, (_, box, sig, ct) in enumerate(boxes):
        (a if i % 2 else b).accept(wire.Query(wire.WRITE, box, sig, ct), [])
    # Both hold box 0; a holds its tombstone.
    cap, box0, sig0, ct0 = boxes[0]
    a.accept(wire.Query(wire.WRITE, box0, sig0, ct0), [])
    tid, tsig = position(cap, 0).tombstone(PIGEONHOLE_CTX)
    assert a.accept(wire.Query(wire.WRITE, tid, tsig, b""), []) == wire.SUCCESS
    run()
    ids = {box for _, box, _, _ in boxes}
    for e in (a, b):
        assert set(e.store.box_ids()) == ids
        assert e.store.get(box0).is_tombstone
    assert a.synced == {R2} and b.synced == {ME}
    assert a.store.due(1e9) == [] and b.store.due(1e9) == []


def test_open_resyncs_after_peer_was_unreachable(tmp_path, monkeypatch):
    a, b, run = pair(tmp_path, monkeypatch)
    run()
    _, box, sig, ct = seal()
    b.accept(wire.Query(wire.WRITE, box, sig, ct), [])  # written while a was away
    a.sync([], lambda d, q: None)
    assert a.synced == set()
    run()
    assert a.store.get(box) is not None


def test_sync_rejects_out_of_range_reply(tmp_path):
    e = engine(tmp_path, mode=OPEN)
    bad = wire.encode_sync(b"\x00" * 32, [])  # ends at the bottom, no progress
    assert e.sync([R2], lambda d, q: bad) == 0 and e.synced == set()
    assert engine(tmp_path, mode=CLOSED, name="c").handle_sync(wire.encode_sync(bytes(32) + b"\xff" * 32, []), R2) == b""
