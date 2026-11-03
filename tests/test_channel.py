# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
import os
import random

import pytest

from pigeonhole_rns import wire
from pigeonhole_rns.channel import HEADER, MAX_PIECES, MSGTYPE, Frame, Reassembler, split

PIECE = 421  # Channel MDU minus the header on a 500 byte MTU link


def feed_all(r, frames):
    out = [r.feed(f) for f in frames]
    return [o for o in out if o is not None]


def wire_trip(f):
    g = Frame()
    g.unpack(f.pack())
    return g


@pytest.mark.parametrize("n", [0, 1, 33, PIECE - 1, PIECE, PIECE + 1, 1000, 3 * PIECE, MAX_PIECES * PIECE])
def test_split_reassemble(n):
    data = os.urandom(n)
    frames = split(7, data, PIECE)
    assert len(frames) == max(1, -(-n // PIECE))
    assert all(len(f.pack()) <= PIECE + HEADER.size for f in frames)
    assert feed_all(Reassembler(), [wire_trip(f) for f in frames]) == [data]


def test_one_piece_and_255_pieces():
    assert len(split(1, b"x" * PIECE, PIECE)) == 1
    assert len(split(1, b"x" * (MAX_PIECES * PIECE), PIECE)) == 255
    with pytest.raises(ValueError):
        split(1, b"x" * (MAX_PIECES * PIECE + 1), PIECE)


def test_frame_layout():
    f = Frame(0x0102, 3, 9, b"abc")
    assert f.pack() == b"\x01\x02\x03\x09abc"
    assert Frame.MSGTYPE == MSGTYPE == 0x5048


def test_reply_larger_than_query():
    q = wire.encode_read(os.urandom(32))
    rep = wire.encode_reply(wire.SUCCESS, os.urandom(64), os.urandom(1020))
    qf, rf = split(5, q, PIECE), split(5, rep, PIECE)
    assert len(qf) == 1 and len(rf) == 3
    assert feed_all(Reassembler(), qf) == [q]
    assert feed_all(Reassembler(), rf) == [rep]


def test_interleaved_out_of_order_and_duplicates():
    a, b = os.urandom(2000), os.urandom(1500)
    fa, fb = split(1, a, PIECE), split(2, b, PIECE)
    frames = fa + fb + fa[:2] + fb[1:3]
    random.Random(4).shuffle(frames)
    got = feed_all(Reassembler(), frames)
    assert sorted(got) == sorted([a, b])


def test_count_mismatch_refused():
    r = Reassembler()
    f = split(3, os.urandom(1000), PIECE)
    assert r.feed(f[0]) is None
    assert r.feed(Frame(3, 1, 4, f[1].data)) is None
    assert len(r) == 0
    assert r.feed(f[2]) is None and len(r) == 1  # a fresh, incomplete request
    assert r.feed(Frame(4, 2, 2, b"")) is None and r.feed(Frame(4, 0, 0, b"")) is None


def test_incomplete_timed_out():
    t = [0.0]
    r = Reassembler(timeout=10, now=lambda: t[0])
    f = split(9, os.urandom(1000), PIECE)
    r.feed(f[0])
    r.feed(f[1])
    t[0] = 11.0
    assert r.feed(f[2]) is None  # the first two pieces were dropped
    assert len(r) == 1
