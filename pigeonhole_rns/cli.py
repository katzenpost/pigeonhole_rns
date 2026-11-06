# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""replica_rns: a Pigeonhole storage replica for Reticulum, with commands to test one."""

from __future__ import annotations

import argparse
import sys

import RNS
from hpqc.bacap.stateless import ReadCap, WriteCap

from . import wire


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="replica_rns", description=__doc__)
    p.add_argument("--config", help="Reticulum config directory")
    p.add_argument("--box-size", type=wire.parse_box_sizes, default=(wire.BOX_PLAINTEXT_MESH,),
                   help="box plaintext sizes, comma separated, each a profile (mesh, %d bytes, the default; mixnet, %d) "
                   "or a size in bytes, at most %d and none over %d. A replica takes these and always the mesh and "
                   "mixnet sizes, 0 alone for any size; a client pads to the first"
                   % (wire.BOX_PLAINTEXT_MESH, wire.BOX_PLAINTEXT_MIXNET, wire.MAX_BOX_SIZES, wire.BOX_PLAINTEXT_MIXNET))
    p.add_argument("-v", "--verbose", action="count", default=0)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("replica", help="run a storage replica")
    r.add_argument("--storage", required=True, help="directory for identity and boxes")
    r.add_argument("--bridge-socket", help="unix socket of a Katzenpost replica on this host")
    r.add_argument("--mixnet", default="", help="with --bridge-socket: a name for the mixnet bridged, such as its PKI identity; bridges giving the same name serve one mixnet")
    r.add_argument("--forward", choices=("all", "on-request"), default="all",
                   help="with --bridge-socket: write every box into the mixnet, or only those clients write to this replica")
    r.add_argument("--announce-interval", type=float, default=600.0)

    r.add_argument("--epoch-period", type=float, default=1200.0, help="seconds in an epoch, Katzenpost's 20 minutes by default")
    r.add_argument("--replica-epoch-epochs", type=int, default=504,
                   help="epochs in a replica epoch, a week by default; boxes are kept for the current and previous replica epoch")
    r.add_argument("--max-storage-mib", type=int, default=0, help="most MiB the box store may take on disk; 0 for no limit")
    r.add_argument("--min-free-storage-mib", type=int, default=500, help="MiB to leave free on the storage filesystem; 0 for none")

    sub.add_parser("new-cap", help="print a fresh write capability and its read capability")

    w = sub.add_parser("write", help="write a message at an index of a stream")
    w.add_argument("--writecap", required=True, help="hex write capability")
    w.add_argument("--index", type=int, default=0)
    w.add_argument("text")

    d = sub.add_parser("delete", help="tombstone an index of a stream")
    d.add_argument("--writecap", required=True)
    d.add_argument("--index", type=int, default=0)

    rd = sub.add_parser("read", help="read an index of a stream")
    rd.add_argument("--readcap", required=True, help="hex read capability")
    rd.add_argument("--index", type=int, default=0)

    for q in (w, d, rd):
        q.add_argument("--mode", choices=("request", "channel"), default="request", help="query as Link requests, or as Channel messages")

    a = p.parse_args(argv)
    loglevel = RNS.LOG_NOTICE + a.verbose

    if a.cmd == "new-cap":
        cap = WriteCap.generate()
        print("writecap", cap.to_bytes().hex())
        print("readcap ", cap.read_cap().to_bytes().hex())
        return 0

    if a.cmd == "replica":
        from .replica import Replica

        Replica(a.config, a.storage, a.box_size, bridge_socket=a.bridge_socket, announce_interval=a.announce_interval,
                mixnet=a.mixnet, forward=a.forward, loglevel=loglevel, epoch_period=a.epoch_period,
                replica_epoch_epochs=a.replica_epoch_epochs, max_storage_mib=a.max_storage_mib,
                min_free_storage_mib=a.min_free_storage_mib).run_forever()
        return 0

    from .client import Client

    if not a.box_size:
        p.error("a client needs a box size")
    c = Client(a.config, a.box_size[0], loglevel=loglevel, mode=a.mode)
    if not c.wait_for_replica():
        print("no replica reachable", file=sys.stderr)
        return 1
    try:
        if a.cmd == "write":
            box_id, code = c.write_message(WriteCap.from_bytes(bytes.fromhex(a.writecap)), a.index, a.text.encode())
            print(box_id.hex(), "code", code)
            return 0 if code in wire.STORED_CODES else 1
        if a.cmd == "delete":
            box_id, code = c.delete_message(WriteCap.from_bytes(bytes.fromhex(a.writecap)), a.index)
            print(box_id.hex(), "code", code)
            return 0 if code in wire.STORED_CODES else 1
        code, text = c.read_message(ReadCap.from_bytes(bytes.fromhex(a.readcap)), a.index)
        if code == wire.SUCCESS:
            sys.stdout.write(text.decode(errors="replace") + "\n")
            return 0
        print("code", code, file=sys.stderr)
        return 1
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())
