# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""End to end push: replica B, a Python hub, and replica A, Python or Rust, on a local
Reticulum network, and a client in this process holding a Link to A. The client subscribes
on A and gets pushed a box written to B (arriving at A by replication), one written to A, one
A already held, and none for an ID it unsubscribed.

    python tests/e2e_push.py --run-dir /path/to/scratch [--rust-bin rust/target/release/replica_rns-rs]

Not collected by pytest: it spawns processes and binds a TCP port."""

from __future__ import annotations

import argparse
import os
import queue
import shutil
import subprocess
import sys
import time

from e2e_two_replicas import HUB_CONFIG, LEAF_CONFIG, write_config

PORT = 42111


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--rust-bin", help="run replica A with the Rust replica")
    ap.add_argument("--box-size", type=int, default=100)
    a = ap.parse_args()
    BOX = a.box_size
    hub, leaf = HUB_CONFIG % ("yes", PORT), LEAF_CONFIG % ("yes", PORT)
    run = os.path.abspath(a.run_dir)
    shutil.rmtree(run, ignore_errors=True)
    os.makedirs(run)
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=pkg_root)
    py = [sys.executable, "-m", "pigeonhole_rns.cli"]
    procs = []
    try:
        for name, cfg, cmd in (("b", hub, py), ("a", leaf, [os.path.abspath(a.rust_bin)] if a.rust_bin else py)):
            cfgdir = write_config(os.path.join(run, "rns-" + name), cfg)
            log = open(os.path.join(run, "replica-%s.log" % name), "w")
            procs.append(subprocess.Popen(cmd + ["--config", cfgdir, "--box-size", str(BOX), "-v", "replica", "--storage",
                                                 os.path.join(run, "store-" + name), "--announce-interval", "3"],
                                          stdout=log, stderr=subprocess.STDOUT, env=env, cwd=pkg_root))
            time.sleep(2.0)

        sys.path.insert(0, pkg_root)
        import RNS
        from hpqc.bacap.stateless import WriteCap

        from pigeonhole_rns import APP_NAME, ASPECT, PIGEONHOLE_CTX, push, rnsio, wire
        from pigeonhole_rns.client import Client, pad, position, unpad

        dest = lambda n: RNS.Destination.hash(RNS.Identity.from_file(os.path.join(run, "store-" + n, "identity")), APP_NAME, ASPECT)
        A, B = dest("a"), dest("b")
        c = Client(write_config(os.path.join(run, "rns-client"), leaf), BOX)
        deadline = time.time() + 40
        while time.time() < deadline and not (c.links.flags.get(A, 0) & 16 and RNS.Transport.has_path(A) and RNS.Transport.has_path(B)):
            time.sleep(0.2)
        print("A %s flags %d, B %s flags %d" % (A.hex()[:8], c.links.flags.get(A, 0), B.hex()[:8], c.links.flags.get(B, 0)))
        if not c.links.flags.get(A, 0) & 16:
            print("FAIL: A does not announce push", file=sys.stderr)
            return 1

        pushes: "queue.Queue" = queue.Queue()
        links = rnsio.Links(on_push=lambda _ep, data: pushes.put((time.time(), data)))
        links.flags[A] = c.links.flags[A]
        cap = WriteCap.generate()
        boxes = [position(cap, i).encrypt(PIGEONHOLE_CTX, pad(b"box %d" % i, BOX)) for i in range(4)]
        ids = [b for b, _, _ in boxes]

        def expect(i: int, since: float, what: str) -> bool:
            try:
                at, data = pushes.get(timeout=30)
            except queue.Empty:
                print("FAIL: no push of", what, file=sys.stderr)
                return False
            r = wire.decode_reply(data[32:])
            text = unpad(position(cap.read_cap(), i).open(PIGEONHOLE_CTX, data[:32], r.ciphertext, r.signature)) if r.code == wire.SUCCESS else None
            print("push of %s: box %d, code %d, %r, %.2fs after" % (what, ids.index(data[:32]), r.code, text, at - since))
            return data[:32] == ids[i] and text == b"box %d" % i

        # Box 2, held by A before the client subscribes.
        print("write box 2 to A:", c.write_box(ids[2], boxes[2][2], boxes[2][1], dest=A))
        t = time.time()
        reply = links.channel_request(A, bytes([push.SUBSCRIBE]) + push.encode_subscribe(600, ids[:3]))
        print("subscribe to boxes 0-2 on A in mode 2:", reply.hex() if reply else reply)
        if reply != push.encode_subscribe_reply(3, 600) or not expect(2, t, "a held box"):
            return 1
        # Box 3 subscribed as a Link request on A, then unsubscribed in mode 2.
        if not a.rust_bin:
            reply = links._request(A, "subscribe", push.encode_subscribe(0, ids[3:]))
            print("subscribe to box 3 as a Link request:", reply.hex() if reply else reply)
            if reply != push.encode_subscribe_reply(1, push.MAX_TTL):
                print("FAIL: request subscribe", file=sys.stderr)
                return 1
        reply = links.channel_request(A, bytes([push.UNSUBSCRIBE]) + ids[3])
        print("unsubscribe box 3:", reply.hex() if reply else reply)

        t = time.time()
        print("write box 0 to B:", c.write_box(ids[0], boxes[0][2], boxes[0][1], dest=B))
        if not expect(0, t, "a box written to B, replicated to A"):
            return 1
        t = time.time()
        print("write box 1 to A:", c.write_box(ids[1], boxes[1][2], boxes[1][1], dest=A))
        if not expect(1, t, "a box written to A"):
            return 1
        print("write box 3 to A:", c.write_box(ids[3], boxes[3][2], boxes[3][1], dest=A))
        try:
            _, data = pushes.get(timeout=5)
            print("FAIL: pushed after unsubscribe", data[:32].hex(), file=sys.stderr)
            return 1
        except queue.Empty:
            print("no push of the unsubscribed box 3")
        links.close()
        c.close()
        print("PASS")
        return 0
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
