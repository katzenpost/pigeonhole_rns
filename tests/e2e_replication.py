# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""End to end, open mode: N replica processes in a mesh or a line and a
client attached to each. The last replica starts late and replica 1 is
stopped for a while: boxes are written at rotating entries before, during
and after its absence, then half are tombstoned. Passes when every replica
holds every box, or its tombstone, and prints the holders per box.

    python tests/e2e_replication.py --run-dir /path/to/scratch -n 5 --topo line

Not collected by pytest: it spawns processes and binds TCP ports."""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import time

REPLICA_CFG = """[reticulum]
  enable_transport = Yes
  share_instance = No
[logging]
  loglevel = 3
[interfaces]
  [[Listen]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = %d
%s"""

CLIENT_CFG = """[reticulum]
  enable_transport = No
  share_instance = No
[logging]
  loglevel = 2
[interfaces]
%s"""

TO = """  [[To%d]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = %d
"""

BOX = 100


def held(store: str, box_id: bytes):
    path = os.path.join(store, "boxes.sqlite")
    if not os.path.exists(path):
        return None
    db = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5)
    try:
        r = db.execute("SELECT length(payload) FROM boxes WHERE box_id = ?", (box_id,)).fetchone()
    finally:
        db.close()
    return None if r is None else ("tomb" if r[0] == 0 else "box")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("-n", type=int, default=3)
    ap.add_argument("--topo", choices=("mesh", "line"), default="mesh")
    ap.add_argument("--boxes", type=int, default=2, help="boxes written in each of the three phases")
    ap.add_argument("--port", type=int, default=47400)
    ap.add_argument("--timeout", type=float, default=240.0, help="seconds to wait for every replica to hold every box")
    ap.add_argument("--src", help="run the replicas from this source tree instead of this one")
    ap.add_argument("--replica-args", default="", help="extra arguments for the replica command")
    ap.add_argument("--rust", default="", help="comma separated replica numbers to run with the Rust replica, e.g. 1,3")
    ap.add_argument("--rust-bin", default="rust/target/release/replica_rns-rs", help="the Rust replica executable")
    a = ap.parse_args()
    rust = {int(i) for i in a.rust.split(",") if i}
    n, late, victim = a.n, a.n - 1, 1
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.abspath(a.src or here)
    run = os.path.abspath(a.run_dir)
    if os.path.isdir(run):
        shutil.rmtree(run)
    os.makedirs(run)
    store = lambda i: os.path.join(run, "store-%d" % i)
    procs = {}

    def start(i):
        d = os.path.join(run, "rns-%d" % i)
        os.makedirs(d, exist_ok=True)
        peers = range(i) if a.topo == "mesh" else range(i - 1, i) if i else ()
        with open(os.path.join(d, "config"), "w") as f:
            f.write(REPLICA_CFG % (a.port + i, "".join(TO % (j, a.port + j) for j in peers)))
        log = open(os.path.join(run, "replica-%d.log" % i), "a")
        cmd = [os.path.abspath(a.rust_bin)] if i in rust else [sys.executable, "-m", "pigeonhole_rns.cli"]
        procs[i] = subprocess.Popen(
            cmd + ["--config", d, "--box-size", str(BOX), "replica",
             "--storage", store(i), "--announce-interval", "5"] + a.replica_args.split(),
            stdout=log, stderr=subprocess.STDOUT, cwd=src, env=dict(os.environ, PYTHONPATH=src))
        time.sleep(1.0)

    def stop(i):
        p = procs.pop(i)
        p.terminate()
        p.wait(timeout=20)

    sys.path.insert(0, src)
    import RNS
    from hpqc.bacap.stateless import WriteCap

    from pigeonhole_rns import PIGEONHOLE_CTX, wire
    from pigeonhole_rns.client import Client, pad, position

    def dest(i):
        while not os.path.exists(os.path.join(store(i), "identity")):
            time.sleep(0.2)
        return RNS.Destination.hash(RNS.Identity.from_file(os.path.join(store(i), "identity")), "pigeonhole", "replica")

    cap = WriteCap.generate()
    want = {}  # box_id -> "box" or "tomb"
    tombs = []
    c = None
    try:
        for i in range(n - 1):
            start(i)
        dests = {i: dest(i) for i in range(n - 1)}
        cdir = os.path.join(run, "rns-client")
        os.makedirs(cdir)
        with open(os.path.join(cdir, "config"), "w") as f:
            f.write(CLIENT_CFG % "".join(TO % (j, a.port + j) for j in range(n)))
        c = Client(cdir, BOX, loglevel=RNS.LOG_WARNING)
        time.sleep(30)  # replicas and client hear each other

        def write(k, entries):
            entry = entries[k % len(entries)]
            pos = position(cap, k)
            box_id, ct, sig = pos.encrypt(PIGEONHOLE_CTX, pad(b"box %d" % k, BOX))
            code = c.write_box(box_id, sig, ct, dest=dests[entry])
            print("write %d at replica %d: code %s" % (k, entry, code), flush=True)
            if code in wire.STORED_CODES:
                want[box_id] = "box"
                tombs.append((k, box_id, entry))

        k = 0
        for _ in range(a.boxes):
            write(k, list(range(n - 1)))
            k += 1
        time.sleep(5)
        stop(victim)
        print("replica %d stopped" % victim, flush=True)
        for _ in range(a.boxes):
            write(k, [i for i in range(n - 1) if i != victim])
            k += 1
        time.sleep(10)
        start(victim)
        start(late)
        dests[late] = dest(late)
        print("replica %d restarted, replica %d joined" % (victim, late), flush=True)
        time.sleep(15)
        for _ in range(a.boxes):
            write(k, list(range(n)))
            k += 1
        for k, box_id, entry in tombs[::2]:
            tid, tsig = position(cap, k).tombstone(PIGEONHOLE_CTX)
            te = (entry + 1) % n
            code = c.write_box(tid, tsig, b"", dest=dests[te])
            print("tombstone %d at replica %d: code %s" % (k, te, code), flush=True)
            if code in wire.STORED_CODES:
                want[box_id] = "tomb"

        t0 = time.time()
        while True:
            got = {b: [i for i in range(n) if held(store(i), b) == w] for b, w in want.items()}
            if all(len(v) == n for v in got.values()) or time.time() - t0 > a.timeout:
                break
            time.sleep(2)
        print("after %.0f s, holders per box (%s):" % (time.time() - t0, "box or tombstone as written"))
        for b, w in want.items():
            print("  %s %-4s %d/%d %s" % (b.hex()[:8], w, len(got[b]), n, got[b]))
        counts = [sum(1 for b in want if held(store(i), b)) for i in range(n)]
        print("boxes held per replica:", counts)
        ok = bool(want) and all(len(v) == n for v in got.values())
        print("PASS" if ok else "FAIL: not every replica holds every box")
        return 0 if ok else 1
    finally:
        if c is not None:
            c.close()
        for i in list(procs):
            stop(i)


if __name__ == "__main__":
    sys.exit(main())
