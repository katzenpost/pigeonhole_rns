# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""End to end: two replica processes on a local Reticulum network and a
client in this process. Writes a message, reads it back through the entry
replica, checks the other replica received the forward, deletes it, and
reads the tombstone; then the same through query mode 2 (Channel), with
boxes written in one mode read in the other. Prints the bytes on the
client's link for a write and a read in each mode.

    python tests/e2e_two_replicas.py --run-dir /path/to/scratch

Not collected by pytest: it spawns processes and binds a TCP port."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

HUB_PORT = 42101

HUB_CONFIG = """[reticulum]
  enable_transport = Yes
  share_instance = No
  link_mtu_discovery = %s
[logging]
  loglevel = 3
[interfaces]
  [[Hub]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = %d
"""

LEAF_CONFIG = """[reticulum]
  enable_transport = No
  share_instance = No
  link_mtu_discovery = %s
[logging]
  loglevel = 3
[interfaces]
  [[ToHub]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = %d
"""


def write_config(d: str, text: str) -> str:
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "config"), "w") as f:
        f.write(text)
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--settle", type=float, default=12.0, help="seconds to let announces and paths settle")
    ap.add_argument("--box-size", type=int, default=100)
    ap.add_argument("--mtu-discovery", choices=("yes", "no"), default="yes", help="no keeps links at the 500 byte MTU")
    ap.add_argument("--replica-bin", help="run the replicas from this executable instead of the source tree")
    a = ap.parse_args()
    BOX = a.box_size
    hub_config, leaf_config = HUB_CONFIG % (a.mtu_discovery, HUB_PORT), LEAF_CONFIG % (a.mtu_discovery, HUB_PORT)

    run = os.path.abspath(a.run_dir)
    if os.path.isdir(run):
        shutil.rmtree(run)
    os.makedirs(run)
    here = os.path.dirname(os.path.abspath(__file__))
    pkg_root = os.path.dirname(here)
    env = dict(os.environ, PYTHONPATH=pkg_root)

    procs = []
    try:
        for name, cfg in (("a", hub_config), ("b", leaf_config)):
            cfgdir = write_config(os.path.join(run, "rns-" + name), cfg)
            log = open(os.path.join(run, "replica-%s.log" % name), "w")
            procs.append(
                subprocess.Popen(
                    ([a.replica_bin] if a.replica_bin else [sys.executable, "-m", "pigeonhole_rns.cli"]) + ["--config", cfgdir, "--box-size", str(BOX), "-v",
                     "replica", "--storage", os.path.join(run, "store-" + name), "--announce-interval", "3"],
                    stdout=log, stderr=subprocess.STDOUT, env=env, cwd=pkg_root,
                )
            )
            time.sleep(2.0)

        sys.path.insert(0, pkg_root)
        import RNS
        from hpqc.bacap.stateless import WriteCap

        from pigeonhole_rns import wire
        from pigeonhole_rns.client import Client

        client_cfg = write_config(os.path.join(run, "rns-client"), leaf_config)
        c = Client(client_cfg, BOX, loglevel=RNS.LOG_NOTICE)
        if not c.wait_for_replica(timeout=a.settle + 20):
            print("FAIL: no replica announced", file=sys.stderr)
            return 1
        time.sleep(a.settle)
        replicas = list(c.replicas)
        print("replicas heard:", [r.hex()[:8] for r in replicas], "entry:", c.entry().hex()[:8])
        if len(replicas) < 2:
            print("FAIL: expected two replicas", file=sys.stderr)
            return 1

        cap = WriteCap.generate()
        box_id, code = c.write_message(cap, 0, b"yo what up? you coming to the party later tonight?")
        print("write code", code)
        if code not in wire.STORED_CODES:
            print("FAIL: write not stored", file=sys.stderr)
            return 1

        code, text = c.read_message(cap.read_cap(), 0)
        print("read code", code, "text", text)
        if code != wire.SUCCESS or text != b"yo what up? you coming to the party later tonight?":
            print("FAIL: read back mismatch", file=sys.stderr)
            return 1

        # Both replicas hold it once the forward has run.
        deadline = time.time() + 30
        holders = set()
        while time.time() < deadline and len(holders) < 2:
            for r in replicas:
                got = c.read_box(box_id, dest=r, path="peek")
                if got is not None and got.code == wire.SUCCESS:
                    holders.add(r)
            time.sleep(1.0)
        print("holders:", [h.hex()[:8] for h in holders])
        if len(holders) < 2:
            print("FAIL: forward did not reach the second replica", file=sys.stderr)
            return 1

        _, code = c.delete_message(cap, 0)
        print("delete code", code)
        c.tombstones.clear()
        code, _ = c.read_message(cap.read_cap(), 0)
        print("read after delete code", code)
        if code != wire.TOMBSTONE:
            print("FAIL: expected a tombstone", file=sys.stderr)
            return 1

        code, _ = c.read_message(cap.read_cap(), 1)
        print("read of unwritten index code", code)
        if code != wire.NOT_FOUND:
            print("FAIL: expected not found", file=sys.stderr)
            return 1

        if not channel_mode(c, cap, BOX, a.settle):
            return 1
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


def check(ok: bool, what: str) -> bool:
    if not ok:
        print("FAIL:", what, file=sys.stderr)
    return ok


def channel_mode(c1, cap, box: int, settle: float) -> bool:
    """Mode 2 against the same replicas, crossed with mode 1 (c1)."""
    from pigeonhole_rns import wire
    from pigeonhole_rns.client import Client

    c2 = Client(None, box, mode="channel")
    if not check(c2.wait_for_replica(timeout=settle + 20), "no replica announced mode 2"):
        return False
    rc = cap.read_cap()
    msg = lambda i: b"box %d written in another mode" % i

    _, code = c2.write_message(cap, 2, msg(2))
    print("mode 2 write code", code)
    if not check(code in wire.STORED_CODES, "mode 2 write not stored"):
        return False
    for who, c in (("mode 2", c2), ("mode 1", c1)):
        code, text = c.read_message(rc, 2)
        print(who, "read of the mode 2 box", code, text)
        if not check(code == wire.SUCCESS and text == msg(2), who + " read of a mode 2 box"):
            return False
    _, code = c1.write_message(cap, 3, msg(3))
    code, text = c2.read_message(rc, 3)
    print("mode 2 read of a mode 1 box", code, text)
    if not check(code == wire.SUCCESS and text == msg(3), "mode 2 read of a mode 1 box"):
        return False
    _, code = c2.delete_message(cap, 2)
    print("mode 2 delete code", code)
    for who, c in (("mode 2", c2), ("mode 1", c1)):
        c.tombstones.clear()
        code, _ = c.read_message(rc, 2)
        print(who, "read after mode 2 delete", code)
        if not check(code == wire.TOMBSTONE, who + " expected a tombstone"):
            return False
    code, _ = c2.read_message(rc, 9)
    print("mode 2 read of unwritten index", code)
    if not check(code == wire.NOT_FOUND, "mode 2 expected not found"):
        return False

    # Bytes of packets on the entry link, sent and received by this process.
    import RNS

    entry = c2.entry()
    count = [0, 0]
    link_ids = set()

    def on_link(raw: bytes) -> bool:
        return raw[2:18] in link_ids or raw[18:34] in link_ids

    for iface in RNS.Transport.interfaces:
        out = iface.process_outgoing

        def counted(data, out=out):
            if on_link(data):
                count[0] += len(data)
            return out(data)

        iface.process_outgoing = counted
    inbound = RNS.Transport.inbound

    def counted_in(raw, interface=None, *args, **kw):
        if on_link(raw):
            count[1] += len(raw)
        return inbound(raw, interface, *args, **kw)

    RNS.Transport.inbound = counted_in
    for i, (name, c) in enumerate((("mode 1", c1), ("mode 2", c2))):
        c.read_box(b"\0" * 32, dest=entry)  # open the link first
        link = c.links._links[entry]
        link_ids.add(bytes(link.link_id))
        idx = 10 + i
        count[:] = [0, 0]
        _, code = c.write_message(cap, idx, os.urandom(box))
        time.sleep(2)
        w = list(count)
        count[:] = [0, 0]
        code2, _ = c.read_message(rc, idx)
        time.sleep(2)
        r = list(count)
        print("%s link mtu %d: write of a %d byte box code %s: %d sent %d received; read code %s: %d sent %d received"
              % (name, link.mtu, box, code, w[0], w[1], code2, r[0], r[1]))
        if not check(code in wire.STORED_CODES and code2 == wire.SUCCESS, name + " measured write and read"):
            return False
    RNS.Transport.inbound = inbound
    c2.close()
    return True


if __name__ == "__main__":
    sys.exit(main())
