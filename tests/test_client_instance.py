# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A Client over a Reticulum instance the caller already started: a GUI
starts it on its main thread, where RNS installs its signal handlers, and
connects from a worker thread."""

import threading

import RNS

from pigeonhole_rns.client import Client


def test_client_reuses_running_instance(tmp_path):
    cfg = tmp_path / "rns"
    cfg.mkdir()
    (cfg / "config").write_text("[reticulum]\n  share_instance = No\n[logging]\n  loglevel = 0\n[interfaces]\n")
    r = RNS.Reticulum(configdir=str(cfg), loglevel=RNS.LOG_ERROR)
    out = []
    t = threading.Thread(target=lambda: out.append(Client(str(cfg), 1000)))
    t.start()
    t.join(10)
    assert out and out[0].reticulum is r
    out[0].close()


def test_client_recalls_replicas_heard_before(tmp_path):
    if RNS.Reticulum.get_instance() is None:
        cfg = tmp_path / "rns"
        cfg.mkdir()
        (cfg / "config").write_text("[reticulum]\n  share_instance = No\n[logging]\n  loglevel = 0\n[interfaces]\n")
        RNS.Reticulum(configdir=str(cfg), loglevel=RNS.LOG_ERROR)
    replica, other = RNS.Identity(), RNS.Identity()
    rdest = RNS.Destination.hash(replica, "pigeonhole", "replica")
    odest = RNS.Destination.hash(other, "lxmf", "delivery")
    RNS.Identity.remember(b"\x00" * 32, rdest, replica.get_public_key(), bytes([3]))
    RNS.Identity.remember(b"\x00" * 32, odest, other.get_public_key(), bytes([3]))
    c = Client(None, 1000, mode="channel")
    assert c.replicas[rdest] == (replica.hash, True)
    assert rdest in c.channel_replicas
    assert odest not in c.replicas
    c.close()
