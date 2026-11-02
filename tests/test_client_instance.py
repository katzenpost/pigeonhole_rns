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
