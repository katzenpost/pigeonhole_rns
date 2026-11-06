# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The two hangs pigeonhole_rns/quint/python_replica.qnt finds: a Link request's response that
arrives before RNS registers the request, and a Channel whose TX ring holds a culled receipt."""
import time
import types

import RNS

from pigeonhole_rns import channel, rnsio


class RacingLink:
    """A Link whose response arrives between sending the request and registering it, as RNS's
    Link.request allows; its own handle_response drops a response for no pending request."""

    ACTIVE, CLOSED = RNS.Link.ACTIVE, RNS.Link.CLOSED
    status = RNS.Link.ACTIVE

    def __init__(self, destination, established_callback=None, closed_callback=None):
        self.pending_requests = []
        established_callback(self)

    def handle_response(self, request_id, response_data, *a, **kw):
        for r in self.pending_requests:
            if r.request_id == request_id:
                r.status, r.response = RNS.RequestReceipt.READY, response_data
                r.response_callback(r)

    def request(self, path, data, response_callback=None, failed_callback=None, timeout=None):
        r = types.SimpleNamespace(request_id=b"r" * 16, status=RNS.RequestReceipt.SENT, response=None,
                                  response_callback=response_callback)
        self.handle_response(r.request_id, b"reply " + data, 7, 7)
        self.pending_requests.append(r)
        return r


def test_a_response_before_its_request_registers_is_not_lost(monkeypatch):
    monkeypatch.setattr(rnsio.RNS.Identity, "recall", lambda dest: object())
    monkeypatch.setattr(rnsio.RNS, "Destination", type("Dest", (), {"OUT": 0, "SINGLE": 0, "__init__": lambda self, *a: None}))
    monkeypatch.setattr(rnsio.RNS, "Link", RacingLink)
    l = rnsio.Links(request_timeout=3)
    t = time.time()
    assert l._request(b"d" * 16, "write", b"q") == b"reply q"
    assert time.time() - t < 1, "answered at once, not after the request timeout"


class CulledChannel:
    """RNS's Channel once Transport culled a receipt in its TX ring."""

    mdu = 400

    def register_message_type(self, cls):
        pass

    def add_message_handler(self, cb):
        pass

    def is_ready_to_send(self):
        raise Exception("Unexpected receipt state: 255")


class ClosingLink:
    status = RNS.Link.ACTIVE

    def get_channel(self):
        return CulledChannel()

    def teardown(self):
        self.status = RNS.Link.CLOSED


def test_a_wedged_channel_closes_its_link_and_does_not_raise():
    link = ClosingLink()
    ep = channel.Endpoint(link, lambda *a: None)
    assert ep.send(1, b"reply") is False
    assert link.status == RNS.Link.CLOSED
