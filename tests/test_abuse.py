"""Abuse-protection tests for /scan: rate limit, client identity behind a
proxy, overall scan deadline and the cap on concurrent scans.

Limits are lowered per test by patching ``app.config.settings``; the network
is the fake one from tests/fakenet.py.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from app.abuse import scan_slots
from app.config import settings
from app.main import app
from tests.fakenet import PUBLIC_IP

CLIENT_A = "203.0.113.10"
CLIENT_B = "203.0.113.11"
INGRESS_POD = "10.244.0.5"  # the reverse proxy, as seen from the app
POD_NETWORK = ipaddress.ip_network("10.244.0.0/16")
PUBLIC_URL = "https://public.example"


def client_from(peer_ip: str) -> TestClient:
    """A test client whose TCP peer address (ASGI ``scope["client"]``) is
    ``peer_ip`` -- what the app sees as the other end of the socket."""

    async def app_with_peer(scope, receive, send):
        if scope["type"] == "http":
            scope = {**scope, "client": (peer_ip, 50000)}
        await app(scope, receive, send)

    return TestClient(app_with_peer)


def scan(client: TestClient, url: str = PUBLIC_URL, xff: str | None = None) -> httpx.Response:
    headers = {} if xff is None else {"X-Forwarded-For": xff}
    return client.get("/scan", params={"url": url}, headers=headers)


def counter(name: str) -> float:
    return REGISTRY.get_sample_value(name) or 0.0


def log_fields(caplog, message: str) -> list[dict]:
    """``extra_fields`` of every log record whose message is ``message``."""
    return [
        getattr(r, "extra_fields", {})
        for r in caplog.records
        if r.getMessage().lower() == message
    ]


@pytest.fixture
def limit_3(monkeypatch) -> None:
    monkeypatch.setattr(settings, "rate_limit", "3/minute")


@pytest.fixture
def behind_ingress(monkeypatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxies", (POD_NETWORK,))


# ── Per-IP rate limit ──────────────────────────────────────────────────────
def test_scan_over_the_limit_is_rejected_with_429(net, limit_3):
    client = client_from(CLIENT_A)
    assert [scan(client).status_code for _ in range(3)] == [200, 200, 200]

    resp = scan(client)
    assert resp.status_code == 429
    assert "rate limit" in resp.json()["detail"].lower()
    assert int(resp.headers["retry-after"]) > 0
    assert len(net.requests) == 3, "a rate-limited request still reached the network"


def test_limit_is_counted_per_client_ip(net, limit_3):
    for _ in range(3):
        scan(client_from(CLIENT_A))
    assert scan(client_from(CLIENT_A)).status_code == 429
    assert scan(client_from(CLIENT_B)).status_code == 200


def test_blocked_targets_use_up_the_limit_too(net, limit_3):
    """Probing internal addresses must not be free: it is the abuse case."""
    client = client_from(CLIENT_A)
    assert [scan(client, "http://127.0.0.1").status_code for _ in range(3)] == [400] * 3
    assert scan(client, "http://127.0.0.1").status_code == 429


def test_health_and_metrics_are_not_rate_limited(limit_3):
    """Probes and Prometheus scrape far more often than the scan limit."""
    client = client_from(CLIENT_A)
    assert {client.get("/health").status_code for _ in range(10)} == {200}
    assert {client.get("/metrics/").status_code for _ in range(10)} == {200}


def test_rate_limited_request_is_counted_and_logged(net, limit_3, caplog):
    client = client_from(CLIENT_A)
    for _ in range(3):
        scan(client)
    before = counter("secscan_rate_limited_total")
    with caplog.at_level(logging.WARNING):
        assert scan(client).status_code == 429
    assert counter("secscan_rate_limited_total") == before + 1
    assert [f.get("client_ip") for f in log_fields(caplog, "rate limited")] == [CLIENT_A]


# ── Who is the client? X-Forwarded-For trust ───────────────────────────────
def test_forwarded_header_from_an_untrusted_peer_is_ignored(net, limit_3):
    """Default config trusts nobody: a client that invents a new
    X-Forwarded-For value per request must not get a new bucket each time."""
    client = client_from(CLIENT_A)
    statuses = [scan(client, xff=f"198.51.100.{i}").status_code for i in range(4)]
    assert statuses == [200, 200, 200, 429]


def test_forwarded_header_from_a_trusted_proxy_identifies_the_client(
    net, limit_3, behind_ingress, caplog
):
    """All traffic arrives from the Ingress pod; the real clients are told
    apart by the address the Ingress appended to X-Forwarded-For."""
    ingress = client_from(INGRESS_POD)
    for _ in range(3):
        assert scan(ingress, xff=CLIENT_A).status_code == 200
    with caplog.at_level(logging.WARNING):
        assert scan(ingress, xff=CLIENT_A).status_code == 429
    assert scan(ingress, xff=CLIENT_B).status_code == 200
    assert [f.get("client_ip") for f in log_fields(caplog, "rate limited")] == [CLIENT_A]


def test_client_supplied_forwarded_entries_are_ignored(net, limit_3, behind_ingress):
    """A proxy APPENDS the peer it saw, so only the right-most entry was
    written by our Ingress. Everything to the left came from the client."""
    ingress = client_from(INGRESS_POD)
    statuses = [
        scan(ingress, xff=f"198.51.100.{i}, {CLIENT_A}").status_code for i in range(4)
    ]
    assert statuses == [200, 200, 200, 429]


def test_chain_of_trusted_proxies_is_skipped(net, limit_3, behind_ingress):
    """Two of our own proxies in a row: the client is the first address,
    counting from the right, that is not one of ours."""
    ingress = client_from(INGRESS_POD)
    for _ in range(3):
        scan(ingress, xff=f"{CLIENT_A}, 10.244.3.9")
    assert scan(ingress, xff=f"{CLIENT_A}, 10.244.3.9").status_code == 429
    assert scan(ingress, xff=f"{CLIENT_B}, 10.244.3.9").status_code == 200


@pytest.mark.parametrize("xff", [None, "", "not-an-ip", "10.244.0.9"])
def test_unusable_forwarded_header_falls_back_to_the_peer(net, limit_3, behind_ingress, xff):
    """Missing, garbage or all-trusted header: key on the peer, never crash
    and never hand out an unlimited bucket."""
    ingress = client_from(INGRESS_POD)
    statuses = [scan(ingress, xff=xff).status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 429]


# ── Overall scan deadline ──────────────────────────────────────────────────
def _slow_redirect_loop(net, seconds_per_hop: float) -> None:
    """Every hop is quick on its own; only the sum is too slow."""

    def slow_lookup() -> list[str]:
        time.sleep(seconds_per_hop)
        return [PUBLIC_IP]

    net.dns["loop.example"] = slow_lookup
    net.routes["loop.example"] = lambda req: httpx.Response(
        302, headers={"location": f"http://loop.example/{len(net.requests)}"}
    )


def test_scan_exceeding_the_overall_deadline_returns_504(net, monkeypatch):
    monkeypatch.setattr(settings, "scan_deadline_seconds", 0.4)
    _slow_redirect_loop(net, seconds_per_hop=0.15)

    started = time.perf_counter()
    resp = scan(client_from(CLIENT_A), "http://loop.example")
    elapsed = time.perf_counter() - started

    assert resp.status_code == 504
    assert "deadline" in resp.json()["detail"].lower()
    assert elapsed < 0.8, f"scan ran for {elapsed:.2f}s with a 0.4s deadline"
    assert len(net.requests) < 6, "the redirect chain was not cut short"


def test_deadline_is_counted_and_logged(net, monkeypatch, caplog):
    monkeypatch.setattr(settings, "scan_deadline_seconds", 0.4)
    _slow_redirect_loop(net, seconds_per_hop=0.15)
    before = counter("secscan_scan_deadline_exceeded_total")
    with caplog.at_level(logging.WARNING):
        scan(client_from(CLIENT_A), "http://loop.example")
    assert counter("secscan_scan_deadline_exceeded_total") == before + 1
    assert len(log_fields(caplog, "scan deadline exceeded")) == 1


# ── Concurrency cap ────────────────────────────────────────────────────────
def test_scan_is_rejected_when_every_slot_is_busy(net, monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    lookup_started = threading.Event()
    release = threading.Event()

    def stuck_lookup() -> list[str]:
        lookup_started.set()
        release.wait(5)
        return [PUBLIC_IP]

    net.dns["slow.example"] = stuck_lookup
    results: dict[str, httpx.Response] = {}

    def run_slow_scan() -> None:
        results["slow"] = scan(client_from(CLIENT_A), "http://slow.example")

    worker = threading.Thread(target=run_slow_scan)
    worker.start()
    try:
        assert lookup_started.wait(5), "the slow scan never started"
        before = counter("secscan_busy_rejections_total")

        # The only slot is taken by the scan that is stuck in DNS.
        resp = scan(client_from(CLIENT_B))
        assert resp.status_code == 503
        assert "busy" in resp.json()["detail"].lower()
        assert int(resp.headers["retry-after"]) > 0
        assert counter("secscan_busy_rejections_total") == before + 1
    finally:
        release.set()
        worker.join(5)

    assert results["slow"].status_code == 200
    # The slot is free again once the slow scan has finished.
    assert scan(client_from(CLIENT_B)).status_code == 200


def test_slot_is_released_when_a_scan_fails(net, monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    client = client_from(CLIENT_A)
    assert scan(client, "http://127.0.0.1").status_code == 400
    assert scan(client, "http://does-not-exist.example").status_code == 400
    assert scan(client).status_code == 200
    assert scan_slots.in_use == 0


class _TrackedBody(httpx.AsyncByteStream):
    """A response body that remembers whether the client closed it."""

    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self):
        yield b""

    async def aclose(self) -> None:
        self.closed = True


def test_deadline_in_dns_releases_the_slot_and_closes_every_response(net, monkeypatch):
    """Deadline fires between hops (during a slow lookup)."""
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    monkeypatch.setattr(settings, "scan_deadline_seconds", 0.4)
    _slow_redirect_loop(net, seconds_per_hop=0.15)
    bodies: list[_TrackedBody] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        bodies.append(_TrackedBody())
        return httpx.Response(
            302,
            headers={"location": f"http://loop.example/{len(net.requests)}"},
            stream=bodies[-1],
        )

    net.routes["loop.example"] = redirect
    client = client_from(CLIENT_A)

    assert scan(client, "http://loop.example").status_code == 504
    assert bodies, "no hop was fetched before the deadline"
    assert all(body.closed for body in bodies), "a response stream was left open"
    assert scan_slots.in_use == 0
    assert scan(client).status_code == 200  # the only slot is usable again


def test_deadline_while_the_target_hangs_releases_the_slot(net, monkeypatch):
    """Deadline fires in the middle of the HTTP request itself."""
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    monkeypatch.setattr(settings, "scan_deadline_seconds", 0.3)
    cancelled = threading.Event()

    async def hang(request: httpx.Request) -> httpx.Response:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return httpx.Response(200)

    net.routes["hang.example"] = hang
    net.dns["hang.example"] = [PUBLIC_IP]
    client = client_from(CLIENT_A)

    started = time.perf_counter()
    resp = scan(client, "http://hang.example")
    assert resp.status_code == 504
    assert time.perf_counter() - started < 2
    assert cancelled.is_set(), "the in-flight request was not cancelled"
    assert scan_slots.in_use == 0
    assert scan(client).status_code == 200


# ── Order of the gates: rate limit -> slot -> SSRF validation -> scan ──────
def test_rate_limited_requests_never_take_a_slot(net, limit_3, monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    client = client_from(CLIENT_A)
    statuses = [scan(client).status_code for _ in range(6)]
    assert statuses == [200, 200, 200, 429, 429, 429]
    assert scan_slots.in_use == 0
    assert scan(client_from(CLIENT_B)).status_code == 200


def test_rate_limit_is_checked_before_the_slot(net, limit_3, monkeypatch):
    """With the only slot busy, a client over its limit gets 429, not 503:
    the request was turned away before it could ask for a slot."""
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    over_limit = client_from(CLIENT_A)
    for _ in range(3):
        scan(over_limit)

    lookup_started = threading.Event()
    release = threading.Event()

    def stuck_lookup() -> list[str]:
        lookup_started.set()
        release.wait(5)
        return [PUBLIC_IP]

    net.dns["slow.example"] = stuck_lookup
    worker = threading.Thread(
        target=lambda: scan(client_from(CLIENT_B), "http://slow.example")
    )
    worker.start()
    try:
        assert lookup_started.wait(5), "the slow scan never started"
        busy_before = counter("secscan_busy_rejections_total")
        assert scan(over_limit).status_code == 429
        assert counter("secscan_busy_rejections_total") == busy_before
        assert scan_slots.in_use == 1  # only the stuck scan
    finally:
        release.set()
        worker.join(5)


def test_busy_rejection_happens_before_any_dns_lookup(net, monkeypatch):
    """A request refused for lack of a slot does no SSRF validation work."""
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    monkeypatch.setattr(scan_slots, "in_use", 1)  # pretend a scan is running
    assert scan(client_from(CLIENT_A)).status_code == 503
    assert net.dns_lookups == []
    assert scan_slots.in_use == 1  # the refused request released nothing
