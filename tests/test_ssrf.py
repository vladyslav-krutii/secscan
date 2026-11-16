"""SSRF regression tests for /scan.

No test here touches the real network: the ``net`` fixture (tests/conftest.py)
swaps DNS and HTTP for the fake internet in tests/fakenet.py.
"""

from __future__ import annotations

import ipaddress
import logging

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from app.main import app
from app.scanner import is_public_ip
from tests.fakenet import PUBLIC_IP, SECURE_HEADERS

client = TestClient(app)


def scan(url: str) -> httpx.Response:
    return client.get("/scan", params={"url": url})


def assert_blocked(resp: httpx.Response) -> None:
    assert resp.status_code == 400, f"expected 400, got {resp.status_code}: {resp.text}"
    assert "blocked target" in resp.json()["detail"].lower()


# ── Address classifier (allowlist: only is_global unicast passes) ──────────
@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",  # carrier-grade NAT (100.64.0.0/10)
        "fd00::1",  # IPv6 unique-local (fc00::/7)
        "fe80::1",  # IPv6 link-local (fe80::/10)
        "192.0.0.1",  # IETF protocol assignments (192.0.0.0/24)
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.1",
        "169.254.169.254",
        "192.0.2.1",  # documentation
        "198.18.0.1",  # benchmarking
        "240.0.0.1",  # reserved for future use
        "255.255.255.255",
        "224.0.0.1",  # multicast
        "::",
        "::1",
        "::ffff:10.0.0.1",  # IPv4-mapped private address
        "2001:db8::1",  # documentation
        "64:ff9b::7f00:1",  # NAT64 wrapping 127.0.0.1
        "2002:7f00:1::1",  # 6to4 wrapping 127.0.0.1
    ],
)
def test_non_public_addresses_are_rejected(address):
    assert is_public_ip(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", PUBLIC_IP, "2606:4700:4700::1111", "::ffff:8.8.8.8"],
)
def test_public_addresses_are_accepted(address):
    assert is_public_ip(ipaddress.ip_address(address)) is True


# ── Direct internal targets ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "url",
    [
        # loopback / unspecified
        "http://127.0.0.1",
        "http://127.0.0.1:8000/health",
        "http://localhost",
        "http://0.0.0.0",
        # cloud metadata (link-local)
        "http://169.254.169.254/latest/meta-data/",
        # private ranges (RFC 1918) and carrier-grade NAT
        "http://10.0.0.1",
        "http://172.18.0.3",
        "http://192.168.1.1",
        "http://100.64.0.1",
        # IPv6: loopback, IPv4-mapped loopback, unique-local, link-local
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://[fd00::1]",
        "http://[fe80::1]",
        # alternative IPv4 notations for 127.0.0.1
        "http://2130706433",
        "http://0x7f000001",
        "http://0177.0.0.1",
        # service names from docker compose / Kubernetes
        "http://prometheus:9090",
        "http://grafana:3000/login",
        "http://api:8000/metrics",
        "http://kubernetes.default.svc",
        # DNS records that point at private space
        "http://internal.example",
        "http://mixed.example",
    ],
)
def test_internal_targets_are_blocked(net, url):
    resp = scan(url)
    assert_blocked(resp)
    assert net.requests == [], "a request was sent to an internal target"


@pytest.mark.parametrize(
    "url",
    [
        "http://public.example:8080",
        "http://public.example:22",
        "https://public.example:8443",
    ],
)
def test_non_web_ports_are_blocked(net, url):
    resp = scan(url)
    assert_blocked(resp)
    assert net.requests == []


# ── Redirect-based bypasses ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://prometheus:9090/api/v1/targets",
        "http://[::1]/",
        "http://2130706433/",
        "http://public.example:9090/",
        "ftp://public.example/file",
    ],
)
def test_redirect_to_internal_target_is_blocked(net, location):
    net.routes["redirector.example"] = lambda req: httpx.Response(
        302, headers={"location": location}
    )
    resp = scan("http://redirector.example")
    assert_blocked(resp)
    # Only the first (public) hop may have been contacted.
    assert net.hosts_requested() == ["redirector.example"]


def test_redirect_chain_is_capped(net):
    net.routes["loop.example"] = lambda req: httpx.Response(
        302, headers={"location": f"http://loop.example/{len(net.requests)}"}
    )
    resp = scan("http://loop.example")
    assert resp.status_code == 400
    assert "too many redirects" in resp.json()["detail"].lower()
    assert len(net.requests) <= 6  # first request + at most 5 redirects


# ── DNS rebinding ──────────────────────────────────────────────────────────
def test_connection_goes_to_the_validated_ip(net):
    """We must dial the IP we validated, not re-resolve the hostname."""
    resp = scan("https://public.example/path?q=1")
    assert resp.status_code == 200
    (request,) = net.requests
    assert request.url.host == PUBLIC_IP
    assert request.url.path == "/path"
    assert request.headers["host"] == "public.example"
    # TLS must still be negotiated and verified for the hostname.
    assert request.extensions.get("sni_hostname") == "public.example"


def test_dns_rebinding_cannot_reach_loopback(net):
    """First lookup is public (passes validation), later lookups say 127.0.0.1."""
    answers = iter([[PUBLIC_IP]])
    net.dns["rebind.example"] = lambda: next(answers, ["127.0.0.1"])
    resp = scan("http://rebind.example")
    assert resp.status_code == 200
    assert [r.url.host for r in net.requests] == [PUBLIC_IP]


# ── Resource limits ────────────────────────────────────────────────────────
class _ExplodingBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise AssertionError("response body was downloaded")
        yield b""  # pragma: no cover


def test_response_body_is_never_downloaded(net):
    """Only headers are graded, so a huge body must not be read at all."""
    net.routes["bigbody.example"] = lambda req: httpx.Response(
        200, headers=SECURE_HEADERS, stream=_ExplodingBody()
    )
    resp = scan("https://bigbody.example")
    assert resp.status_code == 200
    assert resp.json()["grade"] == "A"


# ── Observability ──────────────────────────────────────────────────────────
def _blocked_total() -> float:
    return REGISTRY.get_sample_value("secscan_blocked_targets_total") or 0.0


def test_blocked_target_is_counted_and_logged(net, caplog):
    before = _blocked_total()
    with caplog.at_level(logging.WARNING):
        assert_blocked(scan("http://169.254.169.254/latest/meta-data/"))
    assert _blocked_total() == before + 1
    assert any("blocked target" in r.getMessage().lower() for r in caplog.records)


# ── Legitimate scans must keep working (guards against over-blocking) ──────
def test_public_target_is_scanned(net):
    resp = scan("https://public.example")
    assert resp.status_code == 200
    body = resp.json()
    assert body["grade"] == "A"
    assert body["url"] == "https://public.example"


def test_public_redirects_are_followed(net):
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://public.example/"})
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/home"})  # relative
        return httpx.Response(200, headers=SECURE_HEADERS)

    net.routes["public.example"] = route
    resp = scan("http://public.example")
    assert resp.status_code == 200
    assert resp.json()["grade"] == "A"
    assert [r.url.path for r in net.requests] == ["/", "/", "/home"]


def test_redirect_to_another_public_host_is_followed(net):
    net.routes["public.example"] = lambda req: httpx.Response(
        302, headers={"location": "https://other.example/"}
    )
    resp = scan("https://public.example")
    assert resp.status_code == 200
    assert net.hosts_requested() == ["public.example", "other.example"]


def test_unresolvable_host_is_a_plain_400(net):
    resp = scan("http://does-not-exist.example")
    assert resp.status_code == 400
