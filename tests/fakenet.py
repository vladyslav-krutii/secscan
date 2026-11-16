"""A fake internet for tests: no test may touch the real network.

  * DNS is faked by patching ``socket.getaddrinfo`` (see ``FAKE_DNS``).
  * HTTP is faked with ``httpx.MockTransport``; every request that reaches the
    "wire" is recorded in ``FakeNet.requests``.

The fake internet answers 200 for ANY host, so an unprotected scanner happily
"reaches" internal targets -- which is exactly what the SSRF tests pin down.
"""

from __future__ import annotations

import ipaddress
import socket

import httpx

PUBLIC_IP = "93.184.216.34"

# hostname -> list of IPs the fake resolver returns.
FAKE_DNS: dict[str, list[str]] = {
    "public.example": [PUBLIC_IP],
    "other.example": ["93.184.216.35"],
    "redirector.example": [PUBLIC_IP],
    "loop.example": [PUBLIC_IP],
    "bigbody.example": [PUBLIC_IP],
    "rebind.example": [PUBLIC_IP],
    # Names that only exist inside docker compose / Kubernetes.
    "localhost": ["127.0.0.1"],
    "prometheus": ["172.18.0.3"],
    "grafana": ["172.18.0.4"],
    "api": ["172.18.0.2"],
    "kubernetes.default.svc": ["10.96.0.1"],
    # A public-looking name whose DNS record points at a private address.
    "internal.example": ["10.0.0.5"],
    # Several A records, one of them private.
    "mixed.example": [PUBLIC_IP, "10.0.0.5"],
    # Alternative IPv4 notations: the OS resolver (inet_aton) turns all of
    # these into 127.0.0.1, so the fake resolver does the same.
    "2130706433": ["127.0.0.1"],
    "0x7f000001": ["127.0.0.1"],
    "0177.0.0.1": ["127.0.0.1"],
}

SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
}


class FakeNet:
    def __init__(self) -> None:
        # hostname -> list of IPs, or a callable returning one (called on
        # every lookup, in the resolver thread -- it may block to act slow).
        self.dns: dict = dict(FAKE_DNS)
        self.dns_lookups: list[str] = []
        self.requests: list[httpx.Request] = []
        self.routes: dict = {}  # hostname -> callable(request) -> httpx.Response

    def hosts_requested(self) -> list[str]:
        """Hostnames (from the Host header) that actually received a request."""
        return [host_of(r) for r in self.requests]


def host_of(request: httpx.Request) -> str:
    # The Host header is what the remote server sees, whatever IP we dialled.
    return httpx.URL(f"http://{request.headers['host']}").host


def install(monkeypatch) -> FakeNet:
    """Replace DNS and HTTP with the fake internet for one test."""
    fake = FakeNet()

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if isinstance(host, bytes):
            host = host.decode()
        fake.dns_lookups.append(host)
        answers = fake.dns.get(host)
        if callable(answers):
            answers = answers()
        if answers is None:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known") from None
            answers = [host]
        result = []
        for ip in answers:
            if ":" in ip:
                result.append(
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port or 0, 0, 0))
                )
            else:
                result.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)))
        return result

    def handler(request: httpx.Request) -> httpx.Response:
        fake.requests.append(request)
        route = fake.routes.get(host_of(request))
        if route is not None:
            return route(request)
        # Default: the "internet" answers 200 to anything, like an internal
        # service would if the scanner were allowed to reach it.
        return httpx.Response(200, headers=SECURE_HEADERS)

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)
    return fake
