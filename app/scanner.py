"""Core scanning logic: fetch a URL and grade its HTTP security headers."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import httpx

from .config import settings

# ── SSRF guard settings ────────────────────────────────────────────────────
ALLOWED_PORTS = frozenset({80, 443})
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 5
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DNS_TIMEOUT = 5.0

# Globally routable IPv6 prefixes that merely wrap an IPv4 address (NAT64,
# 6to4). ``is_global`` is true for them, yet a gateway could deliver the
# packet to the embedded -- possibly private -- IPv4 address.
_IPV4_EMBEDDING_NETS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Each check: header name -> (weight, short advice shown when missing).
# Weights sum to 100 so the raw score is already a percentage.
SECURITY_HEADERS: dict[str, tuple[int, str]] = {
    "strict-transport-security": (25, "Add HSTS to force HTTPS."),
    "content-security-policy": (25, "Add a CSP to limit resource origins."),
    "x-frame-options": (15, "Add X-Frame-Options to prevent clickjacking."),
    "x-content-type-options": (15, "Add 'nosniff' to stop MIME sniffing."),
    "referrer-policy": (10, "Add Referrer-Policy to control referrers."),
    "permissions-policy": (10, "Add Permissions-Policy to gate browser APIs."),
}


@dataclass
class HeaderResult:
    name: str
    present: bool
    value: str | None
    advice: str | None


@dataclass
class ScanResult:
    url: str
    status_code: int
    score: int
    grade: str
    headers: list[HeaderResult] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "score": self.score,
            "grade": self.grade,
            "headers": [h.__dict__ for h in self.headers],
        }


class ScanError(Exception):
    """Raised when the target cannot be scanned (bad URL, network error)."""


class BlockedTargetError(ScanError):
    """Raised when the SSRF guard refuses a destination.

    ``str(exc)`` is safe to show to the client; ``reason`` carries the detail
    (e.g. the resolved internal IP) and is meant for server-side logs only.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class ScanDeadlineError(ScanError):
    """Raised when the whole scan (all DNS lookups and redirect hops) takes
    longer than the configured deadline."""


@dataclass(frozen=True)
class _Hop:
    """One validated request: where to connect and what to say."""

    pinned_url: str  # same URL, but the host is replaced by the validated IP
    host_header: str
    sni_hostname: str | None  # hostname for TLS SNI + certificate check


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def validate_url(url: str) -> str:
    """Only allow http(s) URLs with a host. Keeps the scanner from being
    pointed at arbitrary schemes (file://, etc.)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ScanError("URL must start with http:// or https:// and have a host")
    return url


def is_public_ip(ip: IPAddress) -> bool:
    """Allowlist check: only globally routable unicast addresses pass.

    ``is_global`` follows the IANA special-purpose registries, so loopback,
    RFC 1918, link-local (169.254.0.0/16 -- cloud metadata), CGNAT
    (100.64.0.0/10), unique-local (fc00::/7), documentation and reserved
    ranges are all rejected without us keeping a blocklist up to date.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:  # ::ffff:127.0.0.1 is really 127.0.0.1
            ip = ip.ipv4_mapped
        elif any(ip in net for net in _IPV4_EMBEDDING_NETS):
            return False
    return ip.is_global and not ip.is_multicast


async def _resolve(host: str, port: int) -> list[IPAddress]:
    """Resolve ``host`` with the OS resolver (also normalises forms such as
    ``2130706433`` or ``0x7f000001`` into a real address)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), DNS_TIMEOUT
        )
    except (OSError, UnicodeError, TimeoutError) as exc:
        raise ScanError(f"Could not resolve host {host!r}") from exc
    ips: list[IPAddress] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])  # drop IPv6 zone id
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ScanError(f"Could not resolve host {host!r}")
    return ips


async def _validate_hop(url: str, *, is_redirect: bool) -> _Hop:
    """Check one URL (the user's or a redirect target) and pin it to an IP."""
    where = "redirect target" if is_redirect else "destination"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ScanError(f"Invalid URL: {exc}") from exc

    if parts.scheme not in DEFAULT_PORTS:
        raise BlockedTargetError(
            f"Blocked target: {where} must use http or https",
            reason=f"scheme {parts.scheme!r}",
        )
    host = parts.hostname
    if not host:
        raise ScanError("URL must include a host")
    if parts.username is not None or parts.password is not None:
        raise ScanError("URLs with embedded credentials are not supported")
    port = port or DEFAULT_PORTS[parts.scheme]
    if port not in ALLOWED_PORTS:
        raise BlockedTargetError(
            f"Blocked target: {where} port is not allowed (only 80 and 443)",
            reason=f"port {port}",
        )

    ips = await _resolve(host, port)
    for ip in ips:
        # One bad record is enough: we never pick "the good one" from a mix.
        if not is_public_ip(ip):
            raise BlockedTargetError(
                f"Blocked target: {where} is not a public internet address",
                reason=f"{host} resolves to {ip}",
            )
    ip = ips[0]

    # Connect to the IP we just validated instead of letting the HTTP client
    # resolve the name again (a second lookup could return a different,
    # internal address -- DNS rebinding).
    default_port = port == DEFAULT_PORTS[parts.scheme]
    ip_host = f"[{ip}]" if ip.version == 6 else str(ip)
    name_host = f"[{host}]" if ":" in host else host
    pinned_url = urlunsplit(
        (
            parts.scheme,
            ip_host if default_port else f"{ip_host}:{port}",
            parts.path or "/",
            parts.query,
            "",
        )
    )
    try:
        ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False
    return _Hop(
        pinned_url=pinned_url,
        host_header=name_host if default_port else f"{name_host}:{port}",
        sni_hostname=host if parts.scheme == "https" and not is_ip_literal else None,
    )


async def _fetch_headers(
    client: httpx.AsyncClient, hop: _Hop
) -> tuple[int, dict[str, str]]:
    extensions = {"sni_hostname": hop.sni_hostname} if hop.sni_hostname else {}
    # stream(): take the status line and headers, never download the body.
    async with client.stream(
        "GET",
        hop.pinned_url,
        headers={"Host": hop.host_header, "User-Agent": "SecScan/1.0"},
        extensions=extensions,
    ) as resp:
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}


async def scan_url(
    url: str, timeout: float = 5.0, deadline: float | None = None
) -> ScanResult:
    """Fetch ``url`` and score the security headers on the response.

    Redirects are followed by hand (at most ``MAX_REDIRECTS``) so that every
    hop goes through the same SSRF checks as the original URL.

    ``timeout`` limits each network operation of a single hop; ``deadline``
    (default: ``settings.scan_deadline_seconds``) limits the scan as a whole.
    """
    validate_url(url)
    if deadline is None:
        deadline = settings.scan_deadline_seconds
    current = url
    try:
        # One clock for the whole scan. Per-hop timeouts alone add up to
        # (MAX_REDIRECTS + 1) x (DNS + connect + read) for a slow target.
        # When it fires, the task is cancelled wherever it is waiting and the
        # ``async with`` blocks below close the stream and the client.
        async with asyncio.timeout(deadline):
            # trust_env=False: ignore HTTP(S)_PROXY / .netrc from the
            # environment, a proxy would bypass the pinned IP.
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=False, trust_env=False
            ) as client:
                for hop_number in range(MAX_REDIRECTS + 1):
                    hop = await _validate_hop(current, is_redirect=hop_number > 0)
                    status_code, present = await _fetch_headers(client, hop)
                    location = present.get("location")
                    if status_code in REDIRECT_STATUSES and location:
                        current = urljoin(current, location)
                        continue
                    break
                else:
                    raise ScanError(f"Too many redirects (limit is {MAX_REDIRECTS})")
    except TimeoutError as exc:
        raise ScanDeadlineError(f"Scan exceeded the {deadline:g} s deadline") from exc
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        raise ScanError(f"Request failed: {exc}") from exc

    results: list[HeaderResult] = []
    score = 0
    for header, (weight, advice) in SECURITY_HEADERS.items():
        value = present.get(header)
        if value is not None:
            score += weight
            results.append(HeaderResult(header, True, value, None))
        else:
            results.append(HeaderResult(header, False, None, advice))

    return ScanResult(
        url=url,
        status_code=status_code,
        score=score,
        grade=_grade(score),
        headers=results,
    )
