"""Runtime configuration, read once from environment variables.

Every knob has a safe default, so the service is protected even when nothing
is configured. A value that cannot be parsed stops the process at start-up:
silently falling back to a default would hide a typo in a security setting.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass

import limits

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Settings:
    # Scans allowed per client IP, in the "limits" notation ("10/minute").
    rate_limit: str = "10/minute"
    # Peers whose X-Forwarded-For header we believe (the Ingress controller).
    # Empty: believe nobody and always use the address of the TCP peer.
    trusted_proxies: tuple[IPNetwork, ...] = ()
    # Wall-clock budget for one scan: every DNS lookup and redirect hop.
    scan_deadline_seconds: float = 10.0
    # Outbound scans this process runs at the same time.
    max_concurrent_scans: int = 10


def _networks(name: str, raw: str) -> tuple[IPNetwork, ...]:
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"{name}: {item!r} is not an IP address or CIDR") from exc
    return tuple(networks)


def _rate_limit(name: str, raw: str) -> str:
    try:
        limits.parse_many(raw)
    except ValueError as exc:
        raise ValueError(f"{name}: {raw!r} is not a rate limit such as '10/minute'") from exc
    return raw


def _positive(name: str, raw: str, kind: type) -> float | int:
    try:
        value = kind(raw)
    except ValueError as exc:
        raise ValueError(f"{name}: {raw!r} is not a valid {kind.__name__}") from exc
    if not value > 0:
        raise ValueError(f"{name}: must be greater than 0, got {raw!r}")
    return value


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    defaults = Settings()
    return Settings(
        rate_limit=_rate_limit(
            "SECSCAN_RATE_LIMIT", env.get("SECSCAN_RATE_LIMIT", defaults.rate_limit)
        ),
        trusted_proxies=_networks(
            "SECSCAN_TRUSTED_PROXIES", env.get("SECSCAN_TRUSTED_PROXIES", "")
        ),
        scan_deadline_seconds=_positive(
            "SECSCAN_SCAN_DEADLINE_SECONDS",
            env.get("SECSCAN_SCAN_DEADLINE_SECONDS", str(defaults.scan_deadline_seconds)),
            float,
        ),
        max_concurrent_scans=_positive(
            "SECSCAN_MAX_CONCURRENT_SCANS",
            env.get("SECSCAN_MAX_CONCURRENT_SCANS", str(defaults.max_concurrent_scans)),
            int,
        ),
    )


settings = load_settings()
