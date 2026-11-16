"""Abuse protection for /scan: who the client is, how often it may scan and
how many scans run at once."""

from __future__ import annotations

import ipaddress
import math
import time

from slowapi import Limiter
from starlette.requests import Request

from .config import settings


def _is_trusted_proxy(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in settings.trusted_proxies)


def client_ip(request: Request) -> str:
    """The address rate limiting is keyed on.

    The TCP peer is the only address that cannot be forged, so it is the
    default. X-Forwarded-For is read only when the peer is one of our own
    proxies (``SECSCAN_TRUSTED_PROXIES``); otherwise any client could pick a
    fresh identity per request by sending the header itself.

    A proxy APPENDS the address it received the request from, so the list is
    walked right to left and the first entry that is not one of our proxies
    is the client. Entries further left were supplied by the client.
    """
    peer = request.client.host if request.client else "unknown"
    if not _is_trusted_proxy(peer):
        return peer
    # A header may be repeated; joined in order it is one comma-separated list.
    forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
    for entry in reversed(forwarded.split(",")):
        entry = entry.strip()
        try:
            ip = ipaddress.ip_address(entry)
        except ValueError:
            break  # garbage in the chain: stop trusting it
        if not _is_trusted_proxy(entry):
            return str(ip)
    return peer


# In-memory counters: per process, lost on restart (see README, known limits).
# moving-window: no double burst at the edge of a fixed window.
limiter = Limiter(key_func=client_ip, strategy="moving-window")


def retry_after_seconds(request: Request) -> int:
    """Seconds until the client's rate-limit window frees up (at least 1)."""
    try:
        item, args = request.state.view_rate_limit
        reset_at = limiter.limiter.get_window_stats(item, *args)[0]
        return max(1, math.ceil(reset_at - time.time()))
    except Exception:  # never let a header calculation turn a 429 into a 500
        return 60


class ScanSlots:
    """Cap on scans running at once -- a semaphore that never waits.

    When every slot is taken the request is refused immediately instead of
    queued: a queue would keep connections open and let a client pile up work
    for later. No lock is needed because the event loop runs one coroutine
    at a time and there is no ``await`` between the check and the increment.
    """

    def __init__(self) -> None:
        self.in_use = 0

    def try_acquire(self) -> bool:
        if self.in_use >= settings.max_concurrent_scans:
            return False
        self.in_use += 1
        return True

    def release(self) -> None:
        self.in_use -= 1


scan_slots = ScanSlots()
