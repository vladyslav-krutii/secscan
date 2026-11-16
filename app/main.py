"""SecScan API — FastAPI application entrypoint.

Endpoints:
  GET /          service metadata
  GET /health    liveness/readiness probe
  GET /scan      scan a URL's security headers  (?url=https://example.com)
  GET /metrics   Prometheus exposition format
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field
from slowapi.errors import RateLimitExceeded

from . import __version__
from .abuse import client_ip, limiter, retry_after_seconds, scan_slots
from .config import settings
from .metrics import (
    BLOCKED_TARGETS_TOTAL,
    BUSY_REJECTIONS_TOTAL,
    RATE_LIMITED_TOTAL,
    SCAN_DEADLINE_EXCEEDED_TOTAL,
    SCAN_DURATION,
    SCAN_ERRORS_TOTAL,
    SCANS_TOTAL,
)
from .scanner import BlockedTargetError, ScanDeadlineError, ScanError, scan_url


# ── Structured JSON logging (one JSON object per line; Loki/ELK friendly) ──
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.__dict__.get("extra_fields"):
            payload.update(record.__dict__["extra_fields"])
        return json.dumps(payload, ensure_ascii=False)


def _configure_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    return logging.getLogger("secscan")


log = _configure_logging()


# ── API response models (power the auto-generated OpenAPI docs) ────────────
class ServiceInfo(BaseModel):
    name: str = "SecScan"
    version: str
    description: str
    docs: str = "/docs"
    example: str = "/scan?url=https://github.com"


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str


class HeaderCheck(BaseModel):
    name: str
    present: bool
    value: str | None = None
    advice: str | None = None


class ScanResponse(BaseModel):
    url: str
    status_code: int
    score: int = Field(..., ge=0, le=100)
    grade: str = Field(..., examples=["A"])
    headers: list[HeaderCheck]


app = FastAPI(
    title="SecScan API",
    description=(
        "Scan a URL's HTTP security headers (HSTS, CSP, X-Frame-Options, …) "
        "and grade them **A–F**."
    ),
    version=__version__,
    license_info={"name": "MIT"},
    contact={"name": "Vladyslav Krutii", "url": "https://github.com/vladyslav-krutii"},
)

# Prometheus scrape endpoint.
app.mount("/metrics", make_asgi_app())

# slowapi looks the limiter up on app.state when a decorated route is called.
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    RATE_LIMITED_TOTAL.inc()
    retry_after = retry_after_seconds(request)
    log.warning(
        "rate limited",
        extra={
            "extra_fields": {
                "client_ip": client_ip(request),
                "limit": str(exc.detail),
                "retry_after_s": retry_after,
            }
        },
    )
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded ({exc.detail}). Retry later."},
        headers={"Retry-After": str(retry_after)},
    )


_STATIC = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
async def ui() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


@app.get("/info", response_model=ServiceInfo, tags=["meta"])
async def info() -> ServiceInfo:
    return ServiceInfo(
        version=__version__,
        description="Security headers scanner API.",
    )


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


class ErrorResponse(BaseModel):
    detail: str


@app.get(
    "/scan",
    response_model=ScanResponse,
    tags=["scan"],
    responses={
        400: {"model": ErrorResponse, "description": "Bad, unreachable or blocked target"},
        429: {"model": ErrorResponse, "description": "Per-client rate limit exceeded"},
        503: {"model": ErrorResponse, "description": "Too many scans in progress"},
        504: {"model": ErrorResponse, "description": "Scan exceeded the overall deadline"},
    },
)
# Order of the gates: rate limit (this decorator, before the function body)
# -> scan slot -> SSRF validation -> request. Cheapest check first, and a
# request refused by an earlier gate never holds a slot.
@limiter.limit(lambda: settings.rate_limit)
async def scan(
    request: Request,  # required by the rate limiter
    url: str = Query(
        ...,
        description="Target URL to scan.",
        examples=["https://github.com"],
    ),
) -> ScanResponse:
    if not scan_slots.try_acquire():
        BUSY_REJECTIONS_TOTAL.inc()
        log.warning(
            "scan rejected: busy",
            extra={"extra_fields": {"url": url, "client_ip": client_ip(request)}},
        )
        raise HTTPException(
            status_code=503,
            detail="Server is busy: too many scans in progress. Retry shortly.",
            headers={"Retry-After": "1"},
        )

    start = time.perf_counter()
    try:
        result = await scan_url(url)
    except BlockedTargetError as exc:
        BLOCKED_TARGETS_TOTAL.inc()
        # The reason (e.g. the internal IP a name resolved to) stays in the
        # log; the client only gets the generic message.
        log.warning(
            "blocked target",
            extra={"extra_fields": {"url": url, "reason": exc.reason}},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScanDeadlineError as exc:
        SCAN_DEADLINE_EXCEEDED_TOTAL.inc()
        log.warning(
            "scan deadline exceeded",
            extra={
                "extra_fields": {
                    "url": url,
                    "client_ip": client_ip(request),
                    "deadline_s": settings.scan_deadline_seconds,
                }
            },
        )
        # 504: we act as a gateway to the target and it did not answer in time.
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except ScanError as exc:
        SCAN_ERRORS_TOTAL.inc()
        log.warning(
            "scan failed",
            extra={"extra_fields": {"url": url, "error": str(exc)}},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        # Runs on success, on every error above and on cancellation (client
        # went away), so a slot can never leak.
        scan_slots.release()

    elapsed = time.perf_counter() - start
    SCAN_DURATION.observe(elapsed)
    SCANS_TOTAL.labels(grade=result.grade).inc()
    log.info(
        "scan completed",
        extra={
            "extra_fields": {
                "url": url,
                "grade": result.grade,
                "score": result.score,
                "duration_s": round(elapsed, 3),
            }
        },
    )
    return ScanResponse(**result.as_dict())
