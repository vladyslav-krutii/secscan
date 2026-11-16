"""Prometheus metrics for the SecScan API."""

from prometheus_client import Counter, Histogram

SCANS_TOTAL = Counter(
    "secscan_scans_total",
    "Total number of completed scans, labelled by resulting grade.",
    ["grade"],
)

SCAN_ERRORS_TOTAL = Counter(
    "secscan_scan_errors_total",
    "Total number of scans that failed before producing a grade.",
)

BLOCKED_TARGETS_TOTAL = Counter(
    "secscan_blocked_targets_total",
    "Scans refused by the SSRF guard (internal address, port or redirect).",
)

SCAN_DURATION = Histogram(
    "secscan_scan_duration_seconds",
    "Time spent scanning a target URL.",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
