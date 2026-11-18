"""Value-based rules for security headers.

Pure functions, no network: each takes the raw header value and returns
``(credit, issues)`` where ``credit`` is the share of the header's weight it
earns (0.0-1.0) and ``issues`` explains every lost point. Weights stay in
``scanner.SECURITY_HEADERS``, so a rule never needs to know them.

Headers without a rule here are still graded on presence only.
"""

from __future__ import annotations

from collections.abc import Callable

RuleResult = tuple[float, list[str]]

# ── HSTS (RFC 6797) ────────────────────────────────────────────────────────
# 180 days: the minimum the HSTS preload list and most scanners accept.
HSTS_MIN_MAX_AGE = 15_552_000
_HSTS_LONG = 0.8  # max-age >= 180 days
_HSTS_SHORT = 0.4  # 0 < max-age < 180 days: protects, but expires quickly
_HSTS_SUBDOMAINS = 0.2  # bonus: covers every subdomain, no cookie-injection gaps


def check_hsts(value: str) -> RuleResult:
    directives: dict[str, str] = {}
    for part in value.split(";"):
        name, _, arg = part.strip().partition("=")
        if name:
            directives.setdefault(name.strip().lower(), arg.strip().strip('"'))

    raw = directives.get("max-age")
    if raw is None or not raw.isdigit():
        return 0.0, ["HSTS has no valid max-age: browsers ignore the header."]
    max_age = int(raw)
    if max_age == 0:
        # max-age=0 is the documented way to make browsers FORGET the policy.
        return 0.0, ["HSTS max-age=0 disables HSTS."]

    issues: list[str] = []
    if max_age >= HSTS_MIN_MAX_AGE:
        credit = _HSTS_LONG
    else:
        credit = _HSTS_SHORT
        issues.append(
            f"HSTS max-age={max_age} is below {HSTS_MIN_MAX_AGE} (180 days)."
        )
    if "includesubdomains" in directives:
        credit += _HSTS_SUBDOMAINS
    else:
        issues.append("HSTS lacks includeSubDomains: subdomains can be downgraded.")
    return round(credit, 2), issues


# ── CSP (CSP Level 3) ──────────────────────────────────────────────────────
_CSP_UNSAFE_INLINE = 0.3  # inline <script> runs -> XSS mitigation is gone
_CSP_UNSAFE_EVAL = 0.2  # eval()/new Function() allowed
_CSP_WILDCARD = 0.3  # bare * = any origin (except data:/blob:)
_CSP_NO_DEFAULT_SRC = 0.25  # resource types without their own directive are open
_CSP_NO_OBJECT_SRC = 0.1  # plugins (<object>/<embed>) unrestricted

# A nonce or hash in the same directive makes CSP2+ browsers ignore
# 'unsafe-inline'; sites keep it only as a fallback for very old browsers.
_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def check_csp(value: str) -> RuleResult:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            # A repeated directive is ignored by browsers: first one wins.
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])

    if not directives:
        return 0.0, ["CSP is empty: it restricts nothing."]

    # A set, so a problem repeated in several directives is counted once.
    problems: set[str] = set()
    for sources in directives.values():
        has_nonce_or_hash = any(s.startswith(_NONCE_OR_HASH) for s in sources)
        if "'unsafe-inline'" in sources and not has_nonce_or_hash:
            problems.add("unsafe-inline")
        if "'unsafe-eval'" in sources:
            problems.add("unsafe-eval")
        if "*" in sources:
            problems.add("wildcard")

    penalty = 0.0
    issues: list[str] = []
    if "unsafe-inline" in problems:
        penalty += _CSP_UNSAFE_INLINE
        issues.append("CSP allows 'unsafe-inline': inline scripts can run (XSS).")
    if "unsafe-eval" in problems:
        penalty += _CSP_UNSAFE_EVAL
        issues.append("CSP allows 'unsafe-eval': eval() and similar are permitted.")
    if "wildcard" in problems:
        penalty += _CSP_WILDCARD
        issues.append("CSP uses a bare '*' source: content from any origin is allowed.")
    if "default-src" not in directives:
        penalty += _CSP_NO_DEFAULT_SRC
        issues.append("CSP has no default-src fallback for unlisted resource types.")
        if "object-src" not in directives:
            penalty += _CSP_NO_OBJECT_SRC
            issues.append("CSP leaves plugins open: add object-src 'none'.")

    return round(max(0.0, 1.0 - penalty), 2), issues


# header name (lower case) -> rule. Others are graded on presence only.
VALUE_RULES: dict[str, Callable[[str], RuleResult]] = {
    "strict-transport-security": check_hsts,
    "content-security-policy": check_csp,
}
