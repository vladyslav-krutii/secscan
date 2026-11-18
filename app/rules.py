"""Value-based rules for security headers.

Pure functions, no network: each takes the raw header value and returns
``(credit, issues)`` where ``credit`` is the share of the header's weight it
earns (0.0-1.0) and ``issues`` explains every lost point. Weights stay in
``scanner.SECURITY_HEADERS``, so a rule never needs to know them.

All six graded headers have a rule.
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


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Directive name -> source list, all lower case."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            # A repeated directive is ignored by browsers: first one wins.
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_csp(value: str) -> RuleResult:
    directives = _parse_csp(value)
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


# ── X-Frame-Options (RFC 7034) + CSP frame-ancestors ───────────────────────
_XFO_ALLOW_FROM = 0.3  # intent is there, but modern browsers ignore ALLOW-FROM

FRAME_ANCESTORS_NOTE = (
    "Not needed: CSP frame-ancestors protects against clickjacking "
    "and supersedes X-Frame-Options."
)


def check_x_frame_options(value: str | None, csp: str | None = None) -> RuleResult:
    """The only rule that needs a second header: when CSP has
    ``frame-ancestors``, browsers ignore X-Frame-Options entirely (CSP3), so
    that directive alone decides. ``value`` is None when XFO is missing."""
    frame_ancestors = _parse_csp(csp).get("frame-ancestors") if csp else None
    if frame_ancestors is not None:
        if "*" in frame_ancestors:
            return 0.0, [
                "CSP frame-ancestors '*' lets any origin frame the page "
                "(X-Frame-Options is ignored when frame-ancestors is set)."
            ]
        return 1.0, []

    if value is None:
        return 0.0, []
    normalized = value.strip().upper()
    if normalized in ("DENY", "SAMEORIGIN"):
        return 1.0, []
    if normalized.startswith("ALLOW-FROM"):
        return _XFO_ALLOW_FROM, [
            "X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers: "
            "use CSP frame-ancestors."
        ]
    return 0.0, [f"X-Frame-Options value {value.strip()!r} is invalid: browsers ignore it."]


# ── X-Content-Type-Options ─────────────────────────────────────────────────
def check_x_content_type_options(value: str) -> RuleResult:
    # "nosniff" is the only defined value; anything else is ignored.
    if value.strip().lower() == "nosniff":
        return 1.0, []
    return 0.0, [f"X-Content-Type-Options must be exactly 'nosniff', got {value.strip()!r}."]


# ── Referrer-Policy ────────────────────────────────────────────────────────
_REFERRER_PARTIAL = 0.6  # origin leaks to other sites, but not the path/query
_REFERRER_LEAKY = 0.2  # full URL (path + query, maybe tokens) leaks

_REFERRER_STRICT = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
_REFERRER_ORIGIN = {"origin", "origin-when-cross-origin"}
_REFERRER_FULL_URL = {"unsafe-url", "no-referrer-when-downgrade"}


def check_referrer_policy(value: str) -> RuleResult:
    # A comma list is a fallback chain: the browser applies the LAST token it
    # understands, so walk from the right.
    for token in reversed([t.strip().lower() for t in value.split(",")]):
        if token in _REFERRER_STRICT:
            return 1.0, []
        if token in _REFERRER_ORIGIN:
            return _REFERRER_PARTIAL, [
                f"Referrer-Policy '{token}' sends the origin to other sites."
            ]
        if token in _REFERRER_FULL_URL:
            return _REFERRER_LEAKY, [
                f"Referrer-Policy '{token}' leaks full URLs (path and query) to other sites."
            ]
    return 0.0, ["Referrer-Policy has no recognised value: the browser default applies."]


# ── Permissions-Policy ─────────────────────────────────────────────────────
SENSITIVE_FEATURES = ("camera", "microphone", "geolocation")
_PP_UNRESTRICTED_FEATURE = 0.15  # per sensitive feature left open (max 0.45)


def check_permissions_policy(value: str) -> RuleResult:
    # Structured-field dictionary: feature=(allowlist), feature=*, ...
    allowlists: dict[str, str] = {}
    for item in value.split(","):
        feature, sep, allowlist = item.partition("=")
        if sep:
            allowlists.setdefault(feature.strip().lower(), allowlist.strip())

    def restricted(feature: str) -> bool:
        allowlist = allowlists.get(feature)
        # Not listed = the browser default (usually self AND delegable to
        # iframes); '*' = every origin.
        return allowlist is not None and "*" not in allowlist.strip("()").split()

    unrestricted = [f for f in SENSITIVE_FEATURES if not restricted(f)]
    if not unrestricted:
        return 1.0, []
    credit = 1.0 - _PP_UNRESTRICTED_FEATURE * len(unrestricted)
    return round(credit, 2), [
        f"Permissions-Policy does not restrict {', '.join(unrestricted)}: "
        f"add e.g. {unrestricted[0]}=()."
    ]


# header name (lower case) -> rule taking that header's value. X-Frame-Options
# is not here: it also needs the CSP, so the scanner calls it directly.
VALUE_RULES: dict[str, Callable[[str], RuleResult]] = {
    "strict-transport-security": check_hsts,
    "content-security-policy": check_csp,
    "x-content-type-options": check_x_content_type_options,
    "referrer-policy": check_referrer_policy,
    "permissions-policy": check_permissions_policy,
}
