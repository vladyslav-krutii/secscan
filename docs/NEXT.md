# Next session: Phase 3, remaining headers

Done (slice 1): `app/rules.py` grades **HSTS** and **CSP** by value
(`check_hsts`, `check_csp` → `(credit 0..1, issues)`), wired in via
`VALUE_RULES`; responses carry `points` and `issues` per header.

Still presence-only — add a rule + unit tests for each:

- **X-Frame-Options**: only `DENY` / `SAMEORIGIN` count; `ALLOW-FROM` is
  obsolete (ignored by modern browsers). Full credit also when CSP has
  `frame-ancestors` (it supersedes XFO) — needs a rule that sees *both*
  headers, so the rule signature may need the whole header dict.
- **X-Content-Type-Options**: exactly `nosniff` (case-insensitive), else 0.
- **Referrer-Policy**: `no-referrer`, `same-origin`, `strict-origin`,
  `strict-origin-when-cross-origin` = full; `origin`,
  `origin-when-cross-origin` = partial; `unsafe-url`,
  `no-referrer-when-downgrade` = 0. Comma list: the last known token wins.
- **Permissions-Policy**: parse structured-field syntax; partial if only a few
  features are restricted, penalise `*` allowlists (e.g. `camera=*`).

Open points / known simplifications in slice 1:

- Repeated headers: httpx joins them with `, `. For CSP, several policies are
  all enforced (the strictest wins) but we parse the joined string as one;
  for HSTS a joined value fails `max-age` parsing → 0 (conservative).
- CSP: `'strict-dynamic'`, `http:`/`https:`/`data:` scheme sources and
  `script-src` vs `default-src` fallback precision are not evaluated yet.
- Consider `Content-Security-Policy-Report-Only`: report-only should earn 0
  but deserves an issue message ("not enforced").
- UI shows `issues`; maybe show `points/weight` too.
