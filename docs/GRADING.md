# Grading

Each header has a weight (sum = 100) and is graded by its **value**, not
just its presence (pure functions in `app/rules.py`, unit-tested in
`tests/test_rules.py` and `tests/test_grading.py`). In the response,
`points` is what a header earned and `issues` explains every lost point.
Grade: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F.

```bash
curl "http://localhost:8000/scan?url=https://github.com"
```

```json
{
  "url": "https://github.com",
  "status_code": 200,
  "score": 83,
  "grade": "B",
  "headers": [
    {
      "name": "strict-transport-security", "present": true,
      "value": "max-age=31536000", "advice": null, "points": 20,
      "issues": ["HSTS lacks includeSubDomains: subdomains can be downgraded."]
    }
  ]
}
```

(Shortened: the real response lists all six headers. Scores change when
sites change their headers; github.com was B / 83 on 2026-11-21.)

| Header | Full points | Partial / none |
|---|---|---|
| HSTS (25) | `max-age` ≥ 180 days + `includeSubDomains` | shorter `max-age` or no `includeSubDomains` = partial; `max-age=0` / invalid = 0 |
| CSP (25) | no unsafe sources, has `default-src` | penalties for `'unsafe-inline'` (ignored with a nonce/hash), `'unsafe-eval'`, bare `*`, missing `default-src` / `object-src` |
| X-Frame-Options (15) | `DENY` / `SAMEORIGIN`, **or** CSP `frame-ancestors` without `*` (it supersedes XFO, so XFO may be absent) | `ALLOW-FROM` (obsolete) = partial; anything else or `frame-ancestors *` = 0 |
| X-Content-Type-Options (15) | exactly `nosniff` | anything else = 0 |
| Referrer-Policy (10) | `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin` | `origin*` = partial; `unsafe-url`, `no-referrer-when-downgrade` = low. In a comma list the last known value wins, like in the browser |
| Permissions-Policy (10) | restricts `camera`, `microphone` and `geolocation` (not `*`) | each one left open costs points; empty/permissive = partial |

## Known simplifications

- Repeated headers: httpx joins them with `, `. Several CSPs are all enforced
  by the browser, but they are parsed here as one policy; a joined HSTS or
  XFO value fails parsing and scores 0 (conservative).
- CSP: `'strict-dynamic'`, scheme sources (`https:`, `data:`) and the exact
  `script-src` → `default-src` fallback are not evaluated; scheme sources in
  `frame-ancestors` count as restricted.
- `Content-Security-Policy-Report-Only` is ignored (it enforces nothing).
- Permissions-Policy only checks camera, microphone and geolocation.
- Penalty values are my own judgement (named constants in `app/rules.py`),
  not taken from a standard.
