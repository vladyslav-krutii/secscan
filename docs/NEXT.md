# Next session: Phase 4, supply-chain CI

**Phase 3 (value-based grading) is done.** All six headers are graded by value
in `app/rules.py` (pure functions → `(credit 0..1, issues)`); `/scan` returns
`points` and `issues` per header; X-Frame-Options also looks at CSP
`frame-ancestors`, which supersedes it.

## Phase 4 plan

- Pin every GitHub Action by full commit SHA (with a `# vX.Y.Z` comment);
  this also fixes the "Node 20 actions are deprecated" warnings.
- Least-privilege `permissions:` per job (default `contents: read`).
- SAST: Semgrep; secrets: Gitleaks; dependencies: pip-audit / OSV-Scanner.
- Trivy image scan with SARIF upload to GitHub code scanning.
- SBOM with Syft, attach to the image; sign image + SBOM attestation with
  Cosign (keyless, OIDC) and verify the signature in CI.
- Check current stable versions/syntax of every tool before using it.

## Known simplifications left from Phase 3 (fine for now)

- Repeated headers: httpx joins them with `, `. Several CSPs are all enforced
  in the browser, but we parse the joined string as one policy; a joined HSTS
  or XFO value fails parsing and scores 0 (conservative).
- CSP: `'strict-dynamic'`, scheme sources (`https:`, `data:`) and exact
  `script-src` → `default-src` fallback are not evaluated; scheme sources in
  `frame-ancestors` (e.g. `https:`) count as restricted.
- `Content-Security-Policy-Report-Only` is ignored (it enforces nothing).
- Permissions-Policy only checks camera / microphone / geolocation.
- Penalty values are our own judgement (named constants in `app/rules.py`),
  not from a standard.
