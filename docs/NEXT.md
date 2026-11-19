# Next session: Phase 4 slice 2, SBOM + image signing

**Phase 4 slice 1 is done** (c29a066 … f3ee57b): actions pinned by SHA,
least-privilege `permissions:`, Gitleaks, Semgrep, pip-audit, Trivy 0.76.2
with SARIF upload; FastAPI 0.165.0 / Starlette 1.10; base image pinned by
digest, no pip/setuptools in the runtime image. Study notes: `docs/LEARNING.md`
(append an entry after every commit).

## Slice 2 plan

- SBOM with Syft (SPDX or CycloneDX JSON) for the pushed image; upload as a
  build artifact and attach it to the image as an attestation.
- Sign the image by digest with Cosign keyless (GitHub OIDC,
  `id-token: write` only in that job) and attest the SBOM.
- Verify in CI: `cosign verify` / `cosign verify-attestation` with
  `--certificate-identity` (this workflow) and
  `--certificate-oidc-issuer https://token.actions.githubusercontent.com`.
- Push by digest, not only by tag; sign what was scanned.
- Check current stable Syft/Cosign versions; pin actions/images by SHA/digest.

## Live check (needs Docker Desktop running)

Not done after the FastAPI 0.165.0 / Starlette 1.10 bump yet:

```powershell
cd C:\Users\vkryt\Cybersecurity\secscan; docker compose up -d --build; Start-Sleep 10; Invoke-RestMethod "http://localhost:8000/scan?url=https://github.com" | Select-Object score, grade
cd C:\Users\vkryt\Cybersecurity\secscan; 1..12 | ForEach-Object { (curl.exe -s -o NUL -w "%{http_code} " "http://localhost:8000/scan?url=https://example.com") }
```

Expected: a grade for github.com; the burst shows 200s, then 429 after ~10
requests (slowapi 0.1.10 on Starlette 1.10 at runtime, not only in tests).

## Open items from slice 1

- zlib1g CVE-2026-85091 (HIGH): **accepted until 2026-12-10** (`.trivyignore`
  with `exp:`, SECURITY.md "Accepted risks"). Before that date: merge the
  Dependabot base-image digest bump if the rebuilt image has the fix, then
  delete the ignore entry; otherwise re-review and extend with a reason.
- Starlette warns that `starlette.testclient` with `httpx` is deprecated
  (use `httpx2`); tests still pass.
- Python 3.15 base image (closed Dependabot #13): revisit separately.

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
