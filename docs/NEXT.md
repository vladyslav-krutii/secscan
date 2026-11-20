# Next session: Phase 5, Kubernetes hardening

**Phase 4 is done.**
- Slice 1 (c29a066 … 590b6e1): SHA pins, least-privilege `permissions:`,
  Gitleaks, Semgrep, pip-audit, Trivy SARIF, base image pinned by digest.
- Slice 2 (7021aed): Syft SPDX SBOM, Cosign keyless signing and SBOM
  attestation by digest, verified in CI (`sbom-sign` job, the only one with
  `id-token: write`).

Study notes are in `docs/LEARNING.md`; add an entry after every commit.

## Phase 5 plan (draft, confirm at the start)

- NetworkPolicy: default deny; ingress to the API only from the ingress
  controller. Egress: DNS plus 80/443 to the internet, but no pod or service
  CIDRs and no cloud metadata (169.254.169.254). This is a second SSRF layer
  under the app-level guard.
- After that, narrow `SECSCAN_TRUSTED_PROXIES` to the ingress controller.
- Pod Security Admission `restricted` on the namespace. Keep: seccomp
  `RuntimeDefault`, `automountServiceAccountToken: false`, resource limits.
- Deploy by digest, not by `latest`. Optional: admission check of the Cosign
  signature (Kyverno or the sigstore policy-controller) in kind.
- kind needs a CNI that enforces NetworkPolicy (Calico or Cilium); the
  default kindnet does not.

## Known simplifications in slice 2

- Trivy scans the locally loaded build, then the push step rebuilds from the
  same GHA cache. The image is the same, but the digest that gets signed is
  the pushed one, not the one that was scanned. A stricter version would
  push once, then scan and sign that exact digest.
- No SLSA build provenance yet (`actions/attest-build-provenance`).

## Live check: done 2026-11-20

After the FastAPI 0.165.0 / Starlette 1.10 bump, on the compose stack:
github.com scored 83 (grade B); a 12-request burst gave 200×8 then 429×4
(two earlier requests in the same minute also counted against 10/minute);
Grafana "Abuse protection & SSRF guard": Rate limited (429) = 4, Total
scans = 11, errors 0; three requests to `http://prometheus` returned 400 and
Blocked targets (SSRF) = 3 (screenshot `docs/grafana-abuse.png`). Grafana's
host port is now `${GRAFANA_PORT:-3000}` (3000 was taken by another
container).

## Open items from Phase 4

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
