# Project status: DONE (2026-11-21)

All six hardening phases are complete; `main` is green. Study notes for
every commit are in `docs/LEARNING.md`; the interview story in
`docs/INTERVIEW.md`; known limits and accepted risks in
`docs/THREAT_MODEL.md`.

| Phase | What | Commits |
|---|---|---|
| 1 | SSRF in `/scan`: allowlist, IP pinning, redirect re-validation, test-first | 453f7dc … 352f4a6 |
| 2 | Abuse protection: rate limit, concurrency cap, deadline, trusted proxies | cd5f592 … 18ea0c5 |
| 3 | Value-based header grading | 09e5db3 … 124ce1d |
| 4 | Supply chain: SHA/digest pins, Gitleaks, Semgrep, pip-audit, Trivy SARIF, SBOM, Cosign keyless | c29a066 … 3eb6331 |
| 5 | Kubernetes: build once, Kustomize by digest, PSA, NetworkPolicy, Kyverno signature check, verify script | d182d06 … 6ba221c |
| 6 | Presentation: README rewrite, docs split, threat model, interview notes, link check | b92aa91 … (this commit) |

**Phase 6 done.**
- b92aa91: deep dives moved to `docs/` (SSRF, ABUSE_PROTECTION, GRADING,
  KUBERNETES, new SUPPLY_CHAIN); stale statements fixed.
- ce3fc93: new test that the internal IP is logged but never returned
  (189 tests); `k8s-verify.sh` also checks the pod from inside (no SA token,
  read-only root FS, uid 10001): 14/14 PASS.
- 9a3c4d9: `docs/THREAT_MODEL.md`, STRIDE per trust boundary, 29 threats →
  control → where → evidence; accepted risks with revisit dates.
- 5253829: `docs/INTERVIEW.md` (Ukrainian): 3-minute story, 4 hardest
  findings, 20 Q&A, demo script.
- 82d63d7, a5229df: README for a 2-minute read with evidence links and an
  architecture diagram (Mermaid edge syntax fixed so it renders on GitHub).

**Link check (2026-11-21).** All relative links and `#anchors` in the 12
Markdown files resolve; badges, screenshots and all three Mermaid diagrams
render on github.com. External links are checked by the **Docs links**
workflow (`.github/workflows/docs.yml`, lychee, weekly + on Markdown change,
separate from CI so it never blocks a release). Its first run (e96d053)
found 4 broken links out of 146, all in LEARNING.md: a moved Starlette site
(now github.com/Kludex/starlette), an anchor I had invented on kyverno.io
and two fragments lychee cannot see; fixed in the next commit. The
Netlify-hosted docs (kind, sigstore, kyverno, …) that time out from my home
network are fine from GitHub's runners.

## Before 2026-12-10 (the only open deadline)

- zlib1g CVE-2026-85091 (HIGH) is **accepted until 2026-12-10**
  (`.trivyignore` with `exp:`, SECURITY.md "Accepted risks"). Merge the
  Dependabot base-image digest bump if the rebuilt image has the fix, delete
  the ignore entry, re-pin the k8s overlay (`make k8s-pin`). Otherwise
  re-review and extend with a reason. After the date Trivy reports it again
  in the Security tab (SARIF), but the build gate only fails on CRITICAL, so
  this does **not** break CI by itself: it has to be handled by hand.

## Other open items

- `starlette.testclient` with `httpx` is deprecated (use `httpx2`); tests
  still pass.
- Python 3.15 base image (closed Dependabot #13): revisit separately.

## Optional future extensions

| Idea | Why it is interesting |
|---|---|
| **GitHub Action / CLI** (`secscan https://…`, fail CI below grade B) | turns the scanner into a reusable shift-left gate for other repos |
| **TLS checks** (protocol versions, certificate expiry, weak ciphers) | headers are only half of transport security |
| **Cookie flags** (`Secure`, `HttpOnly`, `SameSite`, `__Host-` prefix) | common real-world finding, fits the grading model |
| **e2e test in CI on kind** (Calico + Kyverno, run `k8s-verify.sh`) | proves the K8s hardening on every push, not just on my laptop |
| **Prometheus alerts** (spike in 429 / SSRF blocks, error rate, p95) | moves abuse protection from prevention to detection and response |
| **k6 load test** | measure where the concurrency cap and limits kick in; capacity numbers for the README |
| Redis-backed rate limit | one shared limit across replicas |
| GitOps (Argo CD / Flux) + SLSA provenance, Kyverno checks the SBOM attestation | closes the "manual pin" and "signature only" gaps from the threat model |
| IPv6 egress rules | needed on a dual-stack cluster |
