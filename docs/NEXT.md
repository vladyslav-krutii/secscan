# Next session: Phase 6, README, threat model, interview prep

**Phase 5 is done (2026-11-21).** Commits d182d06 … 7edc642 (+ this one).
- d182d06: CI builds once, pushes `:<sha>`, Trivy scans that `image@digest`,
  Cosign signs the same digest, `:latest` moves only after verify. Closes the
  "scanned ≠ signed" gap from slice 2.
- aa4ad1b: Kustomize (`k8s/namespace`, `base`, `overlays/kind`), deploy by
  digest, PSA `restricted` (enforce v1.36), own SA without token,
  non-root/read-only/drop ALL/seccomp, requests/limits, probes, PDB.
- f5f7b38: default-deny NetworkPolicy; egress only kube-dns + TCP 80/443 to
  public IPs (private ranges, CGNAT, loopback, link-local excluded); optional
  ingress component; `SECSCAN_TRUSTED_PROXIES` empty in the base.
- eaebc92: Kyverno `NamespacedImageValidatingPolicy`: every image by digest
  and keyless-signed by `ci.yml@refs/heads/main`, fail closed.
- 7edc642: `scripts/k8s-verify.sh`, make targets, README section, Kustomize
  render + digest check in CI.

Verified on `kind-k8s-lab` (Calico, Kyverno 1.20): all 11 checks of
`k8s-verify.sh` pass; control run without NetworkPolicy reaches
`10.96.0.1:443`, so the block is ours. Deployed digest:
`sha256:91d9f165…` (pinned via `k8s-pin` after a fresh CI run).

How to get back into the cluster (main kubeconfig is empty):
`kind get kubeconfig --name k8s-lab > ~/.kube/kind-k8s-lab.yaml` and
`$env:KUBECONFIG="$HOME\.kube\kind-k8s-lab.yaml"`.

## Phase 6 plan (draft, confirm at the start)

- **README rewrite** for a reviewer with 2 minutes: what / why / proof at the
  top (badges, one screenshot, the k8s-verify output), details below. Fix
  stale bits (example grades table, github.com now B 83).
- **Threat model** `docs/THREAT_MODEL.md`: STRIDE over the data flow
  (user → API → internet; CI → GHCR → cluster). Assets, trust boundaries,
  each threat → control → evidence (test, CI job, verify script) → residual
  risk. Include the accepted risks and the known limits below.
- **Architecture diagram** (Mermaid in README): request path with the
  guards (rate limit, SSRF guard, NetworkPolicy) and the supply chain
  (build once → scan → sign → Kyverno admission).
- **Interview prep** `docs/INTERVIEW.md`: 2-minute pitch; 15–20 likely
  questions with short answers (taken from LEARNING.md Q&A); "what I'd do
  next" list; a 5-minute live demo script (compose + k8s-verify).

## Known simplifications left from Phase 5

- No Prometheus scrape in k8s (the egress/ingress policy would need a rule
  from the monitoring namespace).
- Rate-limit counters are per pod (2 replicas ≈ 2× the limit); Redis would
  fix it.
- IPv6 egress not covered (kind cluster is IPv4-only); a dual-stack cluster
  needs a `::/0` rule with `fc00::/7`, `fe80::/10`, `::1/128` excluded.
- The SBOM attestation is created and verified in CI, but Kyverno checks
  only the signature, not the attestation. No SLSA provenance yet.
- `kubectl port-forward` bypasses NetworkPolicy by design; access to it is an
  RBAC question (`pods/portforward`).

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
