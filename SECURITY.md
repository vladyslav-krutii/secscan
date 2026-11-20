# Security Policy

## Reporting a vulnerability

This is an educational portfolio project. If you spot a security issue,
please open a GitHub issue or contact the maintainer rather than exploiting it.

## Security practices in this repo

- Container images run as a **non-root** user with a read-only root filesystem
  and all Linux capabilities dropped.
- Images are scanned with **Trivy** in CI; the pipeline fails on CRITICAL
  vulnerabilities.
- Supply chain in CI: GitHub Actions pinned by commit SHA, container images
  (base image, Trivy, Semgrep, Gitleaks) pinned by digest, least-privilege
  `permissions:`; Gitleaks (secrets), Semgrep (SAST), pip-audit
  (dependencies) and Trivy (image, SARIF in the Security tab) on every push.
- Dependencies are kept current via **Dependabot**.
- Every image pushed from `main` has an SPDX SBOM (Syft) and is signed by
  digest with **Cosign keyless** (GitHub OIDC, no long-lived keys); CI
  verifies both. To check an image yourself:

  ```bash
  cosign verify ghcr.io/vladyslav-krutii/secscan@sha256:<digest> \
    --certificate-identity https://github.com/vladyslav-krutii/secscan/.github/workflows/ci.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  cosign verify-attestation --type spdxjson <same flags> ghcr.io/vladyslav-krutii/secscan@sha256:<digest>
  ```
- The scanner has an SSRF guard: only `http`/`https` on ports 80/443, only
  globally routable addresses, every redirect re-validated, and the connection
  pinned to the validated IP. See "Security write-up" in the README.
- `/scan` is protected against abuse: per-client rate limit (`429`), a cap on
  concurrent scans (`503`) and an overall deadline per scan (`504`).
  `X-Forwarded-For` is only believed from configured proxies. See "Abuse
  protection" in the README.

## Accepted risks

Time-boxed exceptions, mirrored in `.trivyignore` with an `exp:` date. After
the expiry date Trivy reports the finding again and it must be re-reviewed.

| ID | Component | Severity | Accepted | Expires | Reason |
|---|---|---|---|---|---|
| CVE-2026-85091 | `zlib1g` in `python:3.12-slim` | HIGH | 2026-11-19 | 2026-12-10 | Fixed in Debian (`deb13u1`) but not yet in the official image. HIGH, not CRITICAL. We prefer reproducible digest-pinned builds over an ad-hoc `apt-get upgrade`; Dependabot will propose the new base digest. |
