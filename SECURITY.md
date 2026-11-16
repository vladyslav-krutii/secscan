# Security Policy

## Reporting a vulnerability

This is an educational portfolio project. If you spot a security issue,
please open a GitHub issue or contact the maintainer rather than exploiting it.

## Security practices in this repo

- Container images run as a **non-root** user with a read-only root filesystem
  and all Linux capabilities dropped.
- Images are scanned with **Trivy** in CI; the pipeline fails on CRITICAL
  vulnerabilities.
- Dependencies are kept current via **Dependabot**.
- The scanner has an SSRF guard: only `http`/`https` on ports 80/443, only
  globally routable addresses, every redirect re-validated, and the connection
  pinned to the validated IP. See "Security write-up" in the README.
