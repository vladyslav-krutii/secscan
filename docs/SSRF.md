# SSRF in `/scan`: write-up

Phase 1 of the hardening: a server-side request forgery in my own scanner,
found, reproduced, fixed test-first and documented. In Kubernetes a second,
independent layer blocks the same requests at the network level
([KUBERNETES.md](KUBERNETES.md)).

## The vulnerability

`/scan` fetches a URL chosen by the caller. The first version only checked the
scheme, then called `httpx` with `follow_redirects=True`. Anyone who could reach
the API could therefore make the server send requests **from inside its own
network** and read back the status code and headers: a server-side request
forgery (SSRF) that works as an internal network mapper.

Reproduced against the docker compose stack before the fix; all four requests
returned `200` (raw responses in [`docs/ssrf-before.txt`](ssrf-before.txt)):

| Request through `/scan`           | What it reached                          |
| --------------------------------- | ---------------------------------------- |
| `http://prometheus:9090`          | Prometheus, by its compose service name  |
| `http://grafana:3000/login`       | Grafana login page                       |
| `http://127.0.0.1:8000/health`    | the API itself over loopback             |
| `http://api:8000/metrics`         | the API's own metrics endpoint           |

In Kubernetes the same request shape reaches `kubernetes.default.svc`, other
pods and the cloud metadata endpoint `169.254.169.254`.

## The fix (`app/scanner.py`)

Every URL, the original one and each redirect target, goes through the same checks:

1. **Scheme and port**: only `http`/`https` on ports 80 and 443. URLs with
   embedded credentials are refused.
2. **Resolve, then allowlist**: the hostname is resolved with the OS resolver
   and every returned address must be globally routable
   (`ipaddress.is_global`, not multicast). This is an allowlist, not a
   blocklist, so loopback, RFC 1918, link-local, CGNAT `100.64.0.0/10`,
   IPv6 unique-local/link-local and reserved ranges are rejected without a
   list to maintain. IPv4-mapped IPv6 is unwrapped first; NAT64 and 6to4
   prefixes are refused. If a name has several records and one is internal,
   the whole request is refused.
3. **Connect to the validated IP**: the request is sent to the address that was
   just checked, with the original name in the `Host` header and in TLS SNI, so
   the certificate is still verified against the hostname. The name is never
   resolved a second time, which closes the DNS-rebinding window between
   "check" and "connect".
4. **Manual redirects**: `follow_redirects=False`; each `Location` is validated
   as in steps 1 to 3, with at most 5 redirects.
5. **Headers only**: the response is opened as a stream and the body is never
   read, so a huge or endless body cannot tie up the service.
6. **No ambient proxy**: `trust_env=False`, so `HTTP_PROXY`-style variables
   cannot reroute the request around the pinned address.

A refused target returns `400` with a generic `Blocked target: ...` message,
increments `secscan_blocked_targets_total` and is logged with the reason. The
resolved internal address is written to the log only, not returned to the caller.

## Before / after

The same requests against the docker compose stack, run from the Linux
container image (raw output: [`docs/ssrf-before.txt`](ssrf-before.txt),
[`docs/ssrf-after.txt`](ssrf-after.txt)):

| Request through `/scan`                                   | Before | After                                      |
| --------------------------------------------------------- | ------ | ------------------------------------------ |
| `http://prometheus:9090`                                  | `200`  | `400` port is not allowed                  |
| `http://grafana:3000/login`                               | `200`  | `400` port is not allowed                  |
| `http://127.0.0.1:8000/health`                            | `200`  | `400` port is not allowed                  |
| `http://api:8000/metrics`                                 | `200`  | `400` port is not allowed                  |
| `http://prometheus` (port 80, resolves to `172.18.0.3`)   | n/a    | `400` not a public internet address        |
| `http://169.254.169.254`                                  | n/a    | `400` not a public internet address        |
| `http://2130706433` (glibc resolves it to `127.0.0.1`)    | n/a    | `400` not a public internet address        |
| public redirector → `http://127.0.0.1/`                   | n/a    | `400` redirect target is not a public address |
| public redirector → `http://169.254.169.254/...`          | n/a    | `400` redirect target is not a public address |
| public redirector → `https://github.com/`                 | n/a    | `200`, grade A (public redirects still work) |
| `https://github.com`                                      | grade A | `200`, grade A                            |

"n/a" rows were not captured before the fix. The redirect rows use
`https://postman-echo.com/redirect-to?url=...`, which answers with a real `302`;
the API log shows one outbound request to the redirector and no second hop.

## The tests (`tests/test_ssrf.py`)

Written before the fix and confirmed failing (38 failures), then made to pass.
DNS and HTTP are both faked, so the suite is deterministic and also asserts
that **no request left the process** for a blocked target. Covered: loopback,
`0.0.0.0`, metadata address, private and CGNAT ranges, IPv6 (`::1`,
IPv4-mapped, unique-local, link-local), decimal/hex/octal IPv4 forms, compose
and Kubernetes service names, DNS records pointing at private space, non-web
ports, redirects from a public host to each kind of internal target, the
redirect cap, connection pinning, a rebinding resolver, and the unread body.

## Known limits

- The error message still distinguishes "blocked" from "could not resolve", so
  a caller can learn whether an internal DNS name exists. Accepted for now in
  exchange for useful errors.
- Only the first resolved address is used; there is no fallback to other
  records if it is unreachable.
- This is one layer. In Kubernetes an egress `NetworkPolicy` denies the
  cluster and metadata ranges as a second, independent layer, verified with
  raw sockets from inside the pod ([KUBERNETES.md](KUBERNETES.md)).
