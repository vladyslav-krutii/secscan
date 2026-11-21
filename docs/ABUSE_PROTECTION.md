# Abuse protection for `/scan`

`/scan` makes the server do network work on behalf of an anonymous caller, so
it is the endpoint worth protecting. `/health` and `/metrics` are not limited:
probes and Prometheus call them far more often than any scan limit allows.

A request to `/scan` passes the gates in this order, cheapest first, and a
request refused by one gate never reaches the next:

| # | Gate                 | Refusal                     | Why                                                   |
| - | -------------------- | --------------------------- | ----------------------------------------------------- |
| 1 | Per-client rate limit | `429` + `Retry-After`      | one client cannot use the scanner as a traffic source |
| 2 | Free scan slot       | `503` + `Retry-After`       | bounded number of outbound scans per process          |
| 3 | SSRF validation      | `400 Blocked target: ...`   | see [SSRF.md](SSRF.md)                                |
| 4 | Overall deadline     | `504`                       | a slow target cannot hold a slot indefinitely         |

- **Rate limit** ([slowapi](https://github.com/laurentS/slowapi), moving
  window). Every request counts, including the ones the SSRF guard refuses:
  probing internal names is exactly the traffic to slow down.
- **Concurrency cap**. When all slots are taken the request is refused at once
  instead of queued. A queue would keep connections open and let a client stack
  up work for later.
- **Deadline**. One clock covers every DNS lookup and redirect hop of a scan.
  Before, only per-hop timeouts existed, so a slow redirect chain could run for
  about 6 hops x (5 s DNS + 5 s HTTP). When the deadline fires the task is
  cancelled, the open response stream and the HTTP client are closed, and the
  slot is released. A single DNS lookup or HTTP request that hits its own
  timeout (5 s) is reported the same way: `504`, same metric, same log line.
  `400` is kept for targets that are invalid, blocked, unresolvable or refuse
  the connection.

## Who is "the client"? (`X-Forwarded-For`)

The rate limit is keyed on the client address, and that address must be one the
client cannot choose.

- By default the address of the **TCP peer** is used and `X-Forwarded-For` is
  ignored. Otherwise a client could send a different header value with every
  request and never be limited.
- Behind a reverse proxy (the Ingress) every request arrives from the proxy, so
  all clients would share a single bucket. `SECSCAN_TRUSTED_PROXIES` lists the
  proxy addresses; only when the peer is in that list is `X-Forwarded-For` read.
- The header is walked **right to left** and the first address that is not a
  trusted proxy is the client. A proxy appends the peer it saw, so only the
  right-hand entries were written by our own infrastructure; everything further
  left was supplied by the client and is ignored.

## Configuration

Read once at start-up. An unparsable value stops the process instead of
silently falling back to a default.

| Variable                        | Default     | Meaning                                                        |
| ------------------------------- | ----------- | -------------------------------------------------------------- |
| `SECSCAN_RATE_LIMIT`            | `10/minute` | Scans per client address (`limits` notation, e.g. `100/hour`)  |
| `SECSCAN_TRUSTED_PROXIES`       | *(empty)*   | Comma-separated IPs/CIDRs whose `X-Forwarded-For` is believed  |
| `SECSCAN_SCAN_DEADLINE_SECONDS` | `10`        | Wall-clock budget for one scan, all hops and DNS included      |
| `SECSCAN_MAX_CONCURRENT_SCANS`  | `10`        | Outbound scans running at once, per process                    |

## Known limits

- **Counters live in process memory.** With N replicas each pod counts on its
  own, so the effective limit is about N x `SECSCAN_RATE_LIMIT`, and a restart
  resets it. The fix is a shared store (Redis, which slowapi supports through
  `storage_uri`); left out to keep the deployment dependency-free.
- **`X-Forwarded-For` is only as trustworthy as `SECSCAN_TRUSTED_PROXIES`.**
  Anything inside the listed ranges can claim any client address. In
  Kubernetes the default is empty (port-forward has no proxy). The optional
  ingress component sets the pod CIDR **together with** a NetworkPolicy that
  admits only the ingress-nginx pods, so no other pod can connect and forge
  the header.
- The limit is per address: clients behind one NAT share a bucket, and an IPv6
  user with a whole `/64` has many addresses.
- A cancelled DNS lookup cannot be interrupted: `getaddrinfo` keeps its worker
  thread until the OS resolver gives up. The concurrency cap bounds how many
  can pile up.
- The concurrency cap is per process, like the rate limit.
