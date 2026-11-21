# Kubernetes hardening

Phase 5: SecScan runs in its own namespace with admission control
(PSA + Kyverno), a locked-down pod and a default-deny network. Every claim
below is checked on a live cluster by [`scripts/k8s-verify.sh`](../scripts/k8s-verify.sh).

## Deploy

Requirements: a CNI that **enforces** NetworkPolicy (Calico or Cilium; kind's
default kindnet accepts the objects but enforces nothing) and Kyverno ≥ 1.16
(tested with 1.20). Tested on kind, Kubernetes v1.36.

```bash
kubectl apply -k k8s/policy          # namespace (PSA restricted) + Kyverno policy FIRST
kubectl -n secscan wait nivpol/verify-secscan-signature \
  --for=jsonpath='{.status.conditionStatus.ready}'=true --timeout=60s
kubectl apply -k k8s/overlays/kind   # the app, pinned to a signed digest
kubectl -n secscan rollout status deploy/secscan
bash scripts/k8s-verify.sh           # app, network, admission
kubectl -n secscan port-forward svc/secscan 8088:80   # http://localhost:8088
```

The policy goes first so no pod can be admitted before the check exists.
With `make`: `make k8s-deploy k8s-verify`. `make k8s-pin` moves the overlay to
the digest `:latest` points to; CI moves `:latest` only after the signature
was verified (see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)).

## Layout and controls

```
k8s/
├── namespace/            # Namespace with Pod Security Admission "restricted" (enforce)
├── base/                 # SA (no token), Deployment, Service, PDB, NetworkPolicies
├── overlays/kind/        # pins the image to the digest CI signed
├── policy/               # Kyverno NamespacedImageValidatingPolicy (apply first)
└── components/ingress/   # optional: Ingress + allow only ingress-nginx + trusted proxy
```

| Layer | What | Why |
|---|---|---|
| Admission: PSA | namespace `restricted`, `enforce-version: v1.36` | the API server itself rejects root, privileged, host namespaces, kept capabilities |
| Admission: Kyverno | only images **signed by this repo's `ci.yml` on `main`** (keyless: exact certificate identity + GitHub OIDC issuer, Rekor), **by digest**, for every image in the namespace | an image built anywhere else, or a moved tag, cannot run here |
| Pod | non-root uid 10001, `readOnlyRootFilesystem`, drop `ALL`, no privilege escalation, seccomp `RuntimeDefault`, `/tmp` as a 16 Mi `emptyDir` | a compromised process has as little as possible |
| Identity | own ServiceAccount, `automountServiceAccountToken: false`, no RBAC, `enableServiceLinks: false` | no API token to steal |
| Availability | requests/limits (CPU, memory, ephemeral storage), startup/liveness/readiness probes, 2 replicas spread by node, PDB `minAvailable: 1` | one pod can't starve the node; drains keep the service up |
| Network | default deny both ways; egress only DNS to kube-dns and TCP 80/443 to `0.0.0.0/0` **except** private ranges (pod CIDR, Service CIDR, nodes), `100.64/10`, link-local (`169.254.169.254`), loopback | **second SSRF layer**: even with a bug in the app guard the network won't carry the request inside the cluster |

**Ingress.** There is no ingress rule in the base, so all ingress is denied.
`kubectl port-forward` still works: the kubelet connects to the port from
inside the pod's own network namespace, not over the pod network, so
NetworkPolicy never sees it. Probes come from the node, which Calico always
allows. With an ingress controller, `k8s/components/ingress` admits only the
ingress-nginx pods on 8000 and only then trusts `X-Forwarded-For`.

**Proof** (`scripts/k8s-verify.sh`, on the kind lab cluster with Calico and
Kyverno 1.20, 2026-11-21):

```
== 1. App works (port-forward, scan https://github.com)
  PASS scan https://github.com -> "score":83, "grade":"B"
== 2. Network from inside the pod (raw TCP, bypassing the app)
  PASS Kubernetes API, Service IP (10.96.0.1:443) -> BLOCKED
  PASS Kubernetes API, endpoint (172.19.0.3:6443) -> BLOCKED
  PASS pod in namespace demo (10.244.217.144:3000) -> BLOCKED
  PASS Service in namespace demo (10.96.97.33:3000) -> BLOCKED
  PASS cloud metadata (169.254.169.254:80) -> BLOCKED
  PASS public site (github.com:443) -> OPEN
== 3. Admission (Kyverno ImageValidatingPolicy, server dry-run)
  PASS signed by our CI -> admitted
  PASS unsigned -> denied: no signatures found
  PASS signed by another identity -> denied: expected SAN value
  PASS our image by tag, no digest -> denied: does not have a digest
```

Control run: with both NetworkPolicies deleted, the same pod **reaches**
`10.96.0.1:443`, so the block is caused by our egress policy. (The `demo`
pods are also closed by that namespace's own default deny, and nothing
listens on 169.254.169.254 in kind; both checks matter on a real cloud.)
