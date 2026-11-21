#!/usr/bin/env bash
# Prove the Kubernetes hardening on a live cluster (make k8s-verify).
#
#  1. The app works: a scan of a public site through kubectl port-forward.
#  2. Network (NetworkPolicy), tested with raw sockets from INSIDE the pod,
#     i.e. as if the app's SSRF guard had a bug and let any URL through:
#       - Kubernetes API (Service IP and the real endpoint) -> blocked
#       - a pod and a Service in namespace demo             -> blocked
#       - cloud metadata 169.254.169.254                    -> blocked
#       - a public site on 443                              -> allowed
#  3. Admission (Kyverno): signed digest admitted; unsigned image, image
#     signed by someone else, and our image by tag are denied.
#  (Section 3 also checks the pod: no SA token, read-only root FS, non-root.)
#     Uses --dry-run=server, so nothing is actually created.
#
# Needs: kubectl (current context = the cluster), curl, docker (to resolve
# digests of the test images). Override with NS=..., PORT=...
set -uo pipefail

NS="${NS:-secscan}"
PORT="${PORT:-18080}"
PUBLIC_HOST="${PUBLIC_HOST:-github.com}"
fails=0

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails + 1)); }

echo "== 1. App works (port-forward, scan https://$PUBLIC_HOST)"
kubectl -n "$NS" port-forward svc/secscan "$PORT":80 >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null' EXIT
for _ in $(seq 1 20); do
  curl -fs "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.5
done
body=$(curl -fs --max-time 30 "http://127.0.0.1:$PORT/scan?url=https://$PUBLIC_HOST" || true)
if printf '%s' "$body" | grep -q '"grade"'; then
  pass "scan https://$PUBLIC_HOST -> $(printf '%s' "$body" | grep -o '"score":[0-9]*' | head -1), $(printf '%s' "$body" | grep -o '"grade":"[A-F]"' | head -1)"
else
  fail "scan https://$PUBLIC_HOST returned: ${body:-<nothing>}"
fi

echo "== 2. Network from inside the pod (raw TCP, bypassing the app)"
pod=$(kubectl -n "$NS" get pod -l app=secscan -o jsonpath='{.items[0].metadata.name}')
api_svc=$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}')
api_ep=$(kubectl -n default get endpointslices -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{.items[0].endpoints[0].addresses[0]}')
api_port=$(kubectl -n default get endpointslices -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{.items[0].ports[0].port}')
demo_pod=$(kubectl -n demo get pod -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)
demo_port=$(kubectl -n demo get pod -o jsonpath='{.items[0].spec.containers[0].ports[0].containerPort}' 2>/dev/null)
demo_svc=$(kubectl -n demo get svc -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null)
demo_svc_port=$(kubectl -n demo get svc -o jsonpath='{.items[0].spec.ports[0].port}' 2>/dev/null)

# Prints OPEN or BLOCKED (timeout/refused) for host:port, from the pod.
probe() {
  kubectl -n "$NS" exec "$pod" -c api -- python -c '
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()
    print("OPEN")
except OSError:
    print("BLOCKED")
' "$1" "$2" 2>/dev/null
}
expect() { # expect OPEN|BLOCKED host port label
  got=$(probe "$2" "$3")
  if [ "$got" = "$1" ]; then pass "$4 ($2:$3) -> $got"; else fail "$4 ($2:$3) -> ${got:-error}, expected $1"; fi
}

expect BLOCKED "$api_svc" 443 "Kubernetes API, Service IP"
expect BLOCKED "$api_ep" "$api_port" "Kubernetes API, endpoint"
if [ -n "$demo_pod" ]; then
  expect BLOCKED "$demo_pod" "${demo_port:-80}" "pod in namespace demo"
  expect BLOCKED "$demo_svc" "${demo_svc_port:-80}" "Service in namespace demo"
else
  echo "  SKIP namespace demo not found"
fi
expect BLOCKED 169.254.169.254 80 "cloud metadata"
expect OPEN "$PUBLIC_HOST" 443 "public site"

echo "== 3. Pod hardening, seen from inside"
pod_check() { # label, python expression that must print OK
  got=$(kubectl -n "$NS" exec "$pod" -c api -- python -c "$2" 2>/dev/null)
  if [ "$got" = "OK" ]; then pass "$1"; else fail "$1 -> ${got:-error}"; fi
}
pod_check "no ServiceAccount token mounted" \
  'import os; print("OK" if not os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token") else "token present")'
pod_check "root filesystem is read-only" \
  'import os
try:
    open("/app/pwned", "w"); print("writable")
except OSError:
    print("OK")'
pod_check "runs as non-root (uid 10001)" \
  'import os; print("OK" if os.getuid() == 10001 else "uid %d" % os.getuid())'

echo "== 4. Admission (Kyverno ImageValidatingPolicy, server dry-run)"
signed=$(kubectl -n "$NS" get deploy secscan -o jsonpath='{.spec.template.spec.containers[0].image}')
digest_of() { docker buildx imagetools inspect "$1" --format '{{json .Manifest.Digest}}' | tr -d '"'; }
unsigned="docker.io/library/busybox@$(digest_of busybox:1.37)"
foreign="ghcr.io/sigstore/cosign/cosign@$(digest_of ghcr.io/sigstore/cosign/cosign:v3.1.4)"
by_tag="ghcr.io/vladyslav-krutii/secscan:latest"

# A PSA-restricted-compliant pod, so a denial comes from Kyverno, not PSA.
try_run() {
  kubectl -n "$NS" run verify-admission --dry-run=server --restart=Never --image="$1" \
    --overrides='{"spec":{"automountServiceAccountToken":false,
      "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},
      "containers":[{"name":"verify-admission","image":"'"$1"'",
        "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' \
    -o name 2>&1
}
out=$(try_run "$signed")
if [ "$out" = "pod/verify-admission" ]; then pass "signed by our CI -> admitted"; else fail "signed image denied: $out"; fi
for case in "unsigned|$unsigned" "signed by another identity|$foreign" "our image by tag, no digest|$by_tag"; do
  label=${case%%|*}; img=${case#*|}
  out=$(try_run "$img")
  if printf '%s' "$out" | grep -q "verify-secscan-signature"; then
    pass "$label -> denied: $(printf '%s' "$out" | grep -oE 'no signatures found|expected SAN value|does not have a digest' | head -1)"
  else
    fail "$label ($img) -> $out"
  fi
done

echo
if [ "$fails" -eq 0 ]; then echo "All checks passed."; else echo "$fails check(s) failed."; exit 1; fi
