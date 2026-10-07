#!/usr/bin/env bash
#
# k3sm B411 acceptance gate — the apiserver aggregation layer's request-header
# trust: a fifth CA, k3sm-request-header-ca, issuing only the front-proxy client
# leaf (CN system:auth-proxy), and the eight kube-apiserver flags k3s sets
# (--requestheader-*, --proxy-client-*, --enable-aggregator-routing=false).
#
# TWO TIERS:
#
#   UNIT TIER (always runs; GOARCH=arm64 CGO_ENABLED=1) — the named unit gates in
#   pkg/certs, pkg/bootstrap, pkg/executor, pkg/rbac and cmd/k3sm, with -race.
#
#   LAB TIER (K3SM_LAB=1, on the SERVER Mac of the rig; uses sudo for reads of the
#   0600 key files only) — against the installed, running server:
#
#     b411.L0  the e2e suite compiles (`go test -c -tags e2e`); a build failure
#              fails the gate, it never skips.
#     b411.L1  <work-dir>/client-auth-proxy.key is mode 0600 and owned by the
#              daemon user (the owner of the work dir).
#     b411.L2  the three live tests, none of which may SKIP:
#                TestB411_ExtensionAPIServerAuthenticationCarriesRequestHeaderCA
#                TestB411_AggregatorPresentsProxyClientCert (backend pinned to
#                  $B411_SERVER_NODE, so the dial never crosses server->worker)
#                TestB411_ForgedFrontProxyRejected (forged signing-CA and
#                  cluster-CA proxy certs, minted in the test process from the
#                  host's CA keys and never written anywhere)
#     b411.L3  kube-scheduler and kube-controller-manager still healthy after the
#              request-header keys appeared (their /healthz, and /readyz?verbose).
#     b411.L4  `k3sm status -o json` request-header row is ok: this server's pin,
#              and a trusted count of 1.
#     b411.L5  `k3sm certificate rotate --restart` once, then L2's first two tests
#              again (the request-header CA pin must survive the rotation).
#
#   Without K3SM_LAB=1 the lab tier is announced PENDING and the gate exits 2: it
#   NEVER passes without the rig run.
#
#   --rollback-check (K3SM_LAB=1): after a rollback to a release without the
#   aggregation layer, asserts kube-system/extension-apiserver-authentication
#   carries no requestheader- key (the runbook deletes it once; this is how the
#   step is not skipped silently).
#
# Environment (lab tier):
#   KUBECONFIG          the admin kubeconfig for the cluster (required)
#   B411_SERVER_NODE    the server's node name (required)
#   B411_WORK_DIR       the server work dir (default /var/lib/k3sm/server)
#   B411_K3SM           the k3sm binary (default: k3sm on PATH)
#   B411_SCHEDULER_PORT / B411_KCM_PORT  loopback health ports (10259 / 10257)
#   B411_EVIDENCE       where the transcripts go (default: a mktemp dir)
#
# Usage:  hack/acceptance/B411.sh [--help]
#         K3SM_LAB=1 hack/acceptance/B411.sh
#         K3SM_LAB=1 hack/acceptance/B411.sh --rollback-check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SELF="$HERE/B411.sh"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

mode=gate
case "${1:-}" in
-h | --help)
	sed -n '2,/^set -euo pipefail$/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'
	exit 0 ;;
--rollback-check) mode=rollback ;;
"") ;;
*) echo "usage: $0 [--help | --rollback-check]" >&2; exit 2 ;;
esac

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
summary() { echo "----------------------------------------"; echo "B411: $PASS passed, $FAIL failed"; }

WORK_DIR="${B411_WORK_DIR:-/var/lib/k3sm/server}"
K3SM="${B411_K3SM:-k3sm}"

if [ "$mode" = rollback ]; then
	if [ "${K3SM_LAB:-}" != 1 ]; then
		echo "PENDING  b411 --rollback-check needs K3SM_LAB=1 and the rolled-back cluster"
		exit 2
	fi
	: "${KUBECONFIG:?KUBECONFIG must name the admin kubeconfig}"
	data="$(kubectl -n kube-system get cm extension-apiserver-authentication -o jsonpath='{.data}')"
	if printf '%s' "$data" | grep -q 'requestheader-'; then
		ladder no "b411.R  extension-apiserver-authentication still carries requestheader- keys after the rollback (delete the ConfigMap once; the old apiserver recreates it)"
	else
		ladder ok "b411.R  extension-apiserver-authentication carries no requestheader- key"
	fi
	summary
	[ "$FAIL" -eq 0 ] || exit 1
	exit 0
fi

echo "==> k3sm B411 acceptance (the aggregation layer's request-header trust) [$K3SM_ROOT]"

# ---- unit tier ---------------------------------------------------------------
b0=ok
bash -n "$SELF" || b0=no
ladder "$b0" "b411.0  the gate parses (bash -n)"

unit() {
	local pkg="$1" run="$2" label="$3"
	if (cd "$K3SM_ROOT" && GOARCH=arm64 CGO_ENABLED=1 go test -race -count=1 -run "$run" "$pkg" >/dev/null 2>&1); then
		ladder ok "$label"
	else
		ladder no "$label (rerun: cd $K3SM_ROOT && go test -race -run '$run' $pkg)"
	fi
}
unit ./pkg/certs '^(TestRequestHeaderCA.*|TestEnsureHierarchyJoinedNeverMints|TestHalfPresentPairIsIncompleteNotMissing|TestBundleV2DecodesV3CarriesRequestHeaderCA|TestBundleV2RoundTripCarriesEtcdCAs|TestBundleRefusesSchemaV1WithoutWriting|TestBundleSchemaVersionSingleSourced|TestReconcileImportedHierarchy|TestReconcileInstallIsKeyThenCertAtomic|TestLoadCARejectsMismatchedKey|TestLoadRequestHeaderPinIsReadOnly|TestNewCertErrorsCarryNoKeyMaterial)$' \
	"b411.1  pkg/certs: the request-header CA, role-gated mint, schema 3, reconcile, pins"
unit ./pkg/bootstrap '^(TestImportCABundleRefusesBundleWithoutRequestHeaderCA|TestImportCABundleBackfillsOnlyMissingCA)$' \
	"b411.2  pkg/bootstrap: a v2 bundle refused before any write; the backfill"
unit ./cmd/k3sm '^(TestServerJoinFetchesBundleOnlyWhenCAMissing|TestServerJoinSavesSecretBeforeFetch|TestServerJoinWaitsOnOlderBundleSource|TestRunServerTraceImportPrecedesMeshPKI|TestEnsureCallersPassRole|TestServerExecutorConfigCarriesServerJoin|TestRunServerUnder150Lines|TestCertificateRotatePreservesCAPin)$' \
	"b411.3  cmd/k3sm: the join, the bounded wait, role sources, rotation pins"
unit ./pkg/executor '^(TestAPIServerArgsCarryAggregatorFlags|TestProxyClientCertIdentity|TestProvisionPassesRole|TestRotationReportListsProxyClientCert|TestApiserverArgsSingleNodeDefault)$' \
	"b411.4  pkg/executor: the eight flags, the proxy leaf, the role, the rotation rows"
unit ./pkg/rbac '^TestProvisionSubjectsUnchanged$' \
	"b411.5  pkg/rbac: no grant added or widened"

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "PENDING  b411.L0-L5 lab tier: run on the server Mac with K3SM_LAB=1, KUBECONFIG and B411_SERVER_NODE set"
	summary
	echo "B411: the lab tier is PENDING; this gate never passes without it" >&2
	[ "$FAIL" -eq 0 ] || exit 1
	exit 2
fi

# ---- lab tier ----------------------------------------------------------------
: "${KUBECONFIG:?KUBECONFIG must name the admin kubeconfig}"
: "${B411_SERVER_NODE:?B411_SERVER_NODE must name the server node the backend is pinned to}"
EVIDENCE="${B411_EVIDENCE:-$(mktemp -d "${TMPDIR:-/tmp}/b411-evidence.XXXXXX")}"
mkdir -p "$EVIDENCE"
echo "    evidence: $EVIDENCE"

cleanup() {
	# The tests clean up after themselves (the APIService first); this catches a
	# killed run.
	kubectl delete apiservice v1alpha1.b411.test.k3sm.io --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# b411.L0 — the e2e suite builds.
if (cd "$K3SM_ROOT" && GOARCH=arm64 CGO_ENABLED=1 go test -c -tags e2e -o "$EVIDENCE/e2e.test" ./e2e) >"$EVIDENCE/L0-build.log" 2>&1; then
	ladder ok "b411.L0  the e2e suite compiles"
else
	ladder no "b411.L0  the e2e suite does not compile (see $EVIDENCE/L0-build.log)"
	summary; exit 1
fi

# b411.L1 — the proxy key's mode and owner.
owner="$(sudo stat -f '%Su' "$WORK_DIR")"
got="$(sudo stat -f '%Lp %Su' "$WORK_DIR/client-auth-proxy.key" 2>/dev/null || echo absent)"
if [ "$got" = "600 $owner" ]; then
	ladder ok "b411.L1  client-auth-proxy.key is 0600 and owned by the daemon user ($owner)"
else
	ladder no "b411.L1  client-auth-proxy.key is '$got', want '600 $owner'"
fi

# run_live <label> <regexp> <log>: the named e2e tests, which must all run (no SKIP).
run_live() {
	local label="$1" run="$2" log="$3"
	if (cd "$K3SM_ROOT" && B411_WORK_DIR="$WORK_DIR" B411_SERVER_NODE="$B411_SERVER_NODE" \
		GOARCH=arm64 CGO_ENABLED=1 go test -tags e2e -count=1 -v -timeout 20m -run "$run" ./e2e) >"$log" 2>&1 &&
		! grep -q -- '--- SKIP' "$log"; then
		ladder ok "$label"
	else
		ladder no "$label (see $log)"
	fi
}
run_live "b411.L2  the request-header trust, the aggregator's proxy cert, the forged-proxy negatives" \
	'^TestB411_(ExtensionAPIServerAuthenticationCarriesRequestHeaderCA|AggregatorPresentsProxyClientCert|ForgedFrontProxyRejected)$' \
	"$EVIDENCE/L2-e2e.log"

# b411.L3 — scheduler and controller-manager healthy with request-header authn on.
health() { curl -sk --max-time 5 "https://127.0.0.1:$1/healthz" 2>/dev/null || true; }
l3=ok
[ "$(health "${B411_SCHEDULER_PORT:-10259}")" = ok ] || { l3=no; echo "  kube-scheduler /healthz is not ok"; }
[ "$(health "${B411_KCM_PORT:-10257}")" = ok ] || { l3=no; echo "  kube-controller-manager /healthz is not ok"; }
kubectl get --raw '/readyz?verbose' >"$EVIDENCE/L3-readyz.txt" 2>&1 || l3=no
grep -q 'readyz check passed' "$EVIDENCE/L3-readyz.txt" || l3=no
ladder "$l3" "b411.L3  kube-scheduler and kube-controller-manager healthy; apiserver /readyz passed"

# b411.L4 — the status row: this server's pin and a trusted count of 1.
# shellcheck disable=SC2024 # the evidence file is this user's; only the read needs root
sudo "$K3SM" status -o json >"$EVIDENCE/L4-status.json" 2>"$EVIDENCE/L4-status.err" || true
l4=no
i=0
while name="$(plutil -extract "rows.$i.name" raw -o - "$EVIDENCE/L4-status.json" 2>/dev/null)"; do
	if [ "$name" = request-header ]; then
		sev="$(plutil -extract "rows.$i.severity" raw -o - "$EVIDENCE/L4-status.json" 2>/dev/null || true)"
		detail="$(plutil -extract "rows.$i.detail" raw -o - "$EVIDENCE/L4-status.json" 2>/dev/null || true)"
		echo "  request-header row: $sev: $detail"
		case "$detail" in *" 1 trusted in extension-apiserver-authentication"*) [ "$sev" = ok ] && l4=ok ;; esac
		break
	fi
	i=$((i + 1))
done
ladder "$l4" "b411.L4  k3sm status: request-header row ok with a trusted count of 1"

# b411.L5 — a rotation keeps the request-header CA, and the trust still works.
pre="$(sudo "$K3SM" certificate rotate --work-dir "$WORK_DIR" 2>&1 | sed -n 's/.*request-header CA *sha256:\([0-9a-f]*\).*/\1/p' | head -1)"
# shellcheck disable=SC2024 # the evidence file is this user's; only the rotation needs root
if sudo "$K3SM" certificate rotate --work-dir "$WORK_DIR" --restart >"$EVIDENCE/L5-rotate.log" 2>&1; then
	post="$(sed -n 's/.*request-header CA *sha256:\([0-9a-f]*\).*/\1/p' "$EVIDENCE/L5-rotate.log" | head -1)"
	if [ -n "$pre" ] && [ "$pre" = "$post" ]; then
		ladder ok "b411.L5a k3sm certificate rotate --restart kept the request-header CA ($pre)"
	else
		ladder no "b411.L5a the request-header CA pin moved or was not reported ('$pre' -> '$post')"
	fi
else
	ladder no "b411.L5a k3sm certificate rotate --restart failed (see $EVIDENCE/L5-rotate.log)"
fi
run_live "b411.L5b after the rotation: the request-header trust and the aggregator's proxy cert" \
	'^TestB411_(ExtensionAPIServerAuthenticationCarriesRequestHeaderCA|AggregatorPresentsProxyClientCert)$' \
	"$EVIDENCE/L5-e2e.log"

summary
[ "$FAIL" -eq 0 ] || exit 1
