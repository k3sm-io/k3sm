#!/usr/bin/env bash
#
# verify-examples.sh — the gate over examples/. Every manifest this repo ships must be
# one a k3sm cluster actually accepts.
#
# Two legs, and the second one is optional ONLY because a cluster is:
#
#   lint         ALWAYS runs, needs no cluster. Strict schema decode plus the k3sm
#                admission/placement rules a YAML schema cannot express: the
#                kubernetes.io/os=darwin nodeSelector the ValidatingAdmissionPolicy
#                demands, a toleration for the k3sm.io/provider:NoSchedule taint every
#                node carries, no hand-pinned nodeName, no blanket toleration, and the
#                native image conventions (`image: native` ⇒ absolute command[0]).
#                Implemented in hack/examples/lintexamples — this script is a thin CLI
#                over it, never a second copy of the rules.
#
#   server       `kubectl apply --dry-run=server` per file, which puts each manifest
#                through the REAL admission chain. Runs only when a cluster answers;
#                when it does not, the skip is printed and named in the summary. This
#                script never reports a bare green over a leg it did not run.
#
# Usage:
#   hack/verify-examples.sh                 # lint, plus server dry-run if a cluster answers
#   hack/verify-examples.sh --lint-only     # never contact a cluster
#   hack/verify-examples.sh --dir <path>    # lint a different directory
#   hack/verify-examples.sh --self-test     # prove the lint catches what it claims to
#
# KUBECTL=<path> overrides the kubectl used for the server leg (e.g. `k3sm kubectl`
# needs a wrapper script; export KUBECTL to point at a plain kubectl instead).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/.." && pwd)"

EXAMPLES_DIR="$K3SM_ROOT/examples"
KUBECTL="${KUBECTL:-kubectl}"
LINT_ONLY=""
SELF_TEST=""

while [ $# -gt 0 ]; do
	case "$1" in
	--dir) EXAMPLES_DIR="${2:?--dir needs a path}"; shift ;;
	--lint-only) LINT_ONLY=1 ;;
	--self-test) SELF_TEST=1 ;;
	-h | --help)
		sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "verify-examples.sh: unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done

lint() { (cd "$K3SM_ROOT" && go run ./hack/examples/lintexamples "$@"); }

# ---------------------------------------------------------------------------------
# --self-test: fixtures that pin BOTH directions of every lint rule.
#
# The fixtures are written to a temp directory rather than committed under examples/,
# for one reason: a deliberately-broken manifest living next to the real ones is a
# manifest somebody eventually applies. They are still fixtures — each names the rule
# it exercises and the substring the finding must contain, so a rule that silently
# stops firing fails here instead of passing quietly.
# ---------------------------------------------------------------------------------
self_test() {
	# `dir` is deliberately NOT local: the EXIT trap fires after this function
	# has returned, when a local would already be gone and the temp dir would leak.
	dir="$(mktemp -d)"
	trap 'rm -rf "$dir"' EXIT
	local failures=0

	cat > "$dir/pass-pod.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: good
spec:
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  containers:
    - name: c
      image: native
      command: ["/bin/echo", "hi"]
YAML

	cat > "$dir/pass-deployment.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  replicas: 1
  selector:
    matchLabels:
      app: good
  template:
    metadata:
      labels:
        app: good
    spec:
      nodeSelector:
        kubernetes.io/os: darwin
      tolerations:
        - key: k3sm.io/provider
          operator: Exists
          effect: NoSchedule
      containers:
        - name: c
          image: /opt/good/bin/good
YAML

	# The shape examples/hello-native.yaml used to ship: no darwin selector, a nodeName
	# pin, and a blanket toleration. One fixture, three findings.
	cat > "$dir/fail-legacy-shape.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: legacy
spec:
  nodeName: k3sm-m0
  tolerations:
    - operator: Exists
  containers:
    - name: c
      image: native
      command: ["/bin/echo", "hi"]
YAML

	cat > "$dir/fail-no-toleration.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: untolerating
spec:
  nodeSelector:
    kubernetes.io/os: darwin
  containers:
    - name: c
      image: native
      command: ["/bin/echo", "hi"]
YAML

	cat > "$dir/fail-relative-command.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: relative
spec:
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  containers:
    - name: c
      image: native
      command: ["echo", "hi"]
YAML

	cat > "$dir/fail-linux-image.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: linuximage
spec:
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  containers:
    - name: c
      image: nginx:1.27
YAML

	cat > "$dir/fail-unknown-field.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: typo
spec:
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
    - key: k3sm.io/provider
      operator: Exists
      effect: NoSchedule
  contaienrs:
    - name: c
      image: native
      command: ["/bin/echo", "hi"]
YAML

	cat > "$dir/fail-unknown-kind.yaml" <<'YAML'
apiVersion: example.com/v1
kind: Widget
metadata:
  name: widget
spec: {}
YAML

	expect_pass() {
		local file="$1" out
		if out="$(lint "$dir/$file" 2>&1)"; then
			echo "  PASS  $file (clean, as expected)"
		else
			echo "  FAIL  $file should have linted clean:"; echo "$out" | sed 's/^/          /'
			failures=$((failures + 1))
		fi
	}

	expect_fail() {
		local file="$1"; shift
		local out rc=0
		out="$(lint "$dir/$file" 2>&1)" || rc=$?
		if [ "$rc" -eq 0 ]; then
			echo "  FAIL  $file linted clean but must not"
			failures=$((failures + 1))
			return
		fi
		local want
		for want in "$@"; do
			if ! printf '%s' "$out" | grep -q -- "$want"; then
				echo "  FAIL  $file failed, but no finding matched: $want"
				echo "$out" | sed 's/^/          /'
				failures=$((failures + 1))
				return
			fi
		done
		echo "  PASS  $file (rejected: $*)"
	}

	echo "==> [examples] self-test"
	expect_pass pass-pod.yaml
	expect_pass pass-deployment.yaml
	expect_fail fail-legacy-shape.yaml "nodeSelector must set kubernetes.io/os=darwin" \
		"nodeName is set" "blanket toleration"
	expect_fail fail-no-toleration.yaml "no toleration for the k3sm.io/provider:NoSchedule taint"
	expect_fail fail-relative-command.yaml "command\[0\] must be an absolute host path"
	expect_fail fail-linux-image.yaml "neither the .native. sentinel nor an"
	expect_fail fail-unknown-field.yaml "does not decode against its schema"
	expect_fail fail-unknown-kind.yaml "unsupported kind"

	# A directory holding no manifests must be an error, not an empty green.
	local empty; empty="$(mktemp -d)"
	if lint "$empty" >/dev/null 2>&1; then
		echo "  FAIL  an empty directory linted clean; a moved examples/ would report green"
		failures=$((failures + 1))
	else
		echo "  PASS  empty directory (rejected)"
	fi
	rmdir "$empty"

	if [ "$failures" -ne 0 ]; then
		echo "FAIL: verify-examples self-test: $failures check(s) failed" >&2
		exit 1
	fi
	echo "OK: verify-examples self-test green"
}

if [ -n "$SELF_TEST" ]; then
	self_test
	exit 0
fi

# ---------------------------------------------------------------------------------
# Leg 1 — lint (always).
# ---------------------------------------------------------------------------------
[ -d "$EXAMPLES_DIR" ] || { echo "verify-examples.sh: no such directory: $EXAMPLES_DIR" >&2; exit 2; }

echo "==> [examples] lint $EXAMPLES_DIR"
lint "$EXAMPLES_DIR"

# ---------------------------------------------------------------------------------
# Leg 2 — server dry-run, when and only when a cluster answers.
# ---------------------------------------------------------------------------------
SKIP_REASON=""
if [ -n "$LINT_ONLY" ]; then
	SKIP_REASON="--lint-only was given"
elif ! command -v "$KUBECTL" >/dev/null 2>&1; then
	SKIP_REASON="no '$KUBECTL' on PATH"
elif ! "$KUBECTL" --request-timeout=5s get --raw /readyz >/dev/null 2>&1; then
	SKIP_REASON="no cluster answered '$KUBECTL get --raw /readyz' within 5s"
fi

if [ -n "$SKIP_REASON" ]; then
	echo "==> [examples] server dry-run SKIPPED — $SKIP_REASON"
	echo "OK: examples lint green (schema + k3sm admission rules); server dry-run NOT run — $SKIP_REASON"
	exit 0
fi

echo "==> [examples] server dry-run ($KUBECTL apply --dry-run=server)"
rc=0
for f in "$EXAMPLES_DIR"/*.yaml; do
	if "$KUBECTL" apply --dry-run=server -f "$f" >/dev/null; then
		echo "ok    $f"
	else
		echo "FAIL  $f — rejected by the live admission chain"
		rc=1
	fi
done
[ "$rc" -eq 0 ] || { echo "FAIL: examples rejected by server dry-run" >&2; exit 1; }

echo "OK: examples green (lint + server dry-run)"
