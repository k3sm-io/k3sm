#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The multi-container vm Pod tracer, against the RUNNING two-Mac cluster, through
# kubectl only. This gate boots, installs and restarts nothing.
#
# --same-image is rung t.0, a premise check on a stock build: a `pair` vm Pod whose two
# containers name ONE image already runs as several containers in one guest. A failure
# here is a bug in what exists today, never in a change under test. It also pulls every
# digest-pinned tracer image on every Mac, so an unreachable image shows now.
#
# Legs, in order. pf.* run once per Mac first; t.* then run per Mac, one Mac at a time:
#   pf.0   the namespace vm-tracer holds no LimitRange (the pods state no memory)
#   pf.a   image A (nginx) pulls and runs on this Mac (imagePullPolicy: Always)
#   pf.b   image B (alpine) likewise
#   pf.c   image C (the larger image) likewise
#   t.1    `web` and `client` are each ready with their own state.running; the Pod is Ready
#   t.2a   `client` fetches nginx's page from `web` at http://127.0.0.1/ (shared localhost)
#   t.2b   /etc/os-release reads the same in both containers (the one image)
#   t.2c   a file written in `web`'s root is absent from `client`'s (one overlay each)
#   t.3    each container reads the other's file in the shared emptyDir
#   t.4    `kubectl logs -c web` and `-c client` each carry only their own marker
#   t.5a   `client` is terminated with exit 7 while `web` runs and the phase stays Running
#   t.5b   `web` then stops: both are terminated and the phase is Failed
#   t.6    a fresh Pod is deleted with `logs -f` held on both: both TERM markers arrive
#   clean  the namespace is gone
#
# The Memory emptyDir of the two-image tracer is left out of this mode: nothing shares
# one across two paths yet. The later rungs and their modes are not written yet.
#
# Pods follow the lab rules: nodeName AND the darwin nodeSelector; tolerations are
# k3sm.io/provider plus only the keys in K3SM_LAB_TOLERATE_KEYS
# (hack/lab/lib/tolerations.sh); in-pod scripts ride a ConfigMap; Events are selected by
# involvedObject.uid. Every object lives in the namespace vm-tracer, deleted on every
# exit; an existing vm-tracer is refused and left alone. Pulled images stay in each
# node's image store.
#
# Environment (all optional):
#   KUBECTL                     kubectl binary (default: kubectl)
#   K3SM_LAB_TOLERATE_KEYS      extra taint keys every pod tolerates with Exists
#   K3SM_TRACER_PULL_TIMEOUT    seconds for one pull pod to finish (default 240)
#   K3SM_TRACER_READY_TIMEOUT   seconds for one pair Pod to be Ready (default 180)
#   K3SM_TRACER_STEP_TIMEOUT    seconds for an exec or a state change (default 60)
#   K3SM_TRACER_DELETE_TIMEOUT  seconds for a delete to finish (default 120)
#   K3SM_TRACER_SETTLE          seconds t.5a holds before re-reading the state (default 5)
#   Each timeout is at most 240.
#
# Exit: 0 every leg held on every Mac; 1 a leg failed (the run log names it); 2 the run
# did not happen: K3SM_LAB unset (SKIP, never a pass), a bad argument, or a refused
# precondition, with nothing created.
#
# Usage:  hack/acceptance/vm-multicontainer-tracer.sh --plan        # the legs; contacts nothing
#         hack/acceptance/vm-multicontainer-tracer.sh --self-test   # offline checks of this script
#         K3SM_LAB=1 hack/acceptance/vm-multicontainer-tracer.sh --same-image [<evidence-dir>]
#             (default evidence dir: a new mktemp directory)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/vm-multicontainer-tracer.sh"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh
. "$REPO_ROOT/hack/lab/lib/tolerations.sh"

GATE_NAME="vm-multicontainer-tracer"
# shellcheck disable=SC2034  # read by the sourced runlog.sh
MODE="same-image"
NS="vm-tracer"

# The tracer images, each a multi-platform index pinned by digest, each carrying
# linux/arm64. Image C is the larger tree the boot-margin rung measures, by entry count
# (17042 entries, 212 MB unpacked); it needs a tree with no case-folding path collision:
# an image carrying usr/share/man/man7/{PAM,pam}.7.gz, such as python:3.13-bookworm, is
# refused at materialize on the case-insensitive host filesystem.
IMAGE_A="docker.io/library/nginx:1.29.3@sha256:2f4e10193b0c4f61472245e9d26cea78e7df7af266c7e7cf5e67353ee2731b51"
IMAGE_B="docker.io/library/alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412"
IMAGE_C="docker.io/library/golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59"

PULL_TIMEOUT="${K3SM_TRACER_PULL_TIMEOUT:-240}"
READY_TIMEOUT="${K3SM_TRACER_READY_TIMEOUT:-180}"
STEP_TIMEOUT="${K3SM_TRACER_STEP_TIMEOUT:-60}"
DELETE_TIMEOUT="${K3SM_TRACER_DELETE_TIMEOUT:-120}"
SETTLE="${K3SM_TRACER_SETTLE:-5}"

# The leg table: `name|statement`. --plan prints it; --self-test checks that the run
# reports every name.
LEGS=(
	"pf.0|the namespace holds no LimitRange"
	"pf.a|image A pulls and runs on this Mac"
	"pf.b|image B pulls and runs on this Mac"
	"pf.c|image C pulls and runs on this Mac"
	"t.1|each container ready with its own state.running; the Pod Ready"
	"t.2a|client fetches nginx's page from web at 127.0.0.1"
	"t.2b|/etc/os-release is the same in both containers"
	"t.2c|a file in web's root is absent from client's root"
	"t.3|the shared emptyDir reads both ways"
	"t.4|each container's log carries only its own marker"
	"t.5a|client exits 7 while web runs and the phase stays Running"
	"t.5b|web stops: both terminated, phase Failed"
	"t.6|a delete delivers TERM to both, seen on held logs -f"
	"clean|the namespace is gone"
)

# ---- pure helpers (the --self-test surface) -----------------------------------------

# TRACER_PY reads a Pod on stdin and answers one question about it.
TRACER_PY='
import json, sys
op, a = sys.argv[1], sys.argv[2:]
d = json.load(sys.stdin)
st = d.get("status") or {}
def cs(n):
    for c in st.get("containerStatuses") or []:
        if c.get("name") == n:
            return c
    return {}
if op == "phase":
    print(st.get("phase", ""))
elif op == "uid":
    print((d.get("metadata") or {}).get("uid", ""))
elif op == "ready":
    print("".join(c.get("status", "") for c in st.get("conditions") or [] if c.get("type") == "Ready"))
elif op == "cstate":
    c = cs(a[0])
    s = c.get("state") or {}
    key = next(iter(s), "none")
    code = (s.get("terminated") or {}).get("exitCode", "")
    print("|".join([str(c.get("ready", False)).lower(), key, str(code)]))
elif op == "cimage":
    c = cs(a[0])
    print(c.get("image", "") + " " + c.get("imageID", ""))
else:
    sys.exit("unknown op " + op)
'

# untolerated_keys <taint-lines>: the NoSchedule/NoExecute taint keys (lines of
# key:Effect) the provider entry and K3SM_LAB_TOLERATE_KEYS leave untolerated.
untolerated_keys() {
	local lines="$1" t key effect keys out=""
	keys=" $(lab_tol_keys) " || exit 2
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		key="${t%:*}"
		effect="${t##*:}"
		[ "$effect" = PreferNoSchedule ] && continue
		[ "$key" = k3sm.io/provider ] && continue
		case "$keys" in *" $key "*) continue ;; esac
		out="${out:+$out }$key"
	done <<<"$lines"
	printf '%s' "$out"
}

# ---- in-pod scripts and manifests -----------------------------------------------------

# web_script: serves nginx on :80, writes /shared/from-web, and exits 0 on /shared/stop-web.
web_script() {
	cat <<'WEB'
#!/bin/sh
trap 'echo "TRACER web term"; kill "$n" 2>/dev/null; exit 0' TERM
nginx -g 'daemon off;' &
n=$!
echo from-web >/shared/from-web
echo "TRACER web up"
while [ ! -e /shared/stop-web ]; do sleep 1; done
kill "$n" 2>/dev/null
wait "$n" 2>/dev/null
echo "TRACER web stopped"
exit 0
WEB
}

# client_script: fetches web over localhost, writes /shared/from-client, and exits 7 on
# /shared/stop.
client_script() {
	cat <<'CLIENT'
#!/bin/sh
trap 'echo "TRACER client term"; exit 0' TERM
until [ -e /shared/from-web ]; do sleep 1; done
tries=0
until wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || curl -fsS http://127.0.0.1/ >/dev/null 2>&1; do
	tries=$((tries + 1))
	[ "$tries" -lt 60 ] || break
	sleep 1
done
echo from-client >/shared/from-client
echo "TRACER client up"
while [ ! -e /shared/stop ]; do sleep 1; done
echo "TRACER client stopping"
exit 7
CLIENT
}

# scripts_configmap <ns>
scripts_configmap() {
	echo "apiVersion: v1"
	echo "kind: ConfigMap"
	echo "metadata: {name: tracer-scripts, namespace: $1}"
	echo "data:"
	echo "  web.sh: |"
	web_script | sed 's/^/    /'
	echo "  client.sh: |"
	client_script | sed 's/^/    /'
}

# pull_pod <ns> <name> <node> <image> <tolerations>: one container that runs and exits,
# with imagePullPolicy Always so a cached image still reaches the registry.
pull_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1}
spec:
  runtimeClassName: vm
  nodeName: $3
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$5]
  restartPolicy: Never
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 5
  containers:
  - name: probe
    image: $4
    imagePullPolicy: Always
    command: ["sh", "-c", "echo TRACER pull ok"]
EOF
}

# pair_pod <ns> <name> <node> <web-image> <client-image> <tolerations>
pair_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1}
spec:
  runtimeClassName: vm
  nodeName: $3
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$6]
  restartPolicy: Never
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 20
  containers:
  - name: web
    image: $4
    imagePullPolicy: IfNotPresent
    command: ["sh", "/tracer/web.sh"]
    ports:
    - {containerPort: 80}
    readinessProbe:
      httpGet: {path: /, port: 80}
      periodSeconds: 2
    volumeMounts:
    - {name: shared, mountPath: /shared}
    - {name: scripts, mountPath: /tracer, readOnly: true}
  - name: client
    image: $5
    imagePullPolicy: IfNotPresent
    command: ["sh", "/tracer/client.sh"]
    readinessProbe:
      exec: {command: ["test", "-f", "/shared/from-web"]}
      periodSeconds: 2
    volumeMounts:
    - {name: shared, mountPath: /shared}
    - {name: scripts, mountPath: /tracer, readOnly: true}
  volumes:
  - {name: shared, emptyDir: {}}
  - {name: scripts, configMap: {name: tracer-scripts}}
EOF
}

# ---- --plan -----------------------------------------------------------------------------

plan() {
	local row
	echo "vm-multicontainer-tracer lab gate: PLAN ONLY (contacts nothing)"
	echo "mode --same-image: rung t.0 on every Mac; a red leg does not end the run"
	for row in "${LEGS[@]}"; do
		printf '  %-6s %s\n' "${row%%|*}" "${row#*|}"
	done
	echo "images: A $IMAGE_A"
	echo "        B $IMAGE_B"
	echo "        C $IMAGE_C"
	echo "exit: 0 every leg held on every Mac, 1 a leg failed, 2 not run (K3SM_LAB unset: SKIP; a bad argument; a refused precondition)"
}

# ---- --self-test --------------------------------------------------------------------------

# fake_kubectl: a stand-in that plays a healthy two-node cluster from state files under
# $FAKE_STATE, and answers wrongly on the one property $FAKE_BREAK names. The negative
# controls below use it to prove that each property reds the gate.
fake_kubectl() {
	cat <<'FAKE'
#!/bin/sh
S="$FAKE_STATE"
B="${FAKE_BREAK:-}"
echo "$*" >>"$S/calls.log"
ctr() { # name ready state exit
	case "$3" in
	running) st='{"running":{}}' ;;
	waiting) st='{"waiting":{}}' ;;
	*) st="{\"terminated\":{\"exitCode\":$4}}" ;;
	esac
	printf '{"name":"%s","ready":%s,"state":%s,"image":"img","imageID":"id"}' "$1" "$2" "$st"
}
doc() { # phase readycond ctr-json...
	p="$1"; r="$2"; shift 2
	printf '{"metadata":{"uid":"u-1"},"status":{"phase":"%s","conditions":[{"type":"Ready","status":"%s"}],"containerStatuses":[%s]}}\n' "$p" "$r" "$(IFS=,; echo "$*")"
}
pair_doc() {
	pod="$1"
	if [ -e "$S/stopweb-$pod" ]; then
		ph=Failed
		[ "$B" = phase-end ] && ph=Running
		doc "$ph" False "$(ctr web false terminated 0)" "$(ctr client false terminated 7)"
	elif [ -e "$S/stop-$pod" ]; then
		ph=Running; wc=running; we=0; ce=7
		[ "$B" = phase-early ] && ph=Failed
		[ "$B" = web-dies ] && { wc=terminated; we=1; }
		[ "$B" = exit-wrong ] && ce=0
		doc "$ph" False "$(ctr web true "$wc" "$we")" "$(ctr client false terminated "$ce")"
	elif [ "$B" = not-ready ]; then
		doc Running False "$(ctr web true running 0)" "$(ctr client false running 0)"
	elif [ "$B" = state-wrong ]; then
		doc Running True "$(ctr web true waiting 0)" "$(ctr client true running 0)"
	else
		doc Running True "$(ctr web true running 0)" "$(ctr client true running 0)"
	fi
}
case "$1 $2" in
"get --raw") echo ok ;;
"get nodes") printf 'node-a\nnode-b\n' ;;
"get nodes,pods") echo "(fake listing)" ;;
"get ns") echo "(fake namespaces)" ;;
"get node")
	case "$*" in
	*Ready*) echo True ;;
	*taints*) echo k3sm.io/provider:NoSchedule ;;
	*) echo v0 ;;
	esac
	;;
"get runtimeclass") exit 0 ;;
"get namespace")
	[ -e "$S/ns" ] || exit 1
	[ -e "$S/ns-deleted" ] && [ "$B" != leftover ] && exit 1
	exit 0
	;;
"create namespace") : >"$S/ns" ;;
"delete namespace") : >"$S/ns-deleted" ;;
"get limitrange") : ;;
"get events") : ;;
"apply -f") : ;;
"delete pod")
	[ "$B" = pod-survives ] || : >"$S/deleted-$3"
	;;
"get pod")
	pod="$3"
	[ -e "$S/deleted-$pod" ] && exit 1
	case "$*" in *yaml*) exit 0 ;; esac
	case "$pod" in
	pull-*)
		if [ "$B" = pull ]; then doc Failed False "$(ctr probe false terminated 1)"; else doc Succeeded False "$(ctr probe false terminated 0)"; fi
		;;
	*) pair_doc "$pod" ;;
	esac
	;;
"logs -f")
	pod="$3"; c="$7"
	echo "TRACER $c up"
	[ "$B" = "term-$c" ] || echo "TRACER $c term"
	;;
logs*)
	pod="$2"; c="$6"
	case "$pod" in pull-*) echo "TRACER pull ok"; exit 0 ;; esac
	case "$*" in *--all-containers*) exit 0 ;; esac
	echo "TRACER $c up"
	[ "$B" = logs-web ] && [ "$c" = web ] && echo "TRACER client up"
	[ "$B" = logs-client ] && [ "$c" = client ] && echo "TRACER web up"
	exit 0
	;;
exec*)
	pod="$2"; c="$6"; script="${10}"
	case "$script" in
	*127.0.0.1*)
		[ "$B" = fetch ] || echo "<h1>Welcome to nginx!</h1>"
		;;
	*os-release*)
		if [ "$B" = osrel ] && [ "$c" = client ]; then echo "ID=other"; else echo "ID=same"; fi
		;;
	*"touch /tracer-only-web"*) echo made ;;
	*"test -e /tracer-only-web"*)
		if [ "$B" = overlay ]; then echo seen; else echo absent; fi
		;;
	*"cat /shared/from-client"*)
		[ "$B" = shared-fwd ] || echo from-client
		;;
	*"cat /shared/from-web"*)
		[ "$B" = shared-rev ] || echo from-web
		;;
	*"touch /shared/stop-web"*) : >"$S/stopweb-$pod" ;;
	*"touch /shared/stop"*) : >"$S/stop-$pod" ;;
	esac
	;;
*) echo "fake kubectl: unexpected: $*" >&2; exit 1 ;;
esac
exit 0
FAKE
}

self_test() {
	local bad=0 row name out code tmp tol m src t t2 pyd brk leg state
	check() { if [ "$1" = ok ]; then echo "ok    $2"; else echo "FAIL  $2"; bad=1; fi; }

	if command -v shellcheck >/dev/null 2>&1; then
		if out="$(shellcheck -x "$SELF" 2>&1)"; then check ok "shellcheck: clean"; else
			printf '%s\n' "$out"
			check no "shellcheck: clean"
		fi
	else
		echo "skip  shellcheck (not installed)"
	fi
	if web_script | sh -n 2>/dev/null; then check ok "web script parses (sh -n)"; else check no "web script parses (sh -n)"; fi
	if client_script | sh -n 2>/dev/null; then check ok "client script parses (sh -n)"; else check no "client script parses (sh -n)"; fi

	src="$(cat "$SELF")"
	for row in "${LEGS[@]}"; do
		name="${row%%|*}"
		case "$src" in *"leg $name "* | *"leg_for $name "*) ;; *) check no "leg $name is reported by the run" ;; esac
	done
	check ok "every leg in the table is reported by the run (${#LEGS[@]})"

	for t in "$IMAGE_A" "$IMAGE_B" "$IMAGE_C"; do
		if [[ "$t" =~ ^docker\.io/library/[a-z]+:[-.a-z0-9]+@sha256:[0-9a-f]{64}$ ]]; then check ok "digest-pinned: ${t%%@*}"; else check no "digest-pinned: $t"; fi
	done

	t="$(printf '%s' '{"metadata":{"uid":"u"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":"client","ready":false,"state":{"terminated":{"exitCode":7}},"image":"i","imageID":"d"}]}}' | python3 -I -c "$TRACER_PY" cstate client)"
	check "$([ "$t" = "false|terminated|7" ] && echo ok)" "cstate: ready, state and exit code ($t)"
	t="$(printf '%s' '{"status":{}}' | python3 -I -c "$TRACER_PY" cstate web)"
	check "$([ "$t" = "false|none|" ] && echo ok)" "cstate: no status yet ($t)"
	t=$'k3sm.io/provider:NoSchedule\nexample.io/estate-off:NoExecute\nexample.io/soft:PreferNoSchedule'
	check "$([ "$(K3SM_LAB_TOLERATE_KEYS="" untolerated_keys "$t")" = example.io/estate-off ] && echo ok)" "untolerated_keys: an unnamed NoExecute key"

	tol="$(K3SM_LAB_TOLERATE_KEYS="" lab_tolerations_yaml NoSchedule)"
	for m in "$(pair_pod ns-x pair-1 node-a "$IMAGE_A" "$IMAGE_A" "$tol")" "$(pull_pod ns-x pull-a-1 node-a "$IMAGE_A" "$tol")"; do
		name="$(printf '%s\n' "$m" | sed -n 's/^metadata: {name: \([^,]*\),.*/\1/p')"
		case "$m" in *"nodeName: node-a"*) check ok "$name: nodeName" ;; *) check no "$name: nodeName" ;; esac
		case "$m" in *"nodeSelector: {kubernetes.io/os: darwin}"*) check ok "$name: darwin nodeSelector" ;; *) check no "$name: darwin nodeSelector" ;; esac
		case "$m" in *"tolerations: [$tol]"*) check ok "$name: tolerations from the helper" ;; *) check no "$name: tolerations from the helper" ;; esac
		case "$tol" in *"key: k3sm.io/provider"*) check ok "$name: tolerates k3sm.io/provider" ;; *) check no "$name: tolerates k3sm.io/provider" ;; esac
		case "$m" in *"{operator"* | *"- operator"*) check no "$name: no key-less toleration" ;; *) check ok "$name: no key-less toleration" ;; esac
		case "$m" in *"runtimeClassName: vm"*"restartPolicy: Never"*) check ok "$name: vm, restartPolicy Never" ;; *) check no "$name: vm, restartPolicy Never" ;; esac
	done
	m="$(pair_pod ns-x pair-1 node-a "$IMAGE_A" "$IMAGE_A" "$tol")"
	t="$(printf '%s\n' "$m" | grep -c "image: $IMAGE_A")" || true
	check "$([ "$t" = 2 ] && echo ok)" "pair: one image in both containers ($t)"
	case "$m" in *"medium"* | *"fast"*) check no "pair: no Memory emptyDir" ;; *) check ok "pair: no Memory emptyDir" ;; esac
	case "$m" in *"httpGet: {path: /, port: 80}"*'"test", "-f", "/shared/from-web"'*) check ok "pair: a probe per container" ;; *) check no "pair: a probe per container" ;; esac
	m="$(pull_pod ns-x pull-a-1 node-a "$IMAGE_A" "$tol")"
	case "$m" in *"imagePullPolicy: Always"*) check ok "pull pod: Always, so a cached image still reaches the registry" ;; *) check no "pull pod: Always, so a cached image still reaches the registry" ;; esac
	m="$(scripts_configmap ns-x)"
	case "$m" in *"  web.sh: |"*"    nginx -g"*"  client.sh: |"*"    exit 7"*) check ok "ConfigMap: both scripts, indented" ;; *) check no "ConfigMap: both scripts, indented" ;; esac

	# The exit contract and every property's red, as child processes under the system
	# bash, with the fake first on PATH.
	tmp="$(mktemp -d "${TMPDIR:-/tmp}/vm-tracer-selftest.XXXXXX")"
	mkdir -p "$tmp/bin"
	fake_kubectl >"$tmp/bin/kubectl"
	chmod +x "$tmp/bin/kubectl"
	pyd="$(dirname "$(command -v python3)")"
	t="PATH=$tmp/bin:/usr/bin:/bin:$pyd"
	run_fake() { # <state-dir> <break> <args...>
		state="$1"
		brk="$2"
		shift 2
		mkdir -p "$state"
		env -i "$t" HOME="$tmp" TMPDIR="$tmp" FAKE_STATE="$state" FAKE_BREAK="$brk" K3SM_LAB=1 \
			K3SM_TRACER_PULL_TIMEOUT=3 K3SM_TRACER_READY_TIMEOUT=3 K3SM_TRACER_STEP_TIMEOUT=2 \
			K3SM_TRACER_DELETE_TIMEOUT=2 K3SM_TRACER_SETTLE=0 /bin/bash "$SELF" "$@" 2>&1
	}

	out="$(env -i "$t" HOME="$tmp" FAKE_STATE="$tmp" /bin/bash "$SELF" --same-image 2>&1)" && code=0 || code=$?
	case "$out" in *SKIP*"NOT a pass"*) ;; *) code=99 ;; esac
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB unset: SKIP, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" FAKE_STATE="$tmp" K3SM_LAB=0 /bin/bash "$SELF" --same-image 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB=0: SKIP, exit 2 (got $code)"
	check "$([ ! -e "$tmp/calls.log" ] && echo ok)" "a SKIP makes no kubectl call"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --plan 2>&1)" && code=0 || code=$?
	for row in "${LEGS[@]}"; do
		case "$out" in *"${row%%|*} "*) ;; *) code=98 ;; esac
	done
	check "$([ "$code" = 0 ] && echo ok)" "--plan: exit 0, every leg listed (got $code)"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --bogus 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "an unknown option: exit 2 (got $code)"
	out="$(run_fake "$tmp/nomode" "")" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/nomode/calls.log" ] && echo ok)" "K3SM_LAB=1 with no mode: refused, exit 2, no kubectl call (got $code)"
	out="$(run_fake "$tmp/toolong" "" --same-image a b)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "two positional arguments: exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" TMPDIR="$tmp" FAKE_STATE="$tmp" K3SM_LAB=1 K3SM_TRACER_READY_TIMEOUT=241 /bin/bash "$SELF" --same-image 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "a wait over 240 seconds: refused, exit 2 (got $code)"
	mkdir -p "$tmp/held"
	: >"$tmp/held/ns"
	out="$(run_fake "$tmp/held" "" --same-image "$tmp/held-ev")" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/held-ev" ] && echo ok)" "an existing vm-tracer: refused, exit 2, nothing created (got $code)"
	if grep -Eq '^(apply|create|delete) ' "$tmp/held/calls.log" 2>/dev/null; then
		check no "a refused run made no write call"
	else
		check ok "a refused run made no write call"
	fi

	# The positive control: every leg on both nodes.
	out="$(run_fake "$tmp/green" "" --same-image "$tmp/green-ev")" && code=0 || code=$?
	if [ "$code" != 0 ]; then printf '%s\n' "$out"; fi
	check "$([ "$code" = 0 ] && echo ok)" "a healthy fake cluster: exit 0 (got $code)"
	case "$out" in *"result: PASS"*) check ok "a healthy fake cluster: result: PASS" ;; *) check no "a healthy fake cluster: result: PASS" ;; esac
	for row in "${LEGS[@]}"; do
		name="${row%%|*}"
		case "$out" in *"PASS  $name "*) ;; *) check no "green run reports $name" ;; esac
	done
	for t2 in node-a node-b; do
		case "$out" in *"PASS  t.6 "*"[$t2]"*) check ok "green run reaches $t2" ;; *) check no "green run reaches $t2" ;; esac
	done
	if grep -q '^delete namespace vm-tracer' "$tmp/green/calls.log"; then check ok "green run deletes its namespace"; else check no "green run deletes its namespace"; fi

	# The negative controls: each property broken alone reds its own leg, exit 1, and the
	# namespace is still deleted.
	for row in pull:pf.a not-ready:t.1 state-wrong:t.1 fetch:t.2a osrel:t.2b overlay:t.2c \
		shared-fwd:t.3 shared-rev:t.3 logs-web:t.4 logs-client:t.4 exit-wrong:t.5a \
		web-dies:t.5a phase-early:t.5a phase-end:t.5b term-web:t.6 term-client:t.6 \
		pod-survives:t.6 leftover:clean; do
		brk="${row%%:*}"
		leg="${row#*:}"
		out="$(run_fake "$tmp/b-$brk" "$brk" --same-image "$tmp/b-$brk-ev")" && code=0 || code=$?
		case "$out" in
		*"FAIL  $leg "*"result: FAIL"*) ;;
		*)
			printf '%s\n' "$out"
			code="no FAIL $leg"
			;;
		esac
		if ! grep -q '^delete namespace vm-tracer' "$tmp/b-$brk/calls.log"; then code="no namespace delete"; fi
		check "$([ "$code" = 1 ] && echo ok)" "broken $brk: FAIL $leg, exit 1, namespace deleted (got $code)"
	done
	rm -rf "$tmp"

	if [ "$bad" = 0 ]; then echo "vm-multicontainer-tracer self-test: green"; else echo "vm-multicontainer-tracer self-test: RED"; fi
	return "$bad"
}

RUN_MODE=""
case "${1:-}" in
--plan)
	plan
	exit 0
	;;
--self-test)
	self_test
	exit $?
	;;
-h | --help)
	sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
	exit 0
	;;
--same-image)
	RUN_MODE=same-image
	shift
	;;
"") ;;
*)
	echo "vm-multicontainer-tracer.sh: unknown option $1 (try --same-image, --plan, --self-test)" >&2
	exit 2
	;;
esac

# ---- lab guard ---------------------------------------------------------------------------
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "vm-multicontainer-tracer lab gate: SKIP (two Macs). Set K3SM_LAB=1 against the running two-node cluster to run it; this is NOT a pass."
	exit 2
fi

# ---- preconditions (exit 2, nothing created) ---------------------------------------------
refuse() {
	echo "vm-multicontainer-tracer lab gate: REFUSED: $*" >&2
	exit 2
}
[ -n "$RUN_MODE" ] || refuse "name a mode: --same-image"
[ "$#" -le 1 ] || refuse "at most one argument after the mode, the evidence directory (got $#)"
for v in "$PULL_TIMEOUT" "$READY_TIMEOUT" "$STEP_TIMEOUT" "$DELETE_TIMEOUT"; do
	case "$v" in '' | *[!0-9]*) refuse "a timeout must be a number of seconds (got '$v')" ;; esac
	[ "$v" -ge 1 ] && [ "$v" -le 240 ] || refuse "a timeout must be 1 to 240 seconds (got $v)"
done
case "$SETTLE" in '' | *[!0-9]*) refuse "K3SM_TRACER_SETTLE must be a number of seconds (got '$SETTLE')" ;; esac
KUBECTL="${KUBECTL:-kubectl}"
command -v "$KUBECTL" >/dev/null 2>&1 || refuse "kubectl not found ($KUBECTL)"
command -v python3 >/dev/null 2>&1 || refuse "python3 not found; the gate reads Pod status with it"
kc() { "$KUBECTL" "$@"; }
TOLERATIONS="$(lab_tolerations_yaml NoSchedule)" || exit 2
kc get --raw /healthz >/dev/null 2>&1 || refuse "the cluster at \$KUBECONFIG is not serving (/healthz)"
NODES="$(kc get nodes -l kubernetes.io/os=darwin -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')" || refuse "cannot list the darwin nodes"
node_count=0
for n in $NODES; do
	node_count=$((node_count + 1))
	ready="$(kc get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
	[ "$ready" = True ] || refuse "node $n is not Ready (got '${ready:-absent}')"
	left="$(untolerated_keys "$(kc get node "$n" -o jsonpath='{range .spec.taints[*]}{.key}:{.effect}{"\n"}{end}')")" || exit 2
	[ -z "$left" ] || refuse "node $n carries taint key(s) this run does not tolerate: $left (name them in K3SM_LAB_TOLERATE_KEYS)"
done
[ "$node_count" -ge 2 ] || refuse "this gate needs two darwin nodes (found $node_count)"
kc get runtimeclass vm >/dev/null 2>&1 || refuse "the vm RuntimeClass is absent"
if kc get namespace "$NS" >/dev/null 2>&1; then
	refuse "namespace $NS already exists: a leftover run, or someone else's; it is left alone"
fi

EVIDENCE="${1:-}"
[ -n "$EVIDENCE" ] || EVIDENCE="$(mktemp -d "${TMPDIR:-/tmp}/vm-tracer-evidence.XXXXXX")"
mkdir -p "$EVIDENCE/manifests" "$EVIDENCE/pods"

# ---- the run ----------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/runlog.sh
. "$REPO_ROOT/hack/lab/lib/runlog.sh"
RUNLOG="$EVIDENCE/run.log"
RESULTS="$EVIDENCE/results.tsv"
: >"$RESULTS"
log() { printf '%s\n' "$*" | tee -a "$RUNLOG"; }
emit_run_log_header "FAIL (provisional; the final result line below is the verdict)" | tee "$RUNLOG"
PASS=0
FAIL=0
# leg <name> <where> <ok|no> <detail>
leg() {
	local verdict=FAIL
	if [ "$3" = ok ]; then
		verdict=PASS
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
	fi
	log "$verdict  $1 [$2] $4"
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$verdict" "$4" >>"$RESULTS"
}
# leg_for <name> <node>: a leg that a failed earlier step left unreachable is a failure.
leg_for() {
	leg "$1" "$2" no "not reached: $3"
}

NS_CREATED=0
FOLLOWERS=""
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	set +e
	local p
	for p in $FOLLOWERS; do kill "$p" 2>/dev/null; done
	if [ "$NS_CREATED" = 1 ]; then
		kc delete namespace "$NS" --wait=true --timeout="${DELETE_TIMEOUT}s" >>"$RUNLOG" 2>&1
	fi
	return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# bounded <seconds> <cmd...>: run cmd, killing it after the budget. macOS ships no
# timeout(1), and an exec into a wedged guest must not hang the gate.
bounded() {
	local secs="$1" pid watchdog rc=0
	shift
	"$@" &
	pid=$!
	(
		sleep "$secs"
		kill "$pid" 2>/dev/null
	) >/dev/null 2>&1 &
	watchdog=$!
	wait "$pid" || rc=$?
	kill "$watchdog" 2>/dev/null || true
	wait "$watchdog" 2>/dev/null || true
	return "$rc"
}
# pq <pod> <op> [args...]: one answer about a Pod (TRACER_PY); non-zero when it is gone.
pq() {
	local doc pod="$1"
	shift
	doc="$(bounded "$STEP_TIMEOUT" "$KUBECTL" get pod "$pod" -n "$NS" -o json 2>/dev/null)" || return 1
	printf '%s' "$doc" | python3 -I -c "$TRACER_PY" "$@"
}
# kx <pod> <container> <script>: run a shell script in one container.
kx() { bounded "$STEP_TIMEOUT" "$KUBECTL" exec "$1" -n "$NS" -c "$2" -- sh -c "$3" 2>&1; }
# in_log <pod> <container>: the container's log.
in_log() { bounded "$STEP_TIMEOUT" "$KUBECTL" logs "$1" -n "$NS" -c "$2" 2>&1; }

# apply_pod <name>: reads the manifest on stdin, keeps it as evidence, and applies it.
apply_pod() {
	cat >"$EVIDENCE/manifests/$1.yaml"
	kc apply -f "$EVIDENCE/manifests/$1.yaml" >>"$RUNLOG" 2>&1
}
# dump_pod <name>: status, Events by uid and logs into the evidence directory.
dump_pod() {
	local pod="$1" uid
	uid="$(pq "$pod" uid 2>/dev/null || true)"
	kc get pod "$pod" -n "$NS" -o yaml >"$EVIDENCE/pods/$pod.yaml" 2>&1 || true
	if [ -n "$uid" ]; then
		kc get events -n "$NS" --field-selector "involvedObject.uid=$uid" -o wide >"$EVIDENCE/pods/$pod.events.txt" 2>&1 || true
	fi
	kc logs "$pod" -n "$NS" --all-containers --prefix >"$EVIDENCE/pods/$pod.logs.txt" 2>&1 || true
}
# show_pod <name>: a failing pod's status and Events, into the run log.
show_pod() {
	log "--- status of $1: phase $(pq "$1" phase 2>/dev/null || echo gone), ready $(pq "$1" ready 2>/dev/null || echo gone)"
	log "--- web $(pq "$1" cstate web 2>/dev/null || true); client $(pq "$1" cstate client 2>/dev/null || true); probe $(pq "$1" cstate probe 2>/dev/null || true)"
	if [ -s "$EVIDENCE/pods/$1.events.txt" ]; then
		log "--- events of $1:"
		log "$(cat "$EVIDENCE/pods/$1.events.txt")"
	fi
}
delete_pod() { bounded "$DELETE_TIMEOUT" "$KUBECTL" delete pod "$1" -n "$NS" --wait=true >>"$RUNLOG" 2>&1 || true; }

# wait_pod_ready <pod>: 0 once the Pod is Ready, 1 when it ends or the budget runs out.
wait_pod_ready() {
	local deadline=$((SECONDS + READY_TIMEOUT)) r ph
	while [ "$SECONDS" -lt "$deadline" ]; do
		r="$(pq "$1" ready 2>/dev/null || true)"
		[ "$r" = True ] && return 0
		ph="$(pq "$1" phase 2>/dev/null || true)"
		case "$ph" in Failed | Succeeded) return 1 ;; esac
		sleep 1
	done
	return 1
}

# ---- preflight ----------------------------------------------------------------------------
log "==> $GATE_NAME --$RUN_MODE (images: $IMAGE_A $IMAGE_B $IMAGE_C)"
kc get nodes,pods -A -o wide >"$EVIDENCE/get-before.txt" 2>&1 || true
cp "$SELF" "$EVIDENCE/vm-multicontainer-tracer.sh"
for n in $NODES; do
	log "node $n: $(kc get node "$n" -o jsonpath='{.status.nodeInfo.kubeletVersion}' 2>/dev/null || echo unknown)"
done

kc create namespace "$NS" >>"$RUNLOG" 2>&1
NS_CREATED=1
scripts_configmap "$NS" >"$EVIDENCE/manifests/tracer-scripts.yaml"
kc apply -f "$EVIDENCE/manifests/tracer-scripts.yaml" >>"$RUNLOG" 2>&1

limits="$(kc get limitrange -n "$NS" -o name 2>&1 || true)"
if [ -z "$limits" ] || grep -q 'No resources found' <<<"$limits"; then
	leg pf.0 cluster ok "namespace $NS holds no LimitRange"
else
	leg pf.0 cluster no "namespace $NS holds: $(tr '\n' ' ' <<<"$limits")"
fi

# pull_leg <leg> <letter> <index> <node> <image>
pull_leg() {
	local name="$1" pod="pull-$2-$3" node="$4" image="$5" start=$SECONDS ph="" deadline tookms logs
	pull_pod "$NS" "$pod" "$node" "$image" "$TOLERATIONS" | apply_pod "$pod" || true
	deadline=$((SECONDS + PULL_TIMEOUT))
	while [ "$SECONDS" -lt "$deadline" ]; do
		ph="$(pq "$pod" phase 2>/dev/null || true)"
		case "$ph" in Succeeded | Failed) break ;; esac
		sleep 1
	done
	tookms=$((SECONDS - start))
	dump_pod "$pod"
	logs="$(in_log "$pod" probe || true)"
	if [ "$ph" = Succeeded ] && grep -q 'TRACER pull ok' <<<"$logs"; then
		leg "$name" "$node" ok "${image%%@*} ran after ${tookms}s ($(pq "$pod" cimage probe 2>/dev/null || true))"
	else
		leg "$name" "$node" no "${image%%@*}: phase '${ph:-none}' after ${tookms}s (budget ${PULL_TIMEOUT}s)"
		show_pod "$pod"
	fi
	delete_pod "$pod"
}

A_PULLED=" "
idx=0
for n in $NODES; do
	idx=$((idx + 1))
	before=$FAIL
	pull_leg pf.a a "$idx" "$n" "$IMAGE_A"
	[ "$FAIL" = "$before" ] && A_PULLED="$A_PULLED$n "
	pull_leg pf.b b "$idx" "$n" "$IMAGE_B"
	pull_leg pf.c c "$idx" "$n" "$IMAGE_C"
done

# ---- the pair, one Mac at a time ----------------------------------------------------------

# state_is <cstate-value> <ready> <state> [<exit>]: compare a cstate answer.
state_is() {
	local want="$2|$3|${4:-}"
	[ "$1" = "$want" ]
}

run_pair() {
	local node="$1" pod="pair-$2" start=$SECONDS ws cs ph out a b deadline
	pair_pod "$NS" "$pod" "$node" "$IMAGE_A" "$IMAGE_A" "$TOLERATIONS" | apply_pod "$pod" || true
	if wait_pod_ready "$pod"; then
		ws="$(pq "$pod" cstate web || true)"
		cs="$(pq "$pod" cstate client || true)"
		if state_is "$ws" true running && state_is "$cs" true running; then
			leg t.1 "$node" ok "Ready after $((SECONDS - start))s; web $ws, client $cs"
		else
			leg t.1 "$node" no "the Pod is Ready, but web is $ws and client is $cs"
		fi
	else
		dump_pod "$pod"
		leg t.1 "$node" no "not Ready within ${READY_TIMEOUT}s"
		show_pod "$pod"
		for a in t.2a t.2b t.2c t.3 t.4 t.5a t.5b; do leg_for "$a" "$node" "t.1 failed"; done
		delete_pod "$pod"
		return 0
	fi
	log "info  [$node] web image: $(pq "$pod" cimage web || true)"
	log "info  [$node] client image: $(pq "$pod" cimage client || true)"

	out="$(kx "$pod" client 'wget -qO- http://127.0.0.1/ 2>/dev/null || curl -fsS http://127.0.0.1/')" || true
	if grep -q 'Welcome to nginx' <<<"$out"; then
		leg t.2a "$node" ok "client reads nginx's page at 127.0.0.1"
	else
		leg t.2a "$node" no "client got: $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
	fi

	a="$(kx "$pod" web 'cat /etc/os-release')" || true
	b="$(kx "$pod" client 'cat /etc/os-release')" || true
	if [ -n "$a" ] && [ "$a" = "$b" ]; then
		leg t.2b "$node" ok "the same /etc/os-release in both: $(sed -n 1p <<<"$a")"
	else
		leg t.2b "$node" no "web: $(tr '\n' ' ' <<<"$a" | cut -c1-120); client: $(tr '\n' ' ' <<<"$b" | cut -c1-120)"
	fi

	a="$(kx "$pod" web 'touch /tracer-only-web && echo made')" || true
	b="$(kx "$pod" client 'if test -e /tracer-only-web; then echo seen; else echo absent; fi')" || true
	if grep -qx made <<<"$a" && grep -qx absent <<<"$b"; then
		leg t.2c "$node" ok "a file in web's root is absent from client's"
	else
		leg t.2c "$node" no "web: $(tr '\n' ' ' <<<"$a" | cut -c1-120); client: $(tr '\n' ' ' <<<"$b" | cut -c1-120)"
	fi

	# client writes its file after its first fetch, which can trail its readiness.
	deadline=$((SECONDS + STEP_TIMEOUT))
	a=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		a="$(kx "$pod" web 'cat /shared/from-client')" || true
		grep -qx from-client <<<"$a" && break
		sleep 1
	done
	b="$(kx "$pod" client 'cat /shared/from-web')" || true
	if grep -qx from-client <<<"$a" && grep -qx from-web <<<"$b"; then
		leg t.3 "$node" ok "web reads /shared/from-client; client reads /shared/from-web"
	else
		leg t.3 "$node" no "web read: $(tr '\n' ' ' <<<"$a" | cut -c1-120); client read: $(tr '\n' ' ' <<<"$b" | cut -c1-120)"
	fi

	a="$(in_log "$pod" web)" || true
	b="$(in_log "$pod" client)" || true
	if grep -q 'TRACER web up' <<<"$a" && ! grep -q 'TRACER client' <<<"$a" &&
		grep -q 'TRACER client up' <<<"$b" && ! grep -q 'TRACER web' <<<"$b"; then
		leg t.4 "$node" ok "each log carries only its own marker"
	else
		leg t.4 "$node" no "web log: $(grep TRACER <<<"$a" | tr '\n' ' ' | cut -c1-160); client log: $(grep TRACER <<<"$b" | tr '\n' ' ' | cut -c1-160)"
	fi

	# t.5a: client exits 7 alone.
	out="$(kx "$pod" web 'touch /shared/stop')" || true
	deadline=$((SECONDS + STEP_TIMEOUT))
	cs=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		cs="$(pq "$pod" cstate client 2>/dev/null || true)"
		case "$cs" in *"|terminated|"*) break ;; esac
		sleep 1
	done
	sleep "$SETTLE"
	cs="$(pq "$pod" cstate client 2>/dev/null || true)"
	ws="$(pq "$pod" cstate web 2>/dev/null || true)"
	ph="$(pq "$pod" phase 2>/dev/null || true)"
	if state_is "$cs" false terminated 7 && case "$ws" in *"|running|"*) true ;; *) false ;; esac && [ "$ph" = Running ]; then
		leg t.5a "$node" ok "client $cs, web $ws, phase $ph"
	else
		leg t.5a "$node" no "client $cs, web $ws, phase ${ph:-none} (want client terminated exit 7, web running, phase Running)"
		show_pod "$pod"
	fi

	# t.5b: web stops; phase by upstream's rule (all mains done, one non-zero).
	out="$(kx "$pod" web 'touch /shared/stop-web')" || true
	deadline=$((SECONDS + STEP_TIMEOUT))
	ph=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		ph="$(pq "$pod" phase 2>/dev/null || true)"
		[ "$ph" = Failed ] && break
		sleep 1
	done
	cs="$(pq "$pod" cstate client 2>/dev/null || true)"
	ws="$(pq "$pod" cstate web 2>/dev/null || true)"
	if [ "$ph" = Failed ] && state_is "$cs" false terminated 7 && state_is "$ws" false terminated 0; then
		leg t.5b "$node" ok "client $cs, web $ws, phase $ph"
	else
		leg t.5b "$node" no "client $cs, web $ws, phase ${ph:-none} (want both terminated, exits 7 and 0, phase Failed)"
		show_pod "$pod"
	fi
	dump_pod "$pod"
	delete_pod "$pod"
}

run_term() {
	local node="$1" pod="pair-term-$2" start f_web f_client p_web p_client deadline detail ok=1 gone=0
	f_web="$EVIDENCE/pods/$pod.web.follow.log"
	f_client="$EVIDENCE/pods/$pod.client.follow.log"
	pair_pod "$NS" "$pod" "$node" "$IMAGE_A" "$IMAGE_A" "$TOLERATIONS" | apply_pod "$pod" || true
	if ! wait_pod_ready "$pod"; then
		dump_pod "$pod"
		leg t.6 "$node" no "the fresh Pod was not Ready within ${READY_TIMEOUT}s"
		show_pod "$pod"
		delete_pod "$pod"
		return 0
	fi
	"$KUBECTL" logs -f "$pod" -n "$NS" -c web >"$f_web" 2>&1 &
	p_web=$!
	"$KUBECTL" logs -f "$pod" -n "$NS" -c client >"$f_client" 2>&1 &
	p_client=$!
	FOLLOWERS="$p_web $p_client"
	# Hold until each follower shows its container's up marker, so it is attached.
	deadline=$((SECONDS + STEP_TIMEOUT))
	while [ "$SECONDS" -lt "$deadline" ]; do
		grep -q 'TRACER web up' "$f_web" 2>/dev/null && grep -q 'TRACER client up' "$f_client" 2>/dev/null && break
		sleep 1
	done
	dump_pod "$pod"
	start=$SECONDS
	delete_pod "$pod"
	detail="delete took $((SECONDS - start))s"
	# The TERM markers can trail the delete by one log flush.
	deadline=$((SECONDS + STEP_TIMEOUT))
	while [ "$SECONDS" -lt "$deadline" ]; do
		grep -q 'TRACER web term' "$f_web" 2>/dev/null && grep -q 'TRACER client term' "$f_client" 2>/dev/null && break
		sleep 1
	done
	kill "$p_web" "$p_client" 2>/dev/null || true
	wait "$p_web" 2>/dev/null || true
	wait "$p_client" 2>/dev/null || true
	FOLLOWERS=""
	grep -q 'TRACER web term' "$f_web" 2>/dev/null || {
		ok=0
		detail="$detail; no web TERM marker on the held logs -f"
	}
	grep -q 'TRACER client term' "$f_client" 2>/dev/null || {
		ok=0
		detail="$detail; no client TERM marker on the held logs -f"
	}
	if kc get pod "$pod" -n "$NS" >/dev/null 2>&1; then
		ok=0
		detail="$detail; the Pod still exists"
		delete_pod "$pod"
	else
		gone=1
	fi
	if [ "$ok" = 1 ] && [ "$gone" = 1 ]; then
		leg t.6 "$node" ok "$detail; both TERM markers arrived; the Pod is gone"
	else
		leg t.6 "$node" no "$detail"
	fi
}

idx=0
for n in $NODES; do
	idx=$((idx + 1))
	log "==> pair on $n"
	case "$A_PULLED" in
	*" $n "*)
		run_pair "$n" "$idx"
		run_term "$n" "$idx"
		;;
	*)
		for a in t.1 t.2a t.2b t.2c t.3 t.4 t.5a t.5b t.6; do leg_for "$a" "$n" "image A did not pull here"; done
		;;
	esac
done

# ---- clean --------------------------------------------------------------------------------
kc delete namespace "$NS" --wait=true --timeout="${DELETE_TIMEOUT}s" >>"$RUNLOG" 2>&1 || true
NS_CREATED=0
if kc get namespace "$NS" >/dev/null 2>&1; then
	leg clean cluster no "namespace $NS is still present after ${DELETE_TIMEOUT}s"
else
	leg clean cluster ok "namespace $NS is gone"
fi
kc get nodes,pods -A -o wide >"$EVIDENCE/get-after.txt" 2>&1 || true
kc get ns >"$EVIDENCE/namespaces-after.txt" 2>&1 || true
log "$(cat "$EVIDENCE/namespaces-after.txt")"

log "----------------------------------------"
log "$GATE_NAME: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
	emit_run_log_verdict FAIL | tee -a "$RUNLOG"
	exit 1
fi
emit_run_log_verdict PASS | tee -a "$RUNLOG"
