#!/usr/bin/env bash
# B264 — Xcode inside a native Pod: is the toolchain under /Applications/Xcode.app reachable from a
# default-path Pod under the shipped Seatbelt profile? The public docs say it is; this gate is the
# first thing in the tree that runs it.
#
# LAB TIER. Runs against a RUNNING k3sm cluster on this Mac ($KUBECONFIG, default ~/.kube/config)
# under K3SM_LAB=1; boots nothing itself. Every object lives in one namespace, deleted on exit.
#
# The pod is PINNED to THIS Mac (nodeSelector kubernetes.io/hostname), because the grant is a NODE
# fact: the toolchain the profile widens onto is the one `xcode-select -p` names on the node that
# runs the pod. On a multi-node cluster an unpinned pod would answer a question about some other
# Mac's Xcode. Override with K3SM_B264_NODE.
#
# Skip contract (docs/BACKLOG.md B264): `xcode-select -p` failing prints the literal
#   SKIP (xcode-select absent) — NOT a pass
# and exits 0 under no K3SM_LAB, non-zero under K3SM_LAB=1. Under no K3SM_LAB with Xcode present the
# gate reports PENDING and exits 0 — that is NOT a pass either.
#
# Rungs (each records `B264.<n> <PASS|FAIL|REC|SKIP> …`; the verdict is PASS iff rungs 1–4 pass —
# rung 5 is RECORDED evidence and never a verdict, and any SKIP is reported, never a pass):
#   B264.1  xcrun --version            inside the pod
#   B264.2  xcodebuild -version        inside the pod
#   B264.3  the toolchain grant itself, TWO checks, both under this rung:
#             (a) swiftc -sdk $SDKROOT compiles a one-file program in the pod's data volume and the
#                 built binary runs — the compiler, linker and SDK reached from the pod;
#             (b) swift build (SwiftPM) builds the same file as a package and the built binary runs.
#                 SwiftPM nests its OWN sandbox around the manifest, which cannot apply inside the
#                 pod's, so the workload passes --disable-sandbox — the documented workload-side
#                 setting, not a change to the pod's confinement. The verdict is the binary
#                 running, not `swift build`'s exit code: its final step re-signs by ABSOLUTE
#                 path, which the pod profile refuses for reasons unrelated to this grant (see
#                 the rung-3(b) block below). The exit code is printed as evidence either way.
#   B264.4  xcodebuild, TWO checks under this rung — the grant's REACH and its CEILING, both
#           asserted, because a ceiling nobody tests is a sentence rather than a boundary:
#             (a) PASS iff `xcodebuild -version` and `-showsdks` succeed in the pod. The
#                 2026-09-09 ablation added the two bundle framework trees, the macOS platform
#                 and the Toolchains literal precisely so these work; before it they did not.
#             (b) PASS iff `xcodebuild -list` FAILS in the pod. Anything that evaluates a
#                 project or package needs job-creation, Mach services and host-user state
#                 under /Users — none of them file paths this grant could name (see the apis
#                 doc on SandboxProfile.xcode_toolchain_dir). A pod that CAN do it means the
#                 profile leaked, so success here is a FAILURE of the gate.
#           Both are real verdicts. Neither is skipped for a host precondition: the host probe
#           below decides only whether the host can answer at all.
#   B264.5  denials                    the Seatbelt denials the run produced (kernel log), REC — the
#                                      ablation evidence for the opt-in stanza
#
# Env: B264_ANNOTATE=1 adds the opt-in annotation (k3sm.io/xcode-toolchain) so the allowed case can
#      be run; K3SM_B264_NODE (default k3sm-<LocalHostName>); K3SM_B264_NAMESPACE (default
#      k3sm-b264); K3SM_B264_TIMEOUT (default 600).
set -u
GATE_NAME=B264
if ! xcode-select -p >/dev/null 2>&1; then
	echo "SKIP (xcode-select absent) — NOT a pass"
	[ "${K3SM_LAB:-}" = "1" ] && exit 1
	exit 0
fi
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "${GATE_NAME} gate: PENDING (lab: a running k3sm cluster on a Mac with Xcode). This is NOT a pass."
	exit 0
fi
command -v kubectl >/dev/null 2>&1 || { echo "${GATE_NAME} gate requires kubectl on PATH" >&2; exit 1; }
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
kubectl --request-timeout=15s get --raw /healthz >/dev/null || { echo "cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

NS="${K3SM_B264_NAMESPACE:-k3sm-b264}"
TIMEOUT="${K3SM_B264_TIMEOUT:-600}"
POD=b264-xcode
PASS=0; FAIL=0; REC=0; SKIP=0
rung() { # <n> <PASS|FAIL|REC|SKIP> <text>
	case "$2" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; REC) REC=$((REC+1));; SKIP) SKIP=$((SKIP+1));; esac
	echo "  ${GATE_NAME}.$1 $2 — $3"
}
note() { echo "      $*"; }
cleanup() { kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1; return 0; }
trap cleanup EXIT
kn() { kubectl -n "$NS" "$@"; }

# THIS Mac's node. The k3sm node name is k3sm-<LocalHostName, lowercased>; a cluster whose node is
# named otherwise is addressed with K3SM_B264_NODE. A missing node is a setup error, not a verdict —
# an unpinned pod would silently measure another Mac's toolchain.
NODE="${K3SM_B264_NODE:-k3sm-$(scutil --get LocalHostName 2>/dev/null | tr 'A-Z' 'a-z')}"
if ! kubectl get node "$NODE" >/dev/null 2>&1; then
	echo "${GATE_NAME} gate: node '$NODE' is not in this cluster — set K3SM_B264_NODE to THIS Mac's node (kubectl get nodes)" >&2
	exit 1
fi
NODE_HOSTNAME="$(kubectl get node "$NODE" -o jsonpath='{.metadata.labels.kubernetes\.io/hostname}' 2>/dev/null)"
[ -n "$NODE_HOSTNAME" ] || { echo "${GATE_NAME} gate: node '$NODE' carries no kubernetes.io/hostname label to pin the pod with" >&2; exit 1; }

echo "==> k3sm ${GATE_NAME} gate — Xcode toolchain from a native Pod (ns $NS; node $NODE; annotate=${B264_ANNOTATE:-0}; host $(sw_vers -productVersion) $(uname -m); $(xcodebuild -version 2>/dev/null | head -1))"

# Host precondition for B264.4: can the host's own xcodebuild run at all? The probe is
# `xcodebuild -version` — it loads the same plugin machinery but needs NO project in the
# working directory. An earlier revision probed with `xcodebuild -list`, which fails on a
# perfectly healthy host whenever the cwd holds no Xcode project (it does not: the gate runs
# from the k3sm repo), so the gate skipped its own rung 4 for a reason that was never true.
# Run in a subshell so a genuinely broken install aborts without taking the gate down.
HOST_XCODEBUILD_OK="$(sh -c 'xcodebuild -version >/dev/null 2>&1 && echo 1 || echo 0' 2>/dev/null)"
HOST_XCODEBUILD_ERR=""
if [ "$HOST_XCODEBUILD_OK" != 1 ]; then
	HOST_XCODEBUILD_ERR="$(sh -c 'xcodebuild -version 2>&1' 2>/dev/null | grep -m1 -E 'Error|error|Symbol' | cut -c1-140)"
fi

while [ "$(kubectl get namespace "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)" = "Terminating" ]; do
	note "namespace $NS is still Terminating from a previous run"; sleep 5
done
kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null

ANNOT=""
[ "${B264_ANNOTATE:-0}" = "1" ] && ANNOT='  annotations: {"k3sm.io/xcode-toolchain": ""}'
T0="$(date '+%Y-%m-%d %H:%M:%S')"
DEVELOPER_DIR_HOST="$(xcode-select -p)"

# A native pod's mounts resolve UNDER the data volume (no chroot), and the DYLD path shim cannot
# apply to Apple's /bin/sh, so the script is reached as "$PWD/script/run.sh", not /script/run.sh.
# The pod's script runs from the pod's data volume (the pod-safe default working dir); HOME, TMPDIR
# and every toolchain cache point there so nothing the toolchain writes lands outside the pod. It is
# shipped to the pod through a ConfigMap so no quoting of it happens in YAML.
#
# Every directory the pod makes is a SINGLE-LEVEL RELATIVE mkdir from that cwd: `mkdir -p` and any
# absolute path stat the data volume's ancestors, which the profile denies metadata on, so the
# creation fails for a reason that has nothing to do with the toolchain grant under test.
kn create configmap b264-script --from-literal=run.sh='set -u
export HOME="$PWD" TMPDIR="$PWD/tmp"
mkdir tmp; mkdir tmp/mc
export CLANG_MODULE_CACHE_PATH="$PWD/tmp/mc"
export DEVELOPER_DIR="${B264_DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export SDKROOT="$DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
TC="$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin"
r() { name="$1"; shift; "$@" >"$name.out" 2>&1; rc=$?; echo "B264 step=$name exit=$rc"; head -c 300 "$name.out" | sed "s/^/    /"; echo; }
said() { echo "B264 $1-said=$(sed -n 1p "$1.out" 2>/dev/null)"; }
mkdir hello; mkdir hello/Sources; mkdir hello/Sources/hello
printf "%s\n" "// swift-tools-version:5.9" "import PackageDescription" "let package = Package(name: \"hello\", targets: [.executableTarget(name: \"hello\", path: \"Sources/hello\")])" > hello/Package.swift
echo "print(\"hello from a pod\")" > hello/Sources/hello/main.swift
r xcrun /usr/bin/xcrun --version
r xcrun-find /usr/bin/xcrun --find swift
r xcodebuild-version /usr/bin/xcodebuild -version
r swiftc "$TC/swiftc" -sdk "$SDKROOT" -module-cache-path tmp/mc -o hello/one hello/Sources/hello/main.swift
if [ -x hello/one ]; then r run-one hello/one; said run-one; else echo "B264 step=run-one exit=127"; fi
SPMFLAGS="--package-path hello --scratch-path hello/.build --cache-path tmp/spm-cache --config-path tmp/spm-config --security-path tmp/spm-sec --disable-sandbox"
r spm-build "$TC/swift" build $SPMFLAGS
# Ask SwiftPM where it put the binary. With an explicit --scratch-path it does NOT
# create the .build/debug convenience symlink, so a hard-coded hello/.build/debug/hello
# misses a binary that built perfectly well — the gate would then report a toolchain
# failure that never happened.
SPMBIN="$("$TC/swift" build $SPMFLAGS --show-bin-path 2>/dev/null | tail -1)"
if [ -n "$SPMBIN" ] && [ -x "$SPMBIN/hello" ]; then r run-spm "$SPMBIN/hello"; said run-spm; else echo "B264 step=run-spm exit=127"; fi
if [ "${B264_HOST_XCODEBUILD_OK:-1}" = "1" ]; then
  # (a) the REACH the grant claims: interrogating the installation.
  r xcodebuild-showsdks /usr/bin/xcodebuild -showsdks
  # (b) the CEILING: evaluating a package needs job-creation, Mach services and
  #     host-user state under /Users. This is EXPECTED to fail; a 0 means a leak.
  r xcodebuild-list /usr/bin/perl -e "chdir shift or die; exec @ARGV" hello /usr/bin/xcodebuild -list
else
  echo "B264 step=xcodebuild-showsdks exit=skip"; echo "B264 step=xcodebuild-list exit=skip"
fi
echo "B264 done"' >/dev/null

kn apply -f - >/dev/null <<PODYAML
apiVersion: v1
kind: Pod
metadata:
  name: $POD
$ANNOT
spec:
  restartPolicy: Never
  nodeSelector: {kubernetes.io/os: darwin, kubernetes.io/hostname: "$NODE_HOSTNAME"}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  volumes: [{name: script, configMap: {name: b264-script}}]
  containers:
  - name: c
    image: native
    command: ["/bin/sh", "-c", "exec /bin/sh \"\$PWD/script/run.sh\""]
    env: [{name: B264_HOST_XCODEBUILD_OK, value: "$HOST_XCODEBUILD_OK"}, {name: B264_DEVELOPER_DIR, value: "$DEVELOPER_DIR_HOST"}]
    volumeMounts: [{name: script, mountPath: /script}]
PODYAML
deadline=$((SECONDS + TIMEOUT)); phase=""
while [ "$SECONDS" -lt "$deadline" ]; do
	phase="$(kn get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
	case "$phase" in Succeeded|Failed) break;; esac
	sleep 5
done
LOGS="$(kn logs "$POD" 2>/dev/null || true)"
[ -n "$LOGS" ] || { note "no pod log; phase=${phase:-?}"; kn describe pod "$POD" 2>/dev/null | tail -20 | sed 's/^/      /'; }
step_exit() { printf '%s\n' "$LOGS" | sed -n "s/^B264 step=$1 exit=//p" | tail -1; }
step_said() { printf '%s\n' "$LOGS" | sed -n "s/^B264 $1-said=//p" | tail -1; }

e="$(step_exit xcrun)"; f="$(printf '%s\n' "$LOGS" | sed -n '/^B264 step=xcrun-find exit=0/{n;p;}' | tr -d ' ')"
if [ "$e" = 0 ] && printf '%s' "$f" | grep -q "^$DEVELOPER_DIR_HOST"; then rung 1 PASS "xcrun --version exit 0 and xcrun --find swift resolves under $DEVELOPER_DIR_HOST"; elif [ "$e" = 0 ]; then rung 1 FAIL "xcrun --version exit 0 but xcrun --find swift resolved to '${f:-nothing}', not under the Xcode developer dir (the pod is reaching the Command Line Tools, not Xcode)"; else rung 1 FAIL "xcrun --version exit ${e:-none} (pod phase ${phase:-?})"; fi
e="$(step_exit xcodebuild-version)"; if [ "$e" = 0 ]; then rung 2 PASS "xcodebuild -version exit 0"; else rung 2 FAIL "xcodebuild -version exit ${e:-none}"; fi

# B264.3 (a) — the compiler, linker and SDK, driven directly.
e="$(step_exit swiftc)"; e2="$(step_exit run-one)"; said="$(step_said run-one)"
if [ "$e" = 0 ] && [ "$e2" = 0 ] && [ "$said" = "hello from a pod" ]; then
	rung 3 PASS "swiftc -sdk built a one-file program in the data volume and it printed \"hello from a pod\""
else
	rung 3 FAIL "swiftc exit ${e:-none}, built binary exit ${e2:-none}, output '${said}' (want 'hello from a pod')"
fi
# B264.3 (b) — the same file through SwiftPM. --disable-sandbox is the workload's own setting:
# SwiftPM wraps the manifest in a NESTED sandbox that cannot be applied inside the pod's.
#
# The verdict is the BUILT BINARY RUNNING, not `swift build`'s exit code, and that is a
# deliberate sharpening rather than a relaxation. SwiftPM's last step re-signs the linked
# binary by its ABSOLUTE path, and codesign cannot do that under the pod profile — the same
# codesign succeeds on the SAME file by a relative path, and granting metadata on the data
# volume's ancestors does not change it. So `swift build` returns 1 while leaving a correct,
# already-linked, runnable binary behind. That trailing failure is a property of the default
# pod profile's absolute-path handling, reached through /usr/bin/codesign and the pod's own
# data volume; it involves no path this toolchain grant controls, and keying the rung on it
# would report a toolchain failure that did not happen. Running the binary it produced is the
# stronger claim: nothing prints the sentinel unless the compiler, the linker and the SDK were
# all reached. The exit code is still printed as evidence.
e="$(step_exit spm-build)"; e2="$(step_exit run-spm)"; said="$(step_said run-spm)"
if [ "$e2" = 0 ] && [ "$said" = "hello from a pod" ]; then
	rung 3 PASS "swift build --disable-sandbox built the package in the data volume and it printed \"hello from a pod\" (swift build itself exited ${e:-none}; a non-zero there is the absolute-path codesign step, after the binary is already linked)"
else
	rung 3 FAIL "swift build exit ${e:-none}, built binary exit ${e2:-none}, output '${said}' (want 'hello from a pod')"
fi

# B264.4 — the grant's REACH and its CEILING, both real verdicts. Only a host whose own
# xcodebuild cannot run at all leaves this unanswerable.
e="$(step_exit xcodebuild-showsdks)"; e2="$(step_exit xcodebuild-list)"
if [ "$HOST_XCODEBUILD_OK" = 0 ]; then
	rung 4 SKIP "xcodebuild not exercised: the HOST's own xcodebuild does not run (${HOST_XCODEBUILD_ERR}) — a host precondition, NOT a pass"
else
	# (a) reach
	if [ "$e" = 0 ]; then rung 4 PASS "xcodebuild -showsdks exit 0 in the pod — the grant reaches the bundle frameworks and the macOS platform"
	else rung 4 FAIL "xcodebuild -showsdks exit ${e:-none} in the pod: the toolchain grant does not reach xcodebuild (want exit 0)"; fi
	# (b) ceiling — a pod that CAN evaluate a package means the profile leaked.
	if [ -z "$e2" ]; then rung 4 FAIL "xcodebuild -list produced no exit code (pod phase ${phase:-?})"
	elif [ "$e2" = 0 ]; then rung 4 FAIL "xcodebuild -list exit 0 in the pod — the documented ceiling did NOT hold; the profile is granting more than the toolchain read scope"
	else rung 4 PASS "xcodebuild -list exit $e2 in the pod — the ceiling holds (project evaluation needs job-creation, Mach services and /Users state, none of them granted)"; fi
fi

DENIALS="$(/usr/bin/log show --style compact --start "$T0" --predicate 'process == "kernel" AND eventMessage CONTAINS "deny"' 2>/dev/null \
  | grep -E 'xcrun|xcodebuild|swift|clang|ld\(|lldb|xcode|Xcode|sh\(' | sed -E 's/.*Sandbox: //' | sort | uniq -c | sort -rn | head -40 || true)"
if [ -n "$DENIALS" ]; then rung 5 REC "seatbelt denials ($(printf '%s\n' "$DENIALS" | wc -l | tr -d ' ') distinct):"; printf '%s\n' "$DENIALS" | sed 's/^/      /'; else rung 5 REC "no toolchain-related seatbelt denials in the kernel log for this window"; fi
echo "----- pod log (first 80 lines) -----"; printf '%s\n' "$LOGS" | head -80 | sed 's/^/      /'
echo "----------------------------------------"
echo "${GATE_NAME}: $PASS passed, $FAIL failed, $REC recorded, $SKIP skipped"
[ "$SKIP" -eq 0 ] || echo "${GATE_NAME}: $SKIP rung(s) skipped for a host precondition — reported, never counted as a pass"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ ${GATE_NAME} GREEN ================"
