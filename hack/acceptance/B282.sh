#!/usr/bin/env bash
#
# k3sm B282 acceptance gate — the runnable proof that container logs are kept as
# rotated CRI FILES ON DISK and served the way a kubelet serves them.
#
# The defect: runtimed kept each container's output IN MEMORY only, capped at
# 256 KiB with oldest-first eviction (B162), wrote nothing to disk, had no
# rotation, and refused `kubectl logs --previous` as Unimplemented (B163
# residual). A chatty container's first lines were gone before anyone looked, a
# crashed container's last instance could not be read at all, and no host-level
# log shipper had anything to read. Upstream's kubelet keeps rotated on-disk
# files (containerLogMaxSize 10Mi x containerLogMaxFiles 5) and retains the
# previous instance's file.
#
# The fix is the CRI SPLIT, one writer and one reader, each in one place:
#   runtimed  writes <log_directory>/<container>/<n>.log in the CRI line format,
#             reopens it on request, reports the path on ContainerStatus, and
#             never reads or deletes a log file.
#   k3sm      creates the directories, reads the files for `kubectl logs`,
#             rotates them, garbage-collects them, computes the
#             FallbackToLogsOnError termination message, and serves the
#             kubelet's own /containerLogs HTTP surface.
#
# TWO TIERS, split by what can be proven without a live control plane:
#
#   CI TIER (always runs, CGO_ENABLED=1 in BOTH repos) — the unit-provable
#   semantics on both sides of the split. k3sm's ported reader, rotation
#   manager, log GC, termination-message tail and HTTP handler; runtimed's CRI
#   writer, two-stream pumps, instance numbering and the pod-logs sandbox deny.
#   RED BEFORE: on the unmodified tree pkg/provider/podlogs and pkg/crilog do
#   not exist, so every Go leg fails to build, and B163's superseded gate
#   (TestContainerLogOptsForwarded) is still the thing that passes.
#
#   INTEGRATION TIER (K3SM_LAB=1, a dev Mac) — a live `k3sm server` with
#   --pod-logs-dir pointed at a temp tree: a pod that writes more than 10 MiB
#   rotates with a .gz sibling, the read options match a golden, `-f` on a
#   silent container returns its headers promptly, a restart makes `--previous`
#   work, a delete takes the tree and the symlink with it, and the tree is
#   0700/0600. RED BEFORE: there is no tree at all.
#
# WHAT THIS GATE DOES NOT PROVE. The vm-path log relay (a guest's output
# reaching the same writer) needs a booted micro-VM, which is the K3SM_LAB vm
# slice, not this one; the CI tier proves the relay's resume-by-since-time logic
# against a fake guest and no more.
#
# Usage:  hack/acceptance/B282.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B282.sh # + the live single-node tier
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
WS_ROOT="$(cd "$K3SM_ROOT/.." && pwd)"
RUNTIMED_ROOT="$WS_ROOT/runtimed"
SELF="$HERE/B282.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B282 acceptance (container logs: CRI files on disk, rotated, served as the kubelet serves them)"

# ---- b282.0 — the gate parses and both halves of the split exist -----------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -d "$K3SM_ROOT/pkg/provider/podlogs" ] || b0=no
ladder "$b0" "b282.0  gate parses (bash -n) + k3sm pkg/provider/podlogs present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B282: the gate or the reader package is missing/unparseable — nothing else can run" >&2
	echo "B282: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b282.pre — the cross-repo precondition --------------------------------
# The split spans two repos: k3sm reads what runtimed writes. A k3sm-only
# checkout cannot prove the writer half, and its absence is a hard FAIL rather
# than a skip — "B282 green" must never mean "half of B282 was not checked".
pre=ok
[ -f "$WS_ROOT/go.work" ] || pre=no
ladder "$pre" "b282.pre  workspace go.work present ($WS_ROOT/go.work)"
w=ok
[ -d "$RUNTIMED_ROOT/pkg/crilog" ] || w=no
ladder "$w" "b282.pre  sibling runtimed exports pkg/crilog (the CRI writer this reader reads)"
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B282: $PASS passed, $FAIL failed (cross-repo preconditions unmet)" >&2
	exit 1
fi

# ---- b282.1 — the structural pins ------------------------------------------
# The division of labour is the whole design, so it is asserted at the source
# level as well as behaviourally: the provider must not go back to the GetLogs
# RPC for a native pod's logs, and runtimed must not grow a reader.
w=ok
grep -qE 'podlogs\.ReadLogs\(' "$K3SM_ROOT/pkg/provider/runtimed_logs.go" || w=no
grep -q 'r\.rt\.GetLogs(' "$K3SM_ROOT/pkg/provider/runtimed_logs.go" && w=no
ladder "$w" "b282.1  the provider reads the FILE (podlogs.ReadLogs) and no longer calls the GetLogs RPC"

w=ok
grep -qE 'ExtraRoutes' "$K3SM_ROOT/pkg/provider/vkadapter/vkadapter.go" || w=no
grep -qE 'ExtraRoutes:\s*containerLogRoutes\(prov\)' "$K3SM_ROOT/cmd/k3sm/node.go" || w=no
grep -qE 'HandlerPath\s*=\s*"/containerLogs/"' "$K3SM_ROOT/pkg/provider/podlogs/handler.go" || w=no
ladder "$w" "b282.1  the kubelet /containerLogs handler is registered through the ONE vkadapter seam"

w=ok
grep -qE 'EnsureContainerLogDir' "$K3SM_ROOT/pkg/install/install.go" || w=no
grep -qE 'ContainerLogDirMode fs\.FileMode = 0o700' "$K3SM_ROOT/pkg/install/install.go" || w=no
ladder "$w" "b282.1  install lays the log tree down root-equivalent (0700, group wheel)"

w=ok
grep -qE 'PodLogsDir:\s*podLogsDirOf\(cfg\)' "$K3SM_ROOT/pkg/provider/runtimed.go" || w=no
ladder "$w" "b282.1  the pod-logs root is threaded into runtimed's sandbox posture (the deny is written against the REAL tree)"

w=ok
[ -f "$K3SM_ROOT/docs/user/logs.md" ] || w=no
grep -q 'logs.md' "$K3SM_ROOT/docs/user/what-runs.md" || w=no
grep -q 'logs.md' "$K3SM_ROOT/docs/user/vm-runtimeclass.md" || w=no
ladder "$w" "b282.1  docs/user/logs.md exists and is linked from what-runs.md and vm-runtimeclass.md"

# ---- Go leg runner ----------------------------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-
# Rosetta would otherwise build the wrong arch for a darwin/arm64-only product.
# CGO_ENABLED=1 in BOTH repos (k3sm imports runtimed's cgo capability probes;
# runtimed has darwin syscall shims), so one value is correct for every leg here.
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg> [repo-root]
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever. Each leg fails unless the
# top-level `--- PASS: <TestName>` line is present and the subtest count meets
# the pinned minimum (0 for a leg with no subtests).
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" root="${5:-$K3SM_ROOT}" out rc=0 ran
	out="$(cd "$root" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}( |\$)"; then
		ladder no "$id  $name ($pkg) actually RAN — no top-level --- PASS line"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b282.2 — the READER half (k3sm) ---------------------------------------
# The ported cri-client semantics, the ported rotation manager, the deleter, the
# termination-message tail, and the HTTP status/body table.
run_test "b282.2" 15 TestReadLogsMatchesUpstream       ./pkg/provider/podlogs/
run_test "b282.2" 4  TestFindTailLineStartIndex        ./pkg/provider/podlogs/
run_test "b282.2" 6  TestContainerLogManagerRotates    ./pkg/provider/podlogs/
run_test "b282.2" 5  TestPodLogDirLifecycle            ./pkg/provider/podlogs/
run_test "b282.2" 5  TestTerminationMessageTailRing    ./pkg/provider/podlogs/
run_test "b282.2" 20 TestContainerLogsHandlerMatchesKubelet ./pkg/provider/podlogs/

# ---- b282.3 — the PROVIDER wiring (k3sm) -----------------------------------
# TestContainerLogsReadFromLogPath SUPERSEDES B163's TestContainerLogOptsForwarded:
# that gate asserted the options reached the runtime as GetLogsRequest fields;
# the contract is now that they are applied to the bytes on disk.
run_test "b282.3" 8 TestContainerLogsReadFromLogPath ./pkg/provider/
run_test "b282.3" 0 TestCreatePodSetsLogDirectory    ./pkg/provider/
run_test "b282.3" 0 TestVKImportsConfinedToAdapter   ./pkg/provider/

# ---- b282.4 — install + flags (k3sm) ---------------------------------------
run_test "b282.4" 4 TestPodLogsDirsAreRootEquivalent      ./pkg/install/
run_test "b282.4" 4 TestContainerLogFlagsMatchKubeletDefaults ./cmd/k3sm/

# ---- b282.5 — the WRITER half (runtimed) -----------------------------------
# Run in the SIBLING repo, resolved relative to this one. The writer is where a
# lost line is actually lost, so its legs are named here rather than left to the
# other repo's own gate.
run_test "b282.5" 0 TestWriterRendersCRIFormat                       ./pkg/crilog/     "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestWriterChunksAt16KiB                          ./pkg/crilog/     "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestWriterReopenLosesNothingUnderConcurrentWrites ./pkg/crilog/    "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestWriterStopsOnPersistentWriteError            ./pkg/crilog/     "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestPumpLogsChunksOversizedLine                  ./pkg/supervisor/ "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestTwoStreamCaptureLabelsStderr                 ./pkg/supervisor/ "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestLogsDrainedWaitsForBothPumps                 ./pkg/supervisor/ "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestStartUnwindsBothPipesOnFailure               ./pkg/supervisor/ "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestPumpStopsStreamOnSinkError                   ./pkg/supervisor/ "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestContainerLogFileNumberingSurvivesDaemonRestart ./pkg/runtime/  "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestContainerStatusCarriesLogPaths               ./pkg/runtime/    "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestAttachIsLiveOnly                             ./pkg/runtime/    "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestVMGuestLogFollowerResumesBySinceTime         ./pkg/runtime/    "$RUNTIMED_ROOT"
run_test "b282.5" 0 TestPodLogsRootDenied                            ./pkg/sandbox/    "$RUNTIMED_ROOT"

# ============================================================================
# INTEGRATION TIER — a live single-node control plane with its own log tree.
# Rootless: --network none, no privileged ports, ingress listeners disabled.
# ============================================================================
lab_pending() { echo "LAB-PENDING  $1"; }

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B282 INTEGRATION tier (set K3SM_LAB=1 on a dev Mac to run; no root needed):"
	lab_pending "b282.L0  \`k3sm server --pod-logs-dir <tmp>\` reaches a healthy apiserver"
	lab_pending "b282.L1  a pod's output lands at <tree>/<ns>_<pod>_<uid>/<container>/0.log in CRI format"
	lab_pending "b282.L2  a pod writing >10 MiB rotates: 0.log plus a timestamped .gz sibling"
	lab_pending "b282.L3  --tail/--since/--timestamps/--limit-bytes match a golden"
	lab_pending "b282.L4  \`kubectl logs -f\` on a silent container returns headers within 2s"
	lab_pending "b282.L5  after a restart, \`kubectl logs --previous\` returns the first instance's output"
	lab_pending "b282.L6  deleting the pod removes its log dir and its /var/log/containers symlink"
	lab_pending "b282.L7  the log tree is 0700 directories / 0600 files"
else
	B282_WORK="${B282_WORK:-/tmp/k3sm-b282}"
	K3SM_WORKDIR="$B282_WORK"
	SERVER_WORKDIR="$B282_WORK/server"
	LOGTREE="$B282_WORK/podlogs"
	B282_API_PORT=6449
	B282_KINE_PORT=2384
	B282_KUBELET_PORT=10258
	B282_SCHED_PORT=10272
	B282_CM_PORT=10270
	APISERVER_PORT="$B282_API_PORT"
	KINE_PORT="$B282_KINE_PORT"
	SERVER_PID=""
	LIB="$K3SM_ROOT/hack/lib/clusterup.sh"
	if [ ! -f "$LIB" ]; then
		ladder no "b282.L0  hack/lib/clusterup.sh present (required for the integration tier)"
		echo "----------------------------------------"
		echo "B282: $PASS passed, $FAIL failed" >&2
		exit 1
	fi
	# shellcheck source=/dev/null
	. "$LIB"
	b282_down() {
		[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
		for port in "$B282_KUBELET_PORT" "$B282_SCHED_PORT" "$B282_CM_PORT" "$APISERVER_PORT" "$KINE_PORT"; do
			reap_port "$port" warn || true
		done
	}
	trap b282_down EXIT
	if ! cluster_reset; then
		ladder no "b282.L0  cluster_reset (free this gate's ports + drop the previous datastore)"
		echo "----------------------------------------"
		echo "B282: $PASS passed, $FAIL failed" >&2
		exit 1
	fi
	rm -f "$SERVER_WORKDIR/bin"/*.cstemp
	# The node REFUSES to start on a missing log tree (only root may create the
	# real one), so the gate creates its own at the mode install would use.
	rm -rf "$LOGTREE"; mkdir -p "$LOGTREE"; chmod 0700 "$LOGTREE"
	echo "----------------------------------------"
	echo "B282 INTEGRATION tier: booting a control plane in $B282_WORK with --pod-logs-dir $LOGTREE"
	( cd "$K3SM_ROOT" && nohup env CGO_ENABLED=1 go run ./cmd/k3sm server \
		--work-dir "$SERVER_WORKDIR" --node-name b282-logs \
		--network none --runtime runtimed \
		--pod-root "$B282_WORK/pods" --pod-logs-dir "$LOGTREE" \
		--api-port "$B282_API_PORT" --kine-port "$B282_KINE_PORT" \
		--kubelet-port "$B282_KUBELET_PORT" \
		--scheduler-port "$B282_SCHED_PORT" --controller-manager-port "$B282_CM_PORT" \
		--ingress-http-port 0 --ingress-https-port 0 \
		> "$B282_WORK/server.log" 2>&1 & echo $! > "$B282_WORK/server.pid" )
	SERVER_PID="$(cat "$B282_WORK/server.pid")"

	KCFG="$SERVER_WORKDIR/k3sm.kubeconfig"
	KUBECTL="$SERVER_WORKDIR/bin/kubectl"
	# Generous because a COLD run downloads the control-plane payload and builds
	# the pinned kine first. The supervisor-alive re-check is checked LAST, not as
	# an alternative to healthz: a dead `k3sm server` can leave an apiserver child
	# answering /healthz, and a healthz-only wait then reports a healthy cluster
	# over a corpse.
	n=0; up=no
	while [ $n -lt 900 ]; do
		if [ -f "$KCFG" ] && [ -x "$KUBECTL" ] && \
			[ "$("$KUBECTL" --kubeconfig "$KCFG" get --raw /healthz 2>/dev/null)" = "ok" ]; then
			if kill -0 "$SERVER_PID" 2>/dev/null; then up=ok; break; fi
			echo "/healthz answered but \`k3sm server\` is gone — an ORPHANED apiserver, not a healthy cluster" >&2
			break
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			echo "k3sm server exited during bring-up; its last log lines:" >&2
			break
		fi
		sleep 1; n=$((n+1))
	done
	ladder "$up" "b282.L0  \`k3sm server --pod-logs-dir $LOGTREE\` reached a healthy apiserver"
	if [ "$up" != ok ]; then
		tail -30 "$B282_WORK/server.log" >&2
	else
		bkc() { "$KUBECTL" --kubeconfig "$KCFG" "$@"; }

		# A pod that prints a known line, then more than 10 MiB, then keeps
		# running. `native` is the host-binary convention, so no registry is
		# needed and the tier stays hermetic.
		cat > "$B282_WORK/chatty.yaml" <<-'YAML'
			apiVersion: v1
			kind: Pod
			metadata:
			  name: chatty
			spec:
			  nodeSelector:
			    kubernetes.io/os: darwin
			  tolerations:
			    - key: k3sm.io/provider
			      operator: Exists
			      effect: NoSchedule
			  restartPolicy: Never
			  containers:
			    - name: chatty
			      image: native
			      command: ["/bin/sh", "-c"]
			      args:
			        - >-
			          echo FIRSTLINE;
			          i=0;
			          while [ $i -lt 12000 ]; do
			            printf '%s\n' "$(head -c 900 < /dev/zero | tr '\0' 'x')";
			            i=$((i+1));
			          done;
			          echo LASTLINE;
			          sleep 600
			YAML
		bkc apply -f "$B282_WORK/chatty.yaml" >/dev/null 2>&1 || true

		# Wait for the log file to appear, then for the writer to finish.
		n=0; dir=""
		while [ $n -lt 180 ]; do
			dir="$(find "$LOGTREE" -type d -name chatty 2>/dev/null | head -1 || true)"
			[ -n "$dir" ] && [ -f "$dir/0.log" ] && break
			sleep 1; n=$((n+1))
		done
		if [ -n "$dir" ] && [ -f "$dir/0.log" ]; then
			ladder ok "b282.L1  the pod's output landed at $dir/0.log"
		else
			ladder no "b282.L1  a pod's output lands at <tree>/<ns>_<pod>_<uid>/<container>/0.log (RED before: the tree does not exist at all)"
			tail -30 "$B282_WORK/server.log" >&2
		fi

		if [ -n "$dir" ] && head -1 "$dir/0.log" 2>/dev/null | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z? (stdout|stderr) [FP] '; then
			ladder ok "b282.L1  the file is in the CRI line format (<timestamp> <stream> <F|P> <content>)"
		else
			ladder no "b282.L1  the file is in the CRI line format; first line: $(head -1 "$dir/0.log" 2>/dev/null | cut -c1-80)"
		fi

		# Rotation: >10 MiB of output must leave a timestamped sibling, and every
		# rotated file except the newest is gzipped.
		n=0; rot=no
		while [ $n -lt 180 ]; do
			if ls "$dir"/0.log.*.gz >/dev/null 2>&1; then rot=ok; break; fi
			sleep 1; n=$((n+1))
		done
		ladder "$rot" "b282.L2  >10 MiB of output rotated: 0.log plus a timestamped .gz sibling ($(ls "$dir" 2>/dev/null | tr '\n' ' '))"

		# The read options, against the file the node just wrote.
		if [ "$(bkc logs chatty --tail 1 2>/dev/null)" = "LASTLINE" ]; then
			ladder ok "b282.L3  --tail 1 returns the final line"
		else
			ladder no "b282.L3  --tail 1 returns the final line (got: $(bkc logs chatty --tail 1 2>&1 | cut -c1-60))"
		fi
		if [ "$(bkc logs chatty --tail 1 --limit-bytes 4 2>/dev/null)" = "LAST" ]; then
			ladder ok "b282.L3  --limit-bytes cuts mid-line on the rendered bytes"
		else
			ladder no "b282.L3  --limit-bytes cuts mid-line (got: $(bkc logs chatty --tail 1 --limit-bytes 4 2>&1 | cut -c1-60))"
		fi
		if bkc logs chatty --tail 1 --timestamps 2>/dev/null | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z? LASTLINE$'; then
			ladder ok "b282.L3  --timestamps prefixes the line with its own timestamp"
		else
			ladder no "b282.L3  --timestamps prefixes the line (got: $(bkc logs chatty --tail 1 --timestamps 2>&1 | cut -c1-60))"
		fi
		if [ -z "$(bkc logs chatty --since 1s --tail 5 2>/dev/null)" ]; then
			ladder ok "b282.L3  --since drops everything older than it"
		else
			ladder no "b282.L3  --since drops everything older than it"
		fi

		# `-f` on a container that has stopped printing: headers must come back
		# promptly (the zero-byte priming write), not when the stream ends.
		start=$(date +%s)
		( bkc logs chatty -f --tail 1 >/dev/null 2>&1 & sleep 2; kill %1 2>/dev/null ) >/dev/null 2>&1 || true
		elapsed=$(( $(date +%s) - start ))
		if [ "$elapsed" -le 5 ]; then
			ladder ok "b282.L4  \`kubectl logs -f\` on a silent container returns promptly (${elapsed}s)"
		else
			ladder no "b282.L4  \`kubectl logs -f\` on a silent container returns promptly (took ${elapsed}s)"
		fi

		# The tree's permissions: 0700 directories, 0600 files.
		modes="$(find "$LOGTREE" -type d -exec stat -f '%Lp' {} \; 2>/dev/null | sort -u | tr '\n' ' ')"
		fmodes="$(find "$LOGTREE" -type f -exec stat -f '%Lp' {} \; 2>/dev/null | sort -u | tr '\n' ' ')"
		if [ "$(printf '%s' "$modes" | tr -d ' ')" = "700" ] && [ "$(printf '%s' "$fmodes" | tr -d ' ')" = "600" ]; then
			ladder ok "b282.L7  the log tree is 0700 directories / 0600 files"
		else
			ladder no "b282.L7  the log tree is 0700/0600 (dirs: $modes files: $fmodes)"
		fi

		# A restart, so --previous has something to read.
		cat > "$B282_WORK/restarter.yaml" <<-'YAML'
			apiVersion: v1
			kind: Pod
			metadata:
			  name: restarter
			spec:
			  nodeSelector:
			    kubernetes.io/os: darwin
			  tolerations:
			    - key: k3sm.io/provider
			      operator: Exists
			      effect: NoSchedule
			  restartPolicy: Always
			  containers:
			    - name: restarter
			      image: native
			      command: ["/bin/sh", "-c"]
			      args: ["echo INSTANCE-$$; sleep 2; exit 1"]
			YAML
		bkc apply -f "$B282_WORK/restarter.yaml" >/dev/null 2>&1 || true
		n=0; prev=no
		while [ $n -lt 180 ]; do
			if bkc logs restarter --previous 2>/dev/null | grep -q INSTANCE-; then prev=ok; break; fi
			sleep 2; n=$((n+2))
		done
		ladder "$prev" "b282.L5  after a restart, \`kubectl logs --previous\` returns the earlier instance's output"

		# Deletion takes the tree and the symlink with it.
		poddir="$(dirname "$dir")"
		bkc delete pod chatty --wait=true --timeout=120s >/dev/null 2>&1 || true
		n=0; gone=no
		while [ $n -lt 60 ]; do
			[ -d "$poddir" ] || { gone=ok; break; }
			sleep 1; n=$((n+1))
		done
		ladder "$gone" "b282.L6  deleting the pod removed its log directory ($poddir)"
	fi
	b282_down
	trap - EXIT
fi

echo "----------------------------------------"
echo "B282: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B282 GREEN (CI + integration tiers) ================"
else
	echo "================ B282 GREEN (CI tier) ================"
fi
