#!/usr/bin/env bash
#
# k3sm B149 acceptance gate — the unit-tier proof of the disposable macOS-guest lab
# harness, hack/lab-vm.sh.
#
# WHAT IS PROVEN HERE. The harness's PLUMBING: that its CLI dispatch works, that it
# speaks the Tart verbs that actually exist, that it refuses to delete a guest it did
# not create, that it fails as a harness (never as a product verdict) when its own
# preconditions are unmet, that a RED in-guest run still collects evidence before it
# destroys the guest, and that no host-mutating vocabulary has leaked out of the one
# guest-mediated function.
#
# WHAT IS NOT PROVEN HERE. See the KNOWN-UNPROVEN block at the end. No VM is created,
# no image is pulled, nothing on this host is touched.
#
# HERMETIC BY CONSTRUCTION. Every external binary the harness shells out to — tart,
# ssh, scp, rsync — is replaced through the harness's own resolution seams
# (--tart-bin / --ssh-bin / --scp-bin / --rsync-bin) with a recording fake that
# appends its argv to a log. Hermeticity therefore does NOT depend on PATH shadowing,
# and it does not depend on this host lacking Tart. b149.2 is the positive control on
# exactly that: a fake that was silently bypassed reds the gate, because "the stub was
# used" is otherwise an unproven assumption on a machine that has the real tool.
#
# Usage: bash hack/acceptance/B149.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
HARNESS="$REPO_ROOT/hack/lab-vm.sh"
SELF="$HERE/B149.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B149 acceptance (disposable macOS-guest lab harness, fully faked)"

# ---- b149.0 — both deliverables exist and parse -----------------------------
b0=ok
[ -f "$HARNESS" ] || b0=no
[ -f "$SELF" ] || b0=no
if [ "$b0" = ok ]; then
	bash -n "$HARNESS" || b0=no
	bash -n "$SELF" || b0=no
fi
ladder "$b0" "b149.0  hack/lab-vm.sh + hack/acceptance/B149.sh exist and parse (bash -n)"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B149: the harness is missing or unparseable — nothing else can run" >&2
	echo "B149: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- fixtures ---------------------------------------------------------------
WORK="$(mktemp -d /tmp/b149.XXXXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

BIN="$WORK/bin"
SRC="$WORK/src"
mkdir -p "$BIN" "$SRC"
echo "workspace fixture" >"$SRC/file.txt"

LOG="$WORK/argv.log"
CLONES="$WORK/clones"
: >"$LOG"; : >"$CLONES"
export B149_LOG="$LOG" B149_CLONES="$CLONES"

# The recording fake tart. It logs EVERY argv it is handed, and answers only the
# verbs Tart actually has. There is deliberately no `snapshot` branch: the harness
# must never reach for a verb the tool does not implement, and b149.3 asserts it.
cat >"$BIN/tart" <<'FAKE'
#!/usr/bin/env bash
printf 'tart %s\n' "$*" >>"${B149_LOG:?}"
case "${1:-}" in
list)  printf 'Source Name Disk Size State\n'
       printf 'oci %s 50 20 stopped\n' 'ghcr.io/cirruslabs/macos-sequoia-base:latest'
       cat "${B149_CLONES:?}" 2>/dev/null || true ;;
ip)    printf '192.0.2.10\n' ;;
clone) printf 'oci %s 50 20 stopped\n' "${2:-}" >>"${B149_CLONES:?}" ;;
run)   exec sleep 20 ;;
esac
exit 0
FAKE

# The recording fake ssh. The in-guest gate's exit status is dictated by
# B149_GATE_RC, so the failure path can be exercised without a guest.
cat >"$BIN/ssh" <<'FAKE'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"${B149_LOG:?}"
case "$*" in
*B149GATE*) echo "fake in-guest ladder output"; exit "${B149_GATE_RC:-0}" ;;
esac
exit 0
FAKE

cat >"$BIN/scp" <<'FAKE'
#!/usr/bin/env bash
printf 'scp %s\n' "$*" >>"${B149_LOG:?}"
exit 0
FAKE

cat >"$BIN/rsync" <<'FAKE'
#!/usr/bin/env bash
printf 'rsync %s\n' "$*" >>"${B149_LOG:?}"
exit 0
FAKE
chmod +x "$BIN/tart" "$BIN/ssh" "$BIN/scp" "$BIN/rsync"

# bounded <secs> <cmd...> — run under a watchdog, returning 124 on expiry. macOS
# ships no timeout(1). Every leg that asserts "and it does not hang" goes through
# this, so a regression that waits forever reds the gate instead of wedging it.
bounded() {
	local secs="$1"; shift
	local pid killer rc=0 marker="$WORK/bounded.$$.$RANDOM"
	rm -f "$marker"
	"$@" &
	pid=$!
	( sleep "$secs"; : >"$marker"; kill -9 "$pid" 2>/dev/null || true ) >/dev/null 2>&1 &
	killer=$!
	wait "$pid" || rc=$?
	kill -TERM "$killer" 2>/dev/null || true
	wait "$killer" 2>/dev/null || true
	if [ -e "$marker" ]; then rm -f "$marker"; return 124; fi
	return "$rc"
}

# harness <args...> — drive the REAL CLI entrypoint with every seam faked and the
# deadlines shortened. Deadlines are passed as environment, which is correct here
# (unlike inside the harness's own self-test) because this spawns a fresh process.
harness() {
	env K3SM_LAB_VM_POLL=0 \
		K3SM_LAB_VM_BOOT_TIMEOUT=10 \
		K3SM_LAB_VM_SSH_TIMEOUT=10 \
		K3SM_LAB_VM_RUN_TIMEOUT=30 \
		bash "$HARNESS" \
			--tart-bin "$BIN/tart" --ssh-bin "$BIN/ssh" \
			--scp-bin "$BIN/scp" --rsync-bin "$BIN/rsync" \
			--src "$SRC" "$@"
}

# ---- b149.1 — the harness's own hermetic self-test ---------------------------
# Runs the REAL --self-test entrypoint. It builds its own fixtures and fakes; a
# non-zero exit here means the harness's internal contract broke.
st_rc=0
bounded 120 bash "$HARNESS" --self-test >"$WORK/selftest.log" 2>&1 || st_rc=$?
if [ "$st_rc" -eq 0 ]; then
	ladder ok "b149.1  hack/lab-vm.sh --self-test exits 0 (hermetic; drives its own dispatch)"
elif [ "$st_rc" -eq 124 ]; then
	ladder no "b149.1  hack/lab-vm.sh --self-test exits 0 — it HUNG past its 120s watchdog"
	sed 's/^/        /' "$WORK/selftest.log" | tail -20
else
	ladder no "b149.1  hack/lab-vm.sh --self-test exits 0 (got $st_rc)"
	sed 's/^/        /' "$WORK/selftest.log" | tail -20
fi

# ---- b149.2 — POSITIVE CONTROL on the recording fake -------------------------
# A green run against a fake that was never invoked proves nothing. This leg drives
# a full run and then requires the argv log to be non-empty AND to carry the tart
# lifecycle, so a seam that silently fell back to a real binary on PATH reds here.
: >"$LOG"; : >"$CLONES"
run_rc=0
bounded 120 harness run --gate B149GATE --out "$WORK/out-green" >"$WORK/green.log" 2>&1 || run_rc=$?
lines="$(grep -c . "$LOG" || true)"
if [ "$run_rc" -eq 0 ] && [ "$lines" -gt 0 ] && grep -q '^tart ' "$LOG" && grep -q '^ssh ' "$LOG"; then
	ladder ok "b149.2  the recording fakes were actually invoked ($lines argv lines: tart + ssh both present) and the green run exited 0"
else
	ladder no "b149.2  the recording fakes were actually invoked and the green run exited 0 (rc=$run_rc, $lines argv lines)"
	sed 's/^/        /' "$WORK/green.log" | tail -20
fi

# ---- b149.3 — Tart VOCABULARY ------------------------------------------------
# Tart has pull/clone/run/ip/stop/delete/list and NO snapshot subcommand. Asserted
# twice: over the recorded argv of a real run, and over the harness source.
vocab=ok
for verb in clone run ip delete; do
	grep -q "^tart $verb " "$LOG" || { vocab=no; echo "        missing verb in argv log: tart $verb"; }
done
grep -q 'snapshot' "$LOG" && { vocab=no; echo "        argv log contains a 'snapshot' call — Tart has no such subcommand"; }

# snap_hits <file> — occurrences of the checkpoint verb in non-comment source.
snap_hits() { grep -vE '^[[:space:]]*#' "$1" | grep -c 'snapshot' || true; }
# POSITIVE CONTROL: the same scan over a copy that DOES emit it must find it. An
# absence assertion that never demonstrated it can detect a presence is not a test.
cp "$HARNESS" "$WORK/mutant-snap.sh"
echo 'tart_cli snapshot "$name"' >>"$WORK/mutant-snap.sh"
if [ "$(snap_hits "$HARNESS")" -ne 0 ]; then
	vocab=no; echo "        hack/lab-vm.sh source emits the checkpoint verb outside a comment"
fi
if [ "$(snap_hits "$WORK/mutant-snap.sh")" -eq 0 ]; then
	vocab=no; echo "        the source scan MEASURED NOTHING — it failed to flag a deliberately mutated copy"
fi
ladder "$vocab" "b149.3  Tart vocabulary: clone/run/ip/delete recorded, no checkpoint verb in argv or source (positive control armed)"

# ---- b149.4 — STATIC SAFETY CANARY: one guest boundary ----------------------
# The harness may escalate privilege, speak to a guest's launchd, and name the k3sm
# host paths a gate creates — but ONLY inside guest_exec. Anywhere else, that
# vocabulary would be a second, unreviewed path from the harness to a real machine.
#
# Comments are excluded (the file's header discusses all of it in prose), and only
# FULL-LINE comments are stripped: a naive `s/#.*//` would corrupt shell parameter
# expansions and could delete a real call that happened to follow a '#'.
HOST_MUTATING='sudo|launchctl|/Library/k3sm|/var/lib/k3sm'

canary_outside() {
	awk '
		/^guest_exec\(\) \{/ { inr=1; next }
		inr==1 && /^\}/      { inr=0; next }
		inr==1               { next }
		{ print }
	' "$1" | grep -vE '^[[:space:]]*#' | { grep -nE "$HOST_MUTATING" || true; }
}
canary_inside() {
	awk '/^guest_exec\(\) \{/{inr=1} inr==1{print} inr==1&&/^\}/{exit}' "$1" \
		| grep -vE '^[[:space:]]*#' | { grep -cE "$HOST_MUTATING" || true; }
}

canary=ok
outside="$(canary_outside "$HARNESS")"
inside="$(canary_inside "$HARNESS")"

if [ -n "$outside" ]; then
	canary=no
	echo "        host-mutating vocabulary OUTSIDE guest_exec:"
	printf '%s\n' "$outside" | sed 's/^/          /' | head -20
fi
# POSITIVE CONTROL 1 — the boundary itself still exists and still carries the
# vocabulary. If guest_exec were renamed or emptied, the extractor above would find
# nothing anywhere and report a serene, meaningless green.
if [ "$inside" -lt 1 ]; then
	canary=no
	echo "        guest_exec contains NO host-mutating vocabulary — the boundary vanished or the extractor broke; the canary measured nothing"
fi
# POSITIVE CONTROL 2 — a deliberately mutated copy, with an escalating call appended
# at top level, MUST be flagged.
cp "$HARNESS" "$WORK/mutant-canary.sh"
printf 'sudo launchctl kickstart -k system/io.k3sm.netd\n' >>"$WORK/mutant-canary.sh"
if [ -z "$(canary_outside "$WORK/mutant-canary.sh")" ]; then
	canary=no
	echo "        the canary failed to flag a deliberately mutated copy — it proves nothing about the real file"
fi
ladder "$canary" "b149.4  host-mutating vocabulary confined to guest_exec ($inside occurrence(s) inside, 0 outside; both positive controls armed)"

# ---- b149.5 — REFUSAL: destroy a guest the harness does not own --------------
# There is no undo for a deleted guest disk, so the prefix check must be structural.
: >"$LOG"
d_rc=0
bounded 60 harness destroy "operator-precious-vm" >"$WORK/destroy.log" 2>&1 || d_rc=$?
if [ "$d_rc" -ne 0 ] && [ "$d_rc" -ne 124 ] && ! grep -q 'delete' "$LOG"; then
	ladder ok "b149.5a foreign guest name refused (exit $d_rc) and NO delete was issued"
else
	ladder no "b149.5a foreign guest name refused with no delete issued (rc=$d_rc)"
	sed 's/^/        /' "$WORK/destroy.log" | tail -10
fi
# The mirror image: a harness-owned name IS accepted, so 5a is a refusal and not a
# subcommand that never worked at all.
: >"$LOG"
d2_rc=0
bounded 60 harness destroy "k3sm-lab-b149-1-2-3" >"$WORK/destroy2.log" 2>&1 || d2_rc=$?
if [ "$d2_rc" -eq 0 ] && grep -q '^tart delete k3sm-lab-b149-1-2-3' "$LOG"; then
	ladder ok "b149.5b harness-owned guest name accepted and deleted (the refusal in 5a is selective, not universal)"
else
	ladder no "b149.5b harness-owned guest name accepted and deleted (rc=$d2_rc)"
fi

# ---- b149.6 — REFUSAL: a missing tart is a HARNESS failure, promptly ---------
# Exit 2 means "the harness broke"; it must never be confused with a product verdict,
# and it must arrive rather than hang.
: >"$LOG"
m_rc=0
bounded 60 bash "$HARNESS" --tart-bin "$WORK/definitely-absent" doctor \
	>"$WORK/notart.log" 2>&1 || m_rc=$?
if [ "$m_rc" -eq 2 ] && ! grep -q . "$LOG"; then
	ladder ok "b149.6a missing tart binary exits 2 (harness-level) without hanging and without any recorded call"
else
	ladder no "b149.6a missing tart binary exits 2 (got $m_rc; 124 means it hung past the watchdog)"
	sed 's/^/        /' "$WORK/notart.log" | tail -10
fi
# An unpinned base image is the other precondition that must refuse UP FRONT rather
# than be discovered as a readiness timeout twenty minutes into a run.
: >"$LOG"
u_rc=0
bounded 60 harness --base "docker.io/somebody/homemade:latest" run --gate B149GATE \
	>"$WORK/unpinned.log" 2>&1 || u_rc=$?
# The REASON is asserted too, not just the exit status: an unpinned base would also
# fail later as "not pulled locally", which is exit 2 with no clone as well. Only the
# pin refusal tells the operator what is actually wrong with their image.
if [ "$u_rc" -eq 2 ] && ! grep -q '^tart clone' "$LOG" \
	&& grep -q 'outside the pinned family' "$WORK/unpinned.log"; then
	ladder ok "b149.6b unpinned base image exits 2 before anything is cloned, naming the pin as the reason"
else
	ladder no "b149.6b unpinned base image exits 2 before anything is cloned, naming the pin as the reason (rc=$u_rc)"
	sed 's/^/        /' "$WORK/unpinned.log" | tail -10
fi

# ---- b149.7 — FAILURE PATH: collect before destroy, status preserved ---------
# The ladder output of a RED in-guest run is the entire reason for the exercise, so
# it must survive the teardown that follows it.
: >"$LOG"; : >"$CLONES"
f_rc=0
export B149_GATE_RC=1
bounded 120 harness run --gate B149GATE --out "$WORK/out-red" \
	>"$WORK/red.log" 2>&1 || f_rc=$?
unset B149_GATE_RC
collect_ln="$(grep -n 'tar -czf' "$LOG" | head -1 | cut -d: -f1 || true)"
delete_ln="$(grep -n '^tart delete' "$LOG" | head -1 | cut -d: -f1 || true)"
fp=ok
[ "$f_rc" -eq 1 ] || { fp=no; echo "        exit was $f_rc, want 1 (the in-guest gate failed, not the harness)"; }
[ -n "$collect_ln" ] || { fp=no; echo "        collection never ran on the failure path"; }
[ -n "$delete_ln" ] || { fp=no; echo "        the guest was never destroyed on the failure path"; }
if [ -n "$collect_ln" ] && [ -n "$delete_ln" ] && [ "$collect_ln" -ge "$delete_ln" ]; then
	fp=no; echo "        collection did not precede destruction (collect line $collect_ln, delete line $delete_ln)"
fi
[ -s "$WORK/out-red/gate.log" ] || { fp=no; echo "        the in-guest gate output was not preserved on the host"; }
ladder "$fp" "b149.7a RED in-guest gate: collect ran, then destroy fired, exit 1 preserved, gate output kept on the host"

# A non-canonical in-guest status comes back verbatim, and a raw 2 is remapped to 1
# so that a caller can never read an in-guest failure as a harness failure.
: >"$LOG"; : >"$CLONES"
v_rc=0
export B149_GATE_RC=7
bounded 120 harness run --gate B149GATE --out "$WORK/out-7" >/dev/null 2>&1 || v_rc=$?
: >"$LOG"; : >"$CLONES"
t_rc=0
export B149_GATE_RC=2
bounded 120 harness run --gate B149GATE --out "$WORK/out-2" >/dev/null 2>&1 || t_rc=$?
unset B149_GATE_RC
if [ "$v_rc" -eq 7 ] && [ "$t_rc" -eq 1 ]; then
	ladder ok "b149.7b exit-code contract: in-guest 7 returned verbatim, in-guest 2 remapped to 1 (never the harness code)"
else
	ladder no "b149.7b exit-code contract: in-guest 7 -> $v_rc (want 7), in-guest 2 -> $t_rc (want 1)"
fi

# ---- b149.8 — shellcheck (deferred if absent, never faked) -------------------
# Deliberately NOT a hard requirement. The installer gate hard-requires shellcheck
# because install.sh is fetched and executed by third parties; hack/lab-vm.sh is
# invoked by an operator from a checkout, so the deferred posture used by the other
# optional-linter gate in this directory applies instead.
if command -v shellcheck >/dev/null 2>&1; then
	sc=ok
	shellcheck -s bash "$HARNESS" || sc=no
	shellcheck -s bash "$SELF" || sc=no
	ladder "$sc" "b149.8  shellcheck clean over hack/lab-vm.sh + hack/acceptance/B149.sh"
else
	echo "NOTE  shellcheck not installed — lint deferred (brew install shellcheck); every assertion above still enforced"
fi

echo "----------------------------------------"
cat <<'UNPROVEN'
KNOWN-UNPROVEN HERE:
  - NO VIRTUAL MACHINE RAN. Every leg above is driven against recording fakes
    substituted through the harness's own resolution seams. This gate proves the
    harness's plumbing, refusals and orderings — it does not prove that a real
    macOS guest boots, that the pinned base image is reachable, or that the guest
    accepts the credentials the harness assumes.
  - The first real in-guest execution of the m2-class gate is a SEPARATE step and
    has not happened. Until it does, treat "B149 GREEN" as "the harness is wired
    correctly", never as "the host-mutating gates now run in a guest".
  - The base image's usability is a stated PRECONDITION, checked here only as a
    name-family match. Whether a given image actually ships sshd, an administrator
    account and scriptable escalation is discovered on first live use.
  - Timing is not modelled. The real boot and copy-in durations, and therefore
    whether the shipped deadlines are generous enough, are unknown until a live run.
  - The nested-virtualization ceiling is documented, not enforced: nothing here
    stops an operator pointing the harness at a gate that itself starts a VM. On an
    M3-or-later host that may work; on M1/M2 it cannot, and the failure will surface
    inside the guest rather than as a refusal.
UNPROVEN
echo "----------------------------------------"
echo "B149: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B149 GREEN ================"
