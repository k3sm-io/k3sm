#!/usr/bin/env bash
#
# lab-vm — run the HOST-MUTATING k3sm acceptance gates inside a DISPOSABLE macOS
# guest instead of on the operator's own Mac.
#
# WHY THIS EXISTS. The m2-class gates are not hermetic and cannot be made hermetic:
# they run `sudo k3sm install`, lay down the io.k3sm.netd + io.k3sm.server
# LaunchDaemons, create /Library/k3sm and /var/lib/k3sm, add lo0 aliases, and
# kickstart launchd jobs. Running them on a workstation leaves real daemons, real
# root-owned directories and real network state behind, and a RED run leaves them
# behind half-configured. A disposable guest gives that gate class a machine it is
# allowed to wreck: every run starts from the pristine pulled base image and the
# clone is deleted whatever the outcome.
#
# WHAT THIS IS NOT. This is NOT a milestone lab gate. It carries none of the
# hack/lab/m<N>.sh family's K3SM_LAB=1 "PENDING is not a pass" contract, it proves
# no milestone, and it is deliberately not a row in hack/acceptance/phases.json.
# It is the provisioning tool a later wiring step will call; wiring it into any
# automated flow is separate work and is not done here.
#
# BACKEND: the Tart CLI, shelled out to. Nothing here links Virtualization.framework
# and nothing here touches pkg/vmhost — that binding is Linux-guest-scoped for the
# `vm` RuntimeClass and is the wrong seam for a macOS guest.
#
# THERE IS NO `tart snapshot` SUBCOMMAND. Tart's verbs are pull, clone, run, ip,
# stop, delete, list. Disposability here is NOT a saved/restored checkpoint: it is a
# fresh `clone` off the pristine pulled base on every run, and a delete afterwards.
# Any design note you may have read that says "base image + checkpoint" is wrong
# about the tool.
#
# ---------------------------------------------------------------------------
# HARD PRECONDITION — the base image and its credentials are PINNED, and PROBED.
#
# The base MUST be a pre-provisioned image that already boots to a usable state:
# sshd enabled, a known administrator account, and administrator escalation that
# runs without an interactive password prompt. The Cirrus Labs `macos-*-base`
# images are built that way and are what the pin below names.
#
# An image you created locally from an IPSW is NOT usable here. It boots to Setup
# Assistant: no account exists, sshd is off, and nothing can be scripted. There is
# no way to recover from that over the network, so the run would sit at the
# ssh-readiness wait until its deadline. `doctor` therefore REFUSES a base outside
# the pinned family up front, with a message, rather than letting you discover it
# as a timeout twenty minutes in. Override deliberately with
# K3SM_LAB_VM_ALLOW_UNPINNED_BASE=1 once you have provisioned your own equivalent.
#
# ---------------------------------------------------------------------------
# EXIT CODE CONTRACT (a caller must be able to tell "the product broke" from
# "the harness broke"):
#
#   0   the in-guest gate passed.
#   1   the in-guest gate FAILED. This is the canonical failure code; an in-guest
#       status of 2 is also reported as 1, so that it can never be confused with a
#       harness failure. Any OTHER non-zero in-guest status is returned verbatim.
#   2   HARNESS-level failure: tart not found, an unpinned/absent base image, a
#       boot / ssh / run deadline expiry, a refused clone name, a missing
#       precondition. The product was never exercised.
#
# ---------------------------------------------------------------------------
# HONEST LIMITS — what a guest run does NOT prove.
#
#   * Paravirtualized GPU is not Metal. MLX and any GPU-backed gate stay on real
#     hardware; a green run here says nothing about them.
#   * Timing is not representative. Never quote a latency, a throughput or a
#     startup number measured in a guest as a product number.
#   * "Multi-node" means two clones on one host — Apple's licence permits at most
#     two macOS guests per host. And clone-to-clone reachability is NOT automatic:
#     the default guest networking is host-NAT, so two clones do not see each
#     other until bridged or softnet networking is configured explicitly. A future
#     multi-node slice must configure that; it must not assume it.
#   * NESTED VIRTUALIZATION CEILING. This harness targets the install / launchd /
#     networking / OOM / Seatbelt gate class ONLY. It EXCLUDES every gate that
#     itself starts a VM — i.e. anything on the `vm` RuntimeClass path — because a
#     VM inside a VM requires an M3-or-later host chip AND a macOS 15+ guest. On an
#     M1 or M2 host that path is simply unavailable, and no flag changes it.
#   * Two different things are called Rosetta and only one of them is in scope.
#     An ordinary macOS guest can translate x86_64 *macOS* binaries. That is not
#     the Rosetta-for-Linux directory share the `vm` path uses for linux/amd64
#     guests; nothing here exercises or implies the latter.
#   * Hosted CI runners are not an alternative: GitHub Actions workflows are
#     switched off across these repos by maintainer directive, so there is no
#     hosted machine to sacrifice instead. That is a statement of fact about this
#     project's CI posture, not a claim about what runners could do.
#
# ---------------------------------------------------------------------------
# SAFETY PROPERTIES (each is asserted by hack/acceptance/B149.sh):
#
#   * Every guest this harness creates is named k3sm-lab-<tag>-<pid>-<epoch>-<rand>.
#     `destroy` and `prune` REFUSE any name lacking that prefix. There is no undo
#     for a deleted guest disk, so the harness is made structurally incapable of
#     deleting a guest it did not create.
#   * `run` installs a cleanup trap on EXIT / INT / TERM before it creates
#     anything, so a killed run cannot orphan a multi-gigabyte guest. That matters
#     beyond disk: with a two-guest cap, one leak blocks the NEXT run.
#   * `run` collects evidence BEFORE it destroys, on the failure path too, and
#     preserves the gate's exit status across both. The ladder output of a RED run
#     is the entire point of the exercise.
#   * Every boot / readiness / execution wait is deadline-bounded and prints
#     `TIMEOUT after <N>s: <phase>` on expiry. Nothing here waits forever.
#   * All privileged and all guest-path knowledge lives in exactly ONE function,
#     guest_exec. Outside it this script never escalates, never speaks to launchd,
#     and never names a k3sm host path.
#
# Modes: provision · clone · run · collect · destroy · prune · doctor · --self-test
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# Every guest this harness creates carries this prefix. destroy/prune refuse
# anything else. Changing it orphans in-flight clones — prune the old ones first.
CLONE_PREFIX="k3sm-lab-"

# The pinned base family. See the HARD PRECONDITION block above.
PINNED_BASE_GLOB="ghcr.io/cirruslabs/macos-*"
BASE_IMAGE="${K3SM_LAB_VM_BASE:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"
GUEST_USER="${K3SM_LAB_VM_USER:-admin}"

# The single tart resolution seam. EVERY tart call site goes through tart_cli,
# which reads this one variable; --tart-bin overrides it. Tests point it at a
# recording fake, so hermeticity never depends on PATH shadowing.
TART_BIN="${K3SM_LAB_VM_TART_BIN:-tart}"
SSH_BIN="${K3SM_LAB_VM_SSH_BIN:-ssh}"
SCP_BIN="${K3SM_LAB_VM_SCP_BIN:-scp}"
RSYNC_BIN="${K3SM_LAB_VM_RSYNC_BIN:-rsync}"

BOOT_TIMEOUT="${K3SM_LAB_VM_BOOT_TIMEOUT:-300}"
SSH_TIMEOUT="${K3SM_LAB_VM_SSH_TIMEOUT:-300}"
RUN_TIMEOUT="${K3SM_LAB_VM_RUN_TIMEOUT:-5400}"
POLL_SECS="${K3SM_LAB_VM_POLL:-3}"

# Where the workspace tree lands inside the guest, relative to the guest home.
GUEST_SRC="k3sm-lab/src"

SRC_DIR="$REPO_ROOT"
OUT_DIR=""
GATE_CMD="hack/acceptance/m2.sh"
TAG="gate"
OLDER_THAN=0

EXIT_HARNESS=2
EXIT_GATE_FAILED=1

note() { echo "lab-vm: $*"; }
warn() { echo "lab-vm: $*" >&2; }
die()  { echo "lab-vm: $*" >&2; exit "$EXIT_HARNESS"; }

# ------------------------------------------------------------------ tart seam
tart_cli() { "$TART_BIN" "$@"; }

require_tart() {
	command -v "$TART_BIN" >/dev/null 2>&1 \
		|| die "tart CLI not found (looked for '$TART_BIN'); install Tart, or point --tart-bin / K3SM_LAB_VM_TART_BIN at it"
}

require_host_tools() {
	local missing="" t
	for t in "$SSH_BIN" "$SCP_BIN" "$RSYNC_BIN"; do
		command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
	done
	[ -z "$missing" ] || die "missing host tool(s):$missing"
}

# base_is_pinned — is the configured base inside the known-good family?
base_is_pinned() {
	[ "${K3SM_LAB_VM_ALLOW_UNPINNED_BASE:-0}" = "1" ] && return 0
	# shellcheck disable=SC2254  # the glob is the point of the comparison
	case "$BASE_IMAGE" in
		$PINNED_BASE_GLOB) return 0 ;;
		*) return 1 ;;
	esac
}

require_pinned_base() {
	base_is_pinned || die "base image '$BASE_IMAGE' is outside the pinned family '$PINNED_BASE_GLOB'.
       A locally built image has no account, no sshd and no scriptable escalation: it boots to
       Setup Assistant and this harness would only ever see a readiness deadline expire.
       Set K3SM_LAB_VM_ALLOW_UNPINNED_BASE=1 once your own image is genuinely pre-provisioned."
}

# base_present — is the base image already pulled locally?
base_present() {
	tart_cli list 2>/dev/null | grep -qF "$BASE_IMAGE"
}

# valid_user <name> — the guest account name must be a plain account name.
#
# This is a SECURITY check, not tidiness. The account was previously pasted into
# the single argv token "$GUEST_USER@$ip"; ssh parses a token beginning with '-'
# as an option however it was meant, and -oProxyCommand=<cmd> is executed BY THE
# LOCAL SHELL, ON THIS HOST, before any guest is contacted. That is a second path
# from the harness to a real machine — exactly what guest_exec exists to prevent
# and what b149.4 certifies does not exist. Two independent controls now stand in
# the way: this charset check (no leading '-', no shell metacharacters), and
# guest_exec's use of `-l <user> <host>`, which puts the account in an option
# VALUE position where it can never be re-read as a flag.
valid_user() {
	case "$1" in
		"") return 1 ;;
		-*) return 1 ;;
		*[!A-Za-z0-9._-]*) return 1 ;;
	esac
	return 0
}

# ------------------------------------------------------------- clone identity
valid_tag() {
	case "$1" in
		"") return 1 ;;
		*[!A-Za-z0-9._]*) return 1 ;;
	esac
	return 0
}

# new_clone_name <tag> — prefix + tag + pid + epoch + random, so two runs on one
# host (or two agents on one host) can never collide on a name.
new_clone_name() {
	local tag="$1" rnd
	rnd="$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
	[ -n "$rnd" ] || rnd="$RANDOM$RANDOM"
	printf '%s%s-%s-%s-%s\n' "$CLONE_PREFIX" "$tag" "$$" "$(date +%s)" "$rnd"
}

# harness_owns <name> — the destroy/prune admission predicate. A name that does not
# carry the harness prefix, or that carries anything outside the generated charset,
# is not ours and is never deleted.
harness_owns() {
	local n="$1"
	case "$n" in
		"$CLONE_PREFIX"?*) ;;
		*) return 1 ;;
	esac
	case "$n" in
		*[!A-Za-z0-9._-]*) return 1 ;;
	esac
	return 0
}

# clone_epoch <name> — the creation epoch embedded in a generated name, or empty
# when the name does not carry one (in which case prune treats its age as unknown).
clone_epoch() {
	local e
	e="$(printf '%s\n' "$1" | awk -F- '{print $(NF-1)}')"
	case "$e" in
		"" | *[!0-9]*) return 0 ;;
		*) printf '%s\n' "$e" ;;
	esac
}

# harness_clones — every harness-owned guest tart currently knows about.
# Token-scan rather than column-parse: `tart list`'s table layout is not a stable
# contract, and a column shift must not turn into a wrong name being deleted.
harness_clones() {
	{ tart_cli list 2>/dev/null || true; } \
		| tr -s ' \t' '\n' \
		| { grep -E "^${CLONE_PREFIX}[A-Za-z0-9._-]+$" || true; } \
		| sort -u
}

# ------------------------------------------------------------------ deadlines
deadline_at() { echo $(( $(date +%s) + $1 )); }
past()        { [ "$(date +%s)" -ge "$1" ]; }
timeout_msg() { echo "TIMEOUT after $1s: $2" >&2; }

# run_with_deadline <secs> <phase> <cmd...> — run a command with a wall-clock
# deadline, returning 124 (and printing the TIMEOUT line) if it expires. macOS
# ships no timeout(1), so the watchdog is open-coded: a sibling process sleeps out
# the deadline, drops a marker, then signals. `wait` is used rather than a
# kill -0 poll because a finished-but-unreaped child still answers kill -0, which
# would turn "the gate passed" into an unbounded spin.
run_with_deadline() {
	local secs="$1" phase="$2"; shift 2
	local pid killer rc=0 marker
	marker="${TMPDIR:-/tmp}/labvm-deadline.$$.$RANDOM"
	rm -f "$marker"
	"$@" &
	pid=$!
	( sleep "$secs"; : >"$marker"; kill -TERM "$pid" 2>/dev/null || true
	  sleep 5; kill -KILL "$pid" 2>/dev/null || true ) >/dev/null 2>&1 &
	killer=$!
	wait "$pid" || rc=$?
	kill -TERM "$killer" 2>/dev/null || true
	wait "$killer" 2>/dev/null || true
	if [ -e "$marker" ]; then
		rm -f "$marker"
		timeout_msg "$secs" "$phase"
		return 124
	fi
	return "$rc"
}

# =========================================================================
# guest_exec — THE ONE GUEST BOUNDARY.
#
# Everything that escalates privilege, everything that speaks to the guest's
# launchd, and every k3sm host path the gate creates is named HERE and only here.
# The acceptance gate scans this script's source and fails if any of that
# vocabulary appears outside this function, so a future edit cannot quietly grow a
# second, unreviewed path from the harness to a real machine.
#
# COPY-IN, NOT A SHARED DIRECTORY. The workspace tree is rsync'd into the guest's
# own filesystem rather than mounted with `tart run --dir`. macOS virtiofs has no
# uid remapping, so a build tree written by root in the guest over a share fails in
# obscure ownership-dependent ways on the host side. A copy costs one rsync and
# removes the whole class.
#
# HOST KEY CHECKING IS OFF on purpose: every run reaches a freshly created guest on
# a host-local address that is reused across runs, so a pinned known-hosts entry
# would produce a mismatch every time. The peer is a guest this process just
# created on this host's own NAT, not a remote server.
#
# Usage: guest_exec <mode> <ip> [args...]
#   probe   <ip>                  cheap ssh reachability check
#   exec    <ip> <cmd...>         run unprivileged in the guest source dir
#   root    <ip> <cmd...>         run with administrator escalation, no prompt
#   push    <ip> <srcdir> <dst>   copy the workspace tree in
#   collect <ip> <destdir>        pull the guest-side artifact bundle out
guest_exec() {
	local mode="$1" ip="$2"; shift 2
	# Enforced HERE, at the one boundary every remote path crosses, rather than only
	# at the flag parser: an account name is also settable from the environment, and
	# a check that sits on one of two entry paths is not a control.
	valid_user "$GUEST_USER" || die "guest account '$GUEST_USER' is not a plain account name.
       It is passed to ssh/scp/rsync, where a value beginning with '-' is read as an
       option — -oProxyCommand=<cmd> would execute <cmd> ON THIS HOST. Allowed: letters,
       digits, dot, underscore, hyphen; never leading '-'."
	local opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
		-o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes)
	local tgz="/tmp/k3sm-lab-collect.tgz"
	case "$mode" in
	probe)
		"$SSH_BIN" "${opts[@]}" -l "$GUEST_USER" "$ip" true
		;;
	exec)
		"$SSH_BIN" "${opts[@]}" -l "$GUEST_USER" "$ip" "cd $GUEST_SRC && $*"
		;;
	root)
		"$SSH_BIN" "${opts[@]}" -l "$GUEST_USER" "$ip" "cd $GUEST_SRC && sudo -n $*"
		;;
	push)
		local src="$1" dst="$2"
		"$SSH_BIN" "${opts[@]}" -l "$GUEST_USER" "$ip" "mkdir -p $dst"
		"$RSYNC_BIN" -a --delete --exclude '.git' --exclude 'k3sm-lab' \
			-e "$SSH_BIN ${opts[*]}" "$src/" "$GUEST_USER@$ip:$dst/"
		;;
	collect)
		# The guest tars up whatever the gate left behind — the k3sm install root
		# /Library/k3sm, the runtime state /var/lib/k3sm, and the guest's own
		# system log — and the bundle is copied out. Missing paths are skipped
		# rather than failing the bundle, because a run that died early
		# legitimately has none of them.
		local dest="$1"
		mkdir -p "$dest"
		chmod 0700 "$dest" 2>/dev/null || true
		"$SSH_BIN" "${opts[@]}" -l "$GUEST_USER" "$ip" \
			"for p in /Library/k3sm /var/lib/k3sm /var/log/system.log; do [ -e \"\$p\" ] && echo \"\$p\"; done | sudo -n tar -czf $tgz -T - 2>/dev/null; sudo -n chmod 0600 $tgz 2>/dev/null" \
			|| true
		"$SCP_BIN" "${opts[@]}" "$GUEST_USER@$ip:$tgz" "$dest/" || true
		;;
	*)
		die "guest_exec: unknown mode '$mode'"
		;;
	esac
}
# =========================================================================

# ------------------------------------------------------------------ lifecycle
CLONE_CREATED=""
TART_RUN_PID=""

# cleanup_clone — installed on EXIT/INT/TERM by cmd_run BEFORE the clone exists,
# so there is no window in which an interrupt orphans a guest. Idempotent: it
# clears CLONE_CREATED first, so the INT path's subsequent EXIT is a no-op.
cleanup_clone() {
	local name="$CLONE_CREATED"
	CLONE_CREATED=""
	if [ -n "$TART_RUN_PID" ]; then
		kill -TERM "$TART_RUN_PID" 2>/dev/null || true
		TART_RUN_PID=""
	fi
	[ -n "$name" ] || return 0
	harness_owns "$name" || return 0
	tart_cli stop "$name" >/dev/null 2>&1 || true
	tart_cli delete "$name" >/dev/null 2>&1 || true
	echo "lab-vm: destroyed $name" >&2
}

# wait_for_ip <name> <secs>
wait_for_ip() {
	local name="$1" secs="$2" dl ip
	dl="$(deadline_at "$secs")"
	while :; do
		ip="$(tart_cli ip "$name" 2>/dev/null || true)"
		ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
		if [ -n "$ip" ]; then
			printf '%s\n' "$ip"
			return 0
		fi
		if past "$dl"; then
			timeout_msg "$secs" "guest boot (no address from 'tart ip $name')"
			return 124
		fi
		sleep "$POLL_SECS"
	done
}

# wait_for_ssh <ip> <secs>
wait_for_ssh() {
	local ip="$1" secs="$2" dl
	dl="$(deadline_at "$secs")"
	while :; do
		if guest_exec probe "$ip" >/dev/null 2>&1; then
			return 0
		fi
		if past "$dl"; then
			timeout_msg "$secs" "ssh readiness on $ip (is the base pre-provisioned with sshd and the '$GUEST_USER' account?)"
			return 124
		fi
		sleep "$POLL_SECS"
	done
}

# ------------------------------------------------------------------- commands
cmd_provision() {
	require_tart
	require_pinned_base
	note "pulling base image $BASE_IMAGE (this is large and slow the first time)"
	tart_cli pull "$BASE_IMAGE" || die "tart pull $BASE_IMAGE failed"
	base_present || die "tart pull reported success but $BASE_IMAGE is not in 'tart list'"
	note "base image ready: $BASE_IMAGE"
}

# cmd_clone — the MANUAL escape hatch: it creates a guest and leaves it running for
# a human to poke at. Deliberately NOT trap-destroyed; that is what makes it useful
# and also what makes it your responsibility.
cmd_clone() {
	require_tart
	require_pinned_base
	base_present || die "base image $BASE_IMAGE not present locally — run: $(basename "$0") provision"
	valid_tag "$TAG" || die "invalid --tag '$TAG' (allowed: A-Za-z0-9._)"
	local name
	name="$(new_clone_name "$TAG")"
	tart_cli clone "$BASE_IMAGE" "$name" || die "tart clone $BASE_IMAGE $name failed"
	printf '%s\n' "$name"
	warn "clone $name is NOT auto-destroyed — remove it with: $(basename "$0") destroy $name  (or prune)"
}

cmd_destroy() {
	local name="$1"
	require_tart
	[ -n "$name" ] || die "usage: destroy <name>"
	harness_owns "$name" \
		|| die "REFUSING to destroy '$name': it does not carry the harness prefix '$CLONE_PREFIX'.
       This harness only ever deletes guests it created; a deleted guest disk has no undo."
	tart_cli stop "$name" >/dev/null 2>&1 || true
	tart_cli delete "$name" || die "tart delete $name failed"
	note "destroyed $name"
}

cmd_prune() {
	require_tart
	local now name epoch age n=0
	now="$(date +%s)"
	for name in $(harness_clones); do
		if ! harness_owns "$name"; then
			warn "skipping '$name' (not harness-owned)"
			continue
		fi
		epoch="$(clone_epoch "$name")"
		if [ -n "$epoch" ] && [ "$OLDER_THAN" -gt 0 ]; then
			age=$(( now - epoch ))
			if [ "$age" -lt "$OLDER_THAN" ]; then
				note "keeping $name (age ${age}s < ${OLDER_THAN}s)"
				continue
			fi
		fi
		tart_cli stop "$name" >/dev/null 2>&1 || true
		if tart_cli delete "$name" >/dev/null 2>&1; then
			note "pruned $name"
			n=$(( n + 1 ))
		else
			warn "could not delete $name"
		fi
	done
	note "pruned $n harness-owned guest(s)"
}

cmd_collect() {
	local name="$1"
	require_tart
	[ -n "$name" ] || die "usage: collect <name> [--out <dir>]"
	harness_owns "$name" || die "'$name' is not harness-owned"
	local out="${OUT_DIR:-$REPO_ROOT/lab-vm-out/$name}"
	local ip
	ip="$(wait_for_ip "$name" "$BOOT_TIMEOUT")" || exit "$EXIT_HARNESS"
	mkdir -p "$out"
	guest_exec collect "$ip" "$out"
	note "artifacts collected into $out"
}

# cmd_run — the disposable path. Ordering is load-bearing:
#   trap -> clone -> boot -> ssh -> copy-in -> GATE -> COLLECT -> DESTROY -> exit rc
# collect and destroy run on the failure path too, and the gate's status survives
# both, because the ladder output of a RED run is the evidence the whole exercise
# exists to produce.
cmd_run() {
	require_tart
	require_host_tools
	require_pinned_base
	base_present || die "base image $BASE_IMAGE not present locally — run: $(basename "$0") provision"
	valid_tag "$TAG" || die "invalid --tag '$TAG' (allowed: A-Za-z0-9._)"
	[ -d "$SRC_DIR" ] || die "--src '$SRC_DIR' is not a directory"

	trap 'cleanup_clone' EXIT
	trap 'cleanup_clone; exit 2' INT TERM

	local name out ip rc=0
	name="$(new_clone_name "$TAG")"
	out="${OUT_DIR:-$REPO_ROOT/lab-vm-out/$name}"
	mkdir -p "$out"

	note "clone $name  <- $BASE_IMAGE"
	tart_cli clone "$BASE_IMAGE" "$name" || die "tart clone failed"
	CLONE_CREATED="$name"

	note "booting $name (deadline ${BOOT_TIMEOUT}s)"
	tart_cli run "$name" --no-graphics >"$out/tart-run.log" 2>&1 &
	TART_RUN_PID=$!

	ip="$(wait_for_ip "$name" "$BOOT_TIMEOUT")" || exit "$EXIT_HARNESS"
	note "guest address $ip"

	wait_for_ssh "$ip" "$SSH_TIMEOUT" || exit "$EXIT_HARNESS"
	note "guest reachable over ssh as $GUEST_USER"

	note "copying $SRC_DIR into the guest at ~/$GUEST_SRC"
	guest_exec push "$ip" "$SRC_DIR" "$GUEST_SRC" || die "copy-in failed"

	note "running in guest: $GATE_CMD  (deadline ${RUN_TIMEOUT}s)"
	set +e
	run_with_deadline "$RUN_TIMEOUT" "in-guest gate" \
		guest_exec root "$ip" "$GATE_CMD" 2>&1 | tee "$out/gate.log"
	rc=${PIPESTATUS[0]}
	set -e

	note "collecting artifacts into $out"
	guest_exec collect "$ip" "$out" || true

	cleanup_clone

	case "$rc" in
	0)   note "in-guest gate PASSED"; exit 0 ;;
	124) warn "in-guest gate exceeded its ${RUN_TIMEOUT}s deadline"; exit "$EXIT_HARNESS" ;;
	2)   warn "in-guest gate FAILED (raw status 2, reported as 1 so it cannot be read as a harness failure)"
	     exit "$EXIT_GATE_FAILED" ;;
	*)   warn "in-guest gate FAILED (status $rc)"; exit "$rc" ;;
	esac
}

cmd_doctor() {
	local rc=0
	echo "==> lab-vm doctor"

	if command -v "$TART_BIN" >/dev/null 2>&1; then
		echo "  ok    tart resolvable ($TART_BIN)"
	else
		echo "  FAIL  tart not found ($TART_BIN) — install Tart or set K3SM_LAB_VM_TART_BIN"
		rc=1
	fi

	local t missing=""
	for t in "$SSH_BIN" "$SCP_BIN" "$RSYNC_BIN"; do
		command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
	done
	if [ -z "$missing" ]; then
		echo "  ok    host tools present ($SSH_BIN, $SCP_BIN, $RSYNC_BIN)"
	else
		echo "  FAIL  missing host tool(s):$missing"
		rc=1
	fi

	if base_is_pinned; then
		echo "  ok    base image inside the pinned family ($BASE_IMAGE)"
	else
		echo "  FAIL  base '$BASE_IMAGE' is outside '$PINNED_BASE_GLOB'."
		echo "        A locally built image boots to Setup Assistant: no account, no sshd, nothing"
		echo "        scriptable. Supply a pre-provisioned image, or set"
		echo "        K3SM_LAB_VM_ALLOW_UNPINNED_BASE=1 if yours genuinely is one."
		rc=1
	fi

	if [ "$rc" = 0 ]; then
		if base_present; then
			echo "  ok    base image present locally"
		else
			echo "  FAIL  base image not pulled yet — run: $(basename "$0") provision"
			rc=1
		fi
	fi

	local chip
	chip="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
	echo "  info  host chip: $chip"
	case "$chip" in
	*"M1"* | *"M2"*)
		echo "        note: nested virtualization needs an M3-or-later host, so no gate that"
		echo "              itself starts a VM can run in a guest on this machine."
		;;
	esac

	echo "  info  guest account '$GUEST_USER'; escalation must be scriptable without a prompt"
	echo "  info  deadlines: boot ${BOOT_TIMEOUT}s, ssh ${SSH_TIMEOUT}s, in-guest ${RUN_TIMEOUT}s"

	if [ "$rc" = 0 ]; then
		echo "doctor: ok"
	else
		echo "doctor: preconditions unmet" >&2
	fi
	[ "$rc" = 0 ] || exit "$EXIT_HARNESS"
}

# ------------------------------------------------------------------ self-test
#
# Hermetic by construction: fixtures under mktemp -d, every external binary
# replaced by a recording fake reached through the --tart-bin / --ssh-bin /
# --scp-bin / --rsync-bin seams, no VM, no network, no host mutation.
#
# Every case drives cmd_dispatch — the REAL entrypoint — rather than calling an
# internal helper, because a self-test bound to helpers stays green while the CLI
# in front of them is broken. Refusal cases run in a subshell, since `die` exits.
#
# The SOURCE-TEXT safety canaries (no checkpoint vocabulary; no escalation outside
# guest_exec) deliberately live in hack/acceptance/B149.sh instead of here: they
# have to grep for literals that this file must not otherwise contain, and a copy
# of them here would be a copy of those literals.
self_test() {
	local tmp rc=0
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN

	local log="$tmp/argv.log"
	: >"$log"

	local fake="$tmp/bin"
	mkdir -p "$fake"

	cat >"$fake/tart" <<'FAKE'
#!/usr/bin/env bash
printf 'tart %s\n' "$*" >>"${LABVM_TEST_LOG:?}"
case "${1:-}" in
list) printf 'Source Name Disk Size State\n'
      printf 'oci %s 50 20 stopped\n' "${LABVM_TEST_BASE:-ghcr.io/cirruslabs/macos-sequoia-base:latest}"
      cat "${LABVM_TEST_CLONES:-/dev/null}" 2>/dev/null || true ;;
ip)   [ "${LABVM_TEST_NO_IP:-0}" = 1 ] && exit 1
      printf '192.0.2.10\n' ;;
clone) printf '%s\n' "${2:-}" >>"${LABVM_TEST_CLONES:-/dev/null}" ;;
run)  exec sleep 20 ;;
esac
exit 0
FAKE

	cat >"$fake/ssh" <<'FAKE'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"${LABVM_TEST_LOG:?}"
case "$*" in
*LABGATE*) echo "fake in-guest gate output"; exit "${LABVM_TEST_GATE_RC:-0}" ;;
esac
exit 0
FAKE

	cat >"$fake/scp" <<'FAKE'
#!/usr/bin/env bash
printf 'scp %s\n' "$*" >>"${LABVM_TEST_LOG:?}"
exit 0
FAKE

	cat >"$fake/rsync" <<'FAKE'
#!/usr/bin/env bash
printf 'rsync %s\n' "$*" >>"${LABVM_TEST_LOG:?}"
exit 0
FAKE
	chmod +x "$fake/tart" "$fake/ssh" "$fake/scp" "$fake/rsync"

	local src="$tmp/src"
	mkdir -p "$src" && echo hi >"$src/file"

	export LABVM_TEST_LOG="$log"
	export LABVM_TEST_CLONES="$tmp/clones"
	: >"$LABVM_TEST_CLONES"

	# _lab — the REAL dispatch, with every external seam pointed at a fake. A
	# subshell, so a refusal path's `die` cannot kill the self-test.
	# The deadlines are overridden by ASSIGNING the script globals inside the
	# subshell, not by prefixing K3SM_LAB_VM_* env vars: those are read once when
	# the script is loaded, so a prefix on a function call arrives far too late and
	# every wait would run at its production length.
	_lab() {
		(
			POLL_SECS=0
			BOOT_TIMEOUT=2
			SSH_TIMEOUT=2
			RUN_TIMEOUT=10
			cmd_dispatch \
				--tart-bin "$fake/tart" --ssh-bin "$fake/ssh" \
				--scp-bin "$fake/scp" --rsync-bin "$fake/rsync" \
				--src "$src" "$@"
		)
	}
	fail() { echo "    SELF-TEST FAIL: $1"; rc=1; }

	# (1) doctor is green against the fakes and the pinned base.
	_lab doctor --out "$tmp/o1" >/dev/null 2>&1 || fail "doctor red against the fakes"

	# (2) an unpinned base is REFUSED before anything is created.
	: >"$log"
	if _lab --base "docker.io/somebody/homemade:latest" doctor >/dev/null 2>&1; then
		fail "doctor accepted an unpinned base image"
	fi
	if _lab --base "docker.io/somebody/homemade:latest" run >/dev/null 2>&1; then
		fail "run accepted an unpinned base image"
	fi
	grep -q '^tart clone' "$log" && fail "an unpinned base still reached 'tart clone'"

	# (3) generated names carry the prefix and never repeat.
	local n1 n2
	n1="$(new_clone_name t)"; n2="$(new_clone_name t)"
	harness_owns "$n1" || fail "generated name '$n1' fails its own ownership predicate"
	[ "$n1" = "$n2" ] && fail "two generated names collided"

	# (4) destroy REFUSES a foreign name, and issues no delete while doing so.
	: >"$log"
	if _lab destroy "someone-elses-vm" >/dev/null 2>&1; then
		fail "destroy accepted a name without the harness prefix"
	fi
	grep -q 'delete' "$log" && fail "a refused destroy still issued a delete"

	# (5) destroy accepts a harness-owned name.
	: >"$log"
	_lab destroy "${CLONE_PREFIX}selftest-1-2-3" >/dev/null 2>&1 \
		|| fail "destroy refused a harness-owned name"
	grep -q "^tart delete ${CLONE_PREFIX}selftest-1-2-3" "$log" \
		|| fail "destroy did not issue tart delete"

	# (6) prune touches harness-owned guests ONLY.
	: >"$log"
	{ printf 'oci %s 1 1 stopped\n' "${CLONE_PREFIX}alpha-1-2-3"
	  printf 'oci %s 1 1 stopped\n' "operator-precious-vm"; } >"$LABVM_TEST_CLONES"
	_lab prune >/dev/null 2>&1 || fail "prune failed"
	grep -q "^tart delete ${CLONE_PREFIX}alpha-1-2-3" "$log" \
		|| fail "prune skipped a harness-owned guest"
	grep -q 'operator-precious-vm' "$log" \
		&& fail "prune touched a guest the harness does not own"
	: >"$LABVM_TEST_CLONES"

	# (7) a missing tart binary is a HARNESS failure (exit 2), promptly.
	: >"$log"
	local rc2=0
	( cmd_dispatch --tart-bin "$tmp/definitely-absent" doctor ) >/dev/null 2>&1 || rc2=$?
	[ "$rc2" = "$EXIT_HARNESS" ] || fail "missing tart gave exit $rc2, want $EXIT_HARNESS"

	# (8) a guest that never gets an address hits the boot deadline and says so.
	: >"$log"
	local rc3=0
	export LABVM_TEST_NO_IP=1
	_lab run --gate LABGATE --out "$tmp/out3" >"$tmp/boot.log" 2>&1 || rc3=$?
	unset LABVM_TEST_NO_IP
	[ "$rc3" = "$EXIT_HARNESS" ] || fail "boot timeout gave exit $rc3, want $EXIT_HARNESS"
	grep -q '^TIMEOUT after .*: guest boot' "$tmp/boot.log" \
		|| fail "boot timeout printed no TIMEOUT line"
	# Cleanup is asserted from the RECORDED CALL, not from the trap's message: an
	# EXIT trap set inside a nested subshell writes outside an enclosing command
	# substitution's redirect (a bash behaviour, reproduced), and the tart call is
	# the stronger evidence regardless.
	grep -q '^tart delete' "$log" \
		|| fail "boot timeout left the clone undestroyed"

	# (9) THE FAILURE PATH: a RED in-guest gate still collects, still destroys, and
	#     still reports a gate failure rather than a harness failure.
	: >"$log"
	local rc4=0
	export LABVM_TEST_GATE_RC=1
	( _lab run --gate LABGATE --out "$tmp/out4" ) >/dev/null 2>&1 || rc4=$?
	unset LABVM_TEST_GATE_RC
	[ "$rc4" = "$EXIT_GATE_FAILED" ] || fail "red gate gave exit $rc4, want $EXIT_GATE_FAILED"
	grep -q 'tar -czf' "$log" || fail "red gate skipped collection"
	grep -q '^tart delete' "$log" || fail "red gate skipped destruction"
	local ci di
	ci="$(grep -n 'tar -czf' "$log" | head -1 | cut -d: -f1)"
	di="$(grep -n '^tart delete' "$log" | head -1 | cut -d: -f1)"
	[ -n "$ci" ] && [ -n "$di" ] && [ "$ci" -lt "$di" ] \
		|| fail "collection did not precede destruction"
	[ -s "$tmp/out4/gate.log" ] || fail "the in-guest gate output was not preserved on the host"

	# (10) a non-canonical in-guest status is returned verbatim; a raw 2 is not.
	: >"$log"
	local rc5=0 rc6=0
	export LABVM_TEST_GATE_RC=7
	( _lab run --gate LABGATE --out "$tmp/out5" ) >/dev/null 2>&1 || rc5=$?
	[ "$rc5" = 7 ] || fail "in-guest status 7 came back as $rc5"
	export LABVM_TEST_GATE_RC=2
	( _lab run --gate LABGATE --out "$tmp/out6" ) >/dev/null 2>&1 || rc6=$?
	unset LABVM_TEST_GATE_RC
	[ "$rc6" = "$EXIT_GATE_FAILED" ] \
		|| fail "in-guest status 2 came back as $rc6, want $EXIT_GATE_FAILED (never the harness code)"

	# (11) the happy path is green and leaves nothing behind.
	: >"$log"
	local rc7=0
	( _lab run --gate LABGATE --out "$tmp/out7" ) >/dev/null 2>&1 || rc7=$?
	[ "$rc7" = 0 ] || fail "green gate gave exit $rc7"
	grep -q '^tart clone' "$log" || fail "green run issued no clone"
	grep -q '^tart delete' "$log" || fail "green run left the clone alive"

	# (12) STRUCTURAL: the usage text and the dispatch table agree. A subcommand
	#      implemented but undocumented (or documented but unrouted) is a CLI defect
	#      no behavioural case can see.
	local implemented documented w
	implemented="$(grep -oE '^cmd_[a-z]+\(\)' "${BASH_SOURCE[0]}" | sed 's/^cmd_//; s/()//' \
		| grep -v '^dispatch$' | sort -u)"
	( cmd_dispatch ) 2>"$tmp/usage.txt" >/dev/null || true
	documented="$(awk '/^  [a-z]/{print $1}' "$tmp/usage.txt" | sort -u)"
	for w in $implemented; do
		printf '%s\n' "$documented" | grep -qx "$w" || fail "subcommand '$w' is implemented but absent from the usage text"
	done

	unset LABVM_TEST_LOG LABVM_TEST_CLONES

	if [ "$rc" = 0 ]; then
		echo "    self-test: dispatch, unpinned-base refusal, name generation, foreign-name destroy refusal, prune ownership, missing-tart exit 2, boot deadline, collect-before-destroy on a RED gate, exit-code contract, usage/dispatch parity"
	fi
	return "$rc"
}

# ------------------------------------------------------------------- dispatch
cmd_dispatch() {
	local sub="" name="" npos=0
	while [ $# -gt 0 ]; do
		case "$1" in
		--tart-bin)     TART_BIN="$2"; shift 2 ;;
		--ssh-bin)      SSH_BIN="$2"; shift 2 ;;
		--scp-bin)      SCP_BIN="$2"; shift 2 ;;
		--rsync-bin)    RSYNC_BIN="$2"; shift 2 ;;
		--base)         BASE_IMAGE="$2"; shift 2 ;;
		--user)         GUEST_USER="$2"; shift 2 ;;
		--src)          SRC_DIR="$2"; shift 2 ;;
		--out)          OUT_DIR="$2"; shift 2 ;;
		--gate)         GATE_CMD="$2"; shift 2 ;;
		--tag)          TAG="$2"; shift 2 ;;
		--older-than)   OLDER_THAN="$2"; shift 2 ;;
		*)              npos=$(( npos + 1 ))
		                [ "$npos" = 1 ] && sub="$1"
		                [ "$npos" = 2 ] && name="$1"
		                shift ;;
		esac
	done

	case "$sub" in
	provision) cmd_provision ;;
	clone)     cmd_clone ;;
	run)       cmd_run ;;
	collect)   cmd_collect "$name" ;;
	destroy)   cmd_destroy "$name" ;;
	prune)     cmd_prune ;;
	doctor)    cmd_doctor ;;
	*)         cat >&2 <<EOF
usage: $(basename "$0") <command> [options]

  provision          pull the pinned base image
  clone              create a guest and LEAVE it running (you destroy it)
  run                clone -> boot -> copy in -> gate -> collect -> destroy
  collect <name>     pull the guest-side artifact bundle out
  destroy <name>     stop + delete a guest this harness created
  prune              delete harness-owned guests (--older-than <secs>)
  doctor             check every precondition and report
  --self-test        hermetic; no VM, no network, no host mutation

options:
  --tart-bin <p>   --ssh-bin <p>   --scp-bin <p>   --rsync-bin <p>
  --base <ref>     --user <name>   --src <dir>     --out <dir>
  --gate <cmd>     --tag <t>       --older-than <secs>

exit: 0 gate passed · 1 gate failed · 2 harness failure
EOF
	           exit "$EXIT_HARNESS" ;;
	esac
}

case "${1:-}" in
--self-test) self_test; exit $? ;;
*)           cmd_dispatch "$@" ;;
esac
