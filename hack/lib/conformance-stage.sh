#!/usr/bin/env bash
# conformance-stage.sh — the conformance helper binaries' HOST-SIDE prerequisites,
# shared by the gates that run the build-tagged e2e suite (sourced, never executed).
#
# Native pods exec a host binary path: there is no image distribution for the
# conformance helpers (e2e/testdata/cmd). The suite's TestMain builds and ad-hoc
# signs them into $K3SM_CONFORMANCE_BIN on the gate host, and the pod spec bakes
# that ABSOLUTE path in. Two consequences, one function each:
#
#   conformance_bin_preflight <dir>
#       The dir must be writable by the user running the gate, or TestMain cannot
#       rebuild into it. A previous root-run gate (hack/acceptance/m2.sh runs under
#       sudo) leaves a root-owned dir behind; say so loudly, with the remedy,
#       instead of failing later inside `go test`.
#
#   conformance_stage_worker <dir> <helper-name>...
#       A pod pinned to ANOTHER Mac execs the same absolute path THERE. With
#       $K3SM_WORKER_SSH (user@host) set, copy each helper to the identical path on
#       the worker; without it, print the prerequisite so the operator stages them.
#       The path is minted once by the caller and reused verbatim on both Macs;
#       never a per-invocation temp dir, which the worker could not match.
#
#   conformance_helper_names <repo_root>
#       The helper names. The directory e2e/testdata/cmd IS the list TestMain
#       builds (conformanceHelpers in e2e/main_test.go names one subdirectory
#       each), so it is read from there, never hand-copied.
#
# Resolution seams (the gates inject recording fakes through these, not PATH):
#   K3SM_SSH_BIN   ssh client (default: ssh)
#   K3SM_SCP_BIN   scp client (default: scp)

# conformance_helper_names <repo_root> prints one helper name per line.
conformance_helper_names() {
	local d
	for d in "$1"/e2e/testdata/cmd/*/; do
		[ -d "$d" ] || continue
		d="${d%/}"
		printf '%s\n' "${d##*/}"
	done
}

# conformance_bin_preflight <dir> returns 0 silently when <dir> is absent or
# writable and owned by the current user; else prints why and the remedy to stderr
# and returns 1.
conformance_bin_preflight() {
	local dir="$1" owner me
	[ -e "$dir" ] || return 0
	owner="$(stat -f %u "$dir" 2>/dev/null || echo unknown)"
	me="$(id -u)"
	if [ -w "$dir" ] && [ "$owner" = "$me" ]; then
		return 0
	fi
	cat >&2 <<MSG
!!! conformance helper dir is not usable by this user: $dir
!!!   owner uid: $owner   current uid: $me   writable: $([ -w "$dir" ] && echo yes || echo no)
!!!   why: a previous gate run as root (sudo) most likely created it, so the e2e
!!!        suite's TestMain cannot rebuild the helpers into it as this user.
!!!   remedy: sudo rm -rf $dir
!!!       or: export K3SM_CONFORMANCE_BIN=<a writable absolute path> -- and use the
!!!           SAME absolute path on the worker Mac (the pod spec bakes it in).
MSG
	return 1
}

# conformance_stage_worker <dir> <helper>... stages <dir>/<helper> to the same
# absolute path on $K3SM_WORKER_SSH, or prints the prerequisite when it is unset.
# Returns 1 only when a requested stage fails.
conformance_stage_worker() {
	local dir="$1"
	shift
	local target="${K3SM_WORKER_SSH:-}"
	local ssh_bin="${K3SM_SSH_BIN:-ssh}" scp_bin="${K3SM_SCP_BIN:-scp}"
	local h qdir
	if [ -z "$target" ]; then
		echo "!!! PREREQUISITE (worker Mac): the worker needs the same conformance helpers at the same absolute path $dir"
		for h in "$@"; do
			echo "!!!   $dir/$h"
		done
		echo "!!! Set K3SM_WORKER_SSH=<user@worker-host> to have this gate stage them over ssh/scp,"
		echo "!!! or copy them there by hand (chmod +x) before the worker-pinned criteria run."
		return 0
	fi
	# An option-shaped target would be parsed by ssh/scp as a flag (-oProxyCommand=...).
	case "$target" in
	-*)
		echo "conformance_stage_worker: refusing option-shaped K3SM_WORKER_SSH: $target" >&2
		return 1
		;;
	esac
	for h in "$@"; do
		if [ ! -f "$dir/$h" ]; then
			echo "conformance_stage_worker: helper not built: $dir/$h" >&2
			return 1
		fi
	done
	qdir="$(printf '%q' "$dir")"
	"$ssh_bin" "$target" "mkdir -p $qdir && chmod 755 $qdir" || {
		echo "conformance_stage_worker: mkdir $dir on $target failed" >&2
		return 1
	}
	local modes=()
	for h in "$@"; do
		"$scp_bin" "$dir/$h" "$target:$dir/" || {
			echo "conformance_stage_worker: scp $h to $target failed" >&2
			return 1
		}
		modes+=("$qdir/$(printf '%q' "$h")")
		echo "staged $h -> $target:$dir/$h"
	done
	[ "${#modes[@]}" -gt 0 ] || return 0
	"$ssh_bin" "$target" "chmod +x ${modes[*]}" || {
		echo "conformance_stage_worker: chmod +x on $target failed" >&2
		return 1
	}
}
