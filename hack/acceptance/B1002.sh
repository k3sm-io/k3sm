#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Install-root path consumers follow the versioned layout.
#
# The install tree is moving its binaries from flat files under /Library/k3sm
# into versions/<v>/, reached through current and flat compatibility links.
# Every consumer of an installed binary's path must work on both layouts: a
# path a peer reports or a Seatbelt rule matches is compared resolved, and a
# path a running pod captured stays valid across a flip.
#
# --check runs:
#   b1002.1  no unlisted install-root path consumer in the non-test Go of
#            runtimed, darwin-net and k3sm: every hit of the scan is claimed by
#            one entry of testdata/B1002/literal-paths.allow (with a reason),
#            every entry claims exactly the number of hits it lists, and every
#            hack/ shell file naming the root matches an exclude line; a
#            self-check plants each defect and requires the verdict to red
#   b1002.2  each Seatbelt allowance resolves the versioned path: runtimed's
#            TestShadowAllowFollowsVersionedDir, and k3sm's
#            TestPodPathsResolveIntoTheVersionDir (the shadow dir and the DYLD
#            shims the node hands runtimed are the resolved versions/<v>/ paths)
#   b1002.3  the vm helper peer identity check accepts the helper flat, through
#            current and under versions/<v>/, and refuses a path outside
#            versions/ or another name (TestVerifyVMHelperFollowsVersionedLayout,
#            TestVersionedBinary)
#   b1002.4  a running pod's shim paths, captured at pod start, name the version
#            directory and stay valid across a flip while that version is
#            retained as previous (TestPodShimPathSurvivesAFlip)
#
# Unit tests only, under -race: no launchd, no privilege. The sibling modules
# are the ones the k3sm build resolves (go list -m), so a workspace build checks
# the workspace's checkouts.
#
# Usage: hack/acceptance/B1002.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
ALLOW="$HERE/testdata/B1002/literal-paths.allow"

check=0
while [ $# -gt 0 ]; do
	case "$1" in
	--check) check=1; shift ;;
	*) echo "usage: $0 --check" >&2; exit 2 ;;
	esac
done
[ "$check" = 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

cd "$K3SM_ROOT"
export CGO_ENABLED=1

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

# runtest <package> <test>...: every named test must run and pass under -race.
runtest() {
	local pkg="$1"; shift
	local re out t
	re="^($(IFS='|'; echo "$*"))\$"
	if ! out="$(go test -race -count=1 -v -run "$re" "$pkg" 2>&1)"; then
		printf '%s\n' "$out" | grep -E '^(--- FAIL|FAIL|panic|.*_test\.go:[0-9]+:)' | sed -n 1,40p >&2
		echo no; return
	fi
	for t in "$@"; do
		grep -q -- "--- PASS: $t " <<<"$out" || { echo "    $t did not run in $pkg" >&2; echo no; return; }
	done
	echo ok
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/b1002.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "==> install-root path consumers follow the versioned layout"

# ---- b1002.1: the scan ------------------------------------------------------
b1=ok
[ -f "$ALLOW" ] || { echo "    missing $ALLOW" >&2; b1=no; }
RUNTIMED_DIR="$(go list -m -f '{{.Dir}}' k3sm.io/runtimed 2>/dev/null || true)"
DARWINNET_DIR="$(go list -m -f '{{.Dir}}' k3sm.io/darwin-net 2>/dev/null || true)"
# A sibling resolved into the module cache is a published copy, not the
# checkout this build compiles: outside a workspace (go.work) go list -m names
# the cache, and the scan would pass over the wrong source.
MODCACHE="$(go env GOMODCACHE 2>/dev/null || true)"
MODCACHE_REAL=""
[ -z "$MODCACHE" ] || [ ! -d "$MODCACHE" ] || MODCACHE_REAL="$(cd "$MODCACHE" && pwd -P)"
for d in "$RUNTIMED_DIR" "$DARWINNET_DIR"; do
	if [ -z "$d" ] || [ ! -d "$d" ]; then
		echo "    could not locate a sibling module (go list -m said '${d:-<nothing>}')" >&2; b1=no; continue
	fi
	real="$(cd "$d" && pwd -P)" incache=no
	for c in "$MODCACHE" "$MODCACHE_REAL"; do
		[ -n "$c" ] || continue
		case "$d/" in "$c"/*) incache=yes ;; esac
		case "$real/" in "$c"/*) incache=yes ;; esac
	done
	if [ "$incache" = yes ]; then
		echo "    sibling module $d is the module-cache copy, not a checkout; run inside the workspace (go.work)" >&2; b1=no
	fi
done

# gofiles <dir>: the non-test Go files of a module, relative, outside testdata.
gofiles() {
	if git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		git -C "$1" ls-files -- '*.go'
	else
		( cd "$1" && find . -name '*.go' -type f | sed 's|^\./||' )
	fi | grep -v '_test\.go$' | grep -v '/testdata/' | grep -v '^testdata/' || true
}

# The scan. One alternative per consumer shape:
#   a "/Library/k3sm" string literal, the root or a path under it;
#   a path built from the install root: filepath.Join or path.Join on
#     InstallDir, DefaultInstallDir or DefaultRoot, or DefaultInstallDir + "/";
#   a fmt.Sprintf whose format names /Library/k3sm;
#   a call of an installed binary path accessor (installedBinary and kin).
PATTERN='"/Library/k3sm(/[^"]*)?"'
PATTERN+='|path\.Join\(([A-Za-z_][A-Za-z0-9_]*\.)?(InstallDir|DefaultInstallDir|DefaultRoot)([^A-Za-z0-9_]|$)'
PATTERN+='|(Default)?InstallDir \+ "/"'
PATTERN+='|fmt\.Sprintf\([^"]*"[^"]*/Library/k3sm'
PATTERN+='|\.installed(Binary|ExecShim|PathShim|DNSShim|VMHost)\(\)'

# scan_repo <repo> <dir> <out>: append the scan's hits in dir to out, as
# <repo>:<path>:<line>:<text>, skipping comment lines.
scan_repo() {
	local repo="$1" dir="$2" out="$3" files
	files="$(mktemp "$tmp/files.XXXXXX")"
	gofiles "$dir" > "$files"
	[ -s "$files" ] || { echo "    no Go files found in $repo ($dir)" >&2; return 1; }
	( cd "$dir" && tr '\n' '\0' < "$files" | xargs -0 grep -nE "$PATTERN" /dev/null || true ) |
		grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' | sed "s|^|$repo:|" >> "$out" || true
}

# check_hits <hits> <allowlist> <shell-files>: the b1002.1 verdict over a hits
# file, an allowlist and the list of hack/ shell files naming the root. Prints
# each finding and the summary; returns 1 on any finding.
#
#   allow   <repo>:<path> | <needle> | <count> | <reason>
#   exclude <repo>:<glob> | <reason>
#
# A hit is claimed by the one entry whose path is its file and whose needle is
# a substring of its line; two entries claiming one hit is an ambiguous
# allowlist. Each entry must claim exactly <count> hits: one more in the file
# is a new consumer hiding behind an old line, and one fewer is a stale count.
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
check_hits() {
	local hits="$1" allowf="$2" shells="$3" ok=0
	local -a a_where=() a_needle=() a_want=() a_got=() x_glob=() x_used=()
	local line kind rest where needle count reason glob hit repo r path text i owner nhits=0 sh matched
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in ''|'#'*) continue ;; esac
		kind="${line%% *}"; rest="${line#* }"
		case "$kind" in
		allow)
			IFS='|' read -r where needle count reason <<< "$rest"
			where="$(trim "$where")"; needle="$(trim "$needle")"; count="$(trim "$count")"; reason="$(trim "$reason")"
			if [ -z "$where" ] || [ -z "$needle" ] || [ -z "$reason" ]; then
				echo "    allowlist line without a path, a needle, a count and a reason: $line" >&2; ok=1; continue
			fi
			if ! [[ "$count" =~ ^[1-9][0-9]*$ ]]; then
				echo "    allowlist line without a positive hit count: $line" >&2; ok=1; continue
			fi
			a_where+=("$where"); a_needle+=("$needle"); a_want+=("$count"); a_got+=(0) ;;
		exclude)
			glob="$(trim "${rest%%|*}")"
			reason=""; [ "$rest" != "${rest#*|}" ] && reason="$(trim "${rest#*|}")"
			if [ -z "$glob" ] || [ -z "$reason" ]; then
				echo "    exclude line without a glob and a reason: $line" >&2; ok=1; continue
			fi
			x_glob+=("$glob"); x_used+=(0) ;;
		*) echo "    allowlist line of unknown kind: $line" >&2; ok=1 ;;
		esac
	done < "$allowf"

	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		nhits=$((nhits+1))
		repo="${hit%%:*}"; r="${hit#*:}"; path="${r%%:*}"; r="${r#*:}"; text="${r#*:}"
		owner=""
		for i in "${!a_where[@]}"; do
			if [ "${a_where[$i]}" = "$repo:$path" ] && [[ "$text" == *"${a_needle[$i]}"* ]]; then
				if [ -n "$owner" ]; then
					echo "    two allowlist entries claim one hit (${a_needle[$owner]} | ${a_needle[$i]}): $hit" >&2; ok=1
				else
					owner="$i"
				fi
			fi
		done
		if [ -z "$owner" ]; then
			echo "    unlisted install-root path consumer: $hit" >&2; ok=1
		else
			a_got[owner]=$((a_got[owner]+1))
		fi
	done < "$hits"
	[ "$nhits" -gt 0 ] || { echo "    the scan found nothing; it cannot be checking anything" >&2; ok=1; }
	for i in "${!a_where[@]}"; do
		if [ "${a_got[$i]}" = 0 ]; then
			echo "    stale allowlist entry (matches nothing): ${a_where[$i]} | ${a_needle[$i]}" >&2; ok=1
		elif [ "${a_got[$i]}" -gt "${a_want[$i]}" ]; then
			echo "    more hits than listed (${a_got[$i]} > ${a_want[$i]}), a new consumer behind an allowed line: ${a_where[$i]} | ${a_needle[$i]}" >&2; ok=1
		elif [ "${a_got[$i]}" -lt "${a_want[$i]}" ]; then
			echo "    fewer hits than listed (${a_got[$i]} < ${a_want[$i]}), a stale count: ${a_where[$i]} | ${a_needle[$i]}" >&2; ok=1
		fi
	done

	# hack/ shell files naming an installed path must sit under an exclude glob.
	while IFS= read -r sh; do
		[ -n "$sh" ] || continue
		matched=no
		for i in "${!x_glob[@]}"; do
			# shellcheck disable=SC2053 # the glob is the point
			if [[ "k3sm:$sh" == ${x_glob[$i]} ]]; then x_used[i]=1; matched=yes; fi
		done
		[ "$matched" = yes ] || { echo "    hack/ shell file names the install root and is not excluded: $sh" >&2; ok=1; }
	done < "$shells"
	for i in "${!x_glob[@]}"; do
		[ "${x_used[$i]}" = 1 ] || { echo "    stale exclude (matches no shell file): ${x_glob[$i]}" >&2; ok=1; }
	done
	echo "    scanned: $nhits hits, ${#a_where[@]} allow entries, ${#x_glob[@]} excludes"
	return "$ok"
}

# self_check: the scan and the verdict red on each planted defect and pass on a
# clean plant, so a green b1002.1 means the checks are live.
self_check() {
	local plant="$tmp/plant" sc=ok name
	mkdir -p "$plant/k3sm/pkg/x"
	cat > "$plant/k3sm/pkg/x/x.go" <<'GO'
package x

const Root = "/Library/k3sm"

func a() string { return filepath.Join(c.InstallDir, "k3sm") }
GO
	: > "$plant/shells"
	cat > "$plant/allow.base" <<'ALLOW'
allow k3sm:pkg/x/x.go | Root = "/Library/k3sm" | 1 | planted root
allow k3sm:pkg/x/x.go | filepath.Join(c.InstallDir, "k3sm") | 1 | planted copy destination
ALLOW
	# expect <name> <want: pass|red> <allowlist> [<extra Go line>]
	expect() {
		local name="$1" want="$2" allowf="$3" extra="${4:-}" hits="$plant/hits.$1" got
		cp "$plant/k3sm/pkg/x/x.go" "$plant/x.go.orig"
		[ -z "$extra" ] || printf '%s\n' "$extra" >> "$plant/k3sm/pkg/x/x.go"
		: > "$hits"
		( cd "$plant/k3sm" && grep -nE "$PATTERN" pkg/x/x.go /dev/null || true ) |
			grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' | sed 's|^|k3sm:|' >> "$hits" || true
		if check_hits "$hits" "$allowf" "$plant/shells" >/dev/null 2>&1; then got=pass; else got=red; fi
		mv "$plant/x.go.orig" "$plant/k3sm/pkg/x/x.go"
		[ "$got" = "$want" ] || { echo "    self-check '$name': want $want, got $got" >&2; sc=no; }
	}
	expect clean pass "$plant/allow.base"
	expect second-hit-behind-an-entry red "$plant/allow.base" 'func b() string { return filepath.Join(c.InstallDir, "k3sm") }'
	expect path-join-default-root red "$plant/allow.base" 'func d() string { return path.Join(layout.DefaultRoot, "k3sm") }'
	expect filepath-join-default-root red "$plant/allow.base" 'func e() string { return filepath.Join(DefaultRoot, "current") }'
	expect sprintf-install-root red "$plant/allow.base" 'func f(v string) string { return fmt.Sprintf("%s/Library/k3sm/%s", "", v) }'
	expect installed-accessor red "$plant/allow.base" 'func g() string { return cfg.installedVMHost() }'
	expect a-commented-hit-is-skipped pass "$plant/allow.base" '	// return cfg.installedBinary()'
	grep -v 'planted root' "$plant/allow.base" > "$plant/allow.unlisted"
	expect unlisted red "$plant/allow.unlisted"
	{ cat "$plant/allow.base"; echo 'allow k3sm:pkg/x/x.go | nothing-matches-this | 1 | planted stale'; } > "$plant/allow.stale"
	expect stale-entry red "$plant/allow.stale"
	sed 's/| 1 | planted copy/| 2 | planted copy/' "$plant/allow.base" > "$plant/allow.overcount"
	expect stale-count red "$plant/allow.overcount"
	sed 's/| 1 | planted root/| planted root/' "$plant/allow.base" > "$plant/allow.nocount"
	expect missing-count red "$plant/allow.nocount"
	{ cat "$plant/allow.base"; echo 'allow k3sm:pkg/x/x.go | "/Library/k3sm" | 1 | planted overlap'; } > "$plant/allow.overlap"
	expect overlapping-entries red "$plant/allow.overlap"
	echo "$sc"
}

: > "$tmp/hits"
if [ "$b1" = ok ]; then
	for pair in "runtimed=$RUNTIMED_DIR" "darwin-net=$DARWINNET_DIR" "k3sm=$K3SM_ROOT"; do
		scan_repo "${pair%%=*}" "${pair#*=}" "$tmp/hits" || b1=no
	done
fi
if [ "$b1" = ok ]; then
	# The listing is captured first so a git failure is a red, and each file's
	# grep is judged by its status: 1 is no match, anything else is an error.
	shlist="$(git ls-files -- 'hack/*.sh' 'hack/**/*.sh')" || { echo "    git ls-files could not list the hack/ shell files" >&2; b1=no; }
	: > "$tmp/shells"
	if [ -n "$shlist" ]; then
		while IFS= read -r f; do
			rc=0; grep -q '/Library/k3sm/' "$f" || rc=$?
			case "$rc" in
			0) echo "$f" ;;
			1) ;;
			*) echo "    could not read $f" >&2; b1=no ;;
			esac
		done <<<"$(sort -u <<<"$shlist")" > "$tmp/shells"
	fi
	check_hits "$tmp/hits" "$ALLOW" "$tmp/shells" || b1=no
	[ "$(self_check)" = ok ] || { echo "    the scan's self-check failed (a planted case gave the wrong verdict)" >&2; b1=no; }
fi
ladder "$b1" "b1002.1  no unlisted install-root path consumer in runtimed, darwin-net, k3sm"

# ---- b1002.2: Seatbelt allowances resolve the versioned path -----------------
b2=ok
if [ -z "$RUNTIMED_DIR" ] || ! grep -qs 'func TestShadowAllowFollowsVersionedDir(' "$RUNTIMED_DIR"/pkg/sandbox/*_test.go; then
	echo "    runtimed's TestShadowAllowFollowsVersionedDir is absent from ${RUNTIMED_DIR:-<runtimed>}/pkg/sandbox" >&2
	b2=no
else
	[ "$(runtest k3sm.io/runtimed/pkg/sandbox TestShadowAllowFollowsVersionedDir)" = ok ] || b2=no
fi
[ "$(runtest ./cmd/k3sm/ TestPodPathsResolveIntoTheVersionDir)" = ok ] || b2=no
ladder "$b2" "b1002.2  each Seatbelt allowance resolves the versioned path"

# ---- b1002.3: peer identity -------------------------------------------------
b3=ok
[ "$(runtest ./pkg/install/ TestVerifyVMHelperFollowsVersionedLayout)" = ok ] || b3=no
[ "$(runtest ./pkg/updater/layout/ TestVersionedBinary)" = ok ] || b3=no
ladder "$b3" "b1002.3  vm helper identity: accepted flat, through current, under versions/; refused elsewhere"

# ---- b1002.4: a running pod's mapped shim survives a flip --------------------
ladder "$(runtest ./pkg/install/ TestPodShimPathSurvivesAFlip)" "b1002.4  a running pod's captured shim paths name the version dir and survive a flip"

echo "----------------------------------------"
echo "install-root path consumers: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
