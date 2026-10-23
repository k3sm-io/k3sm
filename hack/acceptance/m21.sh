#!/usr/bin/env bash
#
# k3sm M21 gates G0, G1 and G2: node resource budget and pressure signals.
# G0 is real; G1 and G2 are still skeletons (always RED until real).
#
# # K3SM-SKELETON (the --g1 and --g2 modes, and the bare invocation)
#
# Rows in hack/acceptance/phases.json (all gate hack/acceptance/m21.sh):
#   M21-G0  --g0  tier lab, manual: false  parses the committed P0 results table
#   M21-G1  --g1  tier integration         the P1 leaves' tests plus the restart leg
#   M21-G2  --g2  tier integration         relay, taint, policy, RBAC 403 and watch,
#                                          and no node grant
# The lab-run modes --g3, --g5 and --g6 live in hack/lab/m21.sh.
#
# G0. The P0 calibration results are committed as a table under "## P0 calibration
# results" in docs/design/node-budget.md, so this public gate can read them. The
# table has the columns Q | verdict | answer | evidence (sha256 prefix). G0 is green
# iff that table has rows (a), (b), (c), (d), (e), (g) and (h) exactly once each and
# no other row ((f) was settled by a design decision and is not a measurement), each
# verdict is exactly PASS, FAIL or N/A, each answer is non-empty, and each evidence
# cell carries at least one backticked sha256 prefix of 7 or more lowercase hex
# characters. On a defect it prints every defect as a FAIL line, the first one first,
# and exits 1. It boots nothing and reads only the table file.
#
# Usage:
#   hack/acceptance/m21.sh --g0 [--table <file>]   check the committed table (or <file>)
#   hack/acceptance/m21.sh --self-test             G0 against testdata/m21 and the doc
#   hack/acceptance/m21.sh --g1 | --g2             skeleton: exits 1
#
# Honesty contract: a manual:false gate skeleton MUST exit non-zero UNCONDITIONALLY
# until real, in every skeleton mode and with no argument, because the release
# process trusts an exit 0 as "milestone proven". Pinned always-RED by
# TestNonManualSkeletonsAlwaysRed, which runs the script with no argument under BOTH
# K3SM_LAB unset and K3SM_LAB=1. Each mode is replaced by its real body in the same
# change that flips its row's skeleton flag to false.
#
# Exit: 0 green; 1 a defect or a skeleton mode; 2 usage.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/m21.sh"
DOC="$REPO_ROOT/docs/design/node-budget.md"
TESTDATA="$HERE/testdata/m21"

# g0_check <file>: print one "ok" line per row and a green summary, or every defect
# as a FAIL line (first defect first) and a red summary; return 0 iff green.
g0_check() {
	local table="$1" out rc
	if [ ! -f "$table" ]; then
		echo "FAIL  M21 G0: table file $table does not exist"
		echo "M21 G0: red (first defect: table file $table does not exist)"
		return 1
	fi
	set +e
	out="$(awk '
		function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
		function defect(msg) { defects[++nd] = msg }
		BEGIN { insec = 0; seen_sec = 0; intable = 0; done = 0; hdr = 0; nrows = 0; nd = 0 }
		/^## / {
			if ($0 ~ /^## P0 calibration results[ \t]*$/) { insec = 1; seen_sec++; next }
			if (insec) { insec = 0; if (intable) done = 1 }
			next
		}
		!insec || done { next }
		/^\|/ {
			if (!intable) { intable = 1; hdr = 1; next }
			if (hdr == 1) {
				hdr = 2
				if ($0 !~ /^\|[-: |]+\|[ \t]*$/) defect("line " NR ": the table header is not followed by a separator row")
				next
			}
			line = $0; sub(/[ \t]+$/, "", line)
			if (line !~ /\|$/) { defect("line " NR ": the row does not end with |"); next }
			n = split(line, c, "|")
			if (n != 6) { defect("line " NR ": the row has " (n - 2) " cells, want 4 (Q, verdict, answer, evidence)"); next }
			q = trim(c[2]); v = trim(c[3]); a = trim(c[4]); e = trim(c[5])
			nrows++
			if (q !~ /^\([abcdegh]\)$/) { defect("line " NR ": unknown row " q " (want one of (a) (b) (c) (d) (e) (g) (h))"); next }
			if (q in count) defect("line " NR ": row " q " appears more than once")
			count[q]++
			if (v != "PASS" && v != "FAIL" && v != "N/A") defect("line " NR ": row " q " has verdict \"" v "\", want PASS, FAIL or N/A")
			if (a == "") defect("line " NR ": row " q " has an empty answer")
			if (e !~ /`[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*`/) defect("line " NR ": row " q " has no backticked sha256 prefix of 7 or more hex characters")
			else ok[q] = v
			next
		}
		{ if (intable) done = 1 }
		END {
			if (seen_sec == 0) defect("no \"## P0 calibration results\" section")
			else if (seen_sec > 1) defect("the \"## P0 calibration results\" section appears " seen_sec " times")
			else if (!intable) defect("no table under \"## P0 calibration results\"")
			split("(a) (b) (c) (d) (e) (g) (h)", want, " ")
			for (i = 1; i <= 7; i++) if (!(want[i] in count)) defect("missing row " want[i])
			if (nd > 0) {
				for (i = 1; i <= nd; i++) print "FAIL  M21 G0: " defects[i]
				print "M21 G0: red (first defect: " defects[1] ")"
				exit 1
			}
			for (i = 1; i <= 7; i++) print "ok    M21 G0: row " want[i] " " ok[want[i]]
			print "M21 G0: green (" nrows " rows)"
		}
	' "$table")"
	rc=$?
	set -e
	printf '%s\n' "$out"
	return "$rc"
}

self_test() {
	local pass=0 fail=0 out rc
	ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; pass=$((pass + 1)); else echo "FAIL  $2"; fail=$((fail + 1)); fi; }
	echo "==> k3sm M21 G0 self-test (the P0 results table parser)"

	set +e; out="$(g0_check "$TESTDATA/g0-green.md")"; rc=$?; set -e
	if [ "$rc" -eq 0 ]; then ladder ok "m21.g0.1  testdata/m21/g0-green.md parses green"
	else ladder no "m21.g0.1  testdata/m21/g0-green.md exit $rc, want 0:"; printf '%s\n' "$out"; fi

	set +e; out="$(g0_check "$TESTDATA/g0-red.md")"; rc=$?; set -e
	if [ "$rc" -eq 1 ] && grep -q 'missing row (c)' <<<"$out" && grep -q 'row (d) has verdict' <<<"$out"; then
		ladder ok "m21.g0.2  testdata/m21/g0-red.md is red, naming the missing row (c) and the bad verdict of (d)"
	else ladder no "m21.g0.2  testdata/m21/g0-red.md exit $rc, want 1 naming both defects:"; printf '%s\n' "$out"; fi

	set +e; out="$(g0_check "$DOC")"; rc=$?; set -e
	if [ "$rc" -eq 0 ]; then ladder ok "m21.g0.3  the committed docs/design/node-budget.md parses green"
	else ladder no "m21.g0.3  docs/design/node-budget.md exit $rc, want 0:"; printf '%s\n' "$out"; fi

	echo "M21 G0 self-test: $pass passed, $fail failed"
	[ "$fail" -eq 0 ]
}

usage() { echo "usage: $SELF --g0 [--table <file>] | --self-test | --g1 | --g2   (--g1, --g2 and no argument are skeletons: they exit non-zero)"; }

case "${1:-}" in
	--g0)
		table="$DOC"
		if [ $# -ge 2 ]; then
			if [ "$2" = --table ] && [ $# -eq 3 ]; then table="$3"
			else echo "$SELF: --g0 takes only --table <file>" >&2; usage >&2; exit 2; fi
		fi
		g0_check "$table"
		exit $?
		;;
	--self-test) self_test; exit $? ;;
	-h|--help) usage; exit 0 ;;
	"") mode="all modes" ;;
	--g1|--g2) mode="${1#--}" ;;
	*) echo "$SELF: unknown argument $1 (expected --g0, --g1, --g2 or --self-test)" >&2; exit 2 ;;
esac
echo "M21 gate (${mode}): NOT YET IMPLEMENTED. The real gate lands with its M21 phase. This is a skeleton and MUST be red."
exit 1
