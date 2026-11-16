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
# G0. The M21 P0 calibration verdicts are committed as a table under "## P0
# calibration results" in docs/design/node-budget.md, so this public gate can read
# them; the raw evidence is kept outside the repository. The table has the columns
# Q | verdict | result and the rule adopted. Each row's Q cell starts with its
# question label, and the labels are the closed set (a), (b1) to (b6), (c), (d),
# (e), (f), (g1), (g2), (h) and (i). G0 is green iff the section appears once and
# holds that table, every row has exactly three cells, every label appears exactly
# once and no other label appears, every verdict is exactly PASS, FAIL or N/A, no
# row is pending (a verdict of PENDING or TODO, or an N/A whose note starts
# "pending:"), every note is non-empty, and no table row follows the end of the
# table anywhere in the section. On a defect it prints every defect as a FAIL line,
# the first one first, and exits 1. It boots nothing and reads only the table file.
#
# What G0 attests: every P0 question is recorded with a verdict, and none is
# pending. It does not re-derive the numbers; the table is the record.
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
		BEGIN {
			insec = 0; seen_sec = 0; intable = 0; ended = 0; hdr = 0; nrows = 0; nd = 0
			nwant = split("(a) (b1) (b2) (b3) (b4) (b5) (b6) (c) (d) (e) (f) (g1) (g2) (h) (i)", want, " ")
			for (i = 1; i <= nwant; i++) known[want[i]] = 1
		}
		/^## / {
			if ($0 ~ /^## P0 calibration results[ \t]*$/) { insec = 1; seen_sec++; next }
			insec = 0
			next
		}
		!insec { next }
		# Once the table has ended, the rest of the section is still scanned: any further
		# table row (a trailing row or a second table) is a defect, never skipped.
		/^\|/ && ended { defect("row after the table at line " NR); next }
		/^\|/ {
			line = $0; sub(/[ \t]+$/, "", line)
			if (!intable) {
				intable = 1; hdr = 1
				if (split(line, h, "|") != 5) defect("line " NR ": the table header has " (split(line, h, "|") - 2) " cells, want 3 (Q, verdict, result and the rule adopted)")
				next
			}
			if (hdr == 1) {
				hdr = 2
				if ($0 !~ /^\|[-: |]+\|[ \t]*$/) defect("line " NR ": the table header is not followed by a separator row")
				next
			}
			if (line !~ /\|$/) { defect("line " NR ": the row does not end with |"); next }
			n = split(line, c, "|")
			if (n != 5) { defect("line " NR ": the row has " (n - 2) " cells, want 3 (Q, verdict, result and the rule adopted)"); next }
			qc = trim(c[2]); v = trim(c[3]); a = trim(c[4])
			nrows++
			# The label is the leading parenthesized token; a description may follow it.
			if (match(qc, /^\([a-z][0-9]*\)/)) q = substr(qc, 1, RLENGTH); else q = qc
			if (!(q in known)) { defect("line " NR ": unknown row " q); next }
			if (q in count) defect("line " NR ": row " q " appears more than once")
			count[q]++
			if (v == "PENDING" || v == "TODO") { defect("line " NR ": row " q " is pending (verdict \"" v "\")"); next }
			if (v != "PASS" && v != "FAIL" && v != "N/A") { defect("line " NR ": row " q " has verdict \"" v "\", want PASS, FAIL or N/A"); next }
			if (a == "") { defect("line " NR ": row " q " has an empty note"); next }
			if (v == "N/A" && tolower(a) ~ /^pending:/) { defect("line " NR ": row " q " is pending (N/A with a pending: note)"); next }
			ok[q] = v
			next
		}
		{ if (intable) ended = 1 }
		END {
			if (seen_sec == 0) defect("no \"## P0 calibration results\" section")
			else if (seen_sec > 1) defect("the \"## P0 calibration results\" section appears " seen_sec " times")
			else if (!intable) defect("no table under \"## P0 calibration results\"")
			if (seen_sec > 0) for (i = 1; i <= nwant; i++) if (!(want[i] in count)) defect("missing row " want[i])
			if (nd > 0) {
				for (i = 1; i <= nd; i++) print "FAIL  M21 G0: " defects[i]
				print "M21 G0: red (first defect: " defects[1] ")"
				exit 1
			}
			for (i = 1; i <= nwant; i++) print "ok    M21 G0: row " want[i] " " ok[want[i]]
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

	set +e; out="$(g0_check "$DOC")"; rc=$?; set -e
	if [ "$rc" -eq 0 ]; then ladder ok "m21.g0.2  the committed docs/design/node-budget.md parses green"
	else ladder no "m21.g0.2  docs/design/node-budget.md exit $rc, want 0:"; printf '%s\n' "$out"; fi

	# One red fixture per defect class: each must exit 1 and print its own FAIL text.
	local i=2 file want
	while IFS='|' read -r file want; do
		i=$((i + 1))
		set +e; out="$(g0_check "$TESTDATA/$file")"; rc=$?; set -e
		if [ "$rc" -eq 1 ] && grep -qF -- "FAIL  M21 G0: $want" <<<"$out"; then
			ladder ok "m21.g0.$i  testdata/m21/$file is red: $want"
		else ladder no "m21.g0.$i  testdata/m21/$file exit $rc, want 1 with FAIL text \"$want\":"; printf '%s\n' "$out"; fi
	done <<'CASES'
g0-red-missing-row.md|missing row (c)
g0-red-duplicate.md|line 24: row (a) appears more than once
g0-red-pending.md|line 9: row (a) is pending (verdict "PENDING")
g0-red-todo.md|line 9: row (a) is pending (verdict "TODO")
g0-red-pending-note.md|line 19: row (f) is pending (N/A with a pending: note)
g0-red-unknown-verdict.md|line 9: row (a) has verdict "pass", want PASS, FAIL or N/A
g0-red-empty-verdict.md|line 9: row (a) has verdict "", want PASS, FAIL or N/A
g0-red-unknown-row.md|line 24: unknown row (j)
g0-red-empty-answer.md|line 9: row (a) has an empty note
g0-red-cell-count.md|line 9: the row has 4 cells, want 3 (Q, verdict, result and the rule adopted)
g0-red-no-section.md|no "## P0 calibration results" section
g0-red-row-after-table.md|row after the table at line 27
CASES

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
