#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# No hack/ script pipes a producer into an early-exiting grep -q, head,
# grep -m or grep -l (the last three only in scripts that set pipefail).
#
# Under set -o pipefail, `producer | grep -q pattern` can fail on a run that
# matched: grep exits at its first match, the producer's next write takes
# SIGPIPE (exit 141) (head, grep -m and grep -l exit early the same way), and pipefail reports the whole pipeline as failed, so a
# gate reads a test that passed as one that did not run. A here-string over a
# captured value (`grep -q -- pat <<<"$out"`) has no writer process to kill.
#
# --check runs:
#   scan        every shell script under hack/ (a *.sh name or a shell
#               shebang, heredoc payloads included) holds no pipeline that ends
#               in grep, egrep or fgrep with -q, --quiet or --silent. Every
#               script is scanned, not only those that set pipefail: a sourced
#               library and a heredoc payload run under the options of the
#               shell that runs them. There is no allowlist.
#   self-check  the scanner reds on each planted shape in
#               testdata/B1080/offending.txt (a printf producer, a command
#               producer, a multi-stage pipeline, pipe and backslash
#               continuations, `command grep`, --quiet, a heredoc payload, a
#               double-quoted remote command) and passes each shape in
#               testdata/B1080/clean.txt (a here-string, grep -c, grep -v,
#               `||`, a quoted or commented pipeline)
#   transcript  a `go test -v` style transcript over 64 KiB, more than a pipe
#               buffer holds, is matched through a here-string under pipefail
#               at its first line and its last, and a name it lacks is not
#
# The scanner reads lines, not a parse tree. A pipeline inside single quotes
# (an awk program, a string handed to eval) or one assembled at run time is
# not seen.
#
# Usage: hack/acceptance/B1080.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
FIXTURES="$HERE/testdata/B1080"
ME="$(basename "$0" .sh)"

[ "${1:-}" = "--check" ] && [ $# -eq 1 ] || { echo "usage: $0 --check" >&2; exit 2; }

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/pipefail-grep.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# SCAN_AWK prints <file>:<line>: <text> for every pipeline into grep -q, and,
# when strict is set (the script sets pipefail), into head, grep -m or grep -l. A
# command continued over lines (a trailing backslash or a trailing pipe) is
# joined first. Comment lines, trailing comments and single-quoted text are
# dropped; double-quoted text is kept, because a command string handed to a
# remote shell is double-quoted. `||` is not a pipe.
# shellcheck disable=SC2016 # an awk program: awk expands its own $ fields
SCAN_AWK='
FNR == 1 { buf = "" }
{
	line = $0
	if (buf == "") start = FNR
	if (line ~ /\\$/) { buf = buf substr(line, 1, length(line) - 1) " "; next }
	if (line ~ /\|[ \t]*$/ && line !~ /\|\|[ \t]*$/) { buf = buf line " "; next }
	full = buf line; buf = ""
	t = full
	sub(/^[ \t]*/, "", t)
	if (substr(t, 1, 1) == "#") next
	gsub(/\047[^\047]*\047/, "", t)
	sub(/[ \t]#.*$/, "", t)
	gsub(/\|\|/, "  ", t)
	n = split(t, seg, "|")
	for (i = 2; i <= n; i++) {
		s = seg[i]
		sub(/[;&)].*$/, "", s)
		sub(/^[ \t!]*/, "", s)
		sub(/^command[ \t]+/, "", s)
		if (strict && s ~ /^head([ \t]|$)/) {
			print FILENAME ":" start ": " full
			break
		}
		if (s !~ /^[ef]?grep([ \t]|$)/) continue
		if (s ~ /[ \t](-[A-Za-z0-9]*q[A-Za-z0-9]*|--quiet|--silent)([ \t]|$)/) {
			print FILENAME ":" start ": " full
			break
		}
		if (strict && s ~ /[ \t](-[A-Za-z0-9]*[lm][A-Za-z0-9]*|--max-count|--files-with-matches)([ \t=]|$)/) {
			print FILENAME ":" start ": " full
			break
		}
	}
}'

# list_scripts <root>: the shell scripts under <root>/hack, relative to <root>:
# the tracked and untracked unignored files when <root> is a git work tree,
# else every file.
list_scripts() {
	local root="$1" files f first
	if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		files="$(git -C "$root" ls-files --cached --others --exclude-standard -- hack)" || return 1
	else
		files="$(cd "$root" && find hack -type f)" || return 1
	fi
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		case "$f" in *.sh) echo "$f"; continue ;; esac
		first="$(head -n 1 "$root/$f" 2>/dev/null || true)"
		case "$first" in '#!'*sh|'#!'*'sh '*|'#!'*bash*|'#!'*zsh*) echo "$f" ;; esac
	done <<<"$files"
}

# scan <dir> <list>: run SCAN_AWK over the files named in <list>, relative to
# <dir>. Prints the hits; returns non-zero only when awk fails.
scan() {
	local dir="$1" list="$2" f strict
	(
		cd "$dir" || exit 1
		while IFS= read -r f; do
			[ -n "$f" ] || continue
			strict=0
			grep -Eq '^[^#]*pipefail' "$f" && strict=1
			awk -v strict="$strict" "$SCAN_AWK" "$f" || exit 1
		done < "$list"
	)
}

# blocks <fixture> <prefix>: split a fixture into one planted script per
# block, each setting pipefail. Prints the number of blocks.
blocks() {
	local fixture="$1" prefix="$2" n=0 line open=no
	while IFS= read -r line || [ -n "$line" ]; do
		if [ "$open" = no ]; then
			case "$line" in '#'*) continue ;; esac
			n=$((n+1)); open=yes
			printf '#!/usr/bin/env bash\nset -euo pipefail\n' > "$prefix.$n.sh"
		fi
		if [ "$line" = '%%' ]; then open=no; continue; fi
		printf '%s\n' "$line" >> "$prefix.$n.sh"
	done < "$fixture"
	echo "$n"
}

cd "$K3SM_ROOT"

# ---- scan ---------------------------------------------------------------------
s1=ok
if ! list_scripts "$K3SM_ROOT" > "$tmp/scripts"; then
	echo "    could not list the files under hack/" >&2; s1=no
fi
nscripts="$(wc -l < "$tmp/scripts" | tr -d ' ')"
[ "$nscripts" -gt 0 ] || { echo "    no shell scripts found under hack/; the scan checks nothing" >&2; s1=no; }
if [ "$s1" = ok ]; then
	if hits="$(scan "$K3SM_ROOT" "$tmp/scripts")"; then
		if [ -n "$hits" ]; then
			printf '%s\n' "$hits" | sed 's/^/    early-exit pipe: /' >&2
			echo "    $(printf '%s\n' "$hits" | wc -l | tr -d ' ') early-exit pipelines; capture the producer and grep a here-string" >&2
			s1=no
		fi
	else
		echo "    the scanner failed" >&2; s1=no
	fi
fi
echo "    scanned $nscripts shell scripts"
ladder "$s1" "no hack/ script pipes into grep -q, or under pipefail into head, grep -m or grep -l"

# ---- self-check -----------------------------------------------------------------
s2=ok
mkdir -p "$tmp/plant"
nred="$(blocks "$FIXTURES/offending.txt" "$tmp/plant/red")"
nclean="$(blocks "$FIXTURES/clean.txt" "$tmp/plant/clean")"
{ [ "$nred" -ge 15 ] && [ "$nclean" -ge 12 ]; } || { echo "    the fixtures hold $nred offending and $nclean clean shapes, want 15 and 12" >&2; s2=no; }
i=1
while [ "$i" -le "$nred" ]; do
	echo "red.$i.sh" > "$tmp/plant/list"
	hit="$(scan "$tmp/plant" "$tmp/plant/list")" || { echo "    the scanner failed on red.$i.sh" >&2; s2=no; }
	[ -n "$hit" ] || { echo "    the scanner passed offending shape $i:" >&2; sed -n '3,$p' "$tmp/plant/red.$i.sh" >&2; s2=no; }
	i=$((i+1))
done
i=1
while [ "$i" -le "$nclean" ]; do
	echo "clean.$i.sh" > "$tmp/plant/list"
	hit="$(scan "$tmp/plant" "$tmp/plant/list")" || { echo "    the scanner failed on clean.$i.sh" >&2; s2=no; }
	[ -z "$hit" ] || { echo "    the scanner flagged clean shape $i: $hit" >&2; s2=no; }
	i=$((i+1))
done
# The lister finds a shebang script with no .sh name, and skips other files.
mkdir -p "$tmp/tree/hack/bin"
printf '#!/bin/sh\nset -o pipefail\nfoo | grep -q x\n' > "$tmp/tree/hack/bin/fake"
printf 'foo | grep -q x\n' > "$tmp/tree/hack/bin/notes.txt"
list_scripts "$tmp/tree" > "$tmp/tree.list" || s2=no
[ "$(cat "$tmp/tree.list")" = "hack/bin/fake" ] || { echo "    the lister found '$(tr '\n' ' ' < "$tmp/tree.list")', want hack/bin/fake" >&2; s2=no; }
echo "    $nred offending and $nclean clean shapes"
ladder "$s2" "the scanner reds on every planted offending shape and passes every clean one"

# ---- transcript -------------------------------------------------------------------
s3=ok
out="--- PASS: TestFirst (0.00s)"$'\n'
pad='    transcript_test.go:42: a line of go test -v output, padding the transcript past one pipe buffer'
i=0
while [ "$i" -lt 2000 ]; do out+="$pad $i"$'\n'; i=$((i+1)); done
out+="--- PASS: TestLast (0.01s)"$'\n'"ok  	k3sm.io/k3sm/pkg/x	0.123s"
[ "${#out}" -gt 65536 ] || { echo "    the transcript is ${#out} bytes, want more than 65536" >&2; s3=no; }
i=0
while [ "$i" -lt 20 ]; do
	grep -q -- '^--- PASS: TestFirst ' <<<"$out" || { echo "    try $i: TestFirst not matched" >&2; s3=no; break; }
	grep -q -- '^--- PASS: TestLast ' <<<"$out" || { echo "    try $i: TestLast not matched" >&2; s3=no; break; }
	if grep -q -- '^--- PASS: TestAbsent ' <<<"$out"; then echo "    try $i: TestAbsent matched" >&2; s3=no; break; fi
	i=$((i+1))
done
echo "    ${#out}-byte transcript, 20 tries"
ladder "$s3" "a transcript past a pipe buffer matches through a here-string under pipefail"

echo "----------------------------------------"
echo "$ME: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
