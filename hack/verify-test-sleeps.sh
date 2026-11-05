#!/usr/bin/env bash
# The test-sleep lint: wall-clock waits and fixed ports in Go tests are flaky by
# construction, so a new one is refused unless hack/test-sleeps.allow lists it.
#
# Flagged in *_test.go files (testdata, vendor and dot directories are skipped,
# and so are lines that are only a // comment):
#   time.Sleep   time.Sleep(
#   time.After   time.After(          (time.AfterFunc is not flagged)
#   time.Tick    time.Tick(           (time.NewTicker is not flagged)
#   Listen       a Listen*( call whose string address has a non-zero port,
#                such as ":8080" or "127.0.0.1:9000"; port 0 is the fix
#
# hack/test-sleeps.allow holds one entry per file and symbol:
#   <path>:<symbol> <reason> <deadline YYYY-MM-DD>
# plus one header line, "# count: <n>", that must equal the number of entries.
# The count makes every addition a deliberate, reviewed change to two lines.
#
# RED when: a hit has no entry; an entry is past its deadline; an entry matches
# no hit (remove it, and lower the count); an entry is malformed or duplicated;
# the count is missing or wrong. Fixing the test means deleting its entry.
#
#   hack/verify-test-sleeps.sh               # lint this repo
#   hack/verify-test-sleeps.sh --self-test   # prove the lint reds and greens
# --root DIR, --allow FILE and --today YYYY-MM-DD point the lint elsewhere; the
# self-test uses them.
set -euo pipefail

root=""; allow=""; today=""; selftest=0
while [ $# -gt 0 ]; do
	case "$1" in
		--self-test) selftest=1; shift ;;
		--root) root="$2"; shift 2 ;;
		--allow) allow="$2"; shift 2 ;;
		--today) today="$2"; shift 2 ;;
		*) echo "verify-test-sleeps: unknown argument: $1" >&2; exit 2 ;;
	esac
done

self="$(cd "$(dirname "$0")" && pwd)/${0##*/}"

lint() {
	local root="$1" allow="$2" today="$3"
	if [ ! -d "$root" ]; then echo "FAIL: verify-test-sleeps: no such root: $root" >&2; return 1; fi
	if [ ! -f "$allow" ]; then echo "FAIL: verify-test-sleeps: allowlist not found: $allow" >&2; return 1; fi
	case "$today" in
		[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
		*) echo "FAIL: verify-test-sleeps: bad --today: $today" >&2; return 1 ;;
	esac

	local hits
	hits="$(cd "$root" && find . \( -name testdata -o -name vendor -o -name '.?*' \) -prune -o -type f -name '*_test.go' -print |
		LC_ALL=C sort | while IFS= read -r f; do
			awk -v f="${f#./}" '
				/^[[:space:]]*\/\// { next }
				/time\.Sleep\(/ { print f ":time.Sleep " FNR }
				/time\.After\(/ { print f ":time.After " FNR }
				/time\.Tick\(/  { print f ":time.Tick " FNR }
				/Listen[A-Za-z]*\(.*"[^"]*:[0-9]+"/ {
					s = $0
					while (match(s, /"[^"]*:[0-9]+"/)) {
						lit = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
						port = lit; sub(/^.*:/, "", port); sub(/"$/, "", port)
						if (port + 0 != 0) { print f ":Listen " FNR; break }
					}
				}
			' "$f"
		done)" || { echo "FAIL: verify-test-sleeps: scanning $root failed" >&2; return 1; }

	printf '%s\n' "$hits" | awk -v today="$today" -v allowfile="$allow" '
		BEGIN {
			bad = 0; n = 0; count = -1
			valid["time.Sleep"] = 1; valid["time.After"] = 1; valid["time.Tick"] = 1; valid["Listen"] = 1
			while ((getline line < allowfile) > 0) {
				ln++
				if (line ~ /^[[:space:]]*$/) continue
				if (line ~ /^#[[:space:]]*count:/) {
					c = line; sub(/^#[[:space:]]*count:[[:space:]]*/, "", c)
					if (c !~ /^[0-9]+$/ || count != -1) { printf "FAIL: %s:%d: bad or repeated count header: %s\n", allowfile, ln, line; bad = 1 }
					else count = c + 0
					continue
				}
				if (line ~ /^#/) continue
				nf = split(line, w, /[[:space:]]+/)
				key = w[1]; dl = w[nf]; sym = key; sub(/^.*:/, "", sym)
				if (nf < 3 || key !~ /_test\.go:/ || !(sym in valid) || dl !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
					printf "FAIL: %s:%d: malformed entry (want <path>:<symbol> <reason> <YYYY-MM-DD>): %s\n", allowfile, ln, line; bad = 1; continue
				}
				if (key in deadline) { printf "FAIL: %s:%d: duplicate entry %s\n", allowfile, ln, key; bad = 1; continue }
				deadline[key] = dl; n++
			}
			close(allowfile)
			if (count == -1) { printf "FAIL: %s: missing \"# count: <n>\" header (entries: %d)\n", allowfile, n; bad = 1 }
			else if (count != n) { printf "FAIL: %s: count header says %d but the file has %d entries; an addition must update the count\n", allowfile, count, n; bad = 1 }
		}
		NF == 2 {
			key = $1
			seen[key] = 1
			if (!(key in deadline)) {
				f = key; sub(/:[^:]*$/, "", f); sym = key; sub(/^.*:/, "", sym)
				printf "FAIL: %s:%s: %s in a test (use testing/synctest, an injected clock or port 0; or add an entry to the allowlist)\n", f, $2, sym; bad = 1
			}
		}
		END {
			for (k in deadline) {
				if (deadline[k] < today) { printf "FAIL: %s: allowlist entry expired on %s; fix the test or set a new deadline\n", k, deadline[k]; bad = 1 }
				if (!(k in seen)) { printf "FAIL: %s: allowlist entry matches nothing; remove it and lower the count\n", k; bad = 1 }
			}
			exit bad
		}
	'
}

if [ "$selftest" = 1 ]; then
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	fails=0
	# case <name> <want: red|green> <fixture body> <allowlist body>
	check() {
		local name="$1" want="$2" body="$3" allowbody="$4" got
		rm -rf "$tmp/root" && mkdir -p "$tmp/root/pkg"
		printf '%s\n' "$body" > "$tmp/root/pkg/x_test.go"
		printf '%s\n' "$allowbody" > "$tmp/allow"
		if bash "$self" --root "$tmp/root" --allow "$tmp/allow" --today 2026-06-15 > "$tmp/out" 2>&1; then got=green; else got=red; fi
		if [ "$got" = "$want" ]; then
			echo "ok   $name ($got)"
		else
			echo "FAIL $name: want $want, got $got"; sed 's/^/     /' "$tmp/out"; fails=$((fails + 1))
		fi
	}
	sleep_line='	time.Sleep(10 * time.Millisecond)'
	entry='pkg/x_test.go:time.Sleep waits on a real child process 2026-07-01'
	check "planted time.Sleep, empty allowlist" red "$sleep_line" '# count: 0'
	check "planted time.Sleep, allowlisted" green "$sleep_line" "# count: 1
$entry"
	check "allowlisted, past its deadline" red "$sleep_line" '# count: 1
pkg/x_test.go:time.Sleep waits on a real child process 2026-06-01'
	check "deadline today is still allowed" green "$sleep_line" '# count: 1
pkg/x_test.go:time.Sleep waits on a real child process 2026-06-15'
	check "entry added without raising the count" red "$sleep_line" "# count: 0
$entry"
	check "missing count header" red "$sleep_line" "$entry"
	check "stale entry matches nothing" red 'func f() {}' "# count: 1
$entry"
	check "malformed entry (no reason)" red "$sleep_line" '# count: 1
pkg/x_test.go:time.Sleep 2026-07-01'
	check "unknown symbol" red "$sleep_line" '# count: 1
pkg/x_test.go:time.Wait reason here 2026-07-01'
	check "duplicate entry" red "$sleep_line" "# count: 2
$entry
$entry"
	check "time.After flagged" red '	<-time.After(time.Second)' '# count: 0'
	check "time.Tick flagged" red '	for range time.Tick(time.Second) {}' '# count: 0'
	check "fixed-port Listen flagged" red '	ln, _ := net.Listen("tcp", "127.0.0.1:9000")' '# count: 0'
	check "fixed-port ListenAndServe flagged" red '	_ = http.ListenAndServe(":8080", nil)' '# count: 0'
	check "port 0 Listen not flagged" green '	ln, _ := net.Listen("tcp", "127.0.0.1:0")' '# count: 0'
	check "time.AfterFunc and NewTicker not flagged" green '	time.AfterFunc(d, f); time.NewTicker(d)' '# count: 0'
	check "comment-only line not flagged" green '	// time.Sleep(time.Second) was here' '# count: 0'
	check "empty tree, empty allowlist" green 'package x' '# count: 0'

	# Files the go tool never builds as tests are out of scope.
	rm -rf "$tmp/root" && mkdir -p "$tmp/root/pkg/testdata" "$tmp/root/.hidden"
	printf '%s\n' "$sleep_line" > "$tmp/root/pkg/testdata/y_test.go"
	printf '%s\n' "$sleep_line" > "$tmp/root/.hidden/y_test.go"
	printf '%s\n' "$sleep_line" > "$tmp/root/pkg/y.go"
	printf '# count: 0\n' > "$tmp/allow"
	if bash "$self" --root "$tmp/root" --allow "$tmp/allow" --today 2026-06-15 > "$tmp/out" 2>&1; then
		echo "ok   testdata, dot dirs and non-test files skipped (green)"
	else
		echo "FAIL testdata, dot dirs and non-test files skipped: want green, got red"; sed 's/^/     /' "$tmp/out"; fails=$((fails + 1))
	fi

	if bash "$self" --root "$tmp/nope" --allow "$tmp/allow" --today 2026-06-15 > /dev/null 2>&1; then
		echo "FAIL missing root: want red, got green"; fails=$((fails + 1))
	else
		echo "ok   missing root (red)"
	fi

	if [ "$fails" -ne 0 ]; then echo "verify-test-sleeps self-test: $fails case(s) failed" >&2; exit 1; fi
	echo "OK: verify-test-sleeps self-test"
	exit 0
fi

[ -n "$root" ] || root="$(cd "$(dirname "$0")/.." && pwd)"
[ -n "$allow" ] || allow="$root/hack/test-sleeps.allow"
[ -n "$today" ] || today="$(date +%Y-%m-%d)"
lint "$root" "$allow" "$today"
