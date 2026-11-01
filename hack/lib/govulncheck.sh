# shellcheck shell=bash
#
# govulncheck.sh: the one home of how k3sm's scripts find, run and read
# govulncheck. Sourced, never run. Callers: hack/ci.sh (the source scan of this
# module and the allow-file check), hack/etcd-wrapper.sh (the source scan of
# the etcd wrapper) and hack/release/stage.sh (the binary scan of every staged
# child).
#
#   gv_pin               the pinned version, read from the GOVULNCHECK_VERSION
#                        line of hack/ci.sh (the one place the pin is written)
#   gv_find <pin>        the path of a govulncheck reporting exactly <pin>
#   gv_scan_binary       one binary scanned in JSON mode, the stream checked and
#                        reduced to one line per vulnerability
#   gv_allow_lint        the allow file's format and expiry, without a scan
#   gv_allow_check       the scan's findings against the allow file
#
# Every failure is NAMED, on stderr, so a red says what broke:
#   "govulncheck missing or wrong version", "vuln DB unreachable",
#   "no config message", "malformed JSON stream", "govulncheck failed",
#   "vulnerability database is not the production one", "vulnerability
#   database is stale".
#
# Nothing here sets GOFLAGS, GOSUMDB, GOPROXY or any other variable that changes
# how modules or the vulnerability database are verified. The caller sets
# `set -euo pipefail`; nothing here changes shell options.

GV_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# gv_pin: the version hack/ci.sh pins. Read from that line, never restated, so a
# bump is one edit and every caller follows it.
gv_pin() {
	local ci="$GV_LIB_DIR/../ci.sh" v
	v="$(sed -n 's/^GOVULNCHECK_VERSION=\(v[^[:space:]#]*\).*/\1/p' "$ci" 2>/dev/null | sed -n 1p)"
	[ -n "$v" ] || { echo "govulncheck: cannot read the GOVULNCHECK_VERSION pin from $ci" >&2; return 1; }
	printf '%s\n' "$v"
}

# gv_find <pin>: print the path of the first candidate (PATH first, then
# $(go env GOPATH)/bin) whose -version reports exactly <pin>. A different
# release can report different findings, so a missing or mismatched tool is a
# named failure, never a skip.
gv_find() {
	local pin="$1" c v seen="" prev=""
	for c in "$(command -v govulncheck 2>/dev/null || true)" "$(go env GOPATH 2>/dev/null)/bin/govulncheck"; do
		[ -n "$c" ] && [ -x "$c" ] && [ "$c" != "$prev" ] || continue
		prev="$c"
		v="$("$c" -version 2>/dev/null | sed -n 's/^Scanner: govulncheck@//p' | sed -n 1p)" || v=""
		if [ "$v" = "$pin" ]; then
			printf '%s\n' "$c"
			return 0
		fi
		seen="${seen}    $c reports ${v:-no version}"$'\n'
	done
	echo "govulncheck missing or wrong version: need $pin (go install golang.org/x/vuln/cmd/govulncheck@$pin)" >&2
	[ -z "$seen" ] || printf 'found:\n%s' "$seen" >&2
	return 1
}

# The JSON-stream reader. JSON mode exits 0 when it finds vulnerabilities, so
# the verdict comes from the stream, never from the exit code; a non-zero exit
# is an error of the tool, named from its stderr. Output, one line per OSV id,
# sorted: `symbol <id> <module>@<version> <symbol>` when any finding carries a
# function in its trace (the binary links a vulnerable symbol), else
# `info <id> <module>@<version>`.
#
# With no -db (every real scan) the config message must name the production
# database, https://vuln.go.dev, and its db_last_modified must be no more than
# GV_DB_MAX_AGE_DAYS before the scan date; a scan against another or a stale
# database is a named red. A -db scan (the hermetic self-test) skips that check.
#
# A stripped binary (-ldflags -s) has no symbol table, and govulncheck then
# reports every symbol of an affected package as present (a function of the
# form `<pkg>/*`), so a stripped child is scanned conservatively: its module-level
# findings become symbol-level ones.
# shellcheck disable=SC2016 # python source, not shell
GV_PARSE_PY='
import datetime, json, re, sys
out, err, rc, pin, dbarg, maxage = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6])
data = open(out, encoding="utf-8", errors="replace").read()
errtext = open(err, encoding="utf-8", errors="replace").read().strip()
def fail(name, detail=""):
    sys.stderr.write("govulncheck: " + name + (": " + detail if detail else "") + "\n")
    sys.exit(1)
DB = re.compile(r"creating client|fetching vulnerabilities|vulndb|vuln\.go\.dev|dial tcp|no such host|i/o timeout|connection refused|connection reset|TLS handshake|unexpected status|index/(db|modules)", re.I)
if rc != 0:
    if DB.search(errtext):
        fail("vuln DB unreachable", errtext.splitlines()[-1] if errtext else "")
    fail("govulncheck failed", "exit %d%s" % (rc, (": " + errtext.splitlines()[-1]) if errtext else ""))
dec, i, msgs = json.JSONDecoder(), 0, []
while True:
    while i < len(data) and data[i].isspace():
        i += 1
    if i >= len(data):
        break
    try:
        obj, i = dec.raw_decode(data, i)
    except ValueError as e:
        fail("malformed JSON stream", "the stream does not end cleanly (%s)" % e)
    if not isinstance(obj, dict):
        fail("malformed JSON stream", "a message is not an object")
    msgs.append(obj)
cfg = next((m["config"] for m in msgs if isinstance(m.get("config"), dict)), None)
if cfg is None:
    fail("no config message", "the stream carries no config, so nothing says what was scanned or with which database")
if cfg.get("scanner_version") != pin:
    fail("govulncheck missing or wrong version", "the stream reports %r, the pin is %s" % (cfg.get("scanner_version"), pin))
if cfg.get("scan_mode") != "binary":
    fail("malformed JSON stream", "scan_mode %r, want binary" % cfg.get("scan_mode"))
if not dbarg:
    if cfg.get("db") != "https://vuln.go.dev":
        fail("vulnerability database is not the production one", "(%s)" % cfg.get("db"))
    lm = cfg.get("db_last_modified")
    try:
        lmd = datetime.date.fromisoformat(str(lm)[:10])
    except ValueError:
        lmd = None
    today = datetime.datetime.now(datetime.timezone.utc).date()
    if lmd is None or (today - lmd).days > maxage:
        fail("vulnerability database is stale", "(%s)" % lm)
osv = {}
for m in msgs:
    f = m.get("finding")
    if not isinstance(f, dict):
        continue
    oid, tr = f.get("osv") or "?", f.get("trace") or [{}]
    top = tr[0] if isinstance(tr[0], dict) else {}
    e = osv.setdefault(oid, {"mod": "%s@%s" % (top.get("module", "?"), top.get("version", "?")), "sym": ""})
    fn = top.get("function") or ""
    if fn and not e["sym"]:
        recv = top.get("receiver") or ""
        e["sym"] = "%s.%s%s" % (top.get("package", "?"), (recv.lstrip("*") + ".") if recv else "", fn)
for oid in sorted(osv):
    e = osv[oid]
    print(("symbol %s %s %s" % (oid, e["mod"], e["sym"])) if e["sym"] else ("info %s %s" % (oid, e["mod"])))
'

# GV_DB_MAX_AGE_DAYS: how old the production database's db_last_modified may be.
GV_DB_MAX_AGE_DAYS=30

# gv_scan_binary <govulncheck> <pin> <binary> [<db-url>]: scan one binary
# (-mode=binary -format json; the default database unless <db-url> is given) and
# print the reduced lines above. Returns 1, the failure named on stderr, when the
# scan cannot be trusted.
gv_scan_binary() {
	local gv="$1" pin="$2" bin="$3" db="${4:-}" tmp rc=0
	[ -f "$bin" ] || { echo "govulncheck failed: $bin is not a file" >&2; return 1; }
	command -v python3 >/dev/null 2>&1 || { echo "govulncheck failed: python3 is needed to read the JSON stream" >&2; return 1; }
	tmp="$(mktemp -d -t k3sm-gv)"
	if [ -n "$db" ]; then
		"$gv" -mode=binary -format json -db "$db" "$bin" >"$tmp/out" 2>"$tmp/err" || rc=$?
	else
		"$gv" -mode=binary -format json "$bin" >"$tmp/out" 2>"$tmp/err" || rc=$?
	fi
	local res=0
	python3 -I -c "$GV_PARSE_PY" "$tmp/out" "$tmp/err" "$rc" "$pin" "$db" "$GV_DB_MAX_AGE_DAYS" || res=1
	rm -rf "$tmp"
	return "$res"
}

# The allow-file reader and checker. The allow file has one entry per line,
# `#` comments and blank lines ignored, in the hack/deps.cooldown-exempt shape:
#
#   <GO-id> <child> <child-version> <reason ...> <expiry YYYY-MM-DD>
#
# An entry allows the symbol-level finding <GO-id> in <child> at exactly
# <child-version> (a pin bump makes the entry match nothing, which re-triggers
# review) until the end of <expiry>. The reason is at least GV_ALLOW_MIN_REASON
# characters and the expiry at most GV_ALLOW_MAX_DAYS days after today, so every
# entry is re-reviewed on a schedule. A malformed entry, an expired entry, and in
# a scan an entry matching no symbol-level finding (stale) are each a red, and
# so is a malformed findings line.
GV_ALLOW_MIN_REASON=20
GV_ALLOW_MAX_DAYS=120
GV_FIX_HINT="bump the child's pin (pkg/executor for kubernetes, the pin files read_pins reads for the rest) or name it in hack/release/govulncheck.allow with a reason and an expiry"
# shellcheck disable=SC2016 # python source, not shell
GV_ALLOW_PY='
import datetime, re, sys
mode, allow, today, minreason, maxdays, hint = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
findings = sys.argv[7] if len(sys.argv) > 7 else None
horizon = (datetime.date.fromisoformat(today) + datetime.timedelta(days=maxdays)).isoformat()
probs, entries, seen = [], [], set()
try:
    lines = open(allow, encoding="utf-8").read().splitlines()
except OSError as e:
    print("allow file: cannot read %s: %s" % (allow, e)); sys.exit(1)
for n, raw in enumerate(lines, 1):
    s = raw.strip()
    if not s or s.startswith("#"):
        continue
    f = s.split()
    where = "%s:%d" % (allow, n)
    if len(f) < 5:
        probs.append("%s: want <GO-id> <child> <child-version> <reason> <expiry>, got %r" % (where, s)); continue
    oid, child, ver, exp, reason = f[0], f[1], f[2], f[-1], " ".join(f[3:-1])
    if not re.fullmatch(r"GO-\d{4}-\d{4,}", oid):
        probs.append("%s: %r is not a GO-YYYY-NNNN id" % (where, oid)); continue
    if not re.fullmatch(r"v\d[\w.+-]*", ver):
        probs.append("%s: child version %r does not look like v<semver>" % (where, ver)); continue
    try:
        datetime.date.fromisoformat(exp)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp): raise ValueError
    except ValueError:
        probs.append("%s: expiry %r is not a YYYY-MM-DD date" % (where, exp)); continue
    if len(reason.strip()) < minreason:
        probs.append("%s: reason %r is shorter than %d characters: say why shipping the finding is acceptable" % (where, reason.strip(), minreason)); continue
    key = (oid, child, ver)
    if key in seen:
        probs.append("%s: duplicate entry for %s %s %s" % (where, oid, child, ver)); continue
    seen.add(key)
    if exp < today:
        probs.append("%s: EXPIRED %s on %s (%s %s %s): fix it or re-review and extend the entry" % (where, exp, today, oid, child, ver))
    elif exp > horizon:
        probs.append("%s: expiry %s is more than %d days after %s (latest %s): re-review sooner" % (where, exp, maxdays, today, horizon))
    entries.append({"key": key, "where": where, "used": False})
if mode == "check":
    unallowed = []
    for line in open(findings, encoding="utf-8").read().splitlines():
        f = line.split()
        if not line.strip():
            continue
        if len(f) < 5:
            probs.append("malformed findings line %r: want <child> <version> <kind> <id> <module>" % line); continue
        child, ver, kind, oid, mod = f[0], f[1], f[2], f[3], f[4]
        sym = f[5] if len(f) > 5 else ""
        hit = [e for e in entries if e["key"] == (oid, child, ver)]
        if kind == "symbol":
            for e in hit:
                e["used"] = True
            if hit:
                print("allowed  %s %s: %s in %s (%s) [%s]" % (child, ver, oid, mod, sym, hit[0]["where"]))
            else:
                unallowed.append("%s %s: %s in %s, symbol %s" % (child, ver, oid, mod, sym))
        else:
            print("info     %s %s: %s in %s (no vulnerable symbol in the binary)" % (child, ver, oid, mod))
    for u in unallowed:
        probs.append("FINDING  " + u + " (" + hint + ")")
    for e in entries:
        if not e["used"]:
            probs.append("%s: STALE, %s %s %s matches no symbol-level finding in this scan: delete it" % ((e["where"],) + e["key"]))
for p in probs:
    print(p)
sys.exit(1 if probs else 0)
'

# gv_allow_lint <allow-file> <today YYYY-MM-DD>: format, reason and expiry (no
# scan, so no stale check). Problems on stdout; non-zero when there are any.
gv_allow_lint() {
	python3 -I -c "$GV_ALLOW_PY" lint "$1" "$2" "$GV_ALLOW_MIN_REASON" "$GV_ALLOW_MAX_DAYS" "$GV_FIX_HINT"
}

# gv_allow_check <allow-file> <today> <findings-file>: <findings-file> holds
# `<child> <child-version> <reduced line>` per finding (gv_scan_binary's lines,
# prefixed). Prints every allowed and informational finding; non-zero, naming
# each, on an unallowed symbol-level finding, a malformed, expired or stale entry.
gv_allow_check() {
	python3 -I -c "$GV_ALLOW_PY" check "$1" "$2" "$GV_ALLOW_MIN_REASON" "$GV_ALLOW_MAX_DAYS" "$GV_FIX_HINT" "$3"
}

# gv_scan_children <govulncheck> <pin> <allow-file> <today> <db-url|""> [<child> <version> <path>]...
# Scan every listed child and check the findings against the allow file. A child
# whose scan cannot be trusted is a red, named; so is the allow check.
gv_scan_children() {
	local gv="$1" pin="$2" allow="$3" today="$4" db="$5" findings out bad=0
	shift 5
	findings="$(mktemp -t k3sm-gv-findings)"
	while [ $# -ge 3 ]; do
		echo "    scan $1 $2 (${3##*/})"
		if out="$(gv_scan_binary "$gv" "$pin" "$3" "$db")"; then
			[ -z "$out" ] || printf '%s\n' "$out" | sed "s|^|$1 $2 |" >>"$findings"
		else
			echo "    $1: the scan failed (named above)"
			bad=1
		fi
		shift 3
	done
	[ $# -eq 0 ] || { echo "    gv_scan_children: arguments must be <child> <version> <path> triples" >&2; bad=1; }
	if [ "$bad" = 0 ]; then
		out="$(gv_allow_check "$allow" "$today" "$findings")" || bad=1
		[ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/    /'
	fi
	rm -f "$findings"
	return "$bad"
}
