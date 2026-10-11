#!/usr/bin/env bash
#
# verify-deps.sh — the dependency supply-chain check.
#
# A Go module graph can be attacked without touching a line of this repo's code:
# a tampered module zip, a typosquatted module pulled in by a new import, a
# compromised maintainer account publishing a malicious patch release that a
# routine bump adopts the same day. This script makes every one of those visible
# before it merges. The stages run in order and each fails closed:
#
#   env guard                the go environment cannot weaken checksum or proxy
#                            verification (GOSUMDB, GONOSUMDB, GOPRIVATE, ...)
#   go mod verify            the module cache matches go.sum
#   lock                     hack/deps.lock equals `go list -m all`; any new,
#                            removed or changed module is a reviewed change
#   cooldown                 no module version younger than 14 days, unless
#                            hack/deps.cooldown-exempt names it with a reason
#   malicious-package check  no module version carries an OSV MAL- advisory
#   replace discipline       every go.mod replace is explained by a comment, and
#                            a filesystem replace points only at a sibling repo
#   pinned tools             no `go install` / `go run` of a remote module in
#                            hack/** or a Makefile without an exact version
#
# Usage (from anywhere; the script runs from the repo root with GOWORK=off):
#   hack/verify-deps.sh              run every stage
#   hack/verify-deps.sh --update     rewrite hack/deps.lock from the current graph,
#                                    then run the cooldown and malicious-package
#                                    stages on the modules that changed
#   hack/verify-deps.sh --self-test  hermetic fixtures (hack/testdata/verify-deps),
#                                    stubbed go and curl, no network
#
# Network: the malicious-package stage queries https://api.osv.dev, and --update
# reads publish times from https://proxy.golang.org. A network failure is a
# failure, never a skip: a supply-chain check that passes when it cannot look
# has checked nothing.
#
# Needs bash, python3 and curl. Exit status: 0 pass; 1 failure; 2 usage.
set -euo pipefail

SELF="$0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export GOWORK=off

COOLDOWN_DAYS=14
PROXY_URL="https://proxy.golang.org"
OSV_BATCH_URL="https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL="https://api.osv.dev/v1/query"
OSV_BATCH_SIZE=500
LOCK="hack/deps.lock"
EXEMPT="hack/deps.cooldown-exempt"
# The only filesystem paths a go.mod replace may name: the sibling k3sm repos.
LOCAL_REPLACE_ALLOW="../apis ../runtimed ../darwin-net ../k3sm"

stage() { echo "==> [verify-deps] $1"; }
fail() {
	local st="$1"
	shift
	echo "FAIL: [verify-deps] $st: $*" >&2
	exit 1
}

# The helper below does the parsing (go.mod, the lock, JSON, shell scanning).
# It is embedded so the script stays one self-contained file.
# (read -d '' rather than $(cat <<EOF): bash 3.2 mis-parses quotes inside a
# here-document nested in a command substitution.)
PY_HELPER=""
IFS= read -r -d '' PY_HELPER <<'PYEOF' || true
import datetime, json, os, re, shlex, sys, time

EXACT = re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+incompatible)?$')
HEADER = (
    "# Module graph lock for hack/verify-deps.sh: one line per module in\n"
    "# `go list -m all` (main module excluded), each with the publish time the\n"
    "# module proxy reports for the version that is built (`local` for a\n"
    "# filesystem replacement). Regenerate with: hack/verify-deps.sh --update\n"
)


def die(msg, code=1):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


def escape(s):
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in s)


def unescape(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "!" and i + 1 < len(s):
            out.append(s[i + 1].upper())
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def parse_key(key):
    """Return (path, version, effective_path, effective_version, is_local)."""
    t = key.split()
    if len(t) == 2:
        return t[0], t[1], t[0], t[1], False
    if len(t) in (4, 5) and t[2] == "=>":
        if len(t) == 4:
            return t[0], t[1], t[3], "", True
        return t[0], t[1], t[3], t[4], False
    raise ValueError("malformed module line: %r" % key)


def read_lock(path):
    """Return a list of (key, time) from a lock file; raise ValueError when malformed."""
    out = []
    with open(path) as f:
        for n, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if " # " not in line:
                raise ValueError("%s:%d: no publish time (want '<module line> # <time>')" % (path, n))
            key, tm = line.split(" # ", 1)
            key, tm = key.strip(), tm.strip()
            parse_key(key)
            out.append((key, tm))
    return out


def read_graph(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def parse_time(s):
    m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$', s)
    if not m:
        return None
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    try:
        return datetime.datetime.fromisoformat(m.group(1) + tz).timestamp()
    except ValueError:
        return None


def cmd_graph_clean():
    lines = sorted({l.rstrip() for l in sys.stdin if l.strip()})
    sys.stdout.write("".join(l + "\n" for l in lines))


def cmd_lockdiff(lockpath, graphpath):
    graph = read_graph(graphpath)
    if os.path.exists(lockpath):
        try:
            lock = [k for k, _ in read_lock(lockpath)]
        except ValueError as e:
            die(str(e))
    else:
        print("(no %s yet: every module is new)" % lockpath)
        lock = []
    lset, gset = set(lock), set(graph)
    lby = {k.split()[0]: k for k in lock}
    gby = {k.split()[0]: k for k in graph}
    drift = False
    for p in sorted(set(lby) | set(gby)):
        a, b = lby.get(p), gby.get(p)
        if a == b:
            continue
        drift = True
        if a is None:
            print("  added:   " + b)
        elif b is None:
            print("  removed: " + a)
        else:
            print("  changed: %s  ->  %s" % (a, b))
    if len(lset) != len(lock):
        drift = True
        print("  duplicate lines in " + lockpath)
    sys.exit(1 if drift else 0)


def cmd_update_plan(lockpath, graphpath, work, proxy):
    graph = read_graph(graphpath)
    old = {}
    if os.path.exists(lockpath):
        try:
            old = dict(read_lock(lockpath))
        except ValueError:
            old = {}
    fetch = open(os.path.join(work, "fetch"), "w")
    plan = open(os.path.join(work, "plan"), "w")
    for i, key in enumerate(graph):
        try:
            _, _, ep, ev, local = parse_key(key)
        except ValueError as e:
            die(str(e))
        prev = old.get(key)
        if local:
            plan.write("%s\tlocal\t%s\n" % (key, "old" if prev == "local" else "new"))
        elif prev is not None and parse_time(prev) is not None:
            plan.write("%s\t%s\told\n" % (key, prev))
        else:
            out = os.path.join(work, "info.%d" % i)
            fetch.write("%s/%s/@v/%s.info %s\n" % (proxy, escape(ep), escape(ev), out))
            plan.write("%s\t@%s\tnew\n" % (key, out))
    fetch.close()
    plan.close()


def cmd_update_write(lockpath, work):
    lines, delta = [], []
    with open(os.path.join(work, "plan")) as f:
        for raw in f:
            key, tm, state = raw.rstrip("\n").split("\t")
            if tm.startswith("@"):
                try:
                    with open(tm[1:]) as g:
                        info = json.load(g)
                    tm = str(info["Time"])
                except (OSError, ValueError, KeyError, TypeError) as e:
                    die("unreadable proxy .info for %s: %s" % (key, e))
                if parse_time(tm) is None:
                    die("proxy .info for %s has an unparseable Time %r" % (key, tm))
            entry = "%s # %s" % (key, tm)
            lines.append(entry)
            if state == "new":
                delta.append(entry)
    with open(lockpath + ".tmp", "w") as f:
        f.write(HEADER + "".join(l + "\n" for l in lines))
    os.replace(lockpath + ".tmp", lockpath)
    with open(os.path.join(work, "delta"), "w") as f:
        f.write(HEADER + "".join(l + "\n" for l in delta))
    print("wrote %s: %d modules, %d new or changed" % (lockpath, len(lines), len(delta)))
    for l in delta:
        print("  " + l)


def read_exempt(path):
    ex = {}
    if not os.path.exists(path):
        return ex
    with open(path) as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            t = line.split(None, 2)
            if len(t) < 3 or not t[2].strip():
                die("%s:%d: want '<module> <version> <reason>', got %r" % (path, n, line))
            ex[(t[0], t[1])] = t[2].strip()
    return ex


def cmd_cooldown(entries, exemptpath, days):
    days = int(days)
    try:
        lock = read_lock(entries)
    except ValueError as e:
        die(str(e))
    ex = read_exempt(exemptpath)
    now = time.time()
    bad, used = [], set()
    for key, tm in lock:
        _, _, ep, ev, local = parse_key(key)
        if local:
            if tm != "local":
                bad.append("%s: a filesystem replacement must record 'local', got %r" % (key, tm))
            continue
        ts = parse_time(tm)
        if ts is None:
            bad.append("%s: unparseable publish time %r (run hack/verify-deps.sh --update)" % (key, tm))
            continue
        # The proxy reports the zero time when it does not know when a version
        # was published; an unknown age cannot clear the cooldown.
        unknown = tm.startswith("0001-01-01")
        age = (now - ts) / 86400.0
        if unknown or age < days:
            what = "no known publish time" if unknown else "%.1f days old" % age
            if (ep, ev) in ex:
                used.add((ep, ev))
                print("  exempt: %s %s (%s): %s" % (ep, ev, what, ex[(ep, ev)]))
                continue
            if unknown:
                bad.append("%s %s: the module proxy reports no publish time (%s)" % (ep, ev, tm))
            else:
                bad.append("%s %s was published %s, %.1f days ago (cooldown is %d days)" % (ep, ev, tm, age, days))
    for k in sorted(set(ex) - used):
        print("  note: exemption '%s %s' matches no module version under the cooldown; delete it" % k)
    for b in bad:
        print("  " + b)
    sys.exit(1 if bad else 0)


def cmd_osv_build(entries, work, size):
    size = int(size)
    try:
        lock = read_lock(entries)
    except ValueError as e:
        die(str(e))
    qs = []
    for key, _ in lock:
        _, _, ep, ev, local = parse_key(key)
        if not local and (ep, ev) not in qs:
            qs.append((ep, ev))
    n = 0
    for i in range(0, len(qs), size):
        chunk = qs[i:i + size]
        with open(os.path.join(work, "osv-req.%d" % n), "w") as f:
            json.dump({"queries": [{"package": {"name": p, "ecosystem": "Go"}, "version": v} for p, v in chunk]}, f)
        with open(os.path.join(work, "osv-q.%d" % n), "w") as f:
            f.write("".join("%s %s\n" % q for q in chunk))
        n += 1
    print(n)


def mal_ids(vulns):
    return [str(v.get("id", "")) for v in vulns if str(v.get("id", "")).startswith("MAL-")]


def cmd_osv_parse(qfile, resp):
    with open(qfile) as f:
        qs = [l.split() for l in f if l.strip()]
    try:
        with open(resp) as f:
            data = json.load(f)
        results = data["results"]
        if not isinstance(results, list) or len(results) != len(qs):
            raise ValueError("%d results for %d queries" % (len(results), len(qs)))
    except (OSError, ValueError, KeyError, TypeError) as e:
        die("malformed OSV response: %s" % e, 2)
    for (p, v), r in zip(qs, results):
        if not isinstance(r, dict):
            die("malformed OSV result for %s %s" % (p, v), 2)
        for i in mal_ids(r.get("vulns") or []):
            print("MAL %s %s %s" % (i, p, v))
        if r.get("next_page_token"):
            print("PAGE %s %s %s" % (p, v, r["next_page_token"]))


def cmd_osv_page_req(p, v, token):
    json.dump({"package": {"name": p, "ecosystem": "Go"}, "version": v, "page_token": token}, sys.stdout)


def cmd_osv_page_parse(p, v, resp):
    try:
        with open(resp) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except (OSError, ValueError) as e:
        die("malformed OSV response: %s" % e, 2)
    for i in mal_ids(data.get("vulns") or []):
        print("MAL %s %s %s" % (i, p, v))
    if data.get("next_page_token"):
        print("PAGE %s %s %s" % (p, v, data["next_page_token"]))


def cmd_replace(gomod, allow):
    allow = set(allow.split())
    bad = []
    with open(gomod) as f:
        lines = [l.rstrip("\n") for l in f]
    in_block = False
    prev = "none"  # kind of the last non-blank line: comment, replace, open, other
    blank_since = False
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s:
            blank_since = True
            continue
        entry = None
        if in_block:
            if s == ")":
                in_block = False
                prev, blank_since = "other", False
                continue
            if s.startswith("//"):
                prev, blank_since = "comment", False
                continue
            entry = s
        elif re.match(r'^replace\s*\($', s):
            in_block = True
            # A comment directly above `replace (` explains the first entry.
            prev = "open-commented" if prev == "comment" and not blank_since else "open"
            blank_since = False
            continue
        elif re.match(r'^replace\s', s):
            entry = s[len("replace"):].strip()
        elif s.startswith("//"):
            prev, blank_since = "comment", False
            continue
        else:
            prev, blank_since = "other", False
            continue
        entry = entry.split("//", 1)[0].strip()
        # Explained by a comment line directly above it, or the next member of a
        # run of replaces that a comment directly above the run's first line explains.
        ok = (prev in ("comment", "open-commented") and not blank_since) or prev == "replace-ok"
        if not ok:
            bad.append("go.mod:%d: replace is not directly after a // comment explaining it: %s" % (n, s))
        if "=>" not in entry:
            bad.append("go.mod:%d: malformed replace: %s" % (n, s))
        else:
            rhs = entry.split("=>", 1)[1].split()
            if len(rhs) == 1:
                target = rhs[0]
                if target.startswith((".", "/")) and target not in allow:
                    bad.append("go.mod:%d: filesystem replace may only name %s: %s"
                               % (n, ", ".join(sorted(allow)), s))
        prev, blank_since = ("replace-ok" if ok else "replace-bad"), False
    for b in bad:
        print("  " + b)
    sys.exit(1 if bad else 0)


VALUE_FLAGS = {"-o", "-C", "-p", "-tags", "-ldflags", "-gcflags", "-asmflags", "-gccgoflags",
               "-mod", "-modfile", "-pkgdir", "-toolexec", "-overlay", "-pgo", "-exec",
               "-covermode", "-coverpkg", "-buildmode", "-compiler", "-installsuffix", "-reldir"}
PREFIX_WORDS = {"env", "nohup", "exec", "sudo", "command", "time", "then", "do", "else",
                "elif", "if", "while", "until", "!", "nice"}


def segments(line):
    """Split one line into shell command segments, outside quotes."""
    segs, cur, stack, i = [], [], ["n"], 0

    def flush():
        if "".join(cur).strip():
            segs.append("".join(cur))
        del cur[:]

    while i < len(line):
        c, top = line[i], stack[-1]
        if top == "s":
            if c == "'":
                stack.pop()
            cur.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i:i + 2])
            i += 2
            continue
        if top == "d":
            if c == '"':
                stack.pop()
                cur.append(c)
            elif line.startswith("$(", i):
                flush()
                stack.append("c")
                i += 1
            elif c == "`":
                flush()
            else:
                cur.append(c)
            i += 1
            continue
        if c == "'":
            stack.append("s")
            cur.append(c)
        elif c == '"':
            stack.append("d")
            cur.append(c)
        elif c == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        elif line.startswith("$(", i):
            flush()
            stack.append("c")
            i += 1
        elif c == "(":
            flush()
            stack.append("p")
        elif c == ")":
            flush()
            if len(stack) > 1:
                stack.pop()
        elif c in ";|&`{}":
            flush()
        else:
            cur.append(c)
        i += 1
    flush()
    return segs


def words(seg):
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return [w.strip("'\"") for w in seg.split()]


ASSIGN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')


def go_invocation(seg):
    w = words(seg)
    i, after_env = 0, False
    while i < len(w):
        t = w[i].lstrip("@+") if i == 0 else w[i]
        if ASSIGN.match(t) or t in PREFIX_WORDS:
            after_env = after_env or t in ("env", "sudo", "nice")
            i += 1
        elif after_env and t.startswith("-"):
            i += 1
        else:
            break
    if i + 1 >= len(w):
        return None
    first = w[i].lstrip("@+-") if i == 0 else w[i]
    if first != "go" or w[i + 1] not in ("install", "run"):
        return None
    args, j = w[i + 2:], 0
    while j < len(args):
        a = args[j]
        if a == "--":
            j += 1
            break
        if a.startswith("-"):
            j += 2 if ("=" not in a and a.split("=")[0] in VALUE_FLAGS) else 1
            continue
        break
    return (w[i + 1], args[j] if j < len(args) else None)


def assignments(files):
    tab = {}
    rx = re.compile(r'(?:^|[\s;(])(?:local\s+|readonly\s+|export\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)=(\S*)')
    for path, lines in files:
        for raw in lines:
            s = raw.strip()
            if s.startswith("#") or s.startswith("//"):
                continue
            for m in rx.finditer(raw):
                val = m.group(2)
                try:
                    val = shlex.split(val)[0] if val else ""
                except (ValueError, IndexError):
                    val = val.strip("'\"")
                tab.setdefault(m.group(1), []).append(val)
    return tab


VARREF = re.compile(r'^\$(?:\{([A-Za-z_][A-Za-z0-9_]*|[0-9]+)(?::?-([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*|[0-9]))$')


def resolve(val, tab, depth=0):
    """Return (literals, computed): every literal version reachable from val."""
    if depth > 8:
        return [], True
    if "$" not in val and "`" not in val:
        return [val], False
    if "$(" in val or "`" in val:
        return [], True
    m = VARREF.match(val)
    if not m:
        return [], True
    name = m.group(1) or m.group(3)
    lits, computed = [], False
    if m.group(2) is not None:
        l, c = resolve(m.group(2), tab, depth + 1)
        lits += l
        computed = computed or c
    if name.isdigit():
        return lits, True
    vals = [v for v in tab.get(name, []) if v != val]
    if not vals:
        return lits, True
    for v in vals:
        l, c = resolve(v, tab, depth + 1)
        lits += l
        computed = computed or c
    return lits, computed


def local_module_prefixes(root):
    pre = []
    try:
        with open(os.path.join(root, "go.mod")) as f:
            for raw in f:
                s = raw.strip()
                m = re.match(r'^module\s+(\S+)', s)
                if m:
                    pre.append(m.group(1).strip('"'))
                m = re.match(r'^(?:replace\s+)?(\S+)(?:\s+\S+)?\s+=>\s+(\.\.?/\S*)\s*$', s)
                if m:
                    pre.append(m.group(1))
    except OSError:
        pass
    return pre


def cmd_tools(root, listfile):
    with open(listfile) as f:
        names = [l.rstrip("\n") for l in f if l.strip()]
    files = []
    for rel in names:
        p = os.path.join(root, rel)
        try:
            with open(p, "rb") as f:
                data = f.read(4 * 1024 * 1024)
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        files.append((rel, data.decode("utf-8", "replace").splitlines()))
    locals_ = local_module_prefixes(root)
    bad, notes = [], []
    for rel, lines in files:
        # A version variable resolves through assignments in the same file only;
        # anything else (a sourced file, a caller's argument) is reported as computed.
        tab = assignments([(rel, lines)])
        for n, raw in enumerate(lines, 1):
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("//"):
                continue
            for seg in segments(raw):
                inv = go_invocation(seg)
                if not inv:
                    continue
                verb, target = inv
                where = "%s:%d: go %s" % (rel, n, verb)
                if target is None:
                    continue
                if "@" in target:
                    mod, ver = target.rsplit("@", 1)
                    if mod.startswith((".", "/")):
                        continue
                    lits, computed = resolve(ver, tab)
                    nonexact = [l for l in lits if not EXACT.match(l)]
                    if nonexact:
                        bad.append("%s %s: version %s is not an exact vX.Y.Z or pseudo-version"
                                   % (where, target, ", ".join(repr(l) for l in nonexact)))
                    elif computed and not lits:
                        notes.append("%s %s: the version is computed at run time, not checked here" % (where, target))
                    continue
                if target.startswith((".", "/", "$", "~")) or target.endswith(".go"):
                    continue
                if "." not in target.split("/")[0]:
                    continue
                if any(target == p or target.startswith(p + "/") for p in locals_):
                    continue
                bad.append("%s %s: a remote module without an @version" % (where, target))
    for x in notes:
        print("  note: " + x)
    for b in bad:
        print("  " + b)
    sys.exit(1 if bad else 0)


def cmd_ago(days):
    t = time.time() - float(days) * 86400
    print(datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


CMDS = {
    "graph-clean": cmd_graph_clean, "lockdiff": cmd_lockdiff,
    "update-plan": cmd_update_plan, "update-write": cmd_update_write,
    "cooldown": cmd_cooldown, "osv-build": cmd_osv_build, "osv-parse": cmd_osv_parse,
    "osv-page-req": cmd_osv_page_req, "osv-page-parse": cmd_osv_page_parse,
    "replace": cmd_replace, "tools": cmd_tools, "ago": cmd_ago,
    "escape": lambda s: print(escape(s)), "unescape": lambda s: print(unescape(s)),
}

if __name__ == "__main__":
    CMDS[sys.argv[1]](*sys.argv[2:])
PYEOF

py() { python3 -I -c "$PY_HELPER" "$@"; }

WORK=""
cleanup() { [ -z "$WORK" ] || rm -rf "$WORK"; }
mkwork() {
	WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-deps.XXXXXX")"
	trap cleanup EXIT
}

# ---- a: env guard ------------------------------------------------------------
env_guard() {
	stage "env guard"
	command -v go >/dev/null 2>&1 || fail "env guard" "go is not on PATH"
	command -v python3 >/dev/null 2>&1 || fail "env guard" "python3 is not on PATH"
	local v bad=""
	v="$(go env GOSUMDB)" || fail "env guard" "go env GOSUMDB failed"
	case "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" in
	"" | off | off,*) bad="${bad}  GOSUMDB='$v' disables checksum-database verification"$'\n' ;;
	esac
	local name
	for name in GONOSUMDB GONOSUMCHECK GOINSECURE GOPRIVATE GONOPROXY; do
		v="$(go env "$name")" || fail "env guard" "go env $name failed"
		# go env prints nothing for a name it does not know; read the variable too.
		[ -n "$v" ] || v="$(printenv "$name" || true)"
		[ -z "$v" ] || bad="${bad}  $name='$v' exempts modules from proxy or checksum verification"$'\n'
	done
	v="$(go env GOFLAGS)" || fail "env guard" "go env GOFLAGS failed"
	local f
	for f in $v; do
		case "$f" in
		-insecure | -insecure=* | --insecure | --insecure=*) bad="${bad}  GOFLAGS carries $f"$'\n' ;;
		-mod=mod | --mod=mod) bad="${bad}  GOFLAGS carries $f, which lets the go command rewrite go.mod and go.sum"$'\n' ;;
		esac
	done
	v="$(go env GOPROXY)" || fail "env guard" "go env GOPROXY failed"
	local first="${v%%[,|]*}"
	[ "$first" = "$PROXY_URL" ] || bad="${bad}  GOPROXY='$v': the first proxy must be $PROXY_URL"$'\n'
	if [ -n "$bad" ]; then
		printf '%s' "$bad" >&2
		fail "env guard" "the go environment weakens module verification; unset the variables above"
	fi
}

# ---- b: go mod verify --------------------------------------------------------
mod_verify() {
	stage "go mod verify"
	go mod verify || fail "go mod verify" "the module cache does not match go.sum"
}

# The current graph, cleaned and sorted, into $WORK/graph.
current_graph() {
	local raw="$WORK/graph.raw"
	go list -m -f '{{if not .Main}}{{.Path}} {{.Version}}{{with .Replace}} => {{.Path}} {{.Version}}{{end}}{{end}}' all >"$raw" ||
		fail "$1" "go list -m all failed"
	py graph-clean <"$raw" >"$WORK/graph"
}

# ---- c: lock -----------------------------------------------------------------
lock_check() {
	stage "lock"
	current_graph lock
	[ -f "$LOCK" ] || fail "lock" "$LOCK is missing; create it with hack/verify-deps.sh --update"
	local rc=0
	py lockdiff "$LOCK" "$WORK/graph" || rc=$?
	if [ "$rc" -ne 0 ]; then
		cat >&2 <<EOF
The module graph no longer matches $LOCK (lines above).
Before accepting it, check every added or changed module:
  - provenance: who publishes it, and is it the module you meant (not a look-alike)?
  - publish age: a version released in the last $COOLDOWN_DAYS days is refused by the cooldown stage
  - need: why this change needs it, and which import pulls it in (go mod why -m <module>)
  - alternative: would a small in-repo implementation do instead?
Then run hack/verify-deps.sh --update and commit $LOCK with the change.
EOF
		fail "lock" "$LOCK is out of date"
	fi
}

# ---- d: cooldown -------------------------------------------------------------
cooldown_check() { # cooldown_check <lock-format file>
	stage "cooldown"
	local rc=0
	py cooldown "$1" "$EXEMPT" "$COOLDOWN_DAYS" || rc=$?
	[ "$rc" -eq 0 ] || fail "cooldown" "module versions under $COOLDOWN_DAYS days old (above); wait, or add '<module> <version> <reason>' to $EXEMPT after an audit"
}

# ---- e: malicious-package check ---------------------------------------------
osv_post() { # osv_post <url> <request file> <response file>
	curl -fsS --max-time 60 --retry 2 -X POST -H 'Content-Type: application/json' \
		--data-binary "@$2" -o "$3" "$1"
}

malicious_check() { # malicious_check <lock-format file>
	stage "malicious-package check"
	local n i rc hits="$WORK/osv-hits" pages="$WORK/osv-pages"
	: >"$hits"
	n="$(py osv-build "$1" "$WORK" "$OSV_BATCH_SIZE")" || fail "malicious-package check" "could not read $1"
	for ((i = 0; i < n; i++)); do
		osv_post "$OSV_BATCH_URL" "$WORK/osv-req.$i" "$WORK/osv-resp.$i" ||
			fail "malicious-package check" "network failure querying $OSV_BATCH_URL (a failed query is a failure, never a skip)"
		rc=0
		py osv-parse "$WORK/osv-q.$i" "$WORK/osv-resp.$i" >>"$hits" || rc=$?
		[ "$rc" -eq 0 ] || fail "malicious-package check" "unreadable response from $OSV_BATCH_URL"
	done
	# A result with more advisories than one page holds carries a page token.
	local guard=0 p v tok
	while grep -q '^PAGE ' "$hits"; do
		guard=$((guard + 1))
		[ "$guard" -le 50 ] || fail "malicious-package check" "OSV paging did not terminate"
		grep '^PAGE ' "$hits" >"$pages"
		grep -v '^PAGE ' "$hits" >"$hits.keep" || true
		mv "$hits.keep" "$hits"
		while read -r _ p v tok; do
			py osv-page-req "$p" "$v" "$tok" >"$WORK/osv-page-req"
			osv_post "$OSV_QUERY_URL" "$WORK/osv-page-req" "$WORK/osv-page-resp" ||
				fail "malicious-package check" "network failure querying $OSV_QUERY_URL (a failed query is a failure, never a skip)"
			rc=0
			py osv-page-parse "$p" "$v" "$WORK/osv-page-resp" >>"$hits" || rc=$?
			[ "$rc" -eq 0 ] || fail "malicious-package check" "unreadable response from $OSV_QUERY_URL"
		done <"$pages"
	done
	if grep -q '^MAL ' "$hits"; then
		local id
		while read -r _ id p v; do
			echo "  $id: $p $v is reported as a malicious package (https://osv.dev/vulnerability/$id)" >&2
		done < <(grep '^MAL ' "$hits")
		fail "malicious-package check" "remove or replace the module versions above"
	fi
}

# ---- f: replace discipline ---------------------------------------------------
replace_check() {
	stage "replace discipline"
	[ -f go.mod ] || fail "replace discipline" "no go.mod at $ROOT"
	local rc=0
	py replace go.mod "$LOCAL_REPLACE_ALLOW" || rc=$?
	[ "$rc" -eq 0 ] || fail "replace discipline" "fix the go.mod replace directives above"
}

# ---- g: pinned tools ---------------------------------------------------------
tools_check() {
	stage "pinned tools"
	local list="$WORK/tool-files"
	if [ -e .git ] && command -v git >/dev/null 2>&1; then
		git ls-files --cached --others --exclude-standard -- hack Makefile >"$list"
	else
		{ find hack -type f 2>/dev/null || true; [ ! -f Makefile ] || echo Makefile; } >"$list"
	fi
	# Fixtures carry deliberately bad lines; Go sources are not shell.
	grep -v -e '^hack/testdata/' -e '\.go$' "$list" >"$list.f" || true
	local rc=0
	py tools "$ROOT" "$list.f" || rc=$?
	[ "$rc" -eq 0 ] || fail "pinned tools" "pin every remote go install / go run to an exact version"
}

# ---- --update ----------------------------------------------------------------
update() {
	env_guard
	mod_verify
	stage "lock (update)"
	current_graph "lock (update)"
	py update-plan "$LOCK" "$WORK/graph" "$WORK" "$PROXY_URL" || fail "lock (update)" "could not plan the update"
	if [ -s "$WORK/fetch" ]; then
		echo "    fetching $(wc -l <"$WORK/fetch" | tr -d ' ') publish times from $PROXY_URL"
		# shellcheck disable=SC2016
		xargs -P 8 -n 2 sh -c 'curl -fsS --max-time 30 --retry 2 -o "$2" "$1" || { echo "    could not fetch $1" >&2; exit 1; }' _ \
			<"$WORK/fetch" ||
			fail "lock (update)" "network failure reading publish times from $PROXY_URL (a failed fetch is a failure, never a skip)"
	fi
	py update-write "$LOCK" "$WORK" || fail "lock (update)" "could not write $LOCK"
	cooldown_check "$WORK/delta"
	malicious_check "$WORK/delta"
	echo "OK: [verify-deps] $LOCK updated; review the diff and commit it"
}

check() {
	env_guard
	mod_verify
	lock_check
	cooldown_check "$LOCK"
	malicious_check "$LOCK"
	replace_check
	tools_check
	echo "OK: [verify-deps] dependency supply-chain check green"
}

# ---- --self-test -------------------------------------------------------------
# Each case copies hack/testdata/verify-deps/good into a temp repo, overlays
# cases/<name>, copies this script in, and runs it with the stub go and curl in
# hack/testdata/verify-deps/bin first on PATH. The stubs answer from the case's
# stub/ directory and never touch the network. Cases run concurrently; results
# print in the order listed.
self_test() {
	local td="$ROOT/hack/testdata/verify-deps"
	[ -d "$td/good" ] && [ -d "$td/bin" ] || { echo "self-test: fixtures missing under $td" >&2; exit 1; }
	mkwork
	local recent old pass=0 failed=0 seq=0 i
	recent="$(py ago 3)"
	old="$(py ago 400)"

	run_case() { # run_case <name> <args|-> <expect: pass|stage> [output fragment] [lock fragment]
		local name="$1" args="$2" want="$3" frag="${4:-}" lockfrag="${5:-}"
		local dir="$WORK/case-$name" out rc=0 verdict=ok
		mkdir -p "$dir"
		cp -R "$td/good/." "$dir/"
		[ ! -d "$td/cases/$name" ] || cp -R "$td/cases/$name/." "$dir/"
		mkdir -p "$dir/hack"
		cp "$SELF" "$dir/hack/verify-deps.sh"
		local f
		for f in "$dir/hack/deps.lock" "$dir/stub/info"; do
			[ ! -f "$f" ] || { sed -e "s/@RECENT@/$recent/g" -e "s/@OLD@/$old/g" "$f" >"$f.s" && mv "$f.s" "$f"; }
		done
		if [ "$args" = "-" ]; then
			out="$(cd "$dir" && env -u GONOSUMDB -u GONOSUMCHECK -u GOINSECURE -u GOPRIVATE -u GONOPROXY PATH="$td/bin:$PATH" bash hack/verify-deps.sh 2>&1)" || rc=$?
		else
			out="$(cd "$dir" && env -u GONOSUMDB -u GONOSUMCHECK -u GOINSECURE -u GOPRIVATE -u GONOPROXY PATH="$td/bin:$PATH" bash hack/verify-deps.sh "$args" 2>&1)" || rc=$?
		fi
		if [ "$want" = pass ]; then
			[ "$rc" -eq 0 ] || verdict="want pass, exit $rc"
		else
			if [ "$rc" -eq 0 ]; then
				verdict="want FAIL in '$want', passed"
			elif ! grep -qF "FAIL: [verify-deps] $want:" <<<"$out"; then
				verdict="want FAIL in '$want', failed elsewhere"
			fi
		fi
		if [ "$verdict" = ok ] && [ -n "$frag" ] && ! grep -qF -- "$frag" <<<"$out"; then
			verdict="output lacks '$frag'"
		fi
		if [ "$verdict" = ok ] && [ -n "$lockfrag" ] && ! grep -qF -- "$lockfrag" "$dir/hack/deps.lock"; then
			verdict="hack/deps.lock lacks '$lockfrag'"
		fi
		if [ "$verdict" = ok ]; then
			echo "  ok   $name"
		else
			echo "  FAIL $name: $verdict"
			printf '%s\n' "$out" | sed 's/^/       | /'
		fi
	}

	bg() {
		seq=$((seq + 1))
		run_case "$@" >"$WORK/result.$seq" 2>&1 &
	}

	echo "==> [verify-deps] self-test"
	bg good - pass "exempt: example.com/fresh v1.1.0"
	bg env-gosumdb-off - "env guard" "GOSUMDB='off'"
	bg env-gonosumdb - "env guard" "GONOSUMDB="
	bg env-goprivate - "env guard" "GOPRIVATE="
	bg env-goinsecure - "env guard" "GOINSECURE="
	bg env-goflags-mod - "env guard" "-mod=mod"
	bg env-goproxy-direct - "env guard" "the first proxy must be"
	bg modverify - "go mod verify"
	bg lock-added - lock "added:   example.com/new v1.0.0"
	bg lock-removed - lock "removed: example.com/old"
	bg lock-changed - lock "changed: example.com/old v1.2.3"
	bg lock-missing-time - lock "no publish time"
	bg cooldown-fresh - cooldown "example.com/young v0.2.0 was published"
	bg cooldown-unknown - cooldown "example.com/old v1.2.3: the module proxy reports no publish time"
	bg osv-mal - "malicious-package check" "MAL-2026-0001"
	bg osv-network - "malicious-package check" "network failure"
	bg osv-garbled - "malicious-package check" "unreadable response"
	bg osv-paged - "malicious-package check" "MAL-2026-0003"
	bg replace-uncommented - "replace discipline" "not directly after a // comment"
	bg replace-path - "replace discipline" "filesystem replace may only name"
	bg tools-latest - "pinned tools" "'latest'"
	bg tools-noat - "pinned tools" "without an @version"
	bg tools-main - "pinned tools" "'main'"
	bg tools-var - "pinned tools" "'master'"
	bg tools-makefile - "pinned tools" "Makefile:2: go install"
	bg update-ok --update pass "2 new or changed" "github.com/Upper/New v1.2.0 # "
	bg update-fresh --update cooldown "example.com/new v1.0.0 was published" "example.com/new v1.0.0 # "
	bg update-mal --update "malicious-package check" "MAL-2026-0002"
	bg update-network --update "lock (update)" "network failure"
	wait
	for ((i = 1; i <= seq; i++)); do
		cat "$WORK/result.$i"
		if grep -q '^  ok   ' "$WORK/result.$i"; then pass=$((pass + 1)); else failed=$((failed + 1)); fi
	done
	echo "self-test: $pass passed, $failed failed"
	[ "$failed" -eq 0 ]
}

case "${1:-}" in
"") mkwork; check ;;
--update) [ $# -eq 1 ] || { echo "usage: hack/verify-deps.sh [--update | --self-test]" >&2; exit 2; }; mkwork; update ;;
--self-test) [ $# -eq 1 ] || { echo "usage: hack/verify-deps.sh [--update | --self-test]" >&2; exit 2; }; self_test ;;
*) echo "usage: hack/verify-deps.sh [--update | --self-test]" >&2; exit 2 ;;
esac
