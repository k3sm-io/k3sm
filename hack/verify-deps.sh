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
#   cooldown                 no module version whose age is under 14 days,
#                            unless hack/deps.cooldown-exempt names it with a
#                            reason. The age is the commit time the module
#                            proxy records for the version (the .info Time),
#                            NOT when the version was first published: a
#                            backdated commit is a known gap. Every module
#                            added or changed since the merge base has its
#                            time re-read from the proxy, so a forged lock
#                            time cannot clear the cooldown.
#   malicious-package check  no module version carries an OSV MAL- advisory
#   wrapper graphs           the same lock, cooldown and malicious-package
#                            stages over each wrapper module's graph (every
#                            module its go.sum hashes the source of), each in
#                            its own lock: the zot wrapper
#                            (pkg/registrysvc/zotchild/go.sum.txt,
#                            hack/deps-zotchild.lock) and the helm wrapper
#                            (pkg/helmchart/helmchild/go.sum.txt,
#                            hack/deps-helmchild.lock). k3sm builds zot and
#                            helm from those go.sums, outside this repo's
#                            go.mod, so their modules are not in the repo
#                            graph above (WRAPPERS below)
#   replace discipline       every go.mod replace sits directly under its own
#                            comment line, and a filesystem replace points
#                            only at a sibling repo
#   pinned tools             no `go install` / `go run` of a remote module in
#                            hack/**, a Makefile or a //go:generate line
#                            without an exact version
#
# Usage (from anywhere; the script runs from the repo root with GOWORK=off):
#   hack/verify-deps.sh              run every stage
#   hack/verify-deps.sh --update     rewrite hack/deps.lock from the current graph
#                                    and each wrapper lock from its wrapper's
#                                    go.sum, then run the cooldown and
#                                    malicious-package stages on the modules
#                                    that changed
#   hack/verify-deps.sh --self-test  hermetic fixtures (hack/testdata/verify-deps),
#                                    stubbed go and curl, no network
#   hack/verify-deps.sh --modules <file>
#                                    run the env guard, the cooldown and the
#                                    malicious-package check over a module list
#                                    that is NOT this repo's graph: one
#                                    "<module> <version>" per line (a relative
#                                    path is read from the caller's directory).
#                                    For binaries k3sm builds from a pinned
#                                    module outside its own go.mod, whose full
#                                    list comes from `go version -m`
#                                    (hack/images/metrics-server/build.sh in the k3sm repository).
#                                    The exemptions in hack/deps.cooldown-exempt
#                                    apply to it too.
#
# Network: the malicious-package stage queries https://api.osv.dev; the cooldown
# stage and --update read commit times from https://proxy.golang.org. A network
# failure is a
# failure, never a skip: a supply-chain check that passes when it cannot look
# has checked nothing.
#
# Needs bash, python3 and curl. Exit status: 0 pass; 1 failure; 2 usage.
set -euo pipefail

SELF="$0"
CALLER_PWD="$PWD"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export GOWORK=off

COOLDOWN_DAYS=14
PROXY_URL="https://proxy.golang.org"
OSV_BATCH_URL="https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL="https://api.osv.dev/v1/query"
OSV_BATCH_SIZE=500
LOCK="hack/deps.lock"
# The wrapper modules: a binary k3sm builds outside its own go.mod, from a
# wrapper module's go.sum embedded in the repo (built with -mod=readonly). Each
# graph gets its own lock, so a module that moves there is a reviewed file
# change exactly like one in hack/deps.lock. One line per wrapper:
#
#   <name> <go.sum> <lock>
#
# zotchild: the registry's zot child (pkg/registrysvc).
# helmchild: the helm binary the daemon builds (pkg/helmchart). Its graph
#   carries golang.org/x/net v0.62.0, the version the control-plane build raises
#   to under the cooldown exemption in hack/release/build-cp.sh (EXEMPT there,
#   expiring 2026-11-10). The matching x/net line in hack/deps.cooldown-exempt
#   rests on that ruling and is to be dropped when that exemption goes.
WRAPPERS="zotchild pkg/registrysvc/zotchild/go.sum.txt hack/deps-zotchild.lock
helmchild pkg/helmchart/helmchild/go.sum.txt hack/deps-helmchild.lock"
# The two go.sum paths again, for the self-test's per-case removal markers.
ZOT_SUM="pkg/registrysvc/zotchild/go.sum.txt"
HELM_SUM="pkg/helmchart/helmchild/go.sum.txt"
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
    "# `go list -m all` (main module excluded), each with the commit time the\n"
    "# module proxy records for the version that is built (not its first\n"
    "# publication; `local` for a filesystem replacement).\n"
    "# Regenerate with: hack/verify-deps.sh --update\n"
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
                raise ValueError("%s:%d: no commit time (want '<module line> # <time>')" % (path, n))
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


def cmd_sum_graph(sumpath):
    """Print "<module> <version>" for every module a go.sum hashes the source
    of (its zip lines; a /go.mod-only line is graph metadata, never built)."""
    try:
        with open(sumpath) as f:
            raw = f.read().splitlines()
    except OSError as e:
        die("cannot read %s: %s" % (sumpath, e))
    mods = {}
    for n, line in enumerate(raw, 1):
        t = line.split()
        if not t:
            continue
        if len(t) != 3 or not t[2].startswith("h1:"):
            die("%s:%d: not a go.sum line" % (sumpath, n))
        if t[1].endswith("/go.mod"):
            continue
        prev = mods.setdefault(t[0], t[1])
        if prev != t[1]:
            die("%s: %s is hashed at two versions (%s, %s)" % (sumpath, t[0], prev, t[1]))
    if not mods:
        die("%s hashes no module source" % sumpath)
    sys.stdout.write("".join("%s %s\n" % (p, mods[p]) for p in sorted(mods)))


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


def cmd_verify_plan(lockpath, basepath, work, proxy):
    try:
        lock = read_lock(lockpath)
    except ValueError as e:
        die(str(e))
    base = set()
    if basepath != "-":
        try:
            base = {k for k, _ in read_lock(basepath)}
        except (OSError, ValueError):
            base = set()
    if basepath == "-" or not base:
        print("    no base lock at the merge base with origin/main: every line is re-checked")
    fetch = open(os.path.join(work, "fetch"), "w")
    plan = open(os.path.join(work, "verify"), "w")
    n = 0
    for i, (key, tm) in enumerate(lock):
        _, _, ep, ev, local = parse_key(key)
        if local or key in base:
            plan.write("%s\t%s\t-\n" % (key, tm))
            continue
        out = os.path.join(work, "vinfo.%d" % i)
        fetch.write("%s/%s/@v/%s.info %s\n" % (proxy, escape(ep), escape(ev), out))
        plan.write("%s\t%s\t%s\n" % (key, tm, out))
        n += 1
    fetch.close()
    plan.close()
    print("    %d lock lines added or changed since the base; re-reading their times from the proxy" % n)


def cmd_verify_times(work, outpath):
    lines, bad = [], []
    with open(os.path.join(work, "verify")) as f:
        for raw in f:
            key, tm, info = raw.rstrip("\n").split("\t")
            if info != "-":
                try:
                    with open(info) as g:
                        proxy_tm = str(json.load(g)["Time"])
                except (OSError, ValueError, KeyError, TypeError) as e:
                    die("unreadable proxy .info for %s: %s" % (key, e))
                a, b = parse_time(tm), parse_time(proxy_tm)
                if a is None or b is None or abs(a - b) > 3600:
                    bad.append("%s: lock time %s does not match the proxy (%s)" % (key, tm, proxy_tm))
                tm = proxy_tm
            lines.append("%s # %s" % (key, tm))
    for b in bad:
        print("  " + b)
    with open(outpath, "w") as f:
        f.write(HEADER + "".join(l + "\n" for l in lines))
    sys.exit(1 if bad else 0)


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
            bad.append("%s: unparseable commit time %r (run hack/verify-deps.sh --update)" % (key, tm))
            continue
        # The proxy records the zero time when it does not know a version's
        # commit time; an unknown age cannot clear the cooldown.
        unknown = tm.startswith("0001-01-01")
        age = (now - ts) / 86400.0
        if unknown or age < days:
            what = "no known commit time" if unknown else "%.1f days old" % age
            if (ep, ev) in ex:
                used.add((ep, ev))
                print("  exempt: %s %s (%s): %s" % (ep, ev, what, ex[(ep, ev)]))
                continue
            if unknown:
                bad.append("%s %s: the module proxy records no commit time (%s)" % (ep, ev, tm))
            else:
                bad.append("%s %s has a proxy-recorded commit time of %s, %.1f days ago (cooldown is %d days)"
                           % (ep, ev, tm, age, days))
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
        # Every replace needs its own comment line directly above it (for the
        # first entry of a block, a comment directly above `replace (` counts).
        ok = prev in ("comment", "open-commented") and not blank_since
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
        prev, blank_since = "replace", False
    for b in bad:
        print("  " + b)
    sys.exit(1 if bad else 0)


VALUE_FLAGS = {"-o", "-C", "-p", "-tags", "-ldflags", "-gcflags", "-asmflags", "-gccgoflags",
               "-mod", "-modfile", "-pkgdir", "-toolexec", "-overlay", "-pgo", "-exec",
               "-covermode", "-coverpkg", "-buildmode", "-compiler", "-installsuffix", "-reldir"}
PREFIX_WORDS = {"env", "nohup", "exec", "sudo", "command", "time", "then", "do", "else",
                "elif", "if", "while", "until", "!", "nice"}


LITERAL_VAR = re.compile(r'\$\{[^}]*\}|\$\([A-Za-z_][A-Za-z0-9_]*\)')
GO_WORD = re.compile(r'^(?:go|\$\(GO[A-Za-z0-9_]*\)|\$\{GO[^}]*\}|\$GO[A-Za-z0-9_]*)$')
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}


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
        m = LITERAL_VAR.match(line, i)
        if m:
            # ${...} and a make-style $(NAME) are words, not grouping.
            cur.append(m.group(0))
            i = m.end()
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


def go_invocations(seg, depth=0):
    """Return [(verb, target)] for every go install / go run in one segment."""
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
    if i >= len(w):
        return []
    first = w[i].lstrip("@+-") if i == 0 else w[i]
    # sh -c "..." / bash -euc '...': the command string is scanned in turn.
    if os.path.basename(first) in SHELLS and depth < 3:
        j = i + 1
        while j < len(w) and w[j].startswith("-"):
            if "c" in w[j].lstrip("-") and not w[j].startswith("--") and j + 1 < len(w):
                out = []
                for sub in segments(w[j + 1]):
                    out += go_invocations(sub, depth + 1)
                return out
            j += 1
        return []
    if not GO_WORD.match(first):
        return []
    j = i + 1
    # go's own flags before the verb: -C <dir> (or -C=<dir>).
    while j < len(w) and w[j].startswith("-"):
        j += 2 if w[j] == "-C" else 1
    if j >= len(w) or w[j] not in ("install", "run"):
        return []
    verb, args, k = w[j], w[j + 1:], 0
    while k < len(args):
        a = args[k]
        if a == "--":
            k += 1
            break
        if a.startswith("-"):
            k += 2 if ("=" not in a and a.split("=")[0] in VALUE_FLAGS) else 1
            continue
        break
    return [(verb, args[k] if k < len(args) else None)]


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
        is_go = rel.endswith(".go")
        # A version variable resolves through assignments in the same file only;
        # anything else (a sourced file, a caller's argument) is reported as computed.
        tab = {} if is_go else assignments([(rel, lines)])
        for n, raw in enumerate(lines, 1):
            s = raw.strip()
            if is_go:
                # In Go source only a //go:generate directive runs a command.
                m = re.match(r'^//go:generate\s+(.*)$', s)
                if not m:
                    continue
                raw = m.group(1)
            elif not s or s.startswith("#") or s.startswith("//"):
                continue
            for seg in segments(raw):
                for verb, target in go_invocations(seg):
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


def cmd_govcs(value):
    """Exit 0 when GOVCS allows nothing beyond the default public:git|hg,private:all."""
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            die("malformed GOVCS entry %r" % entry)
        pattern, vcs = entry.rsplit(":", 1)
        if pattern == "private":
            continue
        if not set(vcs.split("|")) <= {"git", "hg", "off"}:
            die("GOVCS entry %r allows %s" % (entry, vcs))


def cmd_ago(days):
    t = time.time() - float(days) * 86400
    print(datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


CMDS = {
    "graph-clean": cmd_graph_clean, "sum-graph": cmd_sum_graph, "lockdiff": cmd_lockdiff,
    "update-plan": cmd_update_plan, "update-write": cmd_update_write,
    "cooldown": cmd_cooldown, "verify-plan": cmd_verify_plan, "verify-times": cmd_verify_times, "osv-build": cmd_osv_build, "osv-parse": cmd_osv_parse,
    "osv-page-req": cmd_osv_page_req, "osv-page-parse": cmd_osv_page_parse,
    "replace": cmd_replace, "tools": cmd_tools, "ago": cmd_ago, "govcs": cmd_govcs,
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
	# Only the default checksum database: no "off", no other database or key.
	case "$v" in
	"" | sum.golang.org) ;;
	*) bad="${bad}  GOSUMDB='$v': it must be sum.golang.org (or unset)"$'\n' ;;
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
		-modfile | -modfile=* | --modfile | --modfile=*) bad="${bad}  GOFLAGS carries $f, which swaps in a different go.mod and go.sum"$'\n' ;;
		esac
	done
	v="$(go env GOPROXY)" || fail "env guard" "go env GOPROXY failed"
	case "$v" in
	"" | "$PROXY_URL" | "$PROXY_URL,direct") ;;
	*) bad="${bad}  GOPROXY='$v': it must be $PROXY_URL or $PROXY_URL,direct (or unset)"$'\n' ;;
	esac
	v="$(go env GOVCS)" || fail "env guard" "go env GOVCS failed"
	[ -n "$v" ] || v="$(printenv GOVCS || true)"
	if [ -n "$v" ] && ! py govcs "$v" >/dev/null; then
		bad="${bad}  GOVCS='$v' allows more version control systems than the default (public:git|hg,private:all)"$'\n'
	fi
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

# wrapper_graph <stage> <name> <go.sum> <out>: a wrapper module's graph, from
# its go.sum.
wrapper_graph() {
	py sum-graph "$3" >"$4" || fail "$1" "cannot read the $2 wrapper graph from $3"
}

# ---- c: lock -----------------------------------------------------------------
lock_check() {
	stage "lock"
	current_graph lock
	lock_compare lock "$LOCK" "$WORK/graph"
}

# lock_compare <stage> <lock> <graph>: the graph equals the lock, line for line.
lock_compare() {
	local st="$1" lock="$2" graph="$3"
	[ -f "$lock" ] || fail "$st" "$lock is missing; create it with hack/verify-deps.sh --update"
	local rc=0
	py lockdiff "$lock" "$graph" || rc=$?
	if [ "$rc" -ne 0 ]; then
		cat >&2 <<EOF
The module graph no longer matches $lock (lines above).
Before accepting it, check every added or changed module:
  - provenance: who publishes it, and is it the module you meant (not a look-alike)?
  - age: a version whose proxy-recorded commit time is under $COOLDOWN_DAYS days old is
    refused by the cooldown stage (a backdated commit is not caught; check the release)
  - need: why this change needs it, and which import pulls it in (go mod why -m <module>)
  - alternative: would a small in-repo implementation do instead?
Then run hack/verify-deps.sh --update and commit $lock with the change.
EOF
		fail "$st" "$lock is out of date"
	fi
}

# ---- d: cooldown -------------------------------------------------------------
cooldown_ages() { # cooldown_ages <lock-format file> [stage]
	local rc=0 st="${2:-cooldown}"
	py cooldown "$1" "$EXEMPT" "$COOLDOWN_DAYS" || rc=$?
	[ "$rc" -eq 0 ] || fail "$st" "module versions whose proxy-recorded commit time is under $COOLDOWN_DAYS days old (above). The age is the commit time the proxy records, not first publication, so a backdated commit is not caught. Wait, or add '<module> <version> <reason>' to $EXEMPT after an audit"
}

# cooldown_check <lock-format file> [stage]: the age check on lock times that
# are already trusted (--update just fetched them from the proxy).
cooldown_check() {
	stage "${2:-cooldown}"
	cooldown_ages "$1" "${2:-cooldown}"
}

# cooldown_verify: check mode. A lock line added or changed since the merge base
# with origin/main carries a time nobody has re-checked, so its time is read
# from the proxy again and must agree with the lock within an hour; the age
# check then uses the proxy's time. Lines unchanged since the base keep the lock
# time. With no base lock (no origin/main, or no lock there) every line is new.
# cooldown_verify [lock] [stage]: the lock defaults to $LOCK.
cooldown_verify() {
	local lock="${1:-$LOCK}" st="${2:-cooldown}"
	stage "$st"
	local base="-" mb
	rm -f "$WORK/base.lock"
	if [ -e .git ] && command -v git >/dev/null 2>&1 &&
		mb="$(git merge-base HEAD origin/main 2>/dev/null)" &&
		git show "$mb:$lock" >"$WORK/base.lock" 2>/dev/null; then
		base="$WORK/base.lock"
	fi
	py verify-plan "$lock" "$base" "$WORK" "$PROXY_URL" || fail "$st" "could not read $lock"
	fetch_infos "$st"
	local rc=0
	py verify-times "$WORK" "$WORK/verified.lock" || rc=$?
	[ "$rc" -eq 0 ] || fail "$st" "lock time does not match the proxy (above); regenerate the lines with hack/verify-deps.sh --update"
	cooldown_ages "$WORK/verified.lock" "$st"
}

# fetch_infos <stage>: download every "<url> <file>" pair in $WORK/fetch.
fetch_infos() {
	[ -s "$WORK/fetch" ] || return 0
	echo "    fetching $(wc -l <"$WORK/fetch" | tr -d ' ') commit times from $PROXY_URL"
	# shellcheck disable=SC2016
	xargs -P 8 -n 2 sh -c 'curl -fsS --max-time 30 --retry 2 -o "$2" "$1" || { echo "    could not fetch $1" >&2; exit 1; }' _ \
		<"$WORK/fetch" ||
		fail "$1" "network failure reading commit times from $PROXY_URL (a failed fetch is a failure, never a skip)"
}

# ---- e: malicious-package check ---------------------------------------------
osv_post() { # osv_post <url> <request file> <response file>
	curl -fsS --max-time 60 --retry 2 -X POST -H 'Content-Type: application/json' \
		--data-binary "@$2" -o "$3" "$1"
}

malicious_check() { # malicious_check <lock-format file> [stage]
	local st="${2:-malicious-package check}"
	stage "$st"
	local n i rc hits="$WORK/osv-hits" pages="$WORK/osv-pages"
	: >"$hits"
	n="$(py osv-build "$1" "$WORK" "$OSV_BATCH_SIZE")" || fail "$st" "could not read $1"
	for ((i = 0; i < n; i++)); do
		osv_post "$OSV_BATCH_URL" "$WORK/osv-req.$i" "$WORK/osv-resp.$i" ||
			fail "$st" "network failure querying $OSV_BATCH_URL (a failed query is a failure, never a skip)"
		rc=0
		py osv-parse "$WORK/osv-q.$i" "$WORK/osv-resp.$i" >>"$hits" || rc=$?
		[ "$rc" -eq 0 ] || fail "$st" "unreadable response from $OSV_BATCH_URL"
	done
	# A result with more advisories than one page holds carries a page token.
	local guard=0 p v tok
	while grep -q '^PAGE ' "$hits"; do
		guard=$((guard + 1))
		[ "$guard" -le 50 ] || fail "$st" "OSV paging did not terminate"
		grep '^PAGE ' "$hits" >"$pages"
		grep -v '^PAGE ' "$hits" >"$hits.keep" || true
		mv "$hits.keep" "$hits"
		while read -r _ p v tok; do
			py osv-page-req "$p" "$v" "$tok" >"$WORK/osv-page-req"
			osv_post "$OSV_QUERY_URL" "$WORK/osv-page-req" "$WORK/osv-page-resp" ||
				fail "$st" "network failure querying $OSV_QUERY_URL (a failed query is a failure, never a skip)"
			rc=0
			py osv-page-parse "$p" "$v" "$WORK/osv-page-resp" >>"$hits" || rc=$?
			[ "$rc" -eq 0 ] || fail "$st" "unreadable response from $OSV_QUERY_URL"
		done <"$pages"
	done
	if grep -q '^MAL ' "$hits"; then
		local id
		while read -r _ id p v; do
			echo "  $id: $p $v is reported as a malicious package (https://osv.dev/vulnerability/$id)" >&2
		done < <(grep '^MAL ' "$hits")
		fail "$st" "remove or replace the module versions above"
	fi
}

# ---- wrapper graphs -----------------------------------------------------------
# Each wrapper module's graph gets the repo graph's lock, cooldown and
# malicious-package stages: the binary is built from that go.sum, so a module
# moved there runs on the node exactly like one in this repo's go.mod.
# wrapper_check <name> <go.sum> <lock>
wrapper_check() {
	local name="$1" sum="$2" lock="$3"
	if [ ! -f "$sum" ]; then
		[ ! -f "$lock" ] || fail "lock ($name)" "$lock exists but $sum does not: the $name wrapper graph moved or was removed without its lock"
		echo "    no $name wrapper module ($sum absent): the $name stages do not apply to this repo"
		return 0
	fi
	stage "lock ($name)"
	wrapper_graph "lock ($name)" "$name" "$sum" "$WORK/wgraph-$name"
	lock_compare "lock ($name)" "$lock" "$WORK/wgraph-$name"
	cooldown_verify "$lock" "cooldown ($name)"
	malicious_check "$lock" "malicious-package check ($name)"
}

# wrapper_update <name> <go.sum> <lock>: --update for one wrapper; a lock it
# rewrites is appended to $WORK/updated.
wrapper_update() {
	local name="$1" sum="$2" lock="$3" w="$WORK/w-$1"
	[ -f "$sum" ] || return 0
	stage "lock ($name update)"
	mkdir -p "$w"
	wrapper_graph "lock ($name update)" "$name" "$sum" "$w/graph"
	py update-plan "$lock" "$w/graph" "$w" "$PROXY_URL" || fail "lock ($name update)" "could not plan the update"
	cp "$w/fetch" "$WORK/fetch"
	fetch_infos "lock ($name update)"
	py update-write "$lock" "$w" || fail "lock ($name update)" "could not write $lock"
	cooldown_check "$w/delta" "cooldown ($name)"
	malicious_check "$w/delta" "malicious-package check ($name)"
	echo "$lock" >>"$WORK/updated"
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
	# Every file under hack/ and the Makefile, plus every Go file in the repo
	# (only its //go:generate lines are read).
	if [ -e .git ] && command -v git >/dev/null 2>&1; then
		git ls-files --cached --others --exclude-standard -- hack Makefile '*.go' >"$list"
	else
		{ find hack -type f 2>/dev/null || true; [ ! -f Makefile ] || echo Makefile; find . -name '*.go' -type f | sed 's#^\./##'; } >"$list"
	fi
	# Fixtures carry deliberately bad lines.
	grep -v -e '^hack/testdata/' "$list" | LC_ALL=C sort -u >"$list.f" || true
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
	fetch_infos "lock (update)"
	py update-write "$LOCK" "$WORK" || fail "lock (update)" "could not write $LOCK"
	cooldown_check "$WORK/delta"
	malicious_check "$WORK/delta"
	: >"$WORK/updated"
	local name sum lock
	while read -r name sum lock <&3; do
		wrapper_update "$name" "$sum" "$lock"
	done 3<<<"$WRAPPERS"
	if [ -s "$WORK/updated" ]; then
		echo "OK: [verify-deps] $LOCK and $(paste -sd ' ' "$WORK/updated" | sed 's/ /, /g') updated; review the diff and commit them"
	else
		echo "OK: [verify-deps] $LOCK updated; review the diff and commit it"
	fi
}

# ---- --modules -----------------------------------------------------------------
# modules <file>: the cooldown and the malicious-package check over a module list
# from outside this repo's graph. Every commit time is read from the proxy (the
# list carries none), so the age cannot be forged by the caller.
modules() {
	local list="$1"
	case "$list" in /*) ;; *) list="$CALLER_PWD/$list" ;; esac
	env_guard
	stage "modules ($list)"
	[ -s "$list" ] || fail "modules" "no module list at $list (want one '<module> <version>' per line)"
	py graph-clean <"$list" >"$WORK/graph"
	py update-plan "$WORK/none.lock" "$WORK/graph" "$WORK" "$PROXY_URL" || fail "modules" "could not read $list"
	fetch_infos "modules"
	py update-write "$WORK/modules.lock" "$WORK" >/dev/null || fail "modules" "could not record the commit times"
	cooldown_check "$WORK/modules.lock"
	malicious_check "$WORK/modules.lock"
	echo "OK: [verify-deps] $(grep -vc '^#' "$WORK/modules.lock") modules from $list pass the cooldown and the malicious-package check"
}

check() {
	env_guard
	mod_verify
	lock_check
	cooldown_verify
	malicious_check "$LOCK"
	local name sum lock
	while read -r name sum lock <&3; do
		wrapper_check "$name" "$sum" "$lock"
	done 3<<<"$WRAPPERS"
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
		# A case carrying .no-zot is a repo without a zot wrapper module (apis,
		# runtimed, darwin-net): the zotchild stages must not run there.
		[ ! -f "$dir/.no-zot" ] || rm -f "$dir/$ZOT_SUM" "$dir/hack/deps-zotchild.lock" "$dir/.no-zot"
		# .no-zot-sum keeps the lock and removes only the graph: the check must refuse,
		# never skip, a wrapper that moved out from under its lock.
		[ ! -f "$dir/.no-zot-sum" ] || rm -f "$dir/$ZOT_SUM" "$dir/.no-zot-sum"
		# .no-helm and .no-helm-sum do the same for the helm wrapper module.
		[ ! -f "$dir/.no-helm" ] || rm -f "$dir/$HELM_SUM" "$dir/hack/deps-helmchild.lock" "$dir/.no-helm"
		[ ! -f "$dir/.no-helm-sum" ] || rm -f "$dir/$HELM_SUM" "$dir/.no-helm-sum"
		local f
		for f in "$dir/hack/deps.lock" "$dir/hack/deps-zotchild.lock" "$dir/hack/deps-helmchild.lock" "$dir/stub/info" "$dir/base/hack/deps.lock"; do
			[ ! -f "$f" ] || { sed -e "s/@RECENT@/$recent/g" -e "s/@OLD@/$old/g" "$f" >"$f.s" && mv "$f.s" "$f"; }
		done
		# A case with base/hack/deps.lock becomes a git repo whose origin/main
		# holds that lock, so check mode has a merge base to compare against.
		if [ -d "$dir/base" ]; then
			mv "$dir/hack/deps.lock" "$WORK/worklock-$name"
			mv "$dir/base/hack/deps.lock" "$dir/hack/deps.lock"
			rm -rf "$dir/base"
			if ! (cd "$dir" && git init -q && git add -A &&
				git -c user.name=self-test -c user.email=self-test@example.invalid -c commit.gpgsign=false \
					commit -q --no-verify -m base &&
				git update-ref refs/remotes/origin/main HEAD) >/dev/null 2>&1; then
				echo "  FAIL $name: could not build the base git repo"
				return 0
			fi
			mv "$WORK/worklock-$name" "$dir/hack/deps.lock"
		fi
		if [ "$args" = "-" ]; then
			out="$(cd "$dir" && env -u GONOSUMDB -u GONOSUMCHECK -u GOINSECURE -u GOPRIVATE -u GONOPROXY PATH="$td/bin:$PATH" bash hack/verify-deps.sh 2>&1)" || rc=$?
		else
			# Word-split on purpose: a case may pass a flag and its operand.
			# shellcheck disable=SC2086
			out="$(cd "$dir" && env -u GONOSUMDB -u GONOSUMCHECK -u GOINSECURE -u GOPRIVATE -u GONOPROXY PATH="$td/bin:$PATH" bash hack/verify-deps.sh $args 2>&1)" || rc=$?
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
	bg env-goproxy-direct - "env guard" "GOPROXY='direct': it must be"
	bg env-goproxy-mirror - "env guard" "GOPROXY='https://proxy.golang.org,https://mirror.example.invalid'"
	bg env-gosumdb-custom - "env guard" "GOSUMDB='sum.golang.google.cn'"
	bg env-goflags-modfile - "env guard" "GOFLAGS carries -modfile=alt.mod"
	bg env-govcs-all - "env guard" "GOVCS='public:all'"
	bg env-govcs-restrict - pass
	bg modverify - "go mod verify"
	bg lock-added - lock "added:   example.com/new v1.0.0"
	bg lock-removed - lock "removed: example.com/old"
	bg lock-changed - lock "changed: example.com/old v1.2.3"
	bg lock-missing-time - lock "no commit time"
	bg cooldown-fresh - cooldown "example.com/young v0.2.0 has a proxy-recorded commit time"
	bg cooldown-unknown - cooldown "example.com/old v1.2.3: the module proxy records no commit time"
	bg cooldown-forged - cooldown "example.com/young v0.2.0: lock time"
	bg cooldown-unchanged - pass "0 lock lines added or changed since the base"
	bg cooldown-network - cooldown "network failure"
	bg osv-mal - "malicious-package check" "MAL-2026-0001"
	bg osv-network - "malicious-package check" "network failure"
	bg osv-garbled - "malicious-package check" "unreadable response"
	bg osv-paged - "malicious-package check" "MAL-2026-0003"
	bg replace-uncommented - "replace discipline" "not directly after a // comment"
	bg replace-path - "replace discipline" "filesystem replace may only name"
	bg replace-shared-comment - "replace discipline" "go.mod:20: replace is not directly after"
	bg replace-block - "replace discipline" "go.mod:20: replace is not directly after"
	bg tools-latest - "pinned tools" "'latest'"
	bg tools-noat - "pinned tools" "without an @version"
	bg tools-main - "pinned tools" "'main'"
	bg tools-var - "pinned tools" "'master'"
	bg tools-makefile - "pinned tools" "Makefile:2: go install"
	bg tools-gogenerate - "pinned tools" "pkg/bad.go:4: go run example.com/evil/gen@latest"
	bg tools-dash-c - "pinned tools" "go install example.com/evil/cmd@latest"
	bg tools-make-var - "pinned tools" "Makefile:2: go install example.com/evil/cmd@main"
	bg tools-brace-var - "pinned tools" "go run example.com/evil/cmd: a remote module without"
	bg tools-sh-c - "pinned tools" "hack/bad.sh:2: go install example.com/evil/cmd@latest"
	bg tools-bash-c - "pinned tools" "'master'"
	bg update-ok --update pass "2 new or changed" "github.com/Upper/New v1.2.0 # "
	bg update-fresh --update cooldown "example.com/new v1.0.0 has a proxy-recorded commit time" "example.com/new v1.0.0 # "
	bg update-mal --update "malicious-package check" "MAL-2026-0002"
	bg modules-ok "--modules modules.txt" pass "OK: [verify-deps] 2 modules"
	bg modules-exempt "--modules modules.txt" pass "exempt: example.com/fresh v1.1.0"
	bg modules-fresh "--modules modules.txt" cooldown "example.com/young v0.2.0 has a proxy-recorded commit time"
	bg modules-mal "--modules modules.txt" "malicious-package check" "MAL-2026-0004"
	bg modules-missing "--modules absent.txt" modules "no module list"
	bg update-network --update "lock (update)" "network failure"
	bg zot-lock-added - "lock (zotchild)" "added:   example.com/zextra v1.0.0"
	bg zot-cooldown-fresh - "cooldown (zotchild)" "example.com/zyoung v0.1.0 has a proxy-recorded commit time"
	bg zot-osv-mal - "malicious-package check (zotchild)" "MAL-2026-0005"
	bg zot-sum-empty - "lock (zotchild)" "hashes no module source"
	bg zot-sum-two-versions - "lock (zotchild)" "example.com/zchild is hashed at two versions"
	bg zot-update --update pass "wrote hack/deps-zotchild.lock: 3 modules, 1 new or changed"
	bg no-zot - pass "the zotchild stages do not apply to this repo"
	bg no-zot-update --update pass "OK: [verify-deps] hack/deps.lock updated; review the diff and commit it"
	bg zot-lock-no-sum - "lock (zotchild)" "exists but pkg/registrysvc/zotchild/go.sum.txt does not"
	bg helm-clean - pass "==> [verify-deps] malicious-package check (helmchild)"
	bg helm-lock-added - "lock (helmchild)" "added:   example.com/hextra v1.0.0"
	bg helm-cooldown-fresh - "cooldown (helmchild)" "example.com/hyoung v0.1.0 has a proxy-recorded commit time"
	bg helm-osv-mal - "malicious-package check (helmchild)" "MAL-2026-0006"
	bg helm-update --update pass "wrote hack/deps-helmchild.lock: 3 modules, 1 new or changed"
	bg helm-lock-no-sum - "lock (helmchild)" "exists but pkg/helmchart/helmchild/go.sum.txt does not"
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
--modules) [ $# -eq 2 ] || { echo "usage: hack/verify-deps.sh [--update | --self-test | --modules <file>]" >&2; exit 2; }; mkwork; modules "$2" ;;
--update) [ $# -eq 1 ] || { echo "usage: hack/verify-deps.sh [--update | --self-test]" >&2; exit 2; }; mkwork; update ;;
--self-test) [ $# -eq 1 ] || { echo "usage: hack/verify-deps.sh [--update | --self-test]" >&2; exit 2; }; self_test ;;
*) echo "usage: hack/verify-deps.sh [--update | --self-test]" >&2; exit 2 ;;
esac
