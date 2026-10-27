#!/usr/bin/env bash
#
# k3sm update downtime acceptance gate: measure how long a node's daemons and the API
# server are unavailable during a managed update (`k3sm update apply`) or an
# in-place reinstall (`k3sm install`).
#
# The measurer samples five probes on one Mac, each on its own 250 ms cadence
# (a probe slower than the cadence starts its next sample as soon as it ends):
#
#   api     `k3sm kubectl get --raw /readyz` answers "ok" (the admin kubeconfig's
#           server: the node's own endpoint on a server, the mesh server on a
#           worker; B668_API_SERVER overrides it)
#   status  `k3sm status -o json` exits 0 with verdict "running"
#   daemon  the same report's node-daemon row (server or agent) reads "running"
#   netd    the root helper's socket accepts a connection
#   node    the Node's Ready condition is True (the k3sm.io/update-phase
#           annotation is recorded beside it)
#
# Every sample is one CSV row: t_ms (epoch ms at the probe's start), role,
# node, probe, ok (1|0), ms (how long the probe took), detail. A window is the
# span from a probe's first failed sample to its next successful one, per
# probe and per role; a window still open at the end of the trace is printed
# with ">=" seconds. The resolution of a window is the cadence plus the
# probe's own latency (about 1.5 s for status).
#
# Usage:
#   hack/acceptance/B668.sh --self-test
#       the gate: the window computation over four fixed timelines in
#       testdata/B668 (a server roll, a worker roll, a reinstall, no outage),
#       a negative control, and the sampler driven by a fake timeline.
#       Hermetic: touches no cluster, no daemon and no socket.
#   sudo K3SM_LAB=1 hack/acceptance/B668.sh sample --role server|worker \
#       --node <node name> --out <evidence dir> [--duration 3600] [--interval 0.25]
#       sample until --duration elapses, <evidence dir>/STOP appears, or
#       SIGINT/SIGTERM; writes samples-<node>.csv and summary-<node>.txt there.
#       Read-only: it runs k3sm status, k3sm kubectl get and a socket connect.
#   hack/acceptance/B668.sh summarize [--format text|windows] <samples.csv>...
#       print the windows of one or more traces (both Macs of a roll at once).
#
# Environment (sample only):
#   K3SM_LAB=1         required to sample
#   B668_K3SM          the k3sm binary (default /Library/k3sm/k3sm)
#   B668_API_SERVER    an apiserver URL passed as kubectl --server
#   B668_NETD_SOCKET   the root helper's socket (default /var/lib/k3sm/run/netd.sock)
#
# Exit: 0 pass (or the command finished); 1 a failed assertion or a sampler
# failure; 2 usage, or K3SM_LAB unset for sample (not a pass).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SELF="$HERE/B668.sh"
TESTDATA="$HERE/testdata/B668"

PY_PROG="$(
	cat <<'PY'
import csv, datetime, json, os, signal, socket, subprocess, sys, threading, time

FIELDS = ["t_ms", "role", "node", "probe", "ok", "ms", "detail"]
PROBES = ["api", "status", "daemon", "netd", "node"]
ROLES = ["server", "worker"]
DAEMON_ROW = {"server": "server", "worker": "agent"}


def die(msg, code=2):
    sys.stderr.write("update downtime: " + msg + "\n")
    sys.exit(code)


def one_line(s, limit=120):
    s = " ".join(str(s).split())
    return s[:limit]


def utc(t_ms):
    d = datetime.datetime.fromtimestamp(t_ms / 1000.0, tz=datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t_ms % 1000)


# ---- sampling ---------------------------------------------------------------

def run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timed out after %ss" % timeout
    except OSError as e:
        return None, "", str(e)


def failure(rc, err):
    first = (err or "").strip().splitlines()
    return one_line("rc=%s %s" % ("timeout" if rc is None else rc, first[-1] if first else ""))


class Live:
    def __init__(self, role, node):
        self.role, self.node = role, node
        self.k3sm = os.environ.get("B668_K3SM", "/Library/k3sm/k3sm")
        self.sock = os.environ.get("B668_NETD_SOCKET", "/var/lib/k3sm/run/netd.sock")
        srv = os.environ.get("B668_API_SERVER", "")
        self.server = ["--server", srv] if srv else []

    def kubectl(self, *args):
        return [self.k3sm, "kubectl"] + self.server + ["--request-timeout=2s"] + list(args)

    def api(self):
        rc, out, err = run(self.kubectl("get", "--raw", "/readyz"), 5)
        if rc == 0 and out.strip() == "ok":
            return [("api", True, "ok")]
        return [("api", False, failure(rc, err or out))]

    def status(self):
        rc, out, err = run([self.k3sm, "status", "-o", "json"], 20)
        try:
            rep = json.loads(out)
        except ValueError:
            d = failure(rc, err or "no json")
            return [("status", False, d), ("daemon", False, d)]
        verdict = rep.get("verdict", "")
        want = DAEMON_ROW[self.role]
        row = next((r for r in rep.get("rows", []) if r.get("name") == want), {})
        state = row.get("state", "absent")
        return [
            ("status", rc == 0 and verdict == "running", "exit=%s verdict=%s" % (rc, verdict)),
            ("daemon", state == "running", "%s=%s" % (want, state)),
        ]

    def netd(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(self.sock)
            return [("netd", True, "connected")]
        except OSError as e:
            return [("netd", False, one_line(e.strerror or e))]
        finally:
            s.close()

    def node_ready(self):
        path = '{.status.conditions[?(@.type=="Ready")].status} {.metadata.annotations.k3sm\\.io/update-phase}'
        rc, out, err = run(self.kubectl("get", "node", self.node, "-o", "jsonpath=" + path), 5)
        if rc != 0:
            return [("node", False, failure(rc, err))]
        parts = (out.strip() + " ").split(" ", 1)
        ready, phase = parts[0], parts[1].strip()
        return [("node", ready == "True", "ready=%s phase=%s" % (ready or "?", phase))]

    def groups(self):
        return [self.api, self.status, self.netd, self.node_ready]


class Fake:
    """A timeline instead of a cluster: B668_FAKE_TIMELINE is
    probe=a-b[+c-d],... in seconds from the sampler's start; a probe is down
    while the elapsed time is in [a, b)."""

    def __init__(self, spec, start):
        self.start = start
        self.down = {}
        for item in filter(None, spec.split(",")):
            probe, spans = item.split("=", 1)
            self.down[probe] = [tuple(float(x) for x in s.split("-")) for s in spans.split("+")]

    def up(self, probe):
        e = time.monotonic() - self.start
        return not any(a <= e < b for a, b in self.down.get(probe, []))

    def probe(self, *names):
        return lambda: [(n, self.up(n), "fake") for n in names]

    def groups(self):
        return [self.probe("api"), self.probe("status", "daemon"), self.probe("netd"), self.probe("node")]


def sample(argv):
    opts = {"--role": "", "--node": "", "--out": "", "--duration": "3600", "--interval": "0.25"}
    i = 0
    while i < len(argv):
        if argv[i] not in opts or i + 1 >= len(argv):
            die("sample: unknown or incomplete flag %r" % argv[i])
        opts[argv[i]] = argv[i + 1]
        i += 2
    role, node, out = opts["--role"], opts["--node"], opts["--out"]
    if role not in ROLES or not node or not out:
        die("sample needs --role server|worker, --node and --out")
    duration, interval = float(opts["--duration"]), float(opts["--interval"])
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "samples-%s.csv" % node)
    stopfile = os.path.join(out, "STOP")
    start = time.monotonic()
    spec = os.environ.get("B668_FAKE_TIMELINE")
    src = Fake(spec, start) if spec is not None else Live(role, node)
    stop = threading.Event()
    lock = threading.Lock()
    f = open(path, "w", newline="")
    w = csv.writer(f)
    w.writerow(FIELDS)
    f.flush()

    def loop(fn):
        due = time.monotonic()
        while not stop.is_set():
            t0 = int(time.time() * 1000)
            m0 = time.monotonic()
            try:
                results = fn()
            except Exception as e:  # a probe bug is a sample, never a dead thread
                results = [("error", False, one_line(e))]
            ms = int((time.monotonic() - m0) * 1000)
            with lock:
                for probe, ok, detail in results:
                    w.writerow([t0, role, node, probe, 1 if ok else 0, ms, detail])
                f.flush()
            due += interval
            now = time.monotonic()
            if due < now:
                due = now
            stop.wait(due - now)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    threads = [threading.Thread(target=loop, args=(g,), daemon=True) for g in src.groups()]
    for t in threads:
        t.start()
    while not stop.is_set():
        if time.monotonic() - start >= duration or os.path.exists(stopfile):
            stop.set()
        stop.wait(0.1)
    for t in threads:
        t.join(30)
    f.close()
    with open(os.path.join(out, "summary-%s.txt" % node), "w") as s:
        s.write(summarize_text(read([path])))
    print("update downtime: samples in %s" % path)


# ---- the windows ------------------------------------------------------------

def read(paths):
    rows = []
    for p in paths:
        try:
            f = open(p, newline="")
        except OSError as e:
            die("%s: %s" % (p, e.strerror or e), 1)
        with f:
            r = csv.DictReader(f)
            if r.fieldnames != FIELDS:
                die("%s: header is %s, want %s" % (p, r.fieldnames, FIELDS), 1)
            for row in r:
                row["t_ms"] = int(row["t_ms"])
                row["ok"] = row["ok"] == "1"
                rows.append(row)
    if not rows:
        die("no samples", 1)
    return rows


def order(key):
    role, node, probe = key
    return (ROLES.index(role) if role in ROLES else 9, node,
            PROBES.index(probe) if probe in PROBES else 9, probe)


def windows(rows):
    groups = {}
    for r in sorted(rows, key=lambda r: r["t_ms"]):
        groups.setdefault((r["role"], r["node"], r["probe"]), []).append(r)
    out = []
    for key in sorted(groups, key=order):
        g = groups[key]
        wins, cur = [], None
        for i, r in enumerate(g):
            if not r["ok"]:
                if cur is None:
                    cur = {"start": r["t_ms"], "began_down": i == 0, "n": 0, "reasons": []}
                cur["n"] += 1
                reason = r["detail"].split(" ")[0] if r["detail"].startswith("rc=") else r["detail"]
                if reason not in cur["reasons"]:
                    cur["reasons"].append(reason)
            elif cur is not None:
                cur["end"] = r["t_ms"]
                wins.append(cur)
                cur = None
        if cur is not None:
            cur["end"] = None
            cur["last"] = g[-1]["t_ms"]
            wins.append(cur)
        out.append((key, g, wins))
    return out


def phases(rows):
    seen = {}
    for r in sorted(rows, key=lambda r: r["t_ms"]):
        if r["probe"] != "node" or " phase=" not in r["detail"]:
            continue
        p = r["detail"].split(" phase=", 1)[1].strip()
        seq = seen.setdefault((r["role"], r["node"]), [])
        if p and (not seq or seq[-1][0] != p):
            seq.append((p, r["t_ms"]))
    return seen


def seconds(w):
    if w["end"] is None:
        return ">=%.3f" % ((w["last"] - w["start"]) / 1000.0)
    return "%.3f" % ((w["end"] - w["start"]) / 1000.0)


def summarize_windows(rows):
    t0 = min(r["t_ms"] for r in rows)
    lines = []
    for (role, node, probe), g, wins in windows(rows):
        head = "role=%s node=%s probe=%s" % (role, node, probe)
        if not wins:
            lines.append("%s no window (%d samples over %.3fs)" % (
                head, len(g), (g[-1]["t_ms"] - g[0]["t_ms"]) / 1000.0))
        for w in wins:
            lines.append("%s start=+%.3f end=%s seconds=%s down_samples=%d%s reasons=%s" % (
                head, (w["start"] - t0) / 1000.0,
                "open" if w["end"] is None else "+%.3f" % ((w["end"] - t0) / 1000.0),
                seconds(w), w["n"], " began_down" if w["began_down"] else "",
                "|".join(w["reasons"][:3])))
    for (role, node), seq in sorted(phases(rows).items(), key=lambda kv: order(kv[0] + ("",))):
        lines.append("phases role=%s node=%s: %s" % (role, node, " -> ".join(p for p, _ in seq) or "(none)"))
    return "\n".join(lines) + "\n"


def summarize_text(rows):
    t0 = min(r["t_ms"] for r in rows)
    t1 = max(r["t_ms"] for r in rows)
    out = ["unavailability windows, trace %s .. %s (%.1fs, %d samples)" % (
        utc(t0), utc(t1), (t1 - t0) / 1000.0, len(rows))]
    role_seen = None
    for (role, node, probe), g, wins in windows(rows):
        if role != role_seen:
            out.append("")
            out.append("%s (%s)" % (role, node))
            role_seen = role
        closed = [(w["end"] - w["start"]) / 1000.0 for w in wins if w["end"] is not None]
        if not wins:
            out.append("  %-7s up throughout (%d samples)" % (probe, len(g)))
            continue
        out.append("  %-7s %d window(s), longest %.1fs, total %.1fs%s" % (
            probe, len(wins), max(closed) if closed else 0.0, sum(closed),
            ", one still open at the end" if wins[-1]["end"] is None else ""))
        for w in wins:
            out.append("          %s .. %s  %ss  (%d failed samples: %s)" % (
                utc(w["start"]), "open" if w["end"] is None else utc(w["end"]),
                seconds(w), w["n"], "; ".join(w["reasons"][:3])))
    ph = phases(rows)
    if ph:
        out.append("")
        for (role, node), seq in sorted(ph.items(), key=lambda kv: order(kv[0] + ("",))):
            out.append("update phases on %s (%s): %s" % (node, role, " -> ".join(
                "%s@%s" % (p, utc(t)[11:23]) for p, t in seq) or "(none)"))
    return "\n".join(out) + "\n"


def main(argv):
    if not argv:
        die("usage: sample|summarize|check")
    cmd, rest = argv[0], argv[1:]
    if cmd == "check":
        return
    if cmd == "sample":
        return sample(rest)
    if cmd == "summarize":
        fmt = "text"
        if rest[:1] == ["--format"]:
            if len(rest) < 2 or rest[1] not in ("text", "windows"):
                die("summarize --format text|windows")
            fmt, rest = rest[1], rest[2:]
        if not rest:
            die("summarize needs at least one samples CSV")
        rows = read(rest)
        sys.stdout.write(summarize_windows(rows) if fmt == "windows" else summarize_text(rows))
        return
    die("unknown command %r" % cmd)


main(sys.argv[1:])
PY
)"

py() { python3 -I -c "$PY_PROG" "$@"; }

PASS=0
FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS + 1)); else echo "FAIL  $2"; FAIL=$((FAIL + 1)); fi; }

self_test() {
	local work rc
	work="$(mktemp -d "${TMPDIR:-/tmp}/b668.XXXXXX")"
	# shellcheck disable=SC2064 # expand $work now
	trap "rm -rf '$work'" EXIT
	echo "==> k3sm update downtime self-test (the unavailability-window measurer)"

	if bash -n "$SELF" && command -v python3 >/dev/null 2>&1 && py check; then
		ladder ok "b668.0  the script parses and its python program compiles"
	else
		ladder no "b668.0  the script parses and its python program compiles"
		return 1
	fi

	# b668.1-4: each fixed timeline's windows equal its .want, line for line.
	local n=1 fx name
	for name in server-roll worker-roll reinstall no-outage; do
		fx="$TESTDATA/$name.csv"
		if [ ! -f "$fx" ] || [ ! -f "$TESTDATA/$name.want" ]; then
			ladder no "b668.$n  fixture $name.csv and $name.want present"
		elif py summarize --format windows "$fx" >"$work/$name.got" 2>&1 &&
			diff -u "$TESTDATA/$name.want" "$work/$name.got" >"$work/$name.diff"; then
			ladder ok "b668.$n  $name: $(grep -c ' start=' "$work/$name.got" || true) window(s), equal to its .want"
		else
			sed 's/^/        /' "$work/$name.diff" "$work/$name.got" | head -40 || true
			ladder no "b668.$n  $name: windows differ from $name.want"
		fi
		n=$((n + 1))
	done

	# b668.5: the fixtures are not vacuous. The roll and reinstall wants hold
	# windows and the five node-side phases; no-outage holds none; one flipped
	# sample changes the answer.
	local nv=ok
	for name in server-roll worker-roll reinstall; do
		grep -q ' start=' "$TESTDATA/$name.want" 2>/dev/null || nv=no
	done
	[ -f "$TESTDATA/no-outage.want" ] || nv=no
	grep -q ' start=' "$TESTDATA/no-outage.want" 2>/dev/null && nv=no
	for name in server-roll worker-roll; do
		grep -q ': Downloading -> Verifying -> Installing -> Restarting -> Done$' "$TESTDATA/$name.want" 2>/dev/null || nv=no
	done
	awk -F, 'BEGIN{OFS=","} NR==40 && $5=="1" {$5="0"; flipped=1} {print} END{exit flipped?0:1}' \
		"$TESTDATA/no-outage.csv" >"$work/flipped.csv" 2>/dev/null || nv=no
	if py summarize --format windows "$work/flipped.csv" >"$work/flipped.got" 2>&1 &&
		! diff -q "$TESTDATA/no-outage.want" "$work/flipped.got" >/dev/null &&
		grep -q ' start=.* down_samples=1 ' "$work/flipped.got"; then :; else nv=no; fi
	ladder "$nv" "b668.5  fixtures are non-vacuous; one flipped sample opens a one-sample window"

	# b668.6: a malformed trace is refused, not summarized.
	printf 't,role\n1,server\n' >"$work/bad.csv"
	rc=0
	py summarize "$work/bad.csv" >/dev/null 2>&1 || rc=$?
	if [ "$rc" -eq 1 ]; then ladder ok "b668.6  a CSV with the wrong header is refused (exit 1)"; else ladder no "b668.6  wrong header exit $rc, want 1"; fi

	# b668.7: the sampler itself, driven by a fake timeline over 3.5 s at the
	# real 250 ms cadence. Each probe must show exactly one window whose length
	# is the timeline's within two cadences.
	rc=0
	B668_FAKE_TIMELINE="api=0.8-2.0,status=0.6-2.4,daemon=0.6-2.4,netd=0.5-1.0,node=1.0-2.8" \
		py sample --role server --node fake-server --out "$work/live" --duration 3.5 >"$work/sample.log" 2>&1 || rc=$?
	if [ "$rc" -eq 0 ] && py summarize --format windows "$work/live/samples-fake-server.csv" >"$work/live.got" 2>&1 &&
		[ -s "$work/live/summary-fake-server.txt" ] &&
		awk -v want="api=1.2 status=1.8 daemon=1.8 netd=0.5 node=1.8" '
			BEGIN { n = split(want, kv, " "); for (i = 1; i <= n; i++) { split(kv[i], q, "="); w[q[1]] = q[2] } }
			/ start=/ {
				split($3, pr, "="); probe = pr[2]
				for (i = 1; i <= NF; i++) if ($i ~ /^seconds=/) { split($i, s, "="); sec = s[2] }
				if (sec ~ /^>=/ || !(probe in w)) bad = 1
				d = sec - w[probe]; if (d < 0) d = -d
				if (d > 0.5) bad = 1
				seen[probe]++
			}
			END { for (k in w) if (seen[k] != 1) bad = 1; exit bad }' "$work/live.got"; then
		ladder ok "b668.7  the sampler over a fake timeline: one window per probe, each within 0.5s"
	else
		sed 's/^/        /' "$work/sample.log" "$work/live.got" 2>/dev/null | head -20 || true
		ladder no "b668.7  the sampler over a fake timeline (exit $rc)"
	fi

	echo "----------------------------------------"
	echo "update downtime self-test: $PASS passed, $FAIL failed"
	[ "$FAIL" -eq 0 ]
}

case "${1:-}" in
--self-test) self_test ;;
"")
	# Bare invocation (the release gate's CI tier): the self-test is the CI
	# tier; the sampling tier needs a rig node, so it is announced as owed.
	self_test || exit 1
	echo "LAB-PENDING  b668.L  sample and summarize need K3SM_LAB=1 on a rig node (see --help)"
	exit 3
	;;
sample)
	shift
	if [ "${K3SM_LAB:-}" != 1 ]; then
		echo "PENDING  sample needs K3SM_LAB=1 on a rig node (see --help)"
		exit 2
	fi
	py sample "$@"
	;;
summarize)
	shift
	py summarize "$@"
	;;
-h | --help)
	sed -n '2,/^set -euo pipefail$/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'
	;;
*)
	echo "usage: $SELF --self-test | sample ... | summarize ... | --help" >&2
	exit 2
	;;
esac
