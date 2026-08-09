#!/usr/bin/env bash
#
# k3sm B137 acceptance gate — the fully mocked end-to-end proof of the gen-1
# curl|sh installer (install.sh): download → sha256-verify → sudo k3sm install,
# with every external seam substituted (loopback HTTP release server; PATH stubs
# for sudo/uname/sw_vers/sysctl; a stub k3sm that logs its argv). The gate's
# verdict is a function of the tree, never of the host OS or the network.
#
# Unit-tier by construction: the HTTP server binds 127.0.0.1:0 only (hermetic,
# no external egress), no real privilege is exercised (sudo is a PATH stub),
# and fixtures are built from scratch per run. shellcheck is HARD-REQUIRED —
# a missing tool is a FAIL (brew install shellcheck), never a silent skip.
#
# Usage: hack/acceptance/B137.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/install.sh"
CONFIG="$REPO_ROOT/.goreleaser.yaml"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B137 acceptance (gen-1 curl|sh installer, fully mocked e2e)"

# ---- static checks ----------------------------------------------------------

# b137.0 — the script exists and parses.
if [ -f "$SCRIPT" ] && sh -n "$SCRIPT"; then
	ladder ok "b137.0  install.sh present + parses (sh -n)"
else
	ladder no "b137.0  install.sh present + parses (sh -n)"
	echo "----------------------------------------"
	echo "B137: install.sh missing or unparseable — nothing else can run" >&2
	echo "B137: $PASS passed, $((FAIL)) failed" >&2
	exit 1
fi

# b137.1 — shellcheck-clean. Tool absence is a HARD FAIL (no fail-open skip).
if ! command -v shellcheck >/dev/null 2>&1; then
	ladder no "b137.1  shellcheck clean (shellcheck NOT INSTALLED — brew install shellcheck)"
elif shellcheck -s sh "$SCRIPT"; then
	ladder ok "b137.1  shellcheck -s sh clean"
else
	ladder no "b137.1  shellcheck -s sh clean"
fi

# b137.2 — the truncation invariant, structurally: the last non-blank,
# non-comment line is exactly `main "$@"`. A curl|sh stream cut anywhere
# before the end then executes nothing.
last_code_line="$(grep -Ev '^[[:space:]]*(#|$)' "$SCRIPT" | tail -1)"
if [ "$last_code_line" = 'main "$@"' ]; then
	ladder ok "b137.2  last code line is exactly: main \"\$@\""
else
	ladder no "b137.2  last code line is exactly: main \"\$@\" (got: $last_code_line)"
fi

# b137.3 — asset-name cross-check: the goreleaser templates are a frozen public
# contract (m7-plan Res. 21). If either template changes, this goes red instead
# of every future release silently 404ing for the live script.
if grep -qF 'name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"' "$CONFIG" \
	&& grep -qF 'name_template: "{{ .ProjectName }}_{{ .Version }}_checksums.txt"' "$CONFIG" \
	&& grep -qF 'ARCHIVE="k3sm_${VERSION}_darwin_arm64.tar.gz"' "$SCRIPT" \
	&& grep -qF 'CHECKSUMS="k3sm_${VERSION}_checksums.txt"' "$SCRIPT"; then
	ladder ok "b137.3  asset names match the .goreleaser.yaml templates (frozen contract)"
else
	ladder no "b137.3  asset names match the .goreleaser.yaml templates (frozen contract)"
fi

# ---- python3 presence (the mock server needs it) ----------------------------
if ! command -v python3 >/dev/null 2>&1; then
	echo "FAIL  b137  python3 not found — the loopback mock server requires it" >&2
	exit 1
fi

# ---- fixtures ---------------------------------------------------------------
WORK="$(mktemp -d /tmp/b137.XXXXXX)"
SERVER_PIDS=()
cleanup() {
	for p in "${SERVER_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

FIXROOT="$WORK/fixtures"
mk_release() { # <version-without-v> <checksum-mode: good|corrupt|missing-entry>
	local ver="$1" mode="$2"
	local dir="$FIXROOT/releases/download/v$ver" stagedir
	mkdir -p "$dir"
	stagedir="$WORK/stage-$ver"
	mkdir -p "$stagedir"
	cat >"$stagedir/k3sm" <<'STUB'
#!/bin/sh
printf 'k3sm %s\n' "$*" >>"${K3SM_STUB_LOG:?}"
STUB
	chmod +x "$stagedir/k3sm"
	cp "$stagedir/k3sm" "$stagedir/k3sm-netd"
	touch "$stagedir/LICENSE" "$stagedir/NOTICE"
	tar -czf "$dir/k3sm_${ver}_darwin_arm64.tar.gz" -C "$stagedir" k3sm k3sm-netd LICENSE NOTICE
	(cd "$dir" && shasum -a 256 "k3sm_${ver}_darwin_arm64.tar.gz" >"k3sm_${ver}_checksums.txt")
	case "$mode" in
	good) ;;
	corrupt) # flip the hash to all-zeros — valid format, wrong digest
		awk '{ printf "%064d  %s\n", 0, $2 }' "$dir/k3sm_${ver}_checksums.txt" >"$dir/tmp" \
			&& mv "$dir/tmp" "$dir/k3sm_${ver}_checksums.txt" ;;
	missing-entry) # a checksums file that names a DIFFERENT asset only
		awk '{ printf "%s  some_other_asset.tar.gz\n", $1 }' "$dir/k3sm_${ver}_checksums.txt" >"$dir/tmp" \
			&& mv "$dir/tmp" "$dir/k3sm_${ver}_checksums.txt" ;;
	esac
}
mk_release 9.9.9 good
mk_release 6.6.6 corrupt
mk_release 5.5.5 missing-entry

# ---- the loopback mock release server ---------------------------------------
cat >"$WORK/server.py" <<'PY'
import http.server, os, socketserver, sys

ROOT = sys.argv[1]
MODE = sys.argv[2]  # "ok" | "zerorelease"

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _route(self, send_body):
        p = self.path
        if p == "/releases/latest":
            target = "/releases/tag/v9.9.9" if MODE == "ok" else "/releases"
            self.send_response(302); self.send_header("Location", target); self.end_headers()
            return
        if p in ("/releases", "/releases/tag/v9.9.9"):
            body = b"releases page\n"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            if send_body: self.wfile.write(body)
            return
        if p.startswith("/releases/download/"):
            f = os.path.join(ROOT, p.lstrip("/"))
            if os.path.isfile(f):
                data = open(f, "rb").read()
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers()
                if send_body: self.wfile.write(data)
                return
        self.send_response(404); self.end_headers()
    def do_GET(self):  self._route(True)
    def do_HEAD(self): self._route(False)

with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
    print(srv.server_address[1], flush=True)  # ready-handshake: port on stdout
    srv.serve_forever()
PY

start_server() { # <mode> — echoes the port
	local portfile="$WORK/port-$1"
	python3 "$WORK/server.py" "$FIXROOT" "$1" >"$portfile" &
	SERVER_PIDS+=($!)
	local i=0
	while [ ! -s "$portfile" ]; do
		i=$((i + 1))
		[ "$i" -le 100 ] || { echo "mock server ($1) never printed its port" >&2; exit 1; }
		sleep 0.05
	done
	cat "$portfile"
}
PORT_OK="$(start_server ok)"
PORT_ZERO="$(start_server zerorelease)"
BASE_OK="http://127.0.0.1:$PORT_OK/releases"
BASE_ZERO="http://127.0.0.1:$PORT_ZERO/releases"

# ---- PATH stubs (uniform: sudo, uname, sw_vers, sysctl) ---------------------
STUBS="$WORK/stubs"
mkdir -p "$STUBS"
cat >"$STUBS/sudo" <<'STUB'
#!/bin/bash
printf 'sudo %s\n' "$*" >>"${SUDO_LOG:?}"
if [ "${1:-}" = "-n" ]; then exit "${SUDO_N_EXIT:-0}"; fi
exec "$@"
STUB
cat >"$STUBS/uname" <<'STUB'
#!/bin/bash
echo "${STUB_UNAME_S:-Darwin}"
STUB
cat >"$STUBS/sw_vers" <<'STUB'
#!/bin/bash
echo "${STUB_SWVERS:-26.1}"
STUB
cat >"$STUBS/sysctl" <<'STUB'
#!/bin/bash
case "${STUB_SYSCTL_MODE:-arm}" in
arm) echo 1 ;;
zero) echo 0 ;;
missing) exit 1 ;;  # Intel shape: key absent — no output, non-zero
esac
STUB
chmod +x "$STUBS"/*

# ---- the case runner --------------------------------------------------------
# Each case: fresh scratch cwd + pinned TMPDIR; the script is fed as a REAL
# pipe (cat | sh). SUDO_LOG points at the same output file the script's stdout
# appends to, so banner-vs-sudo ORDER is directly observable in one stream.
CASE_RC=0
run_case() { # <name> [ENV=VAL ...]
	local name="$1"; shift
	CASE_DIR="$WORK/case-$name"
	CASE_TMP="$CASE_DIR/tmp"
	OUT="$CASE_DIR/out.log"
	KLOG="$CASE_DIR/k3sm-stub.log"
	mkdir -p "$CASE_DIR" "$CASE_TMP"
	: >"$OUT"; : >"$KLOG"
	set +e
	(cd "$CASE_DIR" && cat "$SCRIPT" | env \
		PATH="$STUBS:$PATH" TMPDIR="$CASE_TMP" \
		SUDO_LOG="$OUT" K3SM_STUB_LOG="$KLOG" \
		"$@" sh >>"$OUT" 2>&1)
	CASE_RC=$?
	set -e
}
has()        { grep -qF "$1" "$OUT"; }
sudo_ran()   { grep -qE '^sudo .*k3sm install$' "$OUT"; }
k3sm_ran()   { grep -qE '^k3sm install$' "$KLOG"; }
no_exec()    { ! grep -qE '^sudo ' "$OUT" && [ ! -s "$KLOG" ]; }
staging_gone() { ! find "$CASE_TMP" -mindepth 1 -maxdepth 1 -name 'k3sm-install.*' 2>/dev/null | grep -q .; }
banner_before_sudo() {
	local b s
	b="$(grep -nF 'about to run: sudo' "$OUT" | head -1 | cut -d: -f1)"
	s="$(grep -nE '^sudo ' "$OUT" | head -1 | cut -d: -f1)"
	[ -n "$b" ] && [ -n "$s" ] && [ "$b" -lt "$s" ]
}

# T1 — happy path, pinned version.
run_case t1 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v9.9.9
if [ "$CASE_RC" -eq 0 ] && sudo_ran && k3sm_ran && banner_before_sudo && staging_gone; then
	ladder ok "b137.T1  happy pinned: exit 0, banner→sudo→k3sm install, staging cleaned"
else
	ladder no "b137.T1  happy pinned: exit 0, banner→sudo→k3sm install, staging cleaned (rc=$CASE_RC)"
fi

# T2 — happy path via the releases/latest 302.
run_case t2 K3SM_INSTALL_BASE_URL="$BASE_OK"
if [ "$CASE_RC" -eq 0 ] && sudo_ran && k3sm_ran && has 'v9.9.9'; then
	ladder ok "b137.T2  happy latest: 302 resolves v9.9.9, install runs"
else
	ladder no "b137.T2  happy latest: 302 resolves v9.9.9, install runs (rc=$CASE_RC)"
fi

# T3 — corrupted checksum: abort, NOTHING executes.
run_case t3 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v6.6.6
if [ "$CASE_RC" -ne 0 ] && has 'sha256 verification FAILED' && no_exec; then
	ladder ok "b137.T3  corrupted checksum: non-zero, nothing executed"
else
	ladder no "b137.T3  corrupted checksum: non-zero, nothing executed (rc=$CASE_RC)"
fi

# T4 — wrong arch (sysctl says 0) and Intel shape (key missing): fail closed.
run_case t4a K3SM_INSTALL_BASE_URL="$BASE_OK" STUB_SYSCTL_MODE=zero
rc_a=$CASE_RC; msg_a=false; has 'Apple silicon' && msg_a=true
run_case t4b K3SM_INSTALL_BASE_URL="$BASE_OK" STUB_SYSCTL_MODE=missing
if [ "$rc_a" -ne 0 ] && $msg_a && [ "$CASE_RC" -ne 0 ] && has 'Apple silicon'; then
	ladder ok "b137.T4  non-arm64: sysctl=0 AND missing-key both fail closed"
else
	ladder no "b137.T4  non-arm64: sysctl=0 AND missing-key both fail closed"
fi

# T5 — non-Darwin.
run_case t5 K3SM_INSTALL_BASE_URL="$BASE_OK" STUB_UNAME_S=Linux
if [ "$CASE_RC" -ne 0 ] && has 'macOS-only'; then
	ladder ok "b137.T5  non-Darwin uname aborts"
else
	ladder no "b137.T5  non-Darwin uname aborts (rc=$CASE_RC)"
fi

# T6 — macOS too old.
run_case t6 K3SM_INSTALL_BASE_URL="$BASE_OK" STUB_SWVERS=15.6
if [ "$CASE_RC" -ne 0 ] && has 'macOS 26 or newer'; then
	ladder ok "b137.T6  macOS < 26 aborts"
else
	ladder no "b137.T6  macOS < 26 aborts (rc=$CASE_RC)"
fi

# T7 — non-tty + no cached sudo creds: abort naming the download-only escape.
# Detached from the controlling tty via os.setsid (macOS ships no setsid(1)).
t7_dir="$WORK/case-t7"; mkdir -p "$t7_dir/tmp"
t7_out="$t7_dir/out.log"; t7_klog="$t7_dir/k3sm-stub.log"
: >"$t7_out"; : >"$t7_klog"
set +e
(cd "$t7_dir" && env \
	PATH="$STUBS:$PATH" TMPDIR="$t7_dir/tmp" \
	SUDO_LOG="$t7_out" K3SM_STUB_LOG="$t7_klog" SUDO_N_EXIT=1 \
	K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v9.9.9 \
	python3 -c 'import os,subprocess,sys
p=subprocess.run(["sh"],stdin=open(sys.argv[1],"rb"),stdout=open(sys.argv[2],"ab"),stderr=subprocess.STDOUT,preexec_fn=os.setsid)
sys.exit(p.returncode)' "$SCRIPT" "$t7_out")
t7_rc=$?
set -e
if [ "$t7_rc" -ne 0 ] && grep -qF 'K3SM_INSTALL_DOWNLOAD_ONLY=1' "$t7_out" && [ ! -s "$t7_klog" ]; then
	ladder ok "b137.T7  non-tty + no cached creds: abort names the download-only escape"
else
	ladder no "b137.T7  non-tty + no cached creds: abort names the download-only escape (rc=$t7_rc)"
fi

# T8 — download-only: verified artifacts land in the cwd, sudo never runs.
run_case t8 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v9.9.9 K3SM_INSTALL_DOWNLOAD_ONLY=1
if [ "$CASE_RC" -eq 0 ] && [ -f "$CASE_DIR/k3sm_9.9.9_darwin_arm64.tar.gz" ] \
	&& [ -f "$CASE_DIR/k3sm_9.9.9_checksums.txt" ] && no_exec; then
	ladder ok "b137.T8  download-only: artifacts in cwd, no sudo"
else
	ladder no "b137.T8  download-only: artifacts in cwd, no sudo (rc=$CASE_RC)"
fi

# T9 — zero-release latest shape (the exact state the live channel ships into).
run_case t9 K3SM_INSTALL_BASE_URL="$BASE_ZERO"
if [ "$CASE_RC" -ne 0 ] && has 'published yet' && no_exec; then
	ladder ok "b137.T9  zero-release latest: friendly 'published yet?' abort"
else
	ladder no "b137.T9  zero-release latest: friendly 'published yet?' abort (rc=$CASE_RC)"
fi

# T10 — pinned version that does not exist: friendly 404 message.
run_case t10 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v0.0.404
if [ "$CASE_RC" -ne 0 ] && has 'published yet' && no_exec; then
	ladder ok "b137.T10 pinned 404: friendly 'published yet?' abort"
else
	ladder no "b137.T10 pinned 404: friendly 'published yet?' abort (rc=$CASE_RC)"
fi

# T11 — checksums file lacks the archive's entry: abort BEFORE shasum.
run_case t11 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v5.5.5
if [ "$CASE_RC" -ne 0 ] && has 'no entry for' && no_exec; then
	ladder ok "b137.T11 missing checksum entry: hard-fail before shasum, nothing executed"
else
	ladder no "b137.T11 missing checksum entry: hard-fail before shasum, nothing executed (rc=$CASE_RC)"
fi

# T12 — truncated stream executes nothing (last line dropped + mid-file cut).
t12_ok=true
total="$(wc -l <"$SCRIPT")"
for n in $((total - 1)) $((total / 2)); do
	t12_dir="$WORK/case-t12-$n"; mkdir -p "$t12_dir/tmp"
	t12_out="$t12_dir/out.log"; t12_klog="$t12_dir/k3sm-stub.log"
	: >"$t12_out"; : >"$t12_klog"
	set +e
	(cd "$t12_dir" && head -"$n" "$SCRIPT" | env \
		PATH="$STUBS:$PATH" TMPDIR="$t12_dir/tmp" \
		SUDO_LOG="$t12_out" K3SM_STUB_LOG="$t12_klog" \
		K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v9.9.9 \
		sh >>"$t12_out" 2>&1)
	set -e
	if grep -qE '^sudo ' "$t12_out" || [ -s "$t12_klog" ] \
		|| grep -qF '[k3sm-install]' "$t12_out"; then
		t12_ok=false
	fi
done
if $t12_ok; then
	ladder ok "b137.T12 truncated stream (last-line + mid-file cuts): zero side effects"
else
	ladder no "b137.T12 truncated stream (last-line + mid-file cuts): zero side effects"
fi

# T13 — version normalization: the unprefixed form resolves the v-tag + assets.
run_case t13 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=9.9.9
if [ "$CASE_RC" -eq 0 ] && sudo_ran && k3sm_ran && has 'k3sm_9.9.9_darwin_arm64.tar.gz'; then
	ladder ok "b137.T13 unprefixed version normalizes to the v-tag and installs"
else
	ladder no "b137.T13 unprefixed version normalizes to the v-tag and installs (rc=$CASE_RC)"
fi

# T14 — cached sudo timestamp (sudo -n succeeds): the banner STILL precedes
# the first sudo invocation — consent never depends on the password prompt.
run_case t14 K3SM_INSTALL_BASE_URL="$BASE_OK" K3SM_INSTALL_VERSION=v9.9.9 SUDO_N_EXIT=0
if [ "$CASE_RC" -eq 0 ] && banner_before_sudo && sudo_ran; then
	ladder ok "b137.T14 cached-sudo path: pre-escalation banner precedes every sudo line"
else
	ladder no "b137.T14 cached-sudo path: pre-escalation banner precedes every sudo line (rc=$CASE_RC)"
fi

echo "----------------------------------------"
echo "B137: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B137 GREEN ================"
