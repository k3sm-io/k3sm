#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# llama.cpp on the GPU sandbox profile: the removal and addition measurement.
#
# Builds one pinned llama-server, then runs it under variants of the profile a
# GPU pod is given, on a Mac with an Apple GPU, and records what each variant
# breaks. It is a measurement: the recorded results are in
# hack/spike/m25/findings-l1.md, and this script reproduces the part of them
# that does not need a cluster.
#
# Usage:
#   hack/acceptance/llamacpp-measure.sh --measure     run (needs K3SM_LAB=1)
#   hack/acceptance/llamacpp-measure.sh --self-test   the pure parts, anywhere
#
# Without K3SM_LAB=1, --measure prints "SKIP: llamacpp-measure" and exits 0:
# it builds a C++ tree, downloads a model and starts a GPU process.
#
# Environment for --measure:
#   K3SM_LAB=1               required
#   K3SM_LLAMA_WORKDIR       required: an empty or reused directory for the
#                            source, the build, the model, the variants and the
#                            logs. The profile must allow reading and writing it,
#                            and the run-as user must be able to traverse it.
#   K3SM_LLAMA_PROFILE       required: the sandbox profile a GPU pod is rendered
#                            with, as text, whose writable paths include the
#                            work directory. Its GPU stanza (the ";; gpu:" comment
#                            through the IOSurfaceRootUserClient line) must equal
#                            the shipped one byte for byte; if it does not, the
#                            script stops before running anything. Only that
#                            stanza is compared, not the rest of the profile.
#   K3SM_LLAMA_RUN_AS        optional: a user to run the engine as, through
#                            sudo -n -u. Default: the current user.
#   K3SM_LLAMA_ENGINE_ENV    optional: extra NAME=value words for the engine's
#                            environment (the pod environment the profile was
#                            rendered for, such as a path-rebasing preload).
#   K3SM_LLAMA_GGUF          optional: a local copy of the pinned GGUF, used
#                            instead of a download. It is verified either way.
#   K3SM_LLAMA_JOBS          optional: build parallelism. Default 8.
#
# Environment differs from the recorded run: the recorded Q1 and Q2 runs also
# injected the pod's two DYLD shims (path rebasing, getaddrinfo) and set the
# K3SM_* variables and the semaphore prefix. This script launches the engine
# with only HOME, TMPDIR, PATH and K3SM_LLAMA_ENGINE_ENV, so it reproduces Q1
# and Q2 under a different environment; supply the shims and variables through
# K3SM_LLAMA_ENGINE_ENV to match. The plus-shadercache variants write to the
# run-as user's per-user Metal cache (DARWIN_USER_CACHE_DIR), outside the work
# directory; the script removes only what it finds new there after those two
# runs and leaves anything that existed before.
#
# The source commit and the GGUF digest are pinned below. Neither is read from
# the environment, and the run stops if either does not verify.
#
# Exit: 0 when the pins verify, the profile carries the shipped grant and the
# unmodified profile serves a completion with every layer on the GPU; 1 on a
# failed pin or a failed baseline; 2 for a usage error. The variant results are
# printed as "finding:" lines and are not asserted: they are what is measured.
#
# What this does not reproduce: see the end of findings-l1.md. In short, the
# pod-level memory limits, the confined build on a pod, the idle denials of a
# real pod, the Go verifier against the Hub, and the -hf download path.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
M25="$(cd "$HERE/../spike/m25" && pwd)"

# Pins. The tag is for the reader; the commit is what is fetched and checked.
PIN_TAG=b11829
PIN_COMMIT=184f6536024668e8908ab8c86033d56708e62b40
PIN_URL=https://github.com/ggml-org/llama.cpp.git
GGUF_REPO=unsloth/Qwen3-0.6B-GGUF
GGUF_REV=50968a4468ef4233ed78cd7c3de230dd1d61a56b
GGUF_FILE=Qwen3-0.6B-Q4_K_M.gguf
GGUF_BYTES=396705472
GGUF_SHA256=ac2d97712095a558e31573f62f466a3f9d93990898b0ec79d7c974c1780d524a

# The shipped grant, as the profile writes it.
IOKIT_BLOCK='(allow iokit-open
  (iokit-registry-entry-class "AGXDeviceUserClient")
  (iokit-registry-entry-class "IOSurfaceRootUserClient"))'

# The shipped GPU stanza as the profile writes it, comment block included. It
# is the text the golden pod profile carries; only this stanza is compared, the
# rest of a pod profile differs per node and per pod.
GPU_STANZA=";; gpu: Metal device access (allow_gpu) $(printf '\342\200\224') the two exact IOKit
;; user-client classes a Metal device open requires. Family-independent
;; and lab-derived by ablation; no mach-lookup, no iokit-get-properties,
;; no CVMS read, and NO shader-cache write are needed or granted.
(allow iokit-open
  (iokit-registry-entry-class \"AGXDeviceUserClient\")
  (iokit-registry-entry-class \"IOSurfaceRootUserClient\"))"

die() { echo "llamacpp-measure: FAIL: $*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }

# ---- pure parts (exercised by --self-test) ---------------------------------

# gpu_stanza FILE: the lines from the ";; gpu:" comment through the first
# IOSurfaceRootUserClient line, or nothing when there is no such comment.
gpu_stanza() {
	awk '/^;; gpu:/ {f=1} f {print} f && /IOSurfaceRootUserClient/ {exit}' "$1"
}

# verify_sha FILE WANT: succeeds only when FILE's SHA-256 is WANT.
verify_sha() {
	local got
	got="$(shasum -a 256 "$1" | awk '{print $1}')"
	[ "$got" = "$2" ]
}

# peak_footprint CSV: the largest footprint_mib column, one decimal.
peak_footprint() {
	awk -F, 'NR>1 && $2+0>m {m=$2+0} END {printf "%.1f\n", m}' "$1"
}

# summarize_denials PID: reads log lines on stdin, keeps the ones for PID
# (sandbox reports and launchd lookups) and prints "count what", most frequent
# first.
summarize_denials() {
	local pid="$1"
	grep -E "Sandbox: [^ ]*\(${pid}\) deny|requestor = [^ ]*\[${pid}\]" |
		sed -nE 's/.*deny\(1\) (.*)/sandbox deny(1) \1/p; s/.*denied lookup: name = ([^,]*),.*/launchd denied lookup \1/p' |
		sort | uniq -c | sort -rn || true
}

# offloaded LOG: the "N/N" of the engine's offload line, or "none".
offloaded() {
	sed -nE 's/.*offloaded ([0-9]+\/[0-9]+) layers to GPU.*/\1/p' "$1" | tail -1 | grep . || echo none
}

self_test() {
	local t
	t="$(mktemp -d)"
	trap 'rm -rf "$t"' RETURN
	python3 -I "$M25/variant.py" --self-test

	printf 'abc' >"$t/f"
	verify_sha "$t/f" ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad || die "self-test: a correct digest was refused"
	verify_sha "$t/f" "$GGUF_SHA256" && die "self-test: a wrong digest was accepted"

	printf '(version 1)\n%s\n(deny default)\n' "$GPU_STANZA" >"$t/p.sb"
	[ "$(gpu_stanza "$t/p.sb")" = "$GPU_STANZA" ] || die "self-test: gpu_stanza did not return the stanza"
	sed 's/AGXDeviceUserClient/AGXOther/' "$t/p.sb" >"$t/q.sb"
	[ "$(gpu_stanza "$t/q.sb")" != "$GPU_STANZA" ] || die "self-test: an altered stanza compared equal"
	[ -z "$(gpu_stanza "$t/f")" ] || die "self-test: a file with no stanza returned one"

	printf 't_ms,footprint_mib,resident_mib\n0,519.6,945.2\n100,522.1,947.9\n200,521.0,947.0\n' >"$t/c.csv"
	[ "$(peak_footprint "$t/c.csv")" = 522.1 ] || die "self-test: peak_footprint"

	cat >"$t/log" <<'LOG'
2026-11-06 01:28:33.766 E  sandboxd[66414:16eaaf88] [com.apple.sandbox.reporting:violation] Sandbox: llama-server(40163) deny(1) mach-lookup com.apple.CoreServices.coreservicesd
2026-11-06 01:28:33.767 E  sandboxd[66414:16eaaf88] [com.apple.sandbox.reporting:violation] Sandbox: llama-server(40163) deny(1) mach-lookup com.apple.CoreServices.coreservicesd
2026-11-06 01:28:33.768 E  sandboxd[66414:16eaaf88] [com.apple.sandbox.reporting:violation] Sandbox: llama-server(99999) deny(1) mach-lookup com.apple.other
2026-11-06 01:26:53.118 Df launchd[1:16eb61fc] [gui/501 [100016]:] denied lookup: name = com.apple.tccd.system, flags = 0x9, requestor = llama-server[40163], error = 159: Sandbox restriction
LOG
	summarize_denials 40163 <"$t/log" >"$t/out"
	grep -q '^ *2 sandbox deny(1) mach-lookup com.apple.CoreServices.coreservicesd$' "$t/out" || die "self-test: denial count"
	grep -q '^ *1 launchd denied lookup com.apple.tccd.system$' "$t/out" || die "self-test: launchd lookup"
	grep -q 'other' "$t/out" && die "self-test: another pid's denial leaked in"
	[ -z "$(summarize_denials 1 <"$t/log")" ] || die "self-test: a pid with no denials printed something"

	printf '0.05.287.364 I load_tensors: offloaded 29/29 layers to GPU\n' >"$t/e"
	[ "$(offloaded "$t/e")" = 29/29 ] || die "self-test: offloaded"
	printf 'nothing\n' >"$t/e"
	[ "$(offloaded "$t/e")" = none ] || die "self-test: offloaded none"

	case "$PIN_COMMIT" in *[!0-9a-f]* | "") die "self-test: PIN_COMMIT is not hex" ;; esac
	[ "${#PIN_COMMIT}" = 40 ] || die "self-test: PIN_COMMIT is not 40 characters"
	[ "${#GGUF_SHA256}" = 64 ] || die "self-test: GGUF_SHA256 is not 64 characters"
	[ "${#GGUF_REV}" = 40 ] || die "self-test: GGUF_REV is not 40 characters"

	local out rc=0
	out="$(env -u K3SM_LAB bash "$0" --measure)" || rc=$?
	[ "$rc" = 0 ] && [ "$out" = "SKIP: llamacpp-measure needs K3SM_LAB=1 (a Mac with an Apple GPU)" ] ||
		die "self-test: --measure without K3SM_LAB=1 did not skip by name (rc=$rc, out=$out)"
	echo "llamacpp-measure: self-test ok"
}

# ---- the measurement ---------------------------------------------------------

as_user() { # run a command as K3SM_LLAMA_RUN_AS when set
	if [ -n "${K3SM_LLAMA_RUN_AS:-}" ]; then sudo -n -u "$K3SM_LLAMA_RUN_AS" "$@"; else "$@"; fi
}
as_root() { if [ -n "${K3SM_LLAMA_RUN_AS:-}" ]; then sudo -n "$@"; else "$@"; fi; }

pin_source() {
	note "source: $PIN_TAG at $PIN_COMMIT"
	local tagged
	tagged="$(git ls-remote "$PIN_URL" "refs/tags/$PIN_TAG" | awk '{print $1}')"
	[ "$tagged" = "$PIN_COMMIT" ] || die "tag $PIN_TAG resolves to '$tagged', not the pinned commit"
	mkdir -p "$SRC"
	git -C "$SRC" init -q
	git -C "$SRC" config core.hooksPath /dev/null
	git -C "$SRC" fetch -q --depth 1 "$PIN_URL" "$PIN_COMMIT"
	git -C "$SRC" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
	[ "$(git -C "$SRC" rev-parse HEAD)" = "$PIN_COMMIT" ] || die "fetched HEAD is not the pinned commit"
	# Refuses a gitlink, a nested .git, a non-empty .gitmodules, a device or a case-fold pair.
	python3 -I "$M25/source_digest.py" "$SRC" | tee "$LOGS/source-digest.txt"
}

build() {
	note "build: Release, Metal with the embedded library, no dynamic backends, no TLS, no downloads"
	local opts=(-DCMAKE_BUILD_TYPE=Release -DGGML_METAL=ON -DGGML_METAL_EMBED_LIBRARY=ON
		-DBUILD_SHARED_LIBS=OFF -DGGML_BACKEND_DL=OFF -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF
		-DLLAMA_OPENSSL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF
		-DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON
		-DCMAKE_OSX_DEPLOYMENT_TARGET=26.0)
	printf '%s\n' "${opts[@]}" >"$LOGS/cmake-options.txt"
	cmake -S "$SRC" -B "$BUILD" "${opts[@]}" --trace-format=json-v1 --trace-expand \
		--trace-redirect="$LOGS/configure-trace.jsonl" >"$LOGS/configure.log" 2>&1 || die "configure failed (see $LOGS/configure.log)"
	[ ! -d "$BUILD/_deps" ] || die "the configure fetched dependencies into _deps"
	# A configure-time download shows as a file() command whose first argument is DOWNLOAD.
	python3 -I - "$LOGS/configure-trace.jsonl" <<'PY' || die "the configure trace holds a file(DOWNLOAD)"
import json, sys
for line in open(sys.argv[1], errors="replace"):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    a = d.get("args") or []
    if str(d.get("cmd", "")).lower() == "file" and a and a[0] in ("DOWNLOAD", "UPLOAD"):
        sys.exit(1)
PY
	cmake --build "$BUILD" --target llama-server -j "${K3SM_LLAMA_JOBS:-8}" >"$LOGS/build.log" 2>&1 || die "build failed (see $LOGS/build.log)"
	cp "$BUILD/bin/llama-server" "$BIN"
	chmod 0755 "$BIN"
	echo "finding: binary sha256 $(shasum -a 256 "$BIN" | awk '{print $1}') (builds are not byte-reproducible across paths)"
	echo "finding: linked libraries: $(otool -L "$BIN" | tail -n +2 | awk '{print $1}' | tr '\n' ' ')"
	echo "finding: entitlements: $(codesign -d --entitlements - "$BIN" 2>&1 | grep -c '<key>' || true) keys"
}

fetch_gguf() {
	note "model: $GGUF_REPO @ $GGUF_REV / $GGUF_FILE"
	if [ -n "${K3SM_LLAMA_GGUF:-}" ]; then
		cp "$K3SM_LLAMA_GGUF" "$MODEL.part"
	else
		curl -fsSL --proto '=https' --tlsv1.2 -o "$MODEL.part" \
			"https://huggingface.co/$GGUF_REPO/resolve/$GGUF_REV/$GGUF_FILE"
	fi
	[ "$(wc -c <"$MODEL.part" | tr -d ' ')" = "$GGUF_BYTES" ] || { rm -f "$MODEL.part"; die "the GGUF is not $GGUF_BYTES bytes"; }
	verify_sha "$MODEL.part" "$GGUF_SHA256" || { rm -f "$MODEL.part"; die "the GGUF digest does not match the pinned $GGUF_SHA256"; }
	mv "$MODEL.part" "$MODEL"
	chmod 0644 "$MODEL"
}

variant() { # variant NAME [variant.py args...]: writes the profile, prints its path; returns 1 if a removal matched nothing
	local p="$WORKDIR/variants/$1.sb"
	shift
	python3 -I "$M25/variant.py" "$PROFILE" "$p" "$@" || return 1
	chmod 0644 "$p"
	echo "$p"
}

launch() { # launch NAME PROFILE PORT engine-args...; sets PID and START
	local name="$1" prof="$2" port="$3"
	shift 3
	START="$(date +"%Y-%m-%d %H:%M:%S")"
	sleep 1
	# shellcheck disable=SC2086,SC2016 # ENGINE_ENV is NAME=value words; $1 and $@ expand in the inner shell
	as_user /bin/sh -c 'cd "$1" && echo "PID=$$" && shift && exec "$@"' sh "$WORKDIR" \
		/usr/bin/sandbox-exec -f "$prof" /usr/bin/env -i HOME="$WORKDIR" TMPDIR="$WORKDIR/tmp" \
		PATH=/usr/bin:/bin ${K3SM_LLAMA_ENGINE_ENV:-} \
		"$BIN" --host 127.0.0.1 --port "$port" "$@" >"$LOGS/$name.engine.log" 2>&1 </dev/null &
	PID=""
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		PID="$(sed -n 's/^PID=//p' "$LOGS/$name.engine.log" | head -1)"
		[ -n "$PID" ] && break
		sleep 0.2
	done
	[ -n "$PID" ] || die "$name: the engine did not start"
}

stop_engine() {
	[ -n "${PID:-}" ] || return 0
	as_root kill "$PID" 2>/dev/null || true
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$PID" 2>/dev/null || as_root kill -0 "$PID" 2>/dev/null || return 0
		sleep 0.5
	done
	as_root kill -9 "$PID" 2>/dev/null || true
}

denials() { # denials NAME: the denials for the engine just run, written beside its log
	sleep 2
	/usr/bin/log show --style compact --start "$START" \
		--predicate 'eventMessage CONTAINS "deny(" OR eventMessage CONTAINS "denied lookup"' 2>/dev/null |
		summarize_denials "$PID" >"$LOGS/$1.denials.txt"
	echo "finding: [$1] denials: $(wc -l <"$LOGS/$1.denials.txt" | tr -d ' ') distinct"
	sed 's/^/           /' "$LOGS/$1.denials.txt"
}

list_devices() { # list_devices NAME PROFILE
	local rc=0
	# shellcheck disable=SC2016 # $1 and $@ expand in the inner shell
	as_user /bin/sh -c 'cd "$1" && shift && exec "$@"' sh "$WORKDIR" /usr/bin/sandbox-exec -f "$2" \
		/usr/bin/env -i HOME="$WORKDIR" TMPDIR="$WORKDIR/tmp" PATH=/usr/bin:/bin \
		"$BIN" --list-devices >"$LOGS/$1.list-devices.txt" 2>&1 || rc=$?
	echo "finding: [$1] --list-devices rc=$rc: $(grep -E 'Available|MTL' "$LOGS/$1.list-devices.txt" | tr '\n' ' ' | cut -c1-120)"
}

serve_and_probe() { # serve_and_probe NAME PROFILE ARGS...: one variant, start to stop
	local name="$1" prof="$2"
	shift 2
	list_devices "$name" "$prof"
	launch "$name" "$prof" "$PORT" -m "$MODEL" --alias m -ngl 99 -c 4096 --parallel 2 --no-webui -v "$@"
	if python3 -I "$M25/probe.py" "$PORT" wait 60 >"$LOGS/$name.health.txt" 2>&1; then
		local ready smoke
		ready="$(tail -1 "$LOGS/$name.health.txt")"
		smoke="$(python3 -I "$M25/probe.py" "$PORT" smoke 2>&1 | head -2 | tr '\n' ' ' | cut -c1-160)"
		echo "finding: [$name] $ready; $smoke; layers $(offloaded "$LOGS/$name.engine.log")"
		SERVED=1
	else
		echo "finding: [$name] did not become ready; alive=$(ps -p "$PID" -o comm= | wc -l | tr -d ' '); layers $(offloaded "$LOGS/$name.engine.log")"
		SERVED=0
	fi
	stop_engine
	denials "$name"
}

ablate() {
	note "removal and addition, one rule at a time, on $PORT"
	local p cache
	serve_and_probe base "$PROFILE"
	[ "$SERVED" = 1 ] || die "the unmodified profile did not serve (see $LOGS/base.engine.log)"
	grep -q 'offloaded \([0-9]*\)/\1 layers' "$LOGS/base.engine.log" || die "the baseline did not put every layer on the GPU"
	serve_and_probe base-again "$PROFILE"

	# Removals.
	p="$(variant no-agx --remove "$IOKIT_BLOCK" --add '(allow iokit-open (iokit-registry-entry-class "IOSurfaceRootUserClient"))')"
	serve_and_probe no-agx "$p"
	p="$(variant no-iosurface --remove "$IOKIT_BLOCK" --add '(allow iokit-open (iokit-registry-entry-class "AGXDeviceUserClient"))')"
	serve_and_probe no-iosurface "$p"
	p="$(variant no-iokit --remove "$IOKIT_BLOCK")"
	serve_and_probe no-iokit "$p"
	local line
	for line in 'allow network-bind' 'allow ipc-posix-sem'; do
		local full
		full="$(grep -F "($line" "$PROFILE" | head -1 || true)"
		if [ -n "$full" ] && p="$(variant "no-${line##* }" --remove "$full")"; then
			serve_and_probe "no-${line##* }" "$p"
		else
			echo "finding: [no-${line##* }] the profile has no '($line' rule to remove"
		fi
	done

	# Additions: measured, never shipped.
	cache="$(as_user getconf DARWIN_USER_CACHE_DIR)"
	p="$(variant plus-getprops --add '(allow iokit-get-properties)')"
	serve_and_probe plus-getprops "$p"
	p="$(variant plus-mtlcompiler --add '(allow mach-lookup (global-name "com.apple.MTLCompilerService"))')"
	serve_and_probe plus-mtlcompiler "$p"
	p="$(variant plus-cvms --add '(allow file-read* (subpath "/private/var/db/CVMS"))')"
	serve_and_probe plus-cvms "$p"
	p="$(variant plus-shadercache --add "(allow file-read* file-write* (subpath \"${cache%/}\"))")"
	as_user find "${cache%/}" 2>/dev/null | LC_ALL=C sort >"$WORKDIR/cache.before" || true
	serve_and_probe plus-shadercache "$p"
	serve_and_probe plus-shadercache-warm "$p"
	# Remove only what these two runs created in the per-user cache.
	as_user find "${cache%/}" 2>/dev/null | LC_ALL=C sort >"$WORKDIR/cache.after" || true
	LC_ALL=C comm -13 "$WORKDIR/cache.before" "$WORKDIR/cache.after" | LC_ALL=C sort -r |
		while IFS= read -r created; do
			case "$created" in "${cache%/}"/?*) as_user rm -rf -- "$created" ;; esac
		done
}

memory() { # memory NAME ARGS...: footprint at ready and after a completion
	local name="$1"
	shift
	launch "$name" "$PROFILE" "$PORT" -m "$MODEL" --alias m -ngl 99 --no-webui -v "$@"
	as_root "$SAMPLER" "$PID" 100 600 >"$LOGS/$name.mem.csv" 2>/dev/null &
	local sp=$! at_ready=""
	if python3 -I "$M25/probe.py" "$PORT" wait 60 >"$LOGS/$name.health.txt" 2>&1; then
		sleep 1
		at_ready="$(tail -1 "$LOGS/$name.mem.csv")"
		python3 -I "$M25/probe.py" "$PORT" smoke >"$LOGS/$name.smoke.txt" 2>&1 || true
		sleep 1
	fi
	echo "finding: [$name] $*: at ready (t_ms,footprint_mib,resident_mib) ${at_ready:-none}; peak footprint $(peak_footprint "$LOGS/$name.mem.csv") MiB; $(head -1 "$LOGS/$name.smoke.txt" 2>/dev/null | cut -c1-60)"
	stop_engine
	kill "$sp" 2>/dev/null || true
	wait "$sp" 2>/dev/null || true
}

questions() {
	note "memory: mapped or not, KV up front, context total or per slot"
	cc -O1 -o "$SAMPLER" "$M25/sampler.c"
	memory mmap -c 4096 -np 1 -lm mmap
	memory nommap -c 4096 -np 1 -lm none
	memory ctx512 -c 512 -np 1
	memory ctx32768 -c 32768 -np 1
	memory np2 -c 4096 -np 2
	memory ctx-from-model -np 1

	note "no GPU grant: which invocations exit, which serve"
	local p name
	p="$(variant nogpu --remove "$IOKIT_BLOCK")"
	for name in ngl99:"-ngl 99" auto: ngl0:"-ngl 0" devnone:"--device none" fitoff:"-ngl 99 --fit off"; do
		local label="${name%%:*}" args="${name#*:}"
		# shellcheck disable=SC2086 # args is a flag list by construction
		launch "nogpu-$label" "$p" "$PORT" -m "$MODEL" --no-webui -v -c 2048 -np 1 $args
		if python3 -I "$M25/probe.py" "$PORT" wait 25 >/dev/null 2>&1; then
			echo "finding: [nogpu-$label] serves"
		else
			echo "finding: [nogpu-$label] not ready; engine alive=$(ps -p "$PID" -o comm= | wc -l | tr -d ' ')"
		fi
		stop_engine
	done

	note "requests: window, remote image, routes, concurrency"
	python3 -I "$M25/listener.py" 18406 >"$LOGS/listener.log" 2>&1 &
	local lp=$!
	sleep 0.5
	launch requests "$PROFILE" "$PORT" -m "$MODEL" --alias m -ngl 99 --no-webui -v -c 512 -np 1
	python3 -I "$M25/probe.py" "$PORT" wait 60 | tail -1
	python3 -I "$M25/probe.py" "$PORT" prompt-over 2000 | cut -c1-200 | sed 's/^/finding: window: /'
	python3 -I "$M25/probe.py" "$PORT" imageurl 18406 | cut -c1-200 | sed 's/^/finding: image_url: /'
	echo "finding: image_url: listener hits $(grep -c HIT "$LOGS/listener.log" || true)"
	for p in /health /v1/models /props /slots /metrics; do
		echo "finding: GET $p => $(python3 -I "$M25/probe.py" "$PORT" get "$p" 120 | cut -c1-120)"
	done
	stop_engine
	kill "$lp" 2>/dev/null || true
	launch concurrent "$PROFILE" "$PORT" -m "$MODEL" --alias m -ngl 99 --no-webui -v -c 16384 -np 4
	python3 -I "$M25/probe.py" "$PORT" wait 60 | tail -1
	python3 -I "$M25/probe.py" "$PORT" concurrent 4 | sed 's/^/finding: concurrent 4: /'
	stop_engine
	"$BIN" --help >"$LOGS/help.txt" 2>&1 || true
	echo "finding: --help captured: $(wc -l <"$LOGS/help.txt" | tr -d ' ') lines in $LOGS/help.txt"
}

measure() {
	if [ "${K3SM_LAB:-}" != 1 ]; then
		echo "SKIP: llamacpp-measure needs K3SM_LAB=1 (a Mac with an Apple GPU)"
		return 0
	fi
	[ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "this needs an Apple-silicon Mac"
	WORKDIR="${K3SM_LLAMA_WORKDIR:?set K3SM_LLAMA_WORKDIR}"
	PROFILE_IN="${K3SM_LLAMA_PROFILE:?set K3SM_LLAMA_PROFILE}"
	local t
	for t in git curl python3 cmake cc shasum otool codesign sandbox-exec; do
		command -v "$t" >/dev/null 2>&1 || [ -x "/usr/bin/$t" ] || die "missing tool: $t"
	done
	mkdir -p "$WORKDIR" && WORKDIR="$(cd "$WORKDIR" && pwd)"
	SRC="$WORKDIR/src" BUILD="$WORKDIR/build" LOGS="$WORKDIR/logs" BIN="$WORKDIR/llama-server"
	MODEL="$WORKDIR/model.gguf" SAMPLER="$WORKDIR/sampler" PORT=18404
	mkdir -p "$LOGS" "$WORKDIR/variants" "$WORKDIR/tmp"
	chmod 0777 "$WORKDIR/tmp" 2>/dev/null || true
	PROFILE="$WORKDIR/variants/shipped.sb"
	cp "$PROFILE_IN" "$PROFILE"
	chmod 0644 "$PROFILE"
	# Fail closed: the profile under test must carry the shipped grant, exactly.
	python3 -I "$M25/variant.py" "$PROFILE" /dev/null --remove "$IOKIT_BLOCK" ||
		die "K3SM_LLAMA_PROFILE does not contain the iokit-open grant text the variants remove"
	[ "$(gpu_stanza "$PROFILE")" = "$GPU_STANZA" ] ||
		die "K3SM_LLAMA_PROFILE's GPU stanza (comment block through the IOSurfaceRootUserClient line) differs from the shipped one"

	pin_source
	build
	fetch_gguf
	ablate
	questions
	note "done: logs in $LOGS"
}

case "${1:-}" in
--self-test) self_test ;;
--measure) measure ;;
*)
	echo "usage: $0 --measure | --self-test" >&2
	exit 2
	;;
esac
