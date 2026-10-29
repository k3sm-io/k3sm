#!/usr/bin/env bash
#
# mlx-serve selftest — the part of the image gate that can run WITHOUT building
# the image.
#
# The full acceptance check for this image is an integration one: it needs a Mac
# with uv, a `k3sm` binary, ~1.3 GB of wheels off the network, and a few minutes.
# This script is what remains provable on any Mac in seconds — and it is chosen
# so that the expensive run cannot be the first place a mistake is found:
#
#   * the scripts parse and are shellcheck-clean;
#   * the Dockerfile they emit is COPY-only, and carries the serving argv the
#     engine will not work without;
#   * the lockfile is exactly pinned with a hash for every artifact, and the
#     build refuses one that is not;
#   * the build refuses to run at all without uv;
#   * the build packages with `k3sm build --no-record --output`, so it needs no
#     root and never records into the cluster registry;
#   * walk-verify goes RED on an invalid signature, on a mislabelled layer, on a
#     blob that does not match its digest, and on a non-Mach-O entrypoint — and
#     GREEN on the universal-binary shape that a whole-file signature check
#     would have failed;
#   * the k3sm-shard entrypoint renders the ring hostfile and the jaccl device
#     matrix into the pod data volume from fake name resolution, retries and
#     bounds resolution, and its liveness probe answers 0 and 1 correctly;
#   * the entrypoint takes --served-model-name itself and makes the engine
#     answer to that name on /v1/models and in a request's model field,
#     against a fake engine module, and refuses to start when a hook it
#     relies on is missing or reshaped (and, with a staged tree, finds every
#     hook on the pinned mlx_lm.server);
#   * the k3sm-serve context guard refuses a request longer than the engine's
#     window with vLLM's HTTP 400 and passes one inside it, against fakes and,
#     when a staged tree is present, against the real vllm-mlx server, on the
#     completion, chat, Messages and Responses routes, streaming or not;
#   * k3sm-serve lowers --max-kv-size for a model whose config.json geometry
#     costs more KV bytes per token than k3sm sized it for, and leaves it alone
#     for a smaller model, a missing config, a missing field and the off switch;
#   * with a staged tree, the patched RotatingKVCache prefill mask keeps the
#     attention-sink columns attended after a trim, which the pinned mlx-lm's
#     own mask does not;
#   * the stage Job stage-job.sh renders pins uv by version and published
#     sha256 and the lockfile by digest, carries the checkout's files verbatim,
#     fails closed on a digest mismatch, carries no credential, and is placed by
#     nodeSelector with the provider toleration;
#   * build.sh --from-stage packages a stage made elsewhere with no uv, and
#     refuses a stage from other pins, without its stamp or interpreter, with a
#     drifted entrypoint module, or with a file the packaging user cannot read.
#
# Usage: hack/images/mlx-serve/selftest.sh
# Exit: 0 all checks pass, 1 otherwise.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build.sh"
WALK="$HERE/walk-verify.sh"
LOCK="$HERE/requirements.lock"

PASS=0; FAIL=0; SKIP=0
ladder() {
	case "$1" in
		ok)   echo "PASS  $2"; PASS=$((PASS + 1)) ;;
		skip) echo "SKIP  $2"; SKIP=$((SKIP + 1)) ;;
		*)    echo "FAIL  $2"; FAIL=$((FAIL + 1)) ;;
	esac
}

echo "==> mlx-serve selftest"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mlx-selftest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

# ---- 0 — the scripts parse and are executable -------------------------------
for s in "$BUILD" "$WALK" "$HERE/stage-job.sh" "$HERE/selftest.sh"; do
	n="$(basename "$s")"
	if [ -x "$s" ] && bash -n "$s" 2>/dev/null; then
		ladder ok "0.$n  executable + parses (bash -n)"
	else
		ladder no "0.$n  executable + parses (bash -n)"
	fi
done

if command -v shellcheck >/dev/null 2>&1; then
	if out="$(shellcheck -s bash "$BUILD" "$WALK" "$HERE/stage-job.sh" "$HERE/selftest.sh" 2>&1)"; then
		ladder ok "0.shellcheck  clean"
	else
		ladder no "0.shellcheck  clean"
		printf '%s\n' "$out" | head -40
	fi
else
	ladder skip "0.shellcheck  not installed on this host"
fi

# ---- 1 — the lockfile is exactly pinned, with hashes ------------------------
# Counted here independently of build.sh, so a broken checker cannot pass itself.
reqs="$(grep -cE '^[^ 	#]' "$LOCK")"
hashes="$(grep -c -- '--hash=' "$LOCK")"
nohash="$(awk '
	/^[ \t]*#/ { next }
	/^[^ \t]/  { if (name != "" && n == 0) print name; name = $1; n = 0; next }
	/--hash=/  { if (name != "") n++ }
	END { if (name != "" && n == 0) print name }
' "$LOCK" | wc -l | tr -d ' ')"
if [ "$reqs" -gt 0 ] && [ "$hashes" -ge "$reqs" ] && [ "$nohash" -eq 0 ]; then
	ladder ok "1.lock  $reqs requirements, $hashes hashes, none hashless"
else
	ladder no "1.lock  $reqs requirements, $hashes hashes, $nohash hashless"
fi

if grep -qE '^[^ 	#]*(git\+|@ +[a-z]+:)' "$LOCK"; then
	ladder no "1.direct  no direct-URL (git+) requirements"
else
	ladder ok "1.direct  no direct-URL (git+) requirements"
fi

if grep -qxE '[^ 	#]+==[^ ]+ *\\?' "$LOCK" && ! grep -qE '^[a-zA-Z0-9._-]+(>=|<=|~=|>|<)' "$LOCK"; then
	ladder ok "1.exact  every requirement is an == pin"
else
	ladder no "1.exact  every requirement is an == pin"
fi

engine="$(grep -E '^[a-zA-Z0-9]' "$HERE/requirements.in" | head -1)"
if [ -n "$engine" ] && grep -qxF "$engine \\" "$LOCK"; then
	ladder ok "1.engine  requirements.in pin ($engine) is the lockfile's pin"
else
	ladder no "1.engine  requirements.in pin ($engine) is the lockfile's pin"
fi

if "$BUILD" --check-lock "$LOCK" >/dev/null 2>&1; then
	ladder ok "1.accept  build.sh accepts the shipped lockfile"
else
	ladder no "1.accept  build.sh accepts the shipped lockfile"
fi

# ---- 2 — build.sh refuses a lockfile that is not fully pinned ---------------
printf 'foo==1.0\nbar==2.0 \\\n    --hash=sha256:aaa\n'        > "$WORK/hashless.txt"
printf 'baz @ git+https://example.invalid/x@abc\n'             > "$WORK/direct.txt"
printf 'qux>=1.0 \\\n    --hash=sha256:aaa\n'                  > "$WORK/range.txt"
printf '# nothing but a comment\n'                             > "$WORK/empty.txt"
for case in hashless direct range empty; do
	if "$BUILD" --check-lock "$WORK/$case.txt" >/dev/null 2>&1; then
		ladder no "2.$case  build.sh refuses it"
	else
		ladder ok "2.$case  build.sh refuses it"
	fi
done

# ---- 3 — build.sh refuses to run without uv --------------------------------
out="$(K3SM_MLX_UV=/nonexistent/uv "$BUILD" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'uv not found'; then
	ladder ok "3.uv  build.sh stops on a missing uv (exit $rc)"
else
	ladder no "3.uv  build.sh stops on a missing uv (exit $rc)"
fi

# The packaging step writes the layout only. Without --no-record, `k3sm build`
# records the image in the cluster registry and warms this node's cache through
# the runtime daemon's socket, which needs root, so a non-root build would fail at
# packaging.
# Every `k3sm build` invocation in build.sh must carry --no-record and --output.
# shellcheck disable=SC2016 # the pattern is the literal text "$K3SM_BIN"
calls="$(grep -F '"$K3SM_BIN" build ' "$BUILD")"
if [ -n "$calls" ] &&
	! printf '%s\n' "$calls" | grep -v -- '--no-record' | grep -q . &&
	! printf '%s\n' "$calls" | grep -v -- '--output' | grep -q .; then
	ladder ok "3.norecord  build.sh packages with k3sm build --no-record --output (no root, no store)"
else
	ladder no "3.norecord  build.sh packages with k3sm build --no-record --output (no root, no store)"
fi

# ---- 4 — the emitted Dockerfile --------------------------------------------
DF="$WORK/Dockerfile"
if "$BUILD" --print-dockerfile > "$DF" 2>/dev/null && [ -s "$DF" ]; then
	ladder ok "4.emit  build.sh --print-dockerfile emits a Dockerfile"
else
	ladder no "4.emit  build.sh --print-dockerfile emits a Dockerfile"
fi

# COPY-only is the property the builder enforces and this image depends on: the
# tree is assembled on the host precisely because nothing can be executed here.
if [ -s "$DF" ] && ! grep -qE '^[[:space:]]*RUN([[:space:]]|$)' "$DF"; then
	ladder ok "4.norun  the Dockerfile has no RUN"
else
	ladder no "4.norun  the Dockerfile has no RUN"
fi
if [ "$(grep -cE '^FROM ' "$DF")" = 1 ] && grep -qE '^FROM scratch$' "$DF"; then
	ladder ok "4.scratch  one FROM, and it is scratch"
else
	ladder no "4.scratch  one FROM, and it is scratch"
fi
if [ "$(grep -cE '^COPY ' "$DF")" = 1 ]; then
	ladder ok "4.copy  exactly one COPY"
else
	ladder no "4.copy  exactly one COPY"
fi

# The serving argv. Without --continuous-batching the engine answers HTTP 503 to
# every concurrent request but one, while /health stays green — so its absence
# is invisible to every check except this one.
ep="$(grep -E '^ENTRYPOINT ' "$DF")"
for token in '"-m"' '"serve"' '"--continuous-batching"' '"0.0.0.0"'; do
	if printf '%s' "$ep" | grep -qF "$token"; then
		ladder ok "4.argv  ENTRYPOINT carries $token"
	else
		ladder no "4.argv  ENTRYPOINT carries $token"
	fi
done
# argv[0] must be the interpreter Mach-O itself — not /bin/python3, which is a
# symlink, and not a shell wrapper.
if printf '%s' "$ep" | grep -qE '\["/bin/python3\.[0-9]+"'; then
	ladder ok "4.argv0  ENTRYPOINT starts at the interpreter binary, not a symlink or a script"
else
	ladder no "4.argv0  ENTRYPOINT starts at the interpreter binary, not a symlink or a script"
fi
# Weights are a volume concern: HF_HOME points at the mount, and no model is
# named anywhere in the image.
if grep -qE '^ENV HF_HOME=/models$' "$DF"; then
	ladder ok "4.hfhome  ENV HF_HOME points at the cache mount"
else
	ladder no "4.hfhome  ENV HF_HOME points at the cache mount"
fi

# ---- 5 — walk-verify fixtures ----------------------------------------------
# The fixtures are built from a system binary and from a hand-written Mach-O
# header, so the RED case needs no signing tool at all.
FIX="$WORK/fix"; mkdir -p "$FIX"
python3 - "$FIX/unsigned-stub" <<'PY'
import struct, sys
# A syntactically valid 64-bit arm64 Mach-O header with no load commands and no
# signature: `file` calls it a Mach-O, codesign refuses it.
hdr = struct.pack("<IiiIIIII", 0xfeedfacf, 0x0100000C, 0, 2, 0, 0, 0x00200085, 0)
open(sys.argv[1], "wb").write(hdr + b"\x00" * 4096)
PY

SYSBIN=/bin/echo
GOOD="$WORK/tree-good"; mkdir -p "$GOOD/bin"
cp "$SYSBIN" "$GOOD/bin/python3.12"
echo "not a mach-o" > "$GOOD/plain.txt"
BAD="$WORK/tree-bad"; mkdir -p "$BAD/bin"
cp "$SYSBIN" "$BAD/bin/python3.12"
cp "$FIX/unsigned-stub" "$BAD/bin/broken.so"

if "$WALK" --tree "$GOOD" >/dev/null 2>&1; then
	ladder ok "5.green  walk-verify passes a validly signed tree"
else
	ladder no "5.green  walk-verify passes a validly signed tree"
fi
out="$("$WALK" --tree "$BAD" 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'INVALID'; then
	ladder ok "5.red  walk-verify fails a tree with an invalid-signature Mach-O (exit $rc)"
else
	ladder no "5.red  walk-verify fails a tree with an invalid-signature Mach-O (exit $rc)"
	printf '%s\n' "$out" | head -10
fi

# The universal-binary lesson, mechanized: a fat Mach-O whose target slice is
# validly signed and whose foreign slice is not must PASS, because only the
# target slice is ever executed. A whole-file check calls the same file
# unsigned — asserted here too, so the fixture cannot silently stop being the
# shape it is meant to be.
FATOK=0
if command -v lipo >/dev/null 2>&1 && [ "$(lipo -archs "$SYSBIN" | wc -w)" -ge 2 ]; then
	slices="$(lipo -archs "$SYSBIN")"
	target=""; foreign=""
	for a in $slices; do
		case "$a" in arm64|arm64e) target="$a" ;; *) foreign="$a" ;; esac
	done
	if [ -n "$target" ] && [ -n "$foreign" ] &&
		lipo "$SYSBIN" -thin "$target" -output "$FIX/t.bin" 2>/dev/null &&
		lipo "$SYSBIN" -thin "$foreign" -output "$FIX/f.bin" 2>/dev/null &&
		codesign --remove-signature "$FIX/f.bin" 2>/dev/null &&
		lipo -create "$FIX/t.bin" "$FIX/f.bin" -output "$FIX/fat.bin" 2>/dev/null; then
		FATOK=1
	fi
fi
if [ "$FATOK" -eq 1 ]; then
	MIX="$WORK/tree-fat"; mkdir -p "$MIX/bin"
	cp "$FIX/fat.bin" "$MIX/bin/universal.so"
	if codesign -v "$FIX/fat.bin" >/dev/null 2>&1; then
		ladder no "5.fatshape  the fixture is a fat binary a whole-file check rejects"
	else
		ladder ok "5.fatshape  the fixture is a fat binary a whole-file check rejects"
	fi
	if "$WALK" --tree "$MIX" >/dev/null 2>&1; then
		ladder ok "5.fat  walk-verify passes it anyway (per-architecture verdict)"
	else
		ladder no "5.fat  walk-verify passes it anyway (per-architecture verdict)"
	fi
else
	ladder skip "5.fat  no universal system binary to build the fixture from"
fi

# ---- 6 — walk-verify on an OCI layout --------------------------------------
# A hand-built layout, so the layout reader is exercised without a builder: the
# real one is identical in shape and is what the live build produces.
mklayout() {
	python3 - "$1" "$2" "$3" "$4" <<'PY'
import hashlib, json, os, shutil, subprocess, sys, tarfile

dest, tree, mode, entrypoint = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
blobs = os.path.join(dest, "blobs", "sha256")
os.makedirs(blobs, exist_ok=True)

tar_path = os.path.join(dest, "layer.tar")
with tarfile.open(tar_path, "w") as tf:
    for name in sorted(os.listdir(tree)):
        tf.add(os.path.join(tree, name), arcname=name)

payload = open(tar_path, "rb").read()
declared = "application/vnd.oci.image.layer.v1.tar"
diff_id = "sha256:" + hashlib.sha256(payload).hexdigest()
if mode == "mislabelled":
    # gzip bytes under the UNCOMPRESSED media type: readable by a reader that
    # sniffs, unreadable by one that trusts the manifest.
    payload = subprocess.run(["gzip", "-c"], input=payload, stdout=subprocess.PIPE).stdout
os.remove(tar_path)

def put(data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    open(os.path.join(blobs, digest.split(":", 1)[1]), "wb").write(data)
    return digest, len(data)

layer_digest, layer_size = put(payload)
if mode == "corrupt":
    # Same name, different bytes: the digest no longer describes the content.
    open(os.path.join(blobs, layer_digest.split(":", 1)[1]), "ab").write(b"\x00")

config = {
    "architecture": "arm64",
    "os": "darwin",
    "config": {"Entrypoint": [entrypoint]},
    "rootfs": {"type": "layers", "diff_ids": [diff_id]},
}
config_digest, config_size = put(json.dumps(config).encode())
manifest = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": config_digest, "size": config_size},
    "layers": [{"mediaType": declared, "digest": layer_digest, "size": layer_size}],
}
manifest_digest, manifest_size = put(json.dumps(manifest).encode())
json.dump({"schemaVersion": 2,
           "manifests": [{"mediaType": manifest["mediaType"],
                          "digest": manifest_digest, "size": manifest_size}]},
          open(os.path.join(dest, "index.json"), "w"))
open(os.path.join(dest, "oci-layout"), "w").write('{"imageLayoutVersion":"1.0.0"}')
PY
}

mklayout "$WORK/layout-ok" "$GOOD" plain /bin/python3.12
if "$WALK" --layout "$WORK/layout-ok" >/dev/null 2>&1; then
	ladder ok "6.layout  walk-verify passes a well-formed layout"
else
	ladder no "6.layout  walk-verify passes a well-formed layout"
	"$WALK" --layout "$WORK/layout-ok" 2>&1 | head -10
fi

mklayout "$WORK/layout-mislabelled" "$GOOD" mislabelled /bin/python3.12
out="$("$WALK" --layout "$WORK/layout-mislabelled" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'gzip'; then
	ladder ok "6.mislabelled  walk-verify fails a layer whose bytes contradict its media type"
else
	ladder no "6.mislabelled  walk-verify fails a layer whose bytes contradict its media type"
fi

mklayout "$WORK/layout-corrupt" "$GOOD" corrupt /bin/python3.12
out="$("$WALK" --layout "$WORK/layout-corrupt" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'digest'; then
	ladder ok "6.corrupt  walk-verify fails a blob that does not match its digest"
else
	ladder no "6.corrupt  walk-verify fails a blob that does not match its digest"
fi

SCRIPTEP="$WORK/tree-script"; mkdir -p "$SCRIPTEP/bin"
cp "$SYSBIN" "$SCRIPTEP/bin/python3.12"
printf '#!/bin/sh\nexec /bin/python3.12 "$@"\n' > "$SCRIPTEP/bin/serve"
mklayout "$WORK/layout-script" "$SCRIPTEP" plain /bin/serve
out="$("$WALK" --layout "$WORK/layout-script" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'ENTRYPOINT'; then
	ladder ok "6.entrypoint  walk-verify fails a non-Mach-O entrypoint"
else
	ladder no "6.entrypoint  walk-verify fails a non-Mach-O entrypoint"
fi

# ---- 7 — the k3sm-shard entrypoint (sharded ranks) ---------------------------
# What a rank does before it starts the engine, with FAKE name resolution: no model, no GPU,
# no cluster DNS. The live rendezvous (real per-pod records, two Macs, the
# sandbox profile) is the M17 lab ladder's sharded-ring rung.
SHARD="$HERE/k3sm_shard.py"
if [ -f "$SHARD" ] && PYTHONDONTWRITEBYTECODE=1 python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$SHARD" 2>/dev/null; then
	ladder ok "7.parse  k3sm_shard.py parses"
else
	ladder no "7.parse  k3sm_shard.py parses"
fi
if grep -q '^stage_shard_entrypoint$' "$BUILD" && grep -q '^SHARD_MODULE="k3sm_shard"$' "$BUILD"; then
	ladder ok "7.staged  build.sh installs k3sm_shard into the image"
else
	ladder no "7.staged  build.sh installs k3sm_shard into the image"
fi

cat > "$WORK/shard-driver.py" <<'PY'
import http.server, json, os, socket, sys, threading
sys.path.insert(0, sys.argv[1])
import k3sm_shard as ks

work = sys.argv[2]
podvol = os.path.join(work, "podvol")
os.makedirs(podvol)
names = ["m-rank-0.m-headless.ns.svc", "m-rank-1.m-headless.ns.svc", "m-rank-2.m-headless.ns.svc"]
fake = {names[0]: "10.42.0.5", names[1]: "10.42.1.5", names[2]: "10.42.2.5"}

def resolver(name):
    if name not in fake:
        raise socket.gaierror(8, "nodename nor servname provided")
    return fake[name]

def env(**kw):
    e = {"MLX_RANK": "1", "MLX_WORLD_SIZE": "2", "K3SM_MLX_BACKEND": "ring", "K3SM_MLX_PARALLELISM": "tensor",
         "K3SM_MLX_RANKS": ",".join(names[:2]), "K3SM_MLX_PORT": "29500", "K3SM_MLX_SERVE_PORT": "8000",
         "TMPDIR": podvol, "K3SM_POD_IP": "10.42.1.5"}
    e.update(kw)
    return {k: v for k, v in e.items() if v is not None}

def check(name, cond):
    print(("ok " if cond else "no ") + name, flush=True)

# ring: the hostfile, written ONLY under the pod data volume
files, cenv, argv = ks.plan(env(), ["--model", "/m", "--max-tokens", "8"], resolver=resolver)
(path, content), = files.items()
check("ring.hostfile  one [podIP:port] entry per rank, in rank order",
      json.loads(content) == [["10.42.0.5:29500"], ["10.42.1.5:29500"]])
check("ring.datavolume  the hostfile lands inside TMPDIR and MLX_HOSTFILE names it",
      path.startswith(podvol + os.sep) and cenv["MLX_HOSTFILE"] == path)
check("ring.argv  runs mlx_lm.server on 0.0.0.0 and the serve port, caller args last, no --pipeline for tensor",
      argv[1:8] == ["-m", "mlx_lm.server", "--host", "0.0.0.0", "--port", "8000", "--model"]
      and argv[-2:] == ["--max-tokens", "8"] and "--pipeline" not in argv)
check("ring.env  MLX_RANK and MLX_WORLD_SIZE exported", cenv["MLX_RANK"] == "1" and cenv["MLX_WORLD_SIZE"] == "2")
_, _, argv = ks.plan(env(K3SM_MLX_PARALLELISM="pipeline"), ["--model", "/m"], resolver=resolver)
check("ring.pipeline  pipeline parallelism adds --pipeline", "--pipeline" in argv)
ks.write_files(files)
check("ring.write  the file is written and reads back", json.load(open(path)) == json.loads(content))

# own address from K3SM_POD_IP, never a lookup of its own name
f2, _, _ = ks.plan(env(K3SM_POD_IP="10.99.0.1"), [], resolver=resolver)
check("ring.ownip  the rank's own entry is K3SM_POD_IP",
      json.loads(next(iter(f2.values())))[1] == ["10.99.0.1:29500"])

# jaccl: the device matrix and the coordinator
matrix = [[None, "rdma_en2", "rdma_en3"], ["rdma_en2", None, "rdma_en4"], ["rdma_en3", "rdma_en4", None]]
files, cenv, _ = ks.plan(env(MLX_RANK="2", MLX_WORLD_SIZE="3", K3SM_MLX_BACKEND="jaccl", K3SM_MLX_RANKS=",".join(names),
                             K3SM_POD_IP="10.42.2.5", K3SM_MLX_IBV_DEVICES_JSON=json.dumps(matrix)), [], resolver=resolver)
(path, content), = files.items()
check("jaccl.devices  MLX_IBV_DEVICES is the matrix, null for self, inside TMPDIR",
      json.loads(content) == matrix and cenv["MLX_IBV_DEVICES"] == path and path.startswith(podvol + os.sep))
check("jaccl.coordinator  MLX_JACCL_COORDINATOR is rank 0's pod IP and the collective port",
      cenv["MLX_JACCL_COORDINATOR"] == "10.42.0.5:29500" and "MLX_HOSTFILE" not in cenv)

# resolution retries until every peer resolves, and is bounded
calls = {"n": 0}
def flaky(name):
    calls["n"] += 1
    if calls["n"] < 3:
        raise socket.gaierror(8, "not yet")
    return resolver(name)
t = {"now": 0.0}
tick = lambda s: t.__setitem__("now", t["now"] + s)
ips = ks.resolve_all(names[:2], flaky, timeout=60, interval=1, clock=lambda: t["now"], sleep=tick)
check("resolve.retry  an unresolved peer is retried until it resolves", ips == ["10.42.0.5", "10.42.1.5"])
try:
    ks.resolve_all(["nope.svc"], resolver, timeout=5, interval=1, clock=lambda: t["now"], sleep=tick)
    check("resolve.bounded  a peer that never resolves ends the rank", False)
except ks.ShardError as e:
    check("resolve.bounded  a peer that never resolves ends the rank", "nope.svc" in str(e))

# thunderbolt path: K3SM_MLX_HOSTS is the hostfile, no lookup, own entry == K3SM_INTERCONNECT_IP
tb_hosts = "169.254.0.2:29500,169.254.0.10:29500"
def no_lookup(name):
    raise AssertionError("the thunderbolt path resolved " + name)
files, cenv, _ = ks.plan(env(K3SM_MLX_HOSTS=tb_hosts, K3SM_INTERCONNECT_IP="169.254.0.10"), [], resolver=no_lookup)
check("tb.hostfile  K3SM_MLX_HOSTS becomes the hostfile in rank order, with no name lookup",
      json.loads(next(iter(files.values()))) == [["169.254.0.2:29500"], ["169.254.0.10:29500"]])
for label, e in (("tb.mismatch  refuses an own entry that is not K3SM_INTERCONNECT_IP",
                  env(K3SM_MLX_HOSTS=tb_hosts, K3SM_INTERCONNECT_IP="169.254.0.18")),
                 ("tb.unattached  refuses K3SM_MLX_HOSTS without K3SM_INTERCONNECT_IP",
                  env(K3SM_MLX_HOSTS=tb_hosts))):
    try:
        ks.plan(e, [], resolver=no_lookup)
        check(label, False)
    except ks.ShardError:
        check(label, True)

# refusals: no pod data volume, a rank list that disagrees with the world size
for label, e in (("nodatavolume  refuses to write anywhere but the pod data volume", env(TMPDIR=None)),
                 ("worldsize  refuses a rank list that disagrees with MLX_WORLD_SIZE", env(MLX_WORLD_SIZE="3"))):
    try:
        ks.plan(e, [], resolver=resolver)
        check(label, False)
    except ks.ShardError:
        check(label, True)

# --served-model-name: taken by the entrypoint, never passed to mlx_lm.server
name, rest = ks.split_served_name(["--model", "/snap", "--served-model-name", "org/m", "--max-tokens", "8"])
check("alias.split  --served-model-name is removed from the engine's argv and returned",
      name == "org/m" and rest == ["--model", "/snap", "--max-tokens", "8"])
name, rest = ks.split_served_name(["--served-model-name", "a", "--served-model-name=b"])
check("alias.lastwins  the last --served-model-name wins, as a caller override does", name == "b" and rest == [])
check("alias.absent  no --served-model-name leaves argv alone",
      ks.split_served_name(["--model", "/m"]) == (None, ["--model", "/m"]))
try:
    ks.split_served_name(["--served-model-name"])
    check("alias.novalue  --served-model-name without a name ends the rank", False)
except ks.ShardError:
    check("alias.novalue  --served-model-name without a name ends the rank", True)

import io, types
def fake_engine(**drop):
    """A stand-in for mlx_lm.server 0.32.0 with the hooks the alias uses."""
    m = types.ModuleType("mlx_lm.server")
    rec = m.rec = {"loads": [], "http": None, "joined": False, "rank": 0}
    class ModelProvider:
        def __init__(self, cli_args):
            self.cli_args = cli_args
        def load(self, model_path, adapter_path=None, draft_model_path=None):
            rec["loads"].append((model_path, adapter_path, draft_model_path))
            return "model", "tokenizer"
    class APIHandler:
        def __init__(self, path):
            self.path, self.created, self.wfile, self.status = path, 7, io.BytesIO(), None
        def handle_models_request(self):
            self.wfile.write(b"upstream")
        def _set_completion_headers(self, status_code=200):
            self.status = status_code
        def end_headers(self):
            pass
    class ResponseGenerator:
        def __init__(self, model_provider, prompt_cache):
            self.model_provider, self.prompt_cache = model_provider, prompt_cache
        def join(self):
            rec["joined"] = True
    def run(host, port, model_provider, server_class=None, handler_class=None):
        raise AssertionError("the stock run was called")
    def _run_http_server(host, port, response_generator, server_class=None, handler_class=APIHandler):
        rec["http"] = (host, port, response_generator, handler_class)
    def main():
        rec["argv"] = list(sys.argv)
        m.run("0.0.0.0", 8000, m.ModelProvider(types.SimpleNamespace(prompt_cache_size=3)))
    group = types.SimpleNamespace(rank=lambda: rec["rank"])
    m.mx = types.SimpleNamespace(distributed=types.SimpleNamespace(init=lambda: group))
    m.ModelProvider, m.APIHandler, m.ResponseGenerator = ModelProvider, APIHandler, ResponseGenerator
    m.LRUPromptCache = lambda size: ("cache", size)
    m.run, m._run_http_server, m.main = run, _run_http_server, main
    for path, value in drop.items():
        owner, _, attr = path.rpartition(".")
        setattr(getattr(m, owner) if owner else m, attr, value)
    return m

eng = fake_engine()
P, Hd, _ = ks.install_alias(eng, "org/m")
prov = eng.ModelProvider(types.SimpleNamespace(prompt_cache_size=3))
prov.load("org/m", None, "default_model")
prov.load("other/x", None, "default_model")
check("alias.load  a request naming the served name loads default_model (the loaded snapshot), others pass through",
      eng.rec["loads"] == [("default_model", None, "default_model"), ("other/x", None, "default_model")])
def models(handler_cls, path):
    h = handler_cls(path)
    h.handle_models_request()
    return h.status, h.wfile.getvalue()
st, body = models(Hd, "/v1/models")
check("alias.models  /v1/models lists the served name and nothing else",
      st == 200 and [d["id"] for d in json.loads(body)["data"]] == ["org/m"])
_, b1 = models(Hd, "/v1/models/org/m")
_, b2 = models(Hd, "/v1/models/other/x")
check("alias.modelsfilter  /v1/models/<id> finds the served name and no other",
      [d["id"] for d in json.loads(b1)["data"]] == ["org/m"] and json.loads(b2)["data"] == [])
eng.main()
host, port, rg, handler = eng.rec["http"]
check("alias.rank0  rank 0 serves HTTP through the aliased handler and provider",
      handler is Hd and isinstance(rg.model_provider, P) and rg.prompt_cache == ("cache", 3) and port == 8000)
eng = fake_engine()
eng.rec["rank"] = 1
ks.install_alias(eng, "org/m")
eng.main()
check("alias.rankn  every other rank joins the generator and serves no HTTP",
      eng.rec["joined"] and eng.rec["http"] is None)
eng = fake_engine()
_, Hn, _ = ks.install_alias(eng, None)
check("alias.none  without a served name the stock models listing answers", models(Hn, "/v1/models")[1] == b"upstream")
for label, drop, needle in (
        ("alias.failclosed.missing  an engine without _run_http_server ends the rank naming it",
         {"_run_http_server": None}, "_run_http_server"),
        ("alias.failclosed.signature  a ModelProvider.load with other parameters ends the rank naming it",
         {"ModelProvider.load": lambda self, model_path: None}, "ModelProvider.load")):
    eng = fake_engine(**drop)
    stock_run, stock_provider = eng.run, eng.ModelProvider
    try:
        ks.install_alias(eng, "org/m")
        check(label, False)
    except ks.ShardError as e:
        check(label, needle in str(e) and eng.run is stock_run and eng.ModelProvider is stock_provider)

# serve: the rendezvous environment is in place before the engine is imported,
# and the engine sees plan()'s argv (pipeline included) without the alias flag
saved = dict(os.environ)
seen = {}
def importer(name):
    seen["name"], seen["hostfile"] = name, os.environ.get("MLX_HOSTFILE")
    seen["eng"] = fake_engine()
    return seen["eng"]
served, rest = ks.split_served_name(["--model", "/snap", "--served-model-name", "org/m"])
files, cenv, cargv = ks.plan(env(K3SM_MLX_PARALLELISM="pipeline"), rest, resolver=resolver)
try:
    ks.serve(cenv, cargv, served, importer=importer)
finally:
    os.environ.clear()
    os.environ.update(saved)
check("serve.env  the engine is imported after MLX_HOSTFILE is set", seen["name"] == "mlx_lm.server"
      and seen["hostfile"] == cenv["MLX_HOSTFILE"])
check("serve.argv  main() sees the plan's argv, --pipeline kept, --served-model-name gone",
      seen["eng"].rec["argv"] == ["mlx_lm.server", "--host", "0.0.0.0", "--port", "8000", "--pipeline", "--model", "/snap"])

# the liveness probe against a local server
class H(http.server.BaseHTTPRequestHandler):
    code = 200
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        self.send_response(H.code if body.get("max_tokens") == 1 else 400)
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = str(srv.server_address[1])
check("probe.serving  a one-token completion answering 200 exits 0",
      ks.probe({"K3SM_MLX_SERVE_PORT": port}, timeout=5) == 0)
H.code = 500
check("probe.error  an error status exits 1", ks.probe({"K3SM_MLX_SERVE_PORT": port}, timeout=5) == 1)
srv.shutdown()
srv.server_close()
s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = str(s.getsockname()[1]); s.close()
check("probe.starting  a server not listening yet exits 0 (starting, not hung)",
      ks.probe({"K3SM_MLX_SERVE_PORT": closed}, timeout=5) == 0)
PY
SHARD_CHECKS=0
# stdout carries the verdicts; stderr (the probe's own diagnostics) is kept
# aside and shown only if the driver did not report every check.
shard_out="$(PYTHONDONTWRITEBYTECODE=1 python3 "$WORK/shard-driver.py" "$HERE" "$WORK/shard" 2>"$WORK/shard-driver.err")"
while read -r verdict name; do
	[ -n "$verdict" ] || continue
	SHARD_CHECKS=$((SHARD_CHECKS + 1))
	case "$verdict" in
		ok) ladder ok "7.$name" ;;
		no) ladder no "7.$name" ;;
		*)  ladder no "7.driver  $verdict $name" ;;
	esac
done <<< "$shard_out"
# A driver that crashed before its checks would otherwise pass vacuously.
if [ "$SHARD_CHECKS" -ge 33 ]; then
	ladder ok "7.count  all $SHARD_CHECKS entrypoint checks reported"
else
	ladder no "7.count  only $SHARD_CHECKS of 33 entrypoint checks reported (the driver crashed?)"
	head -20 "$WORK/shard-driver.err"
fi

# ---- 8 — the k3sm-serve context guard (single-node) --------------------------
# vllm-mlx 0.5.0 has no max-model-len and validates no prompt length; its only
# bound is --max-kv-size, a ROTATING cache, so an over-length request is served
# HTTP 200 on a context that lost its start. k3sm_serve refuses it with vLLM's
# HTTP 400 instead. Here against fakes of the server module and the engine:
# the rule, the four seams, the refusal body, and the fail-closed install.
SERVE="$HERE/k3sm_serve.py"
if [ -f "$SERVE" ] && PYTHONDONTWRITEBYTECODE=1 python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$SERVE" 2>/dev/null; then
	ladder ok "8.parse  k3sm_serve.py parses"
else
	ladder no "8.parse  k3sm_serve.py parses"
fi
if printf '%s' "$ep" | grep -qF '"k3sm_serve", "serve"' && grep -q '^SERVE_MODULE="k3sm_serve"$' "$BUILD" &&
	grep -qE '^	for module in .*SHARD_MODULE.*SERVE_MODULE' "$BUILD"; then
	ladder ok "8.entrypoint  the ENTRYPOINT runs vllm-mlx's serve through k3sm_serve, and build.sh installs it"
else
	ladder no "8.entrypoint  the ENTRYPOINT runs vllm-mlx's serve through k3sm_serve, and build.sh installs it"
fi

cat > "$WORK/serve-driver.py" <<'PY'
import asyncio, sys, types
sys.path.insert(0, sys.argv[1])
import k3sm_serve as ks

def check(name, cond):
    print(("ok " if cond else "no ") + name, flush=True)

def refused(fn):
    try:
        fn()
    except ks.ContextLengthExceeded as e:
        return e.message
    return None

R, D = ks.RequestedMaxTokens, ks.DefaultMaxTokens
check("rule.fit  a prompt and max_tokens inside the window run unchanged", ks.admit(900, R(64), 1024) == 64)
check("rule.edge  prompt + max_tokens == window still fits", ks.admit(960, R(64), 1024) == 64)
m = refused(lambda: ks.admit(1677, R(64), 1024))
check("rule.prompt  a prompt longer than the window is refused with vLLM's message",
      m is not None and m.startswith("This model's maximum context length is 1024 tokens.") and "1677 input tokens" in m)
check("rule.full  a prompt that fills the window is refused (no room to generate)",
      refused(lambda: ks.admit(1024, D(32768), 1024)) is not None)
m = refused(lambda: ks.admit(980, R(64), 1024))
check("rule.maxtokens  a client max_tokens that overruns the window is refused",
      m is not None and "'max_tokens' or 'max_completion_tokens' is too large: 64" in m and "(64 > 1024 - 980)" in m)
check("rule.default  an omitted max_tokens is clamped to the rest of the window", ks.admit(1000, D(32768), 1024) == 24)
check("rule.nowindow  no --max-kv-size, nothing guarded", ks.admit(10**6, R(64), 0) == 64)
check("window.batched  the batched engine's window is its scheduler's max_kv_size",
      ks.window_of(types.SimpleNamespace(_scheduler_config=types.SimpleNamespace(max_kv_size=1024))) == 1024)
check("window.unset  an engine with no max_kv_size has no window", ks.window_of(types.SimpleNamespace()) == 0)

class Tok:
    def encode(self, text):
        return text.split()
check("count.encode  tokens are counted with the tokenizer's encode", ks.count_tokens(Tok(), "a b c") == 3)
check("count.processor  a processor's inner tokenizer is used when it has no encode",
      ks.count_tokens(types.SimpleNamespace(tokenizer=Tok()), "a b") == 2)
body = ks.error_body("m")
check("body.shape  the refusal is vLLM's OpenAI error object",
      body == {"error": {"message": "m", "type": "BadRequestError", "param": None, "code": 400}})

class HTTPError(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code, self.detail = status_code, detail

class App:
    handlers = {}
    def add_exception_handler(self, cls, fn):
        App.handlers[cls] = fn

class Engine:
    def __init__(self, window):
        self._scheduler_config = types.SimpleNamespace(max_kv_size=window)
        self.tokenizer = Tok()
        self.ran = []
    def _apply_chat_template(self, messages, tools, num_images=0, num_audios=0, chat_template_kwargs=None,
                             enable_thinking=None):
        return " ".join("<%s> %s" % (m["role"], m["content"]) for m in messages) + " <assistant>"
    async def generate(self, prompt, max_tokens=256, **kw):
        self.ran.append(max_tokens)
        return "generated"

server = types.ModuleType("fake_server")
server.app = App()
server._resolve_request_max_tokens = lambda v: 32768 if v is None else v
server._prepare_chat_completion_invocation = lambda engine, request, mt: types.SimpleNamespace(
    messages=request["messages"], chat_kwargs={"max_tokens": mt})
server.stream_completion = lambda engine, prompt, request, mt, **kw: ("stream", mt)
server._prepare_anthropic_endpoint_invocation = lambda engine, request, mt: types.SimpleNamespace(
    messages=request["messages"], chat_kwargs={"max_tokens": mt})
CONVERSIONS = []
def to_chat_request(request):
    CONVERSIONS.append(1)
    return types.SimpleNamespace(messages=request["messages"], max_tokens=request.get("max_output_tokens"))
def prepare_responses(request, *, validate_remote_media=True):
    chat_request = server._responses_request_to_chat_request(request)
    return (server._engine, chat_request, chat_request.messages,
            {"max_tokens": chat_request.max_tokens or 32768})
server._responses_request_to_chat_request = to_chat_request
server._prepare_responses_request = prepare_responses
mmc = lambda messages: (None, [], [], [])
Refusal = ks.install(server, Engine, HTTPError, lambda status_code, content: (status_code, content), mmc, lambda t: t)

def refusal(fn):
    try:
        fn()
    except Refusal as e:
        return e
    return None

eng = Engine(64)
long, short = " ".join(["w"] * 70), " ".join(["w"] * 10)
msgs = lambda t: {"messages": [{"role": "user", "content": t}]}
res = server._resolve_request_max_tokens
check("seam.mark  the max_tokens seam marks the client's value and the default apart",
      type(res(8)) is ks.RequestedMaxTokens and type(res(None)) is ks.DefaultMaxTokens and res(None) == 32768)
e = refusal(lambda: server._prepare_chat_completion_invocation(eng, msgs(long), res(8)))
check("chat.over  an over-length chat request is refused with HTTP 400 (stream or not: before either path)",
      e is not None and e.status_code == 400 and "64 tokens" in e.detail and "72 input tokens" in e.detail)
p = server._prepare_chat_completion_invocation(eng, msgs(short), res(8))
check("chat.fit  an in-window chat request passes with its max_tokens", p.chat_kwargs["max_tokens"] == 8)
p = server._prepare_chat_completion_invocation(eng, msgs(short), res(None))
check("chat.default  an omitted max_tokens runs as the rest of the window (64 - 12)", p.chat_kwargs["max_tokens"] == 52)
check("chat.templated  the chat count is of the engine's templated prompt, not the raw text",
      refusal(lambda: server._prepare_chat_completion_invocation(eng, msgs(" ".join(["w"] * 60)), res(3))) is not None)
check("messages.over  an over-length /v1/messages request is refused with HTTP 400 (stream or not)",
      refusal(lambda: server._prepare_anthropic_endpoint_invocation(eng, msgs(long), res(8))) is not None)
p = server._prepare_anthropic_endpoint_invocation(eng, msgs(short), res(8))
check("messages.fit  an in-window /v1/messages request passes with its max_tokens", p.chat_kwargs["max_tokens"] == 8)
p = server._prepare_anthropic_endpoint_invocation(eng, msgs(short), res(None))
check("messages.default  an omitted max_tokens runs as the rest of the window (64 - 12)",
      p.chat_kwargs["max_tokens"] == 52)
server._engine = eng
resp = lambda t, mt=None: dict(msgs(t), max_output_tokens=mt)
check("responses.stream  an over-length /v1/responses request is refused at the conversion the streaming "
      "handler makes before its first SSE event",
      refusal(lambda: server._responses_request_to_chat_request(resp(long, 8))) is not None)
check("responses.streamfit  an in-window /v1/responses conversion returns the chat request",
      server._responses_request_to_chat_request(resp(short, 8)).max_tokens == 8)
check("responses.over  an over-length /v1/responses request is refused where its engine arguments are built",
      refusal(lambda: server._prepare_responses_request(resp(long, 8))) is not None)
CONVERSIONS.clear()
_, _, _, kw = server._prepare_responses_request(resp(short))
check("responses.default  an omitted max_output_tokens runs as the rest of the window (64 - 12)",
      kw["max_tokens"] == 52)
check("responses.once  the conversion inside the preparation is not checked a second time", CONVERSIONS == [1])
check("stream.over  an over-length streaming completion is refused before the stream starts",
      refusal(lambda: server.stream_completion(eng, long, {}, res(8))) is not None)
check("stream.fit  an in-window streaming completion streams", server.stream_completion(eng, short, {}, res(8)) == ("stream", 8))
run = lambda mt, prompt: asyncio.run(Engine.generate(eng, prompt=prompt, max_tokens=mt))
check("generate.over  an over-length completion is refused at the engine call",
      refusal(lambda: run(res(8), long)) is not None)
eng.ran.clear()
check("generate.fit  an in-window completion runs", run(res(8), short) == "generated" and eng.ran == [8])
eng.ran.clear()
run(res(None), short)
check("generate.default  an omitted max_tokens is clamped at the engine call (64 - 10)", eng.ran == [54])
eng.ran.clear()
run(100, long)
check("generate.checked  a value another seam already admitted is not checked twice", eng.ran == [100])
handler = App.handlers.get(Refusal)
status, content = asyncio.run(handler(None, Refusal("too long"))) if handler else (None, None)
check("handler.registered  the refusal answers 400 with the error object", status == 400 and content == ks.error_body("too long"))

broken = types.ModuleType("moved_server")
broken.app = App()
try:
    ks.install(broken, Engine, HTTPError, None, mmc, lambda t: t)
    check("install.failclosed  a moved seam ends the process instead of serving unguarded", False)
except ks.GuardError:
    check("install.failclosed  a moved seam ends the process instead of serving unguarded", True)
check("main.batching  serve without --continuous-batching is refused (the guard needs the batched engine)",
      ks.main(["serve", "/models/m"]) == 2)
PY
SERVE_CHECKS=0
serve_out="$(PYTHONDONTWRITEBYTECODE=1 python3 "$WORK/serve-driver.py" "$HERE" 2>"$WORK/serve-driver.err")"
while read -r verdict name; do
	[ -n "$verdict" ] || continue
	SERVE_CHECKS=$((SERVE_CHECKS + 1))
	case "$verdict" in
		ok) ladder ok "8.$name" ;;
		no) ladder no "8.$name" ;;
		*)  ladder no "8.driver  $verdict $name" ;;
	esac
done <<< "$serve_out"
if [ "$SERVE_CHECKS" -ge 34 ]; then
	ladder ok "8.count  all $SERVE_CHECKS guard checks reported"
else
	ladder no "8.count  only $SERVE_CHECKS of 34 guard checks reported (the driver crashed?)"
	head -20 "$WORK/serve-driver.err"
fi

# ---- 8k — --max-kv-size clamped to the model's KV geometry ------------------
# k3sm sizes --max-kv-size from a fixed 157286 KV bytes per token (a 3B model);
# a larger model costs more, so k3sm_serve lowers the pin at start from the
# model's config.json. Here against fake config.json files shaped like the real
# Qwen2.5-32B, Qwen2.5-3B, Llama-3.3-70B and Gemma 3 (text_config) ones, a fake
# Hub client and a fake engine CLI: no network, no engine.
cat > "$WORK/kv-driver.py" <<'PY'
import argparse, json, os, sys, types
sys.path.insert(0, sys.argv[1])
work = sys.argv[2]
import k3sm_serve as ks

def check(name, cond):
    print(("ok " if cond else "no ") + name, flush=True)

def config(name, **fields):
    d = os.path.join(work, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(fields, f)
    return d

Q32 = config("qwen2.5-32b", num_hidden_layers=64, num_attention_heads=40, num_key_value_heads=8, hidden_size=5120)
Q3 = config("qwen2.5-3b", num_hidden_layers=36, num_attention_heads=16, num_key_value_heads=2, hidden_size=2048)
L70 = config("llama-3.3-70b", num_hidden_layers=80, num_attention_heads=64, num_key_value_heads=8, head_dim=128,
             hidden_size=8192)
G27 = config("gemma-3-27b", model_type="gemma3", text_config={"num_hidden_layers": 62, "num_attention_heads": 32,
             "num_key_value_heads": 16, "head_dim": 128, "hidden_size": 5376})
NOFIELD = config("nolayers", num_attention_heads=40, num_key_value_heads=8, hidden_size=5120)
EMPTY = os.path.join(work, "no-config")
os.makedirs(EMPTY, exist_ok=True)

# A stand-in for vllm-mlx's serve parser: positional model, last --max-kv-size wins.
P = argparse.ArgumentParser()
P.add_argument("command")
P.add_argument("model", nargs="?")
P.add_argument("--max-kv-size", type=int)
P.add_argument("--host"); P.add_argument("--port"); P.add_argument("--max-num-seqs")
P.add_argument("--continuous-batching", action="store_true")
def parse(argv):
    a, _ = P.parse_known_args(argv)
    return a.model, a.max_kv_size

def argv(model, *tail, w="32768"):
    return ["serve", "--continuous-batching", "--host", "0.0.0.0", "--port", "8080", model, "--port", "8080",
            "--max-kv-size", w, "--max-num-seqs", "4", "--continuous-batching"] + list(tail)

def run(args, env=None):
    lines = []
    out = ks.clamp_max_kv_size(args, env or {}, parse=parse, say=lines.append)
    return out, lines

a = argv(Q32)
out, lines = run(a)
check("clamp.32b  a Qwen2.5-32B geometry (262144 B/token) lowers 32768 to floor(32768 x 157286 / 262144) = 19660",
      parse(out)[1] == 19660 and len(out) == len(a) and [t for t in out if t != "19660"] == [t for t in a if t != "32768"])
check("clamp.log  one line names W, the geometry, both figures and the clamped value",
      len(lines) == 1 and all(s in lines[0] for s in ("32768", "64 layers", "8 KV heads", "head_dim 128", "262144",
                                                       "157286", "19660")))
out, lines = run(argv(L70))
check("clamp.70b  a Llama-3.3-70B geometry with an explicit head_dim (327680 B/token) lowers 32768 to 15728",
      parse(out)[1] == 15728 and len(lines) == 1)
out, lines = run(argv(G27))
check("clamp.textconfig  a multimodal config's nested text_config is the geometry read (507904 B/token, 10147)",
      parse(out)[1] == 10147 and "62 layers" in lines[0])
a = argv(Q3)
out, lines = run(a)
check("noclamp.3b  a Qwen2.5-3B geometry (36864 B/token) leaves W alone, silently", out == a and lines == [])
a = argv(EMPTY)
out, lines = run(a)
check("missing.config  a model with no config.json leaves W alone, with one line", out == a and len(lines) == 1)
a = argv(NOFIELD)
out, lines = run(a)
check("missing.field  a config without num_hidden_layers leaves W alone, with one line",
      out == a and len(lines) == 1 and "num_hidden_layers" in lines[0])
a = argv(Q32)
out, lines = run(a, {"K3SM_KV_GEOMETRY_CLAMP": "off"})
check("off  K3SM_KV_GEOMETRY_CLAMP=off leaves W alone", out == a and len(lines) == 1)
out, lines = run(a, {"K3SM_KV_BYTES_PER_TOKEN": "262144"})
check("assumed.env  K3SM_KV_BYTES_PER_TOKEN is the assumed figure (sized for 262144: no clamp)", out == a and lines == [])
out, lines = run(a, {"K3SM_KV_BYTES_PER_TOKEN": "lots"})
check("assumed.bad  an unparsable K3SM_KV_BYTES_PER_TOKEN leaves W alone, with one line", out == a and len(lines) == 1)
out, _ = run(argv(Q32, w="2048"), {"K3SM_KV_BYTES_PER_TOKEN": "1000"})
check("floor  the clamp never goes below 1024", parse(out)[1] == 1024)
a = argv(Q32, w="512")
out, _ = run(a, {"K3SM_KV_BYTES_PER_TOKEN": "1000"})
check("floor.noraise  a W already under 1024 is never raised", out == a)
a = argv(Q32, "--max-kv-size", "16384")
out, _ = run(a)
check("override.last  the operator's later --max-kv-size is the W clamped (16384 -> 9830)", parse(out)[1] == 9830)
a = [t for t in argv(Q32) if t not in ("--max-kv-size", "32768")] + ["--max-kv-size=32768"]
out, _ = run(a)
check("equals  a --max-kv-size=W spelling is rewritten in place", out[-1] == "--max-kv-size=19660" and len(out) == len(a))
a = [t for t in argv(Q32) if t not in ("--max-kv-size", "32768")]
out, lines = run(a)
check("nokv  no --max-kv-size, nothing read or said", out == a and lines == [])
out, _ = run(argv("Qwen/Qwen2.5-32B-Instruct"), {"K3SM_MODEL_CONFIG_DIR": Q32})
check("configdir  K3SM_MODEL_CONFIG_DIR is read instead of the model reference", parse(out)[1] == 19660)

calls = []
hub = types.ModuleType("huggingface_hub")
def snapshot_download(repo, **kw):
    calls.append((repo, kw))
    return Q32
hub.snapshot_download = snapshot_download
sys.modules["huggingface_hub"] = hub
out, _ = run(argv("Qwen/Qwen2.5-32B-Instruct"))
check("hub  a Hub reference fetches only config.json with snapshot_download, into the default cache",
      calls == [("Qwen/Qwen2.5-32B-Instruct", {"allow_patterns": ["config.json"]})] and parse(out)[1] == 19660)
def unreachable(repo, **kw):
    raise OSError("offline")
hub.snapshot_download = unreachable
a = argv("Qwen/Qwen2.5-32B-Instruct")
out, lines = run(a)
check("hub.down  a Hub fetch that fails leaves W alone, with one line", out == a and len(lines) == 1)

seen = []
cli = types.ModuleType("vllm_mlx.cli")
cli.main = lambda: seen.append(list(sys.argv))
pkg = types.ModuleType("vllm_mlx")
pkg.cli = cli
sys.modules["vllm_mlx"], sys.modules["vllm_mlx.cli"] = pkg, cli
ks.engine_serve_args = parse
ks.install_on_engine = lambda: None
os.environ.pop("K3SM_KV_GEOMETRY_CLAMP", None)
os.environ.pop("K3SM_KV_BYTES_PER_TOKEN", None)
os.environ.pop("K3SM_MODEL_CONFIG_DIR", None)
rc = ks.main(argv(Q32))
check("main  serve hands the engine the clamped argv", rc == 0 and len(seen) == 1 and parse(seen[0][1:])[1] == 19660)
PY
KV_CHECKS=0
kv_out="$(PYTHONDONTWRITEBYTECODE=1 python3 "$WORK/kv-driver.py" "$HERE" "$WORK/kv" 2>"$WORK/kv-driver.err")"
while read -r verdict name; do
	[ -n "$verdict" ] || continue
	KV_CHECKS=$((KV_CHECKS + 1))
	case "$verdict" in
		ok) ladder ok "8k.$name" ;;
		no) ladder no "8k.$name" ;;
		*)  ladder no "8k.driver  $verdict $name" ;;
	esac
done <<< "$kv_out"
if [ "$KV_CHECKS" -ge 19 ]; then
	ladder ok "8k.count  all $KV_CHECKS clamp checks reported"
else
	ladder no "8k.count  only $KV_CHECKS of 19 clamp checks reported (the driver crashed?)"
	head -20 "$WORK/kv-driver.err"
fi

# ---- 9 — the guard on the REAL engine (needs a staged tree) -----------------
# The seams above are vllm-mlx 0.5.0's own functions; this rung installs the
# guard on the real server module and drives its real HTTP app (a fake engine
# under it: no model, no GPU), so an engine bump that moves a seam is caught
# here before an image is built. It needs the tree build.sh stages.
STAGED="${K3SM_MLX_STAGE:-${K3SM_MLX_WORK:-$HOME/.cache/k3sm/mlx-serve}/stage}"
if [ -x "$STAGED/bin/python3.12" ] && [ -d "$STAGED/lib/python3.12/site-packages/vllm_mlx" ]; then
	cat > "$WORK/serve-real.py" <<'PY'
import sys, types
sys.path.insert(0, sys.argv[1])
import logging
logging.disable(logging.WARNING)
import k3sm_serve as ks
from fastapi.testclient import TestClient
from vllm_mlx import server
from vllm_mlx.engine.batched import BatchedEngine

ks.install_on_engine()

class Tok:
    def encode(self, text):
        return text.split()
    def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=True, **kw):
        return " ".join("<%s> %s" % (m["role"], m["content"]) for m in messages) + " <assistant>"

class Out:
    def __init__(self, prompt):
        self.output_text = self.new_text = "ok"
        self.output_token_ids = [1]
        self.prompt_tokens, self.completion_tokens = len(prompt.split()), 1
        self.finish_reason, self.finished = "stop", True

RAN = []
class Core:
    async def generate(self, prompt, sampling_params):
        RAN.append(sampling_params.max_tokens)
        return Out(prompt)
    async def add_request(self, prompt, sampling_params, prefix_boundary=0):
        RAN.append(sampling_params.max_tokens)
        self.prompt = prompt
        return "r"
    async def stream_outputs(self, request_id):
        yield Out(self.prompt)

class Engine(BatchedEngine):
    def __init__(self, window):
        self._scheduler_config = types.SimpleNamespace(max_kv_size=window)
        self._tokenizer, self._is_mllm, self._processor = Tok(), False, None
        self._model_name, self._loaded, self._engine, self._mllm_scheduler = "fake", True, Core(), None

engine = Engine(64)
server._engine = engine
async def acquire(raw_request, **kw):
    return engine
async def release(raw_request):
    return None
server._acquire_default_engine_for_request = acquire
server._release_engine_for_request = release
server._validate_model_name = lambda model: None
client = TestClient(server.app)
long, short = " ".join(["w"] * 70), " ".join(["w"] * 10)

def post(path, **body):
    body.setdefault("model", "fake")
    return client.post(path, json=body)

def check(name, r, want, text=None):
    ok = r.status_code == want and (text is None or text in r.text)
    print(("ok " if ok else "no ") + "%s (HTTP %d)" % (name, r.status_code), flush=True)

def refused_unstreamed(name, r):
    # A refusal is the JSON error object and nothing else: no SSE event was
    # written before it, and the engine never ran.
    ok = (r.status_code == 400 and r.headers.get("content-type", "").startswith("application/json")
          and r.json().get("error", {}).get("type") == "BadRequestError"
          and "maximum context length is 64 tokens" in r.json()["error"]["message"]
          and "event:" not in r.text and "data:" not in r.text and RAN == [])
    print(("ok " if ok else "no ") + "%s (HTTP %d, %s)" % (name, r.status_code, r.headers.get("content-type")),
          flush=True)

chat = lambda t: [{"role": "user", "content": t}]
for stream in (False, True):
    tag = "stream" if stream else "plain"
    check("real.chat.over.%s  /v1/chat/completions over the window answers 400" % tag,
          post("/v1/chat/completions", messages=chat(long), max_tokens=8, stream=stream), 400,
          "This model's maximum context length is 64 tokens")
    check("real.chat.fit.%s  /v1/chat/completions inside the window answers 200" % tag,
          post("/v1/chat/completions", messages=chat(short), max_tokens=8, stream=stream), 200)
    check("real.cmpl.over.%s  /v1/completions over the window answers 400" % tag,
          post("/v1/completions", prompt=long, max_tokens=8, stream=stream), 400, '"type":"BadRequestError"')
    check("real.cmpl.fit.%s  /v1/completions inside the window answers 200" % tag,
          post("/v1/completions", prompt=short, max_tokens=8, stream=stream), 200)
for stream in (False, True):
    tag = "stream" if stream else "plain"
    RAN.clear()
    refused_unstreamed("real.msgs.over.%s  /v1/messages over the window answers 400 before any SSE byte" % tag,
                       post("/v1/messages", messages=chat(long), max_tokens=8, stream=stream))
    check("real.msgs.fit.%s  /v1/messages inside the window answers 200" % tag,
          post("/v1/messages", messages=chat(short), max_tokens=8, stream=stream), 200)
    RAN.clear()
    refused_unstreamed("real.resp.over.%s  /v1/responses over the window answers 400 before any SSE byte" % tag,
                       post("/v1/responses", input=long, max_output_tokens=8, stream=stream))
    check("real.resp.fit.%s  /v1/responses inside the window answers 200" % tag,
          post("/v1/responses", input=short, max_output_tokens=8, stream=stream), 200)
RAN.clear()
post("/v1/chat/completions", messages=chat(short))
post("/v1/completions", prompt=short)
post("/v1/responses", input=short)
print(("ok " if RAN[:2] == [52, 54] and len(RAN) == 3 and 0 < RAN[2] < 64 else "no ")
      + "real.default  an omitted max_tokens runs as the rest of the window %r" % RAN)
PY
	REAL_CHECKS=0
	real_out="$(cd "$WORK" && PYTHONDONTWRITEBYTECODE=1 "$STAGED/bin/python3.12" -I -B "$WORK/serve-real.py" "$HERE" 2>"$WORK/serve-real.err")"
	while read -r verdict name; do
		[ -n "$verdict" ] || continue
		REAL_CHECKS=$((REAL_CHECKS + 1))
		case "$verdict" in
			ok) ladder ok "9.$name" ;;
			no) ladder no "9.$name" ;;
			*)  ladder no "9.driver  $verdict $name" ;;
		esac
	done <<< "$real_out"
	if [ "$REAL_CHECKS" -ge 17 ]; then
		ladder ok "9.count  all $REAL_CHECKS real-engine checks reported"
	else
		ladder no "9.count  only $REAL_CHECKS of 17 real-engine checks reported (the driver crashed?)"
		tail -20 "$WORK/serve-real.err"
	fi
else
	ladder skip "9.real  no staged tree at $STAGED (run build.sh, or set K3SM_MLX_STAGE)"
fi

# ---- 9s — the attention-sink mask on the REAL mlx-lm cache (staged tree) ----
# mlx-lm 0.32.0's RotatingKVCache keeps its first `keep` tokens as attention
# sinks, but its prefill mask is a plain sliding window: once the cache has
# trimmed, every query row masks the sink columns out (the upstream defect,
# shown red here first). k3sm_serve patches make_mask; this rung drives the
# pinned mlx-lm's own cache through a chunked prefill past its window and
# checks, row by row, that each query sees the sinks plus exactly the
# max_size - keep most recent tokens, which is what a decode step sees.
if [ -x "$STAGED/bin/python3.12" ] && [ -d "$STAGED/lib/python3.12/site-packages/mlx_lm" ]; then
	cat > "$WORK/sink-real.py" <<'PY'
import sys, types
sys.path.insert(0, sys.argv[1])
import mlx.core as mx
from mlx_lm.models.cache import RotatingKVCache, make_prompt_cache
import k3sm_serve as ks

W, KEEP = 16, 4

def check(name, cond):
    print(("ok " if cond else "no ") + name, flush=True)

def rows_seen(size, keep, history, step, n, window=None, return_array=False):
    """Prefill `history` ids in chunks of `step`, then n more; the ids each new row sees."""
    cache = RotatingKVCache(max_size=size, keep=keep)
    for start in range(0, history, step):
        kv = mx.arange(start, min(start + step, history)).reshape(1, 1, -1, 1)
        cache.update_and_fetch(kv, kv)
    mask = cache.make_mask(n, window, return_array)
    kv = mx.arange(history, history + n).reshape(1, 1, n, 1)
    keys, _ = cache.update_and_fetch(kv, kv)
    ids = keys[0, 0, :, 0].tolist()
    rows = None if isinstance(mask, str) else mask.tolist()
    seen = []
    for row in range(n):
        end = history + row + 1
        seen.append(sorted(t for col, t in enumerate(ids) if (t < end if rows is None else rows[row][col])))
    return seen, rows

def decode_view(size, keep, end):
    return list(range(min(keep, end))) + list(range(max(keep, end - (size - keep)), end))

check("sink.target  make_prompt_cache(model, max_kv_size) builds RotatingKVCache with keep=4",
      [c.keep for c in make_prompt_cache(types.SimpleNamespace(layers=[0]), max_kv_size=W)] == [KEEP])

_, rows = rows_seen(W, KEEP, 40, 8, 8)
check("sink.upstream  unpatched, a trimmed cache's prefill mask hides the sink columns (the defect is real)",
      rows is not None and not all(all(r[:KEEP]) for r in rows))

original = RotatingKVCache.make_mask
classes = ks.rotating_cache_classes()
ks.patch_rotating_kv_cache(classes, mx)
check("sink.patched  RotatingKVCache.make_mask is replaced", RotatingKVCache.make_mask is not original)
ks.patch_rotating_kv_cache(classes, mx)
check("sink.idempotent  a second patch does not wrap the first",
      RotatingKVCache.make_mask.__defaults__[-1] is original)

seen, rows = rows_seen(W, KEEP, 40, 8, 8)
check("sink.columns  after a trim, columns 0..3 are unmasked for every query row",
      rows is not None and all(all(r[:KEEP]) for r in rows))
check("sink.window  every row sees the sinks and the max_size - keep most recent tokens, as decode does",
      all(seen[r] == decode_view(W, KEEP, 40 + r + 1) for r in range(8)))

ok = True
for size in (4, 8, 16):
    for keep in sorted({1, min(4, size - 1), size - 1}):
        for history in (0, size - 1, size, 2 * size + 3):
            for step in (1, size + 1):
                for n in (2, size + 2):
                    for ra in (False, True):
                        seen, _ = rows_seen(size, keep, history, step, n, None, ra)
                        ok = ok and all(seen[r] == decode_view(size, keep, history + r + 1) for r in range(n))
check("sink.sweep  the same holds across sizes, keeps, histories, chunk sizes and return_array", ok)

same = True
for keep, window in ((0, None), (0, 8), (KEEP, 8)):
    for history in (0, 9, 40):
        cache = RotatingKVCache(max_size=W, keep=keep)
        for start in range(0, history, 8):
            kv = mx.arange(start, min(start + 8, history)).reshape(1, 1, -1, 1)
            cache.update_and_fetch(kv, kv)
        a, b = cache.make_mask(6, window, True), original(cache, 6, window, True)
        same = same and mx.array_equal(a, b).item()
check("sink.unchanged  keep=0, or an explicit window other than the cache size, builds upstream's mask", same)

try:
    from mlx_vlm.models.cache import RotatingKVCache as VLM
    check("sink.vlm  mlx-vlm's copy of RotatingKVCache is patched too",
          VLM in classes and getattr(VLM.make_mask, ks.SINK_PATCHED, False))
except ImportError:
    check("sink.vlm  mlx-vlm is not installed; only mlx-lm's cache is patched", classes == [RotatingKVCache])

class Moved:
    def make_mask(self, N):
        return None
try:
    ks.patch_rotating_kv_cache([Moved], mx)
    check("sink.failclosed  a make_mask with another signature ends the process", False)
except ks.GuardError:
    check("sink.failclosed  a make_mask with another signature ends the process", True)
PY
	SINK_CHECKS=0
	sink_out="$(cd "$WORK" && PYTHONDONTWRITEBYTECODE=1 "$STAGED/bin/python3.12" -I -B "$WORK/sink-real.py" "$HERE" 2>"$WORK/sink-real.err")"
	while read -r verdict name; do
		[ -n "$verdict" ] || continue
		SINK_CHECKS=$((SINK_CHECKS + 1))
		case "$verdict" in
			ok) ladder ok "9s.$name" ;;
			no) ladder no "9s.$name" ;;
			*)  ladder no "9s.driver  $verdict $name" ;;
		esac
	done <<< "$sink_out"
	if [ "$SINK_CHECKS" -ge 10 ]; then
		ladder ok "9s.count  all $SINK_CHECKS sink-mask checks reported"
	else
		ladder no "9s.count  only $SINK_CHECKS of 10 sink-mask checks reported (the driver crashed?)"
		tail -20 "$WORK/sink-real.err"
	fi
else
	ladder skip "9s.real  no staged tree at $STAGED (run build.sh, or set K3SM_MLX_STAGE)"
fi

# ---- 9a — the served-name alias against the pinned mlx-lm (staged tree) ------
# k3sm_shard's alias hooks four mlx_lm.server internals; this rung checks them
# on the real module the image carries, so an mlx-lm bump that moves one goes
# red here before a rank refuses to start.
if [ -x "$STAGED/bin/python3.12" ] && [ -d "$STAGED/lib/python3.12/site-packages/mlx_lm" ]; then
	alias_out="$(cd "$WORK" && PYTHONDONTWRITEBYTECODE=1 "$STAGED/bin/python3.12" -I -B -c '
import sys
sys.path.insert(0, sys.argv[1])
import importlib, k3sm_shard as ks
server = importlib.import_module(ks.ENGINE_MODULE)
ks.check_engine_hooks(server)
P, H, run = ks.install_alias(server, "org/m")
ok = server.run is run and server.ModelProvider is P and issubclass(H, server.APIHandler)
print("ok" if ok else "no")
' "$HERE" 2>"$WORK/alias-real.err")"
	if [ "$alias_out" = "ok" ]; then
		ladder ok "9a.hooks  the pinned mlx_lm.server has every hook the served-name alias uses, and it installs"
	else
		ladder no "9a.hooks  the pinned mlx_lm.server has every hook the served-name alias uses, and it installs"
		tail -5 "$WORK/alias-real.err"
	fi
else
	ladder skip "9a.real  no staged tree at $STAGED (run build.sh, or set K3SM_MLX_STAGE)"
fi

# ---- 10 — the stage Job (stage-job.sh render) --------------------------------
# A golden check of what the cluster is asked to run. The uv pin is repeated
# here, independently of stage-job.sh, so an edited pin goes red until it is
# re-checked against the release's published sha256 and edited here too.
STAGEJOB="$HERE/stage-job.sh"
GOLD_UV_VERSION="0.12.7"
GOLD_UV_SHA256="127ebdda7ad953cdf198e964b570ea5771b85467ea93eb7cb6d6f8e6f55408f3"
GOLD_UV_URL="https://github.com/astral-sh/uv/releases/download/$GOLD_UV_VERSION/uv-aarch64-apple-darwin.tar.gz"
GOLD_NODE="k3sm-golden"
RJ="$WORK/stage-job.yaml"

if "$STAGEJOB" render > /dev/null 2>&1; then
	ladder no "10.nonode  render refuses to run without --node"
else
	ladder ok "10.nonode  render refuses to run without --node"
fi
if "$STAGEJOB" render --node "$GOLD_NODE" > "$RJ" 2>/dev/null && [ -s "$RJ" ]; then
	ladder ok "10.render  stage-job.sh render --node emits the manifests"
else
	ladder no "10.render  stage-job.sh render --node emits the manifests"
fi

kinds="$(grep -E '^kind: ' "$RJ" | awk '{print $2}' | tr '\n' ' ')"
if [ "$kinds" = "Namespace PersistentVolumeClaim ConfigMap Job " ]; then
	ladder ok "10.kinds  a Namespace, the stage claim, the source ConfigMap and the Job, nothing else"
else
	ladder no "10.kinds  a Namespace, the stage claim, the source ConfigMap and the Job, nothing else (got: $kinds)"
fi

# The pins and digests the Job carries.
envval() { awk -v n="$1" '$0 ~ "- name: " n "$" { getline; sub(/^ *value: /, ""); gsub(/"/, ""); print; exit }' "$RJ"; }
if [ "$(envval UV_VERSION)" = "$GOLD_UV_VERSION" ] && [ "$(envval UV_SHA256)" = "$GOLD_UV_SHA256" ] &&
	[ "$(envval UV_URL)" = "$GOLD_UV_URL" ]; then
	ladder ok "10.uvpin  uv $GOLD_UV_VERSION, its release URL and its published sha256"
else
	ladder no "10.uvpin  uv $GOLD_UV_VERSION, its release URL and its published sha256"
fi
if grep -qx "UV_MIN=\"$GOLD_UV_VERSION\"" "$BUILD"; then
	ladder ok "10.uvmin  the Job's uv is the uv build.sh pins the lockfile and interpreter to"
else
	ladder no "10.uvmin  the Job's uv is the uv build.sh pins the lockfile and interpreter to"
fi
if [ "$(envval LOCK_SHA256)" = "$(shasum -a 256 "$LOCK" | awk '{print $1}')" ]; then
	ladder ok "10.lockdigest  LOCK_SHA256 is requirements.lock's sha256"
else
	ladder no "10.lockdigest  LOCK_SHA256 is requirements.lock's sha256"
fi

# The ConfigMap carries the checkout's files byte for byte, and the entry script.
cm_out="$(python3 - "$RJ" "$HERE" "$WORK/entry" <<'PY'
import json, os, re, sys
rendered, here, entry_dir = sys.argv[1:]
data, in_cm = {}, False
for line in open(rendered):
    if line.startswith("kind: "):
        in_cm = line.strip() == "kind: ConfigMap"
    m = re.match(r'^  ([A-Za-z0-9._-]+): (".*")$', line.rstrip("\n"))
    if in_cm and m:
        data[m.group(1)] = json.loads(m.group(2))
for name in ("build.sh", "requirements.lock", "k3sm_shard.py", "k3sm_serve.py"):
    ok = name in data and data[name] == open(os.path.join(here, name)).read()
    print(("ok " if ok else "no ") + "bytes." + name)
print(("ok " if set(data) == {"build.sh", "requirements.lock", "k3sm_shard.py", "k3sm_serve.py", "stage-entry.sh"} else "no ") + "keys")
os.makedirs(entry_dir, exist_ok=True)
open(os.path.join(entry_dir, "stage-entry.sh"), "w").write(data.get("stage-entry.sh", ""))
PY
)"
while read -r verdict name; do
	[ -n "$verdict" ] || continue
	case "$verdict" in
		ok) ladder ok "10.cm.$name  the ConfigMap carries it verbatim" ;;
		*)  ladder no "10.cm.$name  the ConfigMap carries it verbatim" ;;
	esac
done <<< "$cm_out"

# The entry script checks both digests before it runs anything, then stages
# with build.sh --stage-only (the same checks as a host build).
ENTRY="$WORK/entry/stage-entry.sh"
lock_line="$(grep -n 'LOCK_SHA256.*shasum -a 256 -c' "$ENTRY" | cut -d: -f1 | head -1)"
uv_line="$(grep -n 'UV_SHA256.*shasum -a 256 -c' "$ENTRY" | cut -d: -f1 | head -1)"
tar_line="$(grep -n 'tar -xzf' "$ENTRY" | cut -d: -f1 | head -1)"
build_line="$(grep -n 'build.sh" --stage-only' "$ENTRY" | cut -d: -f1 | head -1)"
if [ -n "$lock_line" ] && [ -n "$uv_line" ] && [ -n "$tar_line" ] && [ -n "$build_line" ] &&
	[ "$uv_line" -lt "$tar_line" ] && [ "$lock_line" -lt "$build_line" ] && grep -q '^set -euo pipefail$' "$ENTRY"; then
	ladder ok "10.entry  the lock and uv digests are checked (set -e) before uv is unpacked and build.sh --stage-only runs"
else
	ladder no "10.entry  the lock and uv digests are checked (set -e) before uv is unpacked and build.sh --stage-only runs"
fi
# Fail closed, run for real: a lockfile that does not match the rendered digest
# stops the entry script before anything is downloaded.
FAKEROOT="$WORK/fakepod"; mkdir -p "$FAKEROOT/src" "$FAKEROOT/stage"
cp "$ENTRY" "$BUILD" "$HERE/k3sm_shard.py" "$HERE/k3sm_serve.py" "$FAKEROOT/src/"
printf 'tampered==1.0 \\\n    --hash=sha256:aaa\n' > "$FAKEROOT/src/requirements.lock"
( cd "$FAKEROOT" && env -i PATH=/usr/bin:/bin UV_VERSION="$GOLD_UV_VERSION" UV_URL="https://invalid.example/uv.tar.gz" \
	UV_SHA256="$GOLD_UV_SHA256" LOCK_SHA256="$(envval LOCK_SHA256)" /bin/bash ./src/stage-entry.sh ) >/dev/null 2>&1; rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$FAKEROOT/work/dl/uv.tar.gz" ] && [ ! -e "$FAKEROOT/stage/stage" ]; then
	ladder ok "10.failclosed  a lockfile that does not match LOCK_SHA256 stops the Job before any download (exit $rc)"
else
	ladder no "10.failclosed  a lockfile that does not match LOCK_SHA256 stops the Job before any download (exit $rc)"
fi

# No credential reaches the pod: no Secret, no token, no pull secret.
if ! grep -qiE 'secret|serviceAccountName|imagePullSecrets|envFrom|token|password|credential|registry|docker' \
	<(grep -vE '^  (build\.sh|requirements\.lock|k3sm_shard\.py|k3sm_serve\.py|stage-entry\.sh): ' "$RJ" |
		grep -vx '      automountServiceAccountToken: false') &&
	grep -qx '      automountServiceAccountToken: false' "$RJ"; then
	ladder ok "10.nocred  no Secret, token, pull secret or registry reference; the service-account token is not mounted"
else
	ladder no "10.nocred  no Secret, token, pull secret or registry reference; the service-account token is not mounted"
fi
if ! grep -qiE 'token|password|registry|ghcr|push' "$ENTRY"; then
	ladder ok "10.nocred.entry  the entry script names no credential and pushes nothing"
else
	ladder no "10.nocred.entry  the entry script names no credential and pushes nothing"
fi

# Placement: a nodeSelector (the scheduler binds the WaitForFirstConsumer
# claim), never nodeName (which skips the scheduler and leaves it Pending).
if grep -qx '        kubernetes.io/os: darwin' "$RJ" && grep -qx "        kubernetes.io/hostname: $GOLD_NODE" "$RJ" &&
	! grep -q 'nodeName' "$RJ"; then
	ladder ok "10.placement  nodeSelector darwin + hostname $GOLD_NODE, no nodeName"
else
	ladder no "10.placement  nodeSelector darwin + hostname $GOLD_NODE, no nodeName"
fi
tol="$(awk '/^      tolerations:$/ { on = 1; next } on && /^      [a-z]/ { on = 0 } on' "$RJ")"
want_tol="$(printf '        - key: k3sm.io/provider\n          operator: Exists\n          effect: NoSchedule')"
if [ "$tol" = "$want_tol" ]; then
	ladder ok "10.toleration  exactly the provider toleration (NoSchedule), as product pods carry it"
else
	ladder no "10.toleration  exactly the provider toleration (NoSchedule), as product pods carry it"
fi
if grep -qx '          image: native' "$RJ" && grep -qxF '          command: ["/bin/bash", "./src/stage-entry.sh"]' "$RJ" &&
	grep -qx '  backoffLimit: 0' "$RJ" && grep -qx '      restartPolicy: Never' "$RJ" &&
	grep -qx '  storageClassName: local-path' "$RJ"; then
	ladder ok "10.shape  a native pod, run once, its stage on a local-path claim"
else
	ladder no "10.shape  a native pod, run once, its stage on a local-path claim"
fi

# ---- 11 — build.sh --from-stage (package the stage Job's volume) -------------
# The precompile runs serially: -j 0 needs a POSIX semaphore, which the pod
# sandbox refuses, and a failed precompile must reach assert_precompiled.
if grep -qE -- '-m compileall .*-j 1 ' "$BUILD" && ! grep -qE -- '-m compileall .*-j 0' "$BUILD" &&
	grep -q '^assert_precompiled$' "$BUILD" && ! grep -qE 'compileall.*>/dev/null 2>&1' "$BUILD"; then
	ladder ok "11.serial  build.sh precompiles with -j 1, keeps its output, and asserts the result on both paths"
else
	ladder no "11.serial  build.sh precompiles with -j 1, keeps its output, and asserts the result on both paths"
fi
# A fake stage and a fake k3sm: what is proven is the mode's contract (the
# guards, no uv, the packaging argv), not a real build.
PY_KEY_GOLD="$(sed -n 's/^PY_KEY="\(.*\)"$/\1/p' "$BUILD")"
PV="$WORK/pv"
mkstage() {
	rm -rf "$PV"; mkdir -p "$PV/stage/bin" "$PV/stage/lib/python3.12/site-packages"
	# The interpreter build.sh runs to check the precompile: the host's python3.
	printf '#!/bin/sh\nexec python3 "$@"\n' > "$PV/stage/bin/python3.12"
	chmod +x "$PV/stage/bin/python3.12"
	cp "$HERE/k3sm_shard.py" "$HERE/k3sm_serve.py" "$PV/stage/lib/python3.12/site-packages/"
	echo "$PY_KEY_GOLD $(shasum -a 256 "$LOCK" | awk '{print $1}')" > "$PV/stage.stamp"
}
FAKEK3SM="$WORK/fake-k3sm"
cat > "$FAKEK3SM" <<'FAKE'
#!/bin/bash
# Records its argv and writes the one file build.sh reads back from a layout.
printf '%s\n' "$@" > "$FAKE_ARGV"
out=""
while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done
mkdir -p "$out"
printf '{"manifests":[{"digest":"sha256:%064d"}]}\n' 0 > "$out/index.json"
FAKE
chmod +x "$FAKEK3SM"
fromstage() {
	rm -f "$WORK/fake-argv"
	FAKE_ARGV="$WORK/fake-argv" K3SM_MLX_UV=/nonexistent/uv K3SM_BIN="$FAKEK3SM" \
		"$BUILD" --work "$WORK/pkg" --no-verify "$@" 2>&1
}

mkstage
out="$(fromstage --from-stage "$PV/stage")"; rc=$?
if [ "$rc" -eq 0 ] && [ -f "$WORK/fake-argv" ] &&
	[ "$(head -2 "$WORK/fake-argv" | tr '\n' ' ')" = "build --no-record " ] &&
	[ "$(tail -1 "$WORK/fake-argv")" = "$PV/stage" ] &&
	grep -qx -- '--output' "$WORK/fake-argv"; then
	ladder ok "11.package  --from-stage packages the volume's stage with k3sm build --no-record --output, with no uv"
else
	ladder no "11.package  --from-stage packages the volume's stage with k3sm build --no-record --output, with no uv (exit $rc)"
	printf '%s\n' "$out" | tail -5
fi

refused() { # <label> <expected message> <build.sh args...>
	local label="$1" msg="$2"; shift 2
	out="$(fromstage "$@")"; rc=$?
	if [ "$rc" -ne 0 ] && [ ! -f "$WORK/fake-argv" ] && printf '%s' "$out" | grep -q -- "$msg"; then
		ladder ok "11.$label  refused before packaging (exit $rc)"
	else
		ladder no "11.$label  refused before packaging (exit $rc)"
		printf '%s\n' "$out" | tail -3
	fi
}
mkstage; echo "$PY_KEY_GOLD 0000" > "$PV/stage.stamp"
refused "stalestamp  a stage made from other pins is" "other pins" --from-stage "$PV/stage"
mkstage; rm -f "$PV/stage.stamp"
refused "nostamp  a stage without build.sh's stamp is" "no stamp" --from-stage "$PV/stage"
mkstage; echo "# drift" >> "$PV/stage/lib/python3.12/site-packages/k3sm_shard.py"
refused "shard  a stage whose k3sm_shard.py differs from the checkout's is" "k3sm_shard.py differs" --from-stage "$PV/stage"
mkstage; echo "# drift" >> "$PV/stage/lib/python3.12/site-packages/k3sm_serve.py"
refused "serve  a stage whose k3sm_serve.py differs from the checkout's is" "k3sm_serve.py differs" --from-stage "$PV/stage"
mkstage; rm -f "$PV/stage/bin/python3.12"
refused "nointerp  a stage without the interpreter is" "no interpreter" --from-stage "$PV/stage"
mkstage; echo x > "$PV/stage/secret.txt"; chmod 000 "$PV/stage/secret.txt"
if [ -r "$PV/stage/secret.txt" ]; then
	ladder skip "11.unreadable  running as root; every file is readable"
else
	refused "unreadable  a stage with a file the packaging user cannot read is" "UNREADABLE" --from-stage "$PV/stage"
fi
chmod 600 "$PV/stage/secret.txt" 2>/dev/null
# The stage Job once staged a tree with almost no bytecode (the sandbox
# refused compileall's process pool) and nothing noticed. More than a handful of
# modules without a .pyc is now a refusal, wherever the stage was made.
mkstage; for i in 1 2 3 4 5 6; do echo "x = $i" > "$PV/stage/lib/python3.12/site-packages/m$i.py"; done
refused "precompile  a stage with more than a handful of uncompiled modules is" "the precompile step failed" --from-stage "$PV/stage"
mkstage
refused "exclusive  --from-stage with --stage-only is" "opposite halves" --from-stage "$PV/stage" --stage-only
refused "nostage  --from-stage with --stage is" "drop --stage" --from-stage "$PV/stage" --stage "$PV/stage"

# ---- summary ----------------------------------------------------------------
echo "----------------------------------------"
echo "mlx-serve selftest: $PASS passed, $FAIL failed, $SKIP skipped"
cat <<'EOF'

Not covered here — this needs a Mac with uv, a k3sm binary and the network:
  * the stage Job on a cluster (egress, the pod sandbox, the volume) and the
    host packaging its volume with --from-stage;
  * staging the tree (uv python install + uv pip install --require-hashes),
    and with it the interpreter-URL pin assertion;
  * `k3sm build --no-record --format oci` over the real 1.3 GB context, as an
    ordinary user, its digest, and
    building the same context twice to compare digests;
  * walk-verify over the REAL payload (a few hundred Mach-Os), which is the
    acceptance criterion this file only rehearses;
  * a genuinely signed-then-tampered Mach-O (the fixture here is unsigned, which
    codesign rejects for a different reason);
  * `k3sm image push` to a registry;
  * k3sm-shard under the real sandbox profile with live per-pod DNS records and
    a real mlx_lm.server on two Macs (the M17 lab ladder's sharded-ring rung);
  * the context guard on a real model and tokenizer (a live recall probe).
EOF
[ "$FAIL" -eq 0 ] || exit 1
