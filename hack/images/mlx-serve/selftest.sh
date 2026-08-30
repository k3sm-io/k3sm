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
#   * walk-verify goes RED on an invalid signature, on a mislabelled layer, on a
#     blob that does not match its digest, and on a non-Mach-O entrypoint — and
#     GREEN on the universal-binary shape that a whole-file signature check
#     would have failed.
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
for s in "$BUILD" "$WALK" "$HERE/selftest.sh"; do
	n="$(basename "$s")"
	if [ -x "$s" ] && bash -n "$s" 2>/dev/null; then
		ladder ok "0.$n  executable + parses (bash -n)"
	else
		ladder no "0.$n  executable + parses (bash -n)"
	fi
done

if command -v shellcheck >/dev/null 2>&1; then
	if out="$(shellcheck -s bash "$BUILD" "$WALK" "$HERE/selftest.sh" 2>&1)"; then
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

# ---- summary ----------------------------------------------------------------
echo "----------------------------------------"
echo "mlx-serve selftest: $PASS passed, $FAIL failed, $SKIP skipped"
cat <<'EOF'

Not covered here — this needs a Mac with uv, a k3sm binary and the network:
  * staging the tree (uv python install + uv pip install --require-hashes),
    and with it the interpreter-URL pin assertion;
  * `k3sm build --format oci` over the real 1.3 GB context, its digest, and
    building the same context twice to compare digests;
  * walk-verify over the REAL payload (a few hundred Mach-Os), which is the
    acceptance criterion this file only rehearses;
  * a genuinely signed-then-tampered Mach-O (the fixture here is unsigned, which
    codesign rejects for a different reason);
  * `k3sm image push` to a registry.
EOF
[ "$FAIL" -eq 0 ] || exit 1
