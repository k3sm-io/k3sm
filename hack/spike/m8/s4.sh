#!/usr/bin/env bash
# M8.0-d4 / S4 — mlx-serve image size & materialize latency, and the M8.4
# PACKAGING PREMISE check.
#
# Two independent jobs:
#
#   A. BUDGET. Stage a representative mlx-serve rootfs in the lab prefix
#      (python-build-standalone darwin-arm64 + the hash-pinned mlx/mlx-lm wheel
#      set; NO model weights — weights live on a PVC, never in the image) and
#      measure it against the two pruning thresholds the M8 plan sets for S4:
#        >2 GB unpacked      -> forces payload pruning
#        >1 min cold start   -> forces payload pruning
#      Four costs are measured SEPARATELY, because they are paid at different
#      moments by different actors: unpacked size (pull, once per node),
#      ad-hoc tree-sign (AdHocSignTree, once per image arrival), clonefile
#      (per-pod materialize), and cold-start-to-first-token (per pod start).
#
#   B. PREMISE. M8.4 assembles that rootfs with `k3sm build` from a COPY-only
#      Dockerfile. python-build-standalone ships SYMLINKS (bin/python3 ->
#      python3.12 and friends). If a symlink does not survive
#      COPY -> layer tar -> unpack byte-for-byte, the image is broken in a way
#      no size budget would reveal and M8.4 must be re-planned. So: build the
#      k3sm binary on the lab, build the staged tree into an OCI layout, unpack
#      it, and compare every entry — plus a negative control for the one symlink
#      shape the builder is known to refuse.
#
# Usage:
#   hack/spike/m8/s4.sh              # measure + premise (stages on first run)
#   hack/spike/m8/s4.sh --restage    # rebuild the staged rootfs from scratch
#   hack/spike/m8/s4.sh --no-build   # skip the source push + go build
#
# The k3sm binary is built ON THE LAB from a source copy pushed into the prefix
# (the lab has a native arm64 toolchain; a workstation's may be translated).
# Sibling modules resolve through this repo's go.mod replace directives, so
# K3SM_SPIKE_SIBLINGS must name a directory holding apis/, runtimed/ and
# darwin-net/ checkouts (default: this repo's parent).
#
# No sudo, no root, every write confined to $PREFIX — see lib.sh. Cold-start
# numbers are therefore WARM-page-cache (dropping the cache needs root); the
# findings file states what that does and does not license.
#
# Recorded verdict: findings-s4.md.
set -euo pipefail
cd "$(dirname "$0")"; . ./lib.sh

RESTAGE=0; DO_BUILD=1
for a in "$@"; do
  case "$a" in
    --restage)  RESTAGE=1 ;;
    --no-build) DO_BUILD=0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

# lab4 — like lib.sh's lab(), plus the flags this spike needs remote-side.
lab4() { ssh "$HOST" "PREFIX=$PREFIX RESTAGE=$RESTAGE bash -s"; }

REPO_ROOT=$(cd ../../.. && pwd)
SIBLINGS="${K3SM_SPIKE_SIBLINGS:-$(cd "$REPO_ROOT/.." && pwd)}"

if [ "$DO_BUILD" = 1 ]; then
  note "S4 — push a source copy into the prefix and build k3sm with the LAB toolchain"
  for r in apis runtimed darwin-net; do
    [ -d "$SIBLINGS/$r" ] || { echo "missing sibling checkout: $SIBLINGS/$r (set K3SM_SPIKE_SIBLINGS)" >&2; exit 2; }
  done
  ssh "$HOST" "mkdir -p k3sm-spike-m8/src"
  rsync -a --delete --exclude '.git' "$REPO_ROOT/" "$HOST:k3sm-spike-m8/src/k3sm/"
  for r in apis runtimed darwin-net; do
    rsync -a --delete --exclude '.git' "$SIBLINGS/$r/" "$HOST:k3sm-spike-m8/src/$r/"
  done
  lab <<'EOF'
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH
# GOWORK=off: the pushed copy carries no go.work and an inherited one would name
# checkouts outside the prefix. go.mod's RELATIVE replace directives are what
# resolve the siblings, so the copy is self-contained.
cd "$PREFIX/src/k3sm"
GOWORK=off CGO_ENABLED=1 GOARCH=arm64 go build -o "$PREFIX/bin/k3sm" ./cmd/k3sm
file "$PREFIX/bin/k3sm"
EOF
fi

note "S4 — stage the rootfs, measure the four costs, then check the packaging premise"
lab4 <<'EOF'
set -uo pipefail
export UV_CACHE_DIR=$PREFIX/cache UV_PYTHON_INSTALL_DIR=$PREFIX/pyinstall
UV=$PREFIX/bin/uv
S=$PREFIX/stage/mlx-serve
DIST=$(ls -d "$PREFIX"/pyinstall/cpython-3.12.*-macos-aarch64-none | tail -1)
MP=$(ls -d "$PREFIX"/hf/hub/models--*Qwen2.5-0.5B*/snapshots/* | head -1)

# SPY — the staged interpreter, run with bytecode writing OFF. Every measurement
# below reads the stage; an import that drops a __pycache__/*.pyc into it would
# mutate the very tree being measured and hashed (it did, once: `import tarfile`
# in the strict-reader probe added one file between the build and the compare,
# turning PREMISE_CONTENT red for a reason that had nothing to do with the image).
SPY() { PYTHONDONTWRITEBYTECODE=1 "$S/bin/python3.12" -B "$@"; }

# usedk — used KB on the volume holding the prefix. Free-space deltas are how a
# clonefile is proven CoW rather than a byte copy.
usedk()     { df -k "$PREFIX" | awk 'NR==2{print $3}'; }
# apparentk — LOGICAL bytes in KB. du reports ALLOCATED blocks, which for a
# clone-shared tree under-reports what an OCI pull must actually carry.
apparentk() { find "$1" -type f -exec stat -f '%z' {} + | awk '{s+=$1} END{printf "%d\n", s/1024}'; }

echo "### stage — python-build-standalone + the hash-pinned wheel set (NO weights)"
if [ "$RESTAGE" = 1 ] || [ ! -x "$S/bin/python3.12" ]; then
  rm -rf "$S"; mkdir -p "$S"
  cp -Rc "$DIST/." "$S/"
  # uv stamps its managed interpreters EXTERNALLY-MANAGED. An image rootfs is not
  # uv-managed, so the marker is STRIPPED rather than defeated with
  # --break-system-packages, which would also silence a real misconfiguration.
  find "$S" -name EXTERNALLY-MANAGED -delete
  grep -E '^(mlx|mlx-lm|mlx-metal)==' "$PREFIX/logs/pip-freeze.txt" > "$PREFIX/stage/requirements.in"
  # NOTE: no --python-platform. Its default (macOS 13.0) has NO mlx wheel — mlx
  # ships macosx_14_0_arm64 and newer — so a lockfile compiled with the flag is
  # unsatisfiable. M8.4's lockfile must be compiled for macOS 14+ arm64.
  "$UV" pip compile --generate-hashes "$PREFIX/stage/requirements.in" -o "$PREFIX/stage/requirements-mlx.txt" 2>&1 | tail -2
  "$UV" pip install --python "$S/bin/python3.12" --require-hashes -r "$PREFIX/stage/requirements-mlx.txt" 2>&1 | tail -2
fi
echo "  lockfile: $(grep -cE '^[a-z0-9].*==' "$PREFIX/stage/requirements-mlx.txt") pinned packages, $(grep -c -- '--hash' "$PREFIX/stage/requirements-mlx.txt") hashes"
SPY -c 'import mlx.core as mx, importlib.metadata as m; print("  import:  mlx", m.version("mlx"), "mlx-lm", m.version("mlx-lm"), mx.default_device())'

echo
echo "### size — against the >2GB unpacked pruning threshold"
DISKK=$(du -sk "$S" | awk '{print $1}')
APPK=$(apparentk "$S")
NF=$(find "$S" -type f | wc -l | tr -d ' ')
NL=$(find "$S" -type l | wc -l | tr -d ' ')
ND=$(find "$S" -type d | wc -l | tr -d ' ')
awk -v k="$APPK" -v d="$DISKK" 'BEGIN{printf "  unpacked apparent %d KB (%.2f GB)   on-disk %d KB\n", k, k/1048576, d}'
echo "  entries: files=$NF symlinks=$NL dirs=$ND"
awk -v k="$APPK" 'BEGIN{printf "  THRESHOLD >2GB unpacked: %s (%.2f GB)\n", (k>2097152 ? "EXCEEDED" : "PASS"), k/1048576}'
echo "  subtrees by apparent KB:"
for d in "$S"/*/ ; do printf '    %10s KB  %s\n' "$(apparentk "$d")" "${d%/}"; done | sed "s#$S/##" | sort -rn | head -12
echo "  site-packages by apparent KB:"
for d in "$S"/lib/python3.12/site-packages/*/ ; do printf '    %10s KB  %s\n' "$(apparentk "$d")" "${d%/}"; done | sed "s#$S/lib/python3.12/site-packages/##" | sort -rn | head -12
echo "  largest single files:"
find "$S" -type f -exec stat -f '%z %N' {} + | sort -rn | head -8 | awk -v s="$S/" '{printf "    %8.1f MB  %s\n", $1/1048576, substr($2,length(s)+1)}'

echo
echo "### machos — the S2 walk, mechanized and re-measured against THIS payload"
MACHOS=$PREFIX/logs/s4-machos.txt
T0=$(date +%s.%N)
# file(1) emits THREE lines for a universal binary ("<p>: Mach-O universal ...",
# then "<p> (for architecture x86_64): ..." per slice), and pads the description
# with spaces AFTER the colon. So: split on the FIRST colon, then keep only
# fields that are a real file — which drops the per-slice lines by construction.
find "$S" -type f -print0 | xargs -0 file | awk -F: '/Mach-O/{print $1}' \
  | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done | sort -u > "$MACHOS"
T1=$(date +%s.%N)
NM=$(wc -l < "$MACHOS" | tr -d ' ')
awk -v a="$T0" -v b="$T1" -v n="$NM" -v f="$NF" 'BEGIN{printf "  walk: %d files scanned, %d Mach-O found, %.2fs\n", f, n, b-a}'
echo "  fat (universal) Mach-Os:"
while IFS= read -r f; do
  case "$(file -b "$f" | head -1)" in *"universal binary"*|*"fat file"*) echo "    FAT ${f#$S/}" ;; esac
done < "$MACHOS"

echo
echo "### sign — AdHocSignTree cost, measured on a CLONE so the stage stays pristine"
SIGNDIR=$PREFIX/work/s4-sign
rm -rf "$SIGNDIR"; cp -Rc "$S" "$SIGNDIR"
# (a) verify-only, ARCH-AWARE — the S2 finding: a bare `codesign -v` is wrong on
#     a fat Mach-O whose foreign slice is unsigned, and would drive a needless
#     re-sign that de-CoWs the file.
T0=$(date +%s.%N); BADA=0; BADW=0
while read -r f; do
  g=${SIGNDIR}${f#$S}
  codesign -v --arch arm64 "$g" >/dev/null 2>&1 || { BADA=$((BADA+1)); echo "    INVALID_ARCH_AWARE ${f#$S/}"; }
  codesign -v            "$g" >/dev/null 2>&1 || { BADW=$((BADW+1)); echo "    INVALID_WHOLE_FILE ${f#$S/}"; }
done < "$MACHOS"
T1=$(date +%s.%N)
awk -v a="$T0" -v b="$T1" -v n="$NM" -v x="$BADA" -v y="$BADW" \
  'BEGIN{printf "  verify x%d (arch-aware AND whole-file): %.2fs (%.1f ms/file/pass)  invalid: arch-aware=%d whole-file=%d\n", n, b-a, 1000*(b-a)/(2*n), x, y}'
# (b) unconditional re-sign of every Mach-O — the worst case AdHocSignTree pays.
T0=$(date +%s.%N)
while read -r f; do
  g=${SIGNDIR}${f#$S}
  codesign -f -s - "$g" >/dev/null 2>&1 || echo "    SIGN_FAIL ${g#$SIGNDIR/}"
done < "$MACHOS"
T1=$(date +%s.%N)
awk -v a="$T0" -v b="$T1" -v n="$NM" 'BEGIN{printf "  re-sign ALL (codesign -f -s -) x%d: %.2fs  (%.1f ms/file)\n", n, b-a, 1000*(b-a)/n}'
( cd "$SIGNDIR" && "$SIGNDIR/bin/python3.12" -c 'import mlx.core as mx; print("  signed-clone exec: OK", mx.default_device())' ) \
  || echo "  signed-clone exec: FAILED"
rm -rf "$SIGNDIR"

echo
echo "### clonefile — per-pod materialize cost (3 runs), against a byte copy"
for i in 1 2 3; do
  D=$PREFIX/work/s4-clone-$i; rm -rf "$D"
  U0=$(usedk); T0=$(date +%s.%N); cp -Rc "$S" "$D"; T1=$(date +%s.%N); U1=$(usedk)
  awk -v a="$T0" -v b="$T1" -v u0="$U0" -v u1="$U1" -v i="$i" 'BEGIN{printf "  clonefile run %d: %.2fs  used-KB delta %+d\n", i, b-a, u1-u0}'
  rm -rf "$D"
done
D=$PREFIX/work/s4-bytecopy; rm -rf "$D"
U0=$(usedk); T0=$(date +%s.%N); cp -R "$S" "$D"; T1=$(date +%s.%N); U1=$(usedk)
awk -v a="$T0" -v b="$T1" -v u0="$U0" -v u1="$U1" 'BEGIN{printf "  byte copy      : %.2fs  used-KB delta %+d\n", b-a, u1-u0}'
rm -rf "$D"

echo
echo "### coldstart — spawn -> FIRST TOKEN, against the >1min pruning threshold"
POD=$PREFIX/work/s4-pod
rm -rf "$POD"; mkdir -p "$POD/tmp"
cp -Rc "$S" "$POD/rootfs"
cat > "$POD/first.py" <<'PY'
import os, time
T0 = float(os.environ["T_SPAWN"])
t_py = time.time()
from mlx_lm import load, stream_generate
t_imp = time.time()
model, tok = load(os.environ["MODEL_PATH"])
t_load = time.time()
p = tok.apply_chat_template([{"role": "user", "content": "Name three primary colors."}], add_generation_prompt=True)
first, n = None, 0
for _ in stream_generate(model, tok, prompt=p, max_tokens=32):
    n += 1
    if first is None:
        first = time.time()
t_end = time.time()
print("  COLD interp %.2fs | +import %.2fs | +weights %.2fs | +FIRST_TOKEN %.2fs | +%d tokens %.2fs"
      % (t_py - T0, t_imp - T0, t_load - T0, first - T0, n, t_end - T0))
print("  COLD_TTFT_S=%.2f" % (first - T0))
PY
# The S1 minimal profile, re-pointed at the staged rootfs: two exact user-client
# classes and nothing else. Unwidened.
cat > "$PREFIX/sbpl/s4.sb" <<SB
;; k3sm M8.0/S4 — the S1 minimal profile, re-pointed at the staged rootfs.
(version 1)
(deny default)
(import "system.sb")
(allow process-exec*)
(allow process-fork)
(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/Library")
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom"))
(allow file-write* (subpath "$POD") (literal "/dev/null"))
(allow iokit-open
  (iokit-registry-entry-class "AGXDeviceUserClient")
  (iokit-registry-entry-class "IOSurfaceRootUserClient"))
(deny file-read* file-write* (subpath "/Users"))
(deny file-read* file-write* (subpath "/private/var/db"))
(deny file-write* (subpath "/System/Volumes/Preboot/Cryptexes") (subpath "/System/Cryptexes"))
(allow file-read* (subpath "/private/var/db/dyld"))
(allow file-read* (subpath "$PREFIX/hf"))
(allow file-read* file-write* (subpath "$POD"))
SB
one() { ( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/bin \
      MODEL_PATH="$MP" HF_HUB_OFFLINE=1 HF_HOME="$PREFIX/hf" T_SPAWN="$(date +%s.%N)" \
      "$@" 2>&1 ) | grep -E "COLD|Error"; }
cold() { # cold <label> <cmd...> — one discarded warm-up, then 3 measured runs.
  local label="$1"; shift
  one "$@" >/dev/null 2>&1
  echo "  --- $label (3 runs after one discarded warm-up) ---"
  for _ in 1 2 3; do one "$@"; done
}
# Ordering note: the interpreter and weights are page-cached by the staging and
# clone steps above, and dropping the cache needs root. So BOTH numbers are
# warm-page-cache; the warm-up equalizes them so the sandbox delta is readable.
cold "unsandboxed, from the clonefiled rootfs" "$POD/rootfs/bin/python3.12" "$POD/first.py"
cold "under the S1 Seatbelt profile"           /usr/bin/sandbox-exec -f "$PREFIX/sbpl/s4.sb" "$POD/rootfs/bin/python3.12" "$POD/first.py"
echo "  THRESHOLD >1min cold start: compare COLD_TTFT_S above"
# Write amplification: what a pod start dirties inside its own clone. Every file
# written here is a CoW break of a block otherwise shared with every other pod on
# the node, so it is a per-pod disk cost the image can design away.
NEWF=$(find "$POD/rootfs" -type f -newer "$POD/first.py" | wc -l | tr -d ' ')
NEWB=$(find "$POD/rootfs" -type f -newer "$POD/first.py" -exec stat -f '%z' {} + 2>/dev/null | awk '{s+=$1} END{printf "%d", s+0}')
echo "  rootfs write amplification after 4 starts: $NEWF files, $NEWB bytes CoW-broken"
find "$POD/rootfs" -type f -newer "$POD/first.py" | sed "s#$POD/rootfs/#    #" | head -6
echo "  staged tree already ships $(find "$S" -name '*.pyc' | wc -l | tr -d ' ') precompiled .pyc in $(find "$S" -name __pycache__ -type d | wc -l | tr -d ' ') __pycache__ dirs"

echo
echo "### premise — do python-build-standalone's SYMLINKS survive COPY -> layer -> unpack?"
K=$PREFIX/bin/k3sm
if [ ! -x "$K" ]; then
  echo "  SKIP — no k3sm binary in the prefix (re-run without --no-build)"
else
  B=$PREFIX/work/s4-build; rm -rf "$B"; mkdir -p "$B"
  # The Dockerfile lives OUTSIDE the context so `COPY . /` cannot absorb it.
  cat > "$B/Dockerfile" <<'DF'
FROM scratch
COPY . /
ENTRYPOINT ["/bin/python3.12"]
DF
  T0=$(date +%s.%N)
  "$K" build --file "$B/Dockerfile" --tag mlx-serve:s4 --format oci --output "$B/oci" "$S" 2>&1 | sed 's/^/  /'
  RC=$?
  T1=$(date +%s.%N)
  awk -v a="$T0" -v b="$T1" -v rc="$RC" 'BEGIN{printf "  k3sm build --format oci: rc=%d  %.2fs\n", rc, b-a}'
  if [ "$RC" = 0 ]; then
    awk -v k="$(apparentk "$B/oci")" -v d="$(du -sk "$B/oci" | awk '{print $1}')" \
      'BEGIN{printf "  oci layout: apparent %d KB (%.2f GB)  on-disk %d KB\n", k, k/1048576, d}'
    ls -l "$B/oci/blobs/sha256" | sed 's/^/    /'
    # Reproducibility: the same context + Dockerfile must produce the same digest,
    # which is M8.4-d1's "builds reproducibly from the lockfile" gate in miniature.
    D1=$("$K" build --file "$B/Dockerfile" --tag mlx-serve:s4 --format oci --output "$B/oci2" "$S" | awk '/digest:/{print $2}')
    D0=$(SPY -c 'import json,sys; print(json.load(open(sys.argv[1]))["manifests"][0]["digest"])' "$B/oci/index.json")
    echo "  reproducible: first=$D0 second=$D1 -> $([ "$D0" = "$D1" ] && echo IDENTICAL || echo DIVERGED)"
    rm -rf "$B/oci2"
    U=$PREFIX/work/s4-unpack; rm -rf "$U"; mkdir -p "$U"
    LAYERS=$(SPY - "$B/oci" <<'PYA'
import json, os, sys
root = sys.argv[1]
blob = lambda d: os.path.join(root, "blobs", *d.split(":"))
idx = json.load(open(os.path.join(root, "index.json")))
man = json.load(open(blob(idx["manifests"][0]["digest"])))
cfg = json.load(open(blob(man["config"]["digest"])))
print(" ".join(blob(l["digest"]) for l in man["layers"]))
e = sys.stderr
e.write("  config: os=%s arch=%s variant=%s entrypoint=%r\n"
        % (cfg.get("os"), cfg.get("architecture"), cfg.get("variant"),
           cfg.get("config", {}).get("Entrypoint")))
for i, l in enumerate(man["layers"]):
    e.write("  layer[%d] DECLARED mediaType=%s size=%d\n"
            "      manifest digest =%s\n      config diff_id  =%s\n"
            % (i, l["mediaType"], l["size"], l["digest"], cfg["rootfs"]["diff_ids"][i]))
PYA
)
    # DECLARED vs ACTUAL layer format. The consumer that gets hurt by a mismatch
    # is one that dispatches on mediaType -- containerd, ggcr Uncompressed(), or
    # runtimed's LayerApplier, which opens blobs via layer.Compressed and hands
    # them straight to tar.NewReader. bsdtar sniffs gzip, so the round-trip below
    # would hide the mismatch; this block is what refuses to.
    for l in $LAYERS; do
      echo "      ACTUAL bytes    =$(file -b "$l" | cut -c1-70)"
      echo "      sha256 as-is    =$(shasum -a 256 < "$l" | cut -d' ' -f1)"
      echo "      sha256 gunzipped=$(gunzip -c "$l" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)"
      case "$(file -b "$l")" in
        gzip*) echo "      LAYER_FORMAT=MISLABELLED (gzip bytes under an UNCOMPRESSED mediaType)" ;;
        *)     echo "      LAYER_FORMAT=CONSISTENT" ;;
      esac
    done
    # A STRICT consumer: tar with compression explicitly disabled, i.e. exactly
    # what a mediaType-trusting reader does. This is the concrete failure the
    # sniffing round-trip below cannot show.
    for l in $LAYERS; do
      SPY -c '
import sys, tarfile
try:
    with tarfile.open(sys.argv[1], mode="r:") as t:
        print("      STRICT_TAR_READ=OK (%d entries)" % len(t.getnames()))
except Exception as ex:
    print("      STRICT_TAR_READ=FAIL %s: %s" % (type(ex).__name__, ex))' "$l"
    done
    echo "  layers: $(echo "$LAYERS" | wc -w | tr -d ' ')"
    T0=$(date +%s.%N)
    for l in $LAYERS; do tar -xf "$l" -C "$U"; done
    T1=$(date +%s.%N)
    awk -v a="$T0" -v b="$T1" 'BEGIN{printf "  unpack (tar -xf): %.2fs\n", b-a}'
    SPY - "$S" "$U" <<'PY'
import hashlib, os, sys
src, dst = sys.argv[1], sys.argv[2]

def walk(root):
    ent = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for n in list(dirnames) + filenames:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                ent[rel] = ("link", os.readlink(p))
            elif os.path.isdir(p):
                ent[rel] = ("dir", "")
            else:
                ent[rel] = ("file", os.lstat(p).st_size)
        # never descend through a symlinked directory
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return ent

a, b = walk(src), walk(dst)
al = {k: v[1] for k, v in a.items() if v[0] == "link"}
bl = {k: v[1] for k, v in b.items() if v[0] == "link"}
print("  source symlinks: %d   unpacked symlinks: %d" % (len(al), len(bl)))
for k in sorted(al):
    print("    %s %-32s -> %s" % ("OK " if bl.get(k) == al[k] else "BAD", k, al[k]))
missing  = sorted(set(al) - set(b))
demoted  = sorted(k for k in al if k in b and b[k][0] != "link")
mismatch = sorted(k for k in al if k in bl and al[k] != bl[k])
invented = sorted(set(bl) - set(al))
print("  MISSING=%d DEMOTED_TO_FILE=%d TARGET_MISMATCH=%d INVENTED=%d"
      % (len(missing), len(demoted), len(mismatch), len(invented)))
for label, xs in (("MISSING", missing), ("DEMOTED", demoted), ("MISMATCH", mismatch), ("INVENTED", invented)):
    for k in xs[:10]:
        print("      %s %s" % (label, k))

# Whole-tree content digest over (path, sha256 of body), so a silently
# dereferenced or truncated file cannot hide behind a matching entry count.
def digest(root, ent):
    h = hashlib.sha256()
    for k in sorted(k for k, v in ent.items() if v[0] == "file"):
        fh = hashlib.sha256()
        with open(os.path.join(root, k), "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                fh.update(chunk)
        h.update(k.encode() + b"\0" + fh.hexdigest().encode() + b"\n")
    return h.hexdigest()

nf_a = sum(1 for v in a.values() if v[0] == "file")
nf_b = sum(1 for v in b.values() if v[0] == "file")
nd_a = sum(1 for v in a.values() if v[0] == "dir")
nd_b = sum(1 for v in b.values() if v[0] == "dir")
da, db = digest(src, a), digest(dst, b)
print("  regular files: src=%d dst=%d   dirs: src=%d dst=%d" % (nf_a, nf_b, nd_a, nd_b))
print("  content digest src=%s" % da)
print("  content digest dst=%s" % db)
print("  PREMISE_SYMLINKS=%s" % ("PASS" if not (missing or demoted or mismatch or invented) else "FAIL"))
print("  PREMISE_CONTENT=%s"  % ("PASS" if da == db and nf_a == nf_b else "FAIL"))
PY
    # A byte-identical tree whose interpreter will not exec is still a broken
    # image, so run the unpacked one.
    if [ -x "$U/bin/python3.12" ]; then
      ls -l "$U/bin/python3" "$U/bin/python3.12" | sed "s#$U/#  #"
      ( cd "$U" && "$U/bin/python3" -c 'import mlx.core as mx; print("  unpacked-tree exec via bin/python3 SYMLINK: OK", mx.default_device())' ) \
        || echo "  unpacked-tree exec: FAILED"
    else
      echo "  unpacked-tree exec: no /bin/python3.12"
    fi
    rm -rf "$U"
  fi

  echo "  --- negative controls: one build per SYMLINK SHAPE ---"
  # uv's own install dir carries an ABSOLUTE alias symlink
  # (cpython-3.12-macos-aarch64-none -> the absolute versioned dir), so M8.4 must
  # know what the builder does with each shape rather than discover it in CI.
  NC=$PREFIX/work/s4-neg
  shape() { # shape <name> <ln -s args...>
    local n="$1"; shift
    rm -rf "$NC"; mkdir -p "$NC/ctx"
    echo hello > "$NC/ctx/real.txt"
    ln -s "$@"
    printf 'FROM scratch\nCOPY . /\n' > "$NC/Dockerfile"
    local out rc
    out=$("$K" build --file "$NC/Dockerfile" --tag neg:s4 --format oci --output "$NC/oci" "$NC/ctx" 2>&1); rc=$?
    printf '    %-22s rc=%d  %s\n' "$n" "$rc" "$(echo "$out" | tr '\n' ' ' | sed 's/  */ /g')"
    rm -rf "$NC"
  }
  mkdir -p "$NC/ctx"
  shape relative           real.txt "$NC/ctx/rel.txt"
  shape absolute-in-ctx    "$NC/ctx/real.txt" "$NC/ctx/abs.txt"
  shape dangling-relative  nowhere.txt "$NC/ctx/dangling.txt"
  shape escaping-relative  ../../../etc/hosts "$NC/ctx/escape.txt"
  rm -rf "$NC" "$B"
fi
rm -rf "$POD"
EOF
