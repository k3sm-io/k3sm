#!/usr/bin/env bash
#
# walk-verify — assert every Mach-O in an image payload carries a valid
# signature for the target architecture.
#
# The rule it enforces comes from the M8 signing spike
# (hack/spike/m8/findings-s2.md): a python wheel tree arrives LINKER-ad-hoc
# signed, nothing in it carries a team identity, and AMFI will refuse to execute
# anything whose signature does not validate. So an image whose payload contains
# one unsigned or corrupt Mach-O is a broken image, and nothing about its size,
# its digest or its manifest reveals that.
#
# Two lessons from that spike are encoded here, and both are load-bearing:
#
#   * VERIFY PER-ARCHITECTURE. Universal wheels are shipped with a valid arm64
#     slice and an UNSIGNED x86_64 slice. A whole-file `codesign -v` calls those
#     "not signed at all" — a false alarm on a file that is perfectly valid for
#     the architecture that will actually execute. The foreign slice never runs
#     on a darwin/arm64 pod, so only the target slice is verified.
#
#   * READ THE MAGIC, DO NOT EXEC A CLASSIFIER PER FILE. The payload is tens of
#     thousands of files with a few hundred Mach-Os in it; one `file(1)` per
#     candidate costs tens of seconds. The classification below is a single
#     pass that reads four bytes per file, so only the actual Mach-Os cost a
#     process.
#
# Usage:
#   walk-verify.sh --layout <oci-layout-dir>   # unpack the layers, then walk
#   walk-verify.sh --tree <dir>                # walk an already-unpacked tree
#   walk-verify.sh --layout <dir> --keep <dir> # keep the unpacked tree
#   walk-verify.sh --tree <dir> --verbose      # print every verdict
#
# Exit: 0 clean, 1 an invalid signature or a malformed layout, 2 usage/host.
set -euo pipefail

LAYOUT=""
TREE=""
KEEP=""
VERBOSE=0
# The image is darwin/arm64, so the slice to verify is the arm64 one wherever
# there is a choice; arm64e is accepted for anything that ships only that.
ARCH_PREF="arm64 arm64e"

die() { echo "walk-verify: $*" >&2; exit 2; }

usage() {
	# The leading comment block, minus the shebang and the leading "# ".
	awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--layout) LAYOUT="${2:-}"; [ -n "$LAYOUT" ] || die "--layout needs a directory"; shift 2 ;;
		--tree) TREE="${2:-}"; [ -n "$TREE" ] || die "--tree needs a directory"; shift 2 ;;
		--keep) KEEP="${2:-}"; [ -n "$KEEP" ] || die "--keep needs a directory"; shift 2 ;;
		--arch) ARCH_PREF="${2:-}"; [ -n "$ARCH_PREF" ] || die "--arch needs a list"; shift 2 ;;
		--verbose) VERBOSE=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) die "unknown flag: $1 (try --help)" ;;
	esac
done

[ -n "$LAYOUT" ] || [ -n "$TREE" ] || { usage >&2; exit 2; }
[ -z "$LAYOUT" ] || [ -z "$TREE" ] || die "--layout and --tree are alternatives"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v codesign >/dev/null 2>&1 || die "codesign not found — this check needs macOS"

WORKDIR=""
cleanup() { [ -z "$WORKDIR" ] || rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

ENTRYPOINT=""

# ---- layout -----------------------------------------------------------------
# unpack_layout reads the index, verifies every blob against the digest that
# names it, checks that each layer's DECLARED media type matches the bytes it
# actually holds, and extracts the payload.
#
# The media-type check is not pedantry: a layer whose bytes are gzip under an
# uncompressed media type round-trips fine through a reader that sniffs (bsdtar
# does) and fails in one that trusts the manifest (a spec-conformant puller
# does). That exact defect was found, and fixed, during the image spike.
unpack_layout() {
	local layout="$1" dest="$2"
	[ -f "$layout/index.json" ] || die "$layout has no index.json — it is not an OCI layout"

	local plan
	plan="$(python3 - "$layout" <<'PY'
import hashlib, json, os, sys

root = sys.argv[1]
def blob(digest):
    algo, hexd = digest.split(":", 1)
    return os.path.join(root, "blobs", algo, hexd)

def verified(digest, what):
    path = blob(digest)
    if not os.path.exists(path):
        sys.exit("missing blob for %s: %s" % (what, digest))
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    got = "sha256:" + h.hexdigest()
    if got != digest:
        sys.exit("blob content does not match its digest for %s: named %s, is %s"
                 % (what, digest, got))
    return path

index = json.load(open(os.path.join(root, "index.json")))
manifests = index.get("manifests", [])
if len(manifests) != 1:
    sys.exit("layout indexes %d manifests; expected exactly one image" % len(manifests))
desc = manifests[0]
if "index" in (desc.get("mediaType") or ""):
    sys.exit("layout indexes a nested image index (%s)" % desc.get("mediaType"))

manifest = json.load(open(verified(desc["digest"], "manifest")))
config = json.load(open(verified(manifest["config"]["digest"], "config")))

if config.get("os") != "darwin" or config.get("architecture") != "arm64":
    sys.exit("image platform is %s/%s; expected darwin/arm64"
             % (config.get("os"), config.get("architecture")))

entrypoint = (config.get("config") or {}).get("Entrypoint") or []
print("ENTRYPOINT\t%s" % (entrypoint[0] if entrypoint else ""))

UNCOMPRESSED = "application/vnd.oci.image.layer.v1.tar"
GZIP = UNCOMPRESSED + "+gzip"
for i, layer in enumerate(manifest["layers"]):
    declared = layer["mediaType"]
    path = verified(layer["digest"], "layer[%d]" % i)
    with open(path, "rb") as fh:
        magic = fh.read(2)
    is_gzip = magic == b"\x1f\x8b"
    if declared == UNCOMPRESSED:
        if is_gzip:
            sys.exit("layer[%d] declares %s but holds gzip bytes — a reader that "
                     "trusts the manifest cannot read it" % (i, declared))
        print("LAYER\tplain\t%s" % path)
    elif declared == GZIP:
        if not is_gzip:
            sys.exit("layer[%d] declares %s but does not hold gzip bytes" % (i, declared))
        print("LAYER\tgzip\t%s" % path)
    else:
        sys.exit("layer[%d] has media type %s, which this check does not know how "
                 "to read" % (i, declared))
PY
)" || die "layout is not verifiable (see above)"

	local kind path
	while IFS=$'\t' read -r kind path rest; do
		case "$kind" in
			ENTRYPOINT) ENTRYPOINT="$path" ;;
			LAYER)
				echo "  layer ($path): $(basename "$rest")"
				if [ "$path" = "gzip" ]; then
					gunzip -c "$rest" | tar -x -C "$dest"
				else
					tar -x -f "$rest" -C "$dest"
				fi
				;;
		esac
	done <<< "$plan"
	echo "  layout: blobs match their digests, media types match their bytes"
}

# ---- the walk ---------------------------------------------------------------
# classify emits one "path<TAB>kind<TAB>arch,arch" line per Mach-O, reading four
# bytes per file in ONE process. Symlinks are skipped: their target is walked on
# its own, and codesign would otherwise verify the same file twice.
classify() {
	python3 - "$1" <<'PY'
import os, struct, sys

root = sys.argv[1]

# A magic of feedface/feedfacf means the header is BIG-endian; the byte-reversed
# spellings cefaedfe/cffaedfe are the little-endian (every current Mac) form.
THIN = {0xfeedface: ">", 0xfeedfacf: ">", 0xcefaedfe: "<", 0xcffaedfe: "<"}
FAT = {0xcafebabe: ">", 0xcafebabf: ">", 0xbebafeca: "<", 0xbfbafeca: "<"}

# cputype -> (name, {subtype: name}). A cputype outside this table is not a
# Darwin architecture, which is how a Java class file (also 0xcafebabe) is told
# apart from a universal binary.
CPU = {
    7:          ("i386", {}),
    0x01000007: ("x86_64", {}),
    12:         ("arm", {}),
    0x0100000c: ("arm64", {2: "arm64e"}),
    0x0200000c: ("arm64_32", {}),
}

def arch_name(cputype, cpusubtype):
    entry = CPU.get(cputype)
    if entry is None:
        return None
    name, subs = entry
    return subs.get(cpusubtype & 0x00ffffff, name)

def read_head(path, n):
    with open(path, "rb") as fh:
        return fh.read(n)

files = machos = 0
for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        p = os.path.join(dirpath, fn)
        if os.path.islink(p):
            continue
        files += 1
        try:
            head = read_head(p, 4)
        except OSError:
            continue
        if len(head) < 4:
            continue
        magic = struct.unpack(">I", head)[0]
        if magic in THIN:
            endian = THIN[magic]
            try:
                head = read_head(p, 12)
            except OSError:
                continue
            if len(head) < 12:
                continue
            cputype, cpusubtype = struct.unpack(endian + "ii", head[4:12])
            name = arch_name(cputype & 0xffffffff, cpusubtype & 0xffffffff)
            if name is None:
                continue
            machos += 1
            print("%s\tthin\t%s" % (p, name))
        elif magic in FAT:
            endian = FAT[magic]
            try:
                head = read_head(p, 8)
            except OSError:
                continue
            if len(head) < 8:
                continue
            (count,) = struct.unpack(endian + "I", head[4:8])
            if not 1 <= count <= 32:
                continue  # not a universal binary (a Java class file lands here)
            need = 8 + 20 * count
            head = read_head(p, need)
            if len(head) < need:
                continue
            names = []
            for i in range(count):
                off = 8 + 20 * i
                cputype, cpusubtype = struct.unpack(endian + "ii", head[off:off + 8])
                nm = arch_name(cputype & 0xffffffff, cpusubtype & 0xffffffff)
                if nm is None:
                    names = []
                    break
                names.append(nm)
            if not names:
                continue
            machos += 1
            print("%s\tfat\t%s" % (p, ",".join(names)))

sys.stderr.write("  walk: %d files read, %d Mach-O\n" % (files, machos))
PY
}

# ---- main -------------------------------------------------------------------
if [ -n "$LAYOUT" ]; then
	[ -d "$LAYOUT" ] || die "not a directory: $LAYOUT"
	if [ -n "$KEEP" ]; then
		mkdir -p "$KEEP"
		TREE="$KEEP"
	else
		WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/mlx-walk.XXXXXX")"
		TREE="$WORKDIR/rootfs"
		mkdir -p "$TREE"
	fi
	echo "==> unpack $LAYOUT"
	unpack_layout "$LAYOUT" "$TREE"
else
	[ -d "$TREE" ] || die "not a directory: $TREE"
fi

echo "==> classify (Mach-O magic, one pass)"
CAND="$(mktemp "${TMPDIR:-/tmp}/mlx-walk-cand.XXXXXX")"
trap 'rm -f "$CAND"; cleanup' EXIT INT TERM
START="$(date +%s)"
classify "$TREE" > "$CAND"

echo "==> verify signatures (per architecture: $ARCH_PREF)"
ok=0; bad=0; foreign=0; fat=0
while IFS=$'\t' read -r path kind arches; do
	[ "$kind" = fat ] && fat=$((fat + 1))
	want=""
	for a in $ARCH_PREF; do
		case ",$arches," in *",$a,"*) want="$a"; break ;; esac
	done
	rel="${path#"$TREE"/}"
	if [ -z "$want" ]; then
		# No slice for the target architecture. Dead weight in a darwin/arm64
		# image, but not a signature failure: nothing will ever execute it.
		foreign=$((foreign + 1))
		echo "  NO TARGET SLICE  $rel [$arches]"
		continue
	fi
	if msg="$(codesign -v --arch "$want" "$path" 2>&1)"; then
		ok=$((ok + 1))
		[ "$VERBOSE" -eq 0 ] || echo "  ok ($want)  $rel"
	else
		bad=$((bad + 1))
		echo "  INVALID ($want)  $rel: $(printf '%s' "$msg" | head -1 | sed 's|^.*: ||')"
	fi
done < "$CAND"
ELAPSED=$(( $(date +%s) - START ))

if [ -n "$ENTRYPOINT" ]; then
	ep="$TREE$ENTRYPOINT"
	if [ ! -f "$ep" ]; then
		echo "  ENTRYPOINT $ENTRYPOINT is not a file in the payload" >&2
		bad=$((bad + 1))
	elif ! grep -qF "$ep	" "$CAND"; then
		echo "  ENTRYPOINT $ENTRYPOINT is not a Mach-O — argv[0] must be the interpreter binary itself, not a script or a symlink" >&2
		bad=$((bad + 1))
	else
		echo "  entrypoint: $ENTRYPOINT is a signed Mach-O in the payload"
	fi
fi

echo "  totals: $((ok + bad + foreign)) Mach-O ($fat universal), $ok valid, $bad invalid, $foreign without a target slice, ${ELAPSED}s"
if [ "$bad" -gt 0 ]; then
	echo "walk-verify: FAIL — $bad Mach-O did not verify for the target architecture" >&2
	exit 1
fi
echo "walk-verify: OK"
