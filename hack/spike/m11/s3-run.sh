#!/usr/bin/env bash
# M11.0-d3 / S3 — the virtiofs slice, RUN. One hard gate, four recordings.
#
# s3.sh is the RUNBOOK: it owns every criterion's statement and the branch
# consequence each observed answer selects. THIS script RUNS the no-root subset
# and prints every answer as a greppable S3_<criterion>_<key>=<value> console
# line, so findings-s3.md is transcribed from observation rather than written
# from memory. It is the S3 analogue of s5-run.sh and reuses its machinery.
#
# WHY THIS SCRIPT EXISTS AT ALL. The 2026-08-31 S5 sitting recorded that the
# S1/S5 throwaway kernel (Ubuntu 6.8.0-138-generic) CANNOT mount a virtiofs
# share: it builds virtio_fs as a MODULE and an initramfs holds no module tree,
# so every S3 measurement was unreachable — and 6.8 is below the >=6.12 floor
# S3(2) needs in any case. This script fixes both at once with a DIFFERENT
# throwaway: the Ubuntu 25.04 (plucky) arm64 cloud kernel, 6.14.0-37-generic,
# plus the exact matching linux-modules .deb. Only virtiofs.ko is extracted
# (fuse.ko is BUILT IN to that kernel, and virtiofs declares `depends=` empty —
# both facts are recorded from the artifacts, not assumed), and the guest's Go
# PID 1 loads it with finit_module(2) before mounting the tag.
#
# It stays a THROWAWAY. The pinned product kernel is B111's human-gated job;
# making a design-invalidating spike wait on a human-gated producer would invert
# the dependency. What this kernel buys is a floor: >=6.12 with a loadable
# virtiofs, which is the minimum on which S3(2) is even askable.
#
# What runs here (no sudo, no root on the HOST; the guest's PID 1 is of course
# root INSIDE the guest, which is where every privileged operation happens):
#   2      the idmapped-mount GATE over virtiofs, with a tmpfs positive control
#          and a MOUNT_ATTR_NOSUID discriminator on the same virtiofs tree
#   1-lite guest fsync on the RW share, N=50, with a tmpfs contrast
#   4      emptyDir-shaped IO: sequential write/read and random write, share and
#          tmpfs
#   5      APFS case-collision through virtiofs (host creates `File` and `file`;
#          the guest is asked what it sees)
#
# What does NOT run here, and why — recorded, never faked:
#   1 (pgbench)  there is no database in a throwaway minirootfs guest, and
#                installing one would make the measurement about the install.
#   3 (sidecar)  needs the product unpacker's extracted image tree, which does
#                not exist yet.
#   6 (confined) needs the vmhost confinement wiring; S1(5) answered COEXISTENCE,
#                which is a different question from throughput.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

# ---------------------------------------------------------------- the pins
# Every artifact is pinned by URL AND sha256, and the sha256 is re-verified on
# EVERY run rather than only on the first fetch: a moved-on archive artifact
# would silently change the kernel every figure below was taken under.
#
# The two must MATCH. A linux-modules tree from a different ABI build produces a
# vermagic mismatch and finit_module fails — so the deb's version string is
# derived from the same source pin as the kernel, and the guest re-reports
# /proc/version so the pairing is visible in the log.
PLUCKY_KVER="${K3SM_SPIKE_S3_KVER:-6.14.0-37-generic}"
PLUCKY_VMLINUZ_URL="${K3SM_SPIKE_S3_KERNEL_URL:-https://cloud-images.ubuntu.com/releases/25.04/release/unpacked/ubuntu-25.04-server-cloudimg-arm64-vmlinuz-generic}"
PLUCKY_VMLINUZ_SHA256="${K3SM_SPIKE_S3_KERNEL_SHA256:-d2e9d1adff7ac3d40672ad9d2c2b3215cfa8b0982ad61886844e2439b11e7e6c}"
PLUCKY_MODULES_URL="${K3SM_SPIKE_S3_MODULES_URL:-http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-modules-6.14.0-37-generic_6.14.0-37.37_arm64.deb}"
PLUCKY_MODULES_SHA256="${K3SM_SPIKE_S3_MODULES_SHA256:-303be0928f375883f67f9739327036dcb5680df648769b08eb88b1a58b645a13}"

# The guest userland: the SAME pinned Alpine minirootfs the S5 sitting used, so
# the two spikes' guests are comparable and only the kernel differs.
ALPINE_URL="${K3SM_SPIKE_ALPINE_URL:-https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz}"
ALPINE_SHA256="${K3SM_SPIKE_ALPINE_SHA256:-f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259}"

# The x/sys pin the guest helper builds against — the same version k3sm's own
# go.mod carries, so MountSetattr/OpenTree behave here exactly as they would in
# the product.
XSYS_PIN="${K3SM_SPIKE_S3_XSYS:-v0.45.0}"

# Workload sizes. Small on purpose: these are shape measurements for a design
# decision, not a benchmark suite, and a throwaway guest on a shared rig cannot
# support a benchmark claim anyway.
S3_N_FSYNC="${K3SM_SPIKE_S3_N_FSYNC:-50}"
S3_IO_MB="${K3SM_SPIKE_S3_IO_MB:-64}"
S3_RAND_OPS="${K3SM_SPIKE_S3_RAND_OPS:-1024}"

# lab3 — lib.sh's lab() plus the S3 pins and helpers. Kept here rather than
# widened into lib.sh so s1.sh's and s5-run.sh's environments are untouched.
lab3() {
  {
    printf '%s\n' "$LAB_PREAMBLE"
    printf 'PLUCKY_KVER=%s\n'            "$PLUCKY_KVER"
    printf 'PLUCKY_VMLINUZ_URL=%s\n'     "$PLUCKY_VMLINUZ_URL"
    printf 'PLUCKY_VMLINUZ_SHA256=%s\n'  "$PLUCKY_VMLINUZ_SHA256"
    printf 'PLUCKY_MODULES_URL=%s\n'     "$PLUCKY_MODULES_URL"
    printf 'PLUCKY_MODULES_SHA256=%s\n'  "$PLUCKY_MODULES_SHA256"
    printf 'ALPINE_URL=%s\n'             "$ALPINE_URL"
    printf 'ALPINE_SHA256=%s\n'          "$ALPINE_SHA256"
    printf 'XSYS_PIN=%s\n'               "$XSYS_PIN"
    printf 'S3_N_FSYNC=%s\n'             "$S3_N_FSYNC"
    printf 'S3_IO_MB=%s\n'               "$S3_IO_MB"
    printf 'S3_RAND_OPS=%s\n'            "$S3_RAND_OPS"
    printf '%s\n' "$S3_HELPERS"
    cat
  } | ssh "$HOST" "PREFIX=$PREFIX bash -s"
}

read -r -d '' S3_HELPERS <<'HELPEOF' || true
# spawn TIMEOUT LOG CMD... -> sets SPAWN_PID and SPAWN_WATCH. macOS /bin/bash is
# 3.2: no namerefs, no associative arrays, so the caller copies the globals.
#
# EVERY fd of both children is detached from the ssh session's stdio, and the
# watchdog POLLS rather than sleeping the whole timeout. Both are load-bearing,
# not tidiness: a background `sleep <timeout>` that inherits the session's
# stdout keeps the ssh channel open long after the phase has finished — the
# harness appears to hang for the full watchdog interval with every answer
# already printed. Polling also lets the watchdog retire the instant its child
# exits, so a fast phase costs its own duration and no more.
spawn() {
  local secs="$1" log="$2"; shift 2
  "$@" > "$log" 2>&1 < /dev/null &
  SPAWN_PID=$!
  (
    i=0
    while [ "$i" -lt "$secs" ]; do
      kill -0 "$SPAWN_PID" 2>/dev/null || exit 0
      sleep 1; i=$((i + 1))
    done
    kill -TERM "$SPAWN_PID" 2>/dev/null
    sleep 3
    kill -KILL "$SPAWN_PID" 2>/dev/null
  ) >/dev/null 2>&1 < /dev/null &
  SPAWN_WATCH=$!
}
# reap PID WATCHPID — wait for the child, then retire its watchdog.
reap() {
  local rc=0
  wait "$1" 2>/dev/null || rc=$?
  kill -TERM "$2" 2>/dev/null || true
  wait "$2" 2>/dev/null || true
  return "$rc"
}
# field LOG KEY — the value of the first KEY=... console line.
field() { grep -m1 "$2=" "$1" 2>/dev/null | sed "s/.*$2=//" | tr -d '\r'; }
# fetch_pinned URL SHA256 DEST — fetch once, verify EVERY time.
fetch_pinned() {
  local url="$1" want="$2" dest="$3" got
  [ -f "$dest" ] || curl -fsSL -o "$dest" "$url" || { echo "S3 SETUP FAIL: fetch $url"; return 1; }
  got=$(shasum -a 256 "$dest" | awk '{print $1}')
  echo "S3_PIN_$(basename "$dest")=$got"
  [ "$got" = "$want" ] || { echo "S3 SETUP FAIL: sha256 mismatch for $dest (pinned $want, got $got)"; return 1; }
}
# s3_preflight — the host tools this spike needs beyond lib.sh's set. `ar`,
# `tar` and `zstd` are what turn a Debian package into a loadable .ko on macOS.
s3_preflight() {
  local missing=0
  command -v ar    >/dev/null || { echo "S3 PREFLIGHT FAIL: ar not found";    missing=1; }
  command -v tar   >/dev/null || { echo "S3 PREFLIGHT FAIL: tar not found";   missing=1; }
  command -v zstd  >/dev/null || { echo "S3 PREFLIGHT FAIL: zstd not found (brew install zstd)"; missing=1; }
  command -v gzip  >/dev/null || { echo "S3 PREFLIGHT FAIL: gzip not found";  missing=1; }
  [ "$missing" -eq 0 ] || return 1
  echo "s3 preflight ok"
}
HELPEOF

note "S3 — preflight: S1 must have reported GO"
if ! grep -qiE '^\*\*Verdict:\*\* *_?\(?GO' "$HERE/findings-s1.md" 2>/dev/null; then
  cat <<'EOF'
  findings-s1.md does not record a GO.

  S3 extends S1's harness and is meaningless if the boot path is invalid. Run
  s1.sh, record its verdict, and re-run this. If S1 recorded NO-GO on criterion
  1 or 2, M11 halts under the M11 plan's R19(b) and S3 is moot.
EOF
  exit 1
fi

note "S3 phase 0 — the >=6.12 throwaway kernel and its matching module tree"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
mkdir -p out s3/tools s3/mods
spike_preflight
s3_preflight
cd s3

fetch_pinned "$PLUCKY_VMLINUZ_URL" "$PLUCKY_VMLINUZ_SHA256" vmlinuz.gz
echo "S3_KERNEL_URL=$PLUCKY_VMLINUZ_URL"
echo "S3_KERNEL_SHA256=$PLUCKY_VMLINUZ_SHA256"

# VZLinuxBootLoader rejects a gzipped Image (S1 criterion 2's gzip control
# recorded that as a fact), so the cloud vmlinuz is decompressed host-side.
gzip -dc vmlinuz.gz > Image
echo "S3_KERNEL_IMAGE_BYTES=$(stat -f%z Image)"
echo "S3_KERNEL_VERSION_STRING=$(strings -a Image | grep -m1 -E '^Linux version [0-9]' | cut -c1-120)"

fetch_pinned "$PLUCKY_MODULES_URL" "$PLUCKY_MODULES_SHA256" modules.deb
echo "S3_MODULES_URL=$PLUCKY_MODULES_URL"
echo "S3_MODULES_SHA256=$PLUCKY_MODULES_SHA256"

# ------------------------------------------------- the module tree, minimally
# ONLY the modules the virtiofs mount needs are extracted. Which ones those are
# is DERIVED from the package, not assumed:
#   * modules.builtin says whether fuse is already =y (on this kernel it is);
#   * the .ko's own .modinfo `depends=` line names anything else it needs.
# Both are echoed, so a future kernel that changes either is visible in the log
# rather than silently mis-handled.
rm -rf debx && mkdir -p debx && cd debx
ar x ../modules.deb 2>/dev/null || { echo "S3 SETUP FAIL: ar x on the .deb"; exit 1; }
DATA=$(ls data.tar data.tar.zst data.tar.xz data.tar.gz 2>/dev/null | head -1 || true)
[ -n "$DATA" ] || { echo "S3 SETUP FAIL: no data member in the .deb"; exit 1; }
echo "S3_MODULES_DATA_MEMBER=$DATA"

MODROOT="./lib/modules/$PLUCKY_KVER"
tar xf "$DATA" "$MODROOT/modules.builtin" 2>/dev/null || true
if [ -f "lib/modules/$PLUCKY_KVER/modules.builtin" ]; then
  echo "S3_MOD_FUSE_BUILTIN=$(grep -c 'fs/fuse/fuse.ko' "lib/modules/$PLUCKY_KVER/modules.builtin" || true)"
  echo "S3_MOD_VIRTIO_BUILTIN=$(grep -cE 'drivers/virtio/virtio(_pci|_mmio)?\.ko' "lib/modules/$PLUCKY_KVER/modules.builtin" || true)"
else
  echo "S3_MOD_BUILTIN_LIST=absent"
fi

# The candidate set: everything under kernel/fs/fuse/ that is virtiofs or fuse.
# cuse is deliberately not shipped — it is not on the mount path.
CANDS=$(tar tf "$DATA" 2>/dev/null | grep -E "kernel/fs/fuse/(virtiofs|fuse)\.ko" || true)
echo "S3_MOD_CANDIDATES=$(echo "$CANDS" | tr '\n' ' ')"
[ -n "$CANDS" ] || { echo "S3 SETUP FAIL: no virtiofs module in the package"; exit 1; }
for c in $CANDS; do tar xf "$DATA" "$c" 2>/dev/null || true; done

# .ko.zst is Ubuntu's on-disk form; the guest's finit_module wants a plain ELF,
# so decompression happens HOST-side rather than shipping a zstd decoder into
# the initramfs.
cd "$PREFIX/s3"
rm -f mods/*.ko
for f in $(cd debx && find lib -name '*.ko*' -type f); do
  base=$(basename "$f"); base="${base%.zst}"
  case "$f" in
    *.zst) zstd -q -d -f "debx/$f" -o "mods/$base" ;;
    *)     cp "debx/$f" "mods/$base" ;;
  esac
  echo "S3_MOD_EXTRACTED=$base bytes=$(stat -f%z "mods/$base")"
  echo "S3_MOD_DEPENDS_$base=$(strings -a "mods/$base" | grep -m1 '^depends=' || echo 'depends=(none declared)')"
  echo "S3_MOD_VERMAGIC_$base=$(strings -a "mods/$base" | grep -m1 '^vermagic=' || echo 'vermagic=(absent)')"
done
LABEOF

note "S3 phase 1 — the guest: pinned Alpine userland + a static Go PID 1 that IS the probe"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX/s3"

fetch_pinned "$ALPINE_URL" "$ALPINE_SHA256" alpine.tar.gz
echo "S3_ROOTFS_URL=$ALPINE_URL"
echo "S3_ROOTFS_SHA256=$ALPINE_SHA256"

rm -rf rootfs && mkdir -p rootfs
tar xzf alpine.tar.gz -C rootfs
mkdir -p rootfs/mods
cp mods/*.ko rootfs/mods/
echo "S3_ROOTFS_FILES=$(find rootfs | wc -l | tr -d ' ')"

# --------------------------------------------------------------- the guest PID 1
# ONE static binary is both init and every probe. That is deliberate: mount_setattr
# needs CAP_SYS_ADMIN in the mount's userns and a userns fd it created itself, so
# the measuring code has to BE the privileged process rather than shell out to one.
mkdir -p s3init
cat > s3init/main.go <<'GOEOF'
// s3init — the S3 guest: PID 1 in a throwaway VZ Linux guest, and every S3
// probe. Each line it prints on the console is a finding; the host harness
// greps S3_ out of the captured console and nothing else is transcribed.
package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// errstr renders an error as BOTH the errno name and its number. A bare
// "invalid argument" is not a finding: EINVAL and EOPNOTSUPP from
// mount_setattr point at different causes (this mount vs this filesystem
// type), and the S3(2) re-plan depends on which one it was.
func errstr(err error) string {
	if err == nil {
		return "nil"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("%s(errno=%d) %q", errnoName(errno), int(errno), errno.Error())
	}
	return fmt.Sprintf("non-errno %v", err)
}

func errnoName(e unix.Errno) string {
	switch e {
	case unix.EINVAL:
		return "EINVAL"
	case unix.EOPNOTSUPP:
		return "EOPNOTSUPP"
	case unix.EPERM:
		return "EPERM"
	case unix.ENOSYS:
		return "ENOSYS"
	case unix.ENODEV:
		return "ENODEV"
	case unix.EACCES:
		return "EACCES"
	case unix.EBUSY:
		return "EBUSY"
	default:
		return "errno"
	}
}

// mountAt mounts one filesystem and reports the outcome. Nothing has run before
// PID 1 in an initramfs, so /proc, /sys and /dev are all absent, and every
// probe below depends on at least one of them.
func mountAt(src, target, fstype, data string) bool {
	_ = os.MkdirAll(target, 0o755)
	if err := unix.Mount(src, target, fstype, 0, data); err != nil {
		fmt.Printf("S3_MOUNT_%s=fail target=%s err=%s\n", strings.ToUpper(fstype), target, errstr(err))
		return false
	}
	fmt.Printf("S3_MOUNT_%s=ok target=%s\n", strings.ToUpper(fstype), target)
	return true
}

// loadModules loads every .ko in /mods with finit_module(2). Order is
// dependency order by construction: the host harness ships only modules whose
// declared `depends=` are satisfied by built-ins, and echoes that derivation.
func loadModules() {
	ents, err := os.ReadDir("/mods")
	if err != nil {
		fmt.Printf("S3_MODLOAD=fail err=%v\n", err)
		return
	}
	// fuse before virtiofs, if a future kernel ships fuse as a module too.
	names := []string{}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.HasPrefix(names[i], "fuse") && !strings.HasPrefix(names[j], "fuse")
	})
	for _, n := range names {
		f, err := os.Open("/mods/" + n)
		if err != nil {
			fmt.Printf("S3_MODLOAD_%s=open-fail err=%v\n", n, err)
			continue
		}
		err = unix.FinitModule(int(f.Fd()), "", 0)
		_ = f.Close()
		if err != nil {
			fmt.Printf("S3_MODLOAD_%s=fail err=%s\n", n, errstr(err))
			continue
		}
		fmt.Printf("S3_MODLOAD_%s=ok\n", n)
	}
}

// userns forks a child into a fresh user namespace with an explicit,
// non-identity mapping and returns an fd on its user namespace. mount_setattr's
// MOUNT_ATTR_IDMAP takes a userns FD, and a process cannot hand it its own
// namespace — so a child is the only way to obtain one without the measuring
// process giving up the CAP_SYS_ADMIN the syscall requires.
func userns() (int, *exec.Cmd, error) {
	c := exec.Command("/bin/sleep", "300")
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		GidMappingsEnableSetgroups: true,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 65536}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 65536}},
	}
	if err := c.Start(); err != nil {
		return -1, nil, err
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/user", c.Process.Pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
		return -1, nil, err
	}
	return fd, c, nil
}

// setattr clones a detached mount tree at path and applies one mount attribute
// to it. MOUNT_ATTR_IDMAP is only ever accepted on a DETACHED tree, which is
// why every attempt goes through open_tree(OPEN_TREE_CLONE) first — including
// the NOSUID discriminator, so the two differ in exactly one bit.
func setattr(label, path string, attr *unix.MountAttr) {
	tfd, err := unix.OpenTree(unix.AT_FDCWD, path,
		unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|uint(unix.AT_RECURSIVE))
	if err != nil {
		fmt.Printf("S3_C2_%s=opentree-fail path=%s err=%s\n", label, path, errstr(err))
		return
	}
	defer unix.Close(tfd)
	if err := unix.MountSetattr(tfd, "", unix.AT_EMPTY_PATH, attr); err != nil {
		fmt.Printf("S3_C2_%s=FAIL path=%s err=%s\n", label, path, errstr(err))
		return
	}
	fmt.Printf("S3_C2_%s=OK path=%s\n", label, path)
}

// idmapGate is S3(2). Three probes, differing in one variable each, so a
// failure on the gate cannot be blamed on the helper, the namespace, or the
// syscall's availability:
//
//	CONTROL_TMPFS   same helper, same userns, a filesystem KNOWN to allow idmap
//	VIRTIOFS_NOSUID same virtiofs tree, same open_tree, a DIFFERENT attribute
//	VIRTIOFS_IDMAP  the gate itself
func idmapGate(sharePath, ctlPath string) {
	nsfd, child, err := userns()
	if err != nil {
		fmt.Printf("S3_C2_USERNS=fail err=%v\n", err)
		fmt.Println("S3_C2_VERDICT=INDETERMINATE (no user namespace could be created; the gate was not measured)")
		return
	}
	defer func() { _ = child.Process.Kill(); _, _ = child.Process.Wait(); _ = unix.Close(nsfd) }()
	fmt.Printf("S3_C2_USERNS=ok map=0:1000:65536\n")

	idmap := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_IDMAP, Userns_fd: uint64(nsfd)}
	nosuid := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID}

	setattr("CONTROL_TMPFS_IDMAP", ctlPath, idmap)
	setattr("VIRTIOFS_NOSUID", sharePath, nosuid)

	// The gate, run last so the two controls are already on the console
	// whatever it does.
	tfd, err := unix.OpenTree(unix.AT_FDCWD, sharePath,
		unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|uint(unix.AT_RECURSIVE))
	if err != nil {
		fmt.Printf("S3_C2_VIRTIOFS_IDMAP=opentree-fail err=%s\n", errstr(err))
		fmt.Println("S3_C2_VERDICT=INDETERMINATE (the virtiofs tree could not be cloned at all)")
		return
	}
	defer unix.Close(tfd)
	err = unix.MountSetattr(tfd, "", unix.AT_EMPTY_PATH, idmap)
	if err != nil {
		fmt.Printf("S3_C2_VIRTIOFS_IDMAP=FAIL err=%s\n", errstr(err))
		fmt.Println("S3_C2_VERDICT=NO")
		return
	}
	fmt.Println("S3_C2_VIRTIOFS_IDMAP=OK")
	_ = os.MkdirAll("/mnt/idmapped", 0o755)
	if err := unix.MoveMount(tfd, "", unix.AT_FDCWD, "/mnt/idmapped", unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		fmt.Printf("S3_C2_IDMAP_ATTACH=fail err=%s\n", errstr(err))
		fmt.Println("S3_C2_VERDICT=YES (mount_setattr accepted MOUNT_ATTR_IDMAP; the attach failed separately)")
		return
	}
	fmt.Println("S3_C2_IDMAP_ATTACH=ok target=/mnt/idmapped")
	// The shift, demonstrated rather than asserted.
	var a, b unix.Stat_t
	if err := unix.Stat(sharePath+"/MARKER", &a); err == nil {
		if err := unix.Stat("/mnt/idmapped/MARKER", &b); err == nil {
			fmt.Printf("S3_C2_IDMAP_SHIFT=plain uid=%d gid=%d idmapped uid=%d gid=%d\n", a.Uid, a.Gid, b.Uid, b.Gid)
		}
	}
	fmt.Println("S3_C2_VERDICT=YES")
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	i := int(p * float64(len(d)-1))
	return d[i]
}

// fsyncBench is S3(1-lite): create, write, fsync, close, N times. The figure
// that matters is the DISTRIBUTION, not the mean — a virtiofs fsync that is
// sometimes a host F_FULLFSYNC and sometimes not would show as a bimodal tail.
func fsyncBench(label, dir string, n int) {
	_ = os.MkdirAll(dir, 0o755)
	ds := make([]time.Duration, 0, n)
	buf := make([]byte, 4096)
	fails := 0
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("%s/fsync-%d", dir, i)
		t0 := time.Now()
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			fails++
			continue
		}
		if _, err := f.Write(buf); err != nil {
			fails++
			_ = f.Close()
			continue
		}
		if err := f.Sync(); err != nil {
			fmt.Printf("S3_C1_%s_FSYNC_ERR=%s\n", label, errstr(err))
			fails++
			_ = f.Close()
			continue
		}
		_ = f.Close()
		ds = append(ds, time.Since(t0))
		_ = os.Remove(p)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	if len(ds) == 0 {
		fmt.Printf("S3_C1_%s_FSYNC=all-failed n=%d\n", label, n)
		return
	}
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	fmt.Printf("S3_C1_%s_FSYNC=ok n=%d failures=%d min_us=%d median_us=%d p95_us=%d max_us=%d mean_us=%d\n",
		label, len(ds), fails,
		ds[0].Microseconds(), percentile(ds, 0.5).Microseconds(),
		percentile(ds, 0.95).Microseconds(), ds[len(ds)-1].Microseconds(),
		(total / time.Duration(len(ds))).Microseconds())
}

func mbps(bytes int64, d time.Duration) string {
	if d <= 0 {
		return "inf"
	}
	return strconv.FormatFloat(float64(bytes)/1048576.0/d.Seconds(), 'f', 1, 64)
}

// dropCaches makes the sequential-read figure a read of the BACKING STORE
// rather than of the guest page cache. Without it the "read" number is the
// speed of memcpy and says nothing about virtiofs.
func dropCaches() {
	if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o644); err != nil {
		fmt.Printf("S3_C4_DROPCACHES=fail err=%v\n", err)
		return
	}
	fmt.Println("S3_C4_DROPCACHES=ok")
}

// ioBench is S3(4): the emptyDir-shaped access pattern. Sequential write (1 MiB
// records, fsync at the end so the cost of durability is inside the figure),
// sequential read after a cache drop, and a bounded random 4 KiB write pass.
func ioBench(label, dir string, mb, randOps int) {
	_ = os.MkdirAll(dir, 0o755)
	p := dir + "/io.dat"
	rec := make([]byte, 1<<20)
	for i := range rec {
		rec[i] = byte(i)
	}

	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		fmt.Printf("S3_C4_%s_SEQW=fail err=%v\n", label, err)
		return
	}
	t0 := time.Now()
	for i := 0; i < mb; i++ {
		if _, err := f.Write(rec); err != nil {
			fmt.Printf("S3_C4_%s_SEQW=fail err=%v\n", label, err)
			_ = f.Close()
			return
		}
	}
	if err := f.Sync(); err != nil {
		fmt.Printf("S3_C4_%s_SEQW_FSYNC=fail err=%s\n", label, errstr(err))
	}
	dw := time.Since(t0)
	_ = f.Close()
	fmt.Printf("S3_C4_%s_SEQW=ok mib=%d elapsed_ms=%d mib_per_s=%s\n", label, mb, dw.Milliseconds(), mbps(int64(mb)<<20, dw))

	dropCaches()
	rf, err := os.Open(p)
	if err != nil {
		fmt.Printf("S3_C4_%s_SEQR=fail err=%v\n", label, err)
		return
	}
	t1 := time.Now()
	var got int64
	for {
		n, err := rf.Read(rec)
		got += int64(n)
		if err != nil {
			break
		}
	}
	dr := time.Since(t1)
	_ = rf.Close()
	fmt.Printf("S3_C4_%s_SEQR=ok bytes=%d elapsed_ms=%d mib_per_s=%s\n", label, got, dr.Milliseconds(), mbps(got, dr))

	// Random 4 KiB writes at a FIXED seed, so a re-run addresses the same
	// offsets and two runs are comparable.
	wf, err := os.OpenFile(p, os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Printf("S3_C4_%s_RANDW=fail err=%v\n", label, err)
		return
	}
	rnd := rand.New(rand.NewSource(20260831))
	blk := make([]byte, 4096)
	span := int64(mb) << 20
	t2 := time.Now()
	for i := 0; i < randOps; i++ {
		off := rnd.Int63n(span-4096) &^ 4095
		if _, err := wf.WriteAt(blk, off); err != nil {
			fmt.Printf("S3_C4_%s_RANDW=fail at=%d err=%v\n", label, i, err)
			_ = wf.Close()
			return
		}
	}
	if err := wf.Sync(); err != nil {
		fmt.Printf("S3_C4_%s_RANDW_FSYNC=fail err=%s\n", label, errstr(err))
	}
	d2 := time.Since(t2)
	_ = wf.Close()
	iops := float64(randOps) / d2.Seconds()
	fmt.Printf("S3_C4_%s_RANDW=ok ops=%d block=4096 elapsed_ms=%d mib_per_s=%s iops=%s\n",
		label, randOps, d2.Milliseconds(), mbps(int64(randOps)*4096, d2), strconv.FormatFloat(iops, 'f', 0, 64))
	_ = os.Remove(p)
}

// caseProbe is S3(5). The host created `File` and then `file` in the shared
// directory on a case-INSENSITIVE APFS volume. What the guest — whose own
// filesystem semantics are case-SENSITIVE — sees through virtiofs is the fact
// the extractor's collision detection has to be designed against.
func caseProbe(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("S3_C5_LIST=fail err=%v\n", err)
		return
	}
	names := []string{}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	fmt.Printf("S3_C5_GUEST_LIST=%s\n", strings.Join(names, ","))

	var a, b unix.Stat_t
	ea := unix.Stat(dir+"/File", &a)
	eb := unix.Stat(dir+"/file", &b)
	fmt.Printf("S3_C5_STAT_UPPER=%s\n", statLine(ea, &a))
	fmt.Printf("S3_C5_STAT_LOWER=%s\n", statLine(eb, &b))
	if ea == nil && eb == nil {
		fmt.Printf("S3_C5_SAME_INODE=%v ino_upper=%d ino_lower=%d\n", a.Ino == b.Ino, a.Ino, b.Ino)
	}
	// Content is the decisive witness: two names resolving to one inode is a
	// collision even if the guest's readdir shows both.
	if ba, err := os.ReadFile(dir + "/File"); err == nil {
		fmt.Printf("S3_C5_CONTENT_UPPER=%s\n", strings.TrimSpace(string(ba)))
	}
	if bb, err := os.ReadFile(dir + "/file"); err == nil {
		fmt.Printf("S3_C5_CONTENT_LOWER=%s\n", strings.TrimSpace(string(bb)))
	}
	// And the guest's own attempt: can it CREATE a case-colliding pair here?
	_ = os.WriteFile(dir+"/Guest", []byte("guest-upper"), 0o644)
	err2 := os.WriteFile(dir+"/guest", []byte("guest-lower"), 0o644)
	gu, _ := os.ReadFile(dir + "/Guest")
	fmt.Printf("S3_C5_GUEST_CREATE=err=%v upper_after=%s\n", err2, strings.TrimSpace(string(gu)))
}

func statLine(err error, s *unix.Stat_t) string {
	if err != nil {
		return "err=" + errstr(err)
	}
	return fmt.Sprintf("ino=%d uid=%d gid=%d mode=%o size=%d", s.Ino, s.Uid, s.Gid, s.Mode, s.Size)
}

// cmdline reads the s3_* keys the harness passes on the kernel command line —
// the only channel a VZ bootloader gives us, since PID 1 in a guest inherits no
// environment from the host.
func cmdline() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return m
	}
	for _, f := range strings.Fields(string(b)) {
		if k, v, ok := strings.Cut(f, "="); ok && strings.HasPrefix(k, "s3_") {
			m[k] = v
		}
	}
	return m
}

func intKey(m map[string]string, k string, def int) int {
	if v, ok := m[k]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	mountAt("proc", "/proc", "proc", "")
	mountAt("sysfs", "/sys", "sysfs", "")
	mountAt("devtmpfs", "/dev", "devtmpfs", "")
	// A REAL tmpfs, not the initramfs rootfs: rootfs is ramfs on some
	// configurations and ramfs supports neither idmapped mounts nor a
	// meaningful IO figure, which would make the control prove nothing.
	mountAt("tmpfs", "/ctl", "tmpfs", "size=512m")

	if b, err := os.ReadFile("/proc/version"); err == nil {
		fmt.Printf("S3_GUEST_KVER=%s\n", strings.TrimSpace(string(b)))
	}
	loadModules()
	if b, err := os.ReadFile("/proc/filesystems"); err == nil {
		fmt.Printf("S3_GUEST_HAS_VIRTIOFS=%v\n", strings.Contains(string(b), "virtiofs"))
	}

	m := cmdline()
	tag := m["s3_share_tag"]
	if tag == "" {
		tag = "s3share"
	}
	share := "/mnt/share"
	_ = os.MkdirAll(share, 0o755)
	if err := unix.Mount(tag, share, "virtiofs", 0, ""); err != nil {
		fmt.Printf("S3_VIRTIOFS=unavailable tag=%s err=%s\n", tag, errstr(err))
		fmt.Println("S3_C2_VERDICT=INDETERMINATE (no virtiofs mount; the gate was not measured)")
		fmt.Println("S3_PROBE_COMPLETE=aborted-no-share")
		finish()
		return
	}
	fmt.Printf("S3_VIRTIOFS=mounted tag=%s\n", tag)
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.Contains(ln, "virtiofs") {
				fmt.Printf("S3_VIRTIOFS_MOUNTINFO=%s\n", ln)
			}
		}
	}
	// Writability is asserted, not assumed: every figure below is on an RW
	// share, and a silently-read-only share would turn them into error counts.
	// What the guest sees as the OWNER of a host file is the input the fsGroup
	// design consumes: an idmapped mount exists precisely to shift it. Recorded
	// next to the gate rather than left to be inferred from the case probe.
	var ms unix.Stat_t
	if err := unix.Stat(share+"/MARKER", &ms); err == nil {
		fmt.Printf("S3_SHARE_OWNERSHIP=uid=%d gid=%d mode=%o (as the GUEST sees a host-created file)\n", ms.Uid, ms.Gid, ms.Mode)
	} else {
		fmt.Printf("S3_SHARE_OWNERSHIP=unreadable err=%s\n", errstr(err))
	}
	if err := os.WriteFile(share+"/GUEST_WROTE", []byte("s3-guest\n"), 0o644); err != nil {
		fmt.Printf("S3_SHARE_RW=no err=%v\n", err)
	} else {
		fmt.Println("S3_SHARE_RW=yes")
	}

	// (2) THE GATE, first — nothing below it can invalidate it.
	idmapGate(share, "/ctl")

	// (5) the case-collision listing, before the IO passes litter the share.
	caseProbe(share)

	n := intKey(m, "s3_n_fsync", 50)
	mb := intKey(m, "s3_io_mb", 64)
	ro := intKey(m, "s3_rand_ops", 1024)

	// (1-lite) fsync. The share figure is the finding; the tmpfs figure is the
	// contrast that makes it readable.
	fsyncBench("SHARE", share+"/fsyncdir", n)
	fsyncBench("TMPFS", "/ctl/fsyncdir", n)
	fmt.Println("S3_C1_FSYNC_HOST_MAPPING=NOT OBSERVABLE from the guest (whether the host server issues fsync(2) or F_FULLFSYNC needs host-side tracing, which needs root)")
	fmt.Println("S3_PGBENCH=NOT RUN (no database in the throwaway guest)")

	// (4) emptyDir-shaped IO, share and tmpfs.
	ioBench("SHARE", share+"/iodir", mb, ro)
	ioBench("TMPFS", "/ctl/iodir", mb, ro)

	fmt.Println("S3_SIDECAR=NOT RUN (needs the product unpacker's extracted image tree)")
	fmt.Println("S3_CONFINED_THROUGHPUT=NOT RUN (needs the vmhost confinement wiring; S1(5) answered coexistence, not throughput)")
	fmt.Println("S3_PROBE_COMPLETE=ok")
	finish()
}

func finish() {
	_ = os.Stdout.Sync()
	time.Sleep(400 * time.Millisecond)
	// LINUX_REBOOT_CMD_POWER_OFF — the host harness waits for this transition.
	_ = unix.Reboot(0x4321fedc)
	select {}
}
GOEOF

(
  cd s3init
  [ -f go.mod ] || go mod init k3sm.local/s3init >/dev/null
  grep -q 'golang.org/x/sys' go.mod || go get "golang.org/x/sys@$XSYS_PIN" >/dev/null 2>&1
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o ../rootfs/init .
) || { echo "S3 SETUP FAIL: guest init cross-build"; exit 1; }

( cd rootfs && find . | cpio -o -H newc 2>/dev/null > ../initramfs.cpio ) \
  || { echo "S3 SETUP FAIL: cpio"; exit 1; }
echo "S3_INITRAMFS_BYTES=$(stat -f%z initramfs.cpio)"
LABEOF

note "S3 phase 2 — the vzs3 harness (an RW virtiofs share; S5's was read-only)"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX/s3"
mkdir -p vzs3

cat > vzs3/main.go <<'GOEOF'
// vzs3 — the S3 guest harness. One Linux guest, no network device (S3 asks
// nothing of the network and an unused NAT segment is only noise), and a
// READ-WRITE virtiofs share, which is what separates it from S5's harness:
// every S3 figure is a write figure.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Code-Hex/vz/v3"
)

func die(stage string, err error) {
	fmt.Printf("VZS3_FAIL stage=%s err=%v\n", stage, err)
	os.Exit(1)
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	kernel, initrd := os.Getenv("S3_KERNEL"), os.Getenv("S3_INITRD")
	tag := envDefault("S3_SHARE_TAG", "s3share")
	extra := os.Getenv("S3_CMDLINE")
	waitSecs, _ := strconv.Atoi(envDefault("S3_WAIT", "300"))
	mem, _ := strconv.ParseUint(envDefault("S3_MEM_MB", "2048"), 10, 64)

	cmdline := "console=hvc0 quiet s3_share_tag=" + tag
	if extra != "" {
		cmdline += " " + extra
	}
	bl, err := vz.NewLinuxBootLoader(kernel, vz.WithCommandLine(cmdline), vz.WithInitrd(initrd))
	if err != nil {
		die("bootloader", err)
	}
	cfg, err := vz.NewVirtualMachineConfiguration(bl, 2, mem*1024*1024)
	if err != nil {
		die("config", err)
	}
	att, err := vz.NewFileHandleSerialPortAttachment(os.Stdin, os.Stdout)
	if err != nil {
		die("console-attachment", err)
	}
	sc, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(att)
	if err != nil {
		die("console", err)
	}
	cfg.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{sc})

	dir := os.Getenv("S3_SHARE_DIR")
	if dir == "" {
		die("share-dir", fmt.Errorf("S3_SHARE_DIR is required — S3 is the virtiofs spike"))
	}
	fs, err := vz.NewVirtioFileSystemDeviceConfiguration(tag)
	if err != nil {
		die("virtiofs-device", err)
	}
	// readOnly=false: the S3 measurements are writes.
	sd, err := vz.NewSharedDirectory(dir, false)
	if err != nil {
		die("shared-directory", err)
	}
	share, err := vz.NewSingleDirectoryShare(sd)
	if err != nil {
		die("single-share", err)
	}
	fs.SetDirectoryShare(share)
	cfg.SetDirectorySharingDevicesVirtualMachineConfiguration([]vz.DirectorySharingDeviceConfiguration{fs})
	fmt.Printf("VZS3_SHARE=attached tag=%s rw=true\n", tag)

	if ok, err := cfg.Validate(); !ok || err != nil {
		die("validate", err)
	}
	vm, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		die("new-vm", err)
	}
	runtime.LockOSThread()
	t0 := time.Now()
	if err := vm.Start(); err != nil {
		die("start", err)
	}
	fmt.Printf("VZS3_CREATE_TO_START_NS=%d\n", time.Since(t0).Nanoseconds())

	deadline := time.After(time.Duration(waitSecs) * time.Second)
	for {
		select {
		case st := <-vm.StateChangedNotify():
			if st == vz.VirtualMachineStateStopped {
				fmt.Println("VZS3_STOPPED=yes")
				return
			}
		case <-deadline:
			fmt.Println("VZS3_STOPPED=no (deadline)")
			// Never leave a guest running behind the harness.
			_ = vm.Stop()
			time.Sleep(2 * time.Second)
			return
		}
	}
}
GOEOF

(
  cd vzs3
  [ -f go.mod ] || go mod init k3sm.local/vzs3 >/dev/null
  # The same vz release S1 proved the boot path on; pinned, never @latest.
  grep -q 'Code-Hex/vz' go.mod || go get github.com/Code-Hex/vz/v3@v3.7.1 >/dev/null 2>&1
  go build -o ../tools/vzs3 .
) || { echo "S3 SETUP FAIL: vzs3 build"; exit 1; }

# vzs3 constructs VMs, so it needs the same entitlement-only ad-hoc signature S1
# proved BOTH sufficient and necessary.
cat > ent.plist <<'PLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.virtualization</key><true/>
</dict></plist>
PLEOF
codesign -s - -f --entitlements ent.plist tools/vzs3 >/dev/null 2>&1
codesign --verify --strict tools/vzs3 && echo "S3_VZS3_SIGNED=ok"
LABEOF

note "S3 phase 3 — the host half of criterion 5: create a case-colliding pair on APFS"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX/s3"
rm -rf share && mkdir -p share
echo "s3-share-marker" > share/MARKER

# The APFS volume this prefix lives on is case-INSENSITIVE by default. Creating
# `File` and then `file` is therefore the collision the image extractor has to
# detect: on a case-sensitive Linux source tree those are two files.
echo "content-of-File" > share/File
echo "content-of-file" > share/file
# Case-sensitivity is measured, not queried: the two writes above just ran on
# this exact directory, so counting the entries they produced IS the answer, and
# it is the answer for the volume the share actually lives on rather than for /.
CASE_ENTRIES=$(ls -1 share | grep -ciE '^file$' || true)
if [ "$CASE_ENTRIES" = "1" ]; then
  echo "S3_C5_HOST_VOLUME=case-insensitive (writing File then file left ONE entry)"
else
  echo "S3_C5_HOST_VOLUME=case-sensitive (writing File then file left both entries)"
fi
echo "S3_C5_HOST_ENTRIES=$(ls -1 share | tr '\n' ',')"
echo "S3_C5_HOST_MARKER_OWNER=uid=$(stat -f%u share/MARKER) gid=$(stat -f%g share/MARKER)"
echo "S3_C5_HOST_LS=$(ls -li share | tr '\n' '|')"
echo "S3_C5_HOST_FILE_CONTENT=$(cat share/File 2>/dev/null)"
echo "S3_C5_HOST_file_CONTENT=$(cat share/file 2>/dev/null)"
LABEOF

note "S3 phase 4 — boot the guest and run every probe"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
S3DIR="$PREFIX/s3"
export S3_KERNEL="$S3DIR/Image" S3_INITRD="$S3DIR/initramfs.cpio"
export S3_SHARE_DIR="$S3DIR/share" S3_WAIT=420 S3_MEM_MB=2048
export S3_CMDLINE="s3_n_fsync=$S3_N_FSYNC s3_io_mb=$S3_IO_MB s3_rand_ops=$S3_RAND_OPS"

spawn 460 out/s3-guest.log "$S3DIR/tools/vzs3"
reap "$SPAWN_PID" "$SPAWN_WATCH" || true
echo "S3_GUEST_LOG_LINES=$(wc -l < out/s3-guest.log | tr -d ' ')"
echo "S3_C2_VERDICT_SEEN=$(field out/s3-guest.log S3_C2_VERDICT)"
LABEOF

note "S3 phase 5 — the host's view of the share AFTER the guest ran"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX/s3"
echo "S3_POST_HOST_ENTRIES=$(ls -1 share | tr '\n' ',')"
echo "S3_POST_GUEST_WROTE=$(cat share/GUEST_WROTE 2>/dev/null | tr -d '\n')"
echo "S3_POST_HOST_Guest_CONTENT=$(cat share/Guest 2>/dev/null)"
echo "S3_POST_HOST_LS=$(ls -li share | tr '\n' '|')"
LABEOF

note "S3 — every observed line, verbatim (this is what findings-s3.md transcribes)"

lab3 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
for f in out/s3-guest.log; do
  [ -f "$f" ] || { echo "== $f: ABSENT (that leg did not run)"; continue; }
  echo "== $f"
  grep -E '^(S3_|VZS3_)' "$f" | sed 's/^/   /' || true
done

# Leave no VM behind. Scoped to THIS prefix's binary so a co-resident harness on
# the rig is untouched.
pkill -f "$PREFIX/s3/tools/vzs3" 2>/dev/null || true
echo "S3_CLEANUP=done"
LABEOF

note "S3 — record every answer in findings-s3.md as a DECISION TABLE (see s3.sh for the branch consequences)"
