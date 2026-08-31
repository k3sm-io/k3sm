#!/usr/bin/env bash
# M11.0-d1 / S1 — minimal VZ Linux boot. THE DESIGN-INVALIDATING SPIKE.
#
# Everything in M11 is written on the assumption that this passes. It therefore
# runs FIRST and ALONE, and a NO-GO on criterion 1 or 2 fires the M11 plan's R19(b):
# a dated resolution, the m9 ledger row removed, the announcement reverted to
# the vm-EXPERIMENTAL-stub line. Never an ad-hoc gate waiver.
#
# Six criteria (k3sm/docs/PHASES.md M11.0-d1):
#   1 entitlement-only ad-hoc signing suffices        — GO/NO-GO, with counterfactual
#   2 console tokens from a real kernel boot          — GO/NO-GO, with gzip control
#   3 cold-boot latency, TWO figures                  — RECORDING
#   4 guest<->guest reachability                      — RECORDING (a security fact);
#                                                       run by s5-run.sh, mirrored here
#   5 Seatbelt x VZ coexistence in one process        — decides Resolution 7; BOTH
#                                                       orderings (confine-first, VM-first)
#   6 Rosetta availability probe safe when unentitled — HALTS the shipped label path
#
# Criterion 1 is the one most easily mis-proven. Observing that an entitled
# binary constructs a VM proves nothing about what is LOAD-BEARING, so this
# script also runs the same binary unsigned and ad-hoc-WITHOUT-entitlement and
# requires both to fail. Without that counterfactual the criterion is theatre.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

note "S1 — staging the lab-side harness on $HOST"

lab <<'LABEOF'
set -euo pipefail
PREFIX_EXPANDED="$PREFIX"
mkdir -p "$PREFIX_EXPANDED"/{bin,guest,out}
cd "$PREFIX_EXPANDED"

spike_preflight

echo "== rig =="
sw_vers -productVersion; uname -m; sysctl -n hw.model

# ---------------------------------------------------------------- the kernel
# Throwaway, not pinned: B111 owns the shipping artifact. VZLinuxBootLoader
# rejects a gzipped Image, so BOTH forms are kept — the gzipped one is the
# control for criterion 2b, which turns that constraint from a first-boot
# discovery into a recorded fact costing one boot attempt.
if [ ! -f guest/Image ]; then
  echo "== fetching a throwaway arm64 kernel =="
  curl -fsSL -o guest/vmlinuz.gz "$KERNEL_URL" || { echo "S1 SETUP FAIL: kernel fetch"; exit 1; }
  cp guest/vmlinuz.gz guest/Image.gz            # keep the gzipped control
  gunzip -c guest/vmlinuz.gz > guest/Image || { echo "S1 SETUP FAIL: gunzip"; exit 1; }
fi
echo "kernel sha256: $(shasum -a 256 guest/Image | awk '{print $1}')"
echo "kernel bytes:  $(stat -f%z guest/Image)"

# ------------------------------------------------------- the guest init + cpio
# A ~20-line static init, deliberately NOT the real k3sm-guest-init: S1 asks
# whether a VM boots at all, and coupling it to the product's PID1 would make a
# guest-init bug read as a boot failure.
mkdir -p guest/initramfs
cat > guest/init.go <<'GOEOF'
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// tokenFromCmdline reads s1_token= off /proc/cmdline. It CANNOT come from the
// environment: this process is PID 1 inside the guest, and the host's env does
// not cross the VM boundary. The kernel command line is the only channel the
// bootloader gives us.
func tokenFromCmdline() string {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(f, "s1_token="); ok {
			return v
		}
	}
	return ""
}

func main() {
	// /proc is NOT mounted for us: the initramfs is just this binary, and nothing
	// has run before PID 1. Both the token (criterion 2, off /proc/cmdline) and the
	// uptime figure (criterion 3) read from it, so mount it FIRST -- without this
	// every /proc read fails and the criteria report a boot problem that is really
	// a missing mount.
	_ = os.MkdirAll("/proc", 0o555)
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")

	// Criterion 2: the token proves userspace reached exec.
	// Criterion 3: the monotonic stamp is the far end of kernel-start -> init-exec.
	fmt.Printf("K3SM_S1_TOKEN=%s\n", tokenFromCmdline())
	fmt.Printf("K3SM_S1_INIT_EXEC_NS=%d\n", time.Now().UnixNano())
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fmt.Printf("K3SM_S1_UPTIME=%s", string(b))
	}
	fmt.Println("K3SM_S1_DONE")
	os.Stdout.Sync()
	time.Sleep(300 * time.Millisecond)
	// LINUX_REBOOT_CMD_POWER_OFF
	_ = syscall.Reboot(0x4321fedc)
	select {}
}
GOEOF
( cd guest && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o initramfs/init ./init.go ) \
  || { echo "S1 SETUP FAIL: guest init cross-build"; exit 1; }
( cd guest/initramfs && find . | cpio -o -H newc 2>/dev/null > ../initramfs.cpio ) \
  || { echo "S1 SETUP FAIL: cpio"; exit 1; }
echo "initramfs bytes: $(stat -f%z guest/initramfs.cpio)"
LABEOF

note "S1 — building the vzboot harness (Code-Hex/vz) on the lab Mac"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
mkdir -p vzboot && cd vzboot
[ -f go.mod ] || { go mod init k3sm.local/vzboot >/dev/null; go get github.com/Code-Hex/vz/v3 >/dev/null 2>&1; }
cat > main.go <<'GOEOF'
// vzboot — the S1 harness. Boots one Linux guest and prints what it sees.
// Modes: boot (criteria 2,3), pair (4), seatbelt (5), rosetta (6).
package main

/*
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>

// The private, deprecated libsandbox SPI, declared EXACTLY as runtimed's
// internal/execshim declares it (macOS 26, arm64) — criterion 5 is only
// meaningful if the spike confines itself the way the product does.
extern void *sandbox_compile_string(const char *data, void *params, char **error);
extern int   sandbox_apply(void *profile);
extern void  sandbox_free_error(char *error);

static int k3sm_apply_sbpl(const char *profile, char **errmsg) {
	char *err = NULL;
	void *p = sandbox_compile_string(profile, NULL, &err);
	if (p == NULL) {
		*errmsg = err;
		return 1;
	}
	if (sandbox_apply(p) != 0) {
		*errmsg = NULL;
		return 2;
	}
	*errmsg = NULL;
	return 0;
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/Code-Hex/vz/v3"
)

// podSBPLTemplate is a VERBATIM copy of what runtimed's
// pkg/sandbox/sbpl.go Generate() emits for a networked pod with no extra
// paths, no GPU, no denied helper sockets and no credential sub-scope —
// rule for rule and IN ORDER, with only the two site-specific paths
// substituted (@WORKDIR@, @DATAVOL@).
//
// MIRROR OBLIGATION: this literal has no compile-time link to Generate(). If
// Generate() gains, drops or reorders a rule, criterion 5's answer stops
// describing the profile the product actually applies, and this literal must
// be regenerated from Generate() before the criterion is re-quoted. It is
// copied rather than imported deliberately: the spike does not link runtimed
// (k3sm/hack/spike doctrine — the spikes stay standalone and never touch the
// product exec path).
const podSBPLTemplate = `;; k3sm per-pod Seatbelt profile — GENERATED, do not edit.
;; Default-deny; runs a native pod process at host paths (no chroot).
;; Rule order is last-match-wins: OS/extra allows, THEN protected
;; denies (so extra paths can't override them), THEN narrow re-allows.
(version 1)
(deny default)
(import "system.sb")
(allow process-exec*)
(allow process-fork)
;; read: OS + frameworks + validated extra read paths.
(allow file-read*
  (subpath "/Library")
  (subpath "/System")
  (subpath "/bin")
  (subpath "/usr")
  (literal "/dev/null") (literal "/dev/zero")
  (literal "/dev/random") (literal "/dev/urandom"))
;; write: validated extra write paths (+ /dev/null); the pod's own
;; data volume is re-allowed below, after the protected denies.
(allow file-write*
  (literal "/dev/null"))
;; network: ALLOWED — unfiltered outbound+bind+inbound under (deny default).
;; macOS 26 Seatbelt accepts only localhost/* hosts in network filters;
;; per-IP scoping (VIP egress, per-pod-IP bind) does NOT compile.
(allow network-outbound)
(allow network-bind)
(allow network-inbound)
;; mach-lookup the DNS resolver path (mDNSResponder) needs.
(allow mach-lookup
  (global-name "com.apple.dnssd.service")
  (global-name "com.apple.mDNSResponder"))
;; PROTECTED: deny user homes, the secrets/state store, the shared
;; pods root, the daemon-private podreap store AND the control-plane
;; and daemon trees (server, agent, run, blobs — sibling dirs under
;; the work-dir) — read+write, AFTER the allows so a caller's extra
;; path (even an ancestor work-dir grant) can't win.
(deny file-read* file-write*
  (subpath "/Users"))
(deny file-read* file-write*
  (subpath "/private/var/db"))
(deny file-read* file-write*
  (subpath "@WORKDIR@/pods")
  (subpath "@WORKDIR@/podreap")
  (subpath "@WORKDIR@/server")
  (subpath "@WORKDIR@/agent")
  (subpath "@WORKDIR@/run")
  (subpath "@WORKDIR@/blobs")
  (subpath "/var/lib/k3sm/run")
  (subpath "/private/var/lib/k3sm/run")
  )
;; dyld cryptex: deny WRITE only (read is needed at link time).
(deny file-write*
  (subpath "/System/Volumes/Preboot/Cryptexes")
  (subpath "/System/Cryptexes"))
;; re-allow the dyld closure cache read the /private/var/db deny clobbers.
(allow file-read*
  (subpath "/private/var/db/dyld"))
;; re-allow THIS pod's own data volume (under the denied pods root).
(allow file-read* file-write*
  (subpath "@DATAVOL@")
  )
`

// podSBPL renders the mirrored profile for one pod's work-dir and data volume.
func podSBPL(workDir, dataVol string) string {
	return strings.NewReplacer("@WORKDIR@", workDir, "@DATAVOL@", dataVol).Replace(podSBPLTemplate)
}

// confine compiles and applies profile to THIS process, irreversibly. It is a
// copy of runtimed internal/execshim.confine, for the same mirror reason.
func confine(profile string) error {
	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	var cErr *C.char
	rc := C.k3sm_apply_sbpl(cProfile, &cErr)
	if rc == 0 {
		return nil
	}
	msg := ""
	if cErr != nil {
		msg = C.GoString(cErr)
		C.sandbox_free_error(cErr)
	}
	if msg == "" {
		return fmt.Errorf("libsandbox apply failed (rc=%d)", int(rc))
	}
	return fmt.Errorf("libsandbox apply failed (rc=%d): %s", int(rc), msg)
}

func die(stage string, err error) {
	fmt.Printf("VZBOOT_FAIL stage=%s err=%v\n", stage, err)
	os.Exit(1)
}

// buildVM assembles the S1 guest (kernel + stub initramfs + virtio console,
// optionally a NAT device) and returns it unstarted. The failing stage name is
// returned alongside the error so every caller reports the same vocabulary.
func buildVM(kernel, initrd, token string, withNAT bool) (*vz.VirtualMachine, string, error) {
	bl, err := vz.NewLinuxBootLoader(kernel,
		vz.WithCommandLine("console=hvc0 quiet s1_token="+token),
		vz.WithInitrd(initrd))
	if err != nil {
		return nil, "bootloader", err
	}
	cfg, err := vz.NewVirtualMachineConfiguration(bl, 1, 512*1024*1024)
	if err != nil {
		return nil, "config", err
	}
	// Console -> our stdout, which is how the token and the timings get out.
	att, err := vz.NewFileHandleSerialPortAttachment(os.Stdin, os.Stdout)
	if err != nil {
		return nil, "console-attachment", err
	}
	sc, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(att)
	if err != nil {
		return nil, "console", err
	}
	cfg.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{sc})
	if withNAT {
		// Criterion 4 needs two guests on one NAT segment.
		nat, err := vz.NewNATNetworkDeviceAttachment()
		if err != nil {
			return nil, "nat", err
		}
		nc, err := vz.NewVirtioNetworkDeviceConfiguration(nat)
		if err != nil {
			return nil, "net", err
		}
		cfg.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{nc})
	}
	if ok, err := cfg.Validate(); !ok || err != nil {
		return nil, "validate", err
	}
	vm, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		return nil, "new-vm", err
	}
	return vm, "", nil
}

// waitStopped reports whether vm reached the Stopped state within d.
func waitStopped(vm *vz.VirtualMachine, d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case st := <-vm.StateChangedNotify():
			if st == vz.VirtualMachineStateStopped {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// runSeatbelt is criterion 5: does a process confined by the product's own pod
// profile still construct and start a VZ VM, and does the ANSWER DEPEND ON THE
// ORDER? order is "before" (sandbox_apply, then build+start) or "after"
// (build+start, then sandbox_apply).
//
// Every outcome is a valid recording. A denial here is NOT terminal for M11 —
// the M11 plan's R22 admits a documented residual — so this never exits
// non-zero for a denial, only for a harness fault.
func runSeatbelt(order string) {
	workDir, dataVol := os.Getenv("S1_SB_WORKDIR"), os.Getenv("S1_SB_DATAVOL")
	kernel, initrd := os.Getenv("S1_KERNEL"), os.Getenv("S1_INITRD")
	if workDir == "" || dataVol == "" {
		fmt.Println("VZBOOT_SB_HARNESS_FAULT=S1_SB_WORKDIR/S1_SB_DATAVOL unset")
		os.Exit(3)
	}
	profile := podSBPL(workDir, dataVol)
	fmt.Printf("VZBOOT_SB_ORDER=%s\n", order)
	fmt.Printf("VZBOOT_SB_PROFILE_SHA_LEN=%d\n", len(profile))

	// A "works" verdict is theatre unless the profile is proven IN FORCE — the
	// same trap criterion 1's counterfactual exists to avoid. Two controls run
	// immediately after sandbox_apply: a NEGATIVE (a path the profile denies
	// must now be unreadable) and a POSITIVE (the pod's own data volume must
	// still be readable, so a "denied" negative cannot come from a profile that
	// simply broke everything).
	confined := func() bool {
		ok := true
		denied := filepath.Join(workDir, "bin", "vzboot")
		if _, err := os.ReadFile(denied); err != nil {
			fmt.Printf("VZBOOT_SB_CONTROL_NEG=denied err=%v\n", err)
		} else {
			fmt.Println("VZBOOT_SB_CONTROL_NEG=NOT-CONFINED — a denied path read succeeded")
			ok = false
		}
		if _, err := os.ReadFile(filepath.Join(dataVol, "Image")); err != nil {
			fmt.Printf("VZBOOT_SB_CONTROL_POS=unreadable err=%v\n", err)
			ok = false
		} else {
			fmt.Println("VZBOOT_SB_CONTROL_POS=readable")
		}
		return ok
	}
	sandboxProven := false
	apply := func() bool {
		if err := confine(profile); err != nil {
			fmt.Printf("VZBOOT_SB_APPLY=fail err=%v\n", err)
			return false
		}
		fmt.Println("VZBOOT_SB_APPLY=ok")
		sandboxProven = confined()
		return true
	}
	verdict := func(v string) { fmt.Printf("VZBOOT_SB_VERDICT_%s=%s\n", strings.ToUpper(order), v) }

	if order == "before" {
		if !apply() {
			// An unconfined process proves nothing about coexistence.
			verdict("inconclusive: sandbox_apply itself failed")
			return
		}
	}
	vm, stage, err := buildVM(kernel, initrd, "sb-"+order, false)
	if err != nil {
		fmt.Printf("VZBOOT_SB_BUILD=fail stage=%s err=%v\n", stage, err)
		verdict("failed stage=" + stage + " err=" + err.Error())
		return
	}
	fmt.Println("VZBOOT_SB_BUILD=ok")
	runtime.LockOSThread()
	if err := vm.Start(); err != nil {
		fmt.Printf("VZBOOT_SB_START=fail err=%v\n", err)
		verdict("failed stage=start err=" + err.Error())
		return
	}
	fmt.Println("VZBOOT_SB_START=ok")
	if order == "after" {
		if !apply() {
			verdict("failed stage=apply-after-start")
			// The VM is live and must not be left running.
			_ = vm.Stop()
			return
		}
	}
	if waitStopped(vm, 25*time.Second) {
		fmt.Println("VZBOOT_SB_GUEST_REACHED_STOPPED=yes")
		if !sandboxProven {
			verdict("inconclusive: the VM ran but the profile was not proven in force")
			return
		}
		verdict("worked")
		return
	}
	fmt.Println("VZBOOT_SB_GUEST_REACHED_STOPPED=no")
	_ = vm.Stop()
	verdict("failed stage=guest-run err=guest did not power down within 25s")
}

func main() {
	mode := "boot"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "rosetta":
		// Criterion 6: this probe SHIPS in the product binary and is called
		// eagerly once per daemon lifetime. If it raises when unentitled, the
		// daemon crashes at startup on exactly the machines M11 targets.
		avail := vz.LinuxRosettaDirectoryShareAvailability()
		fmt.Printf("VZBOOT_ROSETTA_AVAILABILITY=%v\n", avail)
		fmt.Println("VZBOOT_ROSETTA_PROBE_DID_NOT_RAISE")
		return
	case "seatbelt":
		order := "before"
		if len(os.Args) > 2 {
			order = os.Args[2]
		}
		runSeatbelt(order)
		return
	}

	kernel := os.Getenv("S1_KERNEL")
	initrd := os.Getenv("S1_INITRD")
	token := os.Getenv("S1_TOKEN")

	t0 := time.Now()
	vm, stage, err := buildVM(kernel, initrd, token, mode == "pair")
	if err != nil {
		die(stage, err)
	}
	// Pinned deliberately: VZ drives its own queue, but the process needs a live
	// thread for the delegate callbacks. Conservative until measured otherwise.
	runtime.LockOSThread()
	if err := vm.Start(); err != nil {
		die("start", err)
	}
	fmt.Printf("VZBOOT_CREATE_TO_START_NS=%d\n", time.Since(t0).Nanoseconds())
	deadline := time.After(30 * time.Second)
	select {
	case <-deadline:
		fmt.Println("VZBOOT_TIMEOUT")
		os.Exit(2)
	case <-time.After(8 * time.Second):
		fmt.Printf("VZBOOT_ELAPSED_NS=%d token=%s\n", time.Since(t0).Nanoseconds(), token)
	}
}
GOEOF
go build -o "$PREFIX/bin/vzboot" . || { echo "S1 SETUP FAIL: vzboot build"; exit 1; }
echo "vzboot built"
LABEOF

note "S1 criterion 1 — entitlement-only ad-hoc signing, WITH the counterfactual"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
cat > ent.plist <<'PLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.virtualization</key><true/>
</dict></plist>
PLEOF

run_one() { # $1 label -> prints VERDICT
  set +e
  S1_KERNEL="$PWD/guest/Image" S1_INITRD="$PWD/guest/initramfs.cpio" S1_TOKEN="$1" \
    run_timeout 40 ./bin/vzboot boot >"out/$1.log" 2>&1
  echo "  $1 exit=$?"
  set -e
}

echo "-- 1a UNSIGNED (must FAIL to construct a VM)"
cp bin/vzboot bin/vzboot.unsigned; codesign --remove-signature bin/vzboot.unsigned 2>/dev/null || true
set +e; S1_KERNEL="$PWD/guest/Image" S1_INITRD="$PWD/guest/initramfs.cpio" run_timeout 40 ./bin/vzboot.unsigned boot >out/unsigned.log 2>&1; echo "  unsigned exit=$?"; set -e

echo "-- 1b AD-HOC WITHOUT ENTITLEMENT (must FAIL)"
cp bin/vzboot bin/vzboot.noent; codesign -s - -f bin/vzboot.noent >/dev/null 2>&1
set +e; S1_KERNEL="$PWD/guest/Image" S1_INITRD="$PWD/guest/initramfs.cpio" run_timeout 40 ./bin/vzboot.noent boot >out/noent.log 2>&1; echo "  noent exit=$?"; set -e

echo "-- 1c AD-HOC WITH ENTITLEMENT (must SUCCEED)"
codesign -s - -f --entitlements ent.plist bin/vzboot >/dev/null 2>&1
codesign -d --entitlements - bin/vzboot 2>&1 | sed 's/^/     /'
codesign --verify --strict bin/vzboot && echo "     codesign --verify: OK"
LABEOF

note "S1 criterion 2 — console tokens, and the gzip control"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
TOKEN="s1-$(date +%s)"
set +e
S1_KERNEL="$PWD/guest/Image" S1_INITRD="$PWD/guest/initramfs.cpio" S1_TOKEN="$TOKEN" \
  run_timeout 60 ./bin/vzboot boot >out/boot.log 2>&1
echo "  boot exit=$?"
set -e
echo "-- console transcript (head):"; head -25 out/boot.log | sed 's/^/     /'
grep -q "K3SM_S1_TOKEN=$TOKEN" out/boot.log \
  && echo "  CRITERION 2a: PASS — token observed on the console" \
  || echo "  CRITERION 2a: FAIL — no token (this is a GO/NO-GO criterion)"

echo "-- 2b control: a GZIPPED Image must be REJECTED by VZLinuxBootLoader"
set +e
S1_KERNEL="$PWD/guest/Image.gz" S1_INITRD="$PWD/guest/initramfs.cpio" S1_TOKEN=gz \
  run_timeout 40 ./bin/vzboot boot >out/boot-gz.log 2>&1
echo "  gz exit=$?"
set -e
head -5 out/boot-gz.log | sed 's/^/     /'
LABEOF

note "S1 criterion 3 — cold-boot latency, N=20, TWO figures"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
: > out/latency.tsv
for i in $(seq 1 20); do
  set +e
  S1_KERNEL="$PWD/guest/Image" S1_INITRD="$PWD/guest/initramfs.cpio" S1_TOKEN="lat$i" \
    run_timeout 60 ./bin/vzboot boot >"out/lat$i.log" 2>&1
  set -e
  cs=$(grep -o 'VZBOOT_CREATE_TO_START_NS=[0-9]*' "out/lat$i.log" | cut -d= -f2)
  up=$(grep -o 'K3SM_S1_UPTIME=[0-9.]*'          "out/lat$i.log" | cut -d= -f2)
  printf '%s\t%s\t%s\n' "$i" "${cs:-NA}" "${up:-NA}" >> out/latency.tsv
done
echo "-- run  create->start(ns)  guest uptime at init exec(s)"
cat out/latency.tsv | sed 's/^/     /'
echo "  (figure A = kernel-start -> init-exec, from guest uptime;"
echo "   figure B = CreateVM -> console token, the user-visible restart cost)"
LABEOF

note "S1 criterion 6 — the Rosetta availability probe must be safe when UNENTITLED"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
set +e
run_timeout 30 ./bin/vzboot.noent rosetta >out/rosetta-noent.log 2>&1
echo "  unentitled rosetta probe exit=$?"
set -e
cat out/rosetta-noent.log | sed 's/^/     /'
grep -q VZBOOT_ROSETTA_PROBE_DID_NOT_RAISE out/rosetta-noent.log \
  && echo "  CRITERION 6: PASS — the shipped probe is safe unentitled" \
  || echo "  CRITERION 6: FAIL — HALT the shipped label path; this is a bug in merged code"
LABEOF

note "S1 criterion 5 — Seatbelt × VZ coexistence, BOTH orderings"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"

# The confined process is held to the product's own pod profile, whose
# protected denies cover /Users outright and re-allow ONLY the pod's data
# volume. So the kernel and initramfs must live where a real vm pod's
# artifacts would: inside that data volume. Staging them anywhere else would
# make criterion 5 report a file-read denial that the product would never hit.
SBDATA="$PREFIX/pods/s1seatbelt/data"
mkdir -p "$SBDATA"
cp guest/Image guest/initramfs.cpio "$SBDATA/"

run_order() { # $1 = before|after
  set +e
  S1_KERNEL="$SBDATA/Image" S1_INITRD="$SBDATA/initramfs.cpio" \
  S1_SB_WORKDIR="$PREFIX" S1_SB_DATAVOL="$SBDATA" \
    run_timeout 60 ./bin/vzboot seatbelt "$1" >"out/seatbelt-$1.log" 2>&1
  echo "  seatbelt-$1 exit=$?"
  set -e
  sed 's/^/     /' "out/seatbelt-$1.log"
}

echo "-- 5a sandbox_apply FIRST, then construct+start a VM"
run_order before
echo "-- 5b construct+start a VM FIRST, then sandbox_apply"
run_order after

# The denial text is the finding when an ordering fails, so capture it rather
# than paraphrasing it. Non-root `log show` sees the last few minutes; an empty
# capture is itself recorded (it means no Seatbelt denial was logged).
echo "-- Seatbelt denial log (verbatim; empty = none logged)"
log show --last 4m --style syslog --predicate 'eventMessage CONTAINS "vzboot"' 2>/dev/null \
  | grep -iE 'sandbox|deny' | head -40 | sed 's/^/     /' || true

for o in before after; do
  if grep -q "VZBOOT_SB_VERDICT_$(echo "$o" | tr a-z A-Z)=worked" "out/seatbelt-$o.log"; then
    echo "  CRITERION 5 ($o): WORKS — a VM constructs and starts under the pod profile"
  else
    echo "  CRITERION 5 ($o): DOES NOT WORK — record the verbatim line above; NOT terminal (the M11 plan's R22)"
  fi
done

# Leave nothing running: both orderings power their guest down, but a timeout
# kill can strand one.
pkill -f "$PREFIX/bin/vzboot" 2>/dev/null || true
LABEOF

note "S1 done — criterion 4 (guest<->guest) is the remaining leg"
cat <<'EOF'

  Criterion 4 needs TWO guests with a network userland, which this harness's
  stub init does not have. Its named vehicle is s5-run.sh, whose Alpine guest
  boots two VMs on one NAT segment and prints the matrix; the result is
  mirrored back into findings-s1.md criterion 4 VERBATIM.

  RECORD THE OUTCOME in k3sm/hack/spike/m11/findings-s1.md:
    - the rig table, and the kernel sha256 + byte size this run used;
    - criterion 1 with ALL THREE verdicts (unsigned / ad-hoc-no-entitlement /
      ad-hoc-entitled) — the counterfactual is the evidence, not the success;
    - the console transcript excerpt and the gzip rejection;
    - the latency table with min/median/p95/max for BOTH figures;
    - the guest<->guest matrix, VERBATIM, as a security fact;
    - the Seatbelt x VZ outcome for BOTH orderings: works / fails-with-denial /
      works-with-a-named minimal allow-set (report a delta as an ADOPTED
      ALLOW-SET block, never a silent widening);
    - the Rosetta probe value observed on this rig;
    - any deviation from the guardrails in lib.sh, flagged rather than adopted.

  GO/NO-GO: criteria 1 or 2 failing is TERMINAL for M11 -> the M11 plan's R19(b).
  Criterion 5 failing is NOT terminal (R22 admits a documented residual).
  Criterion 6 failing HALTS the shipped label path — it is a bug in merged code.
EOF
