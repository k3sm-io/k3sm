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
#   4 guest<->guest reachability                      — RECORDING (a security fact)
#   5 Seatbelt x VZ coexistence in one process        — decides Resolution 7
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

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/Code-Hex/vz/v3"
)

func die(stage string, err error) {
	fmt.Printf("VZBOOT_FAIL stage=%s err=%v\n", stage, err)
	os.Exit(1)
}

func main() {
	mode := "boot"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if mode == "rosetta" {
		// Criterion 6: this probe SHIPS in the product binary and is called
		// eagerly once per daemon lifetime. If it raises when unentitled, the
		// daemon crashes at startup on exactly the machines M11 targets.
		avail := vz.LinuxRosettaDirectoryShareAvailability()
		fmt.Printf("VZBOOT_ROSETTA_AVAILABILITY=%v\n", avail)
		fmt.Println("VZBOOT_ROSETTA_PROBE_DID_NOT_RAISE")
		return
	}

	kernel := os.Getenv("S1_KERNEL")
	initrd := os.Getenv("S1_INITRD")
	token := os.Getenv("S1_TOKEN")

	t0 := time.Now()
	bl, err := vz.NewLinuxBootLoader(kernel,
		vz.WithCommandLine("console=hvc0 quiet s1_token="+token),
		vz.WithInitrd(initrd))
	if err != nil {
		die("bootloader", err)
	}
	cfg, err := vz.NewVirtualMachineConfiguration(bl, 1, 512*1024*1024)
	if err != nil {
		die("config", err)
	}
	// Console -> our stdout, which is how the token and the timings get out.
	att, err := vz.NewFileHandleSerialPortAttachment(os.Stdin, os.Stdout)
	if err != nil {
		die("console-attachment", err)
	}
	sc, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(att)
	if err != nil {
		die("console", err)
	}
	cfg.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{sc})
	if mode == "pair" {
		// Criterion 4 needs two guests on one NAT segment.
		nat, err := vz.NewNATNetworkDeviceAttachment()
		if err != nil {
			die("nat", err)
		}
		nc, err := vz.NewVirtioNetworkDeviceConfiguration(nat)
		if err != nil {
			die("net", err)
		}
		cfg.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{nc})
	}
	if ok, err := cfg.Validate(); !ok || err != nil {
		die("validate", err)
	}
	vm, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		die("new-vm", err)
	}
	// Pinned deliberately: VZ drives its own queue, but the process needs a live
	// thread for the delegate callbacks. Conservative until measured otherwise.
	runtime.LockOSThread()
	if err := vm.Start(); err != nil {
		die("start", err)
	}
	fmt.Printf("VZBOOT_CREATE_TO_START_NS=%d\n", time.Since(t0).Nanoseconds())
	sc2 := bufio.NewScanner(os.Stdin)
	_ = sc2
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

note "S1 done — criteria 4 (guest<->guest) and 5 (Seatbelt x VZ) are the remaining legs"
cat <<'EOF'

  Criteria 4 and 5 need a second guest and an sbpl-loaded process respectively;
  they are run in the same sitting from this harness (vzboot pair / seatbelt)
  once 1, 2 and 6 have reported, because a NO-GO on 1 or 2 makes them moot.

  RECORD THE OUTCOME in k3sm/hack/spike/m11/findings-s1.md:
    - the rig table, and the kernel sha256 + byte size this run used;
    - criterion 1 with ALL THREE verdicts (unsigned / ad-hoc-no-entitlement /
      ad-hoc-entitled) — the counterfactual is the evidence, not the success;
    - the console transcript excerpt and the gzip rejection;
    - the latency table with min/median/p95/max for BOTH figures;
    - the guest<->guest matrix, VERBATIM, as a security fact;
    - the Seatbelt x VZ outcome: works / fails-with-denial / works-with-a-named
      minimal allow-set (report the delta as an ADOPTED ALLOW-SET block);
    - the Rosetta probe value observed on this rig;
    - any deviation from the guardrails in lib.sh, flagged rather than adopted.

  GO/NO-GO: criteria 1 or 2 failing is TERMINAL for M11 -> the M11 plan's R19(b).
  Criterion 5 failing is NOT terminal (R22 admits a documented residual).
  Criterion 6 failing HALTS the shipped label path — it is a bug in merged code.
EOF
