#!/usr/bin/env bash
# M11.0-d5 / S5 — the AUTOMATABLE half of guest networking.
#
# s5.sh is the RUNBOOK: it states every criterion and, for each, the branch
# consequence the observed answer selects. THIS script RUNS the subset that
# needs no root, on a network-capable guest, and prints every answer as a
# greppable S5_<criterion>_<key>=<value> console line, so findings-s5.md is
# transcribed from observation rather than written from memory.
#
# What runs here (no sudo, no root, no /etc, no sysctl, no lo0 aliasing):
#   1a  guest -> host listeners (wildcard / gateway-bound / loopback-bound), TCP+UDP
#   1b  guest-side `ip route add` for a service-CIDR-shaped prefix: do packets LEAVE?
#   2   host -> guest dial at the guest's vmnet address
#   4   guest <-> guest matrix, TWO guests on one NAT segment (a SECURITY fact)
#   5   DHCP lease stability across restart under a deterministic MAC, N=3
#   6   THE SOURCE ADDRESS THE HOST OBSERVES  <-- the deciding fact for B113
#   7   guest link MTU
#
# What does NOT run here, and why — recorded, never faked:
#   The real criterion-1 (a)-(d) table needs a ClusterIP VIP aliased on host
#   lo0, and the unprivileged alias attempt already failed (SIOCAIFADDR:
#   permission denied). So the VIP legs are a root-needing HUMAN slice. This
#   script answers the strictly weaker question it CAN answer honestly —
#   whether guest packets addressed to a service-CIDR prefix leave the guest at
#   all — and says exactly that in the findings. It never claims a VIP was
#   reached, and it never attempts to work around the missing privilege.
#
# Guest: the stock Alpine arm64 minirootfs, PINNED by URL and sha256 below,
# unpacked host-side and shipped AS the initramfs with a small GOOS=linux init
# at /init. A read-only virtiofs share is also attached and mount-attempted,
# because whether this kernel can mount one is itself a finding that feeds the
# pinned-kernel config work; no probe depends on it.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

# The pinned guest rootfs. The sha256 is recorded and VERIFIED on every run: a
# moved-on "latest" tarball would silently change the busybox and musl every
# measurement here was taken under.
ALPINE_URL="${K3SM_SPIKE_ALPINE_URL:-https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz}"
ALPINE_SHA256="${K3SM_SPIKE_ALPINE_SHA256:-f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259}"

# lab5 — lib.sh's lab() plus the two S5 pins. Kept here rather than widened into
# lib.sh so s1.sh's environment is untouched.
lab5() {
  {
    printf '%s\n' "$LAB_PREAMBLE"
    printf 'ALPINE_URL=%s\nALPINE_SHA256=%s\n' "$ALPINE_URL" "$ALPINE_SHA256"
    printf '%s\n' "$S5_HELPERS"
    cat
  } | ssh "$HOST" "PREFIX=$PREFIX bash -s"
}

# Lab-side helpers the phases share. Two VMs run CONCURRENTLY in phase 3, so
# every spawn returns its pid in named variables the caller copies — macOS
# /bin/bash is 3.2, with no namerefs and no associative arrays.
read -r -d '' S5_HELPERS <<'HELPEOF' || true
# spawn TIMEOUT LOG CMD... -> sets SPAWN_PID and SPAWN_WATCH
spawn() {
  local secs="$1" log="$2"; shift 2
  "$@" > "$log" 2>&1 &
  SPAWN_PID=$!
  ( sleep "$secs"; kill -TERM "$SPAWN_PID" 2>/dev/null; sleep 3; kill -KILL "$SPAWN_PID" 2>/dev/null ) 2>/dev/null &
  SPAWN_WATCH=$!
}
# reap PID WATCHPID — wait for the child, then retire its watchdog.
reap() {
  local rc=0
  wait "$1" 2>/dev/null || rc=$?
  kill -TERM "$2" 2>/dev/null || true
  return "$rc"
}
# wait_line LOG PATTERN SECONDS — poll a log a background VM is writing.
wait_line() {
  local i=0
  while [ "$i" -lt "$3" ]; do
    if grep -q "$2" "$1" 2>/dev/null; then grep -m1 "$2" "$1"; return 0; fi
    sleep 1; i=$((i + 1))
  done
  return 1
}
# field LOG KEY — the value of the first KEY=... console line.
field() { grep -m1 "$2=" "$1" 2>/dev/null | sed "s/.*$2=//" | tr -d '\r'; }
HELPEOF

note "S5 — preflight: S1 must have reported GO"
if ! grep -qiE '^\*\*Verdict:\*\* *_?\(?GO' "$HERE/findings-s1.md" 2>/dev/null; then
  cat <<'EOF'
  findings-s1.md does not record a GO.

  S5 extends S1's harness and is meaningless if the boot path is invalid. Run
  s1.sh, record its verdict, and re-run this. If S1 recorded NO-GO on criterion
  1 or 2, M11 halts under the M11 plan's R19(b) and S5 is moot.
EOF
  exit 1
fi

note "S5 — staging the network-capable guest and the host probes"

lab5 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
mkdir -p out s5/tools
spike_preflight

# --------------------------------------------------------- the pinned rootfs
# Verified on EVERY run, not only the first: a cached tarball that no longer
# matches the pin is a different guest, and every figure taken under it would
# be attributed to the pinned one.
cd s5
if [ ! -f alpine.tar.gz ]; then
  curl -fsSL -o alpine.tar.gz "$ALPINE_URL" || { echo "S5 SETUP FAIL: rootfs fetch"; exit 1; }
fi
GOT=$(shasum -a 256 alpine.tar.gz | awk '{print $1}')
echo "S5_ROOTFS_URL=$ALPINE_URL"
echo "S5_ROOTFS_SHA256=$GOT"
if [ "$GOT" != "$ALPINE_SHA256" ]; then
  echo "S5 SETUP FAIL: rootfs sha256 mismatch (pinned $ALPINE_SHA256)"
  exit 1
fi
echo "S5_ROOTFS_SHA256_VERIFIED=yes"

rm -rf rootfs && mkdir -p rootfs
tar xzf alpine.tar.gz -C rootfs
echo "S5_ROOTFS_FILES=$(find rootfs | wc -l | tr -d ' ')"

# ------------------------------------------------------------ the host probe
# HOST-AUTHORED and placed at /probe.sh in the initramfs. Also copied into the
# virtiofs share, where it doubles as the mount witness.
mkdir -p share
cat > probe.sh <<'PROBEEOF'
#!/bin/sh
# S5 in-guest probe — host-authored. Every line it prints is a finding.
[ -f /s5env ] && . /s5env
log() { echo "$@"; }

ip link set lo up 2>/dev/null
ip link set eth0 up 2>/dev/null
udhcpc -i eth0 -q -n -t 8 -T 2 -s /usr/share/udhcpc/default.script >/dev/null 2>&1
ADDR=$(ip -4 addr show eth0 | awk '/inet /{split($2,a,"/"); print a[1]}')
GW=$(ip route 2>/dev/null | awk '/^default/{print $3}')

log "S5_ROLE=$S5_ROLE"
log "S5_C5_ADDR=$ADDR"
log "S5_GW=$GW"
log "S5_MAC=$(cat /sys/class/net/eth0/address 2>/dev/null)"
log "S5_C7_MTU=$(cat /sys/class/net/eth0/mtu 2>/dev/null)"
log "S5_C7_IPLINK=$(ip link show eth0 2>/dev/null | tr '\n' '|')"
log "S5_C7_IPADDR=$(ip -4 addr show eth0 2>/dev/null | tr '\n' '|')"
log "S5_ROUTES=$(ip route 2>/dev/null | tr '\n' '|')"

# ------------------------------------------------------------------ role: solo
# Criteria 6, 1a, 1b and 2. The host listeners are already up (the gateway-bound
# one binds with a retry, because bridge100 exists only while a VM runs), so a
# short settle keeps a race out of the answers.
if [ "$S5_ROLE" = "solo" ]; then
  sleep "${S5_SETTLE:-6}"

  try_tcp() { # $1 label  $2 port
    if echo "tcp-from-$ADDR" | nc -w 4 "$GW" "$2" >/dev/null 2>&1; then
      log "S5_C1A_$1_TCP=connected dst=$GW:$2"
    else
      log "S5_C1A_$1_TCP=refused-or-unreachable dst=$GW:$2"
    fi
  }
  send_udp() { # $1 label  $2 port — the HOST-side receipt is the authority for
               # UDP; the guest can only report that the send did not error.
    ERR=$(echo "udp-from-$ADDR" | nc -u -w 2 "$GW" "$2" 2>&1 >/dev/null) || true
    log "S5_C1A_$1_UDP=sent dst=$GW:$2 err=$(echo "$ERR" | tr '\n' ' ')"
  }

  try_tcp WILDCARD "$S5_PW_T"; send_udp WILDCARD "$S5_PW_U"
  try_tcp GWBOUND  "$S5_PG_T"; send_udp GWBOUND  "$S5_PG_U"
  try_tcp LOBOUND  "$S5_PL_T"; send_udp LOBOUND  "$S5_PL_U"

  # (1b) a service-CIDR-shaped prefix routed at the NAT gateway. No VIP is
  # aliased on the host (that needs root), so the question answered here is
  # narrow and stated as such: does the guest ACCEPT the route, and do packets
  # for that prefix LEAVE the interface?
  TX0=$(cat /sys/class/net/eth0/statistics/tx_packets)
  if ip route add "$S5_CIDR" via "$GW" dev eth0 2>/tmp/rerr; then
    log "S5_C1B_ROUTEADD=ok cidr=$S5_CIDR via=$GW"
  else
    log "S5_C1B_ROUTEADD=fail err=$(tr '\n' ' ' </tmp/rerr)"
  fi
  log "S5_C1B_ROUTES=$(ip route | tr '\n' '|')"
  T0=$(date +%s)
  if echo "vip-from-$ADDR" | nc -w 6 "$S5_VIP" "$S5_VIPPORT" >/dev/null 2>&1; then
    RES=connected
  else
    RES=no-answer
  fi
  T1=$(date +%s)
  TX1=$(cat /sys/class/net/eth0/statistics/tx_packets)
  log "S5_C1B_VIP_TCP=$RES dst=$S5_VIP:$S5_VIPPORT elapsed_s=$((T1 - T0)) tx_packets_delta=$((TX1 - TX0))"
  log "S5_C1B_NEIGH=$(ip neigh show | tr '\n' '|')"

  # (2) the host dials back at the guest's own vmnet address.
  log "S5_C2_LISTENING=port=$S5_SRV addr=$ADDR"
  timeout "${S5_LISTEN_S:-30}" nc -l -p "$S5_SRV" >/tmp/rx 2>/dev/null || true
  log "S5_C2_GUEST_RX=$(tr -d '\r\n' </tmp/rx)"
fi

# ------------------------------------------------------------------ role: peer
if [ "$S5_ROLE" = "peer" ]; then
  # LIVENESS CONTROLS. "guest A cannot reach guest B" is only a security fact if
  # B's stack was actually up at B's advertised address. B therefore proves
  # itself to the GATEWAY (ICMP) and to a HOST listener (TCP) first — the host's
  # own accept log then carries B's source address, independently of anything B
  # printed about itself.
  if ping -c 2 -W 2 "$GW" >/dev/null 2>&1; then
    log "S5_C4_PEER_CTL_GW_ICMP=reachable"
  else
    log "S5_C4_PEER_CTL_GW_ICMP=unreachable"
  fi
  if [ -n "${S5_CTLPORT:-}" ]; then
    if echo "peer-alive-$ADDR" | nc -w 4 "$GW" "$S5_CTLPORT" >/dev/null 2>&1; then
      log "S5_C4_PEER_CTL_HOST_TCP=connected"
    else
      log "S5_C4_PEER_CTL_HOST_TCP=refused-or-unreachable"
    fi
  fi
  log "S5_C4_PEER_LISTENING=port=$S5_SRV addr=$ADDR"
  timeout "${S5_LISTEN_S:-45}" nc -l -p "$S5_SRV" >/tmp/rx 2>/dev/null || true
  log "S5_C4_PEER_RX=$(tr -d '\r\n' </tmp/rx)"
  sleep 3
fi

# ---------------------------------------------------------------- role: prober
if [ "$S5_ROLE" = "prober" ]; then
  sleep "${S5_SETTLE:-4}"
  # POSITIVE CONTROLS, run FIRST. Without them, "no ICMP reply from the peer"
  # is indistinguishable from "busybox ping does not work here", and "TCP
  # refused" from "this guest has no working stack".
  if ping -c 2 -W 2 "$GW" >/dev/null 2>&1; then
    log "S5_C4_CTL_GW_ICMP=reachable"
  else
    log "S5_C4_CTL_GW_ICMP=unreachable"
  fi
  if [ -n "${S5_CTLPORT:-}" ]; then
    if echo "prober-alive-$ADDR" | nc -w 4 "$GW" "$S5_CTLPORT" >/dev/null 2>&1; then
      log "S5_C4_CTL_HOST_TCP=connected"
    else
      log "S5_C4_CTL_HOST_TCP=refused-or-unreachable"
    fi
  fi
  PING=$(ping -c 3 -W 2 "$S5_PEER" 2>&1 | tr '\n' '|')
  log "S5_C4_ICMP_RAW=$PING"
  case "$PING" in
    *" 0% packet loss"*) log "S5_C4_ICMP=reachable" ;;
    *)                   log "S5_C4_ICMP=unreachable" ;;
  esac
  if echo "prober-$ADDR" | nc -w 5 "$S5_PEER" "$S5_PEERPORT" >/dev/null 2>&1; then
    log "S5_C4_TCP=connected dst=$S5_PEER:$S5_PEERPORT"
  else
    log "S5_C4_TCP=refused-or-unreachable dst=$S5_PEER:$S5_PEERPORT"
  fi
  log "S5_C4_NEIGH=$(ip neigh show | tr '\n' '|')"
  # The ARP verdict turns on lladdr, NOT on the peer merely APPEARING in the
  # table: a FAILED entry is a record that resolution was ATTEMPTED and did not
  # answer, which is the opposite of adjacency.
  if ip neigh show | grep "^$S5_PEER " | grep -q lladdr; then
    log "S5_C4_ADJACENCY=L2-adjacent (peer ARP-resolved to an lladdr)"
  elif ip neigh show | grep -q "^$S5_PEER "; then
    log "S5_C4_ADJACENCY=NOT-adjacent (ARP attempted, no lladdr: $(ip neigh show | grep "^$S5_PEER " | tr '\n' '|'))"
  else
    log "S5_C4_ADJACENCY=NOT-adjacent (no ARP entry for the peer at all)"
  fi
fi

log "S5_PROBE_COMPLETE=$S5_ROLE"
PROBEEOF
cp probe.sh rootfs/probe.sh && chmod +x rootfs/probe.sh
cp probe.sh share/probe.sh
echo "s5-share-marker" > share/MARKER

# -------------------------------------------------------------- the guest init
cat > init.go <<'GOEOF'
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// mountAt mounts one pseudo-filesystem and reports the outcome on the console.
// Nothing has run before PID 1 in an initramfs, so /proc, /sys and /dev are all
// absent; busybox, udhcpc and every /sys counter the probe reads depend on them.
func mountAt(src, target, fstype string) {
	_ = os.MkdirAll(target, 0o755)
	if err := syscall.Mount(src, target, fstype, 0, ""); err != nil {
		fmt.Printf("S5_MOUNT_%s=fail err=%v\n", strings.ToUpper(fstype), err)
		return
	}
	fmt.Printf("S5_MOUNT_%s=ok\n", strings.ToUpper(fstype))
}

// writeEnv turns the s5_* kernel-command-line keys into /s5env, which the
// host-authored probe sources. The kernel command line is the only channel the
// bootloader gives us: PID 1 in a guest inherits nothing from the host's env.
func writeEnv() {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		fmt.Printf("S5_CMDLINE=unreadable err=%v\n", err)
		return
	}
	var sb strings.Builder
	for _, f := range strings.Fields(string(b)) {
		if !strings.HasPrefix(f, "s5_") {
			continue
		}
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		fmt.Fprintf(&sb, "%s='%s'\n", strings.ToUpper(k), v)
	}
	if err := os.WriteFile("/s5env", []byte(sb.String()), 0o644); err != nil {
		fmt.Printf("S5_ENV=fail err=%v\n", err)
		return
	}
	fmt.Printf("S5_ENV=ok keys=%d\n", strings.Count(sb.String(), "\n"))
}

func main() {
	mountAt("proc", "/proc", "proc")
	mountAt("sysfs", "/sys", "sysfs")
	mountAt("devtmpfs", "/dev", "devtmpfs")
	writeEnv()

	// The virtiofs share is attached by the host harness. Whether THIS kernel
	// can mount it is a recorded finding in its own right (it feeds the pinned
	// kernel's config): a driver built as a module cannot load, because an
	// initramfs holds no modules and nothing here runs modprobe.
	tag := os.Getenv("S5_SHARE_TAG")
	if tag == "" {
		tag = "s5share"
	}
	_ = os.MkdirAll("/mnt/share", 0o755)
	if err := syscall.Mount(tag, "/mnt/share", "virtiofs", 0, ""); err != nil {
		fmt.Printf("S5_VIRTIOFS=unavailable err=%v\n", err)
	} else {
		fmt.Println("S5_VIRTIOFS=mounted")
		if b, err := os.ReadFile("/mnt/share/MARKER"); err == nil {
			fmt.Printf("S5_VIRTIOFS_MARKER=%s\n", strings.TrimSpace(string(b)))
		}
	}

	cmd := exec.Command("/bin/sh", "/probe.sh")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	if err := cmd.Run(); err != nil {
		fmt.Printf("S5_PROBE_ERR=%v\n", err)
	}
	fmt.Println("S5_INIT_DONE")
	_ = os.Stdout.Sync()
	time.Sleep(400 * time.Millisecond)
	// LINUX_REBOOT_CMD_POWER_OFF — the host harness waits for this transition.
	_ = syscall.Reboot(0x4321fedc)
	select {}
}
GOEOF
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags='-s -w' -o rootfs/init ./init.go \
  || { echo "S5 SETUP FAIL: guest init cross-build"; exit 1; }
( cd rootfs && find . | cpio -o -H newc 2>/dev/null > ../initramfs.cpio ) \
  || { echo "S5 SETUP FAIL: cpio"; exit 1; }
echo "S5_INITRAMFS_BYTES=$(stat -f%z initramfs.cpio)"
LABEOF

note "S5 — building the vznet guest harness and the s5host probes"

lab5 <<'LABEOF'
set -euo pipefail
cd "$PREFIX/s5"
mkdir -p vznet s5host

# ---------------------------------------------------------------------- vznet
cat > vznet/main.go <<'GOEOF'
// vznet — the S5 guest harness: one Linux guest on the vmnet NAT segment, with
// a DETERMINISTIC MAC (criterion 5 measures lease stability, which is only
// meaningful if the MAC is stable), a read-only virtiofs share, and a console
// that is the data channel back to the host.
package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Code-Hex/vz/v3"
)

func die(stage string, err error) {
	fmt.Printf("VZNET_FAIL stage=%s err=%v\n", stage, err)
	os.Exit(1)
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	kernel, initrd := os.Getenv("S5_KERNEL"), os.Getenv("S5_INITRD")
	mac := os.Getenv("S5_MAC")
	tag := envDefault("S5_SHARE_TAG", "s5share")
	extra := os.Getenv("S5_CMDLINE")
	waitSecs, _ := strconv.Atoi(envDefault("S5_WAIT", "60"))

	cmdline := "console=hvc0 quiet s5_share_tag=" + tag
	if extra != "" {
		cmdline += " " + extra
	}
	bl, err := vz.NewLinuxBootLoader(kernel, vz.WithCommandLine(cmdline), vz.WithInitrd(initrd))
	if err != nil {
		die("bootloader", err)
	}
	cfg, err := vz.NewVirtualMachineConfiguration(bl, 2, 1024*1024*1024)
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

	nat, err := vz.NewNATNetworkDeviceAttachment()
	if err != nil {
		die("nat", err)
	}
	nc, err := vz.NewVirtioNetworkDeviceConfiguration(nat)
	if err != nil {
		die("net", err)
	}
	if mac != "" {
		hw, err := net.ParseMAC(mac)
		if err != nil {
			die("mac-parse", err)
		}
		m, err := vz.NewMACAddress(hw)
		if err != nil {
			die("mac", err)
		}
		nc.SetMACAddress(m)
		fmt.Printf("VZNET_MAC=%s\n", mac)
	}
	cfg.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{nc})

	// Read-only by construction: the share exists to answer whether this kernel
	// can mount virtiofs at all, and a writable share would widen the guest's
	// reach into the host tree for no gain.
	if dir := os.Getenv("S5_SHARE_DIR"); dir != "" {
		fs, err := vz.NewVirtioFileSystemDeviceConfiguration(tag)
		if err != nil {
			die("virtiofs-device", err)
		}
		sd, err := vz.NewSharedDirectory(dir, true)
		if err != nil {
			die("shared-directory", err)
		}
		share, err := vz.NewSingleDirectoryShare(sd)
		if err != nil {
			die("single-share", err)
		}
		fs.SetDirectoryShare(share)
		cfg.SetDirectorySharingDevicesVirtualMachineConfiguration([]vz.DirectorySharingDeviceConfiguration{fs})
		fmt.Printf("VZNET_SHARE=attached tag=%s\n", tag)
	} else {
		fmt.Println("VZNET_SHARE=none")
	}

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
	fmt.Printf("VZNET_CREATE_TO_START_NS=%d\n", time.Since(t0).Nanoseconds())

	deadline := time.After(time.Duration(waitSecs) * time.Second)
	for {
		select {
		case st := <-vm.StateChangedNotify():
			if st == vz.VirtualMachineStateStopped {
				fmt.Println("VZNET_STOPPED=yes")
				return
			}
		case <-deadline:
			fmt.Println("VZNET_STOPPED=no (deadline)")
			// Never leave a guest running behind the harness.
			_ = vm.Stop()
			time.Sleep(2 * time.Second)
			return
		}
	}
}
GOEOF

# --------------------------------------------------------------------- s5host
cat > s5host/main.go <<'GOEOF'
// s5host — the HOST side of the S5 probes: unprivileged listeners that record
// the SOURCE ADDRESS guest traffic arrives with (criterion 6, the deciding fact
// for per-pod NetworkPolicy attribution), and a dialer for the host->guest leg
// (criterion 2). High ports only; nothing here needs privilege.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func usage() {
	fmt.Println("usage: s5host listen LABEL BIND TCPPORT UDPPORT RUNSECS BINDRETRYSECS")
	fmt.Println("       s5host dial LABEL HOST:PORT PAYLOAD TIMEOUTSECS")
	os.Exit(2)
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		usage()
	}
	return n
}

// listenTCP retries the bind, because the vmnet gateway address exists on the
// host only while a VM is attached — a gateway-bound listener is necessarily
// started against an interface that has not appeared yet.
func listenTCP(label, bind, port string, retry time.Duration) net.Listener {
	deadline := time.Now().Add(retry)
	for {
		ln, err := net.Listen("tcp", net.JoinHostPort(bind, port))
		if err == nil {
			fmt.Printf("S5_HOST_%s_TCPBIND=ok addr=%s\n", label, ln.Addr())
			return ln
		}
		if time.Now().After(deadline) {
			fmt.Printf("S5_HOST_%s_TCPBIND=fail bind=%s:%s err=%v\n", label, bind, port, err)
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func listenUDP(label, bind, port string, retry time.Duration) net.PacketConn {
	deadline := time.Now().Add(retry)
	for {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(bind, port))
		if err == nil {
			fmt.Printf("S5_HOST_%s_UDPBIND=ok addr=%s\n", label, pc.LocalAddr())
			return pc
		}
		if time.Now().After(deadline) {
			fmt.Printf("S5_HOST_%s_UDPBIND=fail bind=%s:%s err=%v\n", label, bind, port, err)
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func serve(label, bind, tcpPort, udpPort string, runSecs, retrySecs int) {
	retry := time.Duration(retrySecs) * time.Second
	ln := listenTCP(label, bind, tcpPort, retry)
	pc := listenUDP(label, bind, udpPort, retry)
	if ln != nil {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// The peer address on an accepted connection IS criterion 6's
				// answer: whatever the guest's packets carry by the time XNU
				// hands them to an ordinary socket.
				buf := make([]byte, 256)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := c.Read(buf)
				fmt.Printf("S5_HOST_%s_TCP_FROM=%s payload=%s\n", label, c.RemoteAddr(), strings.TrimSpace(string(buf[:n])))
				_ = c.Close()
			}
		}()
	}
	if pc != nil {
		go func() {
			buf := make([]byte, 256)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				fmt.Printf("S5_HOST_%s_UDP_FROM=%s payload=%s\n", label, addr, strings.TrimSpace(string(buf[:n])))
			}
		}()
	}
	time.Sleep(time.Duration(runSecs) * time.Second)
	if ln != nil {
		_ = ln.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
	fmt.Printf("S5_HOST_%s_DONE=yes\n", label)
}

func dial(label, target, payload string, timeoutSecs int) {
	d := net.Dialer{Timeout: time.Duration(timeoutSecs) * time.Second}
	c, err := d.Dial("tcp", target)
	if err != nil {
		fmt.Printf("S5_HOST_DIAL_%s=fail target=%s err=%v\n", label, target, err)
		return
	}
	defer c.Close()
	fmt.Printf("S5_HOST_DIAL_%s=ok target=%s local=%s\n", label, target, c.LocalAddr())
	if _, err := c.Write([]byte(payload)); err != nil {
		fmt.Printf("S5_HOST_DIAL_%s_WRITE=fail err=%v\n", label, err)
		return
	}
	fmt.Printf("S5_HOST_DIAL_%s_WRITE=ok payload=%s\n", label, payload)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "listen":
		if len(os.Args) != 8 {
			usage()
		}
		serve(os.Args[2], os.Args[3], os.Args[4], os.Args[5], atoi(os.Args[6]), atoi(os.Args[7]))
	case "dial":
		if len(os.Args) != 6 {
			usage()
		}
		dial(os.Args[2], os.Args[3], os.Args[4], atoi(os.Args[5]))
	default:
		usage()
	}
}
GOEOF

(
  cd vznet
  [ -f go.mod ] || go mod init k3sm.local/vznet >/dev/null
  # The same vz release S1 proved the boot path on; pinned, never @latest.
  grep -q 'Code-Hex/vz' go.mod || go get github.com/Code-Hex/vz/v3@v3.7.1 >/dev/null 2>&1
  go build -o ../tools/vznet .
) || { echo "S5 SETUP FAIL: vznet build"; exit 1; }
(
  cd s5host
  [ -f go.mod ] || go mod init k3sm.local/s5host >/dev/null
  go build -o ../tools/s5host .
) || { echo "S5 SETUP FAIL: s5host build"; exit 1; }

# vznet constructs VMs, so it needs the same entitlement-only ad-hoc signature
# S1 proved sufficient AND necessary. s5host is an ordinary socket program.
cat > ent.plist <<'PLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.virtualization</key><true/>
</dict></plist>
PLEOF
codesign -s - -f --entitlements ent.plist tools/vznet >/dev/null 2>&1
codesign --verify --strict tools/vznet && echo "S5_VZNET_SIGNED=ok"
LABEOF

note "S5 phase 1 — criteria 5 (lease stability, N=3) and 7 (guest link MTU)"

lab5 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
S5DIR="$PREFIX/s5"
export S5_KERNEL="$PWD/guest/Image" S5_INITRD="$S5DIR/initramfs.cpio"
export S5_SHARE_DIR="$S5DIR/share" S5_WAIT=70

# A locally-administered MAC derived from a fixed string, so the DHCP server
# sees the SAME client across restarts. Criterion 5 asks whether that is enough
# to keep the lease: B113b's address->pod registry is only buildable if it is.
MAC_A=$(printf '5a:c3:%s' "$(echo -n k3sm-s5-guest-a | shasum -a 256 | cut -c1-8 | sed 's/../&:/g;s/:$//')")
MAC_CTL=$(printf '5a:c3:%s' "$(echo -n k3sm-s5-guest-ctl | shasum -a 256 | cut -c1-8 | sed 's/../&:/g;s/:$//')")
echo "S5_C5_MAC_A=$MAC_A"
echo "S5_C5_MAC_CONTROL=$MAC_CTL"

for i in 1 2 3; do
  S5_MAC="$MAC_A" S5_CMDLINE="s5_role=discover" \
    spawn 90 "out/s5-lease$i.log" "$S5DIR/tools/vznet"
  reap "$SPAWN_PID" "$SPAWN_WATCH" || true
  echo "S5_C5_RUN${i}_ADDR=$(field "out/s5-lease$i.log" S5_C5_ADDR)"
  echo "S5_C5_RUN${i}_MAC=$(field "out/s5-lease$i.log" S5_MAC)"
done

# The control: a DIFFERENT MAC must get a DIFFERENT address, or "stable across
# restarts" would be indistinguishable from "the server hands out one address".
S5_MAC="$MAC_CTL" S5_CMDLINE="s5_role=discover" \
  spawn 90 "out/s5-lease-ctl.log" "$S5DIR/tools/vznet"
reap "$SPAWN_PID" "$SPAWN_WATCH" || true
echo "S5_C5_CONTROL_ADDR=$(field out/s5-lease-ctl.log S5_C5_ADDR)"

GW=$(field out/s5-lease1.log S5_GW)
echo "$GW" > out/s5-gw.txt
echo "S5_GW_DISCOVERED=$GW"
echo "S5_C7_MTU=$(field out/s5-lease1.log S5_C7_MTU)"
echo "S5_C7_IPLINK=$(field out/s5-lease1.log S5_C7_IPLINK)"
echo "S5_VIRTIOFS=$(field out/s5-lease1.log S5_VIRTIOFS)"
LABEOF

note "S5 phase 2 — criteria 6 (source address), 1a/1b (guest->host), 2 (host->guest)"

lab5 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
S5DIR="$PREFIX/s5"
GW=$(cat out/s5-gw.txt)
[ -n "$GW" ] || { echo "S5 FAIL: no gateway discovered in phase 1"; exit 1; }
echo "S5_GW=$GW"

export S5_KERNEL="$PWD/guest/Image" S5_INITRD="$S5DIR/initramfs.cpio"
export S5_SHARE_DIR="$S5DIR/share" S5_WAIT=110
MAC_A=$(printf '5a:c3:%s' "$(echo -n k3sm-s5-guest-a | shasum -a 256 | cut -c1-8 | sed 's/../&:/g;s/:$//')")

# Three host listeners, all unprivileged, all high ports. Same DESTINATION
# address from the guest (the NAT gateway); three different host-side binds.
spawn 120 out/s5-host-wild.log "$S5DIR/tools/s5host" listen WILDCARD 0.0.0.0   34801 34802 100 5
W_PID=$SPAWN_PID;  W_WATCH=$SPAWN_WATCH
spawn 120 out/s5-host-lo.log   "$S5DIR/tools/s5host" listen LOBOUND  127.0.0.1 34805 34806 100 5
L_PID=$SPAWN_PID;  L_WATCH=$SPAWN_WATCH
# The gateway-bound listener races the bridge interface into existence, so it
# gets a long bind retry rather than a sleep guess.
spawn 120 out/s5-host-gw.log   "$S5DIR/tools/s5host" listen GWBOUND  "$GW"     34803 34804 100 40
G_PID=$SPAWN_PID;  G_WATCH=$SPAWN_WATCH

S5_MAC="$MAC_A" \
S5_CMDLINE="s5_role=solo s5_settle=8 s5_pw_t=34801 s5_pw_u=34802 s5_pg_t=34803 s5_pg_u=34804 s5_pl_t=34805 s5_pl_u=34806 s5_cidr=10.43.0.0/16 s5_vip=10.43.0.10 s5_vipport=34807 s5_srv=34811 s5_listen_s=35" \
  spawn 130 out/s5-solo.log "$S5DIR/tools/vznet"
VM_PID=$SPAWN_PID; VM_WATCH=$SPAWN_WATCH

if wait_line out/s5-solo.log 'S5_C2_LISTENING=' 110 >/dev/null; then
  GUESTIP=$(field out/s5-solo.log S5_C5_ADDR)
  echo "S5_C2_GUEST_ADDR=$GUESTIP"
  "$S5DIR/tools/s5host" dial GUEST "$GUESTIP:34811" "host-to-guest-hello" 8 | tee out/s5-dial.log
else
  echo "S5_C2_HOST_DIAL=NOT RUN — the guest never announced its listener"
fi

reap "$VM_PID" "$VM_WATCH" || true
reap "$W_PID" "$W_WATCH" || true
reap "$L_PID" "$L_WATCH" || true
reap "$G_PID" "$G_WATCH" || true
LABEOF

note "S5 phase 3 — criterion 4: the guest<->guest matrix (TWO guests, one NAT segment)"

lab5 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
S5DIR="$PREFIX/s5"
export S5_KERNEL="$PWD/guest/Image" S5_INITRD="$S5DIR/initramfs.cpio"
export S5_SHARE_DIR="$S5DIR/share" S5_WAIT=110

MAC_B=$(printf '5a:c3:%s' "$(echo -n k3sm-s5-guest-b | shasum -a 256 | cut -c1-8 | sed 's/../&:/g;s/:$//')")
MAC_P=$(printf '5a:c3:%s' "$(echo -n k3sm-s5-guest-p | shasum -a 256 | cut -c1-8 | sed 's/../&:/g;s/:$//')")

# A host listener runs for the whole phase so BOTH guests can prove their stacks
# live against a third party. Its accept log carries each guest's source address
# as the HOST sees it — the independent witness the matrix verdict rests on.
spawn 200 out/s5-host-c4.log "$S5DIR/tools/s5host" listen WILDCARD 0.0.0.0 34801 34802 190 5
C_PID=$SPAWN_PID; C_WATCH=$SPAWN_WATCH

# B first: the prober needs B's leased address, and VZ exposes no guest-IP API,
# so the console IS the discovery channel.
S5_MAC="$MAC_B" S5_CMDLINE="s5_role=peer s5_srv=34812 s5_listen_s=70 s5_ctlport=34801" \
  spawn 150 out/s5-peer.log "$S5DIR/tools/vznet"
B_PID=$SPAWN_PID; B_WATCH=$SPAWN_WATCH

if wait_line out/s5-peer.log 'S5_C4_PEER_LISTENING=' 90 >/dev/null; then
  PEERIP=$(field out/s5-peer.log S5_C5_ADDR)
  echo "S5_C4_PEER_ADDR=$PEERIP"
  S5_MAC="$MAC_P" S5_CMDLINE="s5_role=prober s5_settle=4 s5_peer=$PEERIP s5_peerport=34812 s5_ctlport=34801" \
    spawn 150 out/s5-prober.log "$S5DIR/tools/vznet"
  P_PID=$SPAWN_PID; P_WATCH=$SPAWN_WATCH
  reap "$P_PID" "$P_WATCH" || true
else
  echo "S5_C4=NOT RUN — the peer guest never announced its listener"
fi
reap "$B_PID" "$B_WATCH" || true
reap "$C_PID" "$C_WATCH" || true
LABEOF

note "S5 — every observed line, verbatim (this is what findings-s5.md transcribes)"

lab5 <<'LABEOF'
set -euo pipefail
cd "$PREFIX"
for f in out/s5-lease1.log out/s5-lease2.log out/s5-lease3.log out/s5-lease-ctl.log \
         out/s5-solo.log out/s5-host-wild.log out/s5-host-gw.log out/s5-host-lo.log \
         out/s5-dial.log out/s5-peer.log out/s5-prober.log out/s5-host-c4.log; do
  [ -f "$f" ] || { echo "== $f: ABSENT (that leg did not run)"; continue; }
  echo "== $f"
  grep -E '^(S5_|VZNET_)' "$f" | sed 's/^/   /' || true
done

# Leave no VM behind. Scoped to THIS prefix's binary so a co-resident harness
# on the rig is untouched.
pkill -f "$PREFIX/s5/tools/vznet" 2>/dev/null || true
echo "S5_CLEANUP=done"
LABEOF

note "S5 — record every answer in findings-s5.md as a DECISION TABLE (see s5.sh for the branch consequences)"
