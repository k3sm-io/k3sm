#!/usr/bin/env bash
# M11.0-d5 / S5 — the ROOT-NEEDING half of guest networking. ONE OPERATOR SITTING.
#
#   sudo bash hack/spike/m11/s5-root.sh              # the real sitting
#   bash hack/spike/m11/s5-root.sh --dry-run         # print the plan, touch nothing
#
# s5.sh is the RUNBOOK and owns every criterion's branch consequence. s5-run.sh
# ran the no-root subset and its answers are already in findings-s5.md. THIS
# script runs the legs that findings-s5.md lists as "NOT RUN — the root-needing
# human slice", and nothing else:
#
#   criterion 1, arrangements (a)-(d) against a REAL lo0-alias VIP
#       (a) baseline            no guest route, host forwarding OFF
#       (b) + guest route       ip route add <serviceCIDR> via <natgw>
#       (c) + host forwarding   sysctl -w net.inet.ip.forwarding=1
#       (d) + explicit host route for the VIP
#     dialled over BOTH TCP and UDP/53 — the DNS VIP is the case that matters,
#     and XNU's weak-host behaviour can differ by protocol.
#
#   criterion 3, PodIP-as-guest-eth0-alias + a host route to it: does same-node
#     traffic addressed to the published PodIP deliver?
#
# WHY A SEPARATE SCRIPT, RUN BY A HUMAN. Every leg above mutates host network
# state (an lo0 alias, a global sysctl, the routing table). The spike guardrails
# in lib.sh forbid an agent doing that; and an unattended process that dies
# mid-run leaves a machine with IP forwarding on. So the mutations are confined
# to one script, made in one sitting, with ONE restore path that runs on every
# exit — success, failure, and interrupt alike.
#
# WHAT IT DOES NOT DO. It does not write findings-s5.md. The human slice stays
# human-recorded: the script prints the exact table rows at the end and the
# operator pastes them, so no unattended process can author an observation.
# It also never probes guest -> LAN, which would put traffic on the operator's
# physical network.
#
# PRECONDITIONS. s5-run.sh must have been run first: this script reuses that
# sitting's signed `vznet` harness, its `s5host` probe, its unpacked Alpine
# rootfs and the throwaway kernel, and rebuilds ONLY the initramfs (to swap in
# the probe below). It refuses rather than rebuilding Go toolchain artifacts in
# a root sitting.
set -euo pipefail

# --------------------------------------------------------------------- knobs
VIP="${K3SM_SPIKE_VIP:-10.43.0.10}"                 # a ClusterIP-shaped address
SERVICE_CIDR="${K3SM_SPIKE_SERVICE_CIDR:-10.43.0.0/16}"
# Pod IPs are 100.64.0.0/10 per DESIGN.md (a per-node /24 from node.spec.podCIDR),
# so criterion 3's advisory PodIP is shaped from that range, not from 10.42/16.
PODIP="${K3SM_SPIKE_PODIP:-100.64.0.99}"
VIP_TCP_PORT="${K3SM_SPIKE_VIP_TCP:-34901}"
VIP_UDP_PORT="${K3SM_SPIKE_VIP_UDP:-53}"            # PRIVILEGED — the point of the sitting
C3_PORT="${K3SM_SPIKE_C3_PORT:-34911}"

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1
if [ -n "${1:-}" ] && [ "$1" != "--dry-run" ]; then
  echo "usage: sudo bash $0 [--dry-run]" >&2; exit 2
fi

# The prefix belongs to the INVOKING user, not to root: sudo's HOME handling
# differs by sudoers configuration, so deriving it from $HOME would silently
# write a root-owned tree into /var/root on some machines.
OWNER="${SUDO_USER:-${USER:-$(id -un)}}"
OWNER_HOME="$(eval echo "~$OWNER")"
PREFIX="${K3SM_SPIKE_PREFIX_LOCAL:-$OWNER_HOME/k3sm-spike-m11}"
S5DIR="$PREFIX/s5"
OUT="$PREFIX/out"

# ------------------------------------------------------------- the plan text
plan() {
  cat <<PLAN
================================================================================
 S5 ROOT SITTING — the plan, in full, before anything is touched
================================================================================
 rig            $(hostname) · $(sw_vers -productVersion 2>/dev/null) · $(uname -m)
 invoking user  $OWNER   (VMs and log files run/land as this user, not root)
 lab prefix     $PREFIX

 HOST STATE THIS SCRIPT MUTATES — and restores on EVERY exit path:
   1. lo0 alias           ifconfig lo0 alias $VIP/32
                          restored with: ifconfig lo0 -alias $VIP
   2. IP forwarding       sysctl -w net.inet.ip.forwarding=0  (arrangements a,b)
                                                          =1  (arrangements c,d)
                          restored to the value READ BEFORE the first write
   3. host route (VIP)    route -n add -host $VIP -interface lo0   (arrangement d)
                          restored with: route -n delete -host $VIP
   4. host route (PodIP)  route -n add -host $PODIP <guest vmnet address>  (criterion 3)
                          restored with: route -n delete -host $PODIP

 HOST STATE IT DOES NOT TOUCH: pf, /etc, launchd, DNS configuration, any
 interface other than lo0, any route other than the two host routes above.

 NETWORK TRAFFIC IT GENERATES: guest -> host only, on this Mac. Nothing is sent
 to the physical LAN; guest -> LAN is deliberately out of scope.

 WHAT IT RUNS
   arrangement (a)  VIP aliased, forwarding OFF, NO guest route     -> TCP + UDP/$VIP_UDP_PORT
   arrangement (b)  + guest route $SERVICE_CIDR via the NAT gateway  -> TCP + UDP/$VIP_UDP_PORT
   arrangement (c)  + host forwarding ON                            -> TCP + UDP/$VIP_UDP_PORT
   arrangement (d)  + explicit host route for the VIP on lo0        -> TCP + UDP/$VIP_UDP_PORT
   criterion 3      guest eth0 alias $PODIP + a host route to it     -> host dials $PODIP:$C3_PORT

 EVIDENCE
   raw console + host-listener logs   $OUT/s5root-*.log
   every answer as an S5ROOT_*= line, printed at the end as paste-ready rows.
   This script does NOT edit findings-s5.md — the human slice stays human-recorded.

 REUSED FROM THE s5-run.sh SITTING (not rebuilt here)
   $S5DIR/tools/vznet     (ad-hoc signed, com.apple.security.virtualization)
   $S5DIR/tools/s5host
   $S5DIR/rootfs          (the pinned Alpine minirootfs, already unpacked)
   $PREFIX/guest/Image    (the throwaway kernel S1 and S5 booted)
================================================================================
PLAN
}

if [ "$DRY_RUN" -eq 1 ]; then
  plan
  cat <<'EOF'
 --dry-run: nothing above was executed, no file was written, no host state was
 read-modify-written. Run it for real with:

     sudo bash hack/spike/m11/s5-root.sh
EOF
  exit 0
fi

# ------------------------------------------------------------------- refusals
if [ "$(id -u)" -ne 0 ]; then
  cat >&2 <<EOF
REFUSED: this script must run as root (EUID 0); it is EUID $(id -u).

Every leg it runs mutates host network state that an unprivileged process
cannot touch — which is exactly why these legs were left unrun by s5-run.sh.

    sudo bash $0
    bash $0 --dry-run      # to see the plan without root
EOF
  exit 1
fi

for f in "$S5DIR/tools/vznet" "$S5DIR/tools/s5host" "$PREFIX/guest/Image"; do
  [ -e "$f" ] || { echo "REFUSED: missing $f — run hack/spike/m11/s5-run.sh first (this sitting reuses its artifacts and does not build Go under root)." >&2; exit 1; }
done
[ -d "$S5DIR/rootfs" ] || { echo "REFUSED: missing $S5DIR/rootfs — run hack/spike/m11/s5-run.sh first." >&2; exit 1; }

# A pre-existing alias is someone else's state (or a previous crashed run's).
# Refusing is safer than adopting it: the restore path must only ever undo what
# THIS run did, or it becomes a way to delete configuration nobody asked about.
if ifconfig lo0 2>/dev/null | grep -q "inet $VIP "; then
  echo "REFUSED: $VIP is ALREADY aliased on lo0. This script only removes an alias it created." >&2
  echo "         Inspect it, and if it is a leftover: sudo ifconfig lo0 -alias $VIP" >&2
  exit 1
fi

plan
echo
echo "Starting in 5 seconds — press Ctrl-C to abort."
i=5
while [ "$i" -gt 0 ]; do printf '\r  %d ... ' "$i"; sleep 1; i=$((i - 1)); done
printf '\r  go.      \n\n'

mkdir -p "$OUT"

# ------------------------------------------------------- restore, unconditionally
# Set BEFORE the first mutation. Every flag is flipped only after the mutation
# it guards has succeeded, so the trap never "restores" something that was never
# applied.
DID_ALIAS=0
DID_FWD=0
DID_ROUTE_VIP=0
DID_ROUTE_POD=0
FWD_PRIOR=""

restore() {
  local rc=$?
  set +e
  echo
  echo "=============================== RESTORING ==================================="
  if [ "$DID_ALIAS" -eq 1 ]; then
    ifconfig lo0 -alias "$VIP" 2>/dev/null
    if ifconfig lo0 2>/dev/null | grep -q "inet $VIP "; then
      echo "S5ROOT_RESTORE_LO0_ALIAS=FAILED — $VIP is STILL on lo0; remove it by hand: sudo ifconfig lo0 -alias $VIP"
    else
      echo "S5ROOT_RESTORE_LO0_ALIAS=removed ($VIP is no longer on lo0, verified)"
    fi
  else
    echo "S5ROOT_RESTORE_LO0_ALIAS=nothing-to-do (never aliased)"
  fi

  if [ "$DID_ROUTE_VIP" -eq 1 ]; then
    route -n delete -host "$VIP" >/dev/null 2>&1
    echo "S5ROOT_RESTORE_ROUTE_VIP=deleted host route for $VIP (present after delete: $(netstat -rn -f inet 2>/dev/null | grep -c "^$VIP " || true))"
  else
    echo "S5ROOT_RESTORE_ROUTE_VIP=nothing-to-do (never added)"
  fi

  if [ "$DID_ROUTE_POD" -eq 1 ]; then
    route -n delete -host "$PODIP" >/dev/null 2>&1
    echo "S5ROOT_RESTORE_ROUTE_PODIP=deleted host route for $PODIP (present after delete: $(netstat -rn -f inet 2>/dev/null | grep -c "^$PODIP " || true))"
  else
    echo "S5ROOT_RESTORE_ROUTE_PODIP=nothing-to-do (never added)"
  fi

  if [ "$DID_FWD" -eq 1 ] && [ -n "$FWD_PRIOR" ]; then
    sysctl -w "net.inet.ip.forwarding=$FWD_PRIOR" >/dev/null 2>&1
    echo "S5ROOT_RESTORE_FWD=restored to $FWD_PRIOR (read back: $(sysctl -n net.inet.ip.forwarding 2>/dev/null))"
  else
    echo "S5ROOT_RESTORE_FWD=nothing-to-do (never written; value remains $(sysctl -n net.inet.ip.forwarding 2>/dev/null))"
  fi

  # Never leave a guest or a listener behind, and never leave root-owned files
  # in the invoking user's prefix.
  pkill -f "$S5DIR/tools/vznet"  >/dev/null 2>&1
  pkill -f "$S5DIR/tools/s5host" >/dev/null 2>&1
  echo "S5ROOT_RESTORE_PROCESSES=vznet/s5host reaped"
  chown -R "$OWNER" "$OUT" "$S5DIR" >/dev/null 2>&1
  echo "S5ROOT_RESTORE_OWNERSHIP=$OUT and $S5DIR chowned back to $OWNER"
  echo "============================================================================="
  exit "$rc"
}
trap restore EXIT INT TERM

# ---------------------------------------------------------------- helpers
# spawn TIMEOUT LOG CMD... -> SPAWN_PID / SPAWN_WATCH. macOS ships no timeout(1)
# and /bin/bash is 3.2 (no namerefs), so the caller copies the globals.
# The watchdog POLLS rather than sleeping its whole timeout, and both children
# are detached from this script's stdio. A background `sleep <timeout>` holding
# the session's stdout makes a finished phase look hung for the full interval —
# observed on the s3 harness and fixed there the same way. Killing `sudo` does
# not kill the VM it launched, so the EXIT trap's pkill is the real backstop.
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
reap() {
  wait "$1" 2>/dev/null || true
  kill -TERM "$2" 2>/dev/null || true
  wait "$2" 2>/dev/null || true
  return 0
}
wait_line() {
  local i=0
  while [ "$i" -lt "$3" ]; do
    if grep -q "$2" "$1" 2>/dev/null; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  return 1
}
field() { grep -m1 "$2=" "$1" 2>/dev/null | sed "s/.*$2=//" | tr -d '\r'; }
# asuser CMD... — run as the invoking user. The VM harness is ad-hoc signed for
# that user's session and its logs belong in that user's tree; only the network
# mutations above need root, and they are made by this script directly.
asuser() { sudo -u "$OWNER" "$@"; }

note() { printf '\n==> %s\n' "$*"; }

# ------------------------------------------------------------- the guest probe
# Host-authored, shipped at /probe.sh in the initramfs. The s5-run.sh guest init
# (a static Go PID 1, reused verbatim) turns the s5_* kernel-command-line keys
# into /s5env and then runs this file, so every knob below arrives on the
# kernel command line — the only channel a VZ bootloader offers.
note "S5-ROOT — composing the initramfs (the s5 rootfs + init, with a new probe)"
PROBE="$S5DIR/rootfs/probe.sh"
cat > "$PROBE" <<'PROBEEOF'
#!/bin/sh
# S5 root-sitting in-guest probe — host-authored. Every line it prints is a
# finding. The HOST listener's receipt is the authority for UDP; the guest can
# only report that its send did not error.
[ -f /s5env ] && . /s5env
log() { echo "$@"; }

ip link set lo up 2>/dev/null
ip link set eth0 up 2>/dev/null
udhcpc -i eth0 -q -n -t 8 -T 2 -s /usr/share/udhcpc/default.script >/dev/null 2>&1
ADDR=$(ip -4 addr show eth0 | awk '/inet /{split($2,a,"/"); print a[1]}')
GW=$(ip route 2>/dev/null | awk '/^default/{print $3}')
log "S5ROOT_ARR=$S5_ARR"
log "S5ROOT_GUEST_ADDR=$ADDR"
log "S5ROOT_GW=$GW"

if [ "$S5_ROLE" = "vip" ]; then
  if [ "$S5_ROUTE" = "1" ]; then
    if ip route add "$S5_CIDR" via "$GW" dev eth0 2>/tmp/rerr; then
      log "S5ROOT_${S5_ARR}_ROUTEADD=ok cidr=$S5_CIDR via=$GW"
    else
      log "S5ROOT_${S5_ARR}_ROUTEADD=fail err=$(tr '\n' ' ' </tmp/rerr)"
    fi
  else
    log "S5ROOT_${S5_ARR}_ROUTEADD=not-added (baseline: default route only)"
  fi
  log "S5ROOT_${S5_ARR}_ROUTES=$(ip route | tr '\n' '|')"
  sleep "${S5_SETTLE:-6}"

  TX0=$(cat /sys/class/net/eth0/statistics/tx_packets)
  T0=$(date +%s)
  if echo "vip-tcp-from-$ADDR-$S5_ARR" | nc -w 6 "$S5_VIP" "$S5_VIPTCP" >/dev/null 2>&1; then
    RES=connected
  else
    RES=no-answer
  fi
  T1=$(date +%s)
  TX1=$(cat /sys/class/net/eth0/statistics/tx_packets)
  log "S5ROOT_${S5_ARR}_TCP=$RES dst=$S5_VIP:$S5_VIPTCP elapsed_s=$((T1 - T0)) tx_packets_delta=$((TX1 - TX0))"

  TX2=$(cat /sys/class/net/eth0/statistics/tx_packets)
  ERR=$(echo "vip-udp-from-$ADDR-$S5_ARR" | nc -u -w 3 "$S5_VIP" "$S5_VIPUDP" 2>&1 >/dev/null) || true
  TX3=$(cat /sys/class/net/eth0/statistics/tx_packets)
  log "S5ROOT_${S5_ARR}_UDP=sent dst=$S5_VIP:$S5_VIPUDP err=$(echo "$ERR" | tr '\n' ' ') tx_packets_delta=$((TX3 - TX2))"
  log "S5ROOT_${S5_ARR}_NEIGH=$(ip neigh show | tr '\n' '|')"
fi

# ------------------------------------------------------------ role: podip (C3)
if [ "$S5_ROLE" = "podip" ]; then
  if ip addr add "$S5_PODIP/32" dev eth0 2>/tmp/aerr; then
    log "S5ROOT_C3_ALIAS=ok podip=$S5_PODIP dev=eth0"
  else
    log "S5ROOT_C3_ALIAS=fail err=$(tr '\n' ' ' </tmp/aerr)"
  fi
  log "S5ROOT_C3_ADDRS=$(ip -4 addr show eth0 | tr '\n' '|')"
  # The host learns the guest's vmnet address from THIS line, then adds its
  # route and dials the PodIP while the listener below is up.
  log "S5ROOT_C3_LISTENING=port=$S5_SRV podip=$S5_PODIP vmnet=$ADDR"
  timeout "${S5_LISTEN_S:-45}" nc -l -p "$S5_SRV" >/tmp/rx 2>/dev/null || true
  log "S5ROOT_C3_GUEST_RX=$(tr -d '\r\n' </tmp/rx)"
fi

log "S5ROOT_PROBE_COMPLETE=$S5_ARR"
PROBEEOF
chmod +x "$PROBE"
( cd "$S5DIR/rootfs" && find . | cpio -o -H newc 2>/dev/null > "$S5DIR/initramfs-root.cpio" )
chown "$OWNER" "$S5DIR/initramfs-root.cpio" "$PROBE"
echo "S5ROOT_INITRAMFS_BYTES=$(stat -f%z "$S5DIR/initramfs-root.cpio")"

export S5_KERNEL="$PREFIX/guest/Image" S5_INITRD="$S5DIR/initramfs-root.cpio" S5_WAIT=110

# ------------------------------------------------------- the host state, step 1
note "S5-ROOT — reading the prior host state, then plumbing the VIP on lo0"
FWD_PRIOR="$(sysctl -n net.inet.ip.forwarding)"
echo "S5ROOT_FWD_PRIOR=$FWD_PRIOR"
echo "S5ROOT_UNPRIV_ALIAS_RECHECK=$(sudo -u "$OWNER" ifconfig lo0 alias "$VIP"/32 2>&1 | tr '\n' ' ' || true)"
ifconfig lo0 alias "$VIP"/32
DID_ALIAS=1
echo "S5ROOT_LO0_ALIAS=$(ifconfig lo0 | grep "inet $VIP " | tr -s ' ')"

# ------------------------------------------------------------- the arrangements
# arrangement NAME GUEST_ROUTE(0|1) FORWARDING(0|1) HOST_ROUTE(0|1)
arrangement() {
  local name="$1" groute="$2" fwd="$3" hroute="$4"
  note "S5-ROOT — arrangement ($name): guest_route=$groute host_forwarding=$fwd host_route=$hroute"

  sysctl -w "net.inet.ip.forwarding=$fwd" >/dev/null
  DID_FWD=1
  echo "S5ROOT_${name}_FWD=$(sysctl -n net.inet.ip.forwarding)"

  if [ "$hroute" -eq 1 ] && [ "$DID_ROUTE_VIP" -eq 0 ]; then
    if route -n add -host "$VIP" -interface lo0 >/dev/null 2>&1; then
      DID_ROUTE_VIP=1
      echo "S5ROOT_${name}_HOSTROUTE=added ($VIP -> lo0)"
    else
      echo "S5ROOT_${name}_HOSTROUTE=add-failed ($VIP -> lo0)"
    fi
  elif [ "$hroute" -eq 1 ]; then
    echo "S5ROOT_${name}_HOSTROUTE=already-present ($VIP -> lo0)"
  else
    echo "S5ROOT_${name}_HOSTROUTE=absent"
  fi

  # The listener binds ON THE VIP — not the wildcard. A wildcard bind would
  # accept the packet whatever XNU did with the destination address, which is
  # precisely the question, so it would answer it vacuously.
  # It runs as ROOT because UDP/$VIP_UDP_PORT is a privileged port and the DNS
  # VIP is the case the criterion is about.
  spawn 130 "$OUT/s5root-host-$name.log" \
    "$S5DIR/tools/s5host" listen "VIP$name" "$VIP" "$VIP_TCP_PORT" "$VIP_UDP_PORT" 100 10
  local hpid=$SPAWN_PID hwatch=$SPAWN_WATCH

  spawn 130 "$OUT/s5root-guest-$name.log" \
    sudo -u "$OWNER" env S5_KERNEL="$S5_KERNEL" S5_INITRD="$S5_INITRD" S5_WAIT="$S5_WAIT" \
      S5_CMDLINE="s5_role=vip s5_arr=$name s5_route=$groute s5_settle=8 s5_cidr=$SERVICE_CIDR s5_vip=$VIP s5_viptcp=$VIP_TCP_PORT s5_vipudp=$VIP_UDP_PORT" \
      "$S5DIR/tools/vznet"
  reap "$SPAWN_PID" "$SPAWN_WATCH"
  reap "$hpid" "$hwatch"

  grep -E '^S5ROOT_' "$OUT/s5root-guest-$name.log" 2>/dev/null || echo "S5ROOT_${name}=NO GUEST OUTPUT"
  grep -E '^S5_HOST_' "$OUT/s5root-host-$name.log"  2>/dev/null || echo "S5ROOT_${name}_HOST=no host-listener lines"
}

arrangement a 0 0 0
arrangement b 1 0 0
arrangement c 1 1 0
arrangement d 1 1 1

# ------------------------------------------------------------------ criterion 3
note "S5-ROOT — criterion 3: PodIP as a guest eth0 alias + a host route to it"
spawn 160 "$OUT/s5root-guest-c3.log" \
  sudo -u "$OWNER" env S5_KERNEL="$S5_KERNEL" S5_INITRD="$S5_INITRD" S5_WAIT=140 \
    S5_CMDLINE="s5_role=podip s5_arr=c3 s5_podip=$PODIP s5_srv=$C3_PORT s5_listen_s=60" \
    "$S5DIR/tools/vznet"
C3PID=$SPAWN_PID
C3WATCH=$SPAWN_WATCH

if wait_line "$OUT/s5root-guest-c3.log" 'S5ROOT_C3_LISTENING=' 110; then
  GUESTIP="$(field "$OUT/s5root-guest-c3.log" S5ROOT_GUEST_ADDR)"
  echo "S5ROOT_C3_GUEST_VMNET=$GUESTIP"
  if [ -n "$GUESTIP" ]; then
    if route -n add -host "$PODIP" "$GUESTIP" >/dev/null 2>&1; then
      DID_ROUTE_POD=1
      echo "S5ROOT_C3_HOSTROUTE=added ($PODIP via $GUESTIP)"
    else
      echo "S5ROOT_C3_HOSTROUTE=add-failed ($PODIP via $GUESTIP)"
    fi
    echo "S5ROOT_C3_ROUTE_GET=$(route -n get "$PODIP" 2>&1 | tr '\n' '|')"
    asuser "$S5DIR/tools/s5host" dial C3PODIP "$PODIP:$C3_PORT" "host-to-podip-hello" 10 \
      | tee "$OUT/s5root-c3-dial.log"
  else
    echo "S5ROOT_C3=NOT RUN — the guest never reported a vmnet address"
  fi
else
  echo "S5ROOT_C3=NOT RUN — the guest never announced its listener"
fi
reap "$C3PID" "$C3WATCH"
grep -E '^S5ROOT_' "$OUT/s5root-guest-c3.log" 2>/dev/null || true

# ------------------------------------------------------------------- the report
note "S5-ROOT — every observed line, verbatim"
for f in "$OUT"/s5root-*.log; do
  [ -f "$f" ] || continue
  echo "== $f"
  grep -E '^(S5ROOT_|S5_HOST_|VZNET_)' "$f" | sed 's/^/   /' || true
done

note "S5-ROOT — the findings-s5.md rows to paste (this script does NOT edit that file)"
row() { # row ARR
  local a="$1"
  local g="$OUT/s5root-guest-$a.log" h="$OUT/s5root-host-$a.log"
  printf '| **1 (%s)** | %s | guest: `%s` / `%s` · host receipt: `%s` `%s` | <consequence per s5.sh> |\n' \
    "$a" \
    "$(case $a in
         (a) echo 'baseline — VIP on lo0, no guest route, forwarding off';;
         (b) echo '+ guest route for the service CIDR via the NAT gateway';;
         (c) echo '+ host net.inet.ip.forwarding=1';;
         (d) echo '+ explicit host route for the VIP on lo0';;
       esac)" \
    "$(field "$g" "S5ROOT_${a}_TCP")" \
    "$(field "$g" "S5ROOT_${a}_UDP")" \
    "$(grep -m1 "S5_HOST_VIP${a}_TCP_FROM=" "$h" 2>/dev/null | tr -d '\r' || echo 'no TCP receipt')" \
    "$(grep -m1 "S5_HOST_VIP${a}_UDP_FROM=" "$h" 2>/dev/null | tr -d '\r' || echo 'no UDP receipt')"
}
echo
echo '| # | criterion | observed | consequence this selects |'
echo '|---|---|---|---|'
row a; row b; row c; row d
printf '| **3** | PodIP as a guest eth0 alias + a host route | alias: `%s` · host route: `%s` · host dial: `%s` · guest receipt: `%s` | <consequence per s5.sh> |\n' \
  "$(field "$OUT/s5root-guest-c3.log" S5ROOT_C3_ALIAS)" \
  "$(grep -m1 'S5ROOT_C3_HOSTROUTE=' "$OUT/s5root-guest-c3.log" 2>/dev/null || echo 'see console above')" \
  "$(field "$OUT/s5root-c3-dial.log" S5_HOST_DIAL_C3PODIP)" \
  "$(field "$OUT/s5root-guest-c3.log" S5ROOT_C3_GUEST_RX)"
echo
cat <<'EOF'
Transcribe these into findings-s5.md by hand, replacing each <consequence per
s5.sh> with the branch that answer selects — s5.sh criterion 1 states them:

  (b) alone suffices  => ZERO new privileged surface; the route set becomes data
                         on podnet.GuestNetwork. The outcome to design for.
  needs (c) or (d)    => a narrow netd route verb (B232): prefixes constrained to
                         podCIDR union serviceCIDR, interface constrained to the
                         vmnet family, idempotent, revoked at teardown,
                         LOCAL_PEERCRED uid-gated like every existing verb.
  nothing works       => fallback (iii): a userspace forwarder INSIDE vmhost.

And carry the same one-rig caveat findings-s5.md already carries for criterion 4:
one Mac, one macOS build, one VZNATNetworkDeviceAttachment. XNU's weak-host
behaviour is observed here, not contracted by Apple.
EOF
