#!/usr/bin/env bash
# M11.0-d5 / S5 — guest networking. THE CRITICAL PATH.
#
# S5 decides ALL FOUR darwin-net M11.3 deliverables and both Service legs of the
# m11-core gate. Its findings file is not a report — it is a DECISION TABLE:
# every observed answer maps to the exact encoding the builder implements, so
# nobody improvises a network design in a lab session.
#
# Seven criteria (k3sm/docs/PHASES.md M11.0-d5):
#   1 does XNU weak-host-deliver a guest packet to a host lo0-alias VIP?
#     tested over BOTH TCP and UDP/53 (the DNS VIP is the case that matters, and
#     weak-host behaviour can differ by protocol) under four arrangements, AND
#     whether `route add` succeeds UNPRIVILEGED — that negative is what decides
#     whether a netd verb is needed at all (B232).
#   2 is the guest's vmnet address host-dialable? ONE path carries readiness
#     probes, port-forward, and the Service-proxy backend dial.
#   3 does PodIP-as-guest-eth0-alias + a host route deliver same-node traffic?
#   4 the trust matrix, INCLUDING guest -> every other pod's lo0 /32.
#   5 vmnet lease stability across restart under a deterministic MAC.
#   6 WHAT SOURCE ADDRESS THE HOST OBSERVES for guest traffic — the deciding
#     fact for B113: a gateway rewrite makes per-pod attribution IMPOSSIBLE as
#     specified, and B113a's fail-closed becomes the permanent answer.
#   7 guest link MTU.
#
# Runs on S1's harness plus a throwaway stock linux/arm64 minirootfs over
# virtiofs. Requires S1 GO.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

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

note "S5 criterion 1 — guest -> host lo0-alias VIP, TCP and UDP/53, four arrangements"

lab <<'LABEOF'
set -euo pipefail
cd "$PREFIX"; mkdir -p out

VIP=10.43.0.10          # a ClusterIP-shaped address; the DNS VIP is one of these
echo "== host side: plumb the VIP on lo0 and listen =="
# UNPRIVILEGED FIRST. Whether this needs root is criterion 1's real question:
# if an unprivileged process can neither alias nor route, a netd verb (B232) is
# the only path and that is a privilege-surface expansion at launch.
set +e
ifconfig lo0 alias "$VIP"/32 2>&1 | sed 's/^/  unprivileged ifconfig alias: /'
echo "  unprivileged alias exit=$?"
route -n add -host "$VIP" 127.0.0.1 2>&1 | sed 's/^/  unprivileged route add: /'
echo "  unprivileged route exit=$?"
set -e
echo "  (a non-zero exit here is the finding, not a failure of the script)"
LABEOF

cat <<'EOF'

  NOTE — the remaining criterion-1 arrangements need the guest running with a
  NAT device and a shell. They are driven from the vzboot `pair` mode built in
  S1, extended here with a stock arm64 minirootfs so the guest has `ip`, `nc`
  and `dig`. Each arrangement is recorded separately:

    (a) baseline, no route          — default via the NAT gateway only
    (b) guest-side route            — ip route add <serviceCIDR> via <natgw>
    (c) host ip-forwarding          — sysctl net.inet.ip.forwarding=1
    (d) explicit host route         — VIP pointed at the vmnet interface

  BRANCH CONSEQUENCE, written into findings-s5.md as the M11.3-d1 encoding:

    (b) alone suffices  => ZERO new privileged surface. The route set becomes
                           data on podnet.GuestNetwork, applied by the guest's
                           own route plan. This is the outcome to design for.
    needs (c) or (d)    => a narrow netd route verb: B232. Prefixes constrained
                           to podCIDR union serviceCIDR, interface constrained
                           to the vmnet family, idempotent, revoked at teardown,
                           LOCAL_PEERCRED uid-gated like every existing verb.
    nothing works       => fallback (iii): a userspace forwarder INSIDE vmhost.
                           It already terminates the guest boundary, so it needs
                           no XNU behaviour and no privilege. If S5(1) fails
                           entirely and this is judged out of scope, CORE leg 5
                           (vm pod as a Service CLIENT) drops and the honest
                           claim shrinks to "a vm pod serves Services but cannot
                           consume them" — a real, publishable limitation rather
                           than a silent gap.

EOF

note "S5 criterion 6 — the source address the host observes (decides B113)"
cat <<'EOF'
  With a host listener on both the VIP and the vmnet interface, record what
  source address guest traffic arrives with.

    guest's own vmnet IP  => per-pod attribution is a straight map; B113b is
                             tractable and the lease->pod registry is buildable.
    rewritten to the NAT  => per-pod attribution is IMPOSSIBLE as specified.
    gateway address          B113a's fail-closed becomes the PERMANENT answer,
                             and that must be said plainly in limitations.md
                             rather than left as a "future work" line.

  This criterion is the one most likely to be skipped as an implementation
  detail. It is not: it decides whether a NetworkPolicy can ever mean anything
  for a vm pod.
EOF

note "S5 — the automatable criteria are RUN by s5-run.sh"
cat <<'EOF'
  This script is the runbook: it owns every criterion's statement and its
  branch consequence. The criteria that need NO ROOT are executed by

      hack/spike/m11/s5-run.sh

  on a network-capable Alpine guest — 1a/1b (guest -> host, and whether
  service-CIDR packets leave the guest), 2 (host -> guest), 4 (the guest<->guest
  matrix, with liveness controls), 5 (lease stability under a deterministic
  MAC), 6 (the source address the host observes) and 7 (guest link MTU). Its
  results are already recorded in findings-s5.md.

  What s5-run.sh deliberately does NOT do is the root-needing half: no lo0 VIP
  alias, no host route, no ip-forwarding sysctl. Those legs are listed as the
  human slice at the bottom of findings-s5.md and are run by a human with root
  in one sitting; they are never approximated.
EOF

note "S5 — record every answer in findings-s5.md as a DECISION TABLE, not prose"
