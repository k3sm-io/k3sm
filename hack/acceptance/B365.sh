#!/usr/bin/env bash
#
# k3sm B365 acceptance gate — the runnable proof that
# docs/user/troubleshooting.md carries a real runbook for a node that went
# offline while it was running Pods, not just a pointer at kubectl.
#
# The defect this documents against: a Pod bound to a Mac that goes away stays
# `Terminating` forever, because nothing on that Mac can confirm the container
# is gone. The only escape is the upstream `node.kubernetes.io/out-of-service`
# taint (podgc then force-deletes the stuck Pods), and the doc has to say so
# with the exact taint key, its `NoExecute` effect, the force-delete fallback,
# and the asleep-vs-actually-off distinction first, or a reader tells a
# sleeping Mac it is out of service.
#
# CI TIER ONLY — no rig, no cluster, nothing runs. Every rung but the voice
# lint is a grep over checked-in text; content-anchored per the B336 idiom
# (never heading-only), so a heading with no real content under it still fails.
#
# Usage:  hack/acceptance/B365.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B365.sh"
DOC="$K3SM_ROOT/docs/user/troubleshooting.md"
MULTINODE_DOC="$K3SM_ROOT/docs/user/multi-node.md"
# The voice lint lives in the workspace control-center, one level above the
# repo checkout in the ordinary layout -- but a lane checkout
# The voice lint is a workspace-tier gate; this public repo's script must stand
# alone (no workspace path may appear here). The rung runs only when the caller
# names the lint through K3SM_VOICE_LINT; otherwise it SKIPs, and the workspace
# ci (which owns the lint) still covers the file at publish.
VOICE_LINT="${K3SM_VOICE_LINT:-}"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B365 acceptance (offline-node stuck-terminating runbook)"

# ---- b365.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$DOC" ] || b0=no
[ -f "$MULTINODE_DOC" ] || b0=no
ladder "$b0" "b365.0  gate parses (bash -n) + both docs present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B365: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "B365: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b365.1 — the section heading exists -------------------------------------
h=ok
grep -qE '^## .*Node Went Offline.*Stuck Terminating' "$DOC" || h=no
ladder "$h" "b365.1  troubleshooting.md has an offline-node/stuck-terminating heading"

# Scope every remaining troubleshooting.md rung to the section body, from that
# heading to the next H2 (or EOF) — never the whole file, or a coincidental hit
# elsewhere (or the gate's own comment header) would pass a missing section.
start_line="$(grep -nE '^## .*Node Went Offline.*Stuck Terminating' "$DOC" | head -1 | cut -d: -f1)"
if [ -n "$start_line" ]; then
	end_line="$(awk -v s="$start_line" 'NR>s && /^## /{print NR; exit}' "$DOC")"
	[ -n "$end_line" ] || end_line=$(( $(wc -l < "$DOC") + 1 ))
	SECTION="$(sed -n "${start_line},$((end_line-1))p" "$DOC")"
else
	SECTION=""
fi

# ---- b365.2 — asleep-vs-actually-off comes FIRST, before any escape ----------
a=ok
if [ -z "$SECTION" ]; then
	a=no
else
	printf '%s\n' "$SECTION" | grep -qi 'asleep' || a=no
	printf '%s\n' "$SECTION" | grep -qi 'ping its LAN address\|ping.*LAN' || a=no
	# It must precede the taint command, or a reader could act before checking.
	asleep_pos="$(printf '%s\n' "$SECTION" | grep -ni 'asleep' | head -1 | cut -d: -f1)"
	taint_pos="$(printf '%s\n' "$SECTION" | grep -ni 'kubectl taint node' | head -1 | cut -d: -f1)"
	if [ -z "$asleep_pos" ] || [ -z "$taint_pos" ] || [ "$asleep_pos" -ge "$taint_pos" ]; then
		a=no
	fi
fi
ladder "$a" "b365.2  the asleep/off-network check precedes the taint escape, with the LAN-ping check named"

# ---- b365.3 — the branch: a Mac coming back stops after the taint -----------
br=ok
if [ -z "$SECTION" ]; then
	br=no
else
	printf '%s\n' "$SECTION" | grep -qi 'coming back' || br=no
	printf '%s\n' "$SECTION" | grep -qi 'stop after' || br=no
	printf '%s\n' "$SECTION" | grep -qi 'leaving the cluster' || br=no
	printf '%s\n' "$SECTION" | grep -q 'multi-node.md#removing-a-worker' || br=no
fi
ladder "$br" "b365.3  the section names the coming-back-vs-leaving branch and cross-links the removal flow"

# ---- b365.4 — the exact taint key and NoExecute effect ----------------------
t=ok
if [ -z "$SECTION" ]; then
	t=no
else
	printf '%s\n' "$SECTION" | grep -qF 'kubectl taint node <name> node.kubernetes.io/out-of-service=nodeshutdown:NoExecute' || t=no
	printf '%s\n' "$SECTION" | grep -qF 'kubectl taint node <name> node.kubernetes.io/out-of-service:NoExecute-' || t=no
fi
ladder "$t" "b365.4  the section gives the exact apply and remove out-of-service NoExecute taint commands"

# ---- b365.5 — the force-delete fallback, in the split-brain-safe form -------
f=ok
if [ -z "$SECTION" ]; then
	f=no
else
	printf '%s\n' "$SECTION" | grep -qF -- '--grace-period=0' || f=no
	printf '%s\n' "$SECTION" | grep -qi 'force' || f=no
	printf '%s\n' "$SECTION" | grep -qi 'two copies can run at once' || f=no
	# No em dash anywhere in the section, per the public-tier voice rule; the
	# voice lint below also catches this, but pinning it here names WHY. The
	# literal byte match (not -P, absent from BSD grep) is portable to macOS.
	printf '%s\n' "$SECTION" | grep -qF $'\xe2\x80\x94' && f=no
fi
ladder "$f" "b365.5  the force-delete escape names --grace-period=0 and the split-brain caveat without an em dash"

# ---- b365.6 — the k3sm status pointer ---------------------------------------
s=ok
if [ -z "$SECTION" ]; then
	s=no
else
	printf '%s\n' "$SECTION" | grep -qi 'k3sm status' || s=no
fi
ladder "$s" "b365.6  the section points at the k3sm status workloads-row pointer"

# ---- b365.7 — the DaemonSet rollout prevention advice -----------------------
d=ok
if [ -z "$SECTION" ]; then
	d=no
else
	printf '%s\n' "$SECTION" | grep -qi 'maxSurge' || d=no
	printf '%s\n' "$SECTION" | grep -qi 'maxUnavailable' || d=no
	printf '%s\n' "$SECTION" | grep -qi 'DaemonSet' || d=no
fi
ladder "$d" "b365.7  the section covers DaemonSet surge settings so one offline node cannot freeze a rollout"

# ---- b365.8 — multi-node.md carries the cross-link back ---------------------
m=ok
grep -q 'troubleshooting.md#a-node-went-offline-and-pods-are-stuck-terminating' "$MULTINODE_DOC" || m=no
ladder "$m" "b365.8  multi-node.md cross-links the new troubleshooting section"

# ---- b365.9 — the workspace voice lint, fatal-only --------------------------
v=ok
if [ -z "$VOICE_LINT" ] || [ ! -f "$VOICE_LINT" ]; then
	echo "SKIP  b365.9  voice lint not named (set K3SM_VOICE_LINT); the workspace ci owns it at publish"
	v=skip
else
	if ! bash "$VOICE_LINT" --stdin --tier source --as docs/user/troubleshooting.md < "$DOC" >/tmp/b365-voice.$$ 2>&1; then
		v=no
		echo "  ---- voice lint output ----"
		sed 's/^/  /' /tmp/b365-voice.$$
		echo "  ----------------------------"
	fi
	rm -f /tmp/b365-voice.$$
fi
if [ "$v" != skip ]; then
	ladder "$v" "b365.9  the voice lint reports no fatal finding over the changed file"
fi

echo "----------------------------------------"
echo "B365: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B365 GREEN ================"
