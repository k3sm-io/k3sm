#!/usr/bin/env bash
#
# k3sm B374 acceptance gate — the runnable proof that docs/privilege-model.md
# no longer claims the io.k3sm.* pf anchor survives uninstall.
#
# The defect this documents against: the doc's Uninstall bullet said the
# anchor "is not removed" and uninstall "does *not* flush all privileged
# state" — stale since B274, which added FlushMeshPFAnchor
# (pkg/install/install_darwin.go) as an unconditional, best-effort uninstall
# backstop (pkg/install/install.go wires it into every Uninstall call). This
# gate asserts the corrected sentence is present, the stale claim is gone, and
# the doc now says the packet filter's own enable state is deliberately left
# undescribed pending the wiring work that will decide its ownership.
#
# CI TIER ONLY — no rig, no cluster, nothing runs. Every rung but the voice
# lint is a grep over checked-in text; content-anchored per the B336 idiom
# (never heading-only).
#
# Usage:  hack/acceptance/B374.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B374.sh"
DOC="$K3SM_ROOT/docs/privilege-model.md"
# The voice lint lives in the workspace control-center, one level above the
# repo checkout in the ordinary layout -- but this public repo's script must
# stand alone (no workspace path may appear here, the B365 lesson). The rung
# runs only when the caller names the lint through K3SM_VOICE_LINT; otherwise
# it SKIPs, and the workspace ci (which owns the lint) still covers the file
# at publish.
VOICE_LINT="${K3SM_VOICE_LINT:-}"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B374 acceptance (privilege-model.md: uninstall flushes the mesh pf anchor)"

# ---- b374.0 — the gate parses and its source exists -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$DOC" ] || b0=no
ladder "$b0" "b374.0  gate parses (bash -n) + docs/privilege-model.md present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B374: the gate or its source is missing/unparseable — nothing else can run" >&2
	echo "B374: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b374.1 — the stale "anchor is not removed" claim is gone ---------------
stale=ok
grep -qi 'anchor is not removed' "$DOC" && stale=no
grep -qi 'does .\{0,4\}not\* flush all privileged state' "$DOC" && stale=no
grep -qi 'flush the anchor by hand' "$DOC" && stale=no
ladder "$stale" "b374.1  the stale not-removed / does-not-flush claim is gone"

# ---- b374.2 — the corrected sentence: uninstall flushes the anchor ----------
fixed=ok
grep -qi 'flushes the mesh' "$DOC" || fixed=no
grep -qF 'io.k3sm.mesh' "$DOC" || fixed=no
grep -qi 'best-effort backstop' "$DOC" || fixed=no
grep -qi 'pfctl.*failure is reported' "$DOC" || fixed=no
grep -qi 'never stops the rest of uninstall' "$DOC" || fixed=no
ladder "$fixed" "b374.2  the corrected sentence names the best-effort pfctl flush and its failure handling"

# ---- b374.3 — the pf enable-state deferral sentence -------------------------
# Joined into one line first: the sentence legitimately wraps across the
# markdown source's soft line breaks, and a per-line grep would be fooled by
# reflowing prose that says nothing at all.
deferred=ok
JOINED="$(tr '\n' ' ' < "$DOC")"
printf '%s' "$JOINED" | grep -qi 'stays enabled' || deferred=no
printf '%s' "$JOINED" | grep -qi 'deliberately not described' || deferred=no
printf '%s' "$JOINED" | grep -qi 'wiring work decides' || deferred=no
printf '%s' "$JOINED" | grep -qi 'pf.\{0,20\}stays enabled' || deferred=no
ladder "$deferred" "b374.3  the doc defers pf's own enable-state ownership to the wiring work"

# ---- b374.4 — the workspace voice lint, fatal-only --------------------------
v=ok
if [ -z "$VOICE_LINT" ] || [ ! -f "$VOICE_LINT" ]; then
	echo "SKIP  b374.4  voice lint not named (set K3SM_VOICE_LINT); the workspace ci owns it at publish"
	v=skip
else
	if ! bash "$VOICE_LINT" --stdin --tier source --as docs/privilege-model.md < "$DOC" >/tmp/b374-voice.$$ 2>&1; then
		v=no
		echo "  ---- voice lint output ----"
		sed 's/^/  /' /tmp/b374-voice.$$
		echo "  ----------------------------"
	fi
	rm -f /tmp/b374-voice.$$
fi
if [ "$v" != skip ]; then
	ladder "$v" "b374.4  the voice lint reports no fatal finding over the changed file"
fi

echo "----------------------------------------"
echo "B374: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B374 GREEN ================"
