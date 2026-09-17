#!/usr/bin/env bash
#
# k3sm B336 acceptance gate — the runnable proof that docs/user/multi-node.md
# tells a worker's `--node-ip` for what it actually is.
#
# The defect: the doc told the reader to pass `--node-ip <this-macs-underlay-ip>`
# and called it "this Mac's own underlay address", while `k3sm install --help`
# (cmd/k3sm/install.go) already said "this Mac's own mesh InternalIP, bound into
# the certificates the join issues", and the live join needs the MESH address —
# the /24-carved address the server assigns the node inside the wireguard mesh
# range, not the Mac's LAN address. A reader who followed the doc literally
# handed the join a certificate SAN the node never actually holds on the mesh.
#
# The fix is docs-only: the flag's own description was already correct, so this
# gate pins it as the reference and asserts the doc now agrees with it, plus a
# worked discovery procedure (`k3sm kubectl get meshpeers`, lowest free index,
# first host of that index's /24) a reader can actually follow.
#
# CI TIER ONLY — no rig, nothing runs, nothing is installed. Every rung is a
# grep over checked-in text.
#
# Usage:  hack/acceptance/B336.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B336.sh"
DOC="$K3SM_ROOT/docs/user/multi-node.md"
INSTALL_GO="$K3SM_ROOT/cmd/k3sm/install.go"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B336 acceptance (docs/user/multi-node.md: --node-ip is the worker's mesh address)"

# ---- b336.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$DOC" ] || b0=no
[ -f "$INSTALL_GO" ] || b0=no
ladder "$b0" "b336.0  gate parses (bash -n) + docs/user/multi-node.md and cmd/k3sm/install.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B336: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "B336: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b336.1 — the --node-ip example line itself ----------------------------
# RED BEFORE: the unmodified doc's example line reads
# `--node-ip <this-macs-underlay-ip>` — no "mesh" on the line at all.
w=ok
grep -qE -- '--node-ip <[^>]*mesh[^>]*>' "$DOC" || w=no
grep -qE -- '--node-ip <this-macs-underlay-ip>' "$DOC" && w=no
ladder "$w" "b336.1  the --node-ip example value names the MESH address, not an underlay one"

# ---- b336.2 — the descriptive paragraph the reader actually acts on --------
# Scoped from the example line to the next Markdown heading, so this rung reads
# exactly the prose a reader sees directly under the code block — never the
# --server sentence above it, which legitimately says "underlay" for a
# DIFFERENT flag.
start_line="$(grep -n -- '--node-ip <[^>]*mesh[^>]*>' "$DOC" | head -1 | cut -d: -f1)"
p=ok
if [ -z "$start_line" ]; then
	p=no
else
	end_line="$(awk -v s="$start_line" 'NR>s && /^#/{print NR; exit}' "$DOC")"
	[ -n "$end_line" ] || end_line=$(( $(wc -l < "$DOC") + 1 ))
	para="$(sed -n "${start_line},$((end_line-1))p" "$DOC")"
	printf '%s\n' "$para" | grep -qi 'mesh' || p=no
	printf '%s\n' "$para" | grep -qi 'underlay address' && p=no
fi
ladder "$p" "b336.2  the --node-ip section says 'mesh' and never calls it an 'underlay address'"

# ---- b336.3 — the install --help text agrees (the reference this docs the fix against) ----
# Read straight from the flag registration source, never the built binary.
i=ok
grep -qE 'fs\.StringVar\(&o\.nodeIP, "node-ip".*mesh' "$INSTALL_GO" || i=no
ladder "$i" "b336.3  cmd/k3sm/install.go's --node-ip flag registration string says 'mesh'"

echo "----------------------------------------"
echo "B336: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B336 GREEN ================"
