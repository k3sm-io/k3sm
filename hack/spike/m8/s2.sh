#!/usr/bin/env bash
# M8.0-d2 / S2 — nested-dylib signing under AMFI, and exec from a clonefiled tree.
#
# Feeds runtimed M8.2-d3 (AdHocSignTree) and M8.4-a1's mechanized walk-verify.
# Questions, in order:
#   walk     how many Mach-Os are in an MLX python tree, and what is the
#            signed / linker-ad-hoc / unsigned / INVALID tally?
#   arch     for every file the walk calls INVALID, WHY — per-slice verification
#            of the universal binaries is the discriminator AdHocSignTree needs
#   clone    does `cp -c` (clonefile) preserve the signatures, and does the tree
#            still EXEC from the clone — unsandboxed AND under the S1 profile?
#   cow      is the clone genuinely copy-on-write (free-space delta), and what
#            does it cost against a byte copy?
#
# Recorded verdict: findings-s2.md.
set -euo pipefail
cd "$(dirname "$0")"; . ./lib.sh

note "S2 — Mach-O signing walk + clonefile exec"
lab <<'EOF'
set -uo pipefail
W=$PREFIX/work; POD=$W/pod; V=$PREFIX/venv/bin/python
mkdir -p "$PREFIX/logs" "$POD/tmp"

# --- the walk -------------------------------------------------------------
# `file -b` is the Mach-O discriminator (a .so/.dylib extension is neither
# necessary nor sufficient in a wheel tree). codesign -dvvv classifies; the
# ORDER matters: "not signed at all" is checked before `codesign -v`, because a
# universal binary with one unsigned slice reports BOTH and only the -v verdict
# distinguishes it from a wholly unsigned file.
cat > "$W/s2walk.sh" <<'SH'
#!/bin/bash
set -uo pipefail
ROOT="$1"; OUT="$2"; : > "$OUT"
tot=0; macho=0; adhoc=0; ident=0; unsigned=0; invalid=0
while IFS= read -r -d '' f; do
  tot=$((tot+1))
  case "$(/usr/bin/file -b "$f" 2>/dev/null)" in *Mach-O*) ;; *) continue ;; esac
  macho=$((macho+1))
  dv=$(/usr/bin/codesign -dvvv "$f" 2>&1)
  if echo "$dv" | grep -q "code object is not signed at all"; then
    unsigned=$((unsigned+1)); echo "UNSIGNED $f" >> "$OUT"; continue
  fi
  if ! /usr/bin/codesign -v "$f" >/dev/null 2>&1; then
    invalid=$((invalid+1))
    echo "INVALID  $f  [$(/usr/bin/lipo -info "$f" 2>/dev/null | sed 's/.*are: //')]" >> "$OUT"; continue
  fi
  if echo "$dv" | grep -q "Signature=adhoc"; then
    adhoc=$((adhoc+1)); echo "ADHOC    $f" >> "$OUT"
  else
    ident=$((ident+1)); echo "SIGNED   $f  [$(echo "$dv" | grep '^Authority=' | head -1)]" >> "$OUT"
  fi
done < <(find "$ROOT" -type f -print0)
echo "FILES=$tot MACHO=$macho ADHOC_LINKER_SIGNED=$adhoc SIGNED_IDENTITY=$ident UNSIGNED=$unsigned INVALID=$invalid"
SH
chmod +x "$W/s2walk.sh"

echo "### walk — site-packages (the wheel payload)"
"$W/s2walk.sh" "$PREFIX/venv" "$PREFIX/logs/s2-venv.txt"
echo "### walk — the interpreter install (python-build-standalone analog)"
"$W/s2walk.sh" "$PREFIX/pyinstall" "$PREFIX/logs/s2-pyinstall.txt"

echo "### arch — per-slice verdict for every INVALID file"
grep '^INVALID' "$PREFIX/logs/s2-venv.txt" "$PREFIX/logs/s2-pyinstall.txt" 2>/dev/null | while read -r _ f _; do
  echo "  $f"
  /usr/bin/lipo -info "$f" 2>&1 | sed 's/^/    /'
  for a in $(/usr/bin/lipo -archs "$f" 2>/dev/null); do
    if /usr/bin/codesign -v --arch "$a" "$f" >/dev/null 2>&1; then echo "    arch $a: VALID"
    else echo "    arch $a: $(/usr/bin/codesign -v --arch "$a" "$f" 2>&1 | sed 's|.*: ||' | head -1)"; fi
  done
done

echo "### clone — cp -c (clonefile) then exec"
rm -rf "$W/clone"
CS=$(/usr/bin/python3 -c 'import time;print(time.time())')
FB=$(df -k / | tail -1 | awk '{print $4}')
cp -Rc "$PREFIX/venv" "$W/clone"
FA=$(df -k / | tail -1 | awk '{print $4}')
CE=$(/usr/bin/python3 -c 'import time;print(time.time())')
echo "  clone_seconds=$(/usr/bin/python3 -c "print(round($CE-$CS,3))") tree_KB=$(du -sk "$PREFIX/venv" | cut -f1) free_delta_KB=$((FB-FA))"
echo "### clone — signing tally AFTER clonefile (must match the source)"
"$W/s2walk.sh" "$W/clone" "$PREFIX/logs/s2-clone.txt"

MP=$(ls -d "$PREFIX"/hf/hub/models--*Qwen2.5-0.5B*/snapshots/* | head -1)
echo "### clone — exec from the clone, UNSANDBOXED"
( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/bin MODEL_PATH="$MP" \
    HF_HUB_OFFLINE=1 HF_HOME="$PREFIX/hf" "$W/clone/bin/python" "$W/gen.py" 2>&1 ) \
  | grep -E "TOKENS|Error" | tail -1 | sed 's/^/  unsandboxed => /'

echo "### clone — exec from the clone UNDER the S1 Seatbelt profile"
cat > "$PREFIX/sbpl/clone.sb" <<SB
(version 1)
(deny default)
(import "system.sb")
(allow process-exec*)
(allow process-fork)
(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/Library")
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom"))
(allow file-write* (subpath "$POD") (literal "/dev/null"))
(allow iokit-open
  (iokit-registry-entry-class "AGXDeviceUserClient")
  (iokit-registry-entry-class "IOSurfaceRootUserClient"))
(deny file-read* file-write* (subpath "/Users"))
(deny file-read* file-write* (subpath "/private/var/db"))
(allow file-read* (subpath "/private/var/db/dyld"))
(allow file-read* (subpath "$W/clone") (subpath "$PREFIX/pyinstall") (subpath "$PREFIX/hf") (subpath "$W"))
(allow file-read* file-write* (subpath "$POD"))
SB
( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/bin MODEL_PATH="$MP" \
    HF_HUB_OFFLINE=1 HF_HOME="$PREFIX/hf" \
    /usr/bin/sandbox-exec -f "$PREFIX/sbpl/clone.sb" "$W/clone/bin/python" "$W/gen.py" 2>&1 ) \
  | grep -E "TOKENS|Error" | tail -1 | sed 's/^/  sandboxed   => /'

echo "### cow — byte-copy comparison"
rm -rf "$W/copy"
BS=$(/usr/bin/python3 -c 'import time;print(time.time())'); B2=$(df -k / | tail -1 | awk '{print $4}')
cp -R "$PREFIX/venv" "$W/copy"
A2=$(df -k / | tail -1 | awk '{print $4}'); BE=$(/usr/bin/python3 -c 'import time;print(time.time())')
echo "  copy_seconds=$(/usr/bin/python3 -c "print(round($BE-$BS,3))") free_delta_KB=$((B2-A2))"
rm -rf "$W/copy"
EOF
