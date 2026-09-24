#!/usr/bin/env bash
# M16.0-d2 / S1 — the Darwin build, and an infrastructure-free smoke.
#
# The upstream serving framework (Apache-2.0) keeps macOS as a maintained in-tree
# build target — the build guide covers it, and the python bindings split on
# cfg(not(target_os = "linux")) to drop the CUDA-bearing default features — but it
# publishes NO darwin wheel and runs NO macOS CI. So the one thing this rung is for
# is the risk that reading cannot settle: whether the memory crate's nixl-sys link
# builds on darwin/arm64 at all.
#
# What it answers, in order:
#   s1.1  the toolchain is PINNED, not defaulted — the Rust toolchain and maturin
#         versions are recorded here because a compiled PyO3 extension's behaviour
#         depends on the compiler, not only on the source, and the image build
#         (M16.3) asserts these same two pins before it stages anything.
#   s1.2  the build completes, and the RESOLVED COMMIT is recorded. That sha is the
#         pin the plan's R2 promotes to the first tag containing it; nothing in this
#         repo hard-codes a commit it has not built.
#   s1.3  the built wheel's sha256, and whether the extension arrives
#         linker-ad-hoc-signed — which is what every hack/images/*/walk-verify.sh
#         assumes about a Mach-O it did not sign itself.
#   s1.4  the frontend answers --help, and a frontend plus the in-tree mocker with
#         --discovery-backend file returns tokens for one completion. No etcd, no
#         NATS, no Kubernetes: the point is that the minimum deployment really is
#         two processes and a file.
#
# HALT: if the memory crate / nixl-sys will not build, the worker re-plans on the
# Rust backend contract (which does not pull that crate) BEFORE any build wave
# starts. That substitution is pre-decided; this rung never improvises another.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

RUNG="S1"
QUESTION="Does the upstream serving framework build from source on darwin/arm64 with the CUDA-bearing default features off, and does a frontend plus an in-tree mocker serve a completion with no etcd, no NATS and no Kubernetes?"
METHOD="Rig-side over ssh in the spike prefix: a PINNED Rust toolchain and maturin, a clone at the requested ref with the resolved sha recorded, a release wheel built from the python bindings with default features off, the wheel sha256 and the extension's signature state recorded, then python3 -m dynamo.frontend --help and a frontend plus mocker with --discovery-backend file answering one completion."
HALT="the memory crate / nixl-sys does not build on darwin/arm64 -> the worker re-plans on the Rust backend contract, which does not pull it, BEFORE any build wave starts."

case "${1:-}" in
--plan | --dry-run) spike_plan "$RUNG" "$QUESTION" "$METHOD" "$HALT" ;;
"") ;;
*)
	echo "s1.sh: unknown argument: $1 (try --plan)" >&2
	exit 2
	;;
esac

spike_host

note "S1 — pinned toolchain, darwin build, wheel record, infrastructure-free smoke"
lab <<'EOF'
set -uo pipefail
W="$PREFIX/s1"; mkdir -p "$W"
export UV_CACHE_DIR="$PREFIX/cache" UV_PYTHON_INSTALL_DIR="$PREFIX/pyinstall"
export CARGO_HOME="$PREFIX/cargo" RUSTUP_HOME="$PREFIX/rustup"
export PATH="$CARGO_HOME/bin:$PREFIX/bin:$PATH"

# ---- s1.1 the toolchain, pinned --------------------------------------------------
for t in cmake protoc git curl; do
  command -v "$t" >/dev/null || { verdict FAIL "s1.1 toolchain  $t is not on the rig (brew install cmake protobuf)"; exit 0; }
done
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$PREFIX/bin" sh >/dev/null 2>&1
if ! command -v rustup >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain "$RUST_TOOLCHAIN" >/dev/null 2>&1
fi
rustup toolchain install "$RUST_TOOLCHAIN" >/dev/null 2>&1
rustup default "$RUST_TOOLCHAIN" >/dev/null 2>&1
RUSTC_V=$(rustc --version 2>/dev/null)
case "$RUSTC_V" in
  *"$RUST_TOOLCHAIN"*) verdict PASS "s1.1 toolchain  rustc pinned: $RUSTC_V" ;;
  *) verdict FAIL "s1.1 toolchain  rustc is '$RUSTC_V', not the pinned $RUST_TOOLCHAIN — a wheel built by an unpinned compiler is a different artifact with no assertion to catch it"; exit 0 ;;
esac

spike_venv "$PREFIX/venv-s1" "s1.1 toolchain"
V="$PREFIX/venv-s1/bin/python"
spike_pip "$V" "maturin>=$MATURIN_MIN"
MATURIN_V=$("$PREFIX/venv-s1/bin/maturin" --version 2>/dev/null)
[ -n "$MATURIN_V" ] || { verdict FAIL "s1.1 toolchain  maturin >= $MATURIN_MIN did not install"; exit 0; }
recorded "s1.1 pins: $RUSTC_V | $MATURIN_V | $("$V" -V) | floor MATURIN_MIN=$MATURIN_MIN"

# ---- s1.2 the build, and the commit it pins --------------------------------------
if [ ! -d "$W/src/.git" ]; then
  rm -rf "$W/src"
  git clone --filter=blob:none "$UPSTREAM_REPO" "$W/src" >/dev/null 2>&1 || { verdict FAIL "s1.2 clone  could not clone $UPSTREAM_REPO"; exit 0; }
fi
cd "$W/src" || { verdict FAIL "s1.2 clone  no checkout at $W/src"; exit 0; }
git fetch --all --tags >/dev/null 2>&1
git checkout --quiet "$UPSTREAM_REF" >/dev/null 2>&1 || { verdict FAIL "s1.2 clone  ref $UPSTREAM_REF does not resolve"; exit 0; }
COMMIT=$(git rev-parse HEAD)
DESCRIBE=$(git describe --tags --always 2>/dev/null)
recorded "s1.2 upstream: $UPSTREAM_REPO ref=$UPSTREAM_REF commit=$COMMIT describe=$DESCRIBE — THIS sha is the pin R2 promotes to the first tag containing it"

# The bindings' own Cargo.toml is what drops the CUDA-bearing default features off
# Linux; building the bindings crate is therefore the whole risk surface, and its
# failure mode is the memory crate's nixl-sys link.
cd "$W/src/lib/bindings/python" 2>/dev/null || { verdict FAIL "s1.2 layout  lib/bindings/python is not present at $COMMIT — the build guide's path moved"; exit 0; }
BUILD_LOG="$W/maturin-build.log"
if "$PREFIX/venv-s1/bin/maturin" build --release --out "$W/wheels" > "$BUILD_LOG" 2>&1; then
  verdict PASS "s1.2 build  the python bindings built from source on darwin/arm64 at $COMMIT"
else
  if grep -qiE 'nixl|dynamo-memory|-lstdc\+\+' "$BUILD_LOG"; then
    verdict FAIL "s1.2 build  the memory crate / nixl-sys link failed on darwin/arm64 — the plan's HALT applies: the worker re-plans on the Rust backend contract, which does not pull that crate, BEFORE any build wave. Log: $BUILD_LOG"
  else
    verdict FAIL "s1.2 build  maturin build failed for another reason (tail below); $BUILD_LOG"
  fi
  tail -40 "$BUILD_LOG"
  exit 0
fi

# ---- s1.3 the artifact record ----------------------------------------------------
WHEEL=$(ls -t "$W/wheels"/*.whl 2>/dev/null | head -1)
[ -n "$WHEEL" ] || { verdict FAIL "s1.3 wheel  the build reported success but produced no wheel"; exit 0; }
SHA=$(shasum -a 256 "$WHEEL" | awk '{print $1}')
recorded "s1.3 wheel: $(basename "$WHEEL") sha256=$SHA — a REPRODUCIBILITY RECORD, not provenance: no published darwin wheel exists to pin against"

spike_pip "$V" "$WHEEL"
SO=$("$V" - <<'PY'
import glob, os, sysconfig
sp = sysconfig.get_paths()["purelib"]
hits = glob.glob(os.path.join(sp, "dynamo", "**", "*.so"), recursive=True)
print(hits[0] if hits else "")
PY
)
if [ -n "$SO" ]; then
  if codesign -dv "$SO" >"$W/codesign.txt" 2>&1; then
    SIGKIND=$(grep -iE 'Signature|flags' "$W/codesign.txt" | tr '\n' ' ')
    recorded "s1.3 extension signature: $SO — $SIGKIND (walk-verify.sh assumes a linker ad-hoc signature on a Mach-O it did not sign)"
  else
    recorded "s1.3 extension signature: $SO is UNSIGNED — hack/images/*/walk-verify.sh would refuse it, so the image build must sign it explicitly"
  fi
else
  recorded "s1.3 extension signature: no .so found under the installed package — the binding may be statically linked into the interpreter path"
fi

# ---- s1.4 the infrastructure-free smoke ------------------------------------------
# The frontend and mocker ship in the top-level package, installed FROM THE CLONE
# alongside the wheel s1.2 built. Resolving it by name from the package index pulls
# the index's runtime, which has no darwin wheel, so the smoke would test a sdist
# build instead of the artifact this rung just recorded. Naming the local wheel in
# the same install pins the runtime requirement to it.
spike_pip "$V" "$WHEEL" "$W/src"
if "$V" -m dynamo.frontend --help >"$W/frontend-help.txt" 2>&1; then
  verdict PASS "s1.4 frontend  python3 -m dynamo.frontend --help answers from the darwin build"
else
  verdict FAIL "s1.4 frontend  the frontend module does not run from the darwin build (see $W/frontend-help.txt)"
  tail -20 "$W/frontend-help.txt"; exit 0
fi

mkdir -p "$W/discovery"
nohup "$V" -m dynamo.frontend --discovery-backend file --discovery-path "$W/discovery" \
  --http-port 8111 > "$W/frontend.log" 2>&1 &
FE=$!
nohup "$V" -m dynamo.mocker --discovery-backend file --discovery-path "$W/discovery" \
  --model mock-model > "$W/mocker.log" 2>&1 &
MK=$!
READY=no
for i in $(seq 1 60); do
  curl -fsS -m 3 http://127.0.0.1:8111/v1/models 2>/dev/null | grep -q mock && { READY=yes; break; }
  sleep 2
done
if [ "$READY" = yes ]; then
  OUT=$(curl -fsS -m 60 http://127.0.0.1:8111/v1/chat/completions \
    -H 'content-type: application/json' \
    -d '{"model":"mock-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}' 2>&1)
  case "$OUT" in
    *choices*) verdict PASS "s1.4 smoke  frontend + mocker with --discovery-backend file served a completion: no etcd, no NATS, no Kubernetes" ;;
    *) verdict FAIL "s1.4 smoke  /v1/models answered but the completion did not: $(printf '%s' "$OUT" | head -c 200)" ;;
  esac
else
  verdict FAIL "s1.4 smoke  the file-discovery frontend never listed the mocker's model (see $W/frontend.log, $W/mocker.log)"
  tail -20 "$W/frontend.log" "$W/mocker.log"
fi
kill "$FE" "$MK" 2>/dev/null
EOF

spike_verdict "$RUNG"
