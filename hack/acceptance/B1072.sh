#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The sharded-rank entrypoint exits with the engine's status, and refuses an
# engine whose run is not the body its served-name alias copies.
#
# --check runs hack/images/mlx-serve/k3sm_shard.py as `python3 -m k3sm_shard`,
# a one-rank ring gang, against a stub mlx_lm.server put first on PYTHONPATH
# (the module seam: serve() imports the engine by name). The stub has every
# hook the alias checks, with mlx-lm 0.32.0's signatures, and a run whose body
# is not 0.32.0's.
#   status.return   main() returning 3 makes the process exit 3
#   status.exit     main() raising SystemExit(4) makes the process exit 4
#   status.clean    main() returning None makes the process exit 0
#   runshape        with --served-model-name, the changed run is refused at
#                   start (exit 2, naming ENGINE_RUN_SHA256), and main() never runs
# Then py_compile over the module and the module's own selftest driver, which
# needs no staged tree for its entrypoint rung.
#
# Usage: hack/acceptance/B1072.sh --check [<k3sm_shard.py>]
#   The optional path checks another copy of the module (a red-before proof).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

[ "${1:-}" = "--check" ] && [ $# -le 2 ] || { echo "usage: $0 --check [<k3sm_shard.py>]" >&2; exit 2; }
MODULE="${2:-$K3SM_ROOT/hack/images/mlx-serve/k3sm_shard.py}"
[ -f "$MODULE" ] || { echo "B1072: FAIL: no module at $MODULE"; exit 1; }
command -v python3 >/dev/null || { echo "B1072: FAIL: python3 is not on PATH"; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/b1072.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/lib/mlx_lm" "$WORK/podvol"
cp "$MODULE" "$WORK/lib/k3sm_shard.py"
: > "$WORK/lib/mlx_lm/__init__.py"
cat > "$WORK/lib/mlx_lm/server.py" <<'PY'
"""A stand-in for mlx_lm.server: 0.32.0's hook signatures, not its run body."""
import os
import sys
import types


class ModelProvider:
    def load(self, model_path, adapter_path=None, draft_model_path=None):
        return None


class APIHandler:
    def handle_models_request(self):
        pass

    def _set_completion_headers(self, status_code):
        pass


class ResponseGenerator:
    def join(self):
        pass


def LRUPromptCache(size):
    return size


mx = types.SimpleNamespace(distributed=types.SimpleNamespace(init=lambda: None))


def run(host, port, model_provider, server_class=None, handler_class=None):
    return "not the mlx-lm 0.32.0 body"


def _run_http_server(host, port, response_generator, server_class=None, handler_class=None):
    pass


def main():
    with open(os.environ["B1072_MARK"], "w") as f:
        f.write("main ran\n")
    mode = os.environ["B1072_MODE"]
    if mode == "return":
        return 3
    if mode == "exit":
        sys.exit(4)
    return None
PY

fail=0
# rank <mode> <expected exit> <label> [caller args...]: runs one rank, records
# its exit status and stderr.
rank() {
	local mode="$1" want="$2" label="$3"; shift 3
	rm -f "$WORK/mark"
	set +e
	env -i PATH="$PATH" PYTHONPATH="$WORK/lib" PYTHONDONTWRITEBYTECODE=1 \
		MLX_RANK=0 MLX_WORLD_SIZE=1 K3SM_MLX_BACKEND=ring K3SM_MLX_PARALLELISM=tensor \
		K3SM_MLX_RANKS=m-rank-0.m-headless.ns.svc K3SM_MLX_PORT=29500 K3SM_MLX_SERVE_PORT=8000 \
		K3SM_POD_IP=127.0.0.1 TMPDIR="$WORK/podvol" B1072_MODE="$mode" B1072_MARK="$WORK/mark" \
		python3 -m k3sm_shard --model /snap "$@" 2>"$WORK/err"
	got=$?
	set -e
	if [ "$got" = "$want" ]; then
		echo "ok $label (exit $got)"
	else
		echo "no $label (exit $got, want $want)"; sed 's/^/    /' "$WORK/err"; fail=1
	fi
}

rank return 3 "status.return  an engine main() returning 3 exits 3"
rank exit 4 "status.exit  an engine main() raising SystemExit(4) exits 4"
rank clean 0 "status.clean  an engine main() returning None exits 0"
rank return 2 "runshape  a changed run is refused at start" --served-model-name org/m
if grep -q "ENGINE_RUN_SHA256" "$WORK/err" && grep -q "re-derive" "$WORK/err"; then
	echo "ok runshape.message  the refusal names ENGINE_RUN_SHA256 and the re-derive step"
else
	echo "no runshape.message  the refusal does not name ENGINE_RUN_SHA256"; sed 's/^/    /' "$WORK/err"; fail=1
fi
if [ -e "$WORK/mark" ]; then
	echo "no runshape.norun  the engine main() ran despite the changed run"; fail=1
else
	echo "ok runshape.norun  the engine main() never ran"
fi

python3 -m py_compile "$WORK/lib/k3sm_shard.py" || { echo "B1072: FAIL: py_compile"; exit 1; }

# The module's own entrypoint rung (7.*) needs no staged tree; run the selftest
# only against the checkout, whose selftest pins the stand-in engine's run.
if [ $# -eq 1 ]; then
	out="$(bash "$K3SM_ROOT/hack/images/mlx-serve/selftest.sh" 2>&1)" || {
		printf '%s\n' "$out" | grep -E '^FAIL ' | head -40; echo "B1072: FAIL: mlx-serve selftest"; exit 1; }
	printf '%s\n' "$out" | grep -E '^PASS  7\.(alias\.runshape|serve|count) '
fi

[ "$fail" -eq 0 ] || { echo "B1072: FAIL"; exit 1; }
echo "B1072: PASS"
