# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
"""k3sm-shard: the entrypoint of one rank of a sharded MLXModel.

The k3sm MLX operator renders one Pod per rank and runs this module in each:

    /bin/python3.12 -m k3sm_shard --model <ref> [caller args...]

It does DNS resolution and exec, nothing else:

  1. reads the environment the operator rendered (MLX_RANK, MLX_WORLD_SIZE,
     K3SM_MLX_BACKEND, K3SM_MLX_PARALLELISM, K3SM_MLX_RANKS, K3SM_MLX_PORT,
     K3SM_MLX_SERVE_PORT, and for jaccl K3SM_MLX_IBV_DEVICES_JSON);
  2. resolves every rank's per-pod name under the model's headless Service,
     retrying until all resolve or a bounded deadline passes (a peer's record
     appears only once its Pod has an IP), and takes its OWN address from
     K3SM_POD_IP when the runtime set it;
  3. writes MLX's rendezvous files into the pod data volume ($TMPDIR, the one
     writable path under the pod's sandbox profile) and nowhere else:
       ring:  MLX_HOSTFILE    -> [["<podIP>:<port>"], ...], one entry per rank
       jaccl: MLX_IBV_DEVICES -> the per-rank RDMA device matrix, plus
              MLX_JACCL_COORDINATOR=<rank 0 podIP>:<port>;
  4. execs mlx_lm.server with --host 0.0.0.0, --port <serve port>, --pipeline
     for pipeline parallelism, and its own arguments passed through last.

`k3sm_shard --probe` is the rank-0 liveness probe: it POSTs a one-token
completion to the local server and exits 0 on HTTP 200. A server that is not
listening yet (still downloading or loading weights) also exits 0: the probe
judges a serving gang, never a starting one, so a long first download is not a
kill loop. Anything else (a hung collective, a timeout, an error status)
exits 1.

Standard library only: the image carries the engine's closure and nothing else.
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

# The rendezvous and serving contract with the operator's render
# (k3sm/pkg/mlx/render_sharded.go). A rename there is a rename here.
ENV_RANK = "MLX_RANK"
ENV_WORLD_SIZE = "MLX_WORLD_SIZE"
ENV_BACKEND = "K3SM_MLX_BACKEND"
ENV_PARALLELISM = "K3SM_MLX_PARALLELISM"
ENV_RANKS = "K3SM_MLX_RANKS"
ENV_PORT = "K3SM_MLX_PORT"
ENV_SERVE_PORT = "K3SM_MLX_SERVE_PORT"
ENV_IBV_JSON = "K3SM_MLX_IBV_DEVICES_JSON"
ENV_POD_IP = "K3SM_POD_IP"
ENV_DATA_DIR = "TMPDIR"

BACKEND_RING = "ring"
BACKEND_JACCL = "jaccl"
PARALLELISM_PIPELINE = "pipeline"

# How long a rank waits for every peer's name to resolve. Peers are created
# together, but a peer's record exists only once its Pod has an address, and
# a node can take a while to start a Pod. Bounded, so a peer that never comes
# ends this rank (and, through the operator's gang semantics, the gang).
RESOLVE_TIMEOUT_SECONDS = 600.0
RESOLVE_INTERVAL_SECONDS = 2.0

# The liveness probe's own deadline, kept under the Pod's 30 s probe timeout so
# the probe reports a verdict rather than being killed mid-request.
PROBE_TIMEOUT_SECONDS = 25.0

STATE_SUBDIR = "k3sm-shard"
HOSTFILE_NAME = "mlx-hostfile.json"
IBV_DEVICES_NAME = "mlx-ibv-devices.json"


class ShardError(Exception):
    """A rank cannot be started; the message says why."""


def _require(env, name):
    value = env.get(name, "")
    if value == "":
        raise ShardError(f"{name} is not set; this module runs inside a rank Pod rendered by the k3sm MLX operator")
    return value


def _int(env, name):
    raw = _require(env, name)
    try:
        return int(raw)
    except ValueError:
        raise ShardError(f"{name}={raw!r} is not an integer") from None


def system_resolver(name):
    """Return one address for name, preferring IPv4 (pod addresses are)."""
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    if v4:
        return v4[0]
    return infos[0][4][0]


def resolve_all(names, resolver, timeout=RESOLVE_TIMEOUT_SECONDS, interval=RESOLVE_INTERVAL_SECONDS,
                clock=time.monotonic, sleep=time.sleep, known=None):
    """Resolve every name, retrying the unresolved ones until the deadline.

    known maps an index to an address that needs no lookup (the rank's own).
    """
    addrs = dict(known or {})
    deadline = clock() + timeout
    while True:
        last = {}
        for i, name in enumerate(names):
            if i in addrs:
                continue
            try:
                addrs[i] = resolver(name)
            except (OSError, UnicodeError) as e:
                last[name] = str(e)
        if len(addrs) == len(names):
            return [addrs[i] for i in range(len(names))]
        if clock() >= deadline:
            pending = ", ".join(f"{n} ({err})" for n, err in sorted(last.items()))
            raise ShardError(f"rank names did not all resolve within {timeout:.0f}s: {pending}")
        sleep(interval)


def _endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def plan(env, argv, resolver=system_resolver, **resolve_opts):
    """Decide everything this rank does, without doing it.

    Returns (files, child_env, child_argv): files maps an absolute path inside
    the pod data volume to its content.
    """
    rank = _int(env, ENV_RANK)
    world = _int(env, ENV_WORLD_SIZE)
    backend = _require(env, ENV_BACKEND)
    port = _int(env, ENV_PORT)
    serve_port = _int(env, ENV_SERVE_PORT)
    names = [n for n in _require(env, ENV_RANKS).split(",") if n]
    if len(names) != world:
        raise ShardError(f"{ENV_RANKS} names {len(names)} ranks, {ENV_WORLD_SIZE} is {world}")
    if not 0 <= rank < world:
        raise ShardError(f"{ENV_RANK}={rank} is outside 0..{world - 1}")
    if backend not in (BACKEND_RING, BACKEND_JACCL):
        raise ShardError(f"{ENV_BACKEND}={backend!r} is not {BACKEND_RING} or {BACKEND_JACCL}")

    data_dir = env.get(ENV_DATA_DIR, "")
    if not data_dir or not os.path.isabs(data_dir):
        raise ShardError(f"{ENV_DATA_DIR} is unset or relative; the rendezvous files go only into the pod data volume")
    state = os.path.join(data_dir, STATE_SUBDIR)

    known = {}
    if env.get(ENV_POD_IP):
        known[rank] = env[ENV_POD_IP]
    ips = resolve_all(names, resolver, known=known, **resolve_opts)

    files = {}
    child_env = dict(env)
    if backend == BACKEND_RING:
        hostfile = os.path.join(state, HOSTFILE_NAME)
        files[hostfile] = json.dumps([[_endpoint(ip, port)] for ip in ips])
        child_env["MLX_HOSTFILE"] = hostfile
    else:
        raw = _require(env, ENV_IBV_JSON)
        try:
            matrix = json.loads(raw)
        except ValueError as e:
            raise ShardError(f"{ENV_IBV_JSON} is not JSON: {e}") from None
        if not isinstance(matrix, list) or len(matrix) != world or any(
                not isinstance(row, list) or len(row) != world for row in matrix):
            raise ShardError(f"{ENV_IBV_JSON} is not a {world}x{world} device matrix")
        devices = os.path.join(state, IBV_DEVICES_NAME)
        files[devices] = json.dumps(matrix)
        child_env["MLX_IBV_DEVICES"] = devices
        child_env["MLX_JACCL_COORDINATOR"] = _endpoint(ips[0], port)
    child_env["MLX_RANK"] = str(rank)
    child_env["MLX_WORLD_SIZE"] = str(world)

    child_argv = [sys.executable, "-m", "mlx_lm.server", "--host", "0.0.0.0", "--port", str(serve_port)]
    if env.get(ENV_PARALLELISM) == PARALLELISM_PIPELINE:
        child_argv.append("--pipeline")
    child_argv.extend(argv)
    return files, child_env, child_argv


def write_files(files):
    for path, content in files.items():
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)


def probe(env, timeout=PROBE_TIMEOUT_SECONDS):
    """The rank-0 liveness verdict: 0 serving or not yet listening, 1 otherwise."""
    host = env.get(ENV_POD_IP) or "127.0.0.1"
    try:
        port = int(env.get(ENV_SERVE_PORT, ""))
    except ValueError:
        print(f"k3sm-shard --probe: {ENV_SERVE_PORT} is not set", file=sys.stderr)
        return 1
    url = f"http://{_endpoint(host, port)}/v1/completions"
    body = json.dumps({"prompt": "ping", "max_tokens": 1}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return 0
            print(f"k3sm-shard --probe: {url} answered {resp.status}", file=sys.stderr)
            return 1
    except urllib.error.HTTPError as e:
        print(f"k3sm-shard --probe: {url} answered {e.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        if isinstance(e.reason, ConnectionRefusedError):
            return 0  # not listening yet: starting, not hung
        print(f"k3sm-shard --probe: {url}: {e.reason}", file=sys.stderr)
        return 1
    except ConnectionRefusedError:
        return 0
    except (OSError, TimeoutError) as e:
        print(f"k3sm-shard --probe: {url}: {e}", file=sys.stderr)
        return 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ)
    if argv[:1] == ["--probe"]:
        return probe(env)
    try:
        files, child_env, child_argv = plan(env, argv)
        write_files(files)
    except ShardError as e:
        print(f"k3sm-shard: {e}", file=sys.stderr)
        return 2
    print(f"k3sm-shard: rank {child_env['MLX_RANK']} of {child_env['MLX_WORLD_SIZE']}, "
          f"backend {env[ENV_BACKEND]}, exec {' '.join(child_argv[1:4])}", file=sys.stderr, flush=True)
    os.execve(child_argv[0], child_argv, child_env)
    return 0  # not reached


if __name__ == "__main__":
    sys.exit(main())
