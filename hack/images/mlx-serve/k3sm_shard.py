# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
"""k3sm-shard: the entrypoint of one rank of a sharded MLXModel.

The k3sm MLX operator renders one Pod per rank and runs this module in each:

    /bin/python3.12 -m k3sm_shard --model <ref> --served-model-name <name> [caller args...]

It does DNS resolution, then runs the engine in this process:

  1. reads the environment the operator rendered (MLX_RANK, MLX_WORLD_SIZE,
     K3SM_MLX_BACKEND, K3SM_MLX_PARALLELISM, K3SM_MLX_RANKS, K3SM_MLX_PORT,
     K3SM_MLX_SERVE_PORT, for jaccl K3SM_MLX_IBV_DEVICES_JSON, and on the
     thunderbolt path K3SM_MLX_HOSTS);
  2. on the network path, resolves every rank's per-pod name under the model's
     headless Service, retrying until all resolve or a bounded deadline passes
     (a peer's record appears only once its Pod has an IP), and takes its OWN
     address from K3SM_POD_IP when the runtime set it. On the thunderbolt path
     K3SM_MLX_HOSTS already names every rank's interconnect address and port
     in rank order, so nothing is resolved; the rank refuses to start unless
     its own entry is K3SM_INTERCONNECT_IP, the address the runtime attached
     to it, because MLX's ring backend binds its own hostfile entry;
  3. writes MLX's rendezvous files into the pod data volume ($TMPDIR, the one
     writable path under the pod's sandbox profile) and nowhere else:
       ring:  MLX_HOSTFILE    -> [["<podIP>:<port>"], ...], one entry per rank
              (the K3SM_MLX_HOSTS entries on the thunderbolt path)
       jaccl: MLX_IBV_DEVICES -> the per-rank RDMA device matrix, plus
              MLX_JACCL_COORDINATOR=<rank 0 podIP>:<port>;
  4. runs mlx_lm.server's own main() in this process with --host 0.0.0.0,
     --port <serve port>, --pipeline for pipeline parallelism, and its own
     arguments passed through last, minus --served-model-name.

The engine runs in the process the pod started, so it is the pod command as
an exec would have made it: SIGTERM and SIGINT are delivered to it directly
(this module installs no handler of its own), a SystemExit or an uncaught
exception from it ends the process as it would end the engine, and the value
its main() returns is the process's exit status (None is 0).

mlx_lm.server has no --served-model-name: it names a model by its --model
value, so a pinned model (whose --model is the snapshot path in the cache
volume) would list that path on /v1/models, and a request naming the model's
repository id would make every rank load that id afresh. The entrypoint takes
the option itself and makes the engine answer to that one name: a request
whose model is the name is served by the model already loaded, and
/v1/models lists the name alone. That needs four hooks in mlx_lm.server
(ModelProvider.load, APIHandler.handle_models_request, run and
_run_http_server), none of them a published API. install_alias checks each
against the shape it was written for, mlx-lm 0.32.2, and the source of run
against the 0.32.2 body its replacement copies; the rank exits naming the hook
that moved instead of serving under the wrong name.

Every rank, with or without that option, also replaces mlx-lm 0.32.2's
_inline_image_urls, which fetches any http(s) image URL in a chat request, with
a function that refuses every image URL that is not a data: URL (HTTP 400).
The original's signature and normalized body hash are checked first, and the
rank exits if either moved.

`k3sm_shard --probe` is the rank-0 liveness probe: it POSTs a one-token
completion to the local server and exits 0 on HTTP 200. A server that is not
listening yet (still downloading or loading weights) also exits 0: the probe
judges a serving gang, never a starting one, so a long first download is not a
kill loop. Anything else (a hung collective, a timeout, an error status)
exits 1.

Standard library only: the image carries the engine's closure and nothing else.
"""

import hashlib
import importlib
import inspect
import io
import json
import os
import socket
import sys
import textwrap
import time
import tokenize
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
ENV_HOSTS = "K3SM_MLX_HOSTS"
ENV_INTERCONNECT_IP = "K3SM_INTERCONNECT_IP"
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

# The option the operator renders for the name the engine serves under, and the
# key mlx_lm.server's ModelProvider maps to its --model.
SERVED_NAME_FLAG = "--served-model-name"
ENGINE_MODULE = "mlx_lm.server"
ENGINE_DEFAULT_MODEL = "default_model"
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


def interconnect_hosts(env, rank, world, port):
    """The thunderbolt path's rank endpoints, or None on the network path.

    K3SM_MLX_HOSTS is "<address>:<port>,..." in rank order. The rank's own entry
    must be exactly K3SM_INTERCONNECT_IP: the ring backend binds it, and an
    address the rank does not hold would fail at bind or, worse, listen on the
    wrong network. Any disagreement ends the rank here, loudly.
    """
    raw = env.get(ENV_HOSTS, "")
    if raw == "":
        return None
    hosts = [h for h in raw.split(",") if h]
    if len(hosts) != world:
        raise ShardError(f"{ENV_HOSTS} names {len(hosts)} ranks, {ENV_WORLD_SIZE} is {world}")
    own = hosts[rank]
    host, sep, own_port = own.rpartition(":")
    if not sep or host == "" or own_port != str(port):
        raise ShardError(f"{ENV_HOSTS} entry {own!r} for rank {rank} is not <address>:{port}")
    mine = env.get(ENV_INTERCONNECT_IP, "")
    if mine == "":
        # The provider started the Pod without its slot-1 address (fallback
        # network) and recorded why in the Pod's k3sm.io/InterconnectAttached
        # condition. The rank must not run unattributed on another address; it
        # ends cleanly, and the operator treats the refusal as an interconnect
        # loss (re-place on pod IPs, or hold under fallback none).
        raise ShardError(f"{ENV_HOSTS} is set but {ENV_INTERCONNECT_IP} is not: this rank holds no interconnect "
                         f"address to bind its hostfile entry {own!r} on; the interconnect attach was refused "
                         f"(see the Pod's k3sm.io/InterconnectAttached condition), exiting so the operator re-places the gang")
    if host != mine:
        raise ShardError(f"{ENV_HOSTS} names {host} for rank {rank}, but this rank's interconnect address "
                         f"({ENV_INTERCONNECT_IP}) is {mine}: it would bind an address it does not hold")
    return hosts


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

    endpoints = interconnect_hosts(env, rank, world, port)
    if endpoints is None:
        known = {}
        if env.get(ENV_POD_IP):
            known[rank] = env[ENV_POD_IP]
        ips = resolve_all(names, resolver, known=known, **resolve_opts)
        endpoints = [_endpoint(ip, port) for ip in ips]

    files = {}
    child_env = dict(env)
    if backend == BACKEND_RING:
        hostfile = os.path.join(state, HOSTFILE_NAME)
        files[hostfile] = json.dumps([[ep] for ep in endpoints])
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
        child_env["MLX_JACCL_COORDINATOR"] = endpoints[0]
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


def split_served_name(argv):
    """Remove every --served-model-name from argv; return (name, the rest).

    The last occurrence wins, as argparse would have it, so a caller argument
    after the operator's own still overrides it. None when absent.
    """
    name = None
    rest = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == SERVED_NAME_FLAG:
            if i + 1 >= len(argv) or argv[i + 1] == "":
                raise ShardError(f"{SERVED_NAME_FLAG} needs a model name")
            name = argv[i + 1]
            i += 2
            continue
        if arg.startswith(SERVED_NAME_FLAG + "="):
            name = arg[len(SERVED_NAME_FLAG) + 1:]
            if name == "":
                raise ShardError(f"{SERVED_NAME_FLAG} needs a model name")
            i += 1
            continue
        rest.append(arg)
        i += 1
    return name, rest


# The hooks install_alias relies on, with the parameters mlx-lm 0.32.2 gives
# them (unchanged from 0.32.0). A hook that is missing or takes other parameters ends the rank.
ENGINE_HOOKS = (
    ("main", ()),
    ("run", ("host", "port", "model_provider", "server_class", "handler_class")),
    ("_run_http_server", ("host", "port", "response_generator", "server_class", "handler_class")),
    ("ModelProvider.load", ("self", "model_path", "adapter_path", "draft_model_path")),
    ("APIHandler.handle_models_request", ("self",)),
    ("APIHandler._set_completion_headers", ("self", "status_code")),
    ("ResponseGenerator", None),
    ("ResponseGenerator.join", ("self",)),
    ("LRUPromptCache", None),
    ("mx.distributed.init", None),
)


# The normalized source of mlx_lm.server.run in mlx-lm 0.32.0 and 0.32.2, which
# install_alias's run copies. A bump that changes run's body must re-derive the
# copy. check_engine_hooks compares it against the engine at pod start (the
# image carries the engine's .py source beside its bytecode), and the
# selftest's staged-tree rung against the engine the image carries.
ENGINE_RUN_SHA256 = "fe245246598aa896f0299795f7fc0f12a05d022f36f9a9b9eae4dfa47590e01a"


def source_shape(func):
    """sha256 of func's source with comments, blank lines and layout removed."""
    try:
        src = textwrap.dedent(inspect.getsource(func))
    except (OSError, TypeError) as e:
        raise ShardError(f"cannot read the source of {ENGINE_MODULE}.{getattr(func, '__name__', func)!s} to check it "
                         f"against the mlx-lm 0.32.2 body it was written against: {e}") from None
    skip = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
            tokenize.ENCODING, tokenize.ENDMARKER}
    toks = [t.string for t in tokenize.generate_tokens(io.StringIO(src).readline) if t.type not in skip]
    return hashlib.sha256(" ".join(toks).encode()).hexdigest()


def check_run_shape(server):
    """Raise ShardError unless server.run is the 0.32.2 body install_alias copies."""
    got = source_shape(server.run)
    if got != ENGINE_RUN_SHA256:
        raise ShardError(f"{ENGINE_MODULE}.run is not the mlx-lm 0.32.2 body the served-name alias copies "
                         f"(source sha256 {got}, pinned {ENGINE_RUN_SHA256}): re-derive install_alias's run from "
                         f"the new source, then pin the new hash in ENGINE_RUN_SHA256")


def check_engine_hooks(server):
    """Raise ShardError naming the first hook the engine module lacks.

    Every hook is checked for its 0.32.2 signature, and then run for the 0.32.2
    body install_alias's run copies: an engine whose run changed underneath
    matching signatures would otherwise be replaced by a stale copy.
    """
    for path, params in ENGINE_HOOKS:
        obj = server
        for part in path.split("."):
            obj = getattr(obj, part, None)
            if obj is None:
                raise ShardError(f"{ENGINE_MODULE} has no {path}; the served-name alias was written against "
                                 f"mlx-lm 0.32.2 and this engine moved it")
        if not callable(obj):
            raise ShardError(f"{ENGINE_MODULE}.{path} is not callable; the served-name alias was written against "
                             f"mlx-lm 0.32.2")
        if params is None:
            continue
        got = tuple(inspect.signature(obj).parameters)
        if got != params:
            raise ShardError(f"{ENGINE_MODULE}.{path} takes {got}; the served-name alias was written against "
                             f"mlx-lm 0.32.2's {params}")
    check_run_shape(server)


def install_alias(server, served):
    """Make the engine module serve its --model under the name served.

    Replaces server.ModelProvider and server.run, which main() looks up when it
    runs. With served None nothing is checked or replaced: the engine is stock
    mlx_lm.server. Returns (provider class, handler class, run) as installed.
    """
    if served is None:
        return server.ModelProvider, server.APIHandler, server.run
    check_engine_hooks(server)

    class AliasedModelProvider(server.ModelProvider):
        """Maps the served name to the model already loaded."""

        def load(self, model_path, adapter_path=None, draft_model_path=None):
            if model_path == served:
                model_path = ENGINE_DEFAULT_MODEL
            return super().load(model_path, adapter_path, draft_model_path)

    class AliasedAPIHandler(server.APIHandler):
        """Lists the served name, and only it, on /v1/models."""

        def handle_models_request(self):
            parts = self.path.split("?", 1)[0].split("/")
            wanted = "/".join(parts[3:]) if len(parts) > 3 else None
            models = []
            if wanted is None or wanted == served:
                models.append({"id": served, "object": "model", "created": self.created})
            self._set_completion_headers(200)
            self.end_headers()
            self.wfile.write(json.dumps({"object": "list", "data": models}).encode())
            self.wfile.flush()

    def run(host, port, model_provider, server_class=None, handler_class=None):
        # mlx_lm.server.run as of 0.32.2, except that it hands the HTTP server
        # the aliased handler: the original takes handler_class and drops it.
        group = server.mx.distributed.init()
        prompt_cache = server.LRUPromptCache(model_provider.cli_args.prompt_cache_size)
        response_generator = server.ResponseGenerator(model_provider, prompt_cache)
        if group.rank() == 0:
            kwargs = {"handler_class": AliasedAPIHandler}
            if server_class is not None:
                kwargs["server_class"] = server_class
            server._run_http_server(host, port, response_generator, **kwargs)
        else:
            response_generator.join()

    server.ModelProvider = AliasedModelProvider
    server.run = run
    return AliasedModelProvider, AliasedAPIHandler, run


# The image-URL fetch in mlx-lm 0.32.2: handle_chat_completions calls
# _inline_image_urls(messages), which urlopen()s every http(s) image URL in a
# request body (30 s timeout, redirects followed, no host check, no size cap)
# and reads the whole response into memory. Anyone who can reach a rank's port
# could make the pod fetch an internal address (the node's own services, the
# cloud-style metadata endpoints of a LAN) or exhaust its memory. The image has
# no use for remote image URLs: a client sends the image inline as a data: URL.
# The replacement refuses everything else before any network call.
IMAGE_HOOK = "_inline_image_urls"
IMAGE_HOOK_PARAMS = ("messages",)
IMAGE_HOOK_SHA256 = "c1cba319c81a30792fd2f587aa741ad7575c5a6b2d3e6889ec25e85a40e572a1"


class RemoteImageRefused(ValueError):
    """A request carried an image URL that is not an inline data: URL."""


def refuse_remote_images(messages):
    """Raise RemoteImageRefused for any image part whose URL is not a data: URL.

    Takes the place of mlx_lm.server._inline_image_urls. It looks at every
    content part that names an image under either key mlx-lm reads, whatever
    its type, so a part mlx-lm would still treat as an image is never skipped.
    The server answers the ValueError with HTTP 400.
    """
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            for key in ("image_url", "image"):
                if key not in part:
                    continue
                url = part[key]
                if isinstance(url, dict):
                    url = url.get("url")
                if not isinstance(url, str) or not url.startswith("data:"):
                    raise RemoteImageRefused("remote image URLs are not fetched by this server; "
                                             "send the image inline as a data: URL")


def install_image_guard(server):
    """Replace the engine's remote image fetch with refuse_remote_images.

    Fail-closed: the engine's function must still take (messages) and have the
    0.32.2 body this was written against; otherwise the rank exits rather than
    serve with a fetch it has not read. Runs for every rank, with or without
    --served-model-name.
    """
    func = getattr(server, IMAGE_HOOK, None)
    if func is None or not callable(func):
        raise ShardError(f"{ENGINE_MODULE} has no {IMAGE_HOOK}; the remote-image guard was written against "
                         f"mlx-lm 0.32.2 and this engine moved it")
    got = tuple(inspect.signature(func).parameters)
    if got != IMAGE_HOOK_PARAMS:
        raise ShardError(f"{ENGINE_MODULE}.{IMAGE_HOOK} takes {got}; the remote-image guard was written "
                         f"against mlx-lm 0.32.2's {IMAGE_HOOK_PARAMS}")
    shape = source_shape(func)
    if shape != IMAGE_HOOK_SHA256:
        raise ShardError(f"{ENGINE_MODULE}.{IMAGE_HOOK} is not the mlx-lm 0.32.2 body the remote-image guard "
                         f"replaces (source sha256 {shape}, pinned {IMAGE_HOOK_SHA256}): read the new source, "
                         f"then pin its hash in IMAGE_HOOK_SHA256")
    setattr(server, IMAGE_HOOK, refuse_remote_images)
    return refuse_remote_images


def serve(child_env, child_argv, served, importer=importlib.import_module):
    """Run the engine in this process: the environment, argv, guard, alias, main()."""
    os.environ.clear()
    os.environ.update(child_env)
    # The engine reads the rendezvous environment when it initialises the
    # distributed group, so it is imported only once that environment is set.
    server = importer(ENGINE_MODULE)
    install_image_guard(server)
    install_alias(server, served)
    sys.argv = [ENGINE_MODULE] + list(child_argv[3:])
    return server.main()


def exit_status(result):
    """The process status for what the engine's main() returned, as sys.exit reads it."""
    if result is None:
        return 0
    if isinstance(result, int) and not isinstance(result, bool):
        return result
    print(f"k3sm-shard: {ENGINE_MODULE} main() returned {result!r}", file=sys.stderr, flush=True)
    return 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ)
    if argv[:1] == ["--probe"]:
        return probe(env)
    try:
        served, argv = split_served_name(argv)
        files, child_env, child_argv = plan(env, argv)
        write_files(files)
        print(f"k3sm-shard: rank {child_env['MLX_RANK']} of {child_env['MLX_WORLD_SIZE']}, "
              f"backend {env[ENV_BACKEND]}, {' '.join(child_argv[2:3])} serving as {served or 'its --model'}",
              file=sys.stderr, flush=True)
    except ShardError as e:
        print(f"k3sm-shard: {e}", file=sys.stderr, flush=True)
        return 2
    try:
        result = serve(child_env, child_argv, served)
    except ShardError as e:
        print(f"k3sm-shard: {e}", file=sys.stderr, flush=True)
        return 2
    return exit_status(result)


if __name__ == "__main__":
    sys.exit(main())
