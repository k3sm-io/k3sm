# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
"""k3sm-serve: the single-node entrypoint of the mlx-serve image.

    /bin/python3.12 -m k3sm_serve serve --continuous-batching ... <model> [args...]

It runs vllm-mlx's own CLI (vllm_mlx.cli.main) in this process with the same
argv, so the server, its flags and its HTTP surface are vllm-mlx's. Before the
CLI starts it installs one guard on the server module: a request whose prompt
plus completion would not fit the engine's context window is refused with HTTP
400, the way vLLM enforces max_model_len, instead of being served. It also
patches the prefill mask of mlx-lm's rotating cache so the cache's attention
sinks stay attended (see The attention sinks, below).

Why the guard exists. vllm-mlx 0.5.0 has no max-model-len option and does no
prompt-length validation: its only per-sequence bound is --max-kv-size, which
selects mlx-lm's RotatingKVCache. A sequence that outgrows it evicts its early
tokens and the model answers HTTP 200 with text built on a context it no longer
has (measured: 0/3 recall of a needle even inside the window, on 0.5.0 with
mlx-lm 0.32.2). k3sm renders --max-kv-size from the MLXModel's derived
context, so that value IS the model's served context, and a request that would
outgrow it is a client error, not a request to serve.

The window is the engine's effective max_kv_size (after argparse, so an
operator's own --max-kv-size in spec.runtime.args wins, as it does for the
cache). With no --max-kv-size the cache does not rotate and nothing is guarded.

The rule, per prompt, with P its token count under the served model's
tokenizer (counted exactly as the engine's scheduler counts it, on the prompt
the engine will run: for chat, after the engine's own chat template) and W the
window:

  * P >= W: refused; no room is left for a generated token.
  * max_tokens set by the client and P + max_tokens > W: refused.
  * max_tokens omitted: the engine's default is clamped to W - P, which is what
    vLLM does (it fills the rest of the window) and what keeps the cache from
    rotating mid-generation.

The refusal body is the OpenAI error object vLLM answers with:

    {"error": {"message": "This model's maximum context length is W tokens. ...",
               "type": "BadRequestError", "param": null, "code": 400}}

Where it hooks, and why there. Every check runs before a response starts, so a
streaming request is refused with a real 400 rather than an empty 200 stream:

  * /v1/chat/completions (streaming or not): around
    server._prepare_chat_completion_invocation, which runs once the engine is
    acquired and before either response path;
  * /v1/messages (streaming or not): around
    server._prepare_anthropic_endpoint_invocation, which the handler calls
    once the engine is acquired and before it builds the StreamingResponse;
  * /v1/responses, streaming: around server._responses_request_to_chat_request,
    the one call the handler makes before it builds the StreamingResponse (the
    stream's first SSE event is written before the engine is reached, so a
    check any later would come after bytes were sent);
  * /v1/responses (streaming or not): around server._prepare_responses_request,
    which builds the engine call's arguments, so an omitted max_tokens is
    clamped on the arguments the engine runs with;
  * /v1/completions, streaming: around server.stream_completion, which the
    handler calls synchronously before it builds the StreamingResponse;
  * /v1/completions, not streaming: around BatchedEngine.generate, the call the
    handler awaits per prompt;
  * server._resolve_request_max_tokens marks whether max_tokens came from the
    client or from the server default, so the rule above can tell them apart,
    and so the engine-level check runs only on a value that no other check has
    already admitted.

Each seam is looked up at install time and a missing one ends the process: an
engine bump that moves a seam fails at pod start, loudly, never by serving
unguarded. The guard needs vllm-mlx's batched engine (the one that applies the
chat template in the engine), which --continuous-batching selects; the image's
ENTRYPOINT always passes it, and this module refuses to serve without it.

Not covered: image or audio tokens a multimodal processor adds after the
template, which a text tokenizer does not count.

The attention sinks. mlx-lm 0.32.2's make_prompt_cache(model, max_kv_size)
builds RotatingKVCache(max_kv_size, keep=4): the first four tokens stay in the
cache as attention sinks however far the window rotates. Its make_mask builds
the multi-token (prefill) mask as a plain sliding window over the cache
columns, so once a chunked prefill has trimmed the cache each query row masks
out the sink columns before it (all four, from the fifth row on) and attends
as many more recent tokens in their place as a decode step would not. Decode
(one token at a time) attends the whole cache, so the defect shows only as
lost recall after a long prompt. patch_rotating_kv_cache replaces make_mask
with one that keeps the sink columns attended and the recent band at
max_kv_size - keep, the mask upstream proposes in ml-explore/mlx-lm#1978. In
this image the cache with sinks is the one vllm-mlx's multimodal scheduler
prefills per request; the text scheduler builds its caches with keep=0, where
the patch leaves the mask unchanged.

The KV geometry clamp. k3sm sizes --max-kv-size W from a fixed per-token KV
cost (pkg/mlx/sizing.go's kvBytesPerToken, 157286 bytes, calibrated on a 3B
model), because the model's config.json is not on disk when the pod is
rendered. The real fp16 cost is 4 x num_hidden_layers x num_key_value_heads x
head_dim bytes per token (Qwen2.5-32B: 262144; Llama-3.3-70B: 327680), so on a
large model W would over-allocate the memory it was sized for. Before the
engine starts, clamp_max_kv_size reads the model's config.json (a local
directory directly; a Hub reference by fetching only config.json with
huggingface_hub.snapshot_download into the cache mlx-lm's loader uses, so the
weight download reuses it; K3SM_MODEL_CONFIG_DIR names a directory to read it
from instead), takes the decoder's geometry (a nested text_config wins;
num_key_value_heads falls back to num_attention_heads, head_dim to
hidden_size // num_attention_heads), and when that cost exceeds the assumed one
(K3SM_KV_BYTES_PER_TOKEN, default 157286) rewrites W to
floor(W x assumed / actual), never below 1024, logging one line. A config it
cannot read, or a missing field, logs one line and leaves W as given: the clamp
never fails the pod. K3SM_KV_GEOMETRY_CLAMP=off disables it. It is
conservative where the cache costs less than fp16 for every layer (a quantized
KV cache, sliding-window layers).
"""

import logging
import os
import sys

ENGINE_CLI = "vllm_mlx.cli"
CONTINUOUS_BATCHING = "--continuous-batching"

ERROR_TYPE = "BadRequestError"
STATUS = 400

log = logging.getLogger("k3sm_serve")


class GuardError(Exception):
    """The guard cannot be installed on this engine; the message says why."""


class ContextLengthExceeded(Exception):
    """A request does not fit the context window; the message is vLLM's."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class RequestedMaxTokens(int):
    """A max_tokens the client sent, not yet checked against the window."""


class DefaultMaxTokens(int):
    """The server's default max_tokens (the client sent none), not yet checked."""


def window_of(engine):
    """The engine's per-sequence context window in tokens, or 0 for none.

    The batched engine keeps --max-kv-size on its scheduler config, the simple
    engine on itself; 0 means the cache does not rotate.
    """
    config = getattr(engine, "_scheduler_config", None)
    value = getattr(config, "max_kv_size", None) if config is not None else None
    if value is None:
        value = getattr(engine, "_max_kv_size", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return 0
    return value


def count_tokens(tokenizer, text):
    """Count text's tokens exactly as vllm-mlx's scheduler encodes a prompt."""
    if hasattr(tokenizer, "encode"):
        return len(tokenizer.encode(text))
    inner = getattr(tokenizer, "tokenizer", None)
    if inner is not None and hasattr(inner, "encode"):
        return len(inner.encode(text))
    raise GuardError(f"tokenizer {type(tokenizer).__name__} has no encode method")


def admit(prompt_tokens, max_tokens, window):
    """Return the max_tokens to run with, or raise ContextLengthExceeded.

    max_tokens is a RequestedMaxTokens (the client's) or a DefaultMaxTokens (the
    server's); a plain int is treated as the client's. The messages are vLLM's
    (serving_engine._validate_input) so a client that handles vLLM's refusal
    handles this one.
    """
    if window <= 0:
        return int(max_tokens)
    if prompt_tokens >= window:
        raise ContextLengthExceeded(
            f"This model's maximum context length is {window} tokens. However, your request has "
            f"{prompt_tokens} input tokens. Please reduce the length of the input messages.")
    room = window - prompt_tokens
    if isinstance(max_tokens, DefaultMaxTokens):
        return min(int(max_tokens), room)
    if prompt_tokens + max_tokens > window:
        raise ContextLengthExceeded(
            f"'max_tokens' or 'max_completion_tokens' is too large: {int(max_tokens)}. This model's "
            f"maximum context length is {window} tokens and your request has {prompt_tokens} input "
            f"tokens ({int(max_tokens)} > {window} - {prompt_tokens}).")
    return int(max_tokens)


def error_body(message):
    """The OpenAI error object vLLM answers a refused request with."""
    return {"error": {"message": message, "type": ERROR_TYPE, "param": None, "code": STATUS}}


def chat_prompt(engine, messages, chat_kwargs, extract_multimodal_content, convert_tools_for_template):
    """The prompt text the batched engine will run for a chat request.

    This is BatchedEngine.chat / stream_chat's own preparation, step for step,
    ending in the engine's own _apply_chat_template, so the count is of the
    exact text the scheduler will tokenize.
    """
    apply = getattr(engine, "_apply_chat_template", None)
    if apply is None:
        raise GuardError(f"engine {type(engine).__name__} does not apply the chat template itself; "
                         f"the guard needs the batched engine ({CONTINUOUS_BATCHING})")
    _, images, _, audios = extract_multimodal_content(messages)
    all_images = list(chat_kwargs.get("images") or []) + list(images)
    tools = chat_kwargs.get("tools")
    template_tools = convert_tools_for_template(tools) if tools else None
    return apply(
        messages,
        template_tools,
        num_images=len(all_images),
        num_audios=len(audios),
        chat_template_kwargs=dict(chat_kwargs.get("chat_template_kwargs") or {}),
        enable_thinking=chat_kwargs.get("enable_thinking"),
    )


SINK_PATCHED = "_k3sm_sink_mask"


def sink_mask(mx, N, offset, window, keep):
    """The prefill mask of a rotating cache that keeps `keep` sink tokens.

    Columns are the cache's: the sinks first, then the most recent tokens in
    temporal order, the N new ones last. Each query row attends the sinks it
    follows and the window - keep most recent tokens up to itself, which is
    what a decode step attends once the cache is full. The formula is the one
    upstream proposes in ml-explore/mlx-lm#1978.
    """
    rinds = mx.arange(offset + N)[None]
    linds = mx.arange(offset, offset + N)[:, None]
    return (linds >= rinds) & ((rinds < keep) | (linds < rinds + window - keep))


def patch_rotating_kv_cache(cache_classes, mx):
    """Keep a RotatingKVCache's sink columns attended in its prefill mask.

    Patches make_mask on each class in place. Only the multi-token mask of a
    cache with sinks (keep > 0) at its own window changes; every other call,
    including an explicit window that differs from the cache size, goes to the
    original. Raises GuardError when a class does not have the make_mask this
    was written against, so an mlx-lm bump that moves it fails at pod start.
    """
    import inspect

    patched = []
    for cls in cache_classes:
        original = getattr(cls, "make_mask", None)
        if original is None or not callable(original):
            raise GuardError(f"{cls.__module__}.{cls.__name__} has no make_mask; the sink patch was written "
                             f"against mlx-lm 0.32.2 and this cache moved it")
        if getattr(original, SINK_PATCHED, False):
            patched.append(cls)
            continue
        params = list(inspect.signature(original).parameters)
        if params != ["self", "N", "window_size", "return_array"]:
            raise GuardError(f"{cls.__module__}.{cls.__name__}.make_mask takes {params}; the sink patch was "
                             f"written against mlx-lm 0.32.2's (self, N, window_size, return_array)")

        def make_mask(self, N, window_size=None, return_array=False, _original=original):
            keep = getattr(self, "keep", 0)
            if N > 1 and keep > 0 and (window_size or self.max_size) == self.max_size:
                offset = min(self.max_size - 1, self.offset)
                if offset + N > self.max_size or return_array:
                    return sink_mask(mx, N, offset, self.max_size, keep)
            return _original(self, N, window_size=window_size, return_array=return_array)

        setattr(make_mask, SINK_PATCHED, True)
        make_mask.__doc__ = original.__doc__
        cls.make_mask = make_mask
        patched.append(cls)
    return patched


def _seam(owner, name):
    value = getattr(owner, name, None)
    if value is None or not callable(value):
        raise GuardError(f"{getattr(owner, '__name__', owner)!s} has no {name}; the context guard was written "
                         f"against vllm-mlx 0.5.0 and this engine moved the seam it hooks")
    return value


def install(server, engine_cls, http_exception, json_response, extract_multimodal_content,
            convert_tools_for_template):
    """Install the guard on a vllm_mlx.server module. Returns the refusal class.

    Every collaborator is a parameter so the guard can be exercised against
    fakes; main() passes the real ones.
    """
    resolve = _seam(server, "_resolve_request_max_tokens")
    prepare_chat = _seam(server, "_prepare_chat_completion_invocation")
    prepare_anthropic = _seam(server, "_prepare_anthropic_endpoint_invocation")
    to_chat_request = _seam(server, "_responses_request_to_chat_request")
    prepare_responses = _seam(server, "_prepare_responses_request")
    stream_completion = _seam(server, "stream_completion")
    generate = _seam(engine_cls, "generate")
    app = getattr(server, "app", None)
    if app is None or not hasattr(app, "add_exception_handler"):
        raise GuardError("the server module has no app to register the refusal on")

    class ContextRefusal(http_exception):
        """HTTP 400 for a request that does not fit the context window."""

        def __init__(self, message):
            super().__init__(status_code=STATUS, detail=message)

    def refuse(prompt_tokens, max_tokens, window, where):
        try:
            return admit(prompt_tokens, max_tokens, window)
        except ContextLengthExceeded as e:
            log.info("k3sm-serve: refused %s: %d prompt tokens, max_tokens %d, window %d",
                     where, prompt_tokens, int(max_tokens), window)
            raise ContextRefusal(e.message) from None

    def resolve_marked(requested_value):
        value = resolve(requested_value)
        return DefaultMaxTokens(value) if requested_value is None else RequestedMaxTokens(value)

    def guard_chat(engine, messages, chat_kwargs, max_tokens, where):
        """Check a prepared chat call and set the max_tokens it runs with."""
        window = window_of(engine)
        if window > 0:
            prompt = chat_prompt(engine, messages, chat_kwargs, extract_multimodal_content,
                                 convert_tools_for_template)
            prompt_tokens = count_tokens(engine.tokenizer, prompt)
            chat_kwargs["max_tokens"] = refuse(prompt_tokens, max_tokens, window, where)
        else:
            chat_kwargs["max_tokens"] = int(max_tokens)

    def prepare_chat_guarded(engine, request, effective_max_tokens, *args, **kwargs):
        prepared = prepare_chat(engine, request, effective_max_tokens, *args, **kwargs)
        guard_chat(engine, prepared.messages, prepared.chat_kwargs,
                   prepared.chat_kwargs.get("max_tokens", effective_max_tokens), "/v1/chat/completions")
        return prepared

    def prepare_anthropic_guarded(engine, openai_request, effective_max_tokens, *args, **kwargs):
        prepared = prepare_anthropic(engine, openai_request, effective_max_tokens, *args, **kwargs)
        guard_chat(engine, prepared.messages, prepared.chat_kwargs,
                   prepared.chat_kwargs.get("max_tokens", effective_max_tokens), "/v1/messages")
        return prepared

    # The Responses path builds its engine arguments in _prepare_responses_request,
    # which calls _responses_request_to_chat_request itself. The streaming
    # handler calls the conversion alone before it starts the stream, so the
    # conversion runs the guarded preparation when it is called from outside
    # it. Both are synchronous, so a plain depth count cannot interleave with
    # another request.
    depth = [0]

    def prepare_responses_guarded(request, *args, **kwargs):
        depth[0] += 1
        try:
            engine, chat_request, messages, chat_kwargs = prepare_responses(request, *args, **kwargs)
        finally:
            depth[0] -= 1
        requested = chat_request.max_tokens
        max_tokens = chat_kwargs.get("max_tokens")
        max_tokens = RequestedMaxTokens(max_tokens) if requested else DefaultMaxTokens(max_tokens)
        guard_chat(engine, messages, chat_kwargs, max_tokens, "/v1/responses")
        return engine, chat_request, messages, chat_kwargs

    def to_chat_request_guarded(request, *args, **kwargs):
        if depth[0] == 0:
            prepare_responses_guarded(request, validate_remote_media=False)
        return to_chat_request(request, *args, **kwargs)

    def stream_completion_guarded(engine, prompt, request, max_tokens, *args, **kwargs):
        window = window_of(engine)
        if window > 0 and isinstance(prompt, str):
            max_tokens = refuse(count_tokens(engine.tokenizer, prompt), max_tokens, window,
                                "/v1/completions (stream)")
        return stream_completion(engine, prompt, request, int(max_tokens), *args, **kwargs)

    async def generate_guarded(self, *args, **kwargs):
        max_tokens = kwargs.get("max_tokens")
        prompt = kwargs.get("prompt", args[0] if args else None)
        if isinstance(max_tokens, (RequestedMaxTokens, DefaultMaxTokens)):
            window = window_of(self)
            if window > 0 and isinstance(prompt, str):
                kwargs["max_tokens"] = refuse(count_tokens(self.tokenizer, prompt), max_tokens, window,
                                              "engine.generate")
            else:
                kwargs["max_tokens"] = int(max_tokens)
        return await generate(self, *args, **kwargs)

    async def on_refusal(request, exc):
        return json_response(status_code=STATUS, content=error_body(exc.detail))

    server._resolve_request_max_tokens = resolve_marked
    server._prepare_chat_completion_invocation = prepare_chat_guarded
    server._prepare_anthropic_endpoint_invocation = prepare_anthropic_guarded
    server._prepare_responses_request = prepare_responses_guarded
    server._responses_request_to_chat_request = to_chat_request_guarded
    server.stream_completion = stream_completion_guarded
    engine_cls.generate = generate_guarded
    app.add_exception_handler(ContextRefusal, on_refusal)
    return ContextRefusal


KV_CLAMP_ENV = "K3SM_KV_GEOMETRY_CLAMP"
KV_ASSUMED_ENV = "K3SM_KV_BYTES_PER_TOKEN"
MODEL_CONFIG_DIR_ENV = "K3SM_MODEL_CONFIG_DIR"
MAX_KV_SIZE = "--max-kv-size"
# pkg/mlx/sizing.go's kvBytesPerToken: the per-token KV cost the operator sized
# --max-kv-size with. K3SM_KV_BYTES_PER_TOKEN overrides it.
DEFAULT_KV_BYTES_PER_TOKEN = 157_286
MIN_CLAMPED_KV_SIZE = 1024


class KVGeometryUnknown(Exception):
    """The model's KV geometry could not be read; the message says why."""


def engine_serve_args(argv):
    """(model, max_kv_size) as vllm-mlx's own serve parser reads argv.

    Uses vllm_mlx.cli.create_parser, so the positional model and the final
    --max-kv-size (argparse takes the last occurrence, and accepts an
    abbreviation) are the ones the engine will run with. A parse error is
    left for the engine's own parse to report.
    """
    import contextlib
    import io

    try:
        from vllm_mlx.cli import create_parser
    except ImportError:
        return None, None

    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            args, _ = create_parser().parse_known_args(argv)
    except SystemExit:
        return None, None
    return getattr(args, "model", None), getattr(args, "max_kv_size", None)


def model_config(model, environ):
    """The model's config.json as a dict.

    K3SM_MODEL_CONFIG_DIR, when set, names the directory to read it from (the
    selftest's seam, and a way to point at a staged config). Otherwise a model
    reference that exists on disk is a local directory, read directly, as
    mlx-lm's _download treats it; any other reference is a Hub repository, and
    only its config.json is fetched with huggingface_hub.snapshot_download
    into the default cache, which is the call and the cache mlx-lm's load
    (the engine's loader) downloads the weights with, so that later download
    reuses this file.
    """
    import json
    from pathlib import Path

    override = environ.get(MODEL_CONFIG_DIR_ENV)
    if override:
        directory = Path(override)
    elif Path(model).exists():
        directory = Path(model)
    elif environ.get("MLXLM_USE_MODELSCOPE", "False").lower() == "true":
        raise KVGeometryUnknown("MLXLM_USE_MODELSCOPE is set; only a local model directory is read")
    else:
        try:
            from huggingface_hub import snapshot_download

            directory = Path(snapshot_download(model, allow_patterns=["config.json"]))
        except Exception as e:  # any Hub failure leaves the pin alone; never fail the pod over it
            raise KVGeometryUnknown(f"fetch config.json for {model}: {e}") from None
    path = directory / "config.json"
    try:
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, ValueError) as e:
        raise KVGeometryUnknown(f"read {path}: {e}") from None
    if not isinstance(config, dict):
        raise KVGeometryUnknown(f"{path} is not a JSON object")
    return config


def _positive_int(config, key):
    value = config.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def kv_geometry(config):
    """(layers, kv_heads, head_dim) of the model's text decoder.

    A multimodal config nests the decoder under text_config; its fields win
    over the top level's. num_key_value_heads falls back to
    num_attention_heads and head_dim to hidden_size // num_attention_heads,
    the defaults mlx-lm's models apply.
    """
    merged = dict(config)
    text = config.get("text_config")
    if isinstance(text, dict):
        merged.update(text)
    layers = _positive_int(merged, "num_hidden_layers")
    heads = _positive_int(merged, "num_attention_heads")
    kv_heads = _positive_int(merged, "num_key_value_heads") or heads
    head_dim = _positive_int(merged, "head_dim")
    if head_dim is None:
        hidden = _positive_int(merged, "hidden_size")
        if hidden and heads and hidden % heads == 0:
            head_dim = hidden // heads
    missing = [name for name, value in (("num_hidden_layers", layers), ("num_key_value_heads", kv_heads),
                                        ("head_dim", head_dim)) if value is None]
    if missing:
        raise KVGeometryUnknown("config.json has no usable " + ", ".join(missing))
    return layers, kv_heads, head_dim


def kv_bytes_per_token(layers, kv_heads, head_dim):
    """The fp16 KV cache's bytes per token: a key and a value, 2 bytes each."""
    return 4 * layers * kv_heads * head_dim


def _set_max_kv_size(argv, value, parse):
    out = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == MAX_KV_SIZE and i + 1 < len(argv):
            out += [token, str(value)]
            i += 2
            continue
        if token.startswith(MAX_KV_SIZE + "="):
            token = f"{MAX_KV_SIZE}={value}"
        out.append(token)
        i += 1
    if parse(out)[1] != value:
        out += [MAX_KV_SIZE, str(value)]
    return out


def clamp_max_kv_size(argv, environ, parse=None, load_config=None, say=None):
    """Return argv with --max-kv-size clamped to the model's KV geometry.

    The operator sizes --max-kv-size W from a fixed per-token KV cost (the
    assumed figure, K3SM_KV_BYTES_PER_TOKEN); a model whose own cost is higher
    would outgrow the memory W was sized for. When it is, W becomes
    floor(W x assumed / actual), never below 1024 and never above W. Any
    failure to read the geometry leaves argv unchanged with one line said;
    K3SM_KV_GEOMETRY_CLAMP=off disables the clamp. parse, load_config and say
    default to engine_serve_args, model_config and a line on stderr.
    """
    parse = parse or engine_serve_args
    load_config = load_config or model_config
    say = say or (lambda line: print(line, file=sys.stderr, flush=True))
    model, window = parse(argv)
    if not isinstance(window, int) or window <= 0:
        return argv
    if environ.get(KV_CLAMP_ENV, "").strip().lower() == "off":
        say(f"k3sm-serve: {KV_CLAMP_ENV}=off; --max-kv-size {window} left as given")
        return argv
    raw = environ.get(KV_ASSUMED_ENV, "").strip()
    try:
        assumed = int(raw) if raw else DEFAULT_KV_BYTES_PER_TOKEN
        if assumed <= 0:
            raise ValueError(raw)
    except ValueError:
        say(f"k3sm-serve: {KV_ASSUMED_ENV}={raw!r} is not a positive integer; --max-kv-size {window} left as given")
        return argv
    if not model:
        say(f"k3sm-serve: no single model in argv; --max-kv-size {window} left as given")
        return argv
    try:
        layers, kv_heads, head_dim = kv_geometry(load_config(model, environ))
    except KVGeometryUnknown as e:
        say(f"k3sm-serve: KV geometry of {model} unknown ({e}); --max-kv-size {window} left as given")
        return argv
    actual = kv_bytes_per_token(layers, kv_heads, head_dim)
    if actual <= assumed:
        return argv
    clamped = min(window, max(MIN_CLAMPED_KV_SIZE, window * assumed // actual))
    if clamped >= window:
        return argv
    say(f"k3sm-serve: --max-kv-size {window} clamped to {clamped}: {model} has {layers} layers x {kv_heads} KV "
        f"heads x head_dim {head_dim} = {actual} KV bytes per token, above the {assumed} it was sized with")
    return _set_max_kv_size(argv, clamped, parse)


HF_HOME_ENV = "HF_HOME"
HUB_DIR = "hub"
REPO_FOLDER_PREFIX = "models--"
SNAPSHOTS_DIR = "snapshots"


class SeedError(Exception):
    """A pinned revision could not be put in the cache; the message says why."""


def pinned_snapshot(model, environ):
    """(repo_id, revision, hub) when model is a pinned snapshot path, else None.

    k3sm renders a pinned revision as <HF_HOME>/hub/models--<repo>/snapshots/<rev>
    (pkg/mlx modelReference), because the engine has no revision option. The
    repository id is the folder name with the prefix dropped and "--" turned
    back into "/", the inverse of the Hub cache's own naming; a repository id
    cannot contain "--", so the inverse is exact. Any other model reference,
    including a path outside HF_HOME's hub cache, is not k3sm's pin and is
    left alone.
    """
    home = environ.get(HF_HOME_ENV, "")
    if not model or not home:
        return None
    hub = os.path.normpath(os.path.join(home, HUB_DIR))
    path = os.path.normpath(model)
    snapshots, revision = os.path.split(path)
    folder_path, snapshots_name = os.path.split(snapshots)
    parent, folder = os.path.split(folder_path)
    if snapshots_name != SNAPSHOTS_DIR or parent != hub or not folder.startswith(REPO_FOLDER_PREFIX):
        return None
    repo_id = folder[len(REPO_FOLDER_PREFIX):].replace("--", "/")
    if not repo_id or not revision:
        return None
    return repo_id, revision, hub


def _hub_download(repo_id, revision, cache_dir):
    from huggingface_hub import snapshot_download

    return snapshot_download(repo_id, revision=revision, cache_dir=cache_dir)


def seed_pinned_revision(argv, environ, parse=None, download=None, say=None):
    """Fetch a pinned revision into the cache volume before the engine loads it.

    The engine loads a pinned snapshot path; it never fetches one. So when the
    model is k3sm's pinned path, the revision is fetched here with
    huggingface_hub.snapshot_download into the hub cache that path lives in,
    which lands it at exactly that path. The fetch runs on every start: on a
    complete snapshot it moves no weights, and it finishes a snapshot an
    earlier start left half-written. If the fetch fails and the snapshot is
    already on the volume (a restart with no network), the engine is started
    on it with one line said; if the snapshot is not there, SeedError, so the
    pod fails at start naming the revision. A revision the Hub resolves to a
    different commit (a branch or tag name) is refused: the pin is the commit.

    The cache directory is taken relative to the working directory when the
    mount point is materialized there, as a native pod's volume mount is: the
    path-rebase shim rewrites the mounted prefix, and the Hub client resolves
    /var to /private/var before it creates directories, which would leave the
    prefix behind. Elsewhere the absolute path is used.
    """
    parse = parse or engine_serve_args
    download = download or _hub_download
    say = say or (lambda line: print(line, file=sys.stderr, flush=True))
    model, _ = parse(argv)
    pin = pinned_snapshot(model, environ)
    if pin is None:
        return
    repo_id, revision, hub = pin
    mount = "." + os.path.dirname(os.path.normpath(environ[HF_HOME_ENV]))
    local = os.path.isdir(mount)
    cache_dir = "." + hub if local else hub
    snapshot = "." + os.path.normpath(model) if local else os.path.normpath(model)
    try:
        landed = download(repo_id, revision, cache_dir)
    except Exception as e:  # any Hub failure: serve a staged snapshot, else refuse
        if os.path.isdir(snapshot):
            say(f"k3sm-serve: fetch {repo_id} at {revision} failed ({e}); serving the snapshot already in the cache")
            return
        raise SeedError(f"fetch {repo_id} at revision {revision} into {hub}: {e}") from None
    if os.path.basename(os.path.normpath(str(landed))) != revision or not os.path.isdir(snapshot):
        raise SeedError(f"revision {revision} of {repo_id} resolved to {os.path.basename(str(landed))}; "
                        "pin the full commit hash, a branch or tag name moves")
    say(f"k3sm-serve: {repo_id} at revision {revision} is in the cache")


def rotating_cache_classes():
    """The RotatingKVCache classes the image's engine builds caches from.

    mlx-lm's is required; mlx-vlm carries its own copy of the same class (and
    of the same make_mask), patched too when it is installed.
    """
    from mlx_lm.models.cache import RotatingKVCache

    classes = [RotatingKVCache]
    try:
        from mlx_vlm.models.cache import RotatingKVCache as VLMRotatingKVCache
    except ImportError:
        return classes
    if VLMRotatingKVCache is not RotatingKVCache:
        classes.append(VLMRotatingKVCache)
    return classes


def install_on_engine():
    """Install the sink patch and the guard on the real engine, before it loads."""
    import mlx.core as mx

    patch_rotating_kv_cache(rotating_cache_classes(), mx)

    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from vllm_mlx import server
    from vllm_mlx.api.tool_calling import convert_tools_for_template
    from vllm_mlx.api.utils import extract_multimodal_content
    from vllm_mlx.engine.batched import BatchedEngine

    return install(server, BatchedEngine, HTTPException, JSONResponse, extract_multimodal_content,
                   convert_tools_for_template)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["serve"]:
        if CONTINUOUS_BATCHING not in argv:
            print(f"k3sm-serve: {CONTINUOUS_BATCHING} is required: the context guard runs on the batched engine, "
                  "and without it the engine serves one request at a time", file=sys.stderr, flush=True)
            return 2
        try:
            seed_pinned_revision(argv, os.environ)
        except SeedError as e:
            print(f"k3sm-serve: {e}", file=sys.stderr, flush=True)
            return 2
        argv = clamp_max_kv_size(argv, os.environ)
        try:
            install_on_engine()
        except GuardError as e:
            print(f"k3sm-serve: {e}", file=sys.stderr, flush=True)
            return 2
        print("k3sm-serve: context guard on /v1/completions, /v1/chat/completions, /v1/messages and "
              "/v1/responses (window: the engine's --max-kv-size); RotatingKVCache sink mask patched",
              file=sys.stderr, flush=True)
    from vllm_mlx import cli

    sys.argv = [ENGINE_CLI] + argv
    cli.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
