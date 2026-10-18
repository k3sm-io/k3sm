# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
"""k3sm-serve: the single-node entrypoint of the mlx-serve image.

    /bin/python3.12 -m k3sm_serve serve --continuous-batching ... <model> [args...]

It runs vllm-mlx's own CLI (vllm_mlx.cli.main) in this process with the same
argv, so the server, its flags and its HTTP surface are vllm-mlx's. Before the
CLI starts it installs one guard on the server module: a request whose prompt
plus completion would not fit the engine's context window is refused with HTTP
400, the way vLLM enforces max_model_len, instead of being served.

Why the guard exists. vllm-mlx 0.5.0 has no max-model-len option and does no
prompt-length validation: its only per-sequence bound is --max-kv-size, which
selects mlx-lm's RotatingKVCache. A sequence that outgrows it evicts its early
tokens and the model answers HTTP 200 with text built on a context it no longer
has (measured: 0/3 recall of a needle even inside the window, on 0.5.0 with
mlx-lm 0.32.0). k3sm renders --max-kv-size from the MLXModel's derived
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

Not covered: /v1/responses and /v1/messages (the guard's contract is the two
OpenAI completion endpoints; a non-streaming /v1/messages request reaches the
engine-level check and is held to the same rule), and image or audio tokens a
multimodal processor adds after the template, which a text tokenizer does not
count.
"""

import logging
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

    def prepare_chat_guarded(engine, request, effective_max_tokens, *args, **kwargs):
        prepared = prepare_chat(engine, request, effective_max_tokens, *args, **kwargs)
        window = window_of(engine)
        chat_kwargs = prepared.chat_kwargs
        max_tokens = chat_kwargs.get("max_tokens", effective_max_tokens)
        if window > 0:
            prompt = chat_prompt(engine, prepared.messages, chat_kwargs, extract_multimodal_content,
                                 convert_tools_for_template)
            prompt_tokens = count_tokens(engine.tokenizer, prompt)
            chat_kwargs["max_tokens"] = refuse(prompt_tokens, max_tokens, window, "/v1/chat/completions")
        else:
            chat_kwargs["max_tokens"] = int(max_tokens)
        return prepared

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
    server.stream_completion = stream_completion_guarded
    engine_cls.generate = generate_guarded
    app.add_exception_handler(ContextRefusal, on_refusal)
    return ContextRefusal


def install_on_engine():
    """Install the guard on the real vllm_mlx server (the image's engine)."""
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
            install_on_engine()
        except GuardError as e:
            print(f"k3sm-serve: {e}", file=sys.stderr, flush=True)
            return 2
        print("k3sm-serve: context guard on /v1/completions and /v1/chat/completions "
              "(window: the engine's --max-kv-size)", file=sys.stderr, flush=True)
    from vllm_mlx import cli

    sys.argv = [ENGINE_CLI] + argv
    cli.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
