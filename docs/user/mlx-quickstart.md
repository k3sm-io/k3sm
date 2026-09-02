# MLX quickstart

Serve a language model on your Mac's GPU and call it from an OpenAI-compatible client. k3sm models the
workload as an **`MLXModel`** object: you declare the model and the memory it needs, and k3sm renders
the serving workload, its Services, and its weight cache.

> **Requirements:** Apple Silicon (arm64), macOS 26+, a running k3sm cluster ([Quickstart](quickstart.md)),
> and network access to fetch model weights the first time.

## 1. Check the node offers a GPU

k3sm advertises the Mac's GPU as the extended resource `mlx.k3sm.io/gpu`, alongside labels describing the
chip. A node that does not advertise it cannot serve a model, and an `MLXModel` scheduled there stays
Pending.

```sh
kubectl get nodes -L mlx.k3sm.io/chip,mlx.k3sm.io/chip-family,mlx.k3sm.io/memory-gb
kubectl get nodes -o jsonpath='{.items[*].status.allocatable.mlx\.k3sm\.io/gpu}{"\n"}'
```

The count is `1` — a Mac has one integrated GPU — so **one model serves per node at a time**. A second
`MLXModel` on the same Mac stays Pending until the first is deleted, rather than contending for the
same device.

## 2. Apply a model

[`examples/mlxmodel.yaml`](https://github.com/k3sm-io/k3sm/blob/main/examples/mlxmodel.yaml) serves a small pinned model and is the fastest
way to see the path work end to end:

```sh
kubectl apply -f examples/mlxmodel.yaml
```

Three fields in it look optional but are not:

| Field | Why you must set it |
|---|---|
| `runtime.image` | k3sm ships no built-in serving image. Use the published `mlx-serve` image, ideally by digest — the digest for your release is recorded in [the image's build notes](../../hack/images/mlx-serve/README.md). |
| `port` | Must match the image; `mlx-serve` listens on 8000. |
| `cache.storageClassName` | k3sm marks no StorageClass as default, so `local-path` must be named or the cache volume never binds. See [Storage](storage.md). |

`memory` is the other field worth understanding: on Apple Silicon the GPU shares system memory, so this
is both the scheduling constraint and the budget the serving engine's context window is derived from.
More memory buys a longer context; too little is rejected up front with a reason, rather than failing
later on the node.

Pin `revision` to an exact model revision. Leaving it empty means the repository's default branch, which
moves — two replicas started weeks apart would then serve different weights under one object.

Two things follow from how the pin is applied. The serving engine has no option that takes a revision, so
k3sm points it at that revision's directory **inside the cache volume** instead:

- `revision` requires `cache`. Without a cache volume there is no such directory, and the model is
  rejected up front with an `InvalidSpec` reason rather than served from the moving default branch.
- A pinned revision is loaded from the cache, not fetched into it. On a volume that has never held this
  model, leave `revision` empty for the first start (the engine downloads the default branch), or stage
  the weights into the volume yourself — `hack/acceptance/m8.sh` does the latter.

`quantization` is rejected today: the engine has no expression for it, and serving a different variant
than the one asked for would look like success. Name the quantized repository in `model` instead —
`mlx-community/Qwen3-0.6B-4bit` already does.

## 3. Watch it become ready

The first start downloads the weights, which can take a while on a cold cache — unless `revision` is
pinned, in which case they must already be in the volume (above). Read the **conditions**,
not the `PHASE` column — `PHASE` is a one-word summary for humans and loses information:

```sh
kubectl get mlxmodel qwen3-06b -w
kubectl describe mlxmodel qwen3-06b | sed -n '/Conditions/,$p'
kubectl wait --for=condition=Ready mlxmodel/qwen3-06b --timeout=30m
```

The `Ready` condition's `reason` names the state: `Pending` (no replica running yet), `Downloading`
(fetching weights), `Loading` (weights fetched, model loading), `Serving` (ready), `PodFailed` (the
replica died), `ScaledToZero` (you set `replicas: 0`).

There is deliberately no liveness probe on the serving pod: a first start is an unbounded download, and
a probe that killed it would restart the download from zero.

## 4. Call it

When the model is ready, `status.endpoint` carries the in-cluster address:

```sh
kubectl get mlxmodel qwen3-06b -o jsonpath='{.status.endpoint}{"\n"}'
```

The Service VIP is reachable from the Mac itself, so you can call it directly:

```sh
VIP="$(kubectl get svc qwen3-06b -o jsonpath='{.spec.clusterIP}')"

curl -sS "http://$VIP:8000/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{
        "model": "mlx-community/Qwen3-0.6B-4bit",
        "messages": [{"role": "user", "content": "Name three primary colours."}],
        "max_tokens": 64
      }'
```

Any OpenAI-compatible client works — point its base URL at `http://$VIP:8000/v1` and give it any
non-empty API key. Concurrent requests are batched by the server; the number it will batch is derived
from `memory`.

## 5. Delete it

```sh
kubectl delete mlxmodel qwen3-06b
```

That removes the serving workload, both Services, and the cache PVC. The underlying PersistentVolume is
**retained** — the downloaded weights stay on disk until you remove them by hand ([Storage](storage.md)).

## Things to know

- MLX serving runs on the **default native runtime path**. Do not set `runtimeClassName: vm`: the
  serving process needs direct access to the Mac's GPU, and the [`vm` RuntimeClass](vm-runtimeclass.md) isolates a workload from exactly that.
- Because it runs natively, a served model shares the `_k3sm` trust domain with the other native Pods on
  that Mac. Serve **models and code you trust** — see [Limitations](limitations.md).
- Weights never live in the image. They are downloaded on first start into the cache volume, so give
  that volume room for the model you are serving. A pinned `revision` is loaded from that volume rather
  than downloaded into it — see step 2.
- `spec.distributed` is reserved for future multi-node sharded serving and is rejected today. One model
  serves from one node.
- Memory accounting covers the serving process group; the context window is pinned from `memory` so the
  cache cannot grow past the limit mid-generation.
