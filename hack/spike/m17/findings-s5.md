# S5 findings — ring ranks between pods on two Macs (M17.0)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m17/s5.sh`. Rank logs (one
> JSON line per event) are in `$K3SM_EVIDENCE/s5/`; the tokens/s figures are in
> `$K3SM_EVIDENCE/figures.jsonl`.

## Question

Do two `mlx-lm` ranks in pods on the two Macs bind and dial each other's pod IPs over
the `ring` backend, and what tokens/s does a sharded tiny model reach over the direct
path, wireguard over the cable and Wi-Fi, against the same model on one Mac?

## Method

Two pods (one per Mac, pinned by `nodeName`, the MLX guardrail stanza, one
`mlx.k3sm.io/gpu` each, `restartPolicy: Never`) from the `mlx-serve` image, idle until
exec'd; a ConfigMap carries `rank.py`. Per path, both ranks are exec'd at once with a
hostfile of the two pod IPs: `mx.distributed.init(backend="ring")`, an `all_sum` across
the pair, `sharded_load` (tensor parallel, pipeline as the fallback), then a fixed
prompt at `max_tokens` 128, three generations per path. The model is the one the M16
spike and the M17-lab ladder pin, so the single-Mac figure compares across all three.

## Halt (binding, substitutions pre-decided)

| criterion | on failure |
|---|---|
| s5.1 / s5.2 with the 8 GiB worker's rank out of memory | R8: the rung moves the model to the workstation |
| s5.1 / s5.2 otherwise | no substitution is pre-decided: the sharded path of the M17 plan §5 does not hold under the pod network |

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s5.1 both ranks initialise the ring (size 2) and `all_sum` = 2 over the direct path | | |
| s5.2 rank 0 generates from the sharded model over the direct path | | |
| rig: both nodes Ready after the rung | | |

## Figures

| path | tokens/s median | tokens/s p99 | n |
|---|---|---|---|
| ring over the direct path | | | |
| ring over wireguard on the cable | | | |
| ring over Wi-Fi | | | |
| one Mac (server) | | | |
| one Mac (worker) | | | |

| | |
|---|---|
| image digest the tag resolved to | |
| `sharded_load` parallelism | |
| model, revision | `mlx-community/Qwen3-0.6B-4bit` @ `73e3e38d981303bc594367cd910ea6eb48349da8` |

## Consequences recorded here

- Whether ranks bind and dial pod IPs under the shim, which the sharded `MLXModel`'s
  rank pods rely on.
- The tokens/s any page may quote, beside the single-Mac figure — a sharded figure
  below the single-Mac one is published as such (R15).
