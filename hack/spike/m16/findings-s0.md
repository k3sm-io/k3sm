# S0 findings — k3sm preconditions, no framework (M16.0-d1)

> **Status: NOT YET RUN.** This file is the write-back target for
> `hack/spike/m16/s0.sh`; nothing below is a result until a run fills it in, and a
> half-run rung records what it did and did not measure rather than leaving a row
> blank. Re-running the script overwrites rig state under `$PREFIX`; it does not
> rewrite this file.

## Question

Do k3sm's three unproven preconditions hold?

1. **Webhook delivery, both paths.** Does the apiserver reach a *validating* webhook
   **and** a *CRD conversion* webhook, each registered with `clientConfig.service`
   (never `url`) and backed by a `runtimeClassName: vm` pod, and does
   `failurePolicy: Fail` behave? The service ref is the point: kube-apiserver
   v1.36.2 resolves such a webhook through its informer-backed ClusterIP resolver,
   so the dial lands on `ClusterIP:port`, which darwin-net's proxy owns as a lo0
   alias. A `url:` ref would prove something else, and a native backend would never
   exercise the guest leg the fleet's control plane runs on.
2. **Two engines on one GPU.** Do two `vllm-mlx` engines co-reside within a measured
   memory and latency budget, or does the rig thrash?
3. **The dial nobody has measured.** Can a `vm` guest reach a native pod's own
   lo0-alias pod IP, and the reverse?

## Method

Rig-side over ssh, no framework installed. (1) A python TLS webhook server in a
`runtimeClassName: vm` pod behind a ClusterIP Service, registered for both a
`ValidatingWebhookConfiguration` and a CRD conversion strategy, with the allow, the
deny, and the fail-closed case each exercised. (2) Two `vllm-mlx` host processes on
the pinned small model under the **sustained 1 200-token** methodology at
`--max-num-seqs` concurrency, with per-request latency percentiles and wired-memory
sampling against a one-engine control. (3) A native pod listener dialled from a `vm`
guest, and a `vm` guest listener dialled from a native pod.

## Halt (binding, substitutions pre-decided)

| criterion | on failure |
|---|---|
| (1) webhook delivery | R4(a): v1alpha1 only, no conversion in the path |
| (2) two engines | R5's slot floor rises (a smaller model or a larger slot) and S0(2) re-runs; single-slot only if no small model fits two |
| (3) the guest→native dial | R4(b): the native-Darwin control plane per F2 |

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s0.1a admission (allow / deny / backend reviews) | | |
| s0.1a `failurePolicy: Fail` is fail-closed | | |
| s0.1b CRD conversion | | |
| s0.2 two-engine co-residency (aggregate tok/s, p50/p95/p99, wired) | | |
| s0.3 guest → native pod IP | | |
| s0.3 native → guest published IP (recorded) | | |

## Rig

| | |
|---|---|
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`) |
| SoC / memory | |
| macOS | |
| date (UTC) | |
| engine pin | |
| model pin | |

## Consequences recorded here

- If (3) is **open**, the trust-domain fact goes in `docs/user/mlx-fleet.md`: a `vm`
  guest dialing a native pod IP bypasses the Service proxy and the NetworkPolicy L4
  hint, exactly as any same-node process does.
- The slot floor the capacity policy uses comes from (2)'s measurement, not from the
  planning estimate.
