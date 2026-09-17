# S0 findings — k3sm preconditions, no framework (M16.0-d1)

> **Status: RUN 2026-09-17** on the single-node dev Mac named under Rig. Criteria (1)
> and (3) hold; criterion (2) fails on this rig and its pre-decided substitution is
> applied below. Two earlier attempts the same day never reached the measurement
> (an x86_64 venv on a two-Homebrew Mac, then a load client sending a placeholder
> model id); both are fixed in the scripts that produced this run. Re-running the
> script overwrites rig state under `$PREFIX`; it does not rewrite this file.

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
| s0.1a admission (allow / deny / backend reviews) | PASS | the apiserver reached the service-ref webhook on a vm-backed ClusterIP: allow admitted, deny rejected with the webhook's own message, 2 AdmissionReviews in the backend's log |
| s0.1a `failurePolicy: Fail` is fail-closed | PASS | a CREATE was rejected while the webhook Service was unresolvable |
| s0.1b CRD conversion | PASS | a v1alpha1 read of a v1beta1 object was answered by the service-ref conversion webhook (spec.size=4096, 2 ConversionReviews in the backend's log) |
| s0.2 two-engine co-residency (aggregate tok/s, p50/p95/p99, wired) | FAIL | control (1 engine, conc 4, 3 rounds, 1 200 tok): 12/12 ok, 168.1 tok/s, p50 24.9 s, p95 29.7 s, p99 29.7 s, engine RSS 730 MB, wired 429 MB (baseline 429 MB). Two engines (conc 8 across 2, 3 rounds): 24/24 ok, 105.7 tok/s, p50 85.7 s, p95 105.7 s, p99 105.7 s, RSS 104 MB + 502 MB, peak wired 1 139 MB. p99 rose 3.6x and aggregate throughput fell by a third. Per-process GPU accounting not evaluated |
| s0.3 guest → native pod IP | PASS | a vm guest reached the native pod's own lo0-alias pod IP (100.64.0.13:8099) directly |
| s0.3 native → guest published IP (recorded) | BLOCKED | the inbound direction `docs/user/limitations.md` already documents; recorded, not required |

## Rig

| | |
|---|---|
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`) |
| SoC / memory | Apple M2, 8 GiB (Mac14,2); the rig also hosted the control plane and four vm pods during the run |
| macOS | 26.6.2 |
| date (UTC) | 2026-09-17 |
| engine pin | vllm-mlx 0.4.1 on an arm64 CPython 3.12 venv |
| model pin | mlx-community/Qwen3-0.6B-4bit @ 73e3e38d981303bc594367cd910ea6eb48349da8 |

## Consequences recorded here

- If (3) is **open**, the trust-domain fact goes in `docs/user/mlx-fleet.md`: a `vm`
  guest dialing a native pod IP bypasses the Service proxy and the NetworkPolicy L4
  hint, exactly as any same-node process does.
- The slot floor the capacity policy uses comes from (2)'s measurement, not from the
  planning estimate. **Applied substitution (2026-09-17):** the pinned class is already
  the smallest that fits beside the control plane on 8 GiB, so the halt's "single-slot
  only if no small model fits two" arm applies: on an 8 GiB Mac the capacity policy
  starts at ONE engine slot per node. The second engine's 104 MB RSS and the 1 139 MB
  peak wired figure read as paging under memory pressure, so the two-slot question is
  re-measured on a 16 GiB or larger Mac before the floor is fixed for that class.
- (3) is open in the guest→native direction, so the trust-domain sentence goes in
  `docs/user/mlx-fleet.md` when that document is written.
