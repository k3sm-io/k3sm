# k3sm System Integration Test (SIT)

> **Internal dev-docs only.** This framing (envtest-plus, the SAFE/UNSAFE fidelity
> table, the `k3sm dev` disposable-cluster loop) is deliberately kept out of
> `k3sm.io` while the public site is stealthed. Do not lift this copy into the
> site or any public README.

## What this is (and what it is NOT)

The SIT is ONE runnable script (`run.sh`) that boots the **whole k3sm stack** —
`apis` + `runtimed` + `darwin-net` + `k3sm` — on a **single node** via the
`k3sm dev` disposable-cluster verb, then runs the cross-component conformance
surface as two privilege tiers — plus a third, short **flagged-boot** leg — and
reports what it proved.

It is **more than envtest** — it boots a **REAL upstream control plane**
(`kube-apiserver` v1.36.2 + `kube-controller-manager` + `kube-scheduler`, which
envtest does not run) + a **real single node** (native-process pods under
Seatbelt via `runtimed`).

It is **NOT kind.** kind is CNCF-conformant ("works on kind ⇒ works on real
k8s"); k3sm is **deliberately non-conformant**, so the runtime surface diverges.
The table below is the load-bearing part — read it before trusting a green.

| Axis | SAFE — faithful, develop freely | NEEDS `--datapath` (root) | UNFAITHFUL — won't reproduce on real k8s |
|---|---|---|---|
| What | the declarative API: CRD schemas, SSA, CEL, admission registration, RBAC/Node authz, scheduling, GC/finalizers/ownerReferences, conditions-driven reconcile **up to Ready**; macOS-native workloads | anything that routes: Service/ClusterIP reachability, cluster DNS, Service-backed admission webhooks, the operator's terminal **Ready/Endpoint** | no SRV/PTR/headless DNS (A-only resolver), NetworkPolicy is a hint not isolation, no cgroup CPU limits / HPA-on-cpu, no EventRecorder (`kubectl describe` is blank), no `metrics.k8s.io`, native-process pods (Linux images need the `vm` RuntimeClass) |
| Tier | T0 rootless (`k3sm dev up`) | T1 root (`sudo k3sm dev up --datapath`) | documented ceiling — neither tier |

The **blessed audience** for the SAFE surface: reconcile-only CRD operators
(CRD-ensure / render / CEL / conditions **up to Ready**) and macOS-native
single-process workloads — e.g. the MLX operator, scoped to its
CRD-ensure/render/CEL/conditions-up-to-Ready half. An operator whose primary
output is a datapath-derived `Ready`/`Endpoint`, or that depends on
Service-backed webhook delivery, needs the `--datapath` tier (a `url`+host-port
webhook works rootless).

This is a **capability register, not a restatement**: it cites, and does not
duplicate, the repo's `docs/conformance-profile.md` (the honest self-assessment)
and the internal full-surface conformance register (the canonical "why k3sm cannot
pass `[Conformance]`" summary). This is **not** a CNCF `[Conformance]`/Sonobuoy
pass.

## The two tiers & the root dependency

The SIT maximises the non-root surface and identifies the residual root
dependencies. Every criterion is classified in [`criteria.env`](criteria.env)
along **two orthogonal root axes** (do not conflate them):

| Tier | Bring-up | sudo? | Root axis it exercises |
|---|---|---|---|
| **T0 rootless** | `k3sm dev up` (`runtimed` + `network=none`) | no | none — Seatbelt self-confines (`sandbox_apply` on the shim's own process); the control-plane, pod-lifecycle, mounts/env/probes, graceful-stop, `DenyUsers`, RBAC, and audit/PSA surfaces all run here |
| **T1 root** | `sudo k3sm dev up --datapath` (`runtimed` + `network=direct`) | yes | the **datapath** (a lo0 `/32` alias, or a `<1024` VIP bind). The **uid-drop** axis (setuid for a foreign `runAsUser`/`fsGroup`) is real but currently claimed by no criterion — see below |
| **T2 psa-enforce** | a dedicated `k3sm server --psa-enforce-baseline` (`hostprocess` + `network=none`) | no | **none** — this leg is separated by a *boot flag*, not by a privilege (see below) |

### T2 — the flagged-boot leg

Some criteria can only be observed against a control plane booted with an
apiserver-config flag the two dev tiers deliberately do **not** pass.
`M10_PSAEnforceCutover` is the case that motivated the leg: its assertion is that
a `hostNetwork` pod is **rejected 403 naming `PodSecurity` baseline** while the
baseline-clean reference pod stays admitted — which is only true under
`--psa-enforce-baseline`. `k3sm dev up` boots the **shipped** default on purpose,
because `M10_PSADefaultWarn` / `M10_AuditLogLevel` assert exactly that default;
the two postures cannot be the same cluster.

So T2 brings up a **second, dedicated control plane** for the length of one
slice, exports the `$KUBECONFIG` + `K3SM_PSA_ENFORCE=1` pair the criteria's own
skip-spec names, runs only the `tier=psa-enforce` criteria, and tears it down.
Three properties are load-bearing:

- **Port-isolated.** Every singleton listener (apiserver, datastore, kubelet API,
  scheduler, controller-manager) is allocated by probe over the same windows
  `k3sm dev` uses, so the leg boots beside a live dev instance or a parallel SIT.
  A second control plane left on the fixed defaults does not fail cleanly — it
  takes the first one's datastore over and comes up *reporting healthy*.
- **Rootless.** The criteria are admission-level (an HTTP status from the
  apiserver), so the leg needs neither a datapath nor root, and runs in **both**
  invocations. It uses `hostprocess` + `network=none` because no pod ever has to
  execute.
- **State-clean, cache-warm.** Its work dir keeps only `bin/` (the control-plane
  download cache) across runs; the datastore, certs and kubeconfig are removed at
  both ends, and the cache is seeded from the dev instance the earlier legs
  already provisioned when one is there.

Two root reasons appear in `criteria.env`:

- **datapath** — `lo0-alias` (even a `≥1024` ClusterIP needs root for its lo0
  *alias*; only `127.0.0.1` binds alias-free on Darwin) or `lt1024-bind`.
  `M3_NodePort`'s `*:port` wildcard bind is itself **rootless** (`≥1024`); its
  reason is its **backend pod's** `lo0-alias`, not `lt1024-bind`.
- **uid-drop** — `setuid-uid-drop`: setuid to a foreign uid, root-only **even
  with the netd helper installed**. Seatbelt self-confinement needs **neither**,
  so `DenyUsers`/profile-integrity is a **rootless** (T0) criterion. **No
  criterion carries this reason today**: since B153 the `k3sm-reject-foreign-user`
  ValidatingAdmissionPolicy is provisioned in every posture, so a pod asking for a
  foreign uid/gid is refused at the API and never reaches a `setuid`.

`M2` criteria were originally validated under the `install`/helper topology; the
SIT runs them under `direct`, which gives the same **datapath** pod-view (real pod
IPs, real ClusterIP) — T1 is the full-posture run.

The two topologies were **not** the same for **admission**, and that gap is what
hid B153: the `k3sm-reject-foreign-user` policy was provisioned only under the
helper backend, so `none` (T0) and `direct` (T1) ran with the object absent and
`M2_FsGroup` was red on real hardware for a reason no criterion field expressed.
It is now provisioned in every posture, which is why that criterion is `rootless`
— an admission rejection needs no root and no datapath.

## Running it

```sh
hack/sit/run.sh          # T0 + T2 (rootless) — CRD/reconcile/isolation surface
sudo hack/sit/run.sh     # T0 + T1 (adds the datapath criteria) + T2
hack/sit/run.sh --plan   # dry: print the leg ladder, each leg's boot argv and
                         # exact -run selector, and the bucket accounting — boots
                         # nothing, builds nothing, runs no test
```

`--plan` is how the wiring is checked without a live host: it walks the same leg
ladder and the same accounting as a real run, so "which leg runs which criteria"
and "is every criterion claimed by some bucket" are answerable off-host.

`run.sh` traps `k3sm dev down --all` on exit and prints a **reclaim-state line**
(`pgrep -f k3sm`, residual lo0 aliases, dev port listeners) after each tier, so a
crash leaves nothing wedged. It is **re-runnable**: `k3sm dev up`'s pre-flight
reclaim self-heals a crashed prior run (stale-pid reap + lo0 flush), so a
`kill -9` mid-flight needs no manual `pkill`/`ifconfig`.

## The bucket honesty contract

The summary partitions every criterion into exactly one bucket — none is
silently passed:

- **proven** — a required criterion that PASSED in a tier that actually ran.
- **tier-red** — a criterion of a leg that RAN and went red. It is neither proven
  nor deferred, and it needs its own bucket so it cannot fall into the
  *unaccounted* residue below and mask a wiring hole with a test failure.
- **root-deferred** — a `tier=root` criterion, deferred when you ran without
  `sudo` (T1 did not run).
- **multi-node-deferred** — a criterion a single node cannot prove
  (`M3_InPodKubectlAndDNSOnWorker`, the `M6_*` HA set) — needs a second Mac.
- **feature-unbuilt-deferred** — the permanent `t.Skip` TODO stubs
  (`M10_PerPodIP`, `M10_Ingress`, and the other unbuilt M10 features). These are
  **excluded from every required-set** — a required permanent-skip would red T1
  forever.
- **unaccounted** — the residue: criteria in the manifest that no bucket claimed.
  It must be **empty**, and a non-empty one is RED. This is what makes the
  partition *total* rather than merely plausible: a criterion classified to a
  tier whose harness leg is never invoked would otherwise vanish from the report
  and the run would still print GREEN — silently dropping the very criterion the
  tier was added to prove.

The per-tier `-run` selector is an **exact anchored alternation** derived from
`criteria.env`, **never** a bare `TestM<n>`: a root criterion has no self-skip,
so a bare selector would execute it under `none`, it would hard-fail, and
`hack/lib/conformance.sh`'s exit-code trap would redden the whole slice.

**Capability-principle is authoritative; the empirical run only cross-checks.** A
rootless-classified criterion that fails T0 — or a root one that passes — is a
**manifest bug to investigate**, never a silent auto-reclassify (that circularity
would launder a vacuous pass). `M1`'s Service/DNS *objects* pass T0 vacuously (the
API objects exist; there is no datapath) — recorded object-only, not a datapath
proof.

## Scope

- **Single node only.** Cross-node mesh/DNS/HA criteria are `multi-node-deferred`
  (they run on a two-Mac rig, `hack/lab/`, not here).
- **A diagnostic, not a milestone gate.** The SIT has **no `phases.json` row**
  (a `manual:false` euid-gated row is unmodeled by the `(manual, skeleton)`
  honesty schema and would let an orchestrator read exit-0-on-T0 as "datapath
  proven"). `hack/sit/` does not match the `m[0-9]*.sh` orphan glob, so
  `phases_test.go` stays green.
