# S2 findings — the control plane on k3sm, GPU-free (M16.0-d3)

> **Status: RUN 2026-09-24** on the M16 rig named under Rig, at upstream digests (the
> plan's R12 interim: the mirror push has not happened, so the chart came from the
> upstream registry by digest). Exit **1** (0 passed, 1 failed, 1 recorded) after
> 10m06s, inside the 40-minute kill, which did not fire. The one failure is s2.1: the
> operator Deployment never created a Pod, because the rung patches the pod specs onto
> the darwin node only AFTER `helm upgrade --install --wait` returns, and the cluster's
> admission policy rejects every Pod that does not select `kubernetes.io/os=darwin`, so
> the wait can only end in the Deployment's progress deadline. No later criterion ran.
> The plan's HALT (discovery or the frontend-to-worker dial fails, then R4(b)) was
> **not reached**: the rung never got as far as the question it exists to answer, so
> no substitution is landed here. Re-running the script overwrites rig state under
> `$PREFIX`; it does not rewrite this file.

## Question

Does the upstream serving control plane install and run on k3sm with its operator and
frontend as `vm` Pods, no etcd and no NATS, with Kubernetes-native discovery, live CRD
conversion, and a completion served through the frontend's ClusterIP?

## Method

Rig-side over ssh: `helm upgrade --install` of the digest-pinned chart with etcd and
NATS off and kubernetes discovery on, the pod specs then patched to
`runtimeClassName: vm` with explicit memory requests; then CRD Established checks with
every GVK recorded, a full ClusterRole dump, a v1alpha1 read of a v1beta1 object, the
in-tree mocker deployment, and a completion through the frontend's ClusterIP with the
worker's log inspected for the frontend's dial.

## Halt (binding, substitution pre-decided)

Discovery or the frontend-to-worker dial fails, then R4(b): the native-Darwin control
plane as a second `hack/images` entry.

## Inputs (resolved anonymously against the upstream registry, 2026-09-24)

| input | digest-pinned reference | resolved by |
|---|---|---|
| chart `dynamo-platform` 1.4.2 (OCI chart) | `oci://nvcr.io/nvidia/ai-dynamo/dynamo-platform@sha256:089299c70a31d2e79c933d149a686d04df0965822c4a93d632de9d52701e62a5` | registry v2 `GET /v2/nvidia/ai-dynamo/dynamo-platform/manifests/1.4.2` (`Docker-Content-Digest`, and sha256 of the body); `helm pull oci://…@sha256:…`; `crane digest` (v0.20.2) |
| operator image 1.4.2 (index) | `nvcr.io/nvidia/ai-dynamo/kubernetes-operator:1.4.2@sha256:94e9127882ee30a937a009ae5af0a000047093d5ba5ccefdfbe942c394a020e3` | registry v2 manifests endpoint with an OCI-index `Accept`; `crane digest` (v0.20.2) |
| frontend image 1.4.2 (index) | `nvcr.io/nvidia/ai-dynamo/dynamo-frontend:1.4.2@sha256:80589311c904b82927ae95703c1bc59c49eb7ac10d25925c0e457260da915bc7` | same two |
| planner image 1.4.2 (index; the mocker vehicle) | `nvcr.io/nvidia/ai-dynamo/dynamo-planner:1.4.2@sha256:6a0303be5ae6cd4e1a07d7c1d16d5d5d0d692cad28538de97e640e3893952328` | same two |

Each image index carries `linux/amd64`, `linux/arm64` and two attestation manifests.
The chart is published at `nvcr.io/nvidia/ai-dynamo/dynamo-platform`; the path under
`…/charts/` named in the plan's research has no repository (its anonymous token
request answers 400).

The operator, frontend and mocker image variables were exported to the rung
(`K3SM_M16_OPERATOR_IMAGE`, `K3SM_M16_FRONTEND_IMAGE`, `K3SM_M16_MOCKER_IMAGE`), but see
Findings: this rung does not read them.

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s2.1 values | RECORDED | `etcd.install: false`, `nats.install: false`, `discoveryBackend: kubernetes` (see Findings: at this chart version these keys are not the chart's) |
| s2.1 install | FAIL | helm pulled the chart by digest and created the release, then `resource Deployment/…/m16-dynamo-operator-controller-manager not ready. status: Failed, message: Progress deadline exceeded`. Every Pod create was denied by the `k3sm-require-os-darwin` admission policy (`pods must target a darwin node via nodeSelector kubernetes.io/os=darwin`) |
| s2.2 crds | not run | the payload stops at the s2.1 install failure |
| s2.3 rbac | not run | see Findings for a read-only observation made after the rung exited |
| s2.4 conversion | not run | |
| s2.5 serve | not run | |
| s2.6 dial | not run | |

## The GVK strings (what `pkg/mlxfleet` pins)

Not produced by this run: s2.2 did not run, and the chart installed no CRDs of its own
(see Findings).

| CRD | group | kind | served | storage | conversion |
|---|---|---|---|---|---|
| | | | | | |

## The operator `ClusterRole`, verbatim

Not produced by this run: s2.3 did not run. The dump belongs here once a run reaches
it; the Findings carry a read-only summary taken after this run exited, which is not
a substitute for it.

```yaml
```

## Rig

| | |
|---|---|
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`) |
| SoC / memory | Apple M2, 8 GiB |
| macOS | 26.6.2 |
| cluster | its own single-node k3sm server, v1.36.2, node Ready |
| helm on the rig | v4.2.3, an x86_64 build running under Rosetta; it resolved and pulled the OCI chart by digest with no fault |
| date (UTC) | 2026-09-24, 13:32:23 to 13:42:29 |

## Findings

- **The patch-after-wait ordering cannot pass on k3sm.** s2.1 installs with
  `--wait` and patches the Deployments afterwards, but on this cluster a Pod without
  the darwin node selector is refused at admission, so the ReplicaSet creates nothing
  and `--wait` ends only at the 600 s progress deadline. The chart does not offer a
  way around it through values: `dynamo-operator.controllerManager` exposes
  `tolerations` and `affinity` but no `nodeSelector`, and the admission policy asks
  for the selector specifically. Installing without `--wait` and then patching, or a
  helm `--post-renderer` that adds the selector, runtime class and requests before
  the objects reach the apiserver, would let the rung reach its actual question. Not
  changed here.
- **The values the rung writes are not this chart's keys.** At 1.4.2 the toggles are
  `global.etcd.install`, `global.nats.install` and `dynamo-operator.discoveryBackend`.
  The chart's defaults already are `false`, `false` and `kubernetes`, so the install
  had the intended shape anyway, but by default rather than because the rung said so.
- **The image pins do not reach the chart.** `lib.sh` forwards `OPERATOR_IMAGE`,
  `FRONTEND_IMAGE` and `MOCKER_IMAGE` into the payload and `s2.sh` never reads them;
  `K3SM_M16_VALUES` and `K3SM_M16_DGD_MANIFEST` are read on the rig side but are not in
  the forwarded environment, so neither can be supplied from the driver. The operator
  Deployment therefore referenced `nvcr.io/nvidia/ai-dynamo/kubernetes-operator:1.4.2`
  by tag. No Pod ran, so nothing was pulled; at run time that tag resolved to the
  digest recorded above. The chart renders `repository:tag`, so a digest pin goes
  through `dynamo-operator.controllerManager.manager.image.tag: "1.4.2@sha256:…"`.
- **The chart installs no CRDs itself.** None appeared after the install: with
  `upgradeCRD: true` the operator applies them from its own image through a
  `crd-apply` init container, so s2.2 cannot pass until the operator Pod runs.
- **Two later steps would have failed on this rig for harness reasons.** The rig's
  `python3` has no PyYAML, which s2.3's wildcard scan (it would print `UNPARSED`) and
  s2.5's manifest patch (it exits) both need. And s2.5's manifest search
  (`grep -rl "kind: DynamoGraphDeployment" … | grep -i mocker | head -1`) returns a
  documentation page (`docs/…/mocker-live-simulation.mdx`) first on this checkout, not
  a deployable manifest.
- **The rung does not clean up after a failure.** It left the release, two Services,
  the webhook configurations and thirteen ClusterRoles behind. They were removed after
  the rung exited (`helm uninstall` and a namespace delete); no chart ClusterRole,
  webhook configuration or CRD remains. The MLXModel and its PVC were not touched.
- **ClusterRole observation (read-only, after the rung, not a verdict).** Thirteen
  ClusterRoles carried the release label. None uses a wildcard verb or resource.
  `m16-dynamo-operator-manager-role` has 49 rules, and two of them grant `secrets`
  cluster-wide: `create, get, list, update, watch` and `delete, patch`. That is wider
  than the plan's R11 bound (no `secrets` verb outside the webhook cert's namespace),
  so the RBAC golden test will need either a narrower role or a recorded decision.
  The chart's `dynamo-operator.namespaceRestriction.enabled` (off by default, as here)
  renders the same rules as a namespaced Role and RoleBinding instead; whether the
  operator runs correctly that way is untested.
  The full dump s2.3 is meant to produce still needs a passing run. The validating
  and mutating webhooks on the chart's CRDs use `failurePolicy: Fail`; the one
  mutating webhook on Pods (checkpoint restore) uses `Ignore`, so the stranded webhook
  did not block ordinary Pods while it existed.
