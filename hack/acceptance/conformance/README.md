# Synthetic conformance gate

The **stockkitty-driven** acceptance spec: assertions that exercise every Kubernetes feature class the
`~/stockkitty` reference workload needs, built from tiny native test binaries with **no dependency on
stockkitty's proprietary images**. It proves *feature-class coverage* (deterministic, CI-able) — **not**
image-level stockkitty compatibility (the amd64-Linux images are handled only by the M5 `vm` path). Rationale +
the full feature-gap matrix: `../../../../docs/stockkitty-readiness.md`.

## How it wires in (no parallel gate family)

- The milestone gate stays **`hack/acceptance/m<n>.sh`**, registered in `hack/acceptance/phases.json` — the single
  manifest `/orchestrate` reads. `m<n>.sh` brings the cluster up (reuse `hack/lib/clusterup.sh` `server_up`,
  already `CGO_ENABLED=1`) and runs the conformance assertions for that milestone:
  `go test -tags e2e -run TestM<n>_ ./e2e/...` (mirrors how `m1.sh` delegates to `go test -tags e2e -run TestM1`).
- Assertions are **build-tagged Go test functions named per criterion** — each is the
  **fails-before / passes-after** unit (RED on `main` before the feature, GREEN after). There are **no
  "assert-absence" scripts**: a milestone gate is binary (exit 0/1), and the criterion-named subtest is the thing
  the orchestrator maps to acceptance.
- **CGO_ENABLED=1** for every M2+ slice. **Tier** per `phases.json`: single-node-root → `integration` (`m2.sh`),
  two-Mac / `vm` → `lab` (`K3SM_LAB=1`; `m3.sh`/`m5.sh`). Slices **share one cluster bring-up**; the `vm` slice is
  lab-tiered with a stated wall-clock budget.
- Test binaries (`hello-http`, `writer`, `kubectl-caller`) are built from sources under `testdata/` and
  **ad-hoc-signed** (`codesign -s -`) so they exec under the default-deny Seatbelt profile; the `vm`-slice Linux
  image is **digest-pinned**. Manifests are checked in as golden fixtures.

## Assertion → stockkitty feature (the contract)

| test (named per criterion) | proves | stockkitty feature | milestone / tier |
|---|---|---|---|
| `TestM2_ConfigMapMount` | configMap mounted as a file | `nats.conf` ConfigMap | M2 / integration |
| `TestM2_SecretMount` | secret mounted, read-only sub-scope | `git-ssh-key` Secret | M2 / integration |
| `TestM2_EmptyDir` | emptyDir scratch volume | `/dev/shm` (snapshot gRPC) | M2 / integration |
| `TestM2_DownwardAPIEnv` | `spec.nodeName`/`status.podIP`/`metadata.name` env | `mother` downward-API env | M2 / integration |
| `TestM2_Probes` | readiness fail → endpoint removed; liveness fail → restart | NATS/compile-server probes | M2 / integration |
| `TestM2_FsGroup` | `securityContext.fsGroup` ownership of writable mounts | postgres `fsGroup: 999` | M2 / integration |
| `TestM2_GracefulStop` | SIGTERM honored within the grace period | `terminationGracePeriodSeconds: 30` | M2 / integration |
| `TestM2_InPodKubectl` | projected bound SA token + CA + `kubernetes.default.svc` reach the apiserver | `snapshotManager` in-pod kubectl | M2 / integration |
| `TestM2_DenyUsers` (negative) | pod cannot read `/Users` / a sibling pod dir / write outside its data volume | the default-deny isolation contract | M2 / integration |
| `TestM3_NodePort` | a Deployment is reachable on `*:nodePort` | VSCode SSH NodePort, snapshot gRPC range | M3 / lab |
| `TestM3_PVCPersistsAcrossRestart` | StatefulSet+PVC data survives a pod restart | Postgres / compile-artifacts PVCs | M3 / lab |
| `TestM4_RBACEnforced` | a restricted SA is denied a verb; admin + control-plane SAs allowed | `stockkitty-snapshot-manager` ClusterRole | M4 / integration |
| `TestM5_LinuxImageUnderVM` | a Linux image runs under `runtimeClassName: vm`, Service/DNS-reachable | pgvector / nats Linux images | M5 / lab (`K3SM_LAB=1`) |

## Status

This is the **spec**. The test functions, the `testdata/` binaries+manifests, and `m2.sh`/`m3.sh`/`m5.sh` are
authored as each milestone's work runs (per the `phases.json` convention "gates for unstarted milestones are
authored as that milestone's work runs"). On today's `main` the `TestM2_*` criteria are RED (the features are
M2 work) — which is the fails-before half of the contract.
