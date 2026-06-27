# Synthetic conformance gate

The **stockkitty-driven** acceptance spec: assertions that exercise every Kubernetes feature class the
`~/stockkitty` reference workload needs, built from tiny native test binaries with **no dependency on
stockkitty's proprietary images**. It proves *feature-class coverage* (deterministic, CI-able) — **not**
image-level stockkitty compatibility (the amd64-Linux images are handled only by the M5 `vm` path). Rationale +
the full feature-gap matrix: `../../../../docs/stockkitty-readiness.md`.

## How it wires in (no parallel gate family)

- **The criterion tests live in `e2e/`** (`package e2e`, `//go:build e2e`), NOT under this directory — this
  directory stays the README/spec. Every gate globs `./e2e/...` (`go test -tags e2e -run TestM<n>… ./e2e/...`)
  and the one cluster harness is `e2e/harness.go` (`Up()` / `Cluster`). The per-criterion funcs are
  `TestM<n>_<Criterion>` in `e2e/m2_test.go` / `e2e/m3_test.go`; `e2e/main_test.go` builds the helper binaries.
- The milestone gate stays **`hack/acceptance/m<n>.sh`**, registered in `hack/acceptance/phases.json` — the
  manifest `/orchestrate` reads. `m<n>.sh` brings the cluster up (reuse `hack/lib/clusterup.sh` `server_up`,
  already `CGO_ENABLED=1`) and runs the conformance assertions for that milestone via the shared guard in
  `hack/lib/conformance.sh` (mirrors how `m1.sh` delegates to `go test -tags e2e -run TestM1`).
- Assertions are **build-tagged Go test functions named per criterion** — each is the
  **fails-before / passes-after** unit (RED on `main` before the feature, GREEN after). There are **no
  "assert-absence" scripts**: a milestone gate is binary (exit 0/1), and the criterion-named test is the thing
  the orchestrator maps to acceptance.
- **Non-vacuous guard** (`hack/lib/conformance.sh` `run_conformance_slice`): the gate **enumerates the required
  criterion set** and turns RED on any criterion that is **missing, failed, OR skipped** — closing the old
  `-run TestM<n>` guard's PARTIAL-coverage (1-of-N) and ALL-SKIP false-greens. Deferred criteria are authored as
  `t.Skip`'d TODO tests that are simply absent from the required list (so their skip is allowed and visible) —
  the required set is the checklist of record.
- **CGO_ENABLED=1** for every M2+ slice (k3sm is cgo from M1). **Tier** per `phases.json`: single-node →
  `integration` (`m2.sh` root; `m3.sh` root single-node NodePort+PVC; `m4.sh` non-root RBAC); cross-node / `vm` →
  `lab` (`K3SM_LAB=1`; `hack/lab/m3.sh` two-Mac mesh/DNS, `m5.sh`). M3 and M4 each split an integration row and a
  lab row. Slices **share one cluster bring-up**.
- Helper binaries **`hello-http`** (controllable HTTP server: probe-transition health toggles + NodePort backend)
  and **`conftool`** (`memhog` for OOMKilled, `apicall` for in-pod kubectl, `resolve` for in-pod DNS) are built
  from sources under `e2e/testdata/cmd/` by the suite's `TestMain` into `$K3SM_CONFORMANCE_BIN` and
  **ad-hoc-signed** (`codesign -s -`) so they exec under the default-deny Seatbelt profile. Pure file-content /
  mode / env / fsGroup / graceful-stop checks use inline native `/bin/sh` self-checks (exit 0/1 → pod
  Succeeded/Failed). The `vm`-slice Linux image is **digest-pinned**. The golden ConfigMap payload is
  `e2e/testdata/nats.conf`.

## Assertion → stockkitty feature (the contract)

| test (named per criterion) | proves | stockkitty feature | milestone / tier |
|---|---|---|---|
| `TestM2_ConfigMapMount` | configMap mounted as a file (content intact) | `nats.conf` ConfigMap | M2 / integration |
| `TestM2_SecretMount` | secret mounted read-only, **mode 0400** | `git-ssh-key` Secret | M2 / integration |
| `TestM2_EmptyDir` | emptyDir scratch volume read/write | `/dev/shm` (snapshot gRPC) | M2 / integration |
| `TestM2_DownwardAPIEnv` | downward-API env; **`$MY_POD_IP == status.podIP`** | `mother` downward-API env | M2 / integration |
| `TestM2_EnvFrom` | `envFrom` configMapRef + secretRef populate env | bulk-config env | M2 / integration |
| `TestM2_Probes` | readiness fail → **endpoint removed**; liveness fail → **restartCount++** | NATS/compile-server probes | M2 / integration |
| `TestM2_FsGroup` | `securityContext.fsGroup` owns the writable mount | postgres `fsGroup: 999` | M2 / integration |
| `TestM2_GracefulStop` | SIGTERM honored within the grace period (terminates ≪ grace) | `terminationGracePeriodSeconds: 30` | M2 / integration |
| `TestM2_ResourceLimitsOOMKilled` | `resources.limits.memory` breach → phase Failed, reason OOMKilled | memory-limited workloads | M2 / integration |
| `TestM2_KubectlTop` | kubelet Summary API reports a non-zero working-set | `kubectl top` footprint | M2 / integration |
| `TestM2_InPodKubectl` | projected bound SA token + CA reach the apiserver; granted read allowed, ungranted 403 | `snapshotManager` in-pod kubectl | M2 / integration |
| `TestM2_InPodDNS` | in-pod DNS resolves `kubernetes.default.svc` (getaddrinfo shim) | in-cluster DNS | M2 / integration |
| `TestM2_DenyUsers` (negative) | pod cannot read `/Users` / write outside its volumes (Seatbelt) | the default-deny isolation contract | M2 / integration |
| `TestM2_ImagePullSecrets` (**deferred**) | private-registry pull — not an M2/M3 native-runtime feature | (tracked, `t.Skip`) | M2 / deferred |
| `TestM2_DaemonSet` (**deferred**) | DaemonSet scheduling — not yet a k3sm feature class | (tracked, `t.Skip`) | M2 / deferred |
| `TestM3_NodePort` | a Deployment is reachable on `*:nodePort` | VSCode SSH NodePort, snapshot gRPC range | M3 / integration (single-node) + lab |
| `TestM3_PVCPersistsAcrossRestart` | StatefulSet+PVC data survives a pod restart | Postgres / compile-artifacts PVCs | M3 / integration (single-node) + lab |
| `TestM3_InPodKubectlAndDNSOnWorker` | on the JOINED worker: cluster DNS + in-pod kubectl via the node-local API VIP | cross-node in-cluster access | M3 / lab (`K3SM_WORKER`) |
| `TestM4_RBACEnforced` | a restricted SA is denied a verb; admin + control-plane SAs allowed | `stockkitty-snapshot-manager` ClusterRole | M4 / integration (`m4.sh`) |
| `TestM5_LinuxImageUnderVM` | a Linux image runs under `runtimeClassName: vm`, Service/DNS-reachable | pgvector / nats Linux images | M5 / lab (`K3SM_LAB=1`) |

## Status

This is the **spec**, plus (as of M4.2) the **authored + compile-verified + gate-wired** suite: the
`TestM2_*` / `TestM3_*` criterion funcs live in `e2e/m2_test.go` / `e2e/m3_test.go`, the `hello-http` +
`conftool` helpers under `e2e/testdata/cmd/`, and the gates `m2.sh` (M2), `m3.sh` (single-node M3 integration),
`hack/lab/m3.sh` (two-Mac M3 lab), `m4.sh` (RBAC integration) enumerate their required criteria under the
non-vacuous guard. The **LIVE green is integration-tier** (a dev Mac + root for `m2.sh`/`m3.sh`; `k3sm install`
for the helper posture), so it is not run in unit CI — **M4.2-a1 stays `met:false` (integration-pending)** until
the gates run green on a capable host. The `m5.sh` `vm` slice is authored at M5.
