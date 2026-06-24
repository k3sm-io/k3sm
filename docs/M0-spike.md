# M0 spike — native control plane on macOS / arm64 ✅ VALIDATED (2026-06-24)

**Goal:** prove the k3sm thesis — a real Kubernetes control plane (`kube-apiserver` +
`kube-scheduler` + `kube-controller-manager`) runs **natively on macOS/arm64, zero Linux**,
backed by **kine + SQLite** (no etcd), with `kubectl` working and a node showing **Ready**.

**Result: thesis confirmed.** Real Kubernetes **v1.36.2** control plane runs natively on this
Mac (macOS 26.5.1, arm64) backed by kine+SQLite; `kubectl` fully works.

**Approach (spike vs. product).** The spike uses **prebuilt darwin/arm64 control-plane binaries**
from [`kwok-ci/k8s`](https://kwok.sigs.k8s.io/docs/user/kwokctl-platform-specific-binaries/)
(upstream doesn't ship darwin server binaries — [k/k#118359](https://github.com/kubernetes/kubernetes/issues/118359)).
The **product (M1)** replaces these with the same components **built from source and embedded as
in-process goroutines** (k3s `pkg/executor/embed` pattern). Reproducible script: **`hack/spike/run.sh`**.

## Validation ladder
| # | gate | result | evidence |
|---|---|---|---|
| V1 | kine runs natively on SQLite | ✅ | `db/state.db` (WAL) created; serves etcd API on :2379; trace shows `/registry/*` CRUD/WATCH |
| V2 | CP binaries native arm64 & run | ✅ | `file` → `Mach-O … arm64`; `--version` → `Kubernetes v1.36.2` (after ad-hoc codesign) |
| V3 | apiserver serves against kine | ✅ | `kubectl get --raw /healthz` → `ok` on our :6444 |
| V4 | kubectl talks to the API | ✅ | `version` → Server v1.36.2; 68 api-resources; token auth |
| V5 | scheduler + CM healthy | ✅ | both alive; **CM created the `default` SA in all 4 namespaces** (actively reconciling) |
| V6 | core API works | ✅ | `get ns` → default/kube-system/kube-public/kube-node-lease; `get nodes` returns |
| V7 | a node registers Ready | ✅* | `get nodes` → `spike-darwin-node  Ready  k3sm-spike` (*API-level stand-in; real Virtual Kubelet provider is next) |

## Pinned versions
- Kubernetes: **v1.36.2** (`kwok-ci/k8s`, darwin-arm64)
- kine: **v1.14.2**, **built `CGO_ENABLED=1`** (see finding #1)

## Findings (fed back into DESIGN.md)
1. **kine+SQLite requires CGO — the "CGO_ENABLED=0 fully-static binary" plan was wrong.** kine v1.14.2
   has only `sqlite.go` (`//go:build cgo` → `mattn/go-sqlite3`) and `sqlite_nocgo.go` (`//go:build !cgo`
   → returns `errNoCgo: "sqlite is disabled"`). There is **no** modernc/pure-Go path. Built `CGO_ENABLED=0`,
   kine fatals: *"this binary is built without CGO, sqlite is disabled."* → **k3sm builds `CGO_ENABLED=1`
   on darwin** (fine — macOS has no fully-static binaries anyway; cgo links libSystem + compiled sqlite3 and
   notarizes normally). Future option: add a `modernc.org/sqlite` kine driver to regain CGO_ENABLED=0.
2. **Downloaded arm64 binaries need ad-hoc signing to exec** — `codesign -s - -f` on each (real-world
   confirmation of the "codesign-on-pull" design, §3/§5a).
3. **Docker Desktop's Kubernetes squats on 127.0.0.1:6443** → the spike uses **:6444**. (Caught a false
   `healthz: ok` that was actually Docker's apiserver.)
4. **`--authorization-mode=AlwaysAllow` auto-disables anonymous auth** (apiserver resets `AnonymousAuth=false`).
   → spike uses a **static token file** (`--token-auth-file`) for kubectl/scheduler/CM.
5. Benign warnings (non-blocking): kine has **no `dbstat` table** ([k3s#12292](https://github.com/k3s-io/k3s/issues/12292),
   db-size metrics only); the `kubernetes` Service rejects the **127.0.0.1** endpoint (loopback advertise-addr —
   use a real IP in production); scheduler/CM log `extension-apiserver-authentication not found` (front-proxy/
   aggregator CA not wired — cosmetic).

## Run
```sh
hack/spike/run.sh                      # up: download, build kine, start CP, validate
hack/spike/run.sh kubectl get nodes    # drive it
hack/spike/run.sh down                 # stop
```

## Next (M0 part 2)
Replace V7's API stand-in with a **real Virtual Kubelet node** (no-op `PodLifecycleHandler`) in
`runtimed`/`k3sm`, then a **HostProcess provider** that runs one native arm64 binary as a Pod.
Then M1: build the three CP components **from source** and embed them as in-process goroutines.
