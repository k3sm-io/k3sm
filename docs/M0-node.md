# M0 part 2 — Virtual Kubelet node + native pod ✅ VALIDATED (2026-06-24)

Proves the k3sm runtime end to end: a Kubernetes Pod, applied with `kubectl`, runs as a
**native macOS process** on a real Virtual Kubelet node — **zero Linux, no container, no VM**.

## What runs
- **`k3sm node`** (`cmd/k3sm/node.go`) registers this Mac as a Virtual Kubelet node
  (labels `kubernetes.io/os=darwin`, `kubernetes.io/arch=arm64`) using VK's naive node
  provider → Ready + Lease heartbeat.
- **HostProcess provider** (`pkg/provider/hostprocess.go`) implements the VK
  `PodLifecycleHandler` + `PodNotifier`: each container's `command`/`args` runs as a native
  process (`os/exec` at host paths, in its own process group), with status + combined-log
  capture. No isolation yet — Seatbelt confinement (see
  `runtimed/prototypes/seatbelt-hostpath`) and the gRPC `runtimed` split arrive in M2.

## Validated (macOS 26.5.1, arm64)
| check | result |
|---|---|
| `k3sm node` registers a darwin node | ✅ `k3sm-m0 Ready agent` (lease heartbeat) |
| `kubectl apply` a native pod | ✅ Pod `Running` on `k3sm-m0` (`1/1`) |
| a real native process runs on the Mac | ✅ `/usr/bin/tail -f /dev/null` (host pid) |
| stdout/stderr captured | ✅ log file shows `sw_vers` → `ProductVersion: 26.5.1` |
| `kubectl delete pod` | ✅ provider SIGKILLs the process group; process gone |
| node stays Ready after the pod ends | ✅ heartbeat alive |

**Known gap:** `kubectl logs`/`exec` over the apiserver→node proxy need the node served over
**TLS** with an IP-preferred address (the apiserver currently dials the node by hostname over
HTTPS → `lookup k3sm-m0: no such host`). The on-disk log works today; wiring the kubelet
serving cert + `--kubelet-preferred-address-types=InternalIP` is an M0.3/M2 follow-up.

## Run it
```sh
# 1. control plane (see docs/M0-spike.md) — kine + apiserver are enough for a nodeName-pinned pod
KCFG=/tmp/k3sm-spike/spike.kubeconfig          # produced by hack/spike/run.sh

# 2. the node (HostProcess runtime)
go run ./cmd/k3sm node --kubeconfig "$KCFG" --node-name k3sm-m0 --pod-root /tmp/k3sm-pods

# 3. a native pod
kubectl --kubeconfig "$KCFG" apply -f examples/hello-native.yaml
kubectl --kubeconfig "$KCFG" get pods -o wide
pgrep -fl tail                                  # the real process
kubectl --kubeconfig "$KCFG" delete pod hello-native
```

## Next
- M0.3: kubelet-serving TLS so `kubectl logs/exec` work via the apiserver proxy; scheduler-based
  placement + the provider taint + the `os=darwin` admission policy (so it's not nodeName-pinned).
- M2: move execution into `runtimed` (gRPC), add the Seatbelt default-deny profile + userspace
  resource limits.
- M1: build the control plane **from source** and embed it in-process (replacing the prebuilt
  spike binaries).
