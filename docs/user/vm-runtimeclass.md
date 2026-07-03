# The `vm` RuntimeClass

k3sm runs Pods as native Darwin processes under a **single `_k3sm` user**, so there is **no per-pod uid
isolation** — same-node Pods share one OS trust domain. For **untrusted or multi-tenant** workloads, the
**`vm` RuntimeClass** provides a real isolation boundary backed by Virtualization.framework.

> **Status: EXPERIMENTAL.** The `vm` RuntimeClass (M5) ships as documented **EXPERIMENTAL** — a v0.2
> headline, not launch-blocking. See [limitations.md](limitations.md).

## When to use it

Use `vm` when a workload must not share the `_k3sm` trust domain with its neighbors — untrusted code,
tenant isolation, or anything you would isolate with a strong boundary on Linux. This is the same
framing as [limitations.md](limitations.md) and [concepts.md](concepts.md): the default native path is
**not** a security boundary between Pods; `vm` is. The rationale and the trust-domain analysis live in
`docs/privilege-model.md`.

## Using it

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-job
spec:
  runtimeClassName: vm
  containers:
    - name: app
      image: myapp
```

Pods without `runtimeClassName: vm` use the default native-process runtime and therefore share the
`_k3sm` trust domain with other default Pods on the same node.

## Trade-offs

- **Isolation** — a genuine boundary, at the cost of VM startup and overhead versus a native process.
- **Fidelity** — as an EXPERIMENTAL path, treat behavior as preview-quality and validate your workload.
- **Fallback posture** — when a Seatbelt SPI symbol-canary trips on the native path, the runtime degrades
  to `vm` or refuse-to-run, never to an unconfined process (see `docs/privilege-model.md`).

## Next

- [limitations.md](limitations.md) — the no-per-pod-uid-isolation gap in context.
- [concepts.md](concepts.md) — the trust-domain model.
