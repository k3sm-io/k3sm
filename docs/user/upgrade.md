# Upgrade

Moving a k3sm node or cluster to a new release.

## Single node

```sh
brew upgrade k3sm
```

The Homebrew upgrade replaces the signed binary and re-`launchctl kickstart`s the k3sm LaunchDaemons
(the `io.k3sm.netd` root helper and the `_k3sm` server/agent jobs) onto the new version. This is a
**hard cut** with a brief daemon restart — the node is momentarily unavailable while the daemon
restarts.

## Multi-node — roll node-by-node

A cluster upgrades **one node at a time**, not all at once. Restarting each node's daemon via `launchctl
kickstart` creates a short **binary-version-skew window** where old and new nodes coexist; k3sm releases
are designed so adjacent versions interoperate across that window. Upgrade agents first and the
control-plane Mac last unless a release note says otherwise. See [multi-node.md](multi-node.md) and
[ha.md](ha.md).

## Before you upgrade

- **Snapshot the datastore.** Take a datastore backup first so you can roll back state if needed — see
  [backup-restore.md](backup-restore.md).
- **Keep the previous bottle.** Homebrew retains the prior notarized bottle, so rollback does not require
  a rebuild-and-notarize round-trip.
- **Check the version skew.** Confirm the target Kubernetes pin with `k3sm version` — see
  [versions.md](versions.md).

## Rollback

Rollback is **revert to the previous binary** (`brew` pin/switch to the prior bottle) plus a `launchctl
kickstart`, not a runtime flag flip. Datastore schema migrations may be forward-only; if a release notes
a datastore migration, plan the forward fix rather than assuming a clean downgrade — see
[backup-restore.md](backup-restore.md).

### Rolling back past the LoadBalancer bind change leaves durable state

The release that moved LoadBalancer/Ingress listeners to the wildcard also changed **what k3sm writes
into the cluster**, and the older binary has no code to clean either of those up. Reverting the binary
does **not** revert them; you have to.

1. **Stale `EXTERNAL-IP` entries.** The new server advertises the node's derived InternalIP (e.g.
   `100.64.0.1`). The old server only ever retracted the address it was configured with — the loopback
   default — so it will **never** remove a derived entry. A rolled-back cluster keeps advertising an
   address its listeners are no longer on. Retract them by hand:

   ```sh
   kubectl get svc -A -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'
   kubectl patch svc <name> -n <ns> --subresource=status --type=merge -p '{"status":{"loadBalancer":{}}}'
   ```

   Do the same for any `Ingress` of the `k3sm` class (`kubectl patch ingress … --subresource=status`).

2. **The reserved-port Deny policy keeps rejecting Services.** The new server provisions the
   `k3sm-reject-loadbalancer-reserved-port` ValidatingAdmissionPolicy, which lives in the datastore and
   **survives the downgrade**. The old binary neither knows about it nor deletes it, so a
   `type: LoadBalancer` Service on a NodePort-range port or on `10250` stays rejected at
   `kubectl apply`. If you want the old (unguarded) behaviour back, delete both objects:

   ```sh
   kubectl delete validatingadmissionpolicybinding k3sm-reject-loadbalancer-reserved-port-binding
   kubectl delete validatingadmissionpolicy        k3sm-reject-loadbalancer-reserved-port
   ```

   Leaving them in place is also a valid choice — the policy is honest about a real collision on the old
   binary too.

## Next

- [backup-restore.md](backup-restore.md) — snapshot before upgrading.
- [versions.md](versions.md) — the version you are moving to.
- [troubleshooting.md](troubleshooting.md) — if the daemon does not restart.
