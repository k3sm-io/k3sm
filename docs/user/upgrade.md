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

## Next

- [backup-restore.md](backup-restore.md) — snapshot before upgrading.
- [versions.md](versions.md) — the version you are moving to.
- [troubleshooting.md](troubleshooting.md) — if the daemon does not restart.
