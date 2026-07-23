# Troubleshooting

When a k3sm cluster does not behave. Start with logs, then the common failure modes below.

## Logs

k3sm daemons run as launchd jobs under the `io.k3sm.*` labels and log to the unified log system:

```sh
log show --predicate 'subsystem BEGINSWITH "io.k3sm"' --last 10m
launchctl print system/io.k3sm.server     # daemon state (label may differ per role)
```

## The control plane will not come up

- Confirm install completed: `k3sm version` and `sudo k3sm install` (idempotent).
- Check the datastore is present and not locked — the kine/SQLite DB lives under the server work
  directory (see [backup-restore.md](backup-restore.md)).
- Restart the daemon: `launchctl kickstart -k system/io.k3sm.server` (label per your role).

## A Pod is stuck or exits and does not restart

- **`restartPolicy` is not honored live** — an exited container is reaped, never respawned. This is
  expected today; a controller (Deployment/Job) will replace the Pod, but the container is not restarted
  in place. See [limitations.md](limitations.md).
- Check the Pod was **adapted** to the native image model — a raw Linux image cannot run as a Darwin
  process (see [images.md](images.md)).

## DNS from inside a Pod does not resolve cluster names

In-pod cluster-DNS wiring is **currently unwired at `main`** — the Pod resolver defers to the host
resolver, and headless/SRV/PTR records are planned. This is a known gap, not a misconfiguration — see
[limitations.md](limitations.md).

## A UDP Service does not work

Only cluster DNS on `:53` uses UDP today; general UDP Services (ClusterIP **and** NodePort) are deferred.
See [limitations.md](limitations.md).

## `kubectl top` returns no metrics

k3sm ships no metrics-server and has no CPU accounting; install a metrics-server operator if you need the
`metrics.k8s.io` verb. See [kubectl-access.md](kubectl-access.md) and [limitations.md](limitations.md).

## A control-plane certificate is close to expiry

Component certificates are re-issued on every control-plane boot, so a restart renews them.
`sudo k3sm certificate rotate` reports what a restart would re-issue (and both CA pins, which
never change); `--restart` performs it. Rotation does **not** revoke anything and does not cover
worker-node certs — see [certificates.md](certificates.md) before you rely on it.

## Multi-node join fails

- Re-mint the token (`k3sm token create`) — tokens expire.
- Confirm the agent can reach the server on `6443` and the wireguard mesh is up. See
  [multi-node.md](multi-node.md).

## Next

- [faq.md](faq.md) — quick answers.
- [limitations.md](limitations.md) — is this a bug or a documented gap?
- [backup-restore.md](backup-restore.md) — recover the datastore.
- [certificates.md](certificates.md) — the PKI, rotation, and its limits.
