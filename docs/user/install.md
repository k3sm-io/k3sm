# Install

How k3sm installs, and why it needs admin rights exactly **once**.

## The one-time admin step

k3sm is designed to run **without per-command `sudo`**. A single privileged install sets up an
unprivileged posture that everything else runs under:

```sh
sudo k3sm install
```

That step:

- creates the dedicated unprivileged **`_k3sm`** user,
- installs the minimal root networking helper (`k3sm-netd`) and the `_k3sm` LaunchDaemons
  (`RunAtLoad` / `KeepAlive`, boot-surviving),
- writes an **admin kubeconfig** to the invoking user's home directory.

After install, `k3sm kubectl …` and Pod lifecycle run as you / `_k3sm` with **no `sudo`**. The full
trust model — why this is the Docker Desktop / lima / colima pattern applied to k3sm, and the one
residual limitation (no per-pod uid isolation) — is documented in `docs/privilege-model.md`.

## What gets installed where

- The signed `k3sm` binary (Homebrew keeps the previous bottle so rollback does not require a rebuild).
- LaunchDaemons under the `io.k3sm.*` reverse-DNS labels.
- The kine/SQLite datastore under the server work directory (see [backup-restore.md](backup-restore.md)).

## Homebrew vs release binary

The supported install is the Homebrew tap (a notarized bottle). A standalone notarized release binary is
also published for air-gapped or scripted installs. Both are the same signed artifact.

## Verifying

```sh
k3sm version        # prints the k3sm version + the Kubernetes control-plane pin (see versions.md)
k3sm kubectl get nodes
```

## Next

- [quickstart.md](quickstart.md) — first Pod.
- [kubectl-access.md](kubectl-access.md) — kubeconfig details.
- [upgrade.md](upgrade.md) — how upgrades restart the daemon.
- [limitations.md](limitations.md) — read before relying on k3sm.
