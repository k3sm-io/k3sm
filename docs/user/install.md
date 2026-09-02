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
residual limitation (no per-pod uid isolation) — is documented in
[the privilege model](../privilege-model.md).

## What gets installed where

- The `k3sm` binary, whichever channel delivered it (with Homebrew, the previous version is
  retained so rollback does not require a rebuild; with the script, pin `K3SM_INSTALL_VERSION`
  to reinstall a prior release — the assets stay on GitHub Releases).
- LaunchDaemons under the `io.k3sm.*` reverse-DNS labels.
- The kine/SQLite datastore under the server work directory (see [Backup & restore](backup-restore.md)).

## Install channels — the three generations

k3sm's distribution ships in three explicit generations, in shipping order:

1. **The install script (gen 1 — first to ship):**

   ```sh
   curl -fsSL https://k3sm.io/install.sh | sh
   ```

   The script preflights (Apple silicon, macOS 26+), downloads the release tarball and its
   checksums from GitHub Releases, verifies the sha256, prints exactly what it is about to do,
   and then runs `sudo k3sm install`. The verification is **same-origin integrity** — the
   tarball matches the checksums published beside it — not publisher identity; provenance
   (Developer ID + notarization) arrives with gen 3. Options, via environment variables:
   `K3SM_INSTALL_VERSION=v0.1.0` pins a release (also the repair path — an unpinned re-run
   jumps to latest); `K3SM_INSTALL_DOWNLOAD_ONLY=1` downloads and verifies into the current
   directory without ever running `sudo`, so you can inspect first. Re-running the one-liner
   upgrades in place (both daemons restart briefly — see [Upgrade](upgrade.md)).

2. **Homebrew (gen 2):** `brew install k3sm-io/tap/k3sm`, then `sudo k3sm install` — supported
   once the tap ships.

3. **Notarized `.pkg` (gen 3):** a signed, stapled installer package for offline and managed
   installs.

> **Status:** pre-release builds are published; the script resolves the newest one until the
> first stable release exists, and a pin via `K3SM_INSTALL_VERSION` always wins. The Homebrew
> tap and the `.pkg` follow the first stable release.

**Switching channels:** every channel manages the same `/Library/k3sm`. After switching (script
→ brew or back), run `sudo k3sm install` so the daemons run the newly delivered binary — or
`sudo k3sm uninstall` first for a clean cutover.

## Verifying

```sh
k3sm version        # prints the k3sm version + the Kubernetes control-plane pin (see versions.md)
k3sm kubectl get nodes
```

## Next

- [Quickstart](quickstart.md) — first Pod.
- [kubectl access](kubectl-access.md) — kubeconfig details.
- [Upgrade](upgrade.md) — how upgrades restart the daemon.
- [Limitations](limitations.md) — read before relying on k3sm.
