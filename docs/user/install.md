# Install

How k3sm installs, and why it needs admin rights only once.

## One-Time Admin Step

k3sm runs **without per-command `sudo`**. A single privileged install creates the accounts and
daemons that everything after it runs under:

```sh
sudo k3sm install
```

The install script cannot pass extra flags, so if you want the data root on its own size-capped
APFS volume, run `sudo k3sm install --data-volume` after the script, or in place of it if you
already have the binary. See [The Data Volume](storage.md#the-data-volume).

That step:

- creates the dedicated unprivileged **`_k3sm`** user,
- installs the minimal root networking helper (`k3sm-netd`) and the `_k3sm` LaunchDaemons
  (`RunAtLoad` / `KeepAlive`, boot-surviving),
- links **`/usr/local/bin/k3sm`** so `k3sm` is a command your shell can find,
- writes an **admin kubeconfig** to the invoking user's home directory.

After install, `k3sm kubectl …` and Pod lifecycle run as you / `_k3sm` with **no `sudo`**.
[The privilege model](../privilege-model.md) documents the full trust model. It is the same
privileged-helper pattern the desktop container tools and Linux VM managers use, applied to k3sm,
and one residual limitation remains (no per-pod uid isolation).

## What Gets Installed Where

- The `k3sm` binary in **`/Library/k3sm`** (`root:wheel`), whichever channel delivered it (with the
  script, pin `K3SM_INSTALL_VERSION` to reinstall a prior release, since the assets stay on GitHub
  Releases; the planned Homebrew channel will retain the previous version, so rollback there will
  not need a rebuild).
- The launcher, a symlink **`/usr/local/bin/k3sm` → `/Library/k3sm/k3sm`**. `/usr/local/bin` is
  the first entry in `/etc/paths`, so every terminal opened after the install finds `k3sm` with no
  profile edit; a terminal that was already open may need `hash -r` or simply a new window. Because
  it is a symlink rather than a copy, the daemons and your shell always run the same binary. If
  something other than a symlink already sits at that path, install refuses to replace it and says so.
- LaunchDaemons under the `io.k3sm.*` reverse-DNS labels. The control plane's plist is `0600`
  (root-only), since the arguments it carries can include a datastore password.
- The cluster admin token in **`/var/lib/k3sm/server/token`**, mode `0600` and owned by the
  `_k3sm` service account. The daemon is told where its token is, never what it is, so the token
  does not appear in the plist, in `ps`, or in `launchctl print`. `k3sm uninstall` removes it.
  Because that plist is `0600`, `k3sm status` run without `sudo` reports the server's launchd
  arguments row as unreadable as this user, which never changes the verdict, and `sudo k3sm status`
  shows it.
- The kine/SQLite datastore under the server work directory (see [Backup & restore](backup-restore.md)).

## Install Channels

k3sm's distribution ships in three generations, listed in shipping order:

1. **The install script (gen 1, first to ship):**

   ```sh
   curl -fsSL https://k3sm.io/install.sh | sh
   ```

   The script preflights (Apple silicon, macOS 26+), downloads the release tarball and its
   checksums from GitHub Releases, verifies the sha256, prints exactly what it is about to do,
   and then runs `sudo k3sm install`. The verification checks **same-origin integrity**, meaning
   the tarball matches the checksums published beside it. It does not check publisher identity;
   provenance (Developer ID + notarization) arrives with gen 3. Environment variables set the
   options. `K3SM_INSTALL_VERSION=v0.1.0` pins a release, and it is also the repair path, since
   an unpinned re-run jumps to latest. `K3SM_INSTALL_DOWNLOAD_ONLY=1` downloads and verifies into
   the current directory without ever running `sudo`, so you can inspect first. Re-running the
   one-liner upgrades in place, and both daemons restart briefly (see [Upgrade](upgrade.md)).

2. **Homebrew (gen 2)** is planned, and the `k3sm-io/tap` is not published yet. When it ships, run
   `brew install k3sm-io/tap/k3sm`, then `sudo k3sm install`.

3. **Notarized `.pkg` (gen 3)** is a signed, stapled installer package for offline and managed
   installs.

> **Status:** pre-release builds are published; the script resolves the newest one, and a pin
> via `K3SM_INSTALL_VERSION` always wins. The `k3sm-io/tap` is not published yet. The Homebrew
> channel and the `.pkg` arrive with the first stable release.

Every channel manages the same `/Library/k3sm`. Once more than one has shipped, run
`sudo k3sm install` after switching so the daemons run the newly delivered binary, or run
`sudo k3sm uninstall` first for a clean cutover.

## Uninstalling

```sh
sudo k3sm uninstall
```

It stops and removes both LaunchDaemons, removes `/Library/k3sm`, and removes the
`/usr/local/bin/k3sm` launcher, but only that link, and only while it still points at
`/Library/k3sm/k3sm`. A file you put there yourself, or a link you re-pointed at something else, is
left exactly as it is. It also clears the mesh's pf anchor rule, so a later tunnel never inherits a
stale MSS clamp. Your cluster data, the `_k3sm` user, and your kubeconfig are kept, so a
reinstall picks up where you left off. The command prints the full list of what it kept. If you
installed a data volume, it stays mounted and declared; the command prints `sudo k3sm install
--data-volume` to reinstall onto it and `sudo k3sm datavol delete --yes` to remove it for good.

### Server Flags Across A Reinstall

Any flag you added to the server daemon yourself, such as `--mesh-ip` or `--registry-port`, is
carried into the plist every install renders. Install reads them from the installed daemon, and
records them in `/Library/Preferences/io.k3sm.server-args.json`, so they survive an uninstall too.
That file is root-owned and root-readable only, because a flag can carry a credential. `k3sm status`
shows what the installed server is running with, on the `server-args` row.

The record is written at install time. A flag you edit directly into the daemon's plist is picked up
by the next `sudo k3sm install`, and until then it exists only in the plist, so an uninstall before
that install loses it. Running `sudo k3sm install` after an edit is what makes it durable.

The installed daemon wins while it is there, so a reset means clearing both sources:

```sh
sudo k3sm uninstall                                          # removes the daemon and its flags
sudo rm /Library/Preferences/io.k3sm.server-args.json        # discards the recorded ones
sudo k3sm install                                            # renders the stock template
```

That discards the flags the file lists, and nothing else. Your cluster data is untouched.

Install warns when it finds neither source on a data root that already holds cluster state, which is
what a Mac uninstalled by an older version looks like. The flags are gone on such a Mac, and install
says so rather than starting single-node in silence.

## Verifying

```sh
k3sm version        # prints the k3sm version + the Kubernetes control-plane pin (see the Version Support page)
k3sm status         # what is running: daemons, apiserver, node, workloads, data root
k3sm kubectl get nodes
```

## Next

- [Quickstart](quickstart.md) runs your first Pod.
- [kubectl access](kubectl-access.md) covers kubeconfig details.
- [Upgrade](upgrade.md) explains how upgrades restart the daemon.
- Read [Limitations](limitations.md) before relying on k3sm.
