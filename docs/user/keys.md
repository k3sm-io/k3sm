# Keys

`k3sm keys` keeps key material on a k3sm server: a service's signing key, a third-party API
token, an HMAC key two of your Pods share. Each entry has a name and a history of versions, and
every version is encrypted at rest. You can list the entries, rotate one to a new value, roll it
back, and delete it, all without the value ever appearing on a command line.

Every verb runs as root, on the server that holds the keystore.

## What It Protects, and What It Does Not

The keystore protects values on disk. Each version is sealed with AES-256-GCM under a master key
that k3sm creates for you, so a copy of the entries alone opens nothing. A file changed or moved
by hand is refused rather than read as a different value, and an older copy of an entry put back
over a newer one is refused too (see [Restoring an older keystore/](#restoring-an-older-keystore)).

It does not protect a value from root on the Mac, and it does not keep one native Pod from
another: every native Pod runs as the same service user, `_k3sm`
(see [Concepts](concepts.md)). Treat it as an encrypted, versioned home for the value, not as a
wall between workloads.

## Names

Every name says which scope it belongs to. This build has one scope, `system`, the server's own
store:

```
system/signer-key
system/payments.api-token
```

The part after `system/` is 1 to 253 bytes of dot-separated labels of lowercase letters, digits
and `-`, each starting and ending with a letter or digit, the same rule as a Kubernetes object
name.

- A name without a scope, such as `signer-key`, is refused, and the message shows the
  `system/<name>` form to use. It does not repeat what you typed, in case that was a value.
- A `user/...` name is refused with "user scopes are not supported by this build".

## The Verbs

| Command | What it does |
|---|---|
| `sudo k3sm keys put system/NAME --in FILE` | Creates the entry at version 1. `--kind ed25519` stores an Ed25519 private key (a 32-byte seed or the 64-byte expanded key) and checks it; the default kind is `opaque`, any bytes. The first `put` on a server creates the master key. |
| `sudo k3sm keys list` | One line per entry: name, kind, current version, when it was created (UTC), fingerprint and status. Status is `ok`, or `corrupt` with the reason. `-o json` prints the same as JSON. Exits 1 if any entry is not `ok`, after listing every entry. |
| `sudo k3sm keys show system/NAME` | Prints the entry's metadata, never its value. `--version N` shows an older version. |
| `sudo k3sm keys show system/NAME --reveal` | Prints the stored value and nothing else: no label, no newline added. To a terminal it also needs `--yes`, so a value does not land on screen and in scrollback by accident. |
| `sudo k3sm keys rotate system/NAME --in FILE` | Stores a new version and makes it current. Earlier versions are kept. |
| `sudo k3sm keys rotate system/NAME --from-version N` | Stores a copy of version N as a new version. The copy is made inside k3sm and the value is never printed. This is the rollback. |
| `sudo k3sm keys rm system/NAME --yes` | Deletes the entry and every version. This cannot be undone, so it needs `--yes`. It also removes an entry `list` reports as corrupt. |
| `sudo k3sm keys rewrap --key-out FILE` | Re-seals every entry under a new master key (see [Changing the master key](#changing-the-master-key)). |

`--work-dir DIR` points every verb at a server work dir other than the default
`/var/lib/k3sm/server`. The data root is its parent.

Exit codes: 0 done, 1 refused or failed, 2 usage error, 3 `rewrap` finished an earlier
interrupted rewrap instead of yours (run it again with a new key).

## Giving a Value

A value never comes from the command line. Anything there is visible to every local user through
`ps` and is saved in your shell history. `put` and `rotate` read the value from:

- `--in FILE`: a regular file. A symlink, FIFO or directory is refused. Keep the file readable
  by root only, and delete it once the value is stored; a file group or others can read draws a
  warning.
- `--in -`: standard input, which is also the default. The value must be piped in:

  ```
  issue-token-command | sudo k3sm keys put system/api-token --in -
  ```

  If standard input is a terminal, the verb refuses rather than wait for you to type the value,
  since typed text is echoed and kept in scrollback.

The value is stored byte for byte. Nothing is trimmed, so a trailing newline in the file is part of
the value. Values are capped at 64 KiB.

## Rolling Back

There is no verb that points an entry back at an old version. A rollback writes the old value
forward as a new version, so the version number only goes up:

```
sudo k3sm keys rotate system/signer-key --from-version 3
```

`show --reveal` piped into `rotate --in -` does the same thing, and the copy is byte-exact:

```
sudo k3sm keys show system/signer-key --version 3 --reveal | sudo k3sm keys rotate system/signer-key --in -
```

Use a pipe here, not `<( ... )`: `sudo` closes inherited file descriptors, so that path would not
open.

## Changing the Master Key

`sudo k3sm keys rewrap --key-out FILE` creates a new master key and re-seals every entry under it.
k3sm never prints the key. Before it changes anything, it writes the new key to `FILE`, which must
not exist yet: it is created new, readable by root only (mode 0600), and an existing file or link
at that path is refused.

Name a file in a directory only root can write, such as a new `sudo mkdir -m 700` directory. The
verb refuses a directory that is not root's or that group or others can write. Keep the file out
of any synced folder (iCloud Drive, Dropbox and the like) and out of Time Machine's reach, since a
copy there outlives the rewrap.

Keep that file until `rewrap` reports success, then delete it. If `rewrap` fails before anything is
recorded under the new key, it deletes the file itself and says nothing was changed. If it is
interrupted or fails partway, some entries may already be sealed under the new key, and that file
is the only copy of it. `rewrap` then keeps the file, says a resume is possible, and you finish
with the same key:

```
sudo k3sm keys rewrap --key-in FILE
```

`--key-in` is for that recovery only. It refuses any key whose fingerprint is not the one the
interrupted rewrap recorded, so it never makes a key you made yourself the master key.

If `rewrap` exits 3, it found an earlier rewrap that had been interrupted, finished that one with
its key, and stopped. Run `rewrap --key-out` again with a new file.

If `rewrap` refuses because `keystore/.user` exists, this build cannot re-seal what that path
holds. The message names the path. Nothing was changed.

After a rewrap, backups of the keystore taken before it no longer open (see below), and the
fingerprints of `opaque` entries change.

## Backing Up and Restoring

The keystore is not part of `k3sm snapshot save`. It lives in three places:

| Path | What it is |
|---|---|
| `/var/lib/k3sm/server/keystore/` | The entries and all their versions. |
| `/var/lib/k3sm/server/cred/keystore-master/` | The master key and its fingerprint. |
| `/var/lib/k3sm/keystore-floor.json` | Root's record of the newest version of each entry, which is how an older copy put back is caught. |

Back up the entries and the master key **to different places**, so a copy of the entries that
leaks does not come with the key that opens it. They are still a matched pair: entries open only
with the master key that was current when they were saved, so take both again after every
`rewrap`.

Your datastore backups copy `/var/lib/k3sm/server/cred`, which holds the master key directory too.
Exclude `cred/keystore-master/` from them, and back the master key up on its own, as below.

To save, while no `k3sm keys` verb is running (`ditto` keeps owners and modes):

```
sudo ditto /var/lib/k3sm/server/keystore /path/to/backup/keystore
sudo ditto /var/lib/k3sm/server/cred/keystore-master /other/place/keystore-master
sudo cp -p /var/lib/k3sm/keystore-floor.json /path/to/backup/
```

To restore the same backup, for example after deleting an entry by mistake, move the live copy
aside rather than deleting it, so a bad restore can be undone:

```
sudo k3sm stop
sudo mv /var/lib/k3sm/server/keystore /var/lib/k3sm/server/keystore.pre-restore
sudo ditto /path/to/backup/keystore /var/lib/k3sm/server/keystore
sudo k3sm start
sudo k3sm keys list
```

Only when `list` shows every entry `ok`, delete the copy you moved aside:

```
sudo rm -rf /var/lib/k3sm/server/keystore.pre-restore
```

The values come back byte for byte: `show --reveal` prints exactly what it printed before. Restore
the master key the same way, from its own backup, if it was lost too.

### Restoring an older keystore/

If you restore a backup that is older than the live keystore, for example from before a
`rotate`, every rotated entry is refused as "older than the recorded floor". That is the check
doing its job: it cannot tell your restore from someone putting an old copy back. If the restore
is deliberate:

1. Stop the server: `sudo k3sm stop`.
2. Move the live `keystore/` aside, as above, and restore `keystore/` and the master key that
   matches it.
3. Remove root's record: `sudo rm /var/lib/k3sm/keystore-floor.json`.
4. Run any keys verb, such as `sudo k3sm keys list`. It writes the record again from the restored
   entries.
5. Start the server: `sudo k3sm start`.
6. Once `sudo k3sm keys list` shows every entry `ok`, delete the copy you moved aside.

Only remove the record when you know the restored entries are the ones you want current, since
the next keys verb accepts them as the newest.
