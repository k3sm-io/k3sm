# Keys

`k3sm keys` keeps key material on a k3sm server: a service's signing key, a third-party API
token, an HMAC key two of your Pods share. Each entry has a name and a history of versions, and
every version is encrypted at rest. You can list the entries, rotate one to a new value, roll it
back, and delete it, all without the value ever appearing on a command line.

Every verb runs as root, on the server that holds the keystore. Never delegate the `keys` verbs
through `sudoers`: `put --in` and `show --reveal` read any file root can read, so a user allowed
to run them can read any root-readable file.

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
- A `system/` name that breaks the rule above is refused with "the entry name is not valid
  (DNS-1123 subdomain); it is not echoed". An invalid flag value is refused the same way: the
  message names the flag, never the value. That holds for the path flags too (`--in`,
  `--key-in`, `--key-out`, `--work-dir`): their errors and warnings name the flag and the reason,
  such as "open --in: no such file or directory (the path is not echoed)", never the path. An
  error from the keystore itself shows the paths under `--work-dir` as `<work-dir>`,
  `<master-dir>` and `<data-root>`.

## The Verbs

| Command | What it does |
|---|---|
| `sudo k3sm keys put system/NAME --in FILE` | Creates the entry at version 1. `--kind ed25519` stores an Ed25519 private key (a 32-byte seed or the 64-byte expanded key) and checks it; the default kind is `opaque`, any bytes. The first `put` on a server creates the master key. |
| `sudo k3sm keys list` | One line per entry: name, kind, current version, when it was created (UTC), fingerprint and status. Status is `ok`, or `corrupt` with the reason. `-o json` prints the same as JSON. Exits 1 if any entry is not `ok`, after listing every entry. |
| `sudo k3sm keys show system/NAME` | Prints the entry's metadata, never its value. `--version N` shows an older version. |
| `sudo k3sm keys show system/NAME --reveal` | Prints the stored value and nothing else: no label, no newline added. To a terminal it also needs `--yes`, so a value does not land on screen and in scrollback by accident. It writes the raw bytes, so a value holding terminal escape sequences is interpreted by the terminal. |
| `sudo k3sm keys rotate system/NAME --in FILE` | Stores a new version and makes it current. Earlier versions are kept. |
| `sudo k3sm keys rotate system/NAME --from-version N` | Stores a copy of version N as a new version. The copy is made inside k3sm and the value is never printed. This is the rollback. |
| `sudo k3sm keys rm system/NAME --yes` | Deletes the entry and every version. This cannot be undone, so it needs `--yes`. It also removes an entry `list` reports as corrupt. |
| `sudo k3sm keys rewrap --key-out FILE` | Re-seals every entry under a new master key (see [Changing the master key](#changing-the-master-key)). |
| `sudo k3sm keys deliver system/NAME --namespace NS` | Declares that the server delivers the entry's current version into the cluster as a Secret (see [Delivering an entry as a Secret](#delivering-an-entry-as-a-secret)). |
| `sudo k3sm keys undeliver system/NAME --namespace NS [--secret S]` | Withdraws that declaration. The Secret stays. |

`--work-dir DIR` points every verb at a server work dir other than the default
`/var/lib/k3sm/server`. The data root is its parent.

Exit codes: 0 done, 1 refused or failed, 2 usage error, 3 `rewrap` finished an earlier
interrupted rewrap instead of yours (run it again with a new key).

## Giving a Value

A value never comes from the command line. Anything there is visible to every local user through
`ps` and is saved in your shell history. `put` and `rotate` read the value from:

- `--in FILE`: a regular file. A symlink, FIFO or directory is refused. Keep the file owned by
  root and readable and writable by root only, and delete it once the value is stored. A file
  group or others can read or write, or that another user owns, draws a warning.
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

`FILE` must be an absolute path; a relative one is refused with "give an absolute path".

Keep that file until `rewrap` reports success, then delete it. After a successful rewrap, `FILE`
is a second copy of the live master key: delete it, or move it to offline storage, and never keep
it beside a backup of the entries. If `rewrap` is refused before it
seals anything under the new key, it deletes the file itself and says nothing was changed. If it
is interrupted or fails partway, some entries may already be sealed under the new key, and that
file is the only copy of it. `rewrap` then keeps the file, says a resume may need it, and you
finish with the same key:

```
sudo k3sm keys rewrap --key-in FILE
```

If the failure came after the master key was already swapped to the new key, `rewrap` says "the
master swap completed but did not sync; this run's key file is now a copy of the live master: keep
it until a later rewrap succeeds, then delete it." The rewrap is done; keep `FILE` as that message
says.

`--key-in` is for that recovery only. It accepts the key the interrupted rewrap recorded, or one
that some entry is already sealed under, and refuses any other, so it never makes a key you made
yourself the master key.

If `rewrap` exits 3, it found an earlier rewrap that had been interrupted, finished that one with
its key, and stopped. Run `rewrap --key-out` again with a new file.

If `rewrap` instead fails while finishing that earlier rewrap, it says:

```
an earlier interrupted rewrap was advanced and did not finish; keep the earlier rewrap's key file; finish with: sudo k3sm keys rewrap --key-in <that earlier file>
```

If what failed was the last step of that earlier rewrap, after its master key was already
swapped in, it says instead:

```
the earlier rewrap's master swap completed but did not sync; run sudo k3sm keys rewrap --key-out FILE again; the earlier rewrap's key file is now a copy of the live master; delete it after this rewrap succeeds
```

That rewrap is done, and a new one retires its key. Until then the earlier rewrap's key file is a
second copy of the live master key: delete it once the new rewrap succeeds.

Otherwise, the earlier rewrap's key file is the one to finish with. `rewrap` keeps this run's `FILE` too;
it was never used, so delete it once the earlier rewrap is finished.

If `rewrap` refuses because `keystore/.user` exists, this build cannot re-seal what that path
holds. The message names the path. Nothing was changed.

After a rewrap, backups of the keystore taken before it no longer open (see below), and the
fingerprints of `opaque` entries change.

## Delivering an Entry as a Secret

A Pod reads a key the usual Kubernetes way, from a Secret. `deliver` tells the server which entry
goes into which Secret:

```
sudo k3sm keys deliver system/signer-key --namespace payments
sudo k3sm keys deliver system/signer-key --namespace payments --secret signer --data-key private.key
```

The server then keeps an `Opaque` Secret in that namespace holding the entry's current version.
The Secret is named after the entry, without `system/`, unless you pass `--secret`, and the
value is under the data key `value` unless you pass `--data-key`. An `ed25519` entry is
delivered as the stored 32-byte seed or 64-byte key, with no PEM wrapping. The entry must exist when you run `deliver`.

- **Rotation reaches the Secret.** After a `rotate`, the server updates the Secret within a
  minute. The Secret's `k3sm.io/keystore-version` annotation says which version it holds.
- **Edits are undone.** The server compares the Secret's data with the stored value, so a hand
  edit is put back within a minute, and logged without the value.
- **An immutable Secret is re-created.** If someone sets `immutable: true` on a Secret the server
  created, the server cannot update its data. After a rotation, or if its data drifted from the
  stored value, the server deletes that Secret, only if its UID is still the recorded one,
  creates it again with the current value, and logs both steps. If only its label or
  annotations changed, the server puts them back without deleting it.
- **Only its own Secrets.** The server labels each Secret it creates
  `k3sm.io/keystore-delivery: <entry>`, and records the Secret's UID in
  `/var/lib/k3sm/server/keystore-delivery-state.json` (owned by the server's user, mode 0600).
  It only ever updates a Secret that has the recorded UID, and puts the label back if someone
  removed or changed it. Anyone who can write Secrets in the namespace can set the label, so the
  label alone does not count: a Secret of that name that someone else created first, or that was deleted and created
  again, is "not created by this server". The server leaves it alone and logs why: delete it, or
  pick another `--secret`. The server never lists Secrets, and deletes one only to re-create an
  immutable Secret it created after a rotation or a change to its data, or after an `rm`.
  After an `rm`, the next sweep deletes the Secret the server delivered for that entry, if it
  still has the recorded UID, the label and both annotations, and logs the names; a Secret
  without them is left alone and logged.
- **A namespace that does not exist yet.** Delivering into it goes to whoever later creates that
  namespace.
- **Withdrawing.** `undeliver` removes every delivery of the entry into that namespace from the
  declaration (with `--secret S`, only the one into Secret `S`), and prints: the Secret stays; delete it with kubectl, and rotate the entry to
  revoke. A Pod that read the value still has it, which is why revoking it means rotating.
- **Deleting a delivered entry.** `rm` does not withdraw its deliveries. For each one still
  declared, it warns: still declared for delivery to `<namespace>/<secret>`; the Secret keeps its
  value: run `k3sm keys undeliver` and delete the Secret. Until you do, the server logs that it
  cannot read the entry, and the Secret holds the last value it delivered.

The declaration is `/var/lib/k3sm/keystore-delivery.json`, owned by root, mode 0644, and only
`k3sm keys deliver` and `undeliver` write it. It decides which namespace the server writes a
Secret into, so the server refuses the whole file, and delivers nothing from it, if it is not
owned by root, is writable by its group or by others, is a symlink, is over 64 KiB, or holds a
field or a version it does not know. The refusal is in the server log, and the verbs refuse that
file too rather than overwrite it. Two `deliver` or `undeliver` runs at once take turns on the lock file
`/var/lib/k3sm/.keystore-delivery.lock`, so neither loses the other's change.

### Limitation: one server

Delivery is for single-server clusters. On more than one server, each delivers from its own
keystore: every server runs the delivery from its own declaration and its own keystore, and
they do not coordinate. Two servers declaring the same Secret do not share it: the one that
creates it owns it, and the other logs that it was not created by this server and leaves it alone.

### While secrets encryption is off

A delivered Secret is stored in the datastore like any other. With secrets encryption off (see
`sudo k3sm secrets-encrypt status`), it would be stored there in plaintext, so the server refuses
every delivery and logs a warning for each target. `deliver` still records the target and warns
that the server refuses it unless the server was started with the override
(`--allow-plaintext-secrets-delivery`). It cannot see a running server's flags, so it does not
know whether the server was.

The better fix is to turn secrets encryption on. To deliver without it instead, turn the override
on:

1. Add `--allow-plaintext-secrets-delivery` to the server daemon's arguments, in the
   LaunchDaemon plist.
2. Restart the server daemon. The server reads the flag only at start.
3. Run `sudo k3sm install`, so the server-arguments record keeps the flag. A flag that is only in
   the plist is lost if you uninstall before the next install (see
   [Server flags across a reinstall](install.md#server-flags-across-a-reinstall)).

To turn it off, remove the flag from the plist, restart the server daemon, and run
`sudo k3sm install`. If the record still carries the flag, remove it there too. A Secret delivered
while the override was on stays as it is: the server does not delete it, and stops updating it.

## Backing Up and Restoring

The keystore is not part of `k3sm snapshot save`. It lives in three places:

| Path | What it is |
|---|---|
| `/var/lib/k3sm/server/keystore/` | The entries and all their versions. |
| `/var/lib/k3sm/server/cred/keystore-master/` | The master key and its fingerprint. |
| `/var/lib/k3sm/keystore-floor.json` | Root's record of the newest version of each entry, which is how an older copy put back is caught. |
| `/var/lib/k3sm/keystore-delivery.json` | Which entries are delivered as which Secrets. It holds no value. |

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
