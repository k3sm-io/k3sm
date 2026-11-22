# Keystore design

Status: under review. This fills in the sections issue 731 and PR #743 left open, for
review on this pull request; the contract sketch in `pkg/keystore/keystore.go` may still
change as that review runs. The second revision answers the review on this pull request
(items 1 to 8) and the maintainer's three rulings on the delivery declaration, the master
directory and the pointer rollback. The third revision answers the re-review of the second:
the threat-model sentence and the forged-pointer residual, the byte-exact `--reveal` round
trip and G21, and the six smaller points (the `master.next` mismatch case, the floor with
no entry for a name, the floor's own refusal text, the override procedure on an existing
cluster, the `ReadRegularFile` path, and the pull request description). The fourth revision
adds "User scope": keys a login user stores without `sudo`, the local socket that serves
them, the `KeyDelivery` API, and their gate rows. Where a user-scope fact changes a Phase A
section, that section says so and names the change that brings it.

One point worth stating up front because it resolves an apparent tension elsewhere: this
design needs no operator passphrase and no KDF. The master key is a file k3sm mints from
`crypto/rand` (see "Master key lifecycle"), so `docs/GO-STANDARDS.md`'s "standard library
only" for Phase A and its "cryptography … stay on maintained libraries" exception are the
same answer here, because every primitive this needs (AES-256-GCM, Ed25519, HMAC, SHA-256,
`crypto/rand`) is already in the standard library.

## Problem

Operators run workloads on k3sm that need key material the cluster's own PKI does not
provide — a service's signing key, a third-party API token, an HMAC key for
request-signing between two native Pods. Today there are two ways to give a Pod such a
value, and both are worse than they need to be:

- **A hand-made `kubectl create secret`.** Plaintext in the kine datastore unless the
  cluster was installed with `--secrets-encryption`
  (`docs/user/limitations.md` § "Ingress TLS Keys and Secrets at Rest"), and
  `k3sm snapshot save` copies it into every snapshot in the clear
  (`docs/user/backup-restore.md` § "Snapshots Hold Secrets in Plaintext"). No listing, no
  version history, no rotation workflow — a rotation is a manual edit with no rollback.
- **Baking the value into an image or a ConfigMap.** Worse on every axis above.

Secrets encryption (`pkg/executor/secretsencryption.go`) protects the *datastore*, not an
individual value: one static key, no rotation, nothing Phase A can build on for versioning.
k3sm has no place of its own to keep key material — encrypted at rest, inventoried, rotated
with a rollback path — before it ever becomes a Secret.

## Scope

Phase A only: named, versioned entries (Ed25519 keys and opaque bytes), encryption at
rest, rotation, list, delete, master key re-wrap, the `k3sm keys` verbs (including the one
that declares a delivery target) and the delivery reconciler. Nothing in Phase A changes
`k3sm install`, the datastore, or an existing Secret.

Out of scope here: keys that never enter the datastore (Phase B) and KMS v2 envelope
encryption of the datastore (Phase C). Each is a separate issue after Phase A lands.

The user scope ("User scope") is layered on a finished Phase A and is specified separately.
It does change `k3sm install` (a socket directory and two append-only logs), adds a local
socket and adds a CRD; the statements in this section and in "Non-goals" hold for Phase A
and the system scope.

## Threat model

This statement is fixed. One node is one trust domain, and every native Pod runs as the
same service user. The keystore provides encryption at rest, rotation, and delivery gated
by RBAC. It does not isolate one native Pod from another, and it does not protect key
material from root on the host.

Concretely: once a key is **delivered** as a Secret, every native Pod on the node can read
it exactly as every native Pod can read every other Secret today
(`docs/privilege-model.md` § "One residual limitation: no per-Pod uid isolation") —
delivery is a convenience and an inventory improvement, never a confidentiality
improvement over a hand-made Secret. The value is on the *host* side: encrypted at rest
instead of plaintext in kine, named and versioned instead of an anonymous datastore row,
rotated by one command with a rollback path instead of an unrecoverable manual edit.

One consequence shapes the design. Ownership is not a barrier between a Pod and the
service user's files, because they share a uid. What keeps a confined native Pod out of
`<work dir>/server` is runtimed's Seatbelt profile, which denies it read and write there
(`DaemonTreeSubdirs` in runtimed's `pkg/sandbox`). The denies are emitted first and narrow
re-allows follow them, so the order alone protects nothing; what keeps a caller-supplied extra
path from re-opening the tree is the profile's path validator, which refuses any such path
under a protected prefix ("User scope", "Pod denies"). That is a profile rule, not a
permission, and it names the default work dir. So a record's integrity against a writer that cannot read the
master (a stale restore, a stray file copy) rests on an authenticated record, and the one
fact that must hold even against a writer that can only touch the service user's files lives
where only root can write it. Neither is a defence against a process that runs as the
service user outside that profile and reads the master: that process can already read every
entry, and what it can additionally forge is stated under "Pointer sequence and floor".

Two later facts amend this paragraph. The keystore's files directly under the data root
(Phase A's `keystore-floor.json` and `keystore-delivery.json`, and the user scope's files)
are denied to every Pod by runtimed's data-root denies, which today cover `server` and `agent`
(`DataRootDenySubdirs`) and which the sandbox change that comes with the user scope widens to
every `keystore-*` name in the data root and the whole `keystore-sock/` tree, the socket's
directory; the data-root
denies are used, not `DaemonTreeSubdirs`, because a node's Pod root can differ from its data
root. Both files are root 0644, so a local login user can still read them (residual 11). Whether a Pod can read Phase A's two data-root files
before that change was not measured: the files did not exist on the rig (K0 amendment 2026-11-21); the denies land either way. And the user scope
adds an ownership boundary on the store and its API, not a confidentiality boundary between
Pods ("Threat model for the user scope").

## Storage format and master key

The fixed decisions:

- Standard library only.
- The master key is a mode 0600 file owned by the service user, with a fingerprint beside
  it, in a directory separate from the entries: its own subdirectory of the server's
  credential directory, `/var/lib/k3sm/server/cred/keystore-master/` (the maintainer's
  ruling).
- Each version is sealed with AES-256-GCM. The additional data is a length-prefixed
  encoding of six fields (record-format version, scope, kind, name, version, generation),
  never a bare concatenation; the scope is supplied by the opening store (see "Scope").
- The nonce is 96 bits from crypto/rand, fresh on every seal including Rewrap, never
  derived from the name or the version.
- The current pointer flips last on rotation. It is written to a temporary file and
  renamed into place, with the file and its directory fsynced, and its target version is
  covered by the same authenticated record, so a writer of the files cannot roll an entry
  back by editing the pointer alone. A previously valid pointer copied back over the
  current one is refused as well (the maintainer ruled that residual is not accepted):
  "Pointer sequence and floor" says how.
- Rewrap is two-phase: the new master is written beside the old one, every record is
  re-sealed, then the master flips. A crash leaves a state a rerun completes and nothing
  unreadable.
- A Delete followed by a new Put of the same name at version 1 must not reopen a replayed
  old record: the record carries a per-entry generation, bound into the additional data.
- The master file is opened with O_NOFOLLOW and checked with fstat on the open descriptor
  (owner, mode) and against its fingerprint. The fingerprint detects a wrong file, not
  tampering. `sudo k3sm keys` runs as root against a file owned by the service user, so
  ownership is checked, not assumed.
- Entry names are validated before they become file names: each must be a Kubernetes
  DNS-1123 subdomain, 1 to 253 bytes of dot-separated labels of lowercase letters, digits
  and `-`, each label beginning and ending with a letter or digit. That rules out a path
  separator and a name made only of dots, and also two names that differ only in case
  (APFS is case-insensitive by default, so they would share one directory while the record
  binds the name as given) and a dot name (the store's own `.lock` and temporary files are
  dot names). The default delivered Secret name is the entry name, so the rule also keeps
  that default a valid Kubernetes name. Every operation checks the name, so the rule cannot
  be narrowed later without stranding entries made under it.
- The fingerprint of an Ed25519 entry is a digest of its public key; that of an opaque
  entry is keyed (an HMAC under a key derived from the master) or truncated, never a plain
  hash of the value, so List output is not a guessing oracle for a low-entropy value.
- An Ed25519 value is the 32-byte seed or the 64-byte expanded private key, and is
  checked on Put.

### On-disk layout

```
/var/lib/k3sm/                          data root, root:wheel
  keystore-delivery.json                root:wheel 0644: the declared delivery targets
  keystore-floor.json                   root:wheel 0644: per-entry pointer floor
  server/                               the server work dir
    cred/                               0700, service user (existing)
      encryption-config.yaml            existing secretbox pair, unchanged
      encryption-config.sha256
      keystore-master/                  0700, service user: the master pair, nothing else
                                        (a crash mid-write can leave an ignored temp file)
        master                          0600: 32 random bytes
        master.sha256                   0600: hex SHA-256 of the master bytes
        master.next                     present only mid-Rewrap
        master.next.sha256
    keystore/                           0700, service user, a SIBLING of cred/
      .lock                             0600, the one lock file (see "Concurrency")
      .user                             reserved for user scopes (see "Scope"); created by the
                                        user-scope store, laid out under "User scope"
      <name>/                           one directory per entry; created by Put with a bare
                                        Mkdir (never MkdirAll), so existence and creation
                                        are one atomic check
        generation                      0600, 16 random bytes, hex; written once by Put,
                                        never rewritten by Rotate
        v1, v2, …                       sealed records, one per version
        current                         sealed pointer record naming the current version
```

The master pair stays under `cred/`, already the home for small, singular,
security-critical control-plane files, but in a subdirectory of its own; entries get their
own top-level directory. This is deliberate rather than nesting entries under `cred/`: an
operator's habitual `cp -r cred/ backup/` must not also sweep up every entry's version
history, and a backup of `keystore/` alone must not also carry the one file that unlocks
all of them.

`cred/` and `cred/keystore-master/` are created, if absent, at 0700 and owned by the
service user, with the same discipline the installer's `WriteServiceUserFile` uses for the
encryption pair (owner and mode bound to the open descriptor before anything is published)
but not that function: it lives in `pkg/install`, chowns its directory by name, and fsyncs
nothing, where the keystore's crash order needs the file and the directory fsynced. Every
directory is opened as an `os.Root` and checked (a real directory, the service user's,
closed to group and others), and `keystore-master/` is opened relative to `cred/`, never
by its full path, because the service user owns `server/` and could replace `cred/` with a
symlink. The two root-owned files under the data root are the exception to "owned by the
service user": they exist because a Pod must not be able to write them. The user scope adds
service-user-owned files and a directory under the data root, created by `sudo k3sm
install` ("User scope", "On-disk layout").

### Master key lifecycle

- **Who mints it.** Only k3sm, from `crypto/rand`, 32 bytes. An operator never supplies a
  master key, to any verb, and no verb accepts an operator-made key. `rewrap --key-out FILE`
  saves the key k3sm minted so a crashed rewrap can be finished; `rewrap --key-in FILE`
  only re-reads such a key: its SHA-256 is the `master.next.sha256` an interrupted rewrap
  recorded, or some record already opens under it and not under the live master.
- **When it is created.** By the first root-run `k3sm keys put` that finds no master and
  an empty or absent `keystore/`. The one other state a put mints over, still only with
  `keystore/` empty, is the one an interrupted mint leaves: a master that passes every
  check of its own with no fingerprint file beside it. A master that fails a check of its
  own is refused, never replaced. There is no install step: Phase A changes nothing in
  `k3sm install`, so the keystore is available on a cluster that already exists, with or
  without `--secrets-encryption`, and nothing about that cluster is migrated or imported.
- **When it is never created.** If `keystore/` holds entries and the master is missing,
  every verb refuses with `ErrMasterMissing`. A master is never re-minted over existing
  entries, because that would make every entry unreadable while looking like a repair.
- **Who replaces it.** `k3sm keys rewrap` (see "Rewrap") mints a new master and re-seals
  everything under it. Phase A exposes it as a verb because the maintainer ruled the
  master is created and rotated only by root-run verbs. `Store.Rewrap` keeps taking the
  new key as an argument so tests can drive it; the verb is its only production caller and
  passes a freshly minted key, or, with `--key-in`, the one an interrupted rewrap recorded.
- **Who reads it.** The server process (the delivery reconciler), as the service user,
  through the same checked open as every other reader.

### Record encoding

A version record and the current pointer share one binary encoding (not JSON — every
field is fixed-width or itself length-prefixed, and these files are never meant to be
hand-read):

```
offset  len  field
0       1    record format version (1)
1       1    kind (1 = Ed25519, 2 = Opaque; 0xFF for the current-pointer record)
2       2    name length N (big-endian uint16)
4       N    name (must match the directory this file lives in)
4+N     8    version (big-endian uint64)
12+N    16   generation (opaque 16 bytes, from the entry's `generation` file)
28+N    8    created (Unix seconds, big-endian int64)
36+N    12   nonce (96 bits)
48+N    4    ciphertext length C (big-endian uint32)
52+N    C    ciphertext (AES-256-GCM output: plaintext + 16-byte tag)
```

A version record's plaintext is the stored value. The pointer record's plaintext is 16
bytes: the 8-byte version number it names, then an 8-byte big-endian pointer sequence
(see below). It is deliberately tiny, so the pointer carries no information an attacker
without the master key could use even if every other record were absent.

`created` is a fixed-width integer, not text: a fixed 8-byte Unix-seconds value has no
string to parse, so it has no parse failure to defend against. It is **unauthenticated
display metadata**: it is not in the additional data, and a record whose `created` was
edited still opens.

**Associated data** is six fields:

```
AAD = LP(record-format-version) ‖ LP(scope) ‖ LP(kind) ‖ LP(name) ‖ LP(version, 8B BE) ‖ LP(generation, 16B)
```

`LP(x)` is a 4-byte big-endian length followed by `x`, so no field's bytes can be shifted
into its neighbor. The scope (see "Scope") is **supplied by the opening store, never read
from the file**: it is not in the record's bytes, the header and offsets above do not change
for it, and the store binds it from its own identity, as it checks the name against the
directory the file lives in. `created` is intentionally **not** in the AAD: it is display metadata,
and binding it would turn an honest clock difference (a restored backup, a changed system
clock) into an authentication failure indistinguishable from real tampering of the value.

**Generation closes the Delete-then-Put replay question.** Entry files are named by
version number inside a per-name directory, so after a Delete and a later Put of the same
name, the new entry's `v1` occupies the exact path the old entry's `v1` once did. If an
operator restores a stale backup of just that one file onto the live keystore, an AAD built
only from (format, kind, name, version) is identical between the old, deleted entry's `v1`
and the new entry's, so the restored ciphertext would open cleanly and silently reintroduce
key material the operator believed was gone. A 16-byte random generation, minted fresh by
every Put (including one that follows a Delete) and carried unchanged through an entry's
whole life, breaks that: the restored file's AAD names the old generation, the live AAD for
that name uses a new one, and the GCM tag fails to verify, refused as `ErrCorrupt`. It is a
random value rather than a counter so there is no persisted "next generation" state that
could drift out of sync with reality.

The generation does **not** cover a stale pointer: it is the same for an entry's whole life
and old versions are kept, so an earlier `current` for the same entry still authenticates.
That is what the next section closes.

### Pointer sequence and floor

A pointer carries a monotonic sequence number. Put writes it as 1, every Rotate writes the
previous value plus 1, and Rewrap re-seals it unchanged. The store also **records** the
highest sequence it has committed for each entry, in `keystore-floor.json`:

```json
{"version": 1, "scope": "system", "entries": {"signer-key": {"generation": "<hex>", "seq": 7}}}
```

`scope` names the scope whose entries the floor records, and is always `system`: the floor
belongs to the system store. The file is parsed strictly: a missing or other `scope`, a
`version` other than 1, any field the format does not have (at the top or in an entry), a
generation that is not 32 lower-case hex digits, a sequence of 0, a name `put` would refuse,
data after the object, or any byte that differs from the one encoding a root-run verb
writes (compact, fields in order, entries sorted, an optional final newline; so a
duplicate key or a differently cased one is refused, never resolved) is `ErrCorrupt`, with the floor's own message rather than the
restore-from-backup default. That message says what removing the file costs: replay
protection is off until a root-run verb rebuilds the floor, and the rebuild records
whatever pointers are under `keystore/` as current, so the file is removed as root only
once those pointers are known to be current.

The file is bounded at 4 MiB, on read and on write, tombstones included (see "A deleted
entry put back is refused" below for their share and how they are pruned). A floor write whose result would be
larger is refused before anything is written, so the floor on disk is always one that
reads. Put and Rotate check for room before they write the entry, so a full floor refuses
them with no entry or pointer file written. Other entries' floor records may already have
been raised by the floor sync that runs first; that is safe, because a raise only raises.
A root-run verb's raise leaves out an entry that does not fit
(that entry's floor stays behind its pointer, which readers accept), refuses a keystore
with more entries than the file can hold, and Delete still runs over a full floor, since
it is how room is made.

A reader that opens `current` refuses it, as `ErrCorrupt` with the message below, unless
**both** hold: the pointer's generation equals the floor's generation for that name, and the
pointer's sequence is at least the floor's. So an older `current` that still authenticates
is refused.

**What the reader does when the floor has nothing to compare against.** Two cases, both
accepted, because there is no recorded fact to refuse against:

- *The floor file is absent.* The check is skipped for every entry, and the next root-run
  verb writes the file from the authenticated pointers (this is also the restore procedure).
- *The floor file exists but has no entry for the name.* This is the state an interrupted Put
  leaves (`current` written, floor not yet), and the state after a Delete whose tombstone was
  pruned. A name with only buried generations, none the pointer's, counts as no entry. The
  pointer is accepted if it authenticates, and the next root-run verb records its sequence
  and generation. The residual is a stale backup of a deleted entry whose tombstone was
  pruned, restored under the same name: it is accepted, which is the deliberate-restore case
  the procedure under "Backup and snapshots" already covers, and it reopens nothing the
  generation check (G4) does not already refuse for an entry that was re-created. A deleted
  entry whose tombstone stands is refused (see "A deleted entry put back is refused").

**The refusal message is its own text, not the `ErrCorrupt` default.** `ErrCorrupt`'s stock
message tells the operator to restore from backup, which for a stale pointer is the opposite
of the fix: an older backup is exactly what produced it. A floor refusal wraps `ErrCorrupt`
(so `errors.Is` still matches) and reads: `keystore entry "NAME": the current pointer
(sequence S) is older than the recorded floor (sequence F); an older copy of this entry was
put back. Do not restore from backup. If that was deliberate, follow "Restoring an older
keystore/" in docs/user/backup-restore.md`.

**Where the floor lives is the deciding choice.** A floor kept in the service user's
tree would be one more file that any process running as the service user can copy back, and
the check would only be as strong as that process's patience. `keystore-floor.json` is
therefore root:wheel 0644 directly under the data root. The data root is root:wheel 0755
(`pkg/install/statetree.go`), and on macOS the right to create, rename or unlink an entry is
the parent directory's write bit, so the service user cannot replace the file. It is
written only by root-run verbs, and read with the same check
`pkg/addons` applies to the manifest directory (`rootOwnedNotShared`, judged on the opened
descriptor with O_NOFOLLOW): refused unless root-owned and not group/other-writable. Every
mutating verb is already root-run, so no write path loses anything by this; the service
user, which only reads, never needed to write it.

The write order on a change is: the record, then the pointer, then the floor. Before any of
it, a verb that changes the keystore checks that it can write the floor and takes the floor's
lock (see "Concurrency"), so a caller that cannot write the floor changes nothing, and a
first Put mints no master.

- **Put:** write `generation`, `v1`, `current` (sequence 1), then set the floor entry.
- **Rotate:** write the new version file, flip `current` (sequence + 1), then raise the
  floor to that sequence.
- **Delete:** bury, then take `keystore/.lock` and judge `keystore/`, then remove
  `current`, then the entry directory. The burial of the floor's live record comes first,
  under `keystore-lock` alone, because the service user controls everything after it: it
  owns `keystore/.lock` and can hold or replace it, it owns `keystore/` and can give it a
  refused mode, and it owns the entry's files and can make their removal fail (a `uchg`
  flag makes unlink fail even for root). If the `.lock` or `keystore/` step fails after the
  burial, Delete returns an error saying the entry is already deleted and refused, its tree
  was not removed, and `rm` should be rerun once the lock is free. Once `.lock` is held,
  Delete buries the directory's authenticated generation, when there is one (below). When the removal answers `EPERM`, Delete clears the user locking flags (`uchg`,
  `uappnd` and `uunlnk` only, through the opened descriptor, never following a symlink) on
  `keystore/` itself and on the entry's files, and removes once more; root may clear those.
  It clears a file's flags only when the service user owns it and, for anything but a
  directory, when it has one link: a hard link shares its flags with names that may be outside
  the keystore. A symlink is never opened, so a flag the service user set on a symlink itself
  (`chflags -h`) stays, and the symlink is left behind as an accepted residual, as the hard
  link is: the burial has already landed, so the entry stays deleted and refused. The clear
  opens at most 4096 files in all and stops with the verb's context; past the budget it fails
  and the directory is left behind (`TestDeleteFlagClearBudget`). A flag left in place is
  named in the error, a flag on `keystore/` included. A removal that still fails, or a crash during it, leaves the entry already deleted and
  refused: Delete returns an error saying so and that the directory is left behind, and
  `rm` run again removes the directory without changing the floor. A floor raise at the
  start that cannot complete (more names under `keystore/` than a read takes, which the
  service user can plant, or a keystore larger than the floor holds) does not stop the
  burial: Delete buries from the floor alone and logs the failure at Warn.

**A deleted entry put back is refused: the tombstone.** A completed Delete does not remove
the name's floor record. In the same floor write it buries a generation: it adds it to the
name's buried set, a per-name list of generations a Delete removed, each with a delete
sequence. The floor file gains a `tombstones` object after `entries`, mapping a name to its
buried set, oldest first:

```json
{"version": 1, "scope": "system", "entries": {"signer-key": {"generation": "<hex>", "seq": 7}}, "tombstones": {"old-key": [{"generation": "<hex>", "deleted": 3}], "signer-key": [{"generation": "<hex>", "deleted": 1}, {"generation": "<hex>", "deleted": 4}]}}
```

- *The record.* `deleted` is the delete sequence: one more than the highest `deleted` in the
  floor, or 1 when there is none. It orders burials for pruning and means nothing else, so
  when it would pass 2^53 the next Delete first renumbers every burial 1 to n in its order: the
  sequence never wraps. A name may hold a live entry and a buried set together, as
  `signer-key` above: a Put of a deleted name records its new generation live and keeps every
  generation buried before it. A live generation is never also buried.
- *What Delete buries.* Delete buries the generation the floor records live for the name,
  root's own record, whatever the deleted directory's `generation` file says. That file is in
  the service user's tree, so Delete also buries the generation it read only when the master
  is loaded and the directory's `current` authenticates under that generation, and only when
  it is not the live one or already buried: with no live record, a Put that crashed after its
  pointer and before its floor write; with a live record of another generation, a directory
  of a generation the floor no longer records live. The floor's live generation is buried
  first, so it has the lower delete sequence. A planted
  generation file under a name with no live record therefore buries nothing, and can never
  push a real burial out of the per-name cap or the tombstone budget below. Delete never removes or replaces a
  buried generation; a floor write never lowers what the floor refuses on data from the
  service user's tree. A directory planted under a deleted name with a changed `generation`
  file and removed by `rm` therefore leaves the buried set as it was, and a decoy directory
  swapped in under a live name before `rm` buries the floor's live generation, not the
  decoy's. With neither a live record nor an authenticated pointer, Delete records nothing.
- *No directory to delete.* Delete buries the live record whatever stands under the name: no
  directory (or no `keystore/` at all), a non-directory it unlinks, or an incomplete Put it
  removes. It then succeeds and logs at Warn that the entry directory was already gone and
  the deletion is recorded. Only a name with no live record answers `ErrNotFound`. So an
  entry directory moved away while root runs `rm` and moved back afterwards is refused, and
  so is the copy an earlier build's Delete, which removed the directory before its floor
  write, left when it crashed between the two, once `rm` runs again.
- *The per-name cap.* A name keeps at most 64 buried generations. A Delete that buries a 65th
  drops the name's oldest, and that is a prune (below): logged, and the only way, besides the
  floor's own prune, that a buried generation leaves the floor. The cap is a backstop, not the
  main eviction: the tombstone budget below prunes oldest first across every name, so churning
  one name pushes out its own burials only after 64 deletions, and never another name's sooner
  than age requires. It stays a cap rather than going away so one name's churn cannot fill the
  tombstone budget alone; a name's burials are a slice in memory, at most 64 long.
- *The caps only ever rise.* The per-name cap (64) and the tombstone budget (1 MiB) may only
  ever be raised in a later release, never lowered: the parser refuses a floor over either
  cap as malformed, so a lower cap would make a floor an earlier release wrote, or a
  moved-aside floor the restore merge reads, refuse every root verb. A floor at the caps
  never fails a write: the write prunes.
- *Refusal.* A reader or verb that opens an entry directory whose generation is in the name's
  buried set refuses it as `ErrCorrupt`, with the floor's own message: an older copy of a
  deleted entry was put back. Its advice leads with a safe action. With no live record for
  the name, that is `rm`: a copy the operator did not put back is removed, and the floor
  stays as it is. Only then does it say not to restore from backup, and give the same-backup
  restore recipe in the user docs as the deliberate case, warning that it brings back every
  key deleted since the backup. When the floor also records a live entry of the name under
  another generation, the live entry's directory is missing, so the message says that, says
  to put the live entry's directory back in place of the copy (that copy is accepted), and
  says not to run `rm`, which would delete the live entry; it never says the floor stays as
  it is. The refusals of an older sequence or of another generation with nothing buried lead
  likewise with putting back the copy the floor records, then say not to restore from backup.
  That holds for `Current`, `Get`, `List`
  (the entry is listed with `Err`), Rotate, Rewrap (which refuses, as for any entry `List`
  marks corrupt), and the floor raise at the start of every root verb, which never records a
  buried generation, while the name is live under a newer generation and after it is deleted
  too. A put-back directory with no `current`, in the shape a crashed Put leaves, is damage
  rather than an interrupted Put when its generation is buried: listed with `Err`, and
  `ErrExists` from Put. Put of a name whose put-back directory has a `current` answers
  `ErrExists` too, so the operator removes it with `rm` first. `rm` removes a put-back
  directory as it removes any corrupt entry, and keeps the buried set. A directory of a
  generation not in the buried set under a name with no live entry is a Put that crashed after
  its pointer and before its floor write: the raise records it live beside the buried set.
- *Put keeps the buried set.* A Put of the name mints a fresh generation and records it live
  at sequence 1; the buried set stays. Dropping it would let an old copy of the first
  generation back once the second is deleted too. A live record of another generation, which
  only a Delete interrupted before its floor write leaves (or an entry directory moved away),
  is buried by the Put first, as that Delete would have, so its copy stays refused once the
  new generation is deleted too. `rm` of an absent name with no live record answers
  `ErrNotFound` and writes no floor. Delete of an interrupted Put under a name with no live
  record also answers `ErrNotFound` and buries nothing, since that generation never
  committed a pointer.
- *Bound and pruning.* Tombstones share the floor's 4 MiB cap, split this way: live entries
  may use all of it, and the `tombstones` object at most 1 MiB of it, and only what live
  entries leave. Every floor write, after it applies its own change, prunes buried
  generations oldest first (lowest `deleted`, then by name) until the tombstones fit in 1 MiB
  and the file fits in 4 MiB; a name left with no live entry and no burial is removed. A live
  entry is never pruned. Past the cap the floor therefore prunes rather than fails closed, and
  the room check Put and Rotate make counts only live entries, so a burial never refuses a
  Put or a Rotate; `errFloorFull` keeps its meaning, that the live entries alone would not
  fit. The residual of a pruned burial is the behaviour before this change: an old copy of
  that deleted entry put back under its name is accepted, unless the name's live entry of
  another generation refuses it. The oldest burials are the longest-revoked keys, and any
  root-run churn, bulk puts included, can evict them. That is also why no unprivileged caller
  may ever drive Put or Delete of the system store: pruning is root-only on the assumption that
  only root makes the writes that churn the floor, and a caller that could drive them could
  evict any revoked key's burial at will. So every drop is visible: each prune,
  the per-name cap's included, logs at Warn through `log/slog` with the count and the names.
  A Delete whose floor writes drop any burial, its own new one, another name's, or the name's
  oldest at the per-name cap, fails with `ErrTombstoneEvicted`, naming the count (the floor
  lock collects every burial its writes' prunes drop): the entry is deleted, its burial and its
  tree removal complete as usual, and the error is reported as committed, so `keys rm` prints
  the deletion and exits 4. Every return of Delete reports a pruning write it made, so a
  Delete that finds nothing to delete after a floor raise that pruned is a committed
  `ErrTombstoneEvicted` joined to `ErrNotFound`: `keys rm` exits 4 without printing a
  deletion (`DeleteDone`, `TestDeleteNotFoundReportsEviction`). `keys list` and `keys show`
  print the eviction of the floor raise they make first as a warning on stderr and exit 0,
  since that write is not the change the operator asked for (`TestKeysReadVerbsWarnEviction`).
  A Delete whose own new burial the same write prunes also logs
  that. `keys floor merge` exits 4 too when its report names a dropped burial. A `--keep` name
  the merge keeps nothing for refuses it, with nothing written, and each kept name is warned
  about on stderr as well as listed. 1 MiB holds about 3,500 burials of the
  longest names and about 16,000 of short ones.
- *Deletion without the master.* Delete still works without the master. Burying the floor's
  live record needs only that record and the floor lock, never a key. Over a full floor Delete
  still runs, since the burial it adds is pruned before any live entry is touched. Without the
  master no pointer can vouch for a directory's generation, so a master-less Delete under a
  name with no live record buries nothing. That includes an absent floor file, which then stays
  absent until the next root verb that opens the master rebuilds it, and a Put that crashed
  after its pointer under a name with no live record (none at all, or only burials): that
  generation is lost from the floor, and a copy of it put back later is accepted. The remedy
  is to run `rm` with the master available: the floor raise at its start records the crashed
  Put's pointer live, and the Delete buries it. Any Delete that buries nothing, of a directory
  with a `current` under a name the floor records nothing live for, whose generation it does
  not already bury, logs this residual at Warn, naming the remedy: rerun `rm` with the master.
  That covers a master-less Delete and, with the master, a pointer that does not authenticate.
  *Residual (a directory's generation waits for `.lock`).* A Delete of a name with no live
  floor record buries nothing until it holds `keystore/.lock`: the directory's generation is
  buried only once the master opens its pointer, and that read is under `.lock`, which the
  service user can hold past the bounded wait or replace. Such a Delete therefore records
  nothing while `.lock` is unavailable, unlike the burial of a live record, which lands under
  `keystore-lock` alone. Recorded, not built.
- *Format.* The floor stays format version 1: nothing has shipped, so this is a hard cut with
  no migration. `tombstones` is optional and comes after `entries`; a verb writes it only when
  the floor holds a tombstone, so `"tombstones":{}` is not the encoding a verb writes and is
  refused. A floor with no `tombstones` field, the shape every earlier build wrote, parses as a
  floor with no tombstones. A burial is parsed as strictly as an entry: a name `put` would
  refuse, a generation that is not 32 lower-case hex digits, a `deleted` of 0 or above 2^53,
  a field the format does not have, an empty or over-cap buried set, burials not oldest
  first, a delete sequence used twice in the floor, a generation buried twice, a burial of the
  name's live generation, or tombstones over 1 MiB is `ErrCorrupt` with the floor's
  message. A reader that rejects unknown fields, a build from before this change included,
  refuses a floor with tombstones whole, so it fails closed.

A crash after the pointer flip but before the floor write leaves the floor one behind the
pointer, which the rule above accepts (pointer at or above floor). So that the lag does not
become a window, **Put, Rotate and `RaiseFloor` begin by raising each entry's floor to its
authenticated pointer's sequence**, under the lock, and so does Delete when the master
opens. Delete must work without the master, and with none it raises nothing: it changes
only its own entry's floor. The read verbs (`k3sm keys list` and `show`) take no lock that
writes, so they raise the floor by calling `RaiseFloor` at their start; until the CLI that
does so lands, a floor that lags its pointer is raised by the next write verb or
`RaiseFloor`, and readers meanwhile accept the lag. A live floor record for a name with no
directory (a Delete that crashed after removing the directory, before its floor write) is
buried by a retried `rm`, which succeeds, or by the next Put of the name, which buries it
before it records its own generation.

**The residual against a process that can read the master.** The pointer's authentication
is keyed by the master, and the master is a 0600 file owned by the service user. A process
running as the service user outside runtimed's profile can therefore read it, seal a fresh
`current` that names an older version at the floor's sequence, and pass both checks. The
floor is not a defence against that process, and nothing here should be read as one. What
the floor refuses is a pointer put back by a writer that **cannot** read the master: a stale
restore, a stray file copy, a script that copies a directory over the live one. That is the
case the maintainer's ruling asked to close, and it is worth having. The same-user model
accepts the forging case, in the same class as that process deleting the entries outright,
or reading every one of them: a process that holds the master has the keystore.

What this does not do either, stated plainly: root can replace the pointer and the floor together,
and the threat model does not defend against root. A deliberate restore of an older
`keystore/` from backup is the same act, so it is refused until root removes
`keystore-floor.json`, which a root-run verb then rebuilds from the restored pointers.
"Backup and snapshots" gives that procedure.

### Fingerprint construction

Ed25519: `hex(sha256(publicKey))` — a plain digest is fine since a public key is not
secret, mirroring `EncryptionKeyFingerprint` in `pkg/executor/secretsencryption.go`.
Opaque: `hex(HMAC-SHA256(fpKey, value))` truncated to 16 bytes, where
`fpKey = HMAC-SHA256(master, "k3sm-keystore-fingerprint-v1" ‖ 0x00 ‖ scope)` — a fixed-label
HMAC under the master, with the label including the scope, computed once per master and
scope rather than per entry. The key that seals records is derived the same way,
`sealKey = HMAC-SHA256(master, "k3sm-keystore-seal-v1" ‖ 0x00 ‖ scope)`, so the master keys
only HMAC under fixed labels and is never used both as a raw AES-GCM key on one path and an
HMAC key on another. A scope holds no zero byte, so no two (label, scope) pairs give one
input, and one master gives each scope its own keys. The `system` scope derives from the
master directly, as here; a user scope seals under its own scope key, wrapped by the
master, as "User scope", "Key hierarchy" specifies.

**Where it is stored: nowhere.** It is computed when a version is read, from the decrypted
value. `list` therefore opens each version once; that is one small AES-GCM open per version
(values are capped at 64 KiB), and `list` is an operator command, not a hot path.
**It changes across a Rewrap** for opaque entries, because its key derives from the master;
an Ed25519 fingerprint does not. A fingerprint copied into a runbook goes stale after a
Rewrap, and the verb says so when it finishes.

### Scope

Every record is sealed under a scope, bound into its associated data and its key labels.
Phase A writes only `system`, the scope of the node's own store. The grammar is `system`, or
the scope string `user/<uid>`, where `<uid>` is the user's decimal macOS uid: digits only, no
leading zero unless it is `0`, and fitting in a uint32, so each uid has exactly one scope
string. It is the uid and never the short name, because renaming a macOS account keeps the
uid, and a scope bound to the short name would make every record of a renamed user fail to
open. The store refuses any other scope before it seals, opens or derives anything. Entry
names cannot contain `/`, so the qualified names `system/<name>` and `user/<uid>/<name>` are
unambiguous: there is no shadowing between scopes and no search order.

Amended by the user scope: the shared entry grammar ("User scope", "Scope strings and names")
makes `user/0` invalid, since root has no user scope, so a uid is 1 to 4294967295. The
user-scope store narrows `checkScope` to match (U11).

Two kind bytes are reserved for user scope: `0xFE`, a wrapped scope key, and `0xFD`, a sealed
per-user delivery list. No record carries either yet, and a reader refuses them, like every
kind byte not in "Record encoding", as `ErrCorrupt`. The entries'-directory name `.user` is
reserved for user scopes too, and nothing creates it yet. The first-Put mint counts it as an
entry, whatever its type, so a missing master with only `.user` present is
`ErrMasterMissing`, never a new master. History: Phase A's Rewrap refused with
`ErrScopeUnsupported`, writing nothing, while `.user` existed, whatever its type, since that
build could not re-wrap user scopes and a master rewrapped under them would have left them
unreadable; the refusal named the reserved path. The change that re-wraps scope keys lifted
it (below). A user scope's store, its own key wrapped by the master, its
non-root API, RBAC, delivery and on-disk location are specified under "User scope"; the
scope is in the format now so that adding one needs no format change.

Amended by the user scope: the user-scope store writes kind `0xFE` records (`scope.key`)
and creates `.user`; the change that adds the sealed delivery record writes kind `0xFD`.
The same change that adds the delivery record re-wraps scope keys in Rewrap and lifted the
`ErrScopeUnsupported` refusal; every build before it kept the refusal, so a rollback to one
cannot rewrap the master out from under user scopes ("User scope", "Rewrap of scope keys").

### Master file trust

`keystore-master/master` is opened `O_RDONLY|O_NOFOLLOW`; owner and mode are read off the
*same open descriptor* (fstat, not a separate lstat — the same TOCTOU closure
`ReadRegularFile` in `pkg/install/install_darwin.go` already documents), checked against the
service uid and mode 0600, and its content's SHA-256 checked against the fingerprint file.
Any of the three failing is `ErrMasterUntrusted`; the file being entirely absent while
`keystore/` holds entries is `ErrMasterMissing` — the same two-refusal split
`pkg/executor/secretsencryption.go` already makes for the encryption pair
(`ErrEncryptionKeyFileMode`/`ErrEncryptionKeyFileOwner` vs. `ErrEncryptionKeyMissing`).

While a Rewrap is mid-flight, the master's content is trusted if its SHA-256 equals
`master.sha256` **or** `master.next.sha256`. That is what makes the final swap safe to
interrupt (see "Rewrap").

### List, when one entry is corrupt

Decided: per entry, not for the whole call. `Store.List` returns every entry it can name.
An entry whose generation file, `current`, or any version `current` covers fails to open
(missing, corrupt, stale, or truncated) is still returned, carrying the error; an old
version that no longer opens is damage the operator should see. A file that cannot be read
for want of permission, or an I/O error, is reported as that, not as `ErrCorrupt`, whose
fix (restore from backup) would be the wrong one. `rm` reads nothing inside an entry, so it
removes one `list` reports as corrupt. The contract changes: `Entry` gains `Err error`,
non-nil exactly when the entry could not be opened, and `Current` and `Versions` are then
zero. `List` returns a non-nil error for the whole call only for a failure that is not
about one entry: the master missing or untrusted, or the lock timing out.

**An entry directory with no `current`.** Put writes `generation`, then `v1`, then
`current`, and writes each file through a temporary file renamed into place, so a crash
before the pointer leaves a directory holding `generation` and at most `v1`, plus possibly a
leftover temporary file (a dot-prefixed name ending in `.tmp`). Temporary files do not count
against the shape: a crash while writing `v1` leaves `generation` and a half-written `.tmp`,
and that is an incomplete Put, not damage, or one crash would strand the name. So an empty
directory, `generation` alone, and `generation` and `v1`, each with or without temporary
files, are incomplete Puts, and only those shapes. `v1` without `generation` is damage, since
Put cannot leave it. An incomplete Put is not an entry: `List` does not return it, `Current`, `Get` and `Delete` answer `ErrNotFound`
(Delete removes it too, since a Delete that crashed after removing `current` leaves `generation` and a sealed
`v1`; under a name the floor records live, Delete buries that record and succeeds, as for an
absent directory), and the next Put of the name discards it and starts over. A directory with no `current` that holds
any other file cannot be an incomplete Put, because Put writes nothing else before `current`.
That is a pointer lost to damage or to an interrupted Delete, with sealed records still on
disk. `List` returns it with `Err` set, wrapping `ErrCorrupt`, and `rm` removes the directory
and its floor entry, since `rm` reads nothing inside an entry. Put of that name answers
`ErrExists` and touches nothing, so no Put silently deletes versions an operator can still
see.

**The floor tells a lost pointer from a crashed Put.** By shape alone, a one-version entry
that lost `current` is `generation` and `v1`, the same as an incomplete Put. But Put records
the floor only after its pointer, so a directory in an incomplete-Put shape whose generation
file matches the generation the floor records for its name **did** commit a pointer, and is
damage, not an incomplete Put: `list` returns it with `Err`, `rm` clears it, and Put answers
`ErrExists`. The same holds for an interrupted Delete, which removes `current` first and the
floor entry last, so a retried `rm` clears what the first one left. A floor entry of another
generation (a Delete interrupted before its floor write, then a Put that crashed) and an empty
directory (no generation to compare) do not count. A `generation` file that does not read
while the floor records the name is damage, since a crashed Put writes that file whole. Only
with no floor file, or no floor entry for the name (a Put that crashed after its pointer and
before its floor write, which has `current` and so is not this case), do the two stay
indistinguishable. Then a one-version entry that lost `current` costs its sealed `v1`: `Get`
and `rm` answer not found, the sealed record stays on disk, and the next Put of the name
discards it without saying so. The restore procedure under "Backup and snapshots" recovers
it.

The reason is what an operator running `list` needs: the truth about every entry,
including which one is wrong, not a refusal that hides the healthy ones. A consumer that
must not skip a corrupt entry checks `Err`; the `list` verb prints `corrupt` for that entry
and exits 1 if any entry has one. The delivery reconciler does not use `List`; it opens
each declared target with `Current`, which still returns `ErrCorrupt`.

### Concurrency

One store-wide advisory lock, `flock(2)` on `keystore/.lock`, taken by every operation:
exclusive for Put, Rotate, Delete and Rewrap, shared for List, Get and Current. It
serializes Rewrap, Rotate and Put against each other and against the reconciler's reads.

- Every acquisition has a bounded wait (10 seconds). A timeout is an error, never an
  indefinite block: the service user owns the lock file, so any process running as it
  could hold the lock, a denial of service the same-user model already permits (that
  process can delete the entries), and a reconciler that times out simply tries again on
  its next sweep.
- Each file write is still temp-and-rename, so a process that dies releases the lock and
  leaves a state the next operation can finish or discard. The lock is for serialization,
  not for crash safety.
- Every verb that writes the floor also takes `flock(2)` on `keystore-lock`, a root:wheel
  0600 file in the data root: the data root is opened `O_NOFOLLOW|O_DIRECTORY` and judged
  root-owned and not shared on that descriptor, and the file is created
  `O_CREAT|O_EXCL|O_NOFOLLOW` through that directory, opened `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`
  and refused unless, on that descriptor, it is a regular file owned by root with no group
  or other access; after the flock its name is `lstat`ed again through the same directory
  and must still be the held file. Its link count is not judged: macOS lets any local user
  hard-link a file it cannot read, so refusing a second link would let anyone block every
  floor verb, and a link elsewhere is the same file, so it changes nothing about the lock.
  The order is `keystore-lock` first, then `keystore/.lock`, each with the same bounded
  wait, for every verb that takes both (Put, Rotate, Delete, RaiseFloor, Rewrap); readers
  take only `.lock`, and no verb takes `.lock` before `keystore-lock`, so no two verbs wait
  on each other's lock. `keystore-lock` comes first because only root can hold it: Delete
  buries the floor's live record for the name under it before it takes `.lock` or judges
  `keystore/`, both of which the service user controls. If that later step fails (the lock
  wait times out, `.lock` is not a regular file, `keystore/` is refused), Delete returns an
  error saying the entry is already deleted and refused, its tree was not removed, and `rm`
  should be rerun once the lock is free; it then buries the directory's authenticated
  generation and removes the tree as usual. Under the lock each verb re-reads
  `keystore-floor.json` and applies only its own change to what it read (Rotate and the
  start of a verb raise a sequence of the same generation, Put sets sequence 1 for a new
  generation and keeps the name's burials, Delete buries the floor's live generation and prunes burials to fit), holding
  the lock through the rename and the directory fsync. This lock defends against a writer
  under a swapped `.lock` writing the floor; it does not stop racing entry files under a
  swapped `.lock`. Only root can open `keystore-lock`, so only root can hold this lock. The
  data root itself is root:wheel 0755 and any local process can open it and `flock(2)` it,
  but no verb takes that lock, so holding it blocks nothing (U119). This closes the denial
  of service for every local process except the service user, and every native Pod runs as
  the service user ("Threat model"). It owns `keystore/.lock`, which every root write verb
  takes after `keystore-lock`, so any native Pod can hold that lock and keep rotation failing,
  and keep revocation from removing the entry's tree: each Rotate fails with the lock timeout
  after the bounded wait, again and again, and the failure does not clear until the holder
  lets go or exits. A Delete under a held `.lock` still records the deletion first, so the
  revoked entry is refused while its tree waits for the rerun. That residual
  is accepted, since every native Pod is the service user, one trust domain with the master.
  Holding the lock costs no integrity, because holding a lock writes nothing; that covers a
  held `.lock`, not a replaced one, whose limits are the swapped-`.lock` caveat above (the
  floor stays defended, racing entry files do not).
- An entry directory with no `current` is an incomplete Put only in the one shape a crashed
  Put can leave, ignoring leftover `.tmp` files, and only when the floor does not record its
  generation; any other directory with no `current` is damage. "An entry directory with no
  `current`" under "List, when one entry is corrupt" is the rule, and Put discards only the
  first shape, so one crash does not leave a name that can never be reused.

### Ownership of what root writes

Every verb requires root, because the master and the entries belong to the service user.
Every file or directory a verb creates under `server/` is chowned to the service user
before the verb returns, at the modes in the layout. A file left owned by root would fail
the service user's own read, and a read as the service user is what the reconciler does.
The two files under the data root are the deliberate exception: root:wheel. Amended by the
user scope: every user-scope file is the service user's, under `keystore/.user/` and under
the data root alike (the server writes them), so a root verb that creates one (`install`,
`floor --rebuild`, `audit --rotate`, `rm-scope`) chowns it before it returns. The one
root-owned addition is the maintenance marker, `keystore-maintenance` in the data root.

### Rewrap

Rewrap re-seals every record under a new master. It is `k3sm keys rewrap`, root-run: the
verb mints a new 32-byte master from `crypto/rand` and saves it to the `--key-out` file (or,
with `--key-in`, reads back a key an earlier `--key-out` saved), takes the exclusive lock, and
runs the steps below. "A crash leaves nothing unreadable" needs the *records*, not only the two
master files, to move in two phases:

1. Validate `newMaster` is 32 bytes (the verb always passes one; a wrong length from a
   library caller is a plain error, not a sentinel, since no caller can act on it
   differently, and an empty argument is `ErrMasterMissing`).
2. Write `master.next`, fsync, then `master.next.sha256`, fsync, then fsync the directory.
   If a `master.next` already exists and agrees with its fingerprint, Rewrap never adopts it
   silently. **Nothing committed yet** (no record or pointer is live under it; at most `.new`
   files exist): it is discarded, with its fingerprint and every `.new`, and the caller's key
   is written in its place, so a planted key never goes live. **A commit or swap already
   started** (some record is live under it, or the swap below is half done): discarding it
   would orphan that record, so Rewrap completes it, then returns `ErrRewrapResumed`, whose
   message says an earlier rewrap was completed with a key other than the one supplied and
   that rewrap must run again to retire it. The "committed under `master.next`" signal can be
   forged by the service user, who owns the entry and master directories: it can plant a
   `master.next` with its fingerprint and seal a record under it. A forged commit is
   therefore completed and reported with `ErrRewrapResumed`, never silently. This adds
   nothing the service user could not already do. A caller must treat `ErrRewrapResumed` as
   a failure that needs a second Rewrap; the CLI will exit non-zero on it. If it exists and does not agree, the two cases
   are told apart by whether any `.new` file exists anywhere. With none (step 3 only starts
   after step 2 is durable), the crash was inside step 2: discard it and mint again. **With
   any `.new` file present, refuse with `ErrMasterUntrusted`**: step 3 had started, so
   `master.next` was once good and has since been damaged or replaced, and minting a fresh
   key would orphan records already re-sealed under it. The operator's recovery is to
   restore the matched backup pair.
3. For every entry, every version file and the current pointer, open the **canonical**
   file under the old master, and if that does not authenticate, under the new one. A
   record that opens under the new key was already moved by an interrupted step 4 and is
   skipped. Otherwise re-seal it under the new master (fresh nonce, unchanged plaintext,
   unchanged AAD fields including generation, unchanged pointer sequence) into a sibling
   `<file>.new`, leaving the canonical file alone. Idempotent and resumable.
4. When every record is either already under the new key or has a fsynced `.new`, rename
   each `.new` over its canonical name, fsync the entry's directory, and delete any `.new`
   whose canonical file is already under the new key.
5. Swap the master, **content first, fingerprint second**: rename `master.next` over
   `master`, fsync `keystore-master/`, then rename `master.next.sha256` over
   `master.sha256`, fsync again. The two renames are not atomic together, so the order is
   chosen so a crash between them is safe: after the first, `master` holds the new key,
   `master.sha256` still holds the old fingerprint and `master.next.sha256` holds the new
   one, and the trust rule above accepts the master because it matches the second. Every
   verb that finds `master.next.sha256` without `master.next` and a master matching it
   finishes the second rename first.

**Reader's rule for the whole window:** open under the master named by `master`; if that
fails to authenticate *and* `master.next` is present, retry once under that key. The lock
means a live reader never sees a Rewrap in progress; this fallback exists for the state a
*crashed* Rewrap leaves behind. It stops being tried the moment step 5 removes
`master.next`, so it never becomes a second key this keystore must support indefinitely.

**Settled by the implementation.** The steps above leave some points open; each is settled
the conservative way:

- *What is re-sealed.* Every committed version (`v1` to the version `current` names) and
  `current`, for every entry. A version above `current` (an interrupted Rotate's orphan) and
  an interrupted Put are not entries that anything reads; they are left as they are, and the
  next Rotate or Put discards them. `created` is kept.
- *An entry that does not open* (one `list` reports with `Err`) refuses the Rewrap before
  anything is written, since the swap would strand it under a master that no longer exists.
  It is removed with `rm`, or restored, first.
- *Discarding a bad `master.next`* (one that does not agree with its fingerprint, or a
  `master.next.sha256` without it that the master does not match) also requires that every
  record still opens under the live master, besides no `.new` file existing: after step 4 has
  renamed every `.new` in, none is left, but the records are under `master.next`. Otherwise it
  is `ErrMasterUntrusted`. A `.new` file with no `master.next` is refused the same way.
- *Before each rename* in step 4 the `.new` must open under the new key as the record it
  replaces and hold the same plaintext, kind and `created` as that record opened under the live
  key; otherwise it is `ErrCorrupt` and is not renamed. Before step 5 `master.next` is read
  again, and after its rename `master` is read back; each must be the key the records were
  sealed under, or the Rewrap stops with `ErrMasterUntrusted` before the fingerprint rename.
- *A `.user` created during the run* was, in Phase A, caught by one more check right before
  step 5: the Rewrap stopped with `ErrScopeUnsupported`, the master not swapped. That check,
  and the `.user` refusal in the list below, are history: the change that re-wraps scope keys
  lifted them ("User scope", "Rewrap of scope keys"). In their place, right before step 5, the
  Rewrap walks `.user` again and refuses with `ErrCorrupt`, the master not swapped, unless the
  scopes holding a `scope.key` are exactly those it re-sealed.
- *Recovery for a stuck `master.next`.* If the service user replaces or removes
  `master.next` mid-run, after some record has moved, those records are sealed under the
  caller's new key, which then exists only as the caller's input; the next run's step 2
  refuses (`ErrMasterUntrusted`, or `ErrCorrupt` naming the entry that opens under neither
  key). The operator reruns Rewrap with the same new key: when every record opens under
  the live master or that key, and some only under that key, Rewrap writes `master.next`
  and its fingerprint again from it and completes. A record under any third key still
  refuses it, and a rerun with any other key is refused, writing nothing. A caller
  therefore keeps the new key until Rewrap returns without error.
- *Completing the swap.* Every verb that takes the exclusive lock (Put, Rotate, Delete,
  `RaiseFloor`, Rewrap) finishes the second rename first; readers trust the master and write
  nothing. A Rewrap that finishes it has completed the interrupted one and stops with
  `ErrRewrapResumed` (step 2), unless the key it completed is the one it was given. The reader's fallback key is `master.next` only when it agrees with its
  fingerprint, and an opaque fingerprint read under it uses the master's fingerprint key.
- *The floor.* Rewrap raises it at its start like every root verb, but a floor too full to
  raise does not stop it, since Rewrap records nothing new. It plans by the floor-checked
  pointer, so a pointer the floor refuses (one copied back) refuses the Rewrap before anything
  is written, like any entry `list` reports with `Err`; pointers it does re-seal keep their
  sequence.
- *Refusals before any write:* `.user` present (checked before the lock, whose first
  acquisition creates `.lock`, and again under it); no entries directory (nothing to
  rewrap); no master (`ErrMasterMissing`); and a new master equal to the live one.

**Cost.** Rewrap is bounded, and it is slow on a large keystore by design:

- *Entries.* Put refuses an entry the floor has no room for, and a floor holds at most
  67,650 entries (4 MiB over the smallest entry's 62 bytes). Every directory listing fails
  closed past 131,072 names (`maxDirNames`), whatever put them there.
- *Versions.* A pointer names at most version 65,536 (`maxVersion`), so an entry has at most
  65,537 records, each a value of at most 64 KiB.
- *Passes.* Four, each a walk over every entry: the floor raise, which opens each pointer;
  the plan, which opens every record under the old key or the new; the seal, which opens each
  record still under the old key and writes its `.new`; and the commit, which opens each such
  record and its `.new` again and renames. Every Rewrap that does not resume also runs the
  `.new` check, a listing pass over the entry directories. A discarded `master.next` adds a
  full plan pass, which opens every record under the old key or `master.next`, and a listing
  pass that removes its `.new` files. The recovery for a stuck `master.next` (above) adds one
  more plan pass, and only to a run step 2 refuses.
- *Nonces.* Every seal draws a random 96-bit nonce, and NIST SP 800-38D limits one key to
  2^32 (4,294,967,296) seals with random 96-bit nonces. At the bounds above, a keystore holds
  67,650 × 65,537 = 4,433,578,050 records (about 4.4e9), all of which one Rewrap seals under
  the new key, so the theoretical maximum exceeds that limit, before counting the seals Put
  and Rotate add under the same key. Real keystores are many orders of magnitude below it:
  1,000 entries of 100 versions each are 101,000 records, about 2^17, some 15 doublings
  short of 2^32.
- *Locks.* The whole run holds the exclusive `.lock` and the data-root lock, and checks `ctx`
  every 64 names or versions in each pass, so a cancelled context stops it soon after; what it
  wrote by then is a state a rerun completes or discards.
- *Others wait.* While a long Rewrap runs, every writer, and every reader, since a reader's
  shared lock waits on the exclusive one, times out after the lock's bounded wait (10
  seconds) with the lock-timeout error, and tries again; the delivery reconciler does so on
  its next sweep.

**Consequence for backups.** The old master does not survive step 5, so an entry backup
taken before a Rewrap can no longer be opened with the live master. See "Backup and
snapshots": entry and master backups are a matched pair, and a Rewrap starts a new pair.

## CLI (`k3sm keys`)

The verbs are `sudo k3sm keys put|list|show|rotate|rm|rewrap`, with `deliver` for root
delivery, modeled on `cmd/k3sm/secretsencrypt.go`'s dispatch (a `flag.FlagSet` per verb, a
fixed usage string, named exit codes). The verb for declaring a delivery target is the
maintainer's ruling: beside the existing subcommands, as k3s does with `k3s secrets-encrypt`,
so one place validates input and the store's layout stays private.

Every entry a root verb names is scope-qualified: `system/<name>`, where `<name>` keeps the
entry-name rule above (`sudo k3sm keys put system/signer-key`). A bare name is a usage error,
and a `user/…` name is refused by the root verbs, which serve the system scope only. The
non-root path, the root maintenance verbs and `k3sm keys exec` are under "User scope".

```
put system/<name> [--kind opaque|ed25519] [--in FILE|-]
      Create at version 1. Value from --in FILE, or from stdin with "-" (the
      default), never an argument. --kind defaults to opaque; ed25519 is
      validated as a 32- or 64-byte key on the way in. Creates the master on
      first use.

list [-o table|json]
      One line per entry: name, kind, current version, created, fingerprint
      and status. Values never printed. An entry that cannot be opened prints
      "corrupt" and the command exits 1 after listing the rest.

show system/<name> [--version N] [--reveal [--yes]]
      Metadata only by default. With --reveal, stdout carries exactly the
      stored bytes and nothing else: no trailing newline, no encoding, no
      label; no metadata is printed in that mode, so a pipe sees only the
      value. An opaque value comes back at its stored length and an Ed25519
      value at exactly 32 or 64 bytes, which is what `rotate` accepts, so
      `show --reveal` into `rotate --in -` is a byte-exact round trip. When
      stdout is a terminal, --reveal refuses unless --yes is also given, and
      then writes the raw bytes; it does not add a newline for the prompt.

rotate system/<name> [--in FILE|- | --from-version N]
      A new version, made current. The value comes from the same source as
      put, or with --from-version N it is a copy of version N's bytes, made
      inside the store, so no value leaves it. --in and --from-version are
      exclusive. Refuses a name that does not exist.

rm system/<name> --yes
      Deletes every version. Irreversible; refuses without --yes.

rewrap --key-out FILE | --key-in FILE
      Mint a new master and re-seal every record under it. --key-out FILE
      first saves the minted key to FILE, a new 0600 file in a root-only
      directory, for crash recovery; the file is deleted only when the rewrap
      fails before sealing anything under the key. --key-in FILE only
      finishes an interrupted rewrap: it re-reads a key whose SHA-256 matches
      the recorded master.next.sha256, or that some record already opens
      under, and refuses any other. Takes no value.
      Prints that entry backups taken earlier no longer open.

deliver system/<name> --namespace NS [--secret NAME] [--item FIELD=KEY ...] [--data-key KEY]
      Root delivery: declare delivery of an existing system entry as a
      Secret. Refuses a name that does not exist. Warns when secrets
      encryption is off on this data root.
undeliver system/<name> --namespace NS [--secret NAME]
      Withdraw the entry's root delivery into NS (only into Secret NAME,
      with --secret). The Secret stays.
```

Exit codes: 0 success, 1 refused (the sentinel's message), 2 bad usage, the three-value shape
`secrets-encrypt` uses, plus 3 for `rewrap` alone: it completed an earlier interrupted rewrap
with a key other than the one supplied (`ErrRewrapResumed`), so it must run again. 4 is `put`,
`rotate`, `rm`, `list`, `show` (their floor raise) or `floor merge` done, but its floor write
dropped a recorded deletion to stay within the floor's limits (a committed
`ErrTombstoneEvicted`: `Committed` and `ErrTombstoneEvicted` both match; or a merge that reports
a drop), so a copy of that deleted entry put back is accepted. Put, Rotate and RaiseFloor
report their writes' prunes that way, as Delete does, and a Delete whose burial evicted one and
whose tree removal then failed (the entry already deleted, its directory left behind) is
committed too, so `rm` exits 4, not 1. Every verb
in this list requires root (the non-root path is under "User scope"). The human output is not
stable; `list -o json` and the exit codes are the stable surface. Value input is `--in FILE` or
stdin only, never an argument: argv is visible to every local user via `ps` and lands in shell
history. Opaque values are capped at 64 KiB; Ed25519 values are checked against the two valid
lengths exactly at Put time.

## Delivery reconciler

A reconciler beside the embedded add-on reconciler in `pkg/addons`: converges one
labelled Secret per declared target, never LISTs, never prunes anything it did not itself
apply, log-and-continue on a per-target failure (the same posture `pkg/addons/doc.go`
already documents and justifies).

**Target declaration.** `k3sm keys deliver` and `undeliver` write
`/var/lib/k3sm/keystore-delivery.json`, root:wheel 0644, atomically (temp-and-rename), and
nothing else writes it. The two verbs serialize their read-modify-write on an exclusive flock
of `/var/lib/k3sm/.keystore-delivery.lock`, a root-owned 0600 file opened O_NOFOLLOW and
judged on its descriptor like the declaration, with a bounded wait; the data root directory
itself is never flocked:

```json
{"version": 1, "targets": [
  {"entry": "system/signer-key", "namespace": "payments", "secretName": "signer-key",
   "items": [{"field": "value", "key": "private.key"}]}
]}
```

`entry` is the scope-qualified name (amended by the user scope's naming rule: the file only
ever names `system/` entries, since a user entry reaches a namespace only through a
`KeyDelivery`). `secretName` defaults to the entry name without its `system/` prefix.
`items` is the projection list of "Typed credentials", in the `credential.Item` JSON form
(`{"field": …, "key": …}`, 1 to 8, keys unique), parsed strictly; the verb fills it from
`--item`, from `--data-key K` (which is `--item value=K`), or with neither from the entry
kind's default (`value=value` for `opaque` and `ed25519`), and refuses an `ssh` entry without
`--item`. This file format, `version: 1` with `items`, is the one "Typed credentials" binds; a
target carries no `dataKey` field. The file is root-owned
and outside the service user's tree for the reason the manifest directory is
(`pkg/install/statetree.go`'s `ManifestDirMode`): the declaration decides which namespace
the admin client writes a Secret into, so a file any process running as the service user
could write would hand that process the reconciler's grant. It is read with the manifest
directory's check (`rootOwnedNotShared`, on the opened descriptor, O_NOFOLLOW); a file
that fails the check is refused as a whole and logged. The reconciler sweeps on start, on
a change to the file (fsnotify, debounced), and every `ManifestSweepInterval` as the
backstop, so a Rotate reaches its Secret within one interval.

**Identity.** The reconciler runs in the server process and uses the admin client that
process already holds for the embedded add-on reconciler (the `system:masters` admin
kubeconfig). **It adds no role, no binding and no ServiceAccount.** What it does with that
client is narrower than the client allows: get, create and update of one named `Opaque`
Secret per declared target, labelled as below; delete only an owned immutable Secret, under a
UID precondition; and nothing else — no list, no other delete, no other kind, no Secret it
does not own. The set of principals who can cause a write stays
{root on the node} because only root can edit the declaration. A bounded ServiceAccount in
the manner of `kube-system/k3sm-manifests` would need a new Role granting Secret write,
which widens what the control plane can do; Phase A does not add one. This paragraph holds
for the root-file delivery. The user scope's `KeyDelivery` reconciler is separate and
differs on purpose: it deletes the Secrets it owns when authority is lost, and an unbound
ClusterRole ships for admins to bind ("User scope", "KeyDelivery").

**Ed25519 encoding in the Secret:** the stored seed or expanded key, base64 under the
item's key exactly as Kubernetes already base64-encodes every Secret `data` value — no PEM
wrapping, no bundled public key.

**Ownership label:** `k3sm.io/keystore-delivery: <entry-name>`, distinct from
`k3sm.io/managed` (reusing that label would make this reconciler's Secrets
indistinguishable from the embedded add-on set's objects for "which reconciler may touch
this," the exact hazard `pkg/addons/doc.go` warns a label-selector prune into). The label
is not proof of ownership: anyone who can write Secrets in the namespace can set it on a
Secret they create first. So on create the reconciler records the UID the apiserver gave
the Secret in `<server work dir>/keystore-delivery-state.json`
(`/var/lib/k3sm/server/keystore-delivery-state.json` on an install), mode 0600, written
atomically by the server and so owned by the server's euid (`_k3sm` on an install, root on a
root server). It is read on the opened descriptor, O_NOFOLLOW: the file must be owned by
the server's euid and not group- or other-writable, and the directory owned by that euid, by
root or, for a root server, by the service user, and not group- or other-writable. That owner
adds no trust: a process running as the server's uid already holds the admin kubeconfig and
can write any Secret without forging the file. Pods are kept off it by the runtime's
whole-tree pod deny on the server work dir (`runtimed/pkg/sandbox::TestStateDirDeniedUnderACustomLeaf`,
`TestStateDirEnforcedAcrossCaseAndNormalization`); the `keystore-` prefix, which the runtime's
`keystore-*` deny also covers, is defence in depth only. A service-user-owned parent can rename
or delete the file: a missing record makes the reconciler skip a Secret it cannot prove it
created, failing closed, and a file the service user wrote is refused because it is not root's.
The residual is replay: on a root server the service user can put back an older state file
root wrote, which restores records only for Secrets this server created, in targets root
declared. Ownership is checked by reading the existing Secret first: present and
carrying the recorded UID → update, relabelling it if its label is missing or names another
entry (a tenant's edit, or root re-pointing the Secret at another entry with `deliver`), since
the UID alone decides; anything else (no recorded UID, or a different UID because the Secret
was deleted and recreated, whatever its label says) → "not created by this server", left
alone, skipped with a logged reason, never written into. An update writes
only `data`, `type`, the label and the two annotations, and strips any `immutable` flag on
its own object. A target that leaves a declaration that exists and parses loses its state
entry, so declaring it again does not adopt the old Secret; an absent declaration (the file or
the data root missing) withdraws nothing, keeps every record and changes no Secret. A state file that fails its checks delivers nothing,
and a create happens only after the state file was written successfully in that sweep.

**Re-delivery on rotation:** the sweep compares the target's current version and
fingerprint (`Store.Current`'s `Version.Version` and `Version.Fingerprint`) against the
Secret's own `k3sm.io/keystore-version` and `k3sm.io/keystore-fingerprint` annotations, and
checks that `data` holds exactly the declared items' keys and that their bytes are the projected
value (`subtle.ConstantTimeCompare`, so an edit of `data` that leaves the annotations intact is
drift: re-applied and logged, without the value); any mismatch re-applies `data` and
both annotations — content-derived, like the embedded reconciler's own checksum-skip. The
version alone is not enough: an entry deleted and put back starts at version 1 again with a
new value, and `pkg/keystore` exposes no generation, so the value's fingerprint is what
tells the two apart. A changed item list re-applies too, and a stale key leaves `data`. An
`immutable` Secret the reconciler owns cannot be updated, so a re-delivery deletes it with
`DeleteOptions{Preconditions: {UID: <recorded UID>}}`, creates it again and records the new
UID, logging both steps without the value. It is the reconciler's only delete, and it is safe
because the precondition proves the object is the one this server created; a failed
precondition deletes and creates nothing.

**Refusal while secrets encryption is off.** Delivery is refused by default; the override
is explicit, as the maintainer answered on the issue. Two facts the first revision got
wrong are corrected here:

- *How the reconciler learns encryption is on.* It is not re-read each sweep. The server
  already decides it once at start: `executor.EncryptionAtStart` returns the
  encryption-provider configuration path it passes to the apiserver, or empty when
  encryption is off (`cmd/k3sm/serverprovision.go`). The reconciler is handed that same
  verdict at construction, so it cannot disagree with the apiserver about whether Secrets
  are encrypted.
- *Where the override is held.* `--allow-plaintext-secrets-delivery` is a `k3sm server`
  flag. An operator-supplied `k3sm server` argument is carried in the server arguments
  record (`pkg/dataroot`'s `ServerArgsRecord`) and rendered into the LaunchDaemon's
  arguments, and it is read once, at process start. **Changing it takes a restart of the
  server.** It is not read fresh each sweep.

**The operator's procedure to turn the override on, on an existing cluster:** add
`--allow-plaintext-secrets-delivery` to the server daemon's arguments (the LaunchDaemon
plist), restart the server daemon, then run `sudo k3sm install` so the server-args record
keeps the flag. The install step is what makes it durable: a flag that exists only in the
plist is lost by an uninstall before the next install, and the next install would then
render the stock template without it (`docs/user/install.md` § "Server Flags Across A
Reinstall"). To turn the override off, remove the flag from the plist, restart, and run
`sudo k3sm install`; if the record still carries the flag, remove it there too.

The override is applied per target at the time of that sweep; a target already delivered
before the flag was removed is left as it is, since this converge-only reconciler does not
retroactively delete a Secret an operator may be relying on. A refusal is logged at Warn
once per target per state change (there is no Kubernetes object for a keystore entry to
attach an Event to in Phase A), and `k3sm keys deliver` prints the same refusal when it
declares a target on a data root with encryption off, from the files alone: it cannot see
a running server's flag, so it says "unless the server was started with the override".

## Rotation and rollback

**Crash-safe write order:** Rotate writes the new version file first (durable, not yet
referenced), flips the current pointer, then raises the floor. A crash before the flip
leaves the old version current and an unreferenced next-version file. **A retry always
discards that orphan and seals fresh from the value it was given**; it never reuses it,
because the orphan holds whatever value the interrupted attempt carried, and promoting it
would publish a value the retry did not supply. The same applies to any version file
numbered above the one `current` names. Seeing the orphan and removing it happens under
the exclusive lock.

**Accepted window: a discard while the floor lags.** If a Rotate flips `current` and then
fails to write the floor, the floor is one behind the pointer until the next root-run verb
raises it. If, inside that window, a writer that cannot read the master copies the previous
`current` back, the floor check passes it (its sequence equals the floor's), and the next
Rotate takes the newer version, which the live pointer named, for an orphan and discards
it before sealing its own value. Nothing forged is ever accepted, but the newer version is
lost. This needs a failed floor write and a swap before any root verb runs, and it is
accepted for this phase. No cheap guard tells it apart: a Rotate that crashed before its
flip leaves the same state (a version above `current` that authenticates, a pointer at the
floor's sequence, and no newer pointer anywhere, since the swap's rename replaces it), and
that orphan must be discarded.

**Retention:** every version is kept indefinitely in Phase A; nothing deletes a single old
version short of `rm` of the whole entry. Settled in this document: the simplest correct
answer, left for a later phase to bound once real usage shows it matters.

**Delivered-Secret movement:** covered above under "Re-delivery on rotation" — automatic
on the next sweep after a Rotate.

**Rollback:** no dedicated verb. An operator rolls back by writing the old version's value
forward as a *new* version, never by pointing `current` backward at an existing version:

```
sudo k3sm keys show system/NAME --version N --reveal | sudo k3sm keys rotate system/NAME --in -
```

`sudo k3sm keys rotate system/NAME --from-version N` writes the same new version without the
value leaving the store (row U1); the pipe stays the recipe G21 checks.

A pipe, not a process substitution: `sudo` closes inherited descriptors, so a `<( … )`
path would not open, and each side of the pipe runs its own `sudo`. The round trip is
byte-exact because `show --reveal` writes the stored bytes with no trailing newline and
`rotate --in -` reads stdin to EOF without trimming: version N+1 holds exactly the bytes
version N held, and an Ed25519 value stays at 32 or 64 bytes. The check that proves it is
G21, which compares the two byte for byte. This keeps rotation
the one write path to reason about. A direct point-current-backward operation would now
also have to move the pointer sequence and the floor *backward*, which is the very thing
the floor exists to refuse, so it is not a Phase A verb.

## Backup and snapshots

Not in datastore snapshots (fixed). What an operator backs up instead:

- `keystore/` (including every entry's `generation` file — always a sibling of the
  version files it belongs with, under the same entry directory).
- `cred/keystore-master/` (the master and its fingerprint), **to a different location**
  than the entries, for the same reason they live in a different directory on the live
  host: a backup of "the keys" that does not also hand over "the one file that unlocks
  them" is one a less-trusted location can hold without becoming a full compromise if it
  leaks.
- `keystore-floor.json`, with the entries. Without it a restore still opens, but the
  stale-pointer check starts empty.

**An entry backup and a master backup are a matched pair.** A backup of `keystore/` opens
only with the master that was live when it was taken. `k3sm keys rewrap` replaces that
master and destroys the old one, so **after every rewrap, take both backups again**, and
keep an old master only next to the old entry backup it belongs with. Different locations,
yes; independent schedules, no.

`cred/` is already backed up with every datastore backup (the existing install guidance),
so **the master travels with those** unless it is excluded. An operator who wants the
master kept apart from the datastore backup excludes `cred/keystore-master/` from it.

A restore is checked the same way a live read is: mode, ownership and fingerprint
verified on the restored master before anything is trusted to open under it, so a
mismatched restore fails loudly (`ErrMasterUntrusted`, or every entry `ErrCorrupt`) rather
than silently decrypting into garbage. `k3sm snapshot restore`'s existing
group/other-readable warning for a handed-in file (`docs/user/backup-restore.md`) is the
right model for a restored master too, rather than a differently-worded warning for the
same operator mistake.

**Restoring an older `keystore/` is deliberate and is refused until root says so.** Every
pointer in the restored directory is older than `keystore-floor.json`, so every entry fails
the stale-pointer check. That is the check working. The procedure is: restore `keystore/`
and the matching master, stop the server, `rm /var/lib/k3sm/keystore-floor.json` as root,
then run any root verb (`sudo k3sm keys list`), which rebuilds the floor from the restored
pointers.

**Restoring an entry deleted by mistake is the same act.** Its burial refuses the restored
directory, which is the tombstone working ("A deleted entry put back is refused"). The restore of
the same backup therefore moves the live `keystore-floor.json` aside, as root, to
`keystore-floor.json.pre-restore` (never overwrites it, so the restore can be undone) and puts
back the floor saved with the backup, which records the entry live; restoring `keystore/` alone
leaves the entry refused. That restore is of the whole keystore: it reverts every rotation and
brings back every entry deleted since the backup, with their burials gone, until the merge
below carries them over.

*Restoring with the saved floor: the merge.* Before `k3sm start`, the recipe runs
`sudo k3sm keys floor merge` (`FileStore.MergeFloor`). It takes no path: its only input is the
data root's `keystore-floor.json.pre-restore`, read under `keystore-lock` through the data root
the lock judged, as the floor is read (a regular file, never followed, owned by root and not
group- or other-writable, at most 4 MiB), and parsed with the same strict parser. So the floor
saved with the backup, or any other copy, can never be its input, and nothing needs to tell the
two apart by age (`TestMergeFloorReadsOnlyTheGuardFile`, `TestKeysFloorMergeTakesNoFile`). The
name must still be the file it read when it writes and when it renames it: a guard file
replaced by another inode during the merge refuses it, writing nothing. It refuses, writing
nothing, when the live floor is absent ("restore the saved keystore-floor.json first": merging
into nothing would leave the moved-aside burials with no live records) when the guard file
is the live floor itself, by inode or byte for byte (equal floors are byte-identical files,
since the parser accepts one encoding per floor), and when the merge would retire every live
record the moved-aside floor holds: the live floor neither holds live nor buries any of their
generations, `--keep` names none, and the moved-aside floor buries no generation the live floor
holds live, which is a live floor not saved with this backup
(`TestMergeFloorRefusesRetiringEverything`). A Delete under the guard with the live floor
absent refuses too ("install the saved keystore-floor.json first"), writing nothing: a floor it
created would hold its burial alone, and the merge would take it for the restored floor
(`TestPendingMergeDeleteNeedsLiveFloor`). Then, under `keystore-lock` alone, it adds every
burial it records that the restored floor lacks, oldest first, each at the next delete
sequence, so the merged burials keep their order. It writes only the root-owned floor and
nothing under `keystore/`, so it never takes `keystore/.lock`, which the service user can hold
or replace to stop it; readers need none against it, since the floor is replaced by an atomic
rename. So a key created after the backup and
revoked before the restore stays refused, and so does every generation buried under a name
after the backup, which re-running `rm` could never record. A generation the moved-aside
floor buries and the restored floor holds live is buried too, its live record cleared: the
backup holds an entry deleted after it, perhaps to revoke it, so the merge fails closed rather
than leave it live. The operator names each entry restored on purpose, the one deleted by
mistake, with `--keep system/<name>` (repeatable; `MergeFloor`'s keep set), which keeps that
name's restored generation live. The choice is made before the merge: a burial is never
removed, so a second merge with `--keep` cannot bring back an entry the first buried. The
residual is the operator's: a name kept by mistake is a revoked key live again. The
moved-aside floor's live records are not dropped silently either: for each name whose
moved-aside live generation the restored floor neither holds live nor buries (it holds another
generation live, or none), the merge buries that generation after the merged burials and
counts it as retired. `--keep` spares it only when the restored floor holds no live record of
the name: `--keep` keeps the restored generation, never a second one, so a name kept live as
G1 still has its moved-aside G2 retired, and a copy of G2 stays refused after a later `rm`.
A name kept that the restored floor does not record is recorded live from the moved-aside
floor: its generation at its sequence, with the high-water mark below (one above the higher of
its sequence and mark), so an older copy of that generation is refused, and so is a copy from
the history above the moved-aside record; a rerun keeps it again and writes nothing
(`TestFloorMergeKeepRecordsAsideLive`). Root retired it by choosing the backup:
a name live as G1 at the backup, deleted and put again as G2, has G1 buried (the deletion) and
G2 retired, so neither directory put back is accepted. When the restored floor holds the
moved-aside live generation itself at a lower sequence (the entry rotated since the backup),
the moved-aside history would otherwise outrank the restored one: a pre-restore copy at seq 9
passes a floor at seq 5, and the next Rotate, sealing seq 6, would leave it passing. So the
merge gives that live record a high-water mark, one above the higher of the moved-aside
sequence and the moved-aside record's own mark. Either floor can lag its pointer by one, from a
crash between the pointer flip and the floor write. The `+1` covers a moved-aside floor at seq 9
whose pointer reached 10: that copy is refused too. For the restored side, the merge, which runs
as root, authenticates each fenced entry's restored pointer under the master first, and when
that sequence is exactly one above the restored record (and above its own mark), the lag a crash
leaves, it raises the record to it, so a restored pointer one past its saved floor is never
inside the fence. The raise is bounded to that one sequence: a pointer further above the record
is not raised to, and the fence, computed after the raise, covers it, since an authenticated
pointer the saved floor never saw that far ahead is a copy of the abandoned history, not the
restored one (`TestFloorMergeBoundsRestoredRaise`, and `FuzzMergeFloor` with fuzzed pointers:
no raise exceeds one sequence). Such a pointer, and one that does not authenticate (no master,
a missing or replaced directory, another generation), leaves the record as the restored floor
holds it, logged at Warn and reported as `unverified system/<name>` (`MergeReport.Unverified`). At the sequence limit the mark saturates there
(`TestFloorMergeFenceLaggingFloors`, and `FuzzMergeFloor`'s fence oracle: the result's
`max(seq, highwater)` is at least the moved-aside record's plus one). The mark is written as an optional `"highwater":N` after `"seq"` in the
entry and left out when 0, so the parser's canonical round trip and every earlier floor are
unchanged; the parser refuses a mark at or below `seq`. Readers refuse a pointer of that
generation above `seq` and at or below the mark, the raise never raises into it, and Rotate
seals its next sequence at one above `max(seq, highwater)`; the raise to it clears the mark,
and a Put of a new generation or a burial drops it. The verb counts these as `fenced N`.
Until the merge runs, the restore is unfinished, and the store enforces that: while
`keystore-floor.json.pre-restore` is in the data root, Put, Rotate, Delete and Rewrap refuse
under `keystore-lock`, before they write anything, with a message naming `keys floor merge`
(`errMergePending`), and RaiseFloor, which the read verbs call first, raises nothing and logs
that at Warn, so `list` and `show` still read the restored entries and no pointer put back
before the merge is recorded. A successful merge renames its input to
`keystore-floor.json.merged-<unix>` beside it, through the data root descriptor the lock
judged (never over an existing file, and only if the name is still the file it read), which
clears the guard. A rename that fails after the write is reported as committed: the verb prints
the full report and exits 5 ("merge written, input not renamed: rerun to clear the guard"), which
wins over 4 (a burial dropped); the report still lists every drop. A rerun is safe: the input is read again under `keystore-lock`, and
the merge first runs on a copy of the live floor. When every burial and fence the input records
is already there, it writes nothing, only renames the input, and reports `already merged`. A guard file that is
the data root's live floor by inode is refused outright
(`TestMergeFloorCommittedRerun`, `TestKeysFloorMergeCommittedRerun`). `k3sm start` is not hooked: its start path has no cheap synchronous
check of the keystore, and it writes no floor. The delivery reconciler, the server's one reader
that publishes a value, is: each sweep first asks `FileStore.MergePending` (a Lstat of
`keystore-floor.json.pre-restore`, any answer but not found counting as pending), and while it is
set the sweep delivers nothing, reads no entry and makes no apiserver call, logs at Error and
tries again on the next sweep (`TestDeliveryRefusedWhileMergePending`). `list` and `show` still
read, and print a warning on stderr; until the merge they find no entry, since the restored tree
is staged. The
recipe moves the live `keystore/` into `pre-restore.d/` in the data root, a directory it creates
root:wheel 0700 with `mkdir` (which fails on an existing name) under a parent only root can
write, so the service user cannot reach the moved-aside entries to copy one back, nor rename the
directory, as it could under `server/`. It changes no file inside: a rename changes no inode's
owner. Root's `ditto` copies the backup into `pre-restore.d/restored` (after `test ! -e`), and
`server/keystore` is left absent. The merge opens `pre-restore.d` through the data root the lock
judged, never followed, and refuses it unless root owns it and it grants nothing to group or
others: `ditto` keeps the backup's owner inside, so the directory's mode is what keeps the
service user out of the staged tree. It reads the restored pointers only from
`pre-restore.d/restored`, bytes only root copied (the raise is still by at most one sequence), and
authenticates the moved-aside tree's pointers, `pre-restore.d/keystore`, under the master, so the
fence is one past the highest of the moved-aside floor's sequence, its mark and that pointer: a
moved-aside floor that lagged its pointer by two or more is fenced above the pointer
(`TestFloorMergeFencesAboveAsidePointer`). Anything at `server/keystore` while a tree is staged,
a symlink counted, refuses the merge with nothing written (`TestFloorMergeRefusesExistingTarget`),
and with nothing staged a merge that would change the floor refuses (`TestFloorMergeNeedsStagedTree`).
Before the floor write the merge hands the staged tree to the service user in Go, through
descriptors: `fchownat` with `AT_SYMLINK_NOFOLLOW` on each name, descending only into
directories, refusing a non-directory with a second link (a `ditto` of the backup makes none).
After the floor write it renames `pre-restore.d/restored` to `server/keystore` through the two
directory descriptors with `renameatx_np(RENAME_EXCL)` (from `golang.org/x/sys/unix`), which
refuses an existing name, a symlink included, in the same step; a failed fsync after it is
logged at Warn and the rename stands. Only then is the guard file renamed. A failed move after
the floor write exits 5, and a rerun, which writes nothing more, completes the move and the
rename (`TestFloorMergeMovesStagedTree`). The undo stages the trees the other way round inside
`pre-restore.d` (the moved-aside tree as `restored`, the restored one as `keystore`) and swaps the floors:
the moved-aside floor goes back in place and the restored floor becomes
`keystore-floor.json.pre-restore`, then runs the merge in that reverse direction, so a deletion
made after the restore survives the undo; its `--dry-run` report shows each entry the restored
floor records as deleted, and `--keep` spares a version the first merge retired. No recipe changes owner,
mode or flags recursively (`chown -R`, `chmod -R`, `chflags -R`) over a tree the service user
wrote: root would follow a hard link planted in it to an unrelated inode
(`TestKeysRollbackRoundTrip`). The merge keeps every live record of
the restored floor not buried above. The write is pruned as every floor write is, the per-name cap
included, and each burial dropped is logged at Warn and reported. Only a burial the restored
floor already held before the guard can be dropped: as Put and Rotate ask for room before they
write, the merge first prunes its result on a copy, and when that would drop a deletion since
the backup it refuses with the floor-full error, writing nothing and leaving its input in place,
so the guard stays (`TestMergeFloorRefusesDroppingItsOwnBurials`). A deletion since the backup is
a burial the merge adds (a merged, retired or buried-live one) or a guard-era burial: one `rm`
wrote while the guard was set. A Delete under the guard numbers each burial above
`guardEraSeq`, half the delete-sequence limit, which no floor reaches by counting deletions, so
the merge tells those burials from the restored floor's from the live floor alone, with no
record beside it and nothing more for the Delete to write. The merge moves the guard-era
burials to just above `guardEraSeq`, the others from 1, inserts each burial it adds between the
two, oldest first, and renumbers every burial from 1 at the end, order kept, which the parser's
distinct-and-increasing rule accepts. So the burials it carries over, older in real time than
any written during the guard, are pruned first, and a guard-era burial is never pruned before
them (`TestGuardEraBurialSurvivesPressuredMerge`, and `FuzzMergeFloor`: none ends above
`guardEraSeq`, and every added burial ends below every guard-era one). A floor with a burial
above `guardEraSeq` and no guard (the guard file removed by hand) has those treated as guard-era
by the next merge, which only keeps them longer. The refusal names what binds. When only the
floor's size does, it names `keys rm`, which frees a live record. When the tombstone budget or
the per-name cap binds, `rm` cannot help, since each deletion records one more, so it names the
budget, or the cap and its names, and `--accept-drops` (`MergeOptions.AcceptDrops`), which writes
the merge anyway: the write prunes oldest first, as every floor write does, reports and prints
each burial dropped, exits 4 and renames the input, so the guard has an exit. `--dry-run`
(`MergeOptions.DryRun`) stops after the merge on a copy and prints that report, drops included,
writing and renaming nothing (`TestKeysFloorMergeDryRun`)
(`TestGuardEraTombstoneBudget`, `TestGuardEraBurialPerNameCap`, `TestPendingMergeDeleteMakesRoom`,
`TestKeysFloorMergeAcceptDrops`). A
fence is a mark on a live record, which no prune removes. The verb prints `merged N`,
`already present N`, `buried live N`, `kept N`, `retired N`, `dropped N` and `fenced N`, one per line, then `buried live
system/<name>: ...` for each name whose live generation it buried (and whose directory `rm`
removes), `kept system/<name>: ...` for each name kept, `retired system/<name>: ...` for each
name whose moved-aside live generation it retired and `dropped system/<name>: ...` for each
burial dropped, and exits 0 once the merge is
written, or 4 when it dropped a burial. The saved floor must come from a
root-owned, root-only location: the floor decides what is live, and a planted floor marks
revoked entries live. Removing the floor, the older-keystore procedure above, discards every
burial.

Amended by the user scope's append-only files: the matched set also includes `keystore/.user/`,
`keystore-user-floor.log` and `keystore-audit.log`. The append-only flag does not survive
`cp`, rsync or Time Machine, so every restore ends with `sudo k3sm keys floor --rebuild`, and
`sudo k3sm keys audit --rotate` re-flags the audit log ("User scope", "The user-scope floor").

## User scope

Status: design, not built. Phase A stores and delivers keys the machine owns, with `sudo` for
every act. The user scope lets a person on the Mac store and renew their own credential
without `sudo`, deliver it only into namespaces they may write, and keep it from other people
on the Mac. It layers on a finished Phase A and never reshapes a Phase A record: the scope is
already in every record's associated data and key labels ("Scope"), so nothing here needs a
record-format bump.

The work lands as a series of changes, each named below by what it adds: the user-scope
store; user-scope quotas, scope-key Rewrap and the delivery record; the append-only files;
the socket listener; the socket operations; the non-root CLI and `exec`; KeyDelivery
authoring; the KeyDelivery reconciler (authority, then lifecycle); and the user docs. Two
leaves come from other repos: runtimed's sandbox change (the Pod denies) and the
`KeyDelivery` API in `apis`. The sandbox change merges before the append-only files change
creates any keystore file, and the API is tagged before KeyDelivery authoring opens. The
user-scope store depends on the entry grammar package, `apis/keystore/entry`, so that package is
tagged first, and the user-scope store's change bumps k3sm's requirement on `k3sm.io/apis` to
that tag and says so.

Facts only a spike on the lab rig can settle are marked `[K0 leg N: pending]` where they
apply; "Facts from the rig spike" lists them. A marker is replaced by a dated amendment to
this document that quotes the measured result.

### Decisions the maintainer ruled

- **One real login user on the rig.** The rig acceptance runs as the operator's own login
  user, the only real login user on the rig; no second account is created. Cross-user refusal,
  one real user refused another user's entries, is shown by unit tests with a fake
  peer-credential source (U45), not on the rig.
- **No system grants.** There is no grant of a system entry to a non-root user, for delivery
  or for exec: no `keys grant` or `keys revoke` verb, no grants file, no grant check. System
  entries are delivered and read by root only.
- **Any same-uid process may use the socket.** The caller's code identity is not pinned; any
  process running as the owner's uid can ask for the owner's values (residual 1).
- **The ServiceAccount rotate grant is deferred.** A delegable per-entry rotate grant for a
  ServiceAccount is not built in this release. When it is, it is built through a new
  Pod-reachable endpoint with its own design, since a Pod cannot reach the socket. Nothing
  here opens, reserves or stubs that endpoint.
- **A thread and a milestone.** The keystore is tracked as its own end-to-end thread, whose
  outcome is "a person stores a credential without sudo, and the keystore delivers it only as
  a Secret in namespaces they may write". It claims nothing about Pods on one node reading each
  other's Secrets, which the user scope does not isolate ("Threat model for the user scope"). The end-to-end rig gate (the legs under "Rig legs") is its tracer and the only proof of that
  outcome; every other change supports it. The work is milestone M20.

### Scope strings and names

The scope strings are `system` and `user/<uid>`, with `<uid>` the decimal macOS uid as
"Scope" defines it. The API takes scope-qualified names only:

- `system/<name>` and `user/<uid>/<name>`, where `<name>` keeps Phase A's entry-name rule.
  There is no bare name, no search order and no shadowing.
- Every qualified name in the store, the audit log, `KeyDelivery.spec.entry` and the API is
  `user/<uid>/<name>`. The short name is display-only: the CLI shows it, and the audit line
  carries it beside the uid.
- As input only, the CLI also accepts `user/<shortname>/<name>`. It resolves the short name
  through the uid resolver (`getpwnam`) and prints the result (`resolved user/alice to
  user/501`), so a script sees what it bound to.
- A non-root caller may name only its own uid's entries. A `system/…` name or any other
  `user/<other>/…` name answers `ErrNotFound`, worded identically to an absent entry, so the
  answer is no oracle for another user's names. System entry names are not hidden this way:
  Phase A's two data-root files name them (residual 11).
- **A uid is decimal**, with no leading zero, from 1 to 4294967295. `user/0` is invalid: root
  has no user scope. An all-digit second segment is always a uid, never a short name, even
  when an account of that name exists, so `user/1000/x` names uid 1000 on every input path.
- **`user/<uid>` names do not carry across Macs.** The same person usually has a different uid
  on another Mac, so a qualified name copied to another machine names another account's scope,
  or none. A script that moves between Macs uses the short-name input form, which each Mac
  resolves for itself.

**The entry grammar lives once**, in a Kubernetes-free leaf package in `apis`,
`apis/keystore/entry`, which imports only the standard library. It exports the pattern, the
length bound and the parse:

```
^(system|user/[1-9][0-9]{0,9})/[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
```

The pattern bounds the uid's digits; the range (at most 4294967295) is a CEL rule beside it,
`!self.startsWith('user/') || int(self.split('/')[1]) <= 4294967295`, and the Go parse reads
the uid as a uint32. The name part has its own bound, a second CEL rule,
`size(self.split('/')[size(self.split('/')) - 1]) <= 253`: the pattern allows no `/` in the
name, so the last segment is the name, and the pattern allows only ASCII, so CEL's `size` in
code points equals the byte count. The `maxLength` alone does not bound the name: `system/` or
`user/1/` and a 254-byte name is under 269 bytes. On a KeyDelivery a third CRD CEL rule,
`!self.startsWith('system/')`, refuses a system entry, since a system entry reaches a namespace
only through root's `deliver` ("KeyDelivery"). `spec.entry` has `maxLength` 269, the longest valid entry
(`user/4294967295/` and a 253-byte name: `len("user/")` + 10 + 1 + Phase A's `maxNameLen` of 253),
which also bounds the CEL rules' cost. The CRD pattern,
the admission policy's CEL and the Go resolver all take the grammar from that package, and one
shared vector table in it tests all three (U11, U19, U40, U57). Phase A's `checkName` is a
fourth consumer: it reads the name part of every vector whose scope part is valid and must give
the vector's verdict (U11). "Valid" means valid as an API
entry; the CLI's short-name resolution runs before the grammar sees a name. The table holds at
least:

| input | valid | why |
|---|---|---|
| `system/signer-key` | yes | |
| `user/501/claude-a` | yes | |
| `user/1/a` | yes | the smallest uid |
| `user/4294967295/a` | yes | the largest uid |
| `user/501/registry.example-token` | yes | a dotted name, as Phase A's `checkName` accepts |
| `user/4294967295/` and a 253-byte name | yes | 269 bytes, the `maxLength` |
| `user/4294967295/` and a 254-byte name | no | one over Phase A's name bound |
| `user/1/` and a 254-byte name | no | under the `maxLength`, refused by the name-length rule |
| `system/` and a 254-byte name | no | under the `maxLength`, refused by the name-length rule |
| `user/501/deliveries`, `user/501/scope.key` | yes | ordinary names: entries live under `entries/`, apart from the scope's own files |
| `user/501/a..b`, `user/501/.a`, `user/501/a.` | no | an empty label |
| `system/a/b` | no | a `/` inside the name |
| `user/0/a` | no | uid 0 has no user scope |
| `user/4294967296/a` | no | past a uint32 |
| `user/0501/a` | no | a leading zero |
| `user/+501/a` | no | not decimal digits |
| `user/alice/a` | no | a short name is CLI input only, resolved before it reaches the API |
| `user/1000/a` (CLI input, an account named `1000` exists) | yes, as uid 1000 | an all-digit segment is always a uid |
| `user/501` | no | no name |
| `user/501/a/b` | no | a `/` in the name |
| `system/Signer` | no | upper case |
| `other/a` | no | an unknown scope |

### On-disk layout

Phase A's paths are unchanged. Added:

```
/var/lib/k3sm/                          data root, root:wheel 0755
  keystore-floor.json                   Phase A: root 0644, system floor; now Pod-denied
  keystore-delivery.json                Phase A: root 0644, root-declared deliveries; now Pod-denied
  keystore-user-floor.log               NEW: the user-scope floor, append-only
  keystore-audit.log                    NEW: the audit log, append-only
  keystore-audit.log.1 … .4             NEW: the previous audit logs after `audit --rotate`, `.1` the newest; root 0600, flagged (Open requirement 1)
  keystore-lock                         NEW: root 0600, the floor lock only root can open (Open requirement 2)
  keystore-removed-scopes.json          NEW: root 0644, written by `rm-scope`, parsed strictly; Pod-denied (Open requirement 13)
  keystore-maintenance                  NEW: root 0644, present only while a maintenance verb runs
  keystore-user-floor.log.new           NEW: staging file of `floor --rebuild`, present only during it
  keystore-audit.log.new                NEW: staging file of `audit --rotate`, present only during it
  keystore-sock/                        NEW: root:wheel 0755, made by install, the socket's directory, Pod-denied
    keys.sock                           NEW: srw-rw-rw-, root's, created by launchd from the server plist; access is decided by peer credentials
  server/                               already Pod-denied
    cred/keystore-master/master …       Phase A, unchanged
    keystore/                           Phase A: 0700, service user
      .lock                             Phase A: the one store lock, also taken by user-scope operations
      <name>/ generation v1 … current   Phase A: system entries, unchanged
      .user/                            NEW: 0700, service user (the reserved name)
        <uid>/                          NEW: 0700, service user, one per user who has stored anything
          scope.key                     0600, service user; sealed record, kind 0xFE: the user's scope key, wrapped
          deliveries                    0600, service user; sealed record, kind 0xFD: per delivery, its UID, object name, target tuple, target digest and last delivered version
          entries/                      NEW: 0700, service user, the scope's entries and nothing else
            <name>/ generation v1 … current  same shape as a system entry, sealed under the scope key
```

A user's entries live under `.user/<uid>/entries/<name>/`, apart from the scope's own files
`scope.key` and `deliveries`. Both are valid entry names (`scope.key` is a dotted name), so with
entries beside them a user who stored an entry named `deliveries` or `scope.key` would collide
with the scope's record; under `entries/` they are ordinary names (U63). The modes of
`.user/<uid>/`, `scope.key` and `deliveries` are checked by U132.
`keystore-removed-scopes.json` is root-owned 0644, refused if group- or other-writable or not
root's, and parsed strictly: an unknown field, a duplicate uid or trailing data refuses it,
and a refused file counts as no listing (U133).

The owner and mode of the two logs depend on the floor variant ("The user-scope floor"): with
the append-only flag they are the service user's, mode 0600, flagged `sappnd`; with the floor
helper they are root's, mode 0600. K0 picks; dated amendment.

`.user` is a dot name, so a Phase A build's `List` skips it, and every build before the
scope-key Rewrap refuses Rewrap while it exists. The run directory is not reused for the
socket: it is 0700 (`RunDirMode`), so a login user cannot reach a socket there, and the mesh
key directory already holds the name `keys`, hence `keystore-sock`.

**The socket's directory is root's, so the service uid cannot bind there.** `sudo k3sm install`
creates `keystore-sock/` root:wheel 0755. The socket in it is a launchd `Sockets` socket of the
server's own job: `ServerPlist` (`pkg/install/plist.go:218`) gains a `Sockets` dictionary with
one listener, `SockPathName` `/var/lib/k3sm/keystore-sock/keys.sock` and `SockPathMode` 0666,
rendered by `renderPlist` (`pkg/install/plist.go:609`) from a new field of `launchdPlist`
(`pkg/install/plist.go:573`). launchd creates and binds the socket as root before it starts the
job, and the server takes the listening descriptor with `launch_activate_socket`, sets
`FD_CLOEXEC` on it and passes it to no child (Open requirement 3, U120). No service-uid process can create, unlink or
replace a name in a root-owned 0755 directory, so no service-uid process, the server's
children and a Pod's processes included, can bind `keys.sock`, whether or not the server is
running (U104, E24). That launchd activates a `Sockets` socket for a job with `UserName` set,
and that the server, as the service user, receives it, is a K7a measurement. **If it fails,
the fallback is deny plus pin**: install makes `keystore-sock/` the service user's, 0755, the
server binds `keys.sock` itself, and the bind is kept from Pods by the Seatbelt deny and from
other service-uid code by the client's server pin ("The client pins the server"), as before;
the K7a amendment records which form ships. Two more K7a outcomes select the fallback: a
client-side peer that names launchd (Open requirement 4), and a Pod that can obtain the
listener from launchd itself (Open requirement 5).

### Key hierarchy

| key | made by | stored | derived or wrapped by | used for |
|---|---|---|---|---|
| master `M` | the first root `put` (Phase A) | `cred/keystore-master/master` | none | HMAC only, under fixed labels |
| system seal and fingerprint keys | derived | nowhere | `HMAC(M, label ‖ 0x00 ‖ "system")` | system records |
| scope-wrap key `W` | derived | nowhere | `HMAC(M, "k3sm-keystore-scope-wrap-v1")` | sealing each `scope.key` |
| scope key `K_u` | the first mutating operation on that user's scope (never a read), 32 bytes from `crypto/rand` | `.user/<uid>/scope.key`, a kind-0xFE record sealed under `W` | none | HMAC only |
| user seal and fingerprint keys | derived | nowhere | `HMAC(K_u, label ‖ 0x00 ‖ "user/<uid>")` | that user's records and their opaque fingerprints |
| delivery-record key | derived | nowhere | `HMAC(K_u, "k3sm-keystore-deliveries-v1" ‖ 0x00 ‖ "user/<uid>")` | the `deliveries` record |

The `scope.key` record uses the Phase A encoding with AAD scope `user/<uid>`, name `scope`,
version equal to the key epoch (1), and **generation equal to the account's 16-byte
GeneratedUID**.

The `deliveries` record uses the same encoding with AAD scope `user/<uid>`, kind 0xFD, name
`deliveries`, generation equal to the scope's bound GeneratedUID (the generation of its
`scope.key`), and version equal to the record's **sequence**. Every write re-seals the whole
record at the previous sequence plus 1; the empty record the mint writes is sequence 1.

- *Its floor key.* The record's floor line is `(user/<uid>, .deliveries, generation, seq)`.
  `.deliveries` is no valid entry name (a leading dot is an empty label), so the key never
  collides with an entry named `deliveries` (U63).
- *Write order.* The record, then its floor line, as for an entry's pointer ("The user-scope
  floor"). A crash between the two leaves the floor one behind, which is accepted.
- *Read.* A reader refuses a record whose sequence is below the floor's for its generation,
  with the user-scope floor message, wrapping `ErrCorrupt`. So a copied-back older record,
  which could still list a withdrawn UID as recorded, is refused, and the reconciler reads the
  refusal as `Indeterminate` (U88).

- **The GeneratedUID binding** closes a recycled uid. Before trusting `scope.key`, the store
  reads the uid's live GeneratedUID with `mbr_uid_to_uuid` and refuses with
  `ErrScopeOwnerChanged` when it differs from the record's generation. A deleted account whose
  uid is reused opens nothing of the old account's. Root removes such a scope with `sudo k3sm
  keys rm-scope user/<uid> --yes`, which revokes the scope's deliveries before it removes
  anything ("`rm-scope` revokes first").
- **A synthesized GeneratedUID is no answer.** For a uid with no directory record the
  membership API can return a compatibility UUID it makes up from the uid: the fixed prefix
  `FFFFEEEE-DDDD-CCCC-BBBB-AAAA` followed by the uid in hex. The lookup recognises that
  prefix and answers `ErrScopeOwnerUnknown`, never a GeneratedUID: a directory service that is
  slow or not yet up at boot must not read as a changed owner (U66). The store never binds a
  synthesized value either: a mutating operation that would mint `K_u` refuses with
  `ErrScopeOwnerUnknown` instead. This is measured, not assumed: on the rig, for uid 48213,
  which has no record, the lookup returned `FFFFEEEE-DDDD-CCCC-BBBB-AAAA0000BC55` with status 0,
  a synthesized value and not an error, and uid 0 got the same form
  (`FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000`) (the K0 spike's evidence of
  2026-11-21, `leg3b-unresolved-uid.txt`). So
  the prefix rule is required: without it, a uid whose record is gone would read as a real,
  changed owner.
- **`ErrScopeOwnerChanged` is answered only on a real answer.** It is answered only when the
  lookup returns a real, non-synthesized GeneratedUID that differs from the bound one. It is
  not a deleting outcome in this release: until K7a measures GeneratedUID stability across
  Migration Assistant, a macOS upgrade and a directory rebind, the reconciler reads it as
  `Indeterminate` and `doctor` names the scope (Open requirement 10). Only a dated amendment
  can put it on the allow-list, and then it deletes only on two consecutive sweeps ("Every
  deleting outcome counts only twice in a row"), like every other.
- **The lookup has a deadline.** It goes through the GeneratedUID-lookup seam with a deadline
  of 250 ms, the one value every caller uses (the store, the socket, the reconciler and the
  root verbs); a timeout or an error fails closed with `ErrScopeOwnerUnknown`, and nothing in
  that scope opens. That the GeneratedUID is stable across a server restart, and how long the
  cold lookup takes, which sets the deadline, is measured (K0 amendment 2026-11-21: about
  1.4 ms cold, 2.8 ms worst of 20, so 250 ms has wide margin).
  `mbr_uid_to_uuid` joins k3sm's SPI symbol canary (U7).
- **A missing scope is not an absent entry.** When `.user/<uid>/` or its `scope.key` is
  missing, the store answers the new sentinel `ErrScopeAbsent`, which is not definitive: the
  reconciler reads it as `Indeterminate`, never as a deletion. A scope that a
  restore left out, a volume not yet mounted or a directory moved aside therefore deletes no
  Secret (U64, U65).
- **An incomplete scope is not an empty one.** Inside a scope whose `scope.key` opens, a
  missing `entries/` directory or a missing `deliveries` record is also `ErrScopeAbsent`, and so
  also `Indeterminate`. The mint writes both, `entries/` and an empty `deliveries` record sealed
  under the new `K_u`, before it writes `scope.key`, so a scope whose `scope.key` opens has both
  unless something removed one; a restore that kept `scope.key` and lost `entries/` or
  `deliveries` must not read as "every entry gone" or "every delivery withdrawn". `ErrNotFound`
  holds only when `entries/` exists and opened and the entry's directory is absent from it.
- **The principle holds at every level of the layout.** Only the absence of the last thing
  looked up, an entry directory inside an `entries/` that opened, or a UID inside a
  `deliveries` record that opened and authenticated, is a definitive absence. A missing
  container at any level above it (`.user/`, `.user/<uid>/`, `scope.key`, `entries/`, the
  `deliveries` record) is `ErrScopeAbsent`, and every failure to open or read one is another
  error; none of them is `ErrNotFound` (U64).
- **A read never mints a scope.** `K_u` and the `.user/<uid>/` directory are created by the
  first mutating operation on the scope (`put`, `rotate` or `deliver`), under the store lock.
  A read (`list`, `read-for-exec`, `deliveries`, or any read by the reconciler) on a uid with
  no scope answers `ErrScopeAbsent` and creates nothing (a socket caller sees what an empty
  scope gives: an empty `list`, or `not-found`), so no read can bind a GeneratedUID or plant a scope (U64).
- **Fingerprints are per scope**, so equal values in two users' scopes have different
  fingerprints, and `list` is no equality oracle across users (U9).
- **Who can hold which key.** Root and the service user can read `M`, hence `W`, hence every
  `K_u`: "a process that holds the master has the keystore" stands. A copy of `.user/<uid>/`
  without the master opens nothing, and neither does a copy of one user's records with its
  `scope.key` (U8).

**Rewrap of scope keys.** The change that adds quotas and the delivery record extends
Rewrap's two-phase procedure with one class of record: each `scope.key`, re-sealed under the
new `W`. User records stay sealed under their `K_u`, byte for byte unchanged, and the run is
resumable at every step as G12 requires (U12). Before that change, Rewrap refused with
`ErrScopeUnsupported` while a `.user` directory existed (U5), which is what keeps a rollback
to an earlier build from orphaning user scopes. No user scope existed outside the package
before that change: the user scope was reachable only from inside `pkg/keystore`, a gate a
test enforces (`TestUserScopeIsUnexported`), so no build ever shipped a scope without its
`deliveries` record, and none needs a migration.

**One damaged scope blocks Rewrap.** Rewrap refuses, writing nothing, while any scope's
`scope.key` does not open, a scope directory or `.user` is not one the store trusts, a
`scope.key.new` is not a file Rewrap wrote, `.user` holds a stray directory named for a uid that
can never own a scope (below 501, the service uid, or above 2147483647), which root removes by
hand, or `.user` lists past its name bound: re-wrapping
past it would leave that scope sealed under a master that no longer exists. The refusal is
`ErrCorrupt` and names the scope. After committing every `scope.key`, and before it swaps
the master, Rewrap re-opens each planned `scope.key` under the new `W`; one swapped back to an
old copy or damaged since its commit refuses the swap, so the old master is not retired under
it. Rewrap pins each scope's `K_u` (by a fingerprint, never the key), generation and created
time when it plans the scope, and its commit and that last check refuse (`ErrCorrupt`) a
`scope.key` that no longer holds them, even one that opens under the new `W`. The recovery is root's: restore the scope from a backup, then run `rewrap` again. Removing
that scope's directory `.user/<uid>/` by hand recovers only a user who never delivered (its
owner loses its values and re-puts them): for one who did, the user-scope floor records the
`deliveries` record past its first sequence, and the owner's next put refuses to mint a fresh
scope over it. For that user the recovery is `rm-scope`, which a later change builds. Until it
lands, root removes `.user/<uid>/` and runs `sudo k3sm keys floor --rebuild`, and the cost is
the whole store's: rebuild writes the floor from what is on disk, so it lowers every record's
floor, for every user, to the sequence on disk at that moment, and a copied-back older record
already in place is accepted from then on. Rewrap's refusal is correct either way and stays.

**Rewrap does not re-key `K_u`.** It re-seals each `scope.key` under the new `W`, but the
`K_u` inside is the same 32 bytes, and every user record stays sealed under it. So an old master
together with an old copy of a `scope.key` still opens that user's records, old and new
(residual 15). A per-user re-key (a new `K_u`, re-sealing that user's records) is a non-goal
for this release. Because of that, `sudo k3sm keys rewrap` prints a warning whenever `.user/`
exists, before it starts and again when it finishes: Rewrap does not protect the user scopes
against an exposed master, and the documented procedure after a suspected master exposure is
that each user re-puts their values, with new credentials from each value's issuer (U101).

### Quotas

Each user scope holds at most 256 entries, 16 MiB of sealed records and 64 live entries in its
`deliveries` record. Over the first two, `put` and `rotate` answer `ErrQuota`; over the third,
`deliver` does; `rm` and `withdraw` still work (U13). The byte budget counts every file in every
entry directory, each entry's `generation` file included, and the `deliveries` record. `rm`
makes room; a `withdraw` does not, since its tombstone counts until its Secret is gone, when the
reconciler's pruning (a later change) reclaims it. The `quota` error says so and never claims a
withdrawal frees room.

**When `rotate` gets `ErrQuota`.** Retention is unbounded, so an entry rotated often fills the
byte budget. The recovery is `rm` then `put`: `rm` frees every version of the entry and `put`
stores the new value as version 1 of a new generation. The CLI's `quota` error says so. `rm`
is a deletion, so run `put` at once: the entry's deliveries are deleted only when two
observations at least 60 s apart see it gone ("Deleting observations are spaced in time"), and
one that sees the new entry first resets the count. Past that, the delivered Secrets are
deleted and their deliveries withdrawn, and the user declares them again with `deliver` (U97).

**The `deliveries` record has its own bound.** It is exempt from the store's 64 KiB value cap
and holds at most 320 entries: 64 live entries plus 256 withdrawn tombstones. An entry is at
most 3,328 bytes: the UID (36 bytes), the KeyDelivery's `metadata.name` (at most 253), the
target tuple (`entry` at most 269 bytes, `namespace` 63, `secretName` 253, `requestedBy` 21,
and `items`: at most 8 items, each a `field` of at most 32 bytes and a `key` of at most 253,
each length-prefixed, 8 × 293 = 2,344 bytes in one length-prefixed blob), the 32-byte digest,
the last delivered version (8 bytes), a state byte and seven 4-byte length prefixes, 3,308
bytes in all. So the record's plaintext is at most 1,040 KiB plus a 16-byte header, and the
store refuses to read or write a sealed record over 1,056 KiB.

- *`deliver` is refused at the bound.* It adds an entry, and answers `quota` when the record
  has 64 live entries or 320 in all.
- *Revocation always succeeds,* with the residuals below. A withdrawal turns a live entry
  into a tombstone in place, so it never adds an entry, never grows the record and is never
  refused for the bound. It is
  monotone, so it needs nothing a grant needs: it opens `scope.key` with the generation the
  record authenticates under `W`, never the live GeneratedUID lookup (a lookup that times out,
  fails or answers for a new owner of the uid does not stop it), it opens `scope.key` under the
  live `W` or `master.next`'s, so it runs at every step of a Rewrap, and a floor it cannot read
  does not stop it: it writes the tombstone at the record's sequence plus 1 and appends the
  floor line it can. In place of the floor it checks the record against the highest sequence
  the store process has read or written for that scope and generation, an in-memory mark
  raised on every successful read and write and shared by every store handle in the process
  (keyed by the keystore directory too, so two keystores keep apart), and refuses (`ErrCorrupt`) to re-seal a record
  below it, so a copied-back older record does not come back at a later sequence with a later
  tombstone lost. A withdrawal of a UID already withdrawn appends the record's floor line
  again, so a floor line an earlier withdrawal could not append is written by the next one; the
  floor keeps the highest sequence, so the repeat is idempotent. `rm` is a revocation too: it
  only removes files, so it needs neither `W` nor `K_u`, and is never refused for a lookup
  that ran and failed or timed out, or for `ErrRewrapInProgress`. A lookup refused at once for
  capacity, where none ran (eight already outstanding, or an earlier call for the uid stuck past
  its deadline), refuses `rm` with a retryable error and removes nothing: going ahead on it would
  let a burst of stuck lookups stand in for the owner check. A withdrawal does no lookup, so it
  goes ahead in every case. A lookup that answers a real
  GeneratedUID other than the one `scope.key` records refuses it with `ErrScopeOwnerChanged`:
  the uid was reused, and its new holder must not delete the former owner's values (root
  removes such a scope).
  *Residual (floor unreadable at a withdrawal).* With the floor unreadable, the withdrawal
  cannot check the record against it, only against the process's in-memory mark. A copy put
  back below a sequence this process has not seen (after a restart, say) is re-sealed with the
  tombstone at its own sequence plus 1. That record is at or below the floor, so the next read
  with a readable floor refuses it, except when it was exactly one behind, where the re-sealed
  copy is accepted and a later tombstone or a grant the copy predates is lost; the reconciler's
  target-matching delete and `doctor`'s floor check are what notice it.
  *Residual (record below a readable floor).* A withdrawal whose record is below a floor it
  can read is refused (`ErrCorrupt`, the user-scope floor message): re-sealing it would bring
  back a list the floor already says was replaced. The withdrawal waits on the root remedy:
  restore the current record, or, for a deliberate restore, `sudo k3sm keys floor --rebuild`,
  then withdraw again.
  *Residual (a refused revocation).* A withdrawal or an `rm` can still be refused: by the store
  lock held past its wait, or by damage a process running as the service uid did to the scope
  (a `scope.key` or record it rewrote, a directory it replaced). The store cannot rule out the
  service uid, so the remedy is the reconciler's: it treats a withdrawal that is refused or
  errors as "delete the delivered Secret anyway", so the value leaves the cluster whatever the
  record says. That rule is owed by the reconciler change, not this one.
  *Residual (withdrawal ignores ownership).* A withdrawal does no GeneratedUID lookup, by
  design, so when a uid is reused its new holder can withdraw the former owner's deliveries.
  That costs availability (a delivered Secret is deleted), never access: a withdrawal only
  adds a tombstone, and opens and returns no value.
  *Residual (no lines in this build).* Until the real append-only floor and audit log land,
  `New` installs ones that refuse every call, and a revocation commits regardless: its tombstone
  or removal stands, and it is reported (`errCommitted`) with no audit line and no floor line
  written for it.
- *A tombstone is pruned once its target is no longer its Secret.* The reconciler removes a
  withdrawn entry when its recorded target is not this UID's owned Secret, gone or held by a
  Secret that fails the ownership test for this UID, on two observations at least 60 s apart
  ("Deleting observations are spaced in time"), so a target someone else reuses still prunes
  (Open requirement 7); a failed Get keeps it. A
  tombstone is what lets the orphan sweep and `rm-scope` still find a withdrawn delivery's
  Secret (U96). The delivery bound is what bounds the
reconciler's revocation allowance of each uid ("The user-scope floor", per-uid fairness). Phase A's unbounded retention stays
for the system scope.

### The user-scope floor

Phase A's floor is root-owned and written only by root verbs ("Pointer sequence and floor").
User-scope writes run in the server process as the service user, which cannot write a
root-owned file, and a floor in the service user's tree would reopen the copied-back pointer
residual the maintainer did not accept. So the user-scope floor is an append-only log the
service user can only add to.

- **Lines.** The log holds `(scope, name, generation, seq)` lines. A reader takes, per
  `(scope, name)`, the highest `seq` among the lines whose generation matches the entry's, so
  the floor can only rise. A copied-back older `current` is refused with the user-scope floor
  message, wrapping `ErrCorrupt`: Phase A's text with its last sentence replaced, so that for a
  deliberate restore it names `sudo k3sm keys floor --rebuild`, never removing
  `keystore-floor.json`, which is the system floor and holds no user entry (U20).
- **Write order.** Phase A's: the record, the pointer, then the floor line. A crash between
  the last two leaves the floor one behind, which the rule accepts, and the next user-scope
  write to that entry appends the line.
- **Two variants; K0 picks; dated amendment.** Which one is built depends on a measured
  platform fact, not on a preference:
  1. *The append-only flag.* `sudo k3sm install` creates the log owned by the service user,
     mode 0600, with the BSD system append-only flag (`chflags sappnd`), which only root can
     clear. The service user can append lines; it cannot truncate, overwrite, rename or unlink
     the file, and the data root above it is root's, so it cannot replace it. This variant
     stands only if, on an APFS data volume, the service user can `O_APPEND` and cannot
     defeat the flag with any entry of **the defeat list**: `chflags nosappnd` by the service
     user, `O_TRUNC`, `ftruncate`, a `pwrite` at an offset, a write through a shared writable
     `mmap` of the file, `fcntl(F_PUNCHHOLE)`, `link()` to a new name, `fclonefileat` then a
     swap, a `renamex_np` swap (`RENAME_SWAP`) through the parent, `exchangedata`, `unlink` or
     `rename` through the parent, or a second open with `O_TRUNC`; and if `chmod` by the owner
     widens nothing (measured, K0 amendment 2026-11-21). The kernel securelevel (`sysctl kern.securelevel`)
     and whether root can clear the flag at it are recorded too (measured, K0 amendment 2026-11-21).

     The spike measures the list once; a standing integration row keeps measuring it. U50 runs
     every entry of the defeat list against the flagged files as the service user, through the
     same root-run mechanism as the gate's existing `--root` mode (the test binary is built as
     the invoking user and only it runs under `sudo -n`, dropping to the service user for each
     attempt), and fails if any attempt changes a byte already written or the flag. A macOS
     update that opens a new hole then turns the gate red rather than the floor quietly weak.
  2. *The floor helper.* If any of those checks fails, a small root launchd daemon on the
     `k3sm-netd` pattern owns both logs as root, mode 0600, and appends lines on the server's
     request over a root-owned socket that admits only the service uid, refusing every request
     but `append` and `read`.

     **Binding on the helper variant.** If K0 picks the helper, the K0 amendment must add four
     things before the change that builds the user-scope floor is built: (a) the helper's
     socket path; (b) its Pod deny, through the same `keystore-` prefix deny if the path is
     under it, else a deny of its own in runtimed's leaf; (c) a peer
     check beyond the uid, with the same pinning as the client's ("The client pins the
     server"): the helper reads the peer's audit token and admits only a peer whose cdhash is
     the installed binary's, running as the service uid, and the server pins the helper the
     same way, as root and the installed binary; and (d) its own U and E rows. The pending
     rows U70, U71 and E25 hold their places; they apply only in the helper variant, and the
     amendment names their tests or drops them if K0 picks the flag.
- **The flag is checked, not assumed** (flag variant). The server reads `st_flags &
  SF_APPEND` on both logs at start and at every `doctor` run, through the chflags flag source,
  and refuses to start the listener if either flag is clear or either file is not the
  service user's (U21).
- **Root maintenance verbs.** `sudo k3sm keys floor --rebuild` (the restore procedure) and
  `sudo k3sm keys audit --rotate` run as root only. Each writes the marker
  `keystore-maintenance` and then waits for the listener to stop, which it does when it sees
  the marker (it closes its connections and stops accepting; launchd keeps the socket bound).
That wait is the store `.lock`
  taken exclusively, bounded at 30 s: the verb gets the lock once no server operation holds
  it, and past 30 s it removes its marker and refuses, changing nothing. It then takes the
  floor lock `keystore-lock`, which only root can open (Open requirement 2). Holding both, it
  **writes and fsyncs the new file before it touches the old one**. Rebuild writes
  `keystore-user-floor.log.new` from the scopes' entries, walking `.user/` by descriptor ("Root
  walks service-user trees by descriptor"); rotate writes an empty
  `keystore-audit.log.new`. The new file is created root-owned, mode 0600, and stays so while
  it is written.
- **Rebuild keeps damage visible.** Rebuild writes one line for every entry directory that
  holds a `generation` file, not only for the entries that open. An entry whose `current`
  authenticates gets its pointer's sequence. An entry with no authenticated pointer (no
  `current`, a `current` that fails to open, or one that names a missing version) is recorded
  as present at sequence 0 for the generation its `generation` file holds. A floor line for
  the entry's generation is what makes a pointerless directory damage rather than an
  interrupted put (Phase A's rule, G16), so after a rebuild such an entry still reads
  `ErrCorrupt` and is never turned into `ErrNotFound`, which the reconciler would read as a
  deletion. A directory with no `generation` file is the shape a crashed put leaves before
  its first step and gets no line (U25).
- **Rebuild never lowers.** Rebuild opens every scope under `.user/` before it writes the new
  file's first line, and a line it cannot write is a floor it would lower:
  - *Rebuild skips the owner check.* Rebuild reads every scope whose `scope.key` opens under
    `W` without the GeneratedUID check, as the reconciler reads an owner-changed record ("An
    owner change still finds its targets"), and writes its pointers' and its `deliveries`
    record's lines. So neither an owner change nor a departed account
    (`ErrScopeOwnerUnknown`, a lookup past its deadline) blocks a rebuild, and each such
    scope's floor is kept until root removes the scope (Open requirement 12, U129).
  - *An unopenable scope refuses the rebuild.* If any scope's `scope.key` does not open under
    `W`, or any of its files fails to open or authenticate for any other reason (`ErrBusy`
    included), rebuild refuses to finish and names the scope. It refuses before it touches the
    old file, so it changes nothing: it unlinks its staging file, leaves the old log as it was
    and removes the marker.
  - *The `deliveries` record gets its line.* For each scope rebuild writes the line for the key
    `(user/<uid>, .deliveries, generation, seq)` with the record's authenticated sequence ("Key
    hierarchy"), so a copied-back older record is refused after a rebuild as before it (U88).
- **A flagged file is never renamed, and nothing is renamed over one.** The rig spike measured
  that root's rename over an `sappnd` target fails with `EPERM` and leaves it in place, and
  that the service user cannot rename a flagged file away either (`EPERM`); root can clear
  the flag, at `kern.securelevel` 0 (the K0 spike's evidence of 2026-11-21,
  `status.txt`, leg 1, and `leg1.txt`, the `rename-away`, `rename-over` and `ROOTRENAME` lines). Root renaming a
  flagged source was not measured, so the order below does not depend on it. The steps, after
  the new file is written and fsynced:
  1. clear the old file's flag, on its own descriptor, and in the same step `fchown` it to root
     and `fchmod` it 0600 on that descriptor (Open requirement 1);
  2. rotate only: shift the archives and rename the old log to `keystore-audit.log.1`
     (below);
  3. rename the new file over the canonical name;
  4. set `sappnd` on the new file through the descriptor the verb still holds from its create,
     and, for rotate, on the `.1` file through the old file's descriptor;
  5. flag variant: `fchown` the new file to the service user, on that same descriptor, only
     now that its flag is set;
  6. remove the marker.

  That root's `fchown` succeeds on a file it has just flagged `sappnd` is not measured (leg 1
  saw the owner's `chmod` refused on a flagged file); K7a measures it before the change that
  builds the maintenance verbs, and if it is refused that change waits for a dated amendment
  that names another order.
- **No unflagged window for the new file.** The new file is root-owned 0600 from its create
  until step 5, after its flag is set, so no service-user process can open it before the flag,
  and the service user never holds a descriptor on it from before the flag (U90, run as
  root). The old file gets the same protection the other way round: it becomes root 0600 in
  the step that clears its flag (Open requirement 1, U118). The server opens it only after the marker is gone ("The server reopens after
  maintenance"). A crash that leaves the canonical file unflagged or root-owned keeps the
  listener down: the server's check refuses either (U21), and the marker stays until a rerun
  of the verb finishes the steps.
- **`audit --rotate` keeps four archives.** The previous logs are `keystore-audit.log.1` (the
  newest) to `keystore-audit.log.4`. Rotate refuses, changing nothing, when `.4` exists, unless
  `--discard-oldest` is given, so evidence is never discarded without root saying so; the
  `doctor` hint past the soft cap says to export the archives first (copy them off the Mac),
  then rotate. Step 2 opens each archive from `.3` down to `.1`, clears its flag on its
  descriptor, `fchown`s it to root 0600 in the same step (a no-op for an archive already
  root's, Open requirement 1), renames it one number up and sets the flag again on the same
  descriptor; with `--discard-oldest`, `.4` is first opened, its flag cleared on its
  descriptor, and unlinked.
  Rotation resets every uid's audit share and budgets to 0 (below). That is deliberate: only
  root rotates, and what a uid wrote before is kept in the archives, so the evidence a reset
  share can push out of the live log is bounded by the four archives (U91).
- **Root never acts by path where the service user can write.** `server/` and `.user/` are
  the service user's (and so is `keystore-sock/` in the deny-plus-pin fallback), so a name
  root created there could be a symlink or a swapped file the service user planted. The marker and both staging files therefore live in the root-owned
  data root (root:wheel 0755), where only root creates names, under `keystore-`-prefixed names
  that the Pod prefix deny covers ("Pod denies"). Every step goes through one descriptor on the
  data root, opened `O_DIRECTORY|O_NOFOLLOW` and judged by `fstat` (root-owned, not group- or
  other-writable) before use:
  - each create is `openat` on that descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW`, so an existing
    name, a symlink included, is refused rather than followed or reused;
  - `fchflags` to set `sappnd` goes on the new file's own descriptor right after the rename
    (step 4), since a flagged file cannot be moved, and `fchown` to the service user (flag
    variant) goes on that same descriptor after the flag (step 5);
  - the old file is opened `O_NOFOLLOW` through the same descriptor and judged by `fstat` (a
    regular file, the expected owner) before its flag is cleared with `fchflags` on that
    descriptor; the rename is `renameat` relative to the data-root descriptor, never by path;
  - a staging file left by a crash is opened `O_NOFOLLOW`, its flag cleared on its descriptor,
    and unlinked with `unlinkat` before the create is retried with `O_EXCL`.

  A planted symlink or a swapped file at any of these names refuses the verb and changes no
  byte of either log (U68, run as root). The old file and each shifted archive are unflagged
  between their flag clear and their next flag set, under the exclusive lock with the listener
  stopped, and root 0600 for that whole interval, since the clear and the `fchown` are one step
  (Open requirement 1, U118; residual 12). A crash there can leave an unflagged file; the marker is still
  present, so the listener stays down, and rerunning the verb finishes the steps. The verb
  removes the marker last (U22). Rebuild is
  the user-scope twin of Phase A's "remove `keystore-floor.json`, then run any root verb".
- **The server reopens after maintenance.** The server's append descriptors still name the
  old files after a maintenance verb renames them, and its per-uid counts describe the old
  contents. So when the marker is gone, before the listener restarts and before any server
  append, the server takes the store lock exclusively, reopens its audit and floor append
  descriptors through the data-root descriptor (`O_APPEND|O_NOFOLLOW`, each judged by `fstat`
  as the canonical, flagged file), recounts every uid's share from the new files, and only then
  releases the lock. An append that waited for the lock, the reconciler's included, lands in
  the new file and is charged against the recounted share: after `audit --rotate` every uid's
  audit share is 0, and after `floor --rebuild` every uid's floor share is 0, since rebuild's
  lines are root's and charged to no uid (U22).
- **Every append checks that its descriptor is still the canonical file.** The marker is a
  signal, and a server can miss it: it can be stopped, slow or between checks for the whole
  maintenance run. So under the store lock, before every audit or floor append, the server
  compares its descriptor's `(dev, ino)` from `fstat` with the canonical name's, read with
  `fstatat` on the data-root descriptor and `AT_SYMLINK_NOFOLLOW`. On a mismatch it reopens the
  file as above, judges the new descriptor, and recounts every uid's share from the new file
  before it appends. A server that never saw the marker therefore never writes into a renamed
  archive or an unlinked file, and its counts follow the file it writes to (U99).
- **Size caps.** Each log has a soft cap (`keystore.logSoftCap`, default 64 MiB) and a hard cap
  (`keystore.logHardCap`, default 256 MiB). Past the soft cap `doctor` shows the size and the
  rotate hint; past the hard cap the server refuses every mutating user operation with
  `ErrLogFull` until root rotates or rebuilds, except the revocation class below, which draws
  on its uid's own revocation budgets above the hard cap (U24, U67). A line is at most 1 KiB: every
  field is bounded (names, namespaces, sentinels), and the server refuses to write a longer
  one.
- **Per-uid fairness.** The logs are shared, so one user must not be able to fill them for
  everyone. Each uid gets a budget in each log, a fixed byte count: `keystore.logUIDShare`,
  default 16 MiB, which is 1/16 of the default hard cap. The share is at most 1/16 of the hard
  cap: a configured share above `logHardCap / 16` is refused at server start. At the default
  caps, fewer than 16 uids cannot by themselves bring a log to the hard cap: 15 uids at their
  shares and both their revocation budgets, with the reconciler budget below, come to
  15 × (16 MiB + 320 KiB) + 1 MiB, under 246 MiB of the 256 MiB. Root's own lines, charged to
  no uid, are not bounded by this. The server counts each uid's bytes per log from the log at
  start and on every append.
  - *What is charged.* Every line counts against the share of the uid it acts for, reads
    included: a socket operation's line (`list`, `read-for-exec` and `deliveries` as much as
    `put`) and its floor line to the peer uid, a `refused` line to the peer uid it names (an
    ineligible peer's pre-frame line excepted, below), and a
    reconciler `deliver-write` or `deliver-delete` line, and the floor line of a record
    withdrawal, to the delivery's owner uid, except a drift repair ("Repairs are not charged to
    the owner"), which acts for no uid. Lines written for root verbs are charged to no
    uid. A reconciler line that no uid is charged for draws on the reconciler budget below.
  - *The reconciler budget.* The reconciler's lines that act for no uid draw on one
    **reconciler budget** of 1 MiB per log, separate from every uid's share and budgets and
    excluded from the hard-cap test: they are never charged to a uid and never refused for the
    hard cap. Its lines are the `refused` lines for forged Secrets ("A forgery is not charged
    to the victim"), the drift repairs ("Repairs are not charged to the owner") and their
    summaries, and the pre-frame `refused` lines of ineligible peers (uid 0, the service uid,
    a uid below 501 or at 2^31 and above), which have no share to charge and draw on this
    budget with its once-a-minute dropped-count summary. The budget is split by source, and by
    namespace within two of them (Open requirement 9): 384 KiB for forged-Secret lines, 384 KiB
    for repairs and their summaries, each capped at 64 KiB per namespace, and 256 KiB for
    pre-frame refusals. Each carries `"charge":"reconciler"` and its source, so the server
    recounts every part from the log at start, on every append and after maintenance, like the
    shares. Once a part is spent the reconciler writes none of its lines; `doctor` shows a Warn
    with the count, and the count is persisted, not kept only in memory: the next summary line
    written for that source carries it, and root's next `audit --rotate` writes any count still
    unwritten as one line charged to no uid (U85, U126).
  - *Past the share, reads are refused too.* A uid past its share has its own mutations and
    its own reads refused with `ErrLogFull` (code `log-full`) before any line is written, so
    no read is a way around the share. Its `refused` lines and their summaries are not written
    either: the server counts that uid's dropped lines in memory, `doctor` shows the count,
    and root's next `audit --rotate` writes it as one line charged to no uid.
  - *A share refusal is one uid's alone.* No other uid is refused for it: every other uid's
    mutations and reads draw on its own share, which no other uid's lines are charged to (U51).
    What one uid can still do to another is delay it through the shared store lock, which is
    bounded but not isolated ("The audit log", lock modes and fairness). That refusal
    happens before any append and is not a failed append, so it never counts as the global
    append failure that refuses every uid's reads ("The audit log", fail closed); only an append
    that the file system refuses, or the hard cap, does. That global failure is shared: a full
    disk refuses every uid's mutations and reads alike, and only revocations go ahead.
  - *The reconciler past an owner's share.* A `deliver-write` of a new version past the
    owner's share is refused and the reconciler reads that as `Indeterminate`, so the Secret
    keeps its last version. The one exception is the `deliver-write` that follows a `rotate`
    (the rotation write), which is in the revocation class: a rotation is how a user revokes a
    value a Pod already holds (residual 8), so it must reach the Pods.
  - *The revocation class is never blocked by the share.* Its members are the socket's
    `withdraw`, `rm` and `rotate`, the floor line of a record withdrawal, and the reconciler's
    `deliver-delete`, its `deliver-write` of a withdrawal and its rotation write. Their lines
    are charged to the uid's share while it has room; past the share they bypass it, and the
    hard cap, and draw on one of that uid's two **revocation budgets** in that log:
    - the **reconciler allowance**, 256 KiB, used only by the reconciler's revocation lines for
      that uid's deliveries (`deliver-delete`, the withdrawal's `deliver-write` and floor line,
      the rotation write);
    - the **socket margin**, 64 KiB, used only by that uid's own socket `withdraw`, `rm` and
      `rotate` lines and their floor lines.

    Neither budget can draw on the other, and neither belongs to any other uid. Both are fixed
    and counted per uid from the log, like the share: a uid's bytes past its share are
    revocation lines, and each line's `via` (`reconciler` or `socket`) says which budget it
    used, so the server recounts both with the share at start, on every append and after
    maintenance. Only the exhaustion of the budget a line draws on refuses it, with
    `ErrLogFull`; neither the share, the hard cap, the uid's other budget nor any other uid's
    lines do. One uid's revocations can therefore never be refused because of another uid; a
    user cannot block an admin-driven deletion of its Secrets by spending its own socket
    revocations; and a user cannot keep a revoked Secret in place, or keep a value it means to
    revoke, by filling its share (U67).
  - *Only a line that revokes is in the class.* An `rm`, `withdraw` or `rotate` that names an
    entry or object that does not exist changes nothing, so it is charged like any other line
    and refused past the share.
  - *The reconciler allowance covers every reconciler revocation.* The reconciler's
    revocation lines for a uid's deliveries are charged to the delivery's owner, so they draw
    on the owner's reconciler allowance, never on another uid's and never on the socket
    margin. Their need is bounded: past its share a uid can make no new `deliver`, so they are
    the lines of the at most 64 deliveries live when it crossed its share (the quota,
    "Quotas"), four lines each of at most 1 KiB (the line bound, "Size caps"): the
    `deliver-delete`, the withdrawal's `deliver-write` and floor line, and one rotation write.
    That is at most 64 × 4 × 1 KiB = 256 KiB, the whole allowance, so every reconciler
    revocation for that uid, the first rotation write past the share included, finds room. The
    rotation write is bounded to one per live delivery: past the owner's share, each
    delivery's rotation write draws on the allowance once per log, until root's next `audit
    --rotate` or `floor --rebuild` recounts the shares; a further rotation's write for that
    delivery past the share is `Indeterminate`, the Secret keeps the version the first rotation
    delivered, and `doctor` names the delivery and the rotate hint.
  - *A stall is visible to the user.* A `rotate` whose delivery will stall this way (its owner
    is past its share and a live delivery of the entry has used its rotation write) is still
    stored, and is answered `ok` with the warning `stored; delivery pending: past your log
    share`. The CLI prints that warning line and exits 0, so the user knows the Pods still hold
    the old value (U92).
  - *The socket margin keeps a user able to revoke.* A uid past its share, even with 64 live
    deliveries, still has its 64 KiB socket margin for `withdraw`, `rm` and `rotate`, about 32
    of them at two lines of at most 1 KiB each (the operation's line and its floor line). A uid
    that spends its margin, for instance by rotating without end, refuses only its own further
    socket revocations, until root rotates the log.
  - *How far a log can pass the hard cap.* Only revocation lines are written past the hard
    cap, and each uid's are bounded by its two budgets, so a log can grow past the hard cap by
    at most 320 KiB (256 KiB plus 64 KiB) times the number of user scopes, plus the 1 MiB
    reconciler budget, whose lines the hard cap does not test either. User scopes are
    bounded by the host's eligible local accounts: a scope is minted only for an eligible uid
    (501 to 2147483647) with a real, non-synthesized GeneratedUID ("Key hierarchy", "Eligible
    peers"), so a local user cannot create scopes beyond the accounts root made. When a log's
    size is past the hard cap at all, `doctor` shows a Warn with the overshoot in bytes and the
    `audit --rotate` or `floor --rebuild` hint (U84, residual 5).
  - The hard cap and the per-uid budgets bound the whole log (U51, U62, U67).
- **Backup and restore.** The flag does not survive `cp`, rsync or Time Machine, so a restore
  always ends with `floor --rebuild`, and `audit --rotate` re-flags the audit log. Until then
  the listener refuses to start (U25, E17).
- **What it does not stop.** A process running as the service user can append a huge `seq`
  and make an entry unreadable, a denial of service the same-user model already permits, since
  that process can delete the entries outright; and it can read the master and forge, as Phase
  A says. What the log refuses is what Phase A's floor refuses: a pointer put back by a writer
  that cannot read the master.

### The audit log

`keystore-audit.log` is JSON Lines, append-only like the user-scope floor, with one line per
call through the socket, per root verb, per reconciler write or deletion, and per connection
refused before its first frame:

```json
{"v":1,"ts":"<RFC3339Nano>","op":"put","via":"socket","caller":{"uid":501,"user":"alice","pid":4242},"scope":"user/501","name":"claude-a","version":3,"fingerprint":"<per-scope fingerprint or empty>","namespace":"<ns or empty>","result":"ok"}
```

- **Fields.** `op` and `result` are open sets (today `put`, `rotate`, `rm`, `list`,
  `show`, `exec-read`, `deliver`, `withdraw`, `rewrap`, `rm-scope`, `floor-rebuild`, `audit-rotate`,
  `deliver-write`, `deliver-delete`, `refused`; and `ok` or a sentinel name). `via` is
  `socket`, `root` or `reconciler`. `caller.user` is display-only beside the uid, and `pid` is
  advisory. Readers ignore unknown fields, and `v` bumps only on a breaking change (U23). The
  user docs specify the format.
- **Never a value, never a value length.** Mode 0600 because entry names are private to their
  owner; readable by root and the service user only. Every line also goes to the server log at
  Info, without `fingerprint`.
- **Every append takes the store lock.** Each append to the audit log or the user-scope floor
  takes the store `.lock`, whoever writes it: the listener's operations, the reconciler's
  `deliver-write`, `deliver-delete` and withdrawal lines, the floor line of a withdrawal, root
  verbs and the pre-frame `refused` lines. The maintenance verbs hold that lock exclusively for
  their whole run, so no line can land in a file they are replacing. An append waits at most
  2 seconds for the lock: past that, a socket operation fails with `busy`, the reconciler reads
  `ErrBusy` as `Indeterminate` (a revocation first retries, below), and a pre-frame refusal
  still closes the connection and counts its line as dropped (U22). In `pkg/keystore` a grant
  appends inside the hold it writes under, a revocation commits and then appends inside the
  same hold, and a refusal after the lock was taken appends before it is released; a refusal
  that came before the lock takes it briefly to append, and one for which the lock cannot be
  had (the keystore directory missing, the lock held past its wait, an invalid configuration)
  is not audited rather than appended without it.
- **Lock modes and fairness.** Reads (`list`, `read-for-exec`, `deliveries` and the
  reconciler's reads) take the store lock shared, and their audit lines are appended under that
  shared hold, which excludes the maintenance verbs as an exclusive hold does; the server
  serialises its own appends and share counts in process. Mutations take the lock exclusive.
  In the server both modes go through one in-process reader-writer lock with writer preference
  (a waiting writer blocks new readers, as Go's `sync.RWMutex` does) in front of the `flock`, so
  a stream of reads cannot starve a mutation.
  - *A hold-time bound.* An exclusive hold by the server does at most 50 ms of work per
    operation; larger work (a sweep, a scope's many deliveries) is chunked into separate holds,
    and no hold spans a call to the API server or a directory lookup. The GeneratedUID lookup
    runs before the lock is taken, with its own 250 ms deadline, and its answer is cached for
    that hold, so a slow directory service never stretches a hold. The root verbs that hold the
    lock for their whole run (`rm-scope`, `floor --rebuild`, `audit --rotate`, Rewrap) are
    outside the bound. The bound is asserted on a fake clock (U108) and measured in K7a.
  - *Revocations retry.* A reconciler revocation (a `deliver-delete`, a withdrawal, a rotation
    write) that gets `ErrBusy` retries within the same sweep, up to 3 times with jittered
    waits, before the result is `Indeterminate` (U89).
  - *What one uid can do to another through the lock.* It cannot be refused for another uid's
    log lines ("Per-uid fairness"), but it can delay another uid: its exclusive holds are at most
    5 a second (the mutation rate limit, "The socket") of at most 50 ms each, so one uid holds
    the lock exclusively for at most 250 ms in any second. Many uids together can push another
    uid's wait past the 2-second bound, which is `busy`, never a refusal for the share and
    never a deletion.
- **Order: a grant appends first; a revocation commits first.** A grant (a user `put`, and
  `deliver`, each with the scope's mint) appends its audit line before its first write, after
  every refusal it can give, and only then commits: a failed append refuses it and nothing is
  written, the mint's directories included, so no grant takes effect unrecorded. A refusal
  before that point is audited best effort with its result, and a commit that fails after the
  line gets a second line with its result. Every other socket operation, and the revocation
  class above all (`withdraw`, `rm`, `rotate`), commits its change to the store, then appends
  its audit line, then replies. If the append fails after the commit, the change stands and the
  reply says so: `ok` with the warning `committed; audit failed`, which the CLI prints. The
  server counts every such unaudited operation in memory, and `doctor` shows the count (U112).
  An audit line carries only validated fields; a field that failed its grammar is a fixed
  placeholder.
- **Fail closed, except for revocations.** While appends fail (a full disk, an I/O error), the
  server refuses user mutations and reads (`list`, `read-for-exec`, `deliveries`) until an
  append succeeds (U32). The revocation class is the exception: a socket `withdraw`, `rm` or
  `rotate` and the reconciler's revocation deletes still go ahead, their lines dropped and
  counted in memory, and `doctor` shows the count. A full disk must not keep a revoked
  credential delivered (U109). The user docs recommend, without requiring, a data volume with
  an APFS reserve (`diskutil apfs addVolume … -reserve`), so that other writers on the Mac
  cannot fill the keystore's disk.
- **Coverage.** Three sources write lines besides the socket's operations, so no act on the
  keystore goes unrecorded:
  - *every root verb* (`put`, `rotate`, `rm`, `rewrap`, `deliver`, `floor --rebuild`, `audit
    --rotate`, `rm-scope`, and the reads `list` and `show`), with `via` `root`, once
    `sudo k3sm install` has created the log; before that the system scope works as in Phase A
    and writes no line (U52);
  - *every reconciler write and delete* of a Secret and every withdrawal of a sealed record
    entry, with `via` `reconciler` and the KeyDelivery's namespace and UID (U53);
  - *each pre-frame refusal*: a connection from uid 0, from the service uid or from a uid
    below 501 is refused before any frame is read, and the refusal writes a `refused` line
    carrying the peer uid (U54).
- **`refused` lines are rate-limited per uid**, at most 10 a minute, with one summary line
  giving the count dropped, so a hostile local user cannot fill the log with refusals (U33).
  Pre-frame refusals are rate-limited the same way, per peer uid, with their own dropped-count
  summary (U54).
- **What it claims.** The log is append-only against truncation and deletion by the service
  user, except through a descriptor it opened before a maintenance verb's flag clear (residual
  12); by path it cannot open the old file or an archive while unflagged, since both are root
  0600 by then (Open requirement 1). A service-user process outside Seatbelt can append forged lines, because it shares the
  trust domain with the master; a hash chain would not stop that writer, so there is none.
- `audit --rotate` moves the log aside under the maintenance procedure above.

### The socket

**Listener.** The k3sm server process, as the service user, on server nodes only, and only on
a single-server cluster ("Single-server clusters only"), accepts on
`/var/lib/k3sm/keystore-sock/keys.sock`, the descriptor launchd activated for it ("The socket's
directory is root's"). A worker node runs no listener (E18).

**Lifecycle.**

- The listener runs in a supervised goroutine with `recover`. A panic or accept error is
  logged and the accept loop restarted on the same activated descriptor with backoff from 1
  second to 5 minutes. **A listener failure never takes down the apiserver or kine** (U29).
- **The listener runs only in the installed server.** It refuses to start unless the server's
  effective uid is the service uid, the `_k3sm` uid `sudo k3sm install` creates. A rootless
  `k3sm server` is a supported development mode whose Pods inherit the daemon's login uid
  ("Pod denies", layer 2), so a peer at that uid could be a Pod. The server logs, and `doctor`
  shows, "user scope needs the installed server" (U113).
- The server never creates, unlinks or replaces `keys.sock`; launchd owns the name. In the
  deny-plus-pin fallback only, it unlinks a stale `keys.sock` at start only after an `lstat`
  shows a socket owned by the service user; anything else at that path is refused with a Warn.
- Each request waits for the store `.lock` at most 2 seconds; a timeout fails that request
  (`ErrBusy`), not the server.
- The start check also refuses a data root on a file system mounted with
  `MNT_IGNORE_OWNERSHIP` (read with `fstatfs` on the data-root descriptor, `f_flags`), since
  every owner check in this design means nothing there (U131).
- While the maintenance marker `keystore-maintenance` exists in the data root the listener
  stays down: it accepts nothing, and a client that connects meanwhile waits in launchd's
  backlog until its 10-second `HELLO` wait ends and it reports the server unavailable.
- **Upgrade visibility.** If the directory or either append-only file is absent, wrong or
  unflagged, the listener does not start: fail fast, no fallback. The server logs a Warn naming
  `sudo k3sm install` once at start and again on every listener retry; `k3sm doctor` shows
  "keystore user scope: off (<reason>); run `sudo k3sm install`"; and the CLI's connect error
  names `sudo k3sm install` (U31, U38, E15).

**Peer identity.** At accept, `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` on the connected
descriptor gives the peer's **effective uid at connect time**, and that is the authority. A
setuid binary that connects therefore acts as its effective uid (residual 7). `LOCAL_PEERPID`
is read for the audit line only and is advisory. The listener takes its peer-credential
source as a parameter of its constructor, not from a package variable, and the constructor
refuses a nil one: production passes the real source, each test passes its fake (U45), and no
listener exists without one (U48). The read sits behind the peer-credential
source, in a `*_darwin.go` file; it is a deliberate leaf copy of about 40 lines, because the
two existing copies (in darwin-net's `pkg/netd` and runtimed's `pkg/sandbox`) are unexported
in their repos and `apis` cannot import `x/sys`, and the file cites both. That
`LOCAL_PEERCRED` reports a non-root login uid on the server side, for a socket in a service-user
0755 directory under the root-owned data root, is measured (K0 amendment 2026-11-21).

**Eligible peers** are uids from 501 to 2147483647 that are not the service uid, whose
process is not sandboxed: before the first frame the listener also asks `sandbox_check`, on
the peer's audit token, through its peer-sandbox source, and refuses a sandboxed peer, so a Pod
process is refused by a check that does not rest on its uid (Open requirement 15, U137). Refused before any
frame is read: uid 0 (root uses the direct-file verbs, as in Phase A), the service uid (every
native Pod shares it), every uid below 501 (system accounts) (U26, E6), and every uid at
2^31 (2147483648) or above, `nobody` (4294967294) among them, which is no login user and
which a signed 32-bit reading of the uid would turn negative (U82). The store mints no scope
for a uid outside that range either. The entry grammar still parses a uid as a uint32, so
such a name is well formed and simply has no scope.

**The client's checks are advisory.** The CLI opens the socket through an `os.Root` on the
data root, checks by realpath that `keystore-sock/` is root's, mode 0755, under the root-owned
data root, and that `keys.sock` is a socket (the service user's directory in the fallback), then reads the server's uid off the connected descriptor (`LOCAL_PEERCRED` from the
client side; under socket activation, whether that names the server or launchd, the process
that listened, is measured in K7a with the token below, and if it names launchd the self-bind
form ships, Open requirement 4). **The connected-descriptor peer uid is
the authority in both directions**: a
value is never written to a socket whose peer is not the service user, whatever the path
checks said (U36). That `LOCAL_PEERCRED` reports the service uid on the client side
is measured (K0 amendment 2026-11-21).

**The client pins the server, not just its uid.** With the socket activated from a root-owned
directory, no service-uid process can bind `keys.sock`, and the pin is the second layer. In the
deny-plus-pin fallback it is the first: any service-user process could bind `keys.sock` while
the listener is down (during maintenance, a restart or its backoff), since `keystore-sock/` is
then the service user's. So after the uid check the client reads the peer's
audit token off the connected descriptor (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`), asks the
Security framework for the code of that process (`SecCodeCopyGuestWithAttributes` with the
audit token) and its cdhash, and refuses unless it equals the cdhash of the installed binary,
`/Library/k3sm/k3sm`, read from that file (a static code object). Nothing is written to the
socket before both checks pass (U69, E24).

- *Why this pins the server.* The server's launchd job, `io.k3sm.server`, execs exactly the
  installed binary as the service user: `ServerPlist` (`pkg/install/plist.go:218`) puts
  `cfg.installedBinary()` first (`:221`) in `ProgramArguments`, which is `InstallDir/k3sm`
  (`pkg/install/install.go:1784`), and sets `UserName` to the service user
  (`pkg/install/plist.go:237`). The install directory is root:wheel 0755
  (`DefaultInstallDir`, `pkg/install/install.go:95` to `:97`), so the service user cannot replace the
  file whose cdhash the client reads. A service-user process that is not that binary fails
  the pin.
- *Why the audit token, not `LOCAL_PEERPID`.* The token carries the pid version, so a pid
  reused after the peer exited does not pass for it; a bare pid read at connect time can be
  recycled before the client looks it up.
- *Why not a root-written pid file.* The server runs as the service user under launchd with
  `KeepAlive` (`pkg/install/plist.go:240`) and launchd restarts it with a new pid;
  no root process of k3sm sees each restart, so no root writer could keep a
  `keystore-server.pid` current, and a pid file the server wrote itself would be the service
  user's, which is the writer the pin must not trust.
- *Development builds.* An ad-hoc signature still carries a cdhash, so the pin works for a
  development build installed with `sudo k3sm install`. k3sm already reads cdhashes, for the
  shadow-binary check (`pkg/install/shadow_darwin.go:190`, `pkg/shadow`).
- *Upgrade skew.* Between an upgrade's install and the server's restart, the running server
  is the old binary, so its cdhash differs from the installed file's; the client refuses and
  prints "the server is not running the installed build; restart it" (U69).
- *What the pin leans on: the Pod bind deny.* The cdhash tells the installed binary from
  other code, not the server from another process running that binary. A Pod may exec the
  installed binary: the Pod profile allows `process-exec*` on every path
  (`runtimed/pkg/sandbox/sbpl.go:822`), and a native Pod runs as the service uid, so a Pod
  process running `/Library/k3sm/k3sm` would carry the installed cdhash and the server's uid.
  What keeps such a process from standing in for the server is the root-owned
  `keystore-sock/` (U104), and under it U16's `network-bind` deny on `keystore-sock/`: a Pod
  cannot bind `keys.sock`, whatever binary it runs. In the fallback that deny alone is the
  dependency the pin rests on, and E24 checks it with the real installed binary exec'd
  inside a Pod.
- *What else the pin admits.* It admits any process running the installed binary as the
  service user, so it admits the server's own children that run it, such as the RemoveMesh
  child the server execs from itself (`cmd/k3sm/lifecycle.go:398` to `:402`). The server's
  other children, the apiserver and kine from the work directory's binaries
  (`pkg/executor/supervised.go:1110` to `:1119`) and runtimed's helpers beside the installed
  binary (`runtimed/pkg/sandbox/helperpath.go:35`), carry their own cdhashes and fail it. All of
  them run as the service user inside the server's trust domain, which can read `M`
  ("Who can hold which key"), so admitting one grants it nothing that domain lacks.
- *Which process the token names.* Under socket activation launchd created and listened on
  the socket, and the server only accepts on the descriptor it was given. Whether the
  client-side `LOCAL_PEERTOKEN` names the accepting process or the process that listened is a
  K7a measurement. U69 holds the case either way: a listener inherited or passed to another
  process must not let that process pass the pin, and the server sets `FD_CLOEXEC` on the
  activated descriptor and passes it to no one (Open requirement 3, U120). If the token names
  launchd, the self-bind form ships, and U36 is never relaxed to accept uid 0 (Open
  requirement 4).
- This pins the server for the client; it does not pin the client for the server, which stays
  unpinned by ruling (residual 1). That `LOCAL_PEERTOKEN` is readable on the client side and
  that `SecCodeCopyGuestWithAttributes` resolves a service-user process from a login user's
  process is `[K0 leg 2: pending]` (not in the 2026-11-21 spike; K7a measures it).
- **If the pin cannot be built, the user scope does not ship.** This is binding: if K7a finds
  `LOCAL_PEERTOKEN`, or the code lookup from the token, unusable from a login user's process,
  the user scope fails closed. No CLI that talks to `keys.sock` without the pin is released,
  and no uid-only fallback is built; the listener stays off and `doctor` says the user scope
  is unavailable on this macOS until a dated amendment names another pin.
- *The uid alone cannot tell the server from a Pod.* On the rig the server ran as euid 250
  (`_k3sm`), and a native Pod's process also ran as uid 250, the peer euid it showed at
  `keys.sock` (the K0 spike's evidence of
  2026-11-21, `status.txt` legs 2 and 5). A client that checked only the uid would accept any Pod that
  reached the socket's path as the server.

**Protocol `k3sm-keys/1`.** Internal, not a public API; the public interface is the `k3sm
keys` CLI, which other programs call as a subprocess with the value on stdin. The CLI's human
output is not stable and may change in any release; `-o json` and the exit codes are the stable
surface, and the app consumes only those.

- A frame is a 4-byte big-endian length (at most 128 KiB), a 1-byte type, a length-prefixed
  JSON header (at most 8 KiB, never a value) and an optional length-prefixed binary value. Each
  prefix is 4 bytes, big-endian. Each sub-length must be at most the frame length, checked
  before anything is allocated; a frame that breaks this closes the connection.
- **The frame cap follows the value cap.** The largest frame a request needs is the store's
  maximum value, 65,536 bytes (64 KiB), plus the 8,192-byte header cap, plus 9 bytes of type
  and prefixes: 73,737 bytes. The cap of 131,072 bytes (128 KiB) leaves 57,335 bytes of
  headroom, so a later header field needs no protocol change. A change to the store's value
  cap changes the frame cap in the same change, and a test holds the inequality (U27).
- **Strict frames, tolerant headers.** An oversize frame, an unknown frame type or a missing
  `HELLO` closes the connection; unknown header fields are ignored (U27).
- The first frame is `HELLO {"proto":"k3sm-keys","min":1,"max":1}`. The server waits at most
  the 10-second request bound from accept for a complete `HELLO`, then closes. It replies
  `HELLO {"proto":"k3sm-keys","version":1,"max_frame":131072}`: the highest common version and
  its own frame cap, which the client never exceeds. With no common version it sends an error
  reply with code `unsupported-version` and then closes, so the client can say why.
- **An unknown `op`** in a well-formed request is answered with the code `unknown-op`, and the
  connection stays open, so a newer client can fall back on an older server without
  reconnecting.
- Error codes are a reserved closed set: `not-found`, `quota`, `busy`, `log-full`,
  `scope-owner-changed`, `scope-owner-unknown`, `user-scope-off`, `rate-limited`, `refused`,
  `unsupported-version`, `unknown-op`, `internal`. A client maps any code it does not know to a
  generic failure that prints the code (U38).
- CLI and server are one binary, so version skew exists only between an upgrade's install
  and the server's restart; the server pin refuses that window first ("The client pins the
  server"), and the CLI prints "the server is not running the installed build; restart it" and
  exits 1.

**Bounds.** 64 concurrent connections in all, at most 2 per uid among them; 10 seconds per request;
an idle timeout of 30 seconds after `HELLO` and between requests, so a connection that sends no
next request frame within 30 seconds is closed and frees its slot;
5 mutating operations a second per uid; `list` and `deliveries` rate-limited per uid like
mutations, at 5 a second; `read-for-exec` at most 30 a minute per uid, each audited as
`exec-read` (U28, U34, U51). Reads are limited too because each one writes an audit line; that
line is charged to the uid's log share like a mutation's, and past the share the read is
refused ("Per-uid fairness").

**Operations.** `put`, `rotate` (a value, or `from_version`), `list` (own scope only), `rm`,
`read-for-exec` (own entry only), `deliver` and `withdraw` ("KeyDelivery"), and `deliveries`
(the caller's own declarations and their status). There is no `show --reveal` for a non-root
user: a user's own value is reachable through exec injection only. The socket server's
interface onto the store has no reveal, show or rewrap method (U35).

**`k3sm keys exec`.** `k3sm keys exec user/<uid>/<name> --env VAR -- CMD …` reads the value
with `read-for-exec` and `syscall.Exec`s the command with the variable set in the child only:
nothing on stdout, nothing on disk, the value never in argv (U37, E5). It is unconfined: the
child runs with the calling user's own reach, outside any Pod boundary, and the user docs say
so.

### No system grants

A non-root user may name only its own uid's entries. System entries are delivered only by
root, with `sudo k3sm keys deliver system/…` and the root-owned declaration file ("Delivery
reconciler"), and are read by root only, so `exec` reads only the caller's own entries and a
user's `list` shows only its own scope (U45, E12).

### Pod denies

Pods cannot reach the socket or the keystore's files, in two layers, with the listener's
sandboxed-peer refusal behind both (Open requirement 15). **The peer check is never the first
layer.**

1. **Seatbelt.** The data-root denies cover two things, by prefix rather than by a list: every
   name in the data root that begins `keystore-` (today `keystore-floor.json`,
   `keystore-delivery.json`, `keystore-user-floor.log`, `keystore-audit.log`,
   the archives `keystore-audit.log.1` to `.4`, the floor lock `keystore-lock`, the removal
   record `keystore-removed-scopes.json` (Open requirement 13), the maintenance marker
   `keystore-maintenance` and the staging files
   `keystore-user-floor.log.new` and `keystore-audit.log.new`), and the whole `keystore-sock/`
   tree, which the prefix also covers. A prefix means a keystore file a later change adds is
   denied without a runtimed change. runtimed renders them under the work dir always and under
   `Posture.DataRoot` when it is set and differs (`keystoreRoots`), not under
   `DaemonTreeSubdirs` alone, which is under the work dir and misses a node whose Pod root
   differs from its data root.

   **The keystore stanza is the last rule, and the validator refuses what it would override.**
   As built (`keystoreDenyStanza`, `runtimed/pkg/sandbox/keystore.go`), runtimed emits the
   keystore denies as the last rule of every Pod profile. Seatbelt is last-match-wins, so no
   allow earlier in the profile (an extra path, a volume, an exposure, a credential, a view, a
   host share) re-opens a keystore path. Two refusals sit in front of it, so a grant that the
   stanza would silently override is refused rather than rendered:

   - *A caller path naming a keystore path is refused at validation.* Every caller-supplied
     path (extra read and write paths, `ReadOnlyPaths`, `WritePaths`, `ReadPaths`, host
     shares, `ExposePaths`, artifact views and the Xcode toolchain directory) that is at or
     under a `keystore-*` name, in any spelling or letter case, is refused with
     `ErrProtectedPath` (`validateKeystoreReach`), and the Pod is refused rather than started.
   - *A pods root under a `keystore-*` name is refused* (`ErrInvalidDataRoot`), since the
     last-rule deny would deny every Pod its own volume there.

   A `ReadOnlyPaths` entry, an `ExposePaths` entry or a hostPath naming a keystore path is
   refused (U16).

   **The test reads the whole profile.** U16 does not stop at the stanza's presence; it
   asserts over the whole rendered profile, for every variant, that no emitted allow rule, of
   any operation and any filter (literal, subpath, prefix or regex), matches any keystore path,
   and that the keystore stanza is the last rule. Two variants are where an allow is most
   likely to slip in: a Pod root equal to the data root, and a Pod root that is a parent of the
   data root; each is a case of its own. The facts of the rendering, as built, are stated so the
   test checks them:

   - the stanza denies `file-read*` (metadata included), `file-test-existence` (which
     `file-read*` does not cover, so a stat-free existence test is refused too), `file-write*`
     (create, unlink and rename among them), `file-link`, which `file-write*` does not cover, unix-socket
     `network-outbound` and unix-socket `network-bind`;
   - each deny is written in every spelling of each root: the `/var` form, the resolved
     `/private/var` form, and the data volume's `/System/Volumes/Data/private/var` form
     (`keystoreForms`), so it holds whichever spelling a Pod uses;
   - the `keystore-` prefix deny is a regex rule matched in either letter case
     (`keystorePrefixPattern`, `[Kk][Ee]…`, with the root quoted), because a `subpath` names one
     directory, not a name prefix, and the data volume is case-insensitive by default; the
     `keystore-run` and `keystore-sock` trees also get `subpath` filters;
   - the data volume's own mount path, which `install` sets to the data root (`Mountpoint:
     install.DefaultDataRoot`, `cmd/k3sm/install.go:664`), is taken by the test from the volume
     record, so a volume mounted elsewhere is covered too; the test checks the outcome, not the
     mechanism.

   **An empty `Posture.DataRoot` still gets the denies.** As built, runtimed renders the
   keystore stanza under the work dir when no data root is set (the standalone daemon has none
   to name), where the default node keeps its data root; the denies are never skipped (U16).

   **vm and container-vm Pods.** The guest is given no share of the data root, so nothing in
   the guest names the socket or a keystore file (U16, E10).

   **One home for the names.** runtimed owns the keystore path names in a cgo-free leaf
   package, `runtimed/pkg/keystorepaths`, which imports only the standard library: the
   constants `DataRootPrefix`, `RunDir`, `SockDir` and `SocketName`, and
   `SocketPath(dataRoot)`, which returns `<dataRoot>/keystore-sock/keys.sock`.
   `pkg/sandbox` and k3sm's provider import it; k3sm's `pkg/keystore` imports only
   that leaf, never `pkg/sandbox`, so the store takes on none of the sandbox's dependencies
   (U49). The prefix deny is built from `DataRootPrefix`, install's directory and the
   plist's `SockPathName` from `SockDir` and `SocketPath`, and k3sm's
   `baseSocketDenies` derives the `keys.sock` path from `SocketPath` and adds a
   `(deny network-outbound (remote unix-socket …))` for it, so there is one spelling (U46,
   E10).

   **The denies cover writes, not only reads and connects.** The stanza denies `file-read*`,
   `file-test-existence`, `file-write*`, `file-link`, unix `network-outbound` and unix `network-bind` on every
   `keystore-*` name and the `keystore-sock/` tree, in every spelling, so a Pod can neither plant
   a name nor bind a socket where the server's is. U16 asserts, for every variant, that the
   rendered profile refuses a write, a create, an unlink, a rename and a `network-bind` on
   `keystore-sock/`, on `keys.sock` and on every `keystore-*` name, beside the read and connect
   cases; E10 attempts each on the rig and expects `EPERM`.

   The rig spike ran today's profile, with no keystore denies yet: a Pod connected to
   `keys.sock` (the K0 spike's evidence of
   2026-11-21, `status.txt`, leg 4), so
   runtimed's sandbox change is a hard prerequisite of the listener change, not an ordering
   preference. That a Pod with these denies cannot `connect(2)` to the socket or read any of these
   paths is `[K0 leg 4: pending]` (the K5 rig leg); without them a Pod reached the socket
   (K0 amendment 2026-11-21), and Phase A's two files were absent, so their reach today is unmeasured.
2. **Pod identity refusal, the second layer.** Native Pods on an installed server run as the
   service user, below 501. The sandbox change adds a second layer: runtimed refuses a drop
   whose target identity a Pod may not hold, through `Credential.CheckPodIdentity`, which is
   `CheckPodUID` then `CheckPodGroups` (`runtimed/pkg/supervisor/privdrop.go`), called at
   `startContainer`, at `Exec` (an exec session), at the resident shim's `dropShim` and again
   in `RunLaunchSequence`; it is not in `resolveCredential` (U17, E21). The rule as built:
   a drop target uid is refused if it is 0, negative, 501 or above, or the service uid; the
   groups (the primary gid and every supplemental group, `runAsGroup` and `fsGroup` among
   them) are refused if they are 0, 20, 80, the privileged system groups (wheel, daemon, kmem, sys, tty, operator, procview, procmod, _developer), the service
   gid, negative or out of range, and a gid of 501 or above is refused unless it is an
   admitted `fsGroup`; a Pod that names a user and no group drops to `nobody`; a gid-only
   drop that leaves uid 0 is refused; an inherited uid with no drop is allowed (rootless).
   A gid in 1 to 500 is refused for a Pod drop, as the primary or a supplemental group, when
   the host assigns it (it has a group record); a gid in that range the host does not assign
   is allowed, and so is `nobody`. The never-list above is always refused, and a lookup error
   refuses. An `fsGroup` the operator admitted is still refused when the host assigns it.
   The service identity (the `_k3sm` lookup and the owners of the installed directories) is
   resolved again on every drop check, not cached at startup, and a symlink at an installed
   path refuses every drop (`runtimed/pkg/supervisor::TestPodGroupsHostAssigned`,
   `runtimed/pkg/runtime::TestStartContainerResolvesTheServiceOwnerEachStart`,
   `runtimed/pkg/runtime::TestSymlinkedWorkDirRefusesDrops`).
   The layer holds the identity **at spawn**: a setuid
   exec by the Pod's process after spawn is the sandbox's to stop, a cross-domain item owned by
   runtimed's Seatbelt profile, and this layer claims nothing about it. **The refusal applies
   to native Pods only.** A vm or container-vm guest's uid has no host meaning, since the
   guest's processes run inside the VM; the vm path calls the same `resolveCredential`
   (`runtimed/pkg/runtime/vmcontainers.go:331`) as the native spawn
   (`runtimed/pkg/runtime/pod.go:1910`), so the check sits on the native spawn path, not inside
   `resolveCredential`, and a vm Pod with `runAsUser: 1000` is allowed (U116). An inherited uid is allowed: a Pod with no drop
   runs as the daemon's own euid, which is the service uid on an installed server, the
   developer's login uid under a rootless `k3sm server` (a supported development mode), and
   root on a root daemon. The check is runtimed's `Credential.CheckPodIdentity`. The rootless case is why the listener runs only as the service uid
   ("Lifecycle"); the root case is residual 17.

   **The check is on the final effective uid.** What runtimed does today, read at runtimed
   `b311adc`: `resolveCredential` (`pkg/runtime/security.go:40`) takes the uid from the
   container's `securityContext.runAsUser`, then the Pod's, then `PodBox.uid`, the first that
   is not 0 (`security.go:44`), so **the drop target is Pod-influenced, not fixed**. It sets
   `Drop` when that uid or the gid is not 0 (`security.go:60`). The exec-shim runs
   `RunLaunchSequence` (`internal/execshim/launch_darwin.go:223`), which refuses a drop on a
   non-root daemon with `ErrDropRequiresRoot` (`pkg/supervisor/privdrop.go:78`, called at
   `:281`) and otherwise calls `setuid(cred.UID)` (`privdrop.go:304`) before the sandbox and
   the exec. No uid range is checked anywhere on that path today. The refusal therefore tests
   the drop target, `cred.UID` when `Drop` is set, and nothing when it is not. A gid-only
   request on a root daemon (`runAsUser` unset, `runAsGroup` set) sets `Drop` with `UID` 0, and
   `CheckPodUID` refuses it, since the drop leaves the process root (residual 17).

   With that refusal in place, a Pod that got past Seatbelt would connect under a uid the
   socket's peer check refuses. Until the rig
   spike measures which uid a native Pod's processes run as, and whether any Pod spec field or
   runtimed path can make it 501 or above (`[K0 leg 5: pending]`; a default Pod ran as uid 250, K0 amendment 2026-11-21), this design does not claim
   that a Pod is refused by peer uid; it claims the refusal the sandbox change adds. Row U15 is
   held for a second path if the spike finds one.

### KeyDelivery

A namespaced declaration, `KeyDelivery` in `keystore.k3sm.io/v1alpha1`, delivers a user
entry into a namespace as a Secret. It borrows ExternalSecret's explicit target and policy
fields (a named target Secret, explicit data keys), not its code, since reusing ExternalSecret would
add a dependency and a provider model k3sm does not have. The CRD is alpha: the user docs say
it may change and that a conversion is owed if it does. The Go type is
`k3sm.io/apis/keystore/v1alpha1.KeyDelivery`, and the CRD is
`apis/config/crd/keystore.k3sm.io_keydeliveries.yaml`.

**Shape.**

- `metadata.name` is free.
- `spec.entry` (scope-qualified, the entry pattern above), `spec.secretName` (the target
  Secret), `spec.items` and `spec.requestedBy` are all required in the schema, with no
  defaults. `items` is the projection list of "Typed credentials" (`{field, key}`, 1 to 8,
  keys unique, no default because the API server cannot see the entry's kind); there is no
  `dataKey`. `requestedBy` also carries the pattern
  `^k3sm:local:[1-9][0-9]{0,9}$`. All four are immutable through CRD CEL transition rules
  (`self == oldSelf`, and for `items` a comparison as a map, so a reorder is not a change),
  so the CRD is safe without the admission policy (U18). They are
  required because a CEL transition rule does not run when the old value is
  absent: an optional field left out at create could be set later, by an update, to any value,
  and the immutability rule would never run. A field present from the first write is covered
  for the object's whole life.
- A CRD CEL cross-field rule on `spec` ties the requester to the entry's owner. For a user
  entry, `requestedBy` must be `k3sm:local:` followed by the entry's uid:

  ```
  !self.entry.startsWith('user/') || self.requestedBy == 'k3sm:local:' + self.entry.split('/')[1]
  ```

- The status subresource is on: `observedGeneration`, `conditions` (`Authorized`, `Ready`,
  `SecretRetained`, and for kinds with an expiry `CredentialValid`) as
  the source of truth, and `deliveredVersion`; no value and no fingerprint of an opaque value.
  `conditions` is `listType=map` keyed by `type`, so each condition type appears once.
  **Every condition carries its own `observedGeneration`**, all four of them: the CRD makes it
  a required field of each condition, and the reconciler sets it on every write, since
  `meta.SetStatusCondition` does not fill it in (U43, U142).
- Condition reasons are a closed set listed in the schema description. "No such entry" and
  "not yours" share one reason, `EntryUnavailable`, so status reveals nothing about existence;
  `NotRecorded` is reported only after the entry's owner has matched `requestedBy`.
  `SecretExists` covers a Secret already holding the target name that is present and not
  claimed by a KeyDelivery: an unlabelled one, or one Phase A delivered; `SecretClaimed`
  covers a second KeyDelivery naming a Secret another one already owns: one declaration per
  target Secret. **Precedence comes only from honoured records plus `creationTimestamp`, then
  name**: among the KeyDeliveries that are honoured for a target, the oldest by
  `creationTimestamp`, then by name, wins (U43). Only a KeyDelivery that is honoured, its UID
  recorded in the sealed record and its digest matching, can claim a target: an unrecorded
  object, however old, claims nothing, so a copy or a forgery cannot hold a name against the
  owner's real declaration (U73). **The claim survives a transient fault.** An object whose
  check is `Indeterminate` counts as honoured for precedence, so it keeps the claim until a
  definitive deleting outcome for it (on two consecutive sweeps, "Every deleting outcome counts
  only twice in a row"), and an outage never hands the target to another object, however old
  (U73). The one exception is a scope listed in `keystore-removed-scopes.json` for the
GeneratedUID it was bound to: that listing is root's own definitive record, so the scope's
objects lose their claim at once, whatever their check reads (Open requirement 12, U130).
**The annotation never decides.** The Secret's owner annotation is read only to test
  ownership against the record; it is never an input to precedence, so a writer who rewrites it
  to name another recorded UID cannot move the target to that object (U111). The set
  is closed per condition: a condition carries only the reasons its own rows below give, with
  the status those rows give. The set is `ConditionReasons()` in
  `k3sm.io/apis/keystore/v1alpha1`, with the `Reason*` constants beside it, and the
  `CredentialValid` reasons are `credential.Validities()`. `CredentialValid` is absent for kinds
  without an expiry, and `Ready` does not change on expiry or revocation.

  | reason | condition | status | when |
  |---|---|---|---|
  | `Authorized` | `Authorized` | `True` | every check below passes |
  | `EntryUnavailable` | `Authorized` | `False` | check 1 answers `ErrNotFound` or `ErrScopeOwnerChanged` (the latter only once a K7a amendment puts it on the allow-list, Open requirement 10) |
  | `NotRecorded` | `Authorized` | `False` | check 2 fails |
  | `NotAuthorized` | `Authorized` | `False` | a SubjectAccessReview in check 3 returns a definitive denial on two consecutive sweeps |
  | `Indeterminate` | `Authorized` | `Unknown` | any outcome not on the allow-list of definitive outcomes ("A denial deletes; an error does not") |
  | `Pending` | `Ready` | `Unknown` | the initial state, before the first sweep decides; and while `Authorized` is `Unknown` |
  | `Delivered` | `Ready` | `True` | the Secret holds the entry's current version, by its version annotation and its `k3sm.io/keystore-digest` |
  | `NotAuthorized` | `Ready` | `False` | `Authorized` is `False`, for any of its reasons; the message names that reason |
  | `SecretExists` | `Ready` | `False` | a Secret not claimed by a KeyDelivery (unlabelled, or delivered by Phase A) holds the target name |
  | `SecretClaimed` | `Ready` | `False` | an older KeyDelivery owns the target Secret |
  | `EncryptionOff` | `Ready` | `False` | secrets encryption is off and the override is not set (G18) |
  | `UserScopeOff` | `Ready` | `False` | more than one server is registered |
  | `ProjectionInvalid` | `Ready` | `False` | an item names a field the entry's kind does not have ("Typed credentials"); any existing Secret is left untouched: an error, not a denial |
  | `DeletePending` | `SecretRetained` | `True` | `Authorized` is `False` and the Secret this object owns is due for deletion but still exists: the delete call failed, or the owner's reconciler allowance is exhausted |
  | `Unowned` | `SecretRetained` | `True` | `Authorized` is `False` with `NotRecorded` for a UID never recorded, and a labelled Secret names this UID: it is not this object's to delete, and it stays |
  | `Indeterminate` | `SecretRetained` | `True` | `Authorized` is `Unknown` and a labelled Secret that is this object's recorded target stays, at its last version |
| `LabelRemoved` | `SecretRetained` | `True` | a Secret stands at this object's recorded target (namespace and name) without the label or without an owner annotation naming this UID: it is never overwritten or deleted |
| `UserScopeOff` | `SecretRetained` | `True` | more than one server is registered and a labelled Secret that is this object's recorded target stays; it must be deleted by hand |
| `OwnerUnresolvable` | `SecretRetained` | `True` | the entry owner's uid has no directory record (the lookup answers a synthesized GeneratedUID), and a labelled Secret that is this object's recorded target stays |
  | `NoneRetained` | `SecretRetained` | `False` | no labelled Secret of this object stays while `Authorized` is `Unknown` or `False`; and whenever `Authorized` is `True` |
  | `Valid` | `CredentialValid` | `True` | kinds with an expiry only (`token`, `oauth`): not expiring, refresh healthy |
  | `Expiring` | `CredentialValid` | `True` | inside the expiry threshold of "Typed credentials" |
  | `RefreshFailing` | `CredentialValid` | `True` | oauth: the last server refresh failed transiently and the access token is still valid |
  | `Expired` | `CredentialValid` | `False` | past the (access) expiry with no newer version |
  | `Revoked` | `CredentialValid` | `False` | oauth: the token endpoint answered a code in the profile's `revokedErrorCodes` |
  | `Indeterminate` | `CredentialValid` | `Unknown` | the entry could not be opened |

  **What each `Authorized=False` reason does to the Secret.** Every reason is tied to one
  action, and the status says which:

  - `EntryUnavailable`: the Secret this object owns is **deleted** (on two consecutive
    sweeps), since the entry is gone from a scope that opened. An owner change gives this
    reason only once a K7a amendment puts `ErrScopeOwnerChanged` on the allow-list; until then
    it is `Indeterminate` (Open requirement 10).
  - `NotRecorded`, for a UID the record names withdrawn or a digest mismatch: **deleted** (on
    two consecutive sweeps).
  - `NotRecorded`, for a UID never recorded: **retained**. No Secret is written, and since
    ownership rests on the record, the object owns none; a labelled Secret that names its UID
    is left in place and reported as `SecretRetained=True`, reason `Unowned`.
  - `NotAuthorized`: **deleted** (on two consecutive sweeps).

  When a deletion is due and the Secret still exists, `SecretRetained` is `True` with reason
  `DeletePending` until it is gone, so a kept Secret is never silent (U43). The rule is
  general: `SecretRetained` is `True` whenever a labelled Secret stays while `Authorized` is
  `Unknown` or `False`, with `Indeterminate`, `UserScopeOff`, `OwnerUnresolvable`, `LabelRemoved`, `DeletePending` or `Unowned` saying why, and
  `False` only when no such Secret stays or `Authorized` is `True` (U78).

  While `Authorized` is `False`, `Ready` is `False` with the single reason `NotAuthorized`, and
  its message carries the `Authorized` reason (`EntryUnavailable`, `NotRecorded` or
  `NotAuthorized`), so `Ready` has one reason for every authority failure. While `Authorized`
  is `Unknown`, `Ready` is `Unknown` with reason `Pending`; nothing was changed, so the Secret,
  if any, keeps its last version, and `SecretRetained` is `True` with reason `Indeterminate`
  while it does. **A tolerant
  reader:** a consumer treats a reason it does not know as a generic failure of the condition
  that carries it, so a reason added later breaks no reader.

**Admission checks the requester; it is not the authority.** A `ValidatingAdmissionPolicy` in
`pkg/policy`, the shape of the existing ones, adds only what CRD CEL cannot see: on create,
`spec.requestedBy == request.userInfo.username`, and a requester under
`system:serviceaccount:` is refused (U40, E13). Because `requestedBy` is required, held to the
requester on create and immutable afterwards, the policy's check on create is enough: the
only value an object can carry is its creator's name. That `request.userInfo.username` reports
the impersonated user under impersonation is not yet checked; U40 and E3 check it. **Neither
admission layer is the authority.** The authority is the sealed delivery record plus the
reconciler-time SubjectAccessReviews below. `requestedBy` is checked by admission
and by the CRD's cross-field rule, which is what lets the reconciler name it as the principal
of those reviews, but it authorises nothing by itself.

**Admission binds update and delete to the owner.** The same policy also matches UPDATE and
DELETE of `keydeliveries` (the resource itself; `keydeliveries/status` is not matched, so status
writes are not checked by it). It admits one only when the requester is the object's owner,
`request.userInfo.username == oldObject.spec.requestedBy`, or is the k3sm server's identity
(the admin client's user `admin`, `pkg/executor/setup.go:1349`), or carries the group
`system:masters`. So another author who may edit or delete `keydeliveries` in the namespace
can neither delete the object nor change it (U87, E23).

- *A finalizer edit is an UPDATE.* Removing `keystore.k3sm.io/delivery` is an update of the
  object's metadata, so another author cannot strip the finalizer to skip the Secret's
  deletion either.
- *The reconciler's and `withdraw`'s own writes still pass.* The reconciler adds and drops the
  finalizer and deletes through the admin client, whose token maps to `system:masters`
  (`pkg/executor/setup.go:1349`, `pkg/rbac/doc.go:31`); `withdraw` deletes impersonating
  `k3sm:local:<peer uid>`, which is the object's `requestedBy`.
- *The namespace controller may delete.* One more requester is admitted, for DELETE only:
  `system:serviceaccount:kube-system:namespace-controller`. The controller-manager runs each
  controller under its own ServiceAccount (`--use-service-account-credentials=true`,
  `controllerManagerArgs`, `pkg/executor/supervised.go:1069`), and without this a namespace
  holding a KeyDelivery could never finish deleting. The finalizer still holds each object
  until the reconciler has deleted its Secret.
- *The policy fails closed.* Its `failurePolicy` is `Fail`, unlike the advisory policies'
  `Ignore` (`pkg/policy/admission.go:260`): an evaluation error must not admit a delete by
  another author. That is why the expressions must never read `object` on a DELETE. U135
  checks `failurePolicy: Fail` and that the namespace controller's exemption admits DELETE
  only, never an UPDATE (Open requirement 13).

**What the policy sees on a DELETE.** The API server runs validating admission for a DELETE with
`object` null and `oldObject` set to the stored object. This is checked against the version
k3sm pins, Kubernetes `v1.37.1` (`DefaultKubeVersion`, `pkg/executor/executor.go:278`) and
`k8s.io/apiserver v0.37.1` (`go.mod:33`). There, `AdmissionToValidateObjectDeleteFunc` builds the
admission attributes with a nil object and a copy of the old one
(`k8s.io/apiserver@v0.37.1/pkg/registry/rest/delete.go:189` to `:192`), for a single DELETE and
for each item of a DELETE collection (`pkg/endpoints/handlers/delete.go:169` and `:329`), and a
nil object becomes CEL `null` (`pkg/admission/conversion.go:137`, read into `object` at
`pkg/admission/plugin/cel/activation.go:70`). So the policy reads `object` only on a CREATE and
`oldObject` on an UPDATE or a DELETE.

**Who creates one.** The owner, through the socket: `k3sm keys deliver user/<uid>/<name>
--namespace NS --secret S [--item field=key …] [--data-key K]` (the short-name form is
accepted; `--data-key K` is `--item value=K`, and with no `--item` the CLI takes the kind's
default from "Typed credentials", refusing an `ssh` entry).

- The server creates the object with the admin client **impersonating exactly
  `k3sm:local:<peer uid>`** with the group `k3sm:local-users`. The uid is the peer uid the
  listener read with `LOCAL_PEERCRED` at accept, never a value from the request and never the
  uid in the entry name, so a request naming another user's entry impersonates the peer, not
  the entry's owner (and is answered `ErrNotFound` before any create). The admin client's
  impersonation is limited to users `k3sm:local:*` and the group `k3sm:local-users`: a wrapper
  refuses any other `Impersonate-User` or `Impersonate-Group`, and refuses to send
  `Impersonate-Uid` or any `Impersonate-Extra-*` header, before the request leaves (U41). The
  API server's own RBAC then decides whether that principal may create `keydeliveries` in
  `NS`.
- After the create, the server appends to the caller's sealed `deliveries` record (kind
  0xFD, under the user-scope floor) the object's `metadata.uid` and `metadata.name`, the full **target tuple**
  (`entry`, `namespace`, `secretName`, `items`, `requestedBy`), all under the record's seal,
  and the **target digest**
  `sha256("k3sm-keystore-delivery-target/v1" ‖ LP(entry) ‖ LP(namespace) ‖ LP(secretName) ‖
  LP(items))`, where `items` is one length-prefixed blob of the items sorted by `key` bytewise,
  each `LP(field) ‖ LP(key)` ("Typed credentials", U14, U41, U161). The digest is over those
  values only, as the live object's spec gives them, never over the object's serialised shape,
  so a field the API server adds changes no digest, and a reorder of `items` changes none
  either. The store holds each field to its KeyDelivery grammar when it adds an entry and
  again when it parses the record, so a record a writer could not have produced is
  `ErrCorrupt`: `metadata.uid` UUID-shaped, `metadata.name` and `secretName` DNS-1123
  subdomains (at most 253), `namespace` a DNS-1123 label (at most 63), `entry` a user entry,
  `requestedBy` matching `RequestedByPattern` and equal to `k3sm:local:<the entry's uid>`,
  each item's `field` in the Fields table and its `key` a Secret data key. A refused add's
  audit line carries a fixed placeholder for the fields, never the values. `requestedBy` is not in the digest and needs no place there: check 1 below holds
  `requestedBy` to the owner of the entry the digest binds, and the CRD's cross-field rule ties
  it to the entry's uid, so an object whose requester is changed under its UID fails check 1
  (`EntryUnavailable`) while a retargeted one fails the digest. The record keeps `requestedBy`
  in its tuple for `withdraw` and the reviews. The digest
  checks a live object against the record; the tuple is what lets the reconciler and root find
  the one Secret a recorded UID owns without trusting anything written on the Secret itself
  ("Ownership at deletion rests on the record").
- **Version tags.** The digest carries that domain label, and the record's plaintext starts
  with a format version byte (1). A reader that meets a record version it does not know refuses
  it, and the reconciler treats that refusal as `Indeterminate`, never as a denial, so a format
  change, read by a build that predates it, cannot delete a Secret (U56).
- `withdraw` (CLI `k3sm keys undeliver`) deletes the object; the record entry is withdrawn by
  the reconciler after the Secret is gone. It names the object by namespace and name, so it
  can also delete the caller's own **unrecorded** object (a create whose record append never
  happened, or a copy): the server Gets the object, checks that its `spec.requestedBy` is
  `k3sm:local:<peer uid>`, and deletes it impersonating that principal, with a UID
  precondition so a replaced object is not deleted in its place (U74). An object whose
  `requestedBy` names another uid answers `not-found`, worded as for an absent object. Before
  any of it, `withdraw` opens the caller's scope, so the GeneratedUID check runs: a new account
  that was given a deleted account's uid gets `scope-owner-changed` and cannot withdraw the old
  account's objects (U94). `undeliver` prints "a pod that read this value
  keeps it; rotate the entry to revoke it".
- Only an entry in the caller's own `user/<uid>` scope can be declared. A system entry reaches
  a namespace only through root's `deliver system/…`, never through a KeyDelivery.

**The reconciler honours a KeyDelivery only when all of these hold, re-checked every sweep:**

1. The entry exists, is a `user/<uid>` entry (a `system/…` entry never is), and `requestedBy`
   (`k3sm:local:<uid>`) is its owner; otherwise `EntryUnavailable`.
2. Its UID is in that uid's sealed `deliveries` record and the digest recomputed from the live
   object matches the recorded one; otherwise `NotRecorded`.
3. SubjectAccessReviews for `requestedBy` in that namespace pass for `create keydeliveries`
   and `create secrets` with no resource name, and for `update` and `delete` on `secrets` with
   `resourceNames` `spec.secretName`; otherwise `NotAuthorized`. The secrets checks are
   required: without them, a principal allowed to declare deliveries but not to write Secrets
   could plant or remove a Secret a workload expects to mount, under a name of its choosing
   (U42).

**The reviews ask about the principal the create used.** Each SubjectAccessReview carries
`spec.user` `k3sm:local:<uid>` and `spec.groups` equal to the groups the impersonated create
carried: `k3sm:local-users`, and `system:authenticated`, which the API server adds to an
impersonated user. So a grant bound to the group `k3sm:local-users` is honoured consistently:
the create passes on it and every sweep's reviews pass on it, and removing that binding is a
definitive denial like removing a user binding (U42). The docs recommend binding the user
`k3sm:local:<uid>`, not the group: a group binding lets every login user on the Mac deliver into
that namespace.

**Why create is checked without a name.** RBAC cannot match `resourceNames` on `create`: a
create request carries no name for the authorizer to match, so a rule that lists
`resourceNames` never allows a create. A review that named the object would pass such a rule
where the real create fails, so the reconciler asks the question the API server would answer:
create without a name, update and delete with the Secret's name. E23 checks this against the
real authorizer.

Encryption-off refusal (G18) applies unchanged, as `EncryptionOff`.

**What a definitive SubjectAccessReview denial is.** A review's answer is a definitive denial
only when the call succeeded, `status.allowed` is `false` and `status.evaluationError` is
empty, whatever `status.denied` says. The API server returns the union verdict of its
authorizer chain, and the RBAC authorizer never sets `denied`: it refuses by returning no
opinion, which the chain reports as `allowed=false`. Reading `denied=false` as "no opinion"
would mean that under the default `Node,RBAC` chain a removed RoleBinding never deletes a
Secret. Every other answer is `Indeterminate`: a failed call, a non-empty `evaluationError`
(the authorizer could not decide), and any response before the readiness gate below. Two more
conditions guard a denial before it deletes anything:

- **No sweep before the API server is ready.** The reconciler runs no sweep until the API
  server's `readyz` answers ready and its own informers report synced: the RBAC ones (Roles,
  RoleBindings, ClusterRoles, ClusterRoleBindings) and the KeyDelivery and Secret informers. An
  authorizer that has not loaded its rules can deny what it would allow a moment later, and an
  informer that has not synced can show an object missing that exists.
- **Every deleting outcome counts only twice in a row.** This holds for every outcome on the
  allow-list below, not only for a denial. A deleting outcome for one KeyDelivery deletes
  nothing on the sweep that first sees it. It deletes only when the next sweep again sees a
  deleting outcome for the same object and the same `metadata.generation`; any other answer
  in between resets the count. Until then `Authorized` is `Unknown` with reason
  `Indeterminate` (U65).
- **Deleting observations are spaced in time.** The reconciler sweeps every 30 s by default,
  and a watch event can start a sweep early. Two consecutive deleting observations count only
  when the second is at least 60 s after the first, by the reconciler's clock seam; a deleting
  outcome seen sooner is not a second observation and leaves the first one standing. So a fault
  that lasts less than a minute, a directory service rebinding or a burst of watch events,
  cannot delete a Secret however many sweeps it spans (U93). The observation state lives only
  in the reconciler's memory: a restart resets it, which delays a deletion by a further pair
  of observations and never speeds one up.
- **No sweep during maintenance.** While the marker `keystore-maintenance` exists in the data
  root the reconciler pauses: it starts no sweep, and an append already waiting for the store
  lock lands in the new file after the server's reopen ("The server reopens after
  maintenance").
- **Single-server is re-checked before every sweep.** Before each sweep the reconciler lists
  the nodes with the `node-role.kubernetes.io/control-plane` label afresh, not from a cache.
  With more than one, the sweep does not run and KeyDeliveries get `UserScopeOff`; when the
  List fails, the sweep does not run and nothing changes. A second server's keystore holds no
  scope for these users, so a sweep there would read `ErrScopeAbsent` for every entry (U65).

**A denial deletes; an error does not.** The reconciler deletes a Secret, or withdraws a
record entry, only on an outcome from an explicit allow-list of definitive outcomes, and only
when two consecutive sweeps see one ("Every deleting outcome counts only twice in a row"). The
list is closed:

1. the store's typed `ErrNotFound` for the entry (`errors.Is(err, keystore.ErrNotFound)`),
   which the store answers only for an entry missing from an `entries/` directory that exists
   and opened, in a scope whose `scope.key` opened;
2. a withdrawn record entry for the KeyDelivery's UID, read from a `deliveries` record that
   exists, opened and authenticated;
3. a digest mismatch: the digest recomputed from the live object differs from the one in a
   record that opened and authenticated;
4. a definitive SubjectAccessReview denial, as defined above, on two consecutive sweeps.

The store's typed `ErrScopeOwnerChanged` is not on the list in this release (Open requirement
10): it is `Indeterminate`, and `doctor` names the scope. A dated K7a amendment that measures
GeneratedUID stability across Migration Assistant, a macOS upgrade and a directory rebind may add
it as item 5, and only for a real, non-synthesized GeneratedUID that differs from the bound one;
a synthesized compatibility UUID is `ErrScopeOwnerUnknown`, which is `Indeterminate` either way.

**Every other outcome is `Indeterminate`**, whatever it is: `ErrScopeOwnerChanged` (Open
requirement 10), `ErrScopeAbsent` (a missing
`.user/<uid>/` or `scope.key`, or, in a scope whose `scope.key` opened, a missing `entries/`
directory or `deliveries` record), `ErrCorrupt` (the floor refusal
included, which wraps it), `ErrMasterMissing`, `ErrScopeUnsupported`, `ErrBusy`, `ErrLogFull`,
`ErrScopeOwnerUnknown` (the GeneratedUID lookup past its deadline), a missing or unflagged
user-scope floor log (for a write, "The reconciler checks the floor too"), a
cancelled or expired ctx, the store's refusal to read while an audit append fails (U32), a
delivery record whose version it does not know, a SubjectAccessReview call that fails or an
answer that is not a definitive denial, a denial seen on one sweep only, any other API server
error, and any error this list does not name, including one a later change adds. The rule is
written as an allow-list so that a new sentinel is safe by default: it deletes nothing until a
change adds it here. `ErrScopeOwnerChanged` would be the outcome for uid reuse, where a new
person holds the uid and the old owner's credential must not stay delivered to them; it is
held back from the list until K7a's measurement (Open requirement 10), so in this release uid
reuse is reported by `doctor` and cleared by root with `rm-scope`, and no Secret is deleted
for it automatically. A departed account whose uid is not reused has no directory record, so the lookup answers a synthesized value,
which is `ErrScopeOwnerUnknown` and stays `Indeterminate`: the reconciler cannot tell it from a
directory service that is not up yet. Such a scope is reported, not acted on: `doctor` lists
it, each of its deliveries gets `SecretRetained=True` with reason `OwnerUnresolvable`, and its
removal is left to root ("A departed account is left to root"). A UID absent from a readable record is `NotRecorded` and gets no Secret written,
but it is not on the list, so it deletes nothing.

**An owner change still finds its targets.** A delete of an owner-changed scope's Secret (the
object's deletion, the orphan sweep, `rm-scope`, and the owner-change delete itself only once a
K7a amendment allows it, Open requirement 10) needs the record's targets, and the scope no
longer opens through the normal path. So on `ErrScopeOwnerChanged` the reconciler opens that scope's `scope.key` under `W` without the
GeneratedUID check (the bound value is the record's own generation field, "Record encoding"),
and through it reads only the `deliveries` record, which must still authenticate. That read is
used for one thing: finding each recorded target, recorded or withdrawn, to delete under the
target-matching rule ("Ownership at deletion rests on the record"). It never delivers, never
rotates, never writes the record and never opens an entry, so the old owner's values reach no
one. A record that does not open or authenticate is `Indeterminate`, and nothing is deleted.
`rm-scope` reads the record the same way, so an owner change is never a reason for
`--orphan-secrets` (U55, U77).

**The reconciler checks the floor too.** Before any `deliver-write` it checks the user-scope
floor log through the store's flag check, the one the listener uses (U21). A missing or
unflagged `keystore-user-floor.log` is `Indeterminate` for writes: without the floor a
copied-back `current` would read as current, so no `deliver-write` runs until `floor
--rebuild` leaves a flagged log, and the Secrets keep their last versions. Deletes split by
what drives them:

- *An absence-driven delete waits for the floor.* A delete driven by `ErrNotFound` is
  `Indeterminate` while the user floor is missing or unflagged. Without the floor a restored
  older tree that lacks an entry reads as an absent entry, since the floor line is what marks a
  missing entry as damage rather than removal, so absence is not definitive then.
- *A revocation-driven delete goes ahead.* A delete driven by a withdrawn record entry, a
  digest mismatch or a definitive SubjectAccessReview denial (and an owner change, once a K7a
  amendment allows it, Open requirement 10) never depends on the floor check: each is decided by the allow-list
  above and the two spaced observations, and none reads a pointer the floor guards.

The record withdrawal that follows a delete writes the `deliveries` record and its floor line,
so it waits for the floor, and the finalizer stays until then (U83, U107).

**Absence is told apart from an unreadable store only by `ErrNotFound`.** The store answers
`ErrNotFound` only after it opened the scope and its `entries/` directory and found no entry
there; a missing scope, a missing `entries/` and a missing `deliveries` record are
`ErrScopeAbsent`, and every failure to open or read the store is another
error, and so `Indeterminate`. The
reconciler never infers absence from an empty result, a missing file or an error's text.

On an `Indeterminate` outcome the reconciler changes nothing (the Secret, the record entry and
the finalizer stay as they are), sets `Authorized` to `Unknown` with reason `Indeterminate`,
and retries with backoff (U55). Otherwise a short outage of the API server or of the directory
service would delete every delivered Secret on the node, and a Pod restarted in that window
would lose a credential its owner never withdrew. The object's deletion and the orphan sweep
below are lifecycle, not authority, and keep their own triggers.

**Why the sealed record binds the whole target.** The installing user's own kubeconfig
carries the admin context, and admin can impersonate anyone. Without a record only the service
user and root can write, that holder could create, copy or replay a KeyDelivery for any user's
entry. A UID alone is not enough: an object whose spec is changed under its UID (a CRD edited
to drop the transition rules) would keep it. With the UID and the digest, a copied or replayed
object has a UID the owner never recorded, a retargeted one fails the digest, and a forged one
has no record: each is refused (E7, E8). Admin can still delete any KeyDelivery and read any
delivered Secret, as today.

**Writes.** One labelled `Opaque` Secret per honoured object, whose `data` holds exactly one
key per item, rendered by `typed.Project` ("Typed credentials"), with:

- the label `k3sm.io/keystore-delivery` (`credential.LabelDelivery`, Phase A's label key) set to
  the constant value `keydelivery` (`credential.LabelValueKeyDelivery`);
- the version annotation `k3sm.io/keystore-version` (`credential.AnnotationVersion`);
- the **owner annotation**, two keys: `k3sm.io/keystore-delivery-uid`, holding the
  KeyDelivery's `metadata.uid`, and `k3sm.io/keystore-entry` (`credential.AnnotationEntry`),
  naming the entry it delivers;
- the content digest annotation `k3sm.io/keystore-digest` (below);
- and an ownerReference to the KeyDelivery as the garbage-collection backstop.

The label, the version and the entry keys are public names in `k3sm.io/apis/keystore/credential`,
because the provider and other readers match on them. `k3sm.io/keystore-delivery-uid` and
`k3sm.io/keystore-digest` are read only by the reconciler, `rm-scope` and the mount audit, so
they are declared in `pkg/keystore/reconcile`, not in `apis`. The label value is a constant
because Phase A's label value is an entry name, and `user/<uid>/<name>` is not a valid label
value (a label value allows no `/`), so the entry goes in the annotation. Everywhere this
document says "the owner annotation names a UID", the UID is read from
`k3sm.io/keystore-delivery-uid`.

**`Ready=Delivered` checks the content, not only the version.** The reconciler also writes the
annotation `k3sm.io/keystore-digest`, the sha256 of the Secret's `data` (each key and value
length-prefixed, keys in order), and compares it with the live Secret's `data` on every sweep.
`Delivered` requires both the version annotation and the digest to match, so a Secret whose
`data` was substituted under an intact version annotation is drift and is repaired ("Repairs
are not charged to the owner"). The digest discloses nothing new: whoever can read the
annotation can read the `data` it digests (U86).

**Repairs are not charged to the owner.** A delivered Secret that someone other than the
reconciler edited or deleted (drift: the Secret is gone, or its data or annotations differ from
what the reconciler last wrote, while the entry's current version is the one already delivered)
is re-created or repaired by the reconciler, but that write is not the owner's act:

- *Reconciler-class.* A repair write draws on the reconciler budget ("The user-scope floor",
  per-uid fairness), never on the owner's share or revocation budgets, so a namespace writer who
  edits or deletes the Secret over and over cannot spend the owner's share.
- *Coalesced and rate-limited.* Repairs of one delivery write at most one audit line per 10
  minutes, a `deliver-write` with `"repair":true` and the count of repairs since the last such
  line. Repairs of one delivery are themselves rate-limited, with exponential backoff from one
  sweep period, doubling on each repair, capped at 10 minutes and reset once the Secret has
  stayed as written for 10 minutes. Once the reconciler budget is spent, a repair still runs
  (a writer must not be able to hold a substituted value in place by exhausting it), its line is
  dropped and counted, and `doctor` warns.
- *What stays the owner's.* A write of a new version, after the owner's own `rotate` or `put`,
  is the owner's act and stays charged to the owner as above; only the write that restores the
  version already delivered is a repair (U86).
- *Which version was delivered comes from the record.* The sealed `deliveries` record holds,
  per delivery, the last version the reconciler delivered; the reconciler raises it, with the
  record's floor line, after the Secret write succeeds. The classifier that tells a repair from
  an owner's write compares the entry's current version with that recorded value only. It never
  reads the Secret's version annotation or the KeyDelivery's `status.deliveredVersion`, since a
  namespace writer can set the first and a status writer the second, and either would let them
  move a repair onto the owner's share or an owner's write onto the reconciler budget. A crash
  between the Secret write and the record write leaves the recorded version one behind, so the
  next sweep's write is charged to the owner once more, which is the safe direction (U102).

**A KeyDelivery never touches a Phase A Secret.** A Secret belongs to the KeyDelivery
reconciler only when it carries the label value `keydelivery` and a `k3sm.io/keystore-entry`
annotation naming a `user/` entry. A Phase A Secret carries no `k3sm.io/keystore-entry`, so
it is never claimed by a KeyDelivery, even for a system entry that happens to be named
`keydelivery`, and the KeyDelivery reconciler never overwrites or deletes one: a target
Secret that is present and not claimed by a KeyDelivery, unlabelled or delivered by Phase A,
is `SecretExists`. In the other direction, the Phase A reconciler leaves alone any Secret that
carries `k3sm.io/keystore-entry`, so neither reconciler writes the other's Secret (U81).

**Ownership at deletion rests on the record, not the ownerReference.** The reconciler owns a
Secret when it carries the label, its owner annotation names a KeyDelivery UID, that UID is in
the sealed `deliveries` record of the entry's owner (recorded or withdrawn), **and the Secret
is that UID's recorded target**: the Secret's own namespace and name equal the namespace and
`secretName` the record stores for that UID, and the record's `entry` for that UID equals the
entry the owner annotation names. The ownerReference is not part of the test: a delete with
`--cascade=orphan` (`propagationPolicy: Orphan`) has the garbage collector strip it from the
Secret before the object goes, and the Secret must still be deleted. The label and the
annotation alone are not enough either, since anyone who may write Secrets in the namespace
can set both; the sealed record is what neither that writer nor an admin can forge (U44, U72).

- **A real UID on the wrong Secret owns nothing.** A KeyDelivery's UID is visible to anyone
  who may read the object, so a writer can copy a real, recorded UID into the owner annotation
  of another Secret, in another namespace or under another name, beside a forged label. The
  UID check alone would then delete that Secret as the owner's. The target check refuses it:
  the Secret is not the recorded target, so neither the orphan sweep nor a lost-authority
  delete touches it, and it is left alone (U44).
- **Another honoured record's target is never deleted.** Two uids' honoured records can name
  the same `(namespace, secretName)`. The orphan sweep, a lost-authority delete and `rm-scope`
  never delete a Secret that another honoured record claims at that target, and the owner
  annotation never selects which record's tombstone governs a delete; nothing is charged to
  the victim (Open requirement 6, U123).
- **A stripped label is reported, never acted on.** A Secret at a recorded target whose label
  or owner annotation was removed no longer passes the ownership test, and the reconciler
  cannot tell that from a Secret someone else put at that name. So it never overwrites or
  deletes it, under any outcome, the object's deletion and `rm-scope` included. The
  KeyDelivery gets `SecretRetained=True` with reason `LabelRemoved`, and `doctor` names the
  Secret's namespace and name and the KeyDelivery, so root or the namespace's admin can judge
  it (U103). Whoever could strip the label holds update on that Secret and could already copy
  its value (residual 16).
- **A forgery is not charged to the victim.** Such a Secret is not the owner's act, so the
  reconciler charges nothing to the owner uid's log share for it and writes no `deliver-delete`
  in the owner's name. It writes one `refused` line, `via` `reconciler`, naming the Secret's
  namespace and name and the UID it claimed, against the reconciler budget ("The user-scope
  floor", per-uid fairness), never against a uid's share or budgets. Forged Secrets are
  counted in memory in a bounded LRU of 1024 (namespace, name) pairs: a pair already in it
  writes no new line however often its Secret is updated, and there is no
  per-`resourceVersion` set. Lines for newly seen pairs are rate-limited to 10 a minute, and at
  most one summary `refused` line a minute carries the count dropped since the last one, the
  way U33's pre-frame refusals are summarised. Once the reconciler budget is spent these lines
  are dropped and counted, and `doctor` warns. So a forger cannot drain a user's share, fill
  the log or grow the reconciler's memory by planting or rewriting Secrets, and no uid's reads
  or mutations are refused for it (U85).

**Finalizer and lost authority.** The reconciler adds the finalizer
`keystore.k3sm.io/delivery`. On deletion of the object, or when authority is lost (a definitive
denial, an outcome on the allow-list above), the reconciler deletes the Secret it owns (the label and the owner annotation
matching, the annotation's UID in the sealed record, and the Secret being that UID's recorded
target) and sets `Authorized=False`. Every reconciler Secret delete or update, and every
`rm-scope` delete, passes `Preconditions{UID, ResourceVersion}` from the ownership read, so a
Secret replaced in between is not touched (Open requirement 8, U125). The crash order is fixed: **delete the
Secret, then withdraw the sealed record entry, then drop the finalizer**, so a crash at any
point leaves a state the next sweep finishes. An **orphan sweep** deletes a labelled Secret
only if its owner annotation names a KeyDelivery UID that the sealed record holds, the
Secret's own namespace and name equal the record's target for that UID and the record's entry
for that UID equals the one the owner annotation names, and that
KeyDelivery no longer exists (a Get of that object answers not found, or returns an object
with another UID) or the record names it withdrawn. The ownerReference is not needed, so an
orphan-cascade delete still deletes the Secret; the label and the owner annotation without
the record are not enough, and neither is a recorded UID on a Secret that is not its recorded
target; an unlabelled or foreign Secret is never touched, and a Get that
fails is an error, not a denial (U44, U72, E11, E14).

- *The sweep asks the API server, by name.* The record stores each delivery's KeyDelivery
  `metadata.name` beside its UID, so the sweep's existence check is a live Get of
  `keydeliveries/<recorded name>` in the recorded namespace, sent to the API server. It never
  reads an informer cache and never infers absence from a List: a cache that has not caught up,
  or a List that was cut short, would show a live object as gone.
- *Gone is a deleting outcome like any other.* A Get that answers not found, or returns an
  object with another UID, counts only on two consecutive observations at least 60 s apart
  ("Deleting observations are spaced in time"); any other answer in between resets the count
  (U98).

**An unopenable or removed scope counts as withdrawn for the finalizer.** The finalizer's
middle step withdraws the record entry. When the owner changed (`ErrScopeOwnerChanged`), the
record is read without the GeneratedUID check only to find the Secret to delete ("An owner
change still finds its targets") and is never written, so the withdraw step counts as done
and the finalizer drops after that Secret is gone. When root removed the scope with
`rm-scope`, there is no record left to withdraw from, and the step counts as done the same
way. Removal is known only from root's own record: `rm-scope` writes
`keystore-removed-scopes.json` in the data root, root-owned 0644, through the data-root
descriptor rules ("Root never acts by path where the service user can write"), listing each
removed scope's uid and the GeneratedUID it was bound to, before it removes the scope. Only a
scope listed there, for that GeneratedUID, counts as removed for the finalizer; a plain
`ErrScopeAbsent` stays non-definitive and keeps the finalizer, since a restore that left the
scope out or an unmounted volume also reads as absent (U114). A scope whose `scope.key` opens but whose
`entries/` or `deliveries` is missing is damage, not removal, and keeps the finalizer. A
transient failure (`ErrScopeOwnerUnknown`,
`ErrBusy`, any other error) keeps the finalizer and retries. This is lifecycle, not authority:
the object is already being deleted, so treating an absent scope as withdrawn here deletes
nothing that the object's deletion did not already (U75). This differs on purpose from Phase A's root-file delivery, which never deletes (G20): a
revocation that leaves a long-lived token in place is not a revocation.

**`rm-scope` revokes first.** Removing a scope must not leave its delivered Secrets in place
with no record left to find them by. `sudo k3sm keys rm-scope user/<uid> --yes` holds the store
lock exclusively, and the floor lock `keystore-lock` (Open requirement 2), for its whole run,
so no reconciler write from that scope lands in between, and runs in this order:

0. **List the uid's bindings.** It lists every RoleBinding and ClusterRoleBinding with a
   subject `k3sm:local:<uid>` and prints each, a RoleBinding with its namespace. Unless none
   exist, `--keep-bindings` is given or `--remove-bindings` is given, it refuses and changes
   nothing: a uid macOS gives to a new account would inherit those grants (residual 14), so
   root removes them first, or keeps them knowingly (U95). `--remove-bindings` deletes each
   listed binding through the admin client before step 1, and stops, changing nothing further,
   if a delete fails (U115).
1. **Read the sealed `deliveries` record, if it opens.** Root opens `scope.key` under `W`
   without the GeneratedUID check, since removing an owner-changed scope is the verb's main
   use and the record's targets are what it needs; the record must still authenticate.
2. **Delete every recorded delivery's Secret** through the admin client the reconciler uses,
   with the target-matching rule of "Ownership at deletion rests on the record": for each UID
   in the record, recorded or withdrawn, only the Secret whose namespace and name are that
   UID's recorded target, carrying the label and an owner annotation naming that UID and the
   recorded entry. A Secret already gone counts as done; any other Secret is left alone. Each
   delete writes a `deliver-delete` line, `via` `root`, charged to no uid.
   Then it records the scope in `keystore-removed-scopes.json` ("An unopenable or removed scope
   counts as withdrawn for the finalizer") and deletes the scope's KeyDeliveries, each recorded
   UID's object by its recorded namespace and name with a UID precondition, so a stale object
   holds no claim (Open requirement 12, U130).
3. **Then remove the scope**, walking `.user/<uid>/` by descriptor ("Root walks service-user
   trees by descriptor").

If the API server is unreachable, `rm-scope` refuses and changes nothing: it removes no
Secret and no file. If a delete fails part-way, it stops before step 3, so a rerun finds the
record intact and resumes. If the record cannot be opened (missing, corrupt, or sealed under a
`scope.key` that does not open under `W`), `rm-scope` refuses unless `--orphan-secrets` is
given. An owner change is not such a case: step 1 reads the record without the GeneratedUID
check, as the reconciler does on `ErrScopeOwnerChanged`, and deletes by its targets. With
that flag it lists every Secret labelled for KeyDelivery whose owner annotation names an
entry of this scope, marking each match `unauthenticated (annotation only)`, with every control character stripped
from the annotation text it prints, as every root verb and `doctor` strip it (Open requirement
14, U136), since nothing
sealed ties it to the scope, deletes none of them, leaves them for root to judge, and then removes the
scope; it still refuses when the API server is unreachable, since it cannot list (U77). The
KeyDeliveries that named the scope then drop their finalizers as for a removed scope (U75).

**Root walks service-user trees by descriptor.** `.user/<uid>/` is the service user's, so
every name in it may be a symlink, a FIFO or a directory swapped mid-walk. Every root path that
reads or changes a keystore tree therefore walks it by descriptor: `rm-scope`, `floor
--rebuild`, Rewrap of each `scope.key` and every other root write under `server/keystore/`
(Open requirement 11, U128), `sudo k3sm install` over an existing tree (which judges and keeps what it finds),
`uninstall --purge` (which clears the logs' flags and removes the trees) and `doctor` (which
reads sizes, flags and scopes). The purge already walks the data root off one descriptor with a
device and inode check (`purgeTree`, `pkg/install/install_darwin.go:2542`); the keystore trees
follow the rules below on every one of these paths (U80, U105, run as root). Each walks it the way the maintenance verbs walk the data root ("Root
never acts by path where the service user can write"):

- each step is `openat` relative to the parent's descriptor with `O_NOFOLLOW` (and
  `O_DIRECTORY` for a directory), and each removal is `unlinkat` relative to the parent's
  descriptor, never a path;
- a symlink, a FIFO, a socket, a device or any non-regular file is refused, and so is a
  directory anywhere but where the layout puts one (`.user/`, `.user/<uid>/`, `entries/`,
  `entries/<name>/`); the verb stops and changes nothing further;
- every read is bounded: a record at the store's maximum record size (1,056 KiB for the
  `deliveries` record, "Quotas"), a `generation` file at
  its fixed size, a directory listing at the store's entry bound; a longer file is refused;
- after each open the verb re-checks with `fstat` and `SameFile` that the descriptor is the
  object the parent's listing named, and never follows a directory that was swapped between
  the listing and the open (U80, U105, run as root).

**Every root verb refuses a non-root caller.** `rm-scope`, `floor --rebuild`, `audit
--rotate`, `rewrap` and `deliver system/…` check the effective uid through the euid source
before they open anything, and a non-root caller is refused with the same message and exit
code for each, changing nothing; one table test runs every verb through that seam (U106).

**A departed account is left to root.** When an account is removed and its uid is not given
to anyone, its scope does not open (`ErrScopeOwnerUnknown`) and nothing is deleted
automatically. `doctor` lists every scope under `.user/` whose uid has no directory record (the
lookup answers a synthesized GeneratedUID), with the number of its deliveries, and the
reconciler sets `SecretRetained=True` with reason `OwnerUnresolvable` on each of them. The user
docs say that root, when it removes an account, runs `sudo k3sm keys rm-scope user/<uid> --yes`
for it, which revokes the scope's deliveries first (U100).

**Revocation is rotation.** Deleting the Secret does not un-share a value a Pod already read.
The docs and the CLI say so (residual 8).

**Identity.** The reconciler uses the admin client the server already holds for `pkg/addons`,
as Phase A decided; the impersonated create is the only new use of it. A ClusterRole
`k3sm:keystore-delivery-author` ships **unbound**. It grants `create`, `update` and `delete` on
`keydeliveries` only, and nothing on Secrets: the reconciler's admin client writes the Secret,
never the user. An admin binds it per user and namespace to `k3sm:local:<uid>`. Because check 3
asks whether the user may write the target Secret, an admin who lets a user deliver into a
namespace also grants that: the built-in `edit` ClusterRole, or a Role with `create` on
`secrets` and `update` and `delete` on `secrets` limited by `resourceNames` to the target names
(E23). No ServiceAccount is granted anything.

**The `k3sm:local:*` usernames are reserved** for the server's impersonation. A client
certificate whose CN is `k3sm:local:<anything>`, or whose organisation is `k3sm:local-users`,
must not be issued: its holder would be that local user to RBAC, to the admission policy and to
the reconciler's reviews, without the peer-credential check that ties the name to a uid on the
Mac. The user docs say so beside the RBAC example.

**The reservation is enforced, not only documented.** k3sm's own CA refuses both in every
issuing path, the way it already refuses the update signer's identity
(`refuseUpdateSignerIdentity`, `pkg/certs/updatesigner.go:62`):

- the refusal goes in `issueLeaf` (`pkg/certs/ca.go:342`), the one core below `signLeaf`
  (`pkg/certs/ca.go:334`) and `IssueUpdateSigner`, so every leaf is covered: `IssueClient`
  (`pkg/certs/ca.go:222`), whose CN and Organization are caller-supplied, the serving and
  server-client issuers, and both CSR signers, `SignClientCSR` (`pkg/certs/ca.go:298`) and
  `SignServingCSR` (`pkg/certs/ca.go:315`);
- the CSR paths through them are the join exchange's `ApproveAndSignNodeCSR`,
  `ApproveAndSignKubeletServing` and `ApproveAndSignNetserveCSR` (`pkg/bootstrap/csr.go:200`,
  `:230` and `:266`), after the CSR is parsed (`pkg/bootstrap/server.go:680`). Each sets the
  subject itself, so a CSR's own subject never reaches a certificate; the check in
  `issueLeaf` holds even if a later path passes a requested subject through;
- the Kubernetes CSR API issues nothing: the controller-manager is started with no
  `--cluster-signing-*` key (`controllerManagerArgs`, `pkg/executor/supervised.go:1069`), and a
  test holds that, so a change that adds a cluster signer must add the same refusal there.

A CN of `k3sm:local:` followed by anything, or an Organization entry `k3sm:local-users`, is
refused with a sentinel before any signing (U76).

### Single-server clusters only

Each server would hold its own keystore, so the user scope is supported only on a cluster
with exactly one server. When the apiserver lists more than one node with the
`node-role.kubernetes.io/control-plane` label, the server does not start the listener,
`doctor` reports "keystore user scope: off (more than one server registered)", and
KeyDeliveries get `UserScopeOff` (U30). The check is not only at start: the single-server
check the reconciler runs before every sweep also gates the listener, so when a second server
registers at runtime the listener stops, closing its connections, and each KeyDelivery gets
`Ready=False` and `SecretRetained=True`, both with reason `UserScopeOff`. The Secrets already
delivered stay, at their last versions, and nothing rotates or deletes them; `doctor` and the
user docs say so and that they must be deleted by hand if the user scope is not brought back
(U110). The system scope keeps Phase A's behaviour. The
limitations page says so. Replicating the keystore across servers is a later design.

### Package layout and seams

- `pkg/keystore` stays Kubernetes-free: it imports no client-go package, and a `go list -deps`
  test asserts it (U11).
- The socket server is `pkg/keystore/socket` and the KeyDelivery reconciler
  `pkg/keystore/reconcile`, siblings that import `pkg/keystore`, never the reverse.
- Each consumer declares the small interface it needs at its own site. The socket server's has
  no reveal, show or rewrap method; the reconciler's reads a value only for a delivery it has
  authorised, and its value read takes that authorisation as an argument it cannot build
  itself (U134).
- The entry grammar lives once, in `apis/keystore/entry`, which imports only the standard
  library.

**The named seams.** Each replaces one real primitive, and the primitive is banned at unit
tier: a unit test that reaches one fails. The ban is checkable, not a convention. Each package
with a seam has a `TestMain` that, before any test runs, sets every seam the package has to a
stub that panics, naming the primitive, if called: the GeneratedUID lookup, `LOCAL_PEERCRED`,
the chflags flag read, `getpwnam`, and the clock where the package reads one. Each test then
injects the fake it needs. A unit test that forgets to inject one panics instead of reaching
the host. A test injects a fake through a helper that saves the seam's current value and
restores it with `t.Cleanup`, so no fake outlives its test and no test sees another's. One guard
row per package proves the stubs are in place: `TestRealPrimitivesUnreachable` calls each seam
without injecting a fake and expects each panic. Integration and rig tests use the real
primitive; an integration test calls it directly, never through a seam the stub holds, and its
row says integration.

**Which packages carry seams, and their guards.** The seam-bearing packages are a closed list,
and a repo-level guard holds it: `k3sm/pkg/keystore::TestEverySeamPackageHasAGuard` (U58) names
each package below, parses its test files, and fails when one lacks the `TestMain` stub install
or its `TestRealPrimitivesUnreachable`; it also fails when a package outside the list declares
a seam (a package-level variable of a function type whose name ends in `Seam`). Each change that
adds a seam package adds it to the list in the same change.

| package | its seams | guard row |
|---|---|---|
| `pkg/keystore` | clock, uid resolver, chflags flag source, GeneratedUID lookup | U47 |
| `pkg/keystore/socket` | clock, chflags flag source, euid source (the listener's service-uid check); the server-side peer-credential source and the peer-sandbox source (`sandbox_check` on the peer's audit token, Open requirement 15) are constructor parameters of the listener, not package variables | U48 |
| `pkg/keystore/reconcile` | clock (sweep interval, backoff, the two-sweep count) | U59 |
| `cmd/k3sm` | clock, uid resolver, peer-credential source (client side), server code identity, exec, euid source, file-attribute writer (the maintenance verbs) | U60 |
| `pkg/install` | euid source, file-attribute writer | U61 |
| `pkg/policy` | none: its tests evaluate the policy's CEL in process and reach no host primitive | none |

| seam | the real primitive it replaces | what the unit fake gives | what `TestMain` installs |
|---|---|---|---|
| clock | `time.Now`, timers and tickers (rate limits, request timeout, listener backoff, lock waits) | a controlled clock, or `testing/synctest` | a panicking stub, in each package that reads the clock |
| uid resolver | `getpwnam` and `getpwuid` | a fixed name-to-uid table | a panicking stub |
| peer-credential source | `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` and `LOCAL_PEERPID` on the connected descriptor, both sides | any uid and pid per connection, which is how cross-user refusal is tested (U45) | client side: a panicking stub; server side: none, since it is the listener's constructor parameter and a test passes its fake there, and the constructor refuses nil (U48) |
| chflags flag source | `fstat` `st_flags & SF_APPEND` on the two logs, and `chflags` in the maintenance verbs | a flag set or clear per file | a panicking stub |
| GeneratedUID lookup | `mbr_uid_to_uuid`, with its deadline | a fixed GeneratedUID, a changed one, an error, or a lookup past the deadline | a panicking stub |
| peer-sandbox source | `sandbox_check` on the peer's audit token (`LOCAL_PEERTOKEN`) on the connected descriptor, server side (Open requirement 15) | sandboxed or not per connection, or a lookup error, which refuses (U137) | none: it is the listener's constructor parameter, and the constructor refuses nil |
| audit sink | the append to `keystore-audit.log` | an in-memory log, and one whose append fails | none: it writes a file under the test's own directory, not a host primitive |
| server code identity | `LOCAL_PEERTOKEN` on the client's connected descriptor, `SecCodeCopyGuestWithAttributes` and the cdhash of the installed binary | a peer cdhash and an installed cdhash, equal or not, or a lookup error | a panicking stub |
| exec | `syscall.Exec` in `k3sm keys exec` | a recorder of the path, argv and environment it was given, which returns instead of replacing the process (U37) | a panicking stub |
| euid source | `os.Geteuid`, behind the root check of every root verb, `install` and the maintenance verbs | any euid, so the refusal of a non-root caller and the root path are both unit-tested | a panicking stub |
| file-attribute writer | `chown`, `chmod` and `chflags` (`sappnd` set and cleared) in `install` and in `floor --rebuild` and `audit --rotate` | a recorder of each call in order, and one that fails a chosen call, which is how the crash order is unit-tested (U21, U22) | a panicking stub |

What each new seam does not cover is integration-tier only: that the real `syscall.Exec`
replaces the process with the value in the child's environment alone is E5; that the real
`chown`, `chmod` and `chflags` leave the modes and flags this design names is U50 (root-run)
and E1, E17 and E20 on the rig; the real euid is the root path every `--root` row (R1) runs.

### Deployment and rollback

The user scope ships in one step, with no flag and no phased rollout: a new feature, an additive CRD (a new kind), a single-node
daemon behaviour change and an install-tree change. The keystore is not in kine, so there is
no datastore migration. The skew window:

| state | effect |
|---|---|
| server new, worker old | workers run no keystore code; delivered Secrets mount like any Secret (E18) |
| server rolled back to the release before M20 | that release has **no keystore at all**: the keystore files are left unused, the CRD stays installed, no reconciler runs; delivered Secrets stay and nothing rotates them; KeyDeliveries are inert and, carrying the finalizer, cannot finish deleting until it is stripped (E16) |
| server rolled back to a build with Phase A but before the scope-key Rewrap | user scopes are ignored (dot name) and its Rewrap refuses while `.user` exists, so the master cannot be rewrapped out from under them |
| CLI new, server old (between the symlink flip and the restart) | `HELLO` finds no common version; the CLI says restart the server |
| more than one server registered | the user scope stays off, with a `doctor` row and `UserScopeOff` |

**Before deploying:** the cluster runs with `--secrets-encryption`, or delivery is refused
(G18); the cluster has one server, or the user scope stays off; and `sudo k3sm install` runs
after the upgrade, since it creates `keystore-sock/`, the server plist's `Sockets` entry and
the two append-only files. Without it
the user scope stays off, the server Warns at start and on every retry, `doctor` says why and
the CLI's error names the command; the system scope works.

**Rollback** is revert, rebuild and reinstall the previous binary. The release before M20 has
no keystore, so a downgrade leaves every keystore file unused rather than misread. Three
cautions for the runbook:

1. The append-only files cannot be removed by an older binary's `uninstall --purge`, so run
   `sudo chflags nosappnd /var/lib/k3sm/keystore-*.log*` before purging with one. This
   release's `uninstall --purge` clears the flags first.
2. Secrets delivered from KeyDeliveries are left in place, not deleted, because the old binary
   runs no reconciler; revoking means rotating the source.
3. KeyDeliveries keep the `keystore.k3sm.io/delivery` finalizer, so before deleting one under
   an old binary, delete its Secret and strip the finalizer with `kubectl patch keydelivery
   <name> -n <ns> --type merge -p '{"metadata":{"finalizers":null}}'`.

Rolling forward again re-adopts every object: the orphan sweep and the digest check run on the
first sweep (E16).

### Threat model for the user scope

Phase A's statement stands unchanged. The user scope adds an **authorization and ownership
boundary on the store and its API**, not a confidentiality boundary between Pods. Identity is
the uid throughout.

| principal | can | cannot |
|---|---|---|
| root | everything: every scope's values (through `M`), the floors, the audit log; the only principal that delivers or reads a system entry | (not defended against) |
| the service user (the server, runtimed, kine, the control plane, and any of its processes outside Seatbelt) | read `M` and every `K_u`, hence every value; append to the floor log and the audit log, including forged audit lines | lower the user floor, truncate or delete audit lines (outside residual 12: a descriptor opened before a maintenance verb's flag clear, Open requirement 1), write the system floor |
| a native Pod (the service uid, under Seatbelt) | read a Secret delivered into a namespace it may read, like any Secret | reach `keys.sock`, `keystore-sock/`, `server/`, the logs or Phase A's files (Seatbelt first); run under an explicit drop target of 501 or above, which is the second layer the sandbox change adds ("Pod denies"); a root Pod is outside this model (residual 17) |
| the entry's owner (a login uid of 501 or above) | put, rotate (including from a version), list, rm and exec its own entries; declare deliveries where RBAC lets `k3sm:local:<uid>` write keydeliveries and that Secret | reveal a value through any verb but exec; touch another uid's scope or any system entry; see another user's names through any verb |
| another login user | the same for its own scope | list, read, rotate, delete or deliver the owner's entries; learn their names |
| a holder of the admin kubeconfig (by default the installing user) | delete any KeyDelivery, read any delivered Secret, bind RBAC | create a working delivery for someone else's entry (a replayed, copied or retargeted object fails the UID and digest check, a forged one has no sealed record); read an undelivered value |
| the server's admin client | impersonate exactly `k3sm:local:<peer uid>` and `k3sm:local-users` for a create | impersonate any other user or group, a uid taken from the request or the entry name, or send `Impersonate-Uid` or `Impersonate-Extra-*` |

**Residuals, stated.**

1. Any process running as the owner's uid can ask the socket for the owner's values through
   `read-for-exec`: a malicious package the user installs can read every value in that user's
   scope, within the exec-read cap. Pinning the caller's code identity (`LOCAL_PEERTOKEN` with
   a code-signing requirement) would narrow it to the signed `k3sm` binary, but development
   builds are ad-hoc signed and the value would still reach the child. It is not pinned, by
   ruling; the limitations page says so.
2. The child's environment is readable by the same uid and by root (`ps -E`); `exec` is
   unconfined, with the user's own reach.
3. A KeyDelivery object, including the entry's name, is visible to anyone who may read
   keydeliveries in that namespace: names are hidden from other users on the Mac, not from the
   namespace's readers.
4. A delivered value is in kine (encrypted only with `--secrets-encryption`) and in every
   Pod-readable Secret on the node, exactly as Phase A says. Direct mounts (Phase B) would
   remove the kine copy, not the Pod reach.
5. A local user can spend the server's CPU, up to 16 MiB of disk within quota, two
   connections, and its own share of each shared log, which every line it causes is charged
   to, reads included. Past that share its own mutations and reads are refused with
   `ErrLogFull`, except its revocations (`withdraw`, `rm`, `rotate`, and the reconciler's
   deletions and first rotation write per delivery), which draw on its own revocation budgets
   above the hard cap: a 64 KiB socket margin for its own revocations and a 256 KiB reconciler
   allowance for the reconciler's. It cannot fill a log for other users, and its log lines
   cannot get another uid's mutations, reads or revocations refused, since those draw on that
   uid's own share and budgets. It can delay them through the shared store lock, by at most
   250 ms of exclusive hold in any second per uid, and enough uids together can make another
   uid's operation `busy` (a revocation retries 3 times first). The isolation is of log
   shares, not of the disk: when the file system itself refuses an append (a full disk), every
   uid's mutations and reads are refused alike, and only revocations go ahead, unaudited and
   counted. It cannot refuse the reconciler's revocations of its own Secrets either, since its
   socket revocations never draw on the reconciler allowance. What it can exhaust is its own
   socket margin, by rotating past its share; that refuses only its own further socket
   revocations, until root rotates the log. Each scope can push a log past the hard cap by at
   most 320 KiB, and the reconciler budget by 1 MiB more, so the overshoot is bounded by the
   host's eligible local accounts, and `doctor` warns when it is non-zero. A namespace writer
   who plants forged Secrets spends only the reconciler budget, never a uid's share.
6. A user account deleted and recreated under the same uid loses its old scope, by design
   (U6), and root must clear it; its delivered Secrets stay until root runs `rm-scope` (Open
   requirement 10, residual 13). A user account deleted with its uid not reused keeps its
   delivered Secrets until root runs `rm-scope`: the reconciler cannot tell a missing
   directory record from a directory service that is not up, so it reports the scope
   (`doctor`, `OwnerUnresolvable`) and deletes nothing.
7. The peer uid is the effective uid at connect time, so a setuid program the user runs acts as
   that program's owner.
8. **Revocation is rotation**: removing a delivery deletes the Secret, but a Pod that read the
   value keeps it.
9. The service user can append forged audit lines; the log proves nothing against that writer.
10. The user scope is off on a cluster with more than one server.
11. Phase A's `keystore-floor.json` and `keystore-delivery.json` are root 0644, so a local
    login user can read the system entries' names, and the declared delivery targets. This is
    accepted: the service user must read the floor, and neither file holds a value. Pods are
    covered by the data-root denies ("Pod denies"). What a login user cannot do with a system
    entry is read or deliver it (E12).
12. During `audit --rotate` and `floor --rebuild`, the old log and each archive rotate shifts
    are unflagged between their flag clear and their next flag set, with the listener stopped
    and the lock held. They are root 0600 from the clear's own step (Open requirement 1), so no
    service-user process can open one by path in that interval. What stays: a service-user
    process that opened a writable descriptor on one before the clear could truncate it through
    that descriptor in the interval, and so could an open landing between the two consecutive
    calls of the clear's step. The new file has no such window ("No unflagged window for the
    new file").
13. The GeneratedUID's stability across a macOS upgrade, a Migration Assistant transfer or a
    directory rebind is not measured; K0 measured it only across processes and a restart. A
    change there reads as `ErrScopeOwnerChanged`, which in this release is `Indeterminate` and
    a `doctor` report, never a deletion (Open requirement 10): the account's scope no longer
    opens, its delivered Secrets stay at their last versions, and root judges it. So does a
    real uid reuse, whose new account keeps the old account's delivered Secrets in place until
    root runs `rm-scope`.
14. macOS can give a deleted account's uid to a new account. The GeneratedUID binding keeps
    the new account out of the old scope (`withdraw` included), but RoleBindings and
    ClusterRoleBindings naming `k3sm:local:<uid>` stay and grant the new account what the old
    one had, until root removes them; `rm-scope` lists them and refuses while any exist,
    unless `--keep-bindings` is given.
15. Rewrap does not re-key `K_u`. Someone who holds an old master and an old copy of a user's
    `scope.key` (a backup, a disk image) can still open that user's records after a Rewrap,
    including values stored since. The only remedy in this release is the documented one: after
    a suspected master exposure each user re-puts their values with new credentials, and
    `rewrap` warns whenever user scopes exist.
16. A delivered Secret whose label or owner annotation someone removed is left in place
    (`LabelRemoved`), so it is not deleted when the delivery is revoked, and it is never
    repaired either: a writer who strips the label holds a substituted value in place at that
    name, and the reconciler only reports it. This adds no reach: the principal that could edit
    the Secret's metadata holds update on it and could already read, copy or replace its
    value.
17. Root Pods are out of the user-scope threat model. A Pod with no drop on a root daemon runs
    as root, and runtimed does not refuse it (`CheckPodUID` in
    `runtimed/pkg/supervisor/privdrop.go` judges only a drop, and a gid-only drop that leaves uid 0 is refused). The socket refuses peer uid 0 before any frame
    (U26), and root owns the host anyway (Phase A), so a root Pod gains nothing here that root
    lacks. Short of that, the drop refusals hold on a root daemon too: a gid in 1 to 500 that the
    host assigns is refused as the primary or a supplemental group, the service identity is
    resolved on every check, and a symlink at an installed path refuses every drop
    (`runtimed/pkg/supervisor::TestPodGroupsHostAssigned`,
    `runtimed/pkg/runtime::TestSymlinkedWorkDirRefusesDrops`). The exec shim does not receive the data root, so it relies on the runtime's check, which runs before the shim is spawned.
18. Permission to update `nodes` freezes revocation. A principal that may label a node
    `node-role.kubernetes.io/control-plane` (or register a second server) makes the
    single-server check see more than one server, which stops the listener and every sweep
    ("Single-server clusters only"): no delivered Secret is deleted or rotated until the label
    goes, so a revoked credential stays delivered. `nodes` update is therefore a
    revocation-freezing permission; the user docs say to grant it to no one who should not hold
    that power, and `doctor` names the extra server.
19. The GeneratedUID binding trusts whatever the directory service answers. On a Mac bound to
    a network directory (LDAP, or Active Directory with mobile accounts), the GeneratedUID
    `mbr_uid_to_uuid` returns comes from that directory, so whoever controls the directory,
    or its answers to this Mac, can make a reused uid look like the scope's original owner,
    or make the real owner look changed (`ErrScopeOwnerChanged`, which deletes nothing in
    this release). The binding closes uid reuse by local accounts; it is no defence against
    the directory itself.
### What the user scope does not do

Phase B direct mounts; a ServiceAccount rotate transport, deferred to a new endpoint with its
own design; grants of system entries to non-root users; a per-user re-key of `K_u` in this
release (residual 15); a per-user
kubeconfig or any Kubernetes identity for local users (the socket is the path); the user scope
on a worker node or across several servers; a hash chain on the audit log; un-sharing a value
a Pod already read; a hardware-backed master; a `k3sm status` field or app change (the `doctor`
rows are not a contract).

### Open requirements carried to the slices

A finding from the design's last review round that is not closed here is a binding
requirement on the slice named beside it, re-checked by that slice's own security review.
Each entry names the defect, the required fix, the owning slice and the row whose test fails
without the fix. Where the design's text above states the behaviour an entry changes, that
text points here.

1. **The old log is service-user-owned while unflagged (K8).** During `audit --rotate` and
   `floor --rebuild` the old file, and every archive `audit --rotate` shifts, is unflagged
   between its flag clear and its next flag set while still owned by the service user, so a
   service-user process can open it by path with `O_TRUNC` and truncate it. *Fix:* the step
   that clears `sappnd` also `fchown`s the file to root and `fchmod`s it 0600, both on the
   verb's own descriptor, as consecutive calls with nothing between them; no later step runs
   until both succeed, and the archives stay root 0600 from then on. *Test:* U118, root-run: the
   service user's `open(O_WRONLY|O_TRUNC)` of the old file and of each shifted archive, between
   the clear and the re-flag, gets `EACCES`.
2. **Any local user can hold the floor lock (K8, and merged Phase A code).** Phase A's floor
   writers take `flock(2)` on the data-root directory itself (`pkg/keystore/floor.go:368` to
   `:375`); the data root is root:wheel 0755, so any local user can open it, take the lock and
   hold it, and every root verb that writes the floor, the revocation and recovery verbs
   included, then fails with the lock timeout. *Fix:* the floor lock moves to a file
   `keystore-lock` in the data root, root-owned 0600, created by the first root verb through
   the data-root descriptor rules ("Root never acts by path where the service user can write"),
   which only root can open. Every root verb that writes the system floor or a keystore file in
   the data root takes it, after the store `.lock` and with the same bounded wait: `put`,
   `rotate`, `rm`, `rewrap`, `deliver system/…`, the floor raise at the start of `list` and
   `show`, `rm-scope`, `floor --rebuild` and `audit --rotate`. The server never takes it. This
   changes Phase A code already merged and Phase A's "Concurrency" text, so it is also filed as
   its own change. *Test:* U119, root-run: a non-root process other than the service user
   holding the old data-root flock blocks none of those verbs (the service user still owns
   `keystore/.lock`; see "Concurrency").
3. **The activated listener must reach no child (K9a).** The listening descriptor launchd
   passes to the server must not be inherited by any process the server starts. *Fix:* the
   server sets `FD_CLOEXEC` on it before any other work, and no spawn path passes it on.
   *Test:* U120, server-side integration: spawn each child type (an `exec.Command` child, the
   runtimed helper, a Pod through the exec shim), list each one's open descriptors, and fail if
   the listening socket is among them.
4. **Under activation the client may see launchd as the peer (K9a, measured in K7a).** The
   client-side `LOCAL_PEERCRED` and `LOCAL_PEERTOKEN` may name launchd (uid 0), the process
   that listened, not the accepting server. *Binding rule, a K7a outcome:* K7a measures both
   from a login user's process. If either names launchd, or names anything but the accepting
   server, the build ships the deny-plus-pin self-bind form ("The socket's directory is
   root's"). U36's rule is never relaxed to accept uid 0. *Test:* U121: a client whose peer
   reads as uid 0 or as launchd's code refuses and writes nothing.
5. **A Pod might obtain the listener from launchd (K9a, measured in K7a).** A process
   descended from the server's job can ask launchd for the job's sockets with
   `launch_activate_socket`, and Pods descend from it (`runtimed/pkg/runtime/podreap.go:40`).
   *Fix:* K7a measures this from a Pod. If a Pod can obtain the listener, the build ships the
   self-bind form, and the Pod profile denies the launchd socket-activation lookup in either
   form. *Test:* U122 (the rendered Pod profile carries the deny) and rig leg E27 (a Pod's
   `launch_activate_socket` for the server's socket name gets no descriptor).
6. **Same-target cross-record deletion (K13b).** Two honoured records, of two uids, can name
   the same `(namespace, secretName)`. The orphan sweep, the lost-authority delete and
   `rm-scope` match a Secret against one record's target, so one uid's tombstone, or a forged
   owner annotation naming it, could delete the Secret another uid's live delivery owns.
   *Fix:* none of the three deletes a Secret that another honoured record claims at the same
   `(namespace, secretName)`; the owner annotation never selects which record's tombstone
   governs a delete; and no line is charged to the victim. *Test:* U123,
   `TestForgedTombstoneAnnotationOnOtherUsersLiveSecretIsNotDeleted`, which drives the
   target-matching decision the reconciler and `rm-scope` share.
7. **A tombstone whose target is reused never prunes (K13b).** Pruning only on a Get that
   answers not found keeps a tombstone forever once someone else's Secret stands at its target.
   *Fix:* a tombstone is pruned when its target is not this UID's owned Secret (gone, or held
   by anything that fails the ownership test for this UID) on two observations at least 60 s
   apart. *Test:* U124: an occupied target still prunes.
8. **A delete can land on a replaced Secret (K13b).** A Secret can be deleted and re-created
   under the same name between the ownership read and the delete. *Fix:* every reconciler
   Secret delete or update and every `rm-scope` delete passes `Preconditions{UID,
   ResourceVersion}` from the ownership read, and a precondition failure is `Indeterminate`.
   *Test:* U125: a fake client swaps the Secret between the read and the delete, and the delete
   is refused.
9. **One source can spend the whole reconciler budget (K13b).** *Fix:* the 1 MiB reconciler
   budget is split by source: 384 KiB for forged-Secret `refused` lines, 384 KiB for drift
   repairs and their summaries, 256 KiB for pre-frame refusals; the forged and repair budgets
   are also capped at 64 KiB per namespace. Dropped counts are persisted: each summary line
   carries the count dropped since the last summary line written for that source, so the count
   reaches the log with the next line written, not only memory. *Test:* U126.
10. **`ErrScopeOwnerChanged` is not yet a deleting outcome (K7a).** GeneratedUID stability
    across Migration Assistant, a macOS upgrade and a directory rebind is not measured, so a
    change there could delete every delivered Secret of a user who still owns them. *Fix:*
    until a K7a amendment records that measurement, `ErrScopeOwnerChanged` is `Indeterminate`
    plus a `doctor` report naming the scope; it is not on the allow-list, and the Secrets stay.
    *Test:* U127.
11. **Rewrap writes under the service user's tree by path (K7b).** *Fix:* Rewrap of each
    `scope.key`, and every root write under `server/keystore/`, walks by descriptor and joins
    the list in "Root walks service-user trees by descriptor". *Test:* U128, root-run, and a
    Rewrap case in U80.
12. **A departed account blocks a rebuild, and a removed scope keeps its claims (K7a and
    K13b).** *Fix:* `floor --rebuild` reads any scope whose `scope.key` opens under `W`
    without the GeneratedUID check, so `ErrScopeOwnerUnknown` blocks nothing (K7a; U129). A scope
    listed in `keystore-removed-scopes.json` counts as definitive for claims, so its stale
    objects lose their claim, and `rm-scope` also deletes that scope's KeyDeliveries (K13b;
    U130).
13. **Missing rows (K9a, K7a, K13b; the policy's row K12).** *Fix:* rows for the
    `MNT_IGNORE_OWNERSHIP` start refusal (K9a; U131); the modes of `.user/<uid>/`, `scope.key`
    and `deliveries` (K7a; U132); `keystore-removed-scopes.json`, added to the on-disk layout and
    the Pod-deny list, root-owned, its mode and a strict parse (K13b; U133); the reconciler's
    store interface reading a value only for an authorised delivery (K13b; U134); and the
    policy's `failurePolicy: Fail` with the namespace-controller exemption covering DELETE only
    (K12, which ships the policy; U135).
14. **Annotation text reaches root's terminal (K9b, K13b).** A namespace writer controls
    Secret annotations. *Fix:* every root verb and `doctor` line that prints annotation text
    strips control characters first. *Test:* U136.
15. **A Pod at the service uid relies on the uid check alone behind Seatbelt (K9a, measured
    in K7a).** In the shipped posture Pods and the listener share the service uid; the
    eligibility rule refuses that uid, but nothing independent of the uid refuses a Pod process
    that passed a Seatbelt miss. *Fix:* the listener refuses, before the first frame, any peer
    that is sandboxed: it calls `sandbox_check` on the peer's audit token (`LOCAL_PEERTOKEN`)
    through a cgo seam behind an interface, the listener's peer-sandbox source, a constructor
    parameter like the peer-credential source. K7a measures that `sandbox_check` on a peer token
    reports a Seatbelt-confined Pod process as sandboxed and an unconfined login shell as not.
    *Test:* U137 with a fake token source, and rig leg E26: a real Pod's connect is refused with
    the keystore deny stanza removed.

### Facts from the rig spike

A script-only spike on the rig's server measured these before any code depends on them. A
spike never counts as proof. Its result is quoted here as a dated amendment, which also picks
the floor variant.

**K0 amendment, 2026-11-21.** The spike ran on the rig's server (macOS 27, APFS data volume,
`kern.securelevel` 0) from a recorded build, as root, and cleaned up after itself. Evidence:
the K0 spike's evidence of 2026-11-21 (`status.txt`, `leg1.txt` to `leg4-*.txt`,
`leg3b-unresolved-uid.txt`).

| leg | the fact | result | where it applies |
|---|---|---|---|
| 1 | `sappnd` on an APFS data volume as the service user: append works, the whole defeat list fails, owner `chmod` widens nothing; the securelevel, whether root can clear the flag, whether a rename over an `sappnd` target needs the clear first | **Measured.** Append works. All 12 defeat attempts fail with EPERM and leave the inode intact: truncate, ftruncate, open-truncate, `pwrite` at offset 0, `F_PUNCHHOLE`, `link`, `fclonefileat` then rename over, rename over, rename away, unlink, `chflags nosappnd`, and `chmod`. At securelevel 0 root can clear the flag. Root's rename over a flagged target fails with EPERM, so maintenance clears the old file's flag before the rename. **The flag variant is chosen**; the floor helper variant is not built. | "The user-scope floor" |
| 2 | `LOCAL_PEERCRED` both ways, a login uid over SSH; `LOCAL_PEERTOKEN` and the code lookup on the client side | **`LOCAL_PEERCRED` measured both ways**: the server saw root (euid 0) and the login user (euid 501), and each client saw the server as the service user (euid 250). **Pending:** `LOCAL_PEERTOKEN` and resolving the server's code and cdhash from it were not in the spike; K7a measures them before the client's server pin is built, and the pin's rows (U69, E24) stay pending until then. If either is unusable from a login user's process, the user scope does not ship ("The client pins the server"). | "The socket" |
| 3 | `mbr_uid_to_uuid` is stable across a server restart; its cold latency; what it returns for a uid with no record | **Measured.** The GeneratedUID equals `dscl`'s and is stable across processes. Cold first lookup about 1.4 ms, worst of 20 cold processes 2.8 ms, warm median 0.17 ms, so a 250 ms deadline has wide margin. A uid with no record returns the synthesized form `FFFFEEEE-DDDD-CCCC-BBBB-AAAA<uid hex>` with status 0, and so does root; the synthesized-prefix rule is required. | "Key hierarchy" |
| 4 | a Pod with the data-root denies cannot reach the socket or any `keystore-*` path; without them, what a Pod reaches today | **Without the denies, measured:** a native Pod on the server connected to `keys.sock` (two accepts), so the denies are a hard prerequisite of any keystore file or socket (K5 before K8). Phase A's two data-root files did not exist on the rig, so their readability today is unmeasured. **Pending:** the Pod with the denies is the K5 rig leg (E10). | "Pod denies", "Threat model" |
| 5 | which uid a native Pod's processes run as; whether a Pod spec field or runtimed path can make it 501 or above | **Measured for a default Pod:** uid 250 (the service user), below 501, and the socket saw peer euid 250. **Pending:** the spec-field and runtimed-path half (`runAsUser` and the other fields) is K5's row U15. Pods and the server share uid 250, which is why the client pins the server by more than its uid. | "Pod denies" (layer 2, row U15) |

**Owed to K7a.** K7a is the measurement run before the changes that depend on it, recorded
as a dated amendment like K0's. It measures: `LOCAL_PEERTOKEN` and the code lookup from it on
the client side (leg 2's pending half); root's `fchown` of a file it has just flagged `sappnd`;
the 50 ms exclusive hold bound ("The audit log", lock modes); whether the client-side
`LOCAL_PEERCRED` and `LOCAL_PEERTOKEN` name the accepting process or the one that listened
("The client pins the server", Open requirement 4); and whether launchd activates a
`Sockets` socket for a job with `UserName` set, root-owned in a root-owned directory, with the
server receiving it through `launch_activate_socket` ("The socket's directory is root's"). If
that one fails, the deny-plus-pin fallback ships. It also measures: whether a Pod can obtain the listener from launchd
(Open requirement 5); GeneratedUID stability across Migration Assistant, a macOS upgrade and a
directory rebind (Open requirement 10); and `sandbox_check` on a peer's audit token for a
confined Pod process and an unconfined login shell (Open requirement 15).

Two facts are open but are not spike legs: whether the admission policy sees the impersonated
user in `request.userInfo.username` (U40 and E3), and whether the rig runs with
`--secrets-encryption` (E1).

## Typed credentials

The user scope stores and delivers one opaque value or one Ed25519 key per entry. This section
extends it to the credentials a service actually issues: a token that expires, an SSH key, and
an OAuth access and refresh pair. It adds multi-field and access-only projection into a Secret,
expiry and revocation visible on the KeyDelivery, a per-pod mount audit, and a server-side
refresher for OAuth pairs. Where an earlier section of this document disagrees with this one,
this one binds, and the earlier text has been amended to match: the target digest, the
`deliveries` record bound, the KeyDelivery shape and reasons, the delivered Secret's metadata
keys and the root-file format.

Entry names follow the existing grammar ("Scope strings and names"): a service credential is
`user/<uid>/<service>.<account>` or `system/<service>.<account>`, for example
`user/501/github.ci-bot`. Values still arrive only on stdin or over `k3sm-keys/1`. Nothing in
k3sm names a service: a service is described by data (a refresh profile, below), never by code.

What the user scope already gives and this section keeps: both scopes; one KeyDelivery per
(namespace, Secret) and delivery to any number of namespaces; rotation without a pod restart for
a Secret **volume**, since the provider re-renders a volume about once a minute and never through
`subPath` (`pkg/provider/projectedrefresh.go`), while `env`, `envFrom` and `subPath` consumers see
a new value only after a restart, as upstream; `Authorized` and `Ready` with "a denial deletes;
an error does not"; an audit line for every socket call, root verb and reconciler write; `exec`
injection; no system grants; a single server; delivery refused while secrets encryption is off
(G18).

The record kinds as merged are `KindUnknown = 0` (never written), `KindEd25519 = 1` and
`KindOpaque = 2` (`pkg/keystore/keystore.go`, `record.go`). Kinds 0xFF (the pointer), 0xFE and
0xFD are unchanged.

### Record kinds, the typed envelope and retention

`recordFormat` stays 1. Three kind bytes are added; 6 to 0xFC stay unassigned.

| byte | kind (`--kind`) | sealed plaintext | fingerprint |
|---|---|---|---|
| 1 | `ed25519` | 32- or 64-byte key, unchanged | `hex(sha256(pub))`, unchanged |
| 2 | `opaque` | raw bytes, unchanged | keyed HMAC, unchanged |
| 3 | `token` | envelope: `value`, `expiresAt`, `issuedAt` | keyed HMAC over the canonical envelope |
| 4 | `ssh` | envelope: `algorithm` (1 = ed25519), `seed` (32 B), `comment` (optional) | OpenSSH `SHA256:<b64>` of the public key, the string a forge shows |
| 5 | `oauth` | envelope: `accessToken`, `accessExpiresAt`, `accessIssuedAt`, `refreshToken`, `refreshExpiresAt` (optional), `tokenType` (optional, default `Bearer`), `refreshOwner` | keyed HMAC over the canonical envelope |

- A credential that never expires is `opaque`. `token` always carries `expiresAt`, so "token"
  always means "it expires".
- **An OAuth pair is one record**: one entry, one version per refresh. The access and refresh
  tokens move together under one pointer flip and one floor line. Two entries would need
  cross-entry atomicity, which the store does not have.
- **Kind is fixed when the entry is created.** `rotate`, and `put` over an existing name, refuse a
  different kind with `ErrKindMismatch` (wire `kind-mismatch`). A KeyDelivery's immutable `items`
  is therefore valid for the entry's whole life; changing kind means a new entry name (U146).

**The envelope** (kinds 3 to 5):

- Layout: a 1-byte envelope version (1), then TLV fields: tag (1 B), length (2 B big-endian),
  value.
- Tags: token 0x10 `value`, 0x11 `expiresAt`, 0x12 `issuedAt`; ssh 0x20 `algorithm`, 0x21 `seed`,
  0x22 `comment`; oauth 0x30 `accessToken`, 0x31 `accessExpiresAt`, 0x32 `accessIssuedAt`, 0x33
  `refreshToken`, 0x34 `refreshExpiresAt`, 0x35 `tokenType`, 0x36 `refreshOwner`. Strictly
  ascending, no duplicates, every required tag present, the per-kind set closed.
- Bounds: token value at most 16 KiB, access token 32 KiB, refresh token 8 KiB, comment 255
  printable ASCII bytes, `tokenType` 32 bytes of `[A-Za-z]`, `refreshOwner` 70 bytes in the
  refresh-owner grammar. Times are Unix seconds, int64 big-endian. The whole envelope fits
  `MaxValueSize` (64 KiB).
- **`issuedAt` and `accessIssuedAt` are sealed**, stamped from the server's clock seam at `put`,
  `rotate` or refresh. The `Expiring` threshold and the refresh schedule use them, never the
  record's `created` header, which stays unauthenticated display metadata: a party who can write
  record files but not the master cannot move a credential's timing (U144).
- A bad envelope (unknown tag, wrong order, missing field, out of bounds) is `ErrCorrupt`: no
  build writes one.
- Binary, not JSON, like the record layer ("Record encoding").
- **Where it lives.** The codec, the projection renderer and the SSH helpers are a pure,
  seam-free package, `pkg/keystore/typed`. It imports no Kubernetes package and holds no store
  state.
- **Tests pin the bytes.** Committed per-kind golden vectors under
  `pkg/keystore/typed/testdata/envelope/` (U143). `FuzzEnvelopeParse` asserts that an accepted
  input re-encodes byte-identically and that an error never contains input bytes; its seeds live
  in `testdata/fuzz/FuzzEnvelopeParse/`, which a lint keeps non-empty (U154).

**Binding into the AAD.** The kind byte is already `LP(kind)` in the six-field AAD ("Record
encoding"), so relabelling a typed record as another kind fails to open. The metadata sits
inside the sealed plaintext, which GCM authenticates and hides: a disk reader learns neither
expiry nor owner. No AAD field is added and the offset table does not change.

**Kind-byte table** (U145): 1, 2, 3, 4, 5 and 0xFF are known; 6 to 0xFC and an unknown envelope
version are `ErrKindUnsupported`; 0xFD and 0xFE stay `ErrCorrupt` until their own changes give
them meaning.

**Retention, with a sealed low-water mark.**

- `token` and `ssh` keep the unbounded retention of every other kind.
- `oauth` keeps the current version and one previous. Otherwise refreshes would fill the 16 MiB
  quota and keep dead refresh tokens forever; a pruned version's refresh token is gone, which is
  the point.
- **The mark lives in the current-pointer plaintext.** Today that is 16 bytes (`version`,
  `sequence`). A pointer that records a prune carries 24 bytes: `version`, `sequence`, `low`,
  where `low` is the oldest retained version and `1 ≤ low ≤ version`. A 16-byte pointer means
  `low = 1`, so every existing pointer and every `token` or `ssh` pointer stays byte-identical.
  Any other size, or `low` out of range, is `ErrCorrupt`.
- *Why the pointer.* The mark must move in the same atomic step as `current`, and the pointer's
  rename is already the entry's one commit point, so a crash never leaves a mark that disagrees
  with `current`. It must be authenticated: the pointer is sealed under the entry's AAD, so a disk
  writer can neither lower it (making pruned versions look missing, which reads as damage) nor
  raise it (hiding committed versions). List, Rewrap, Delete and the floor already open the
  pointer first. A separate mark file would need cross-file atomicity, and the floor file is
  unsealed.
- *The write order:* seal version V+1, write the pointer `{V+1, seq+1, low = V}`, the floor line,
  the audit line, then unlink every version below `low`. A crash after the pointer leaves files
  below `low` on disk; they are not committed, List ignores them, and the next write, Rewrap and
  Delete unlink them.
- **The committed range is `low..current`.** This amends the contiguity rule ("v1 to the version
  `current` names") for List ("List, when one entry is corrupt"), Rewrap ("re-seals every
  committed version"), Delete, the floor and the pointer copy-back check. A version missing inside
  `low..current` is still damage. A copied-back pointer naming a version below another pointer's
  `low` fails the floor's sequence check as before (U151, U152).
- `rotate --from-version` is refused for `oauth`: resurrecting a rotated refresh token can trip a
  provider's reuse detection and revoke the whole grant family (U153).

**The refresh token is write-only after `put`, and the store enforces it by type.**

- For kinds 3 to 5, `Store.Get` and `Current` return the kind and a `typed.Credential`, decoded
  inside the store. `typed.Credential` has no refresh field to fill, so the socket, both
  reconcilers, `exec`, `show --reveal` and `typed.Project` never hold the refresh token's bytes.
- The full envelope comes back only from an opener in `pkg/keystore/internal/refreshopen`.
  `pkg/keystore` installs the opener at init, and only `pkg/keystore/refresh` calls it. Go's
  internal-package rule keeps every package outside `pkg/keystore/...` from importing it, and an
  import-graph test keeps every sibling but `refresh` (and the installing `pkg/keystore`) out.
- A behavioural test plants a refresh token, calls every exported method of `pkg/keystore` and
  every consumer interface (the socket handlers, both reconcilers' store interfaces,
  `typed.Project`), and scans every result for its raw, standard and URL-safe base64, and
  percent-encoded forms (U149).
- Writing is unrestricted by kind: `put`, the owner's `rotate` and the refresher's `RotateIf`
  take a full pair in.
- Root can still read the master. That is not defended against, as before.

### Unknown kinds, ownership and rollback

- **No format bump.** `parseRecord`'s refusal splits: a kind byte in 6 to 0xFC, or an unknown
  envelope version, is `ErrKindUnsupported`: "this entry was written by a newer k3sm; upgrade". It
  is not wrapped in `ErrCorrupt`, whose text says to restore from backup. `list` shows such an
  entry as `unsupported` and exits 1, like `corrupt`.
- **The reconcilers' mapping is unchanged.** Only `ErrNotFound` (and, once allowed,
  `ErrScopeOwnerChanged`) are denials. `ErrKindUnsupported` and `ErrCorrupt` fall under U55's rule
  that every other sentinel is `Indeterminate`, so U55's allow-list test needs no change; the
  typed case is its own row (U164). Nothing is deleted on either error.
- **No interim guard.** A reconciler that meets kind 3 to 5 before projection lands takes the
  unknown-kind path: `Indeterminate`, nothing written, nothing deleted.
- Rewrap stays kind-agnostic: it re-seals bytes and keeps the kind byte, over `low..current`.
- **A reader that predates typed kinds** refuses kinds 3 to 5 as `ErrCorrupt`. No release ships
  the user scope without them, because the release before has no keystore at all.
- **Rolling back past typed kinds needs re-logins, not a restore.** A build without typed kinds,
  or without the refresher, cannot read or refresh `server/` pairs, and a provider has usually
  rotated their refresh tokens already. So each owner signs in again for their `server/` pairs
  after rolling forward. A `corrupt` or `unsupported` typed entry then is **not** a
  restore-from-backup case: a backup holds older, already-rotated refresh tokens the provider
  refuses. `list`, `doctor` and the user docs say so.

### Projection: KeyDelivery `items` and the root-file target

`spec.items` replaces a single data key. It is a list of `{field, key}`, the
`k3sm.io/apis/keystore/credential` `Item` type, **required, with no CRD default**: a kind-blind
default is wrong for `oauth`, and the API server cannot see the entry's kind.

- `minItems` 1, `maxItems` 8; `listType=map` keyed by `key`, so keys are unique.
- `key` matches the Secret data-key pattern `^[-._a-zA-Z0-9]+$`, `maxLength` 253, and a CEL rule
  refuses `.` and any key starting with `..`, as the API server's own data-key check does
  (U139).
- `field` is a CRD `enum` equal to `credential.Fields()`, the union of the field table across
  kinds, `maxLength` 32 (`credential.MaxFieldLength`). `refreshToken` (`credential.RefreshTokenField`)
  is in no kind's fields, so the schema refuses it (U140, E31). A field in the enum but wrong for
  the entry's kind is caught at reconcile as `ProjectionInvalid`.
- **Immutable, order-insensitive.** The transition rule compares items as a map:
  `size(self) == size(oldSelf) && self.all(i, oldSelf.exists(o, o.key == i.key && o.field == i.field))`.
  A reorder is accepted; a changed `field`, `key` or count is refused. U139 tests both and the
  rule's CEL cost estimate.
- There is no `spec.dataKey`. The CRD's first tagged shape is this one.

**The field table** lives in `k3sm.io/apis/keystore/credential` (`FieldsFor`, `Fields`). The CRD
enum, the CLI and `typed.Project` all derive from it, and a conformance test in k3sm checks that
`Project` supports exactly the table's fields per kind (U160).

| kind | projectable fields | rendering in the Secret | CLI default with no `--item` |
|---|---|---|---|
| `opaque` | `value` | the bytes | `value=value` |
| `ed25519` | `value` | the seed or key, as the root-file delivery renders it | `value=value` |
| `token` | `value`, `expiresAt` | the bytes; RFC 3339 UTC text | `value=token`, `expiresAt=expires_at` |
| `ssh` | `privateKey`, `publicKey` | unencrypted OpenSSH PEM; an `authorized_keys` line with the comment | **none: refused** |
| `oauth` | `accessToken`, `accessExpiresAt`, `tokenType` | the bytes; RFC 3339 UTC; text | `accessToken=access_token`, `accessExpiresAt=access_expires_at` |

- **Access-only is structural.** No kind has a projectable refresh field, so no KeyDelivery,
  root-file target, `exec --field` or `show --field` can name one, and `Project` receives a
  `typed.Credential`, which has none (U140, U141, U149, U160).
- **An `ssh` private key is projected only when named.** The CLI has no default for `ssh`:
  delivering an ssh entry must name `--item privateKey=…`, and without items it is refused
  (U163).
- A field that the entry's kind does not have sets `Ready=False`, reason `ProjectionInvalid`, and
  leaves any existing Secret untouched: an error, not a denial (U161).
- **Item order is not semantic** anywhere: the CRD rule compares as a map, and the digest sorts
  by key.
- **The target digest** is
  `sha256("k3sm-keystore-delivery-target/v1" ‖ LP(entry) ‖ LP(namespace) ‖ LP(secretName) ‖ LP(items))`,
  where `items` is one length-prefixed blob: the items sorted by `key` bytewise, each
  `LP(field) ‖ LP(key)`. Golden vectors (one item, two items, a shuffled input) are committed under
  `testdata` (U161). The label stays `/v1`, since nothing has shipped. This replaces the earlier
  five-string digest over `dataKey` and `requestedBy` ("KeyDelivery", U14, U41).
- **The root-file target** (`keystore-delivery.json`) carries the same `items`, in the
  `credential.Item` JSON form `{"field": …, "key": …}`, at file `version: 1`.
  `sudo k3sm keys deliver system/… --item field=key …` writes it, and it is parsed strictly
  (U162; "Delivery reconciler").
- `typed.Project(kind, cred, items) (map[string][]byte, error)` serves both reconcilers.
- **Secrets at rest.** G18 (delivery refused while secrets encryption is off) covers kinds 3 to 5
  unchanged; a row proves it for each typed kind (U164).
- **File modes are the pod's, and they are not a confidentiality control.** k3sm sets no mode;
  `defaultMode` and `items[].mode` decide. Native pods share the service uid
  (`runtimed/pkg/mount/doc.go`), so mode bits protect nothing from another process in any pod; the
  Seatbelt read scope is the only barrier. OpenSSH refuses a private key readable beyond its
  owner, so an ssh key needs `defaultMode` 0400 or 0600. The user docs say: mount a volume, never
  use `subPath`; deliver long-lived keys (`ssh`, `token`) only to dedicated namespaces whose pods
  run trusted code; rendered files stay on the pod's data volume until the pod is reaped.
- **CLI:** `--data-key K` is shorthand for `--item value=K`; with no `--item`, the CLI takes the
  table's per-kind default.

### Expiry and revocation: `CredentialValid` and Events

- **`Ready` means delivered.** It does not change on expiry or revocation. The CRD description and
  the user docs say that health readers read `CredentialValid`, and that
  `kubectl wait --for=condition=Ready` says nothing about the credential's health.
- **`CredentialValid`** is set only for kinds with an expiry (`token`, `oauth`) and is absent for
  the others. Its reasons are `credential.Validities()`, the `Validity` type:

| reason | status | when |
|---|---|---|
| `Valid` | `True` | not expiring, refresh healthy |
| `Expiring` | `True` | token: remaining ≤ min(30 d, 25% of `expiresAt − issuedAt`); oauth: the same rule on `refreshExpiresAt − accessIssuedAt` of the first version, when `refreshExpiresAt` is known |
| `RefreshFailing` | `True` | oauth: the last server refresh failed transiently and the access token is still valid |
| `Expired` | `False` | token: past `expiresAt`; oauth: past `accessExpiresAt` with no newer version |
| `Revoked` | `False` | oauth: the token endpoint answered an error code in the profile's `revokedErrorCodes` |
| `Indeterminate` | `Unknown` | the entry could not be opened ("Unknown kinds, ownership and rollback") |

- **`Valid`, `Expiring` and `RefreshFailing` share `True` deliberately.** The access token still
  works in all three, and readers key on the reason (the tolerant-reader rule). The CRD
  description and the docs say so.
- **Every condition carries `observedGeneration`**: `Authorized`, `Ready`, `SecretRetained` and
  `CredentialValid`. The CRD requires it on each condition, since `meta.SetStatusCondition` does
  not fill it in (U142, U165).
- **Expiry never deletes a Secret.** An expired token is harmless, and a clock step must not
  delete a Secret. Withdrawal is the owner's act (U168).
- `Revoked` is evidence k3sm holds itself. k3sm cannot see revocation of a `token`, so a token is
  only ever `Expiring` or `Expired`.
- **Where refresh state comes from.** `pkg/keystore/reconcile` defines a consumer-side
  `RefreshStatus` interface (per entry: state `ok`, `failing`, `revoked` or `off`, a cause, the
  last refresh time). `pkg/keystore/refresh` implements it from its persisted state. Until the
  refresher lands the reconciler holds a nil `RefreshStatus` and derives oauth conditions from
  stored expiry only.
- **Events fire on real transitions only.** The reconciler takes the previous state from the
  KeyDelivery's persisted status (reason and `lastTransitionTime`), never from memory, so a server
  restart re-emits nothing. Hysteresis: a reason must hold for two consecutive evaluations, or
  60 s, before it replaces the previous one, except `Revoked` and `Expired`, which apply at once
  (U166).
- **The Events** use `events.k8s.io/v1`, `regarding` the KeyDelivery and `related` the Secret, so
  `kubectl describe secret` shows them. Reasons and types are `credential.EventReasons()`:

| reason | type | when |
|---|---|---|
| `CredentialExpiring` | `Warning` | into `Expiring` |
| `CredentialExpired` | `Warning` | into `Expired` |
| `CredentialRefreshFailing` | `Warning` | into `RefreshFailing` |
| `CredentialRevoked` | `Warning` | into `Revoked` |
| `CredentialRecovered` | `Normal` | back to `Valid` after any other reason |

  Routine successful refreshes emit no Event.
- **What a message may carry:** the KeyDelivery name, the Secret name, the delivered version,
  RFC 3339 times, and for `RefreshFailing` one cause from the closed set `invalid_client`,
  `unauthorized_client`, `invalid_scope`, `server_error`, `temporarily_unavailable`, `http-4xx`,
  `http-5xx`, `network`, `dns`, `tls`, `clock-skew`, `dial-refused`, `profile-unavailable`,
  `client-secret-unavailable`, `response-invalid`, `log-full`, `multi-server`.
- **What a message may never carry:** a value, a length, a fingerprint, the endpoint's
  `error_description` or body, a response header, or the caller's uid (U167).
- The reconciler requeues at the next threshold time through its clock seam (the controller's
  rate-limited `AddAfter`) rather than waiting for a sweep.
- **The same facts without Kubernetes.** `k3sm keys list -o json` and the socket's `list` and
  `deliveries` replies gain `kind`, `expires_at`, `access_expires_at`, `refresh_expires_at`,
  `refresh_owner`, `refresh_state` (`credential.RefreshStates()`) and `last_refresh_at`: metadata,
  never bytes. Reading them opens each typed entry's current version under the owner's scope key,
  inside the existing per-uid `list` rate limit. An entry that does not open shows `corrupt` or
  `unsupported` with null metadata. The keys are snake_case to match the existing `-o json`
  output, deliberately (U159).

### Per-pod mount audit

Two observers; the server holds the durable record.

1. **The durable line: `pkg/keystore/mountaudit`**, its own package beside `reconcile`, with its
   own informer, RBAC (list and watch pods, cluster-wide) and failure policy.
   - **Level-based.** It keeps a mounted set keyed by (pod UID, Secret, version), fed by a shared
     pod informer and a Secret lister filtered on `k3sm.io/keystore-delivery`, and reconciles the
     set against the cache. It acts on state, not edges, so a relist emits nothing.
   - **On startup** it computes the set from the cache, writes **one** baseline summary line
     (`op: pod-mount-baseline`, a count per namespace), and emits per-pod lines only for later
     changes (U169).
   - Lines, with `via: mountaudit`: `op: pod-mount` when a pod referencing a labelled Secret first
     has a started container on a node; `op: pod-refresh` when the Secret's version annotation
     moves, **only for a `secret` volume or projected `secret` source mounted without `subPath`**;
     `op: pod-unmount` on deletion, including `DeleteFinalStateUnknown` tombstones, and when a pod
     reaches `Succeeded` or `Failed`.
   - **Refs that never refresh are named as such.** An `env.valueFrom.secretKeyRef`,
     `envFrom.secretRef` or `subPath` reference gets its `pod-mount` line with `refreshes: false`,
     and never a `pod-refresh` line (U170). The docs say a `pod-refresh` line means "a new version
     was available to a refreshing mount", not "the pod read it".
   - **Fields, a closed set:** `namespace`, `pod`, `podUID`, `node`, `secret`, `delivery` (the
     KeyDelivery UID from the Secret's `k3sm.io/keystore-delivery-uid` annotation, or `file` for a
     root-file target), `entry`, `version`, `ref` (`volume`, `projected`, `env` or `envFrom`),
     `subPath` (bool), `refreshes` (bool), `keys` (the data keys referenced, or `*`) (U171).
   - It covers root-file deliveries too, by label. It runs on the server only, so old workers need
     nothing (E18 still holds).
2. **The node's trace: the provider.** An injected `MountObserver` seam is called by the
   **caller** of `kubeResolver.Secret()` (at create and in `refreshProjectedOnce`), outside the
   byte-handling closure.
   - It reads the Secret's label and version annotation from the provider's Secret **lister**,
     never from the data bytes. `mount.SourceData` and the runtimed seam do not change.
   - For a labelled Secret it records a Normal Event `KeystoreSecretMounted` on the Pod, once per
     pod per delivered version, naming the Secret and the version, and logs one Info line on its
     node with the same fields.
   - Dedupe state is bounded and lives on the pod's track, so it ends with the pod. After a
     provider restart the observer re-derives each running pod's last-seen version from the lister
     and the pod's start, so it does not re-emit (U173).
   - It is not audit-grade: Events are writable by namespace editors and age out. The docs say so,
     and say it must not feed automated decisions.

- **Built from metadata only.** Every mount line, Event and log line is assembled from object
  metadata. Never in one: a value, a value length, a fingerprint, the pod's env, args, image,
  annotations or ServiceAccount token, or the entry's owner uid. The Pod Event also omits
  `entry`. A planted-token test covers the resolver's error path (U171, U173).
- **Pod churn cannot fill the log, and cannot hide a first read.**
  - A first-seen (pod UID, Secret) pair is **never** dropped by a rate limit. Only repeats
    (`pod-refresh`, and a re-mount of an already-seen pair) are limited: 30 a minute per namespace
    and 120 a minute across all namespaces, with one dropped-count summary line per window.
  - Mount lines are observations, not gates, and are a server class, charged to no uid ("The
    audit-log budget").
  - They **stop at the log's soft cap**, first-seen lines included, with one summary line, a
    `doctor` row and a server Warn, so they never push the log to the hard cap and never turn on
    `ErrLogFull` for real operations. The soft-cap stop is the only thing that drops a first-seen
    line; the 80% Warn fires before it (U172, U174).
  - A failed append is logged and never fails anything.

### SSH keys

- **Stored format:** the 32-byte ed25519 seed and an optional comment, in the kind-4 envelope.
  **ed25519 only** in this release.
- **k3sm both generates and stores.** `k3sm keys generate user/<uid>/<service>.<account> --kind ssh
  [--comment C]`, a socket `generate` op (and a root verb for `system/`), mints from the store's
  random seam inside the server and returns only the public key line and its OpenSSH fingerprint.
  The private half leaves the store only by projection to a Secret (U148, U157).
- `k3sm keys pubkey <entry>` prints the public line at any time. A public key is not a value; U37's
  "no non-root verb writes a value to stdout" is amended to say so.
- Import is `put --kind ssh --in -` of an **unencrypted OpenSSH ed25519** private key. An encrypted
  key, RSA, ECDSA or an SSH certificate is refused with `invalid-value`, because there is no
  passphrase path.
- **Library.** OpenSSH key parsing and marshalling use `golang.org/x/crypto/ssh`
  (`ParseRawPrivateKey`, `MarshalPrivateKey`, `MarshalAuthorizedKey`, `FingerprintSHA256`) in
  `pkg/keystore/typed`. `golang.org/x/crypto` is already a direct dependency of k3sm. It parses
  untrusted input, which stays on the maintained library.
- **Tests do not compare the library with itself.** `TestSSHFingerprintMatchesOpenSSH` checks
  against a committed `ssh-keygen -l -E sha256` output for a committed key (U148).

### Refresh owners and the refresher

- Every `oauth` record names exactly one refresh owner in its sealed envelope, in the grammar
  `credential.RefreshOwnerPattern` (`^(local|server/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)$`, at most
  `credential.MaxRefreshOwnerLength`, 70 bytes), parsed by `credential.ParseRefreshOwner`:
  - **`server/<profile>`**: the k3sm server refreshes, using the refresh profile `<profile>` (a
    DNS-1123 label) that root declared. The server is then the only writer of refreshes for that
    pair.
  - **`local`**: a process outside k3sm (an app, a LaunchAgent running as the owner's uid)
    refreshes and writes each new pair through the socket's `rotate`. The server never refreshes
    a `local` pair, and still computes `CredentialValid` from the stored expiry.
- **Who holds the refresh token:** only the keystore, sealed under the owner's scope key. Only the
  refresher reads it, through the opener, in the server process, as the service user. It never
  reaches the socket, a Secret, `exec`, `show`, a log, an Event or an audit line.
- **A pod is never a refresh owner in this release.** Pods cannot reach the socket, and a
  pod-reachable write endpoint is deferred.
- **No exec hooks.** The only refresh procedure built in is RFC 6749 §6, the `refresh_token`
  grant. A "hook" is a declared profile (data), never a program.
- **The store interface.** The refresher is not a socket peer. Its consumer interface,
  `OAuthRefreshStore`, has the opener for a `server/`-owned pair's current version and
  `RotateIf(name, expectVersion, value)`, a compare-and-swap Rotate, with bytes taken only from a
  token-endpoint response. It has no reveal, show, list or rewrap method (U150).
- **A re-login by the owner always wins.** If the owner rotates a new pair while a refresh is in
  flight, `RotateIf` fails on the version check and the refresher's result is discarded (U185).
- **`refresh-now`.** `k3sm keys refresh <entry>`, socket op `refresh-now`, is owner-only, 1 a minute
  per entry, and answers `refresh-not-owned` for a `local` pair. On a parked pair it sends no
  request and replies with state `revoked` (U189).
- **How a pair arrives.** A client pipes the token endpoint's **RFC 6749 §5.1 JSON response** on
  stdin: `k3sm keys put user/<uid>/<svc>.<acct> --kind oauth --refresh-owner server/<profile> --in -`.
  One server-side parser (fuzzed, at most 64 KiB) takes `access_token`, `token_type`,
  `expires_in` or `expires_at`, `refresh_token` and `refresh_token_expires_in`, stamps
  `accessIssuedAt` and the absolute expiries from the clock seam at receipt, and drops every other
  field (`id_token` and `scope` included). A response carrying an `error` field is refused with
  `invalid-value`, and the CLI prints only the RFC 6749 `error` code, never the description or any
  token. `put` checks the named profile exists (`refresh-profile-unknown`) (U156).
- **Schedule.**
  - Refresh at 50% of `accessExpiresAt − accessIssuedAt`, with ±10% jitter and a lead of at least
    5 minutes before expiry; due pairs are taken nearest-expiry first.
  - At most one refresh per entry per 10 minutes. Globally 4 concurrent refreshes and 60 a minute
    per profile.
  - **Fairness, per uid on a profile:** at most 10 refreshes a minute and 8 `server/`-owned pairs
    per uid on one profile (a ninth `put` is `quota`); at most 32 `server/`-owned pairs per user
    scope (`quota`).
  - Transient failures back off from 30 seconds to 15 minutes. **A pair keeps retrying at the
    15-minute maximum after its access token expires**, and is never abandoned while its refresh
    token may still be valid (before `refreshExpiresAt`, or always when that is unknown). Only a
    revoked-code answer parks it (U182).
- **Lock order.** The per-entry lease (in process), then the store's `.lock` taken shared, then
  the store's own write path; never `.lock` before the lease. No refresh starts while the
  `keystore-maintenance` marker exists or a maintenance verb holds or waits for `.lock`
  exclusively: the shared acquisition is a non-blocking try, and a refusal reschedules the pair at
  +30 s without growing its backoff. A started refresh holds `.lock` shared from opening version V
  through its audit line, at most the 30 s client timeout plus the write, so a maintenance verb
  waits for in-flight refreshes instead of racing them; if the bounded lock wait is shorter than
  35 s, the maintenance verb answers busy rather than proceeding (U188).
- **The success path, in order:**
  1. Take the lease; check the server count and the maintenance marker; take `.lock` shared.
  2. Open current version V through the opener.
  3. POST the grant.
  4. On success, `RotateIf(V)` with the new access token, its `accessIssuedAt` and expiry. Keep the
     old refresh token when the response omits one (RFC 6749 allows that); store the new one when
     it rotates.
  5. Write the floor line, then fold the success into the entry's daily `refresh-ok-summary` line.
  6. Prune to two versions.
  7. The reconciler re-delivers within one sweep and the provider re-renders the volume within
     about a minute, so no pod restarts (U183).
- **How failure surfaces.**
  - An error code in the profile's `revokedErrorCodes` gives `Revoked`, an audit line
    `result: revoked`, and the pair **parked**: no retry until its version changes. Unparking by a
    new `put` or `rotate` is limited to once per entry per 10 minutes.
  - Every other failure gives `RefreshFailing` with a closed cause, retried with backoff, and
    `Expired` once the access token lapses.
  - **Park and failure state persists** in `keystore-run/refresh-state.json`, the service user's,
    mode 0600, atomically replaced: per entry name the state, the cause, the park version and
    `last_refresh_at`. Names and states only, never a secret. Losing it costs one retry per parked
    pair, which re-learns the same answer (U184).
- **Shutdown.** On SIGTERM (`launchctl kickstart -k`, reboot, uninstall) the refresher stops
  starting refreshes, cancels any not yet sent, and waits up to 10 s for in-flight ones to commit.
  launchd's default 20 s `ExitTimeOut` covers it, and a test holds that the shipped plist does not
  lower it. A SIGKILL or power loss mid-refresh is a residual ("Threats").
- **Single server only.** The server count is checked before each refresh and on a watch of server
  registrations. With more than one server registered, the refresher starts nothing, system-scope
  pairs included, and pairs show `RefreshFailing` (`multi-server`); `doctor` shows it once at
  cluster level. When the count is back to one, the refresher resumes on its own (U187).

### Refresh profiles and the HTTP client

- **Root declares profiles**: `sudo k3sm keys refresh-profile add <name> --token-url https://…
  --client-id ID [--client-secret-entry system/<name>] [--auth-style header|params]
  [--revoked-error-codes c1,c2] [--allow-private]`, plus `rm`, `list` and `test`.
- **URL validation at `add`:** `https` only; no userinfo; no fragment; no IP-literal host unless
  `--allow-private` (U176).
- **The file** is `/var/lib/k3sm/keystore-refresh-profiles.json`, **`0640 root:_k3sm`**,
  atomically replaced. Format:
  `{"version":1,"profiles":{"<name>":{"tokenURL","clientID","clientSecretEntry","authStyle","revokedErrorCodes","allowPrivate"}}}`,
  parsed strictly like the floor (an unknown field, non-canonical bytes or more than 1 MiB is a
  refusal). `revokedErrorCodes` defaults to `["invalid_grant"]`.
- It is read on the opened descriptor through **the floor's owner-check helper and its stat seam**
  (owner root, group `_k3sm`, no other-read, no write but root), so the rows need no root. It is
  re-read on fsnotify plus a sweep (U175).
- **A profile changed or removed mid-flight:** in-flight grants finish against the old values;
  pairs naming a removed profile get `RefreshFailing` (`profile-unavailable`) and keep retrying at
  the maximum backoff, in case it returns.
- **Why root.** A profile decides where refresh tokens are sent and makes the control-plane process
  dial out, the same reason `keystore-delivery.json` is root's. Any user may *reference* any
  profile: it holds no user secret, and a user's refresh token reaches only the endpoint root
  chose.
- Pods are denied the file by the `keystore-*` prefix deny ("Pod denies"; E35), which is a hard
  dependency of every change that writes a new `keystore-*` file or anything under
  `keystore-run/`.
- **A confidential client's secret** is a `system/` entry. Only the server refresher reads it, to
  authenticate to the profile's endpoint. That is not a grant ("No system grants"): no non-root
  principal reads, delivers or execs it. `--client-secret-entry` is refused unless the entry exists
  and is `opaque` or `token`.
- **Generic error mapping.** A profile declares the error codes that mean "revoked". The client
  also treats an HTTP 200 whose body carries an `error` field as an error. No service is named in
  code. Recorded real response shapes (success, revoked, bad client, 200-with-error) are golden
  fixtures under `pkg/keystore/refresh/testdata/` (U179).
- **The HTTP client.**
  - `golang.org/x/oauth2` performs the grant (`Config.TokenSource(…).Token()`,
    `RetrieveError.ErrorCode`). It is already in `hack/deps.lock` as an indirect module; making it
    direct changes `go.mod` but not the lock graph, and that one diff is the only `go.mod` change
    the typed credentials make. A `RetrieveError` is converted to a closed cause at the call site
    and never formatted, because its `Error()` embeds the body.
  - k3sm's own `http.Client`: `https` only; **`Transport.Proxy = nil`** (an HTTP proxy is
    unsupported in this release, and the docs say so); no redirects (`CheckRedirect` returns
    `ErrUseLastResponse`, so a 3xx is `response-invalid`); system trust roots, no per-profile CA
    (a profile CA would be a new trust root); a 30 s timeout; responses capped at 64 KiB and never
    logged (U177).
  - **The dial guard** runs in `net.Dialer.Control`, on the resolved address, so DNS rebinding
    cannot get round it. Denied: loopback, unspecified, link-local (including 169.254.169.254),
    multicast, RFC 1918, CGNAT 100.64.0.0/10 (the mesh), ULA fc00::/7, IPv4-mapped IPv6, and NAT64
    (64:ff9b::/96, 64:ff9b:1::/48). A profile's root-only `--allow-private` lifts the RFC 1918,
    CGNAT and ULA entries for that profile only; loopback, unspecified, link-local and multicast
    stay denied for every profile (U178, E36).
  - **Causes** distinguish `dns` (resolution failed), `tls`, `clock-skew` (a certificate outside
    its validity window by the server's clock), `dial-refused` (the guard), `network` and the rest.
- **Seams, and where they are tested.** Three seams, a `RoundTripper` factory, a resolver and the
  `Dialer.Control` function, plus the clock. The guard is tested by calling the Control function
  with synthetic addresses, including a fake resolver that rebinds to 169.254.169.254; the
  redirect, cap, 200-with-error and timeout tests use a fake `RoundTripper`, so no test-only trust
  root or dial path exists in the shipped client. `testing/synctest` is used only with an
  in-bubble fake `RoundTripper`. The seam guard (`TestRealPrimitivesUnreachable`) lands with the
  seams, and `pkg/keystore/refresh` and `pkg/keystore/mountaudit` join U58's closed seam-package
  list (U180). The refresher adds its jitter and schedule-clock seams to the same guard.
- **`sudo k3sm keys refresh-profile test <name>`** probes a profile from the root CLI with the same
  client package. It sends a freshly generated random refresh token, so no user's refresh token is
  sent (the client secret goes only to the endpoint it already belongs to), and expects an error
  code in the profile's `revokedErrorCodes`. It prints `ok` with the latency, or the closed cause,
  and exits non-zero on anything else (U181).

### Wire protocol additions

`k3sm-keys/1` stays version 1, since none of it has shipped.

- `put` and `rotate` headers gain `kind` (`opaque`, `ed25519`, `token`, `ssh`, `oauth`),
  `expires_at` (token, RFC 3339), `format: token-response` (oauth) and `refresh_owner`.
- New ops `generate`, `pubkey` and `refresh-now`.
- `read-for-exec` gains `field` (default per kind: token `value`, oauth `accessToken`; ssh needs an
  explicit field). `refreshToken` is not a field (U158).
- `deliver` gains `items`. `list` and `deliveries` replies gain the metadata above.
- **Must-understand headers.** The HELLO reply carries a capability list (`typed`, `items`,
  `generate`, `refresh-now`). The mutating ops `put`, `rotate`, `deliver`, `read-for-exec` and
  `generate` refuse any header they do not know with the new error `unknown-header`; non-mutating
  ops stay tolerant. This amends U27 ("an unknown header field is ignored" now holds for
  non-mutating ops only). The CLI checks HELLO's capabilities before it sends a typed header, and
  against a daemon without them refuses locally ("the server is older than this CLI; restart
  it"), which closes the upgrade window between the symlink flip and the server's restart (U155).
- New error codes: `kind-unsupported`, `kind-mismatch`, `invalid-value`, `projection-invalid`,
  `refresh-profile-unknown`, `refresh-not-owned`, `unknown-header`.
- New audit `op` values: `generate`, `refresh`, `refresh-ok-summary`, `refresh-now`, `pod-mount`,
  `pod-mount-baseline`, `pod-refresh`, `pod-unmount`, `profile-add`, `profile-rm`. `via` gains
  `refresher` and `mountaudit`, and `via` is an open set ("The audit log": readers ignore unknown
  values).

### Public names live in `apis`

The stdlib-only leaf `k3sm.io/apis/keystore/credential`, beside `apis/keystore/entry`, holds every
name a consumer matches on, with vector tests (U141):

- the kind names, `Kind` (`ed25519`, `opaque`, `token`, `ssh`, `oauth`; `Kinds()`);
- the projection field table (`Field`, `FieldsFor`, `Fields`, `MaxFieldLength`,
  `RefreshTokenField`) and the `Item` type `{field, key}`, which the CRD's Go type embeds and the
  root-file JSON reuses;
- the refresh-owner grammar and its vectors (`RefreshOwnerPattern`, `ParseRefreshOwner`,
  `MaxRefreshOwnerLength`);
- `ConditionCredentialValid` and its reasons, the `Validity` type (`Validities()`); the Event
  reasons and types (`EventReasons()`, `KeystoreSecretMounted` included);
- the `refresh_state` values (`RefreshStates()`);
- the metadata keys a reader matches on, so the provider never imports `pkg/keystore`:
  `LabelDelivery` (`k3sm.io/keystore-delivery`), `LabelValueKeyDelivery` (`keydelivery`, its value
  on a Secret a KeyDelivery wrote), `AnnotationVersion` (`k3sm.io/keystore-version`),
  `AnnotationEntry` (`k3sm.io/keystore-entry`, the entry a KeyDelivery's Secret delivers) and
  `FinalizerDelivery` (`keystore.k3sm.io/delivery`).

`k3sm.io/apis/keystore/v1alpha1` holds the `KeyDelivery` type (`spec.items` of `credential.Item`),
the condition names `ConditionAuthorized`, `ConditionReady`, `ConditionSecretRetained` and
`ConditionCredentialValid`, the `Reason*` constants, and `ConditionReasons()`, the closed reason set
per condition, which the CRD description lists (U142).

**The Secret's metadata, reconciled.** A Secret a KeyDelivery wrote carries the label
`k3sm.io/keystore-delivery: keydelivery`, the version annotation `k3sm.io/keystore-version` and the
entry annotation `k3sm.io/keystore-entry`: the public names above. It also carries two annotations
only the reconciler, `rm-scope` and the mount audit read, declared in `pkg/keystore/reconcile`
rather than `apis` because no outside reader matches on them:
`k3sm.io/keystore-delivery-uid`, the **owner annotation** holding the KeyDelivery's
`metadata.uid`, and `k3sm.io/keystore-digest`, the content digest that `Ready=Delivered` checks
("KeyDelivery", Writes). Wherever this document says "the owner annotation" it means
`k3sm.io/keystore-delivery-uid` together with `k3sm.io/keystore-entry`. The root-file delivery's
Secrets keep their own shape: the label's value is the entry name, with the version and
`k3sm.io/keystore-fingerprint` annotations.

Rendering stays in k3sm (`pkg/keystore/typed`). The conformance test iterates the `apis` table
and checks `typed.Project` supports exactly those fields per kind (U160), so the two cannot drift.

### The audit-log budget

- **Refresher lines are a server class**: charged to no uid's share (U51), counted against the
  log's soft and hard caps only.
- **Success is compacted**: one `refresh-ok-summary` line per entry per UTC day (the count and the
  first and last success times). The refresher keeps the day's count in `refresh-state.json` and
  appends the line when the UTC day rolls, or at shutdown. Every failure, park, unpark,
  `refresh-now` and state change is its own line.
- **Mount lines** are the same server class.
- **The arithmetic** (defaults: soft cap 64 MiB, hard cap 256 MiB, per-uid share at most 1/16 of
  the hard cap, 16 MiB; a refresher line is at most 512 bytes, U183):
  - The 10-minute per-entry interval bounds a pair to 144 refreshes a day. Uncompacted, 32 pairs
    would write 32 × 144 × 512 B ≈ 2.25 MiB a day and reach the soft cap in about 28 days.
  - Compacted, 32 pairs write 32 summary lines a day whatever the lifetime: about 5.7 MiB a year.
    One user at the full 32-pair quota takes more than 11 years to reach the soft cap alone;
    eight such users still take more than a year.
  - Failures are bounded by the backoff: a pair failing without pause writes at most about 100
    lines a day at the 15-minute maximum, so one user's 32 pairs all failing write about 1.6 MiB a
    day, and the 80% Warn fires after about four weeks of total outage for that user, well before
    the soft cap.
- **A `doctor` row and a server Warn fire at 80% of the soft cap**, with the rotate hint, beside
  the existing soft-cap row (U24, U174).

### Observability

- **`doctor` rows** (U190): the refresher on or off, with the reason (`multi-server`, `no
  profiles`, `maintenance`); profiles loaded, and parse errors by name; `server/` pairs failing and
  revoked, by count; the last outbound success per profile; the audit log against its soft cap.
- **Logs at Warn or Error** for every refresher state change (on or off, park, unpark, failing,
  recovered, a profile-file reload failure), under the os_log subsystem `io.k3sm.keystore`. Lines
  carry names and closed causes only, never a body.
- **`k3sm keys refresh-profile test <name>`** is the pre-deploy probe for egress, TLS and the
  profile's error shape.

### Rig credentials and custody

The rig legs E28 to E36 prove the typed credentials against a real forge (GitHub) through public
surfaces only.

- **No GitHub App private key is ever used or stored**, and no installation token is minted. The
  gate never holds a credential: it registers public halves, starts flows and pipes responses into
  `k3sm keys put`.
- **The test repository** is a private repository the operator owns, with Actions disabled at
  creation.
- **Push** uses an SSH deploy key k3sm generates in the server (`k3sm keys generate --kind ssh`);
  the gate registers only its public half, one key per run.
- **The pull request** uses a GitHub App **user access token**: an `oauth` pair owned by
  `server/github-e2e`, obtained once through GitHub's device flow, which needs only the App's
  `client_id`. The operator approves the code in the browser, attended, once; the gate pipes the
  token response straight into `k3sm keys put --kind oauth --in -` and never echoes or stores it.
- **The client secret** is `system/github-app.e2e`, put once by the operator with sudo. Only the
  server refresher reads it.
- **Lifetime.** The refresh token lives about 6 months, so later runs are unattended while the pair
  survives on the server node. If it is lost, E28 and E32 report **PENDING** (exit 3), never FAIL
  and never green, and the operator repeats the device flow.
- **Host key.** `known_hosts` is built from GitHub's published SSH keys (`gh api meta`), and ssh
  runs with `StrictHostKeyChecking=yes`. git, ssh and curl come from a pinned pod image, by digest.
- **Cleanup.** Every object carries a run-id label or name. A trap removes them on any exit, and a
  start-of-run sweep removes earlier runs' deploy keys, branches, pull requests, labelled
  namespaces and per-run deploy-key entries. The long-lived oauth pair is kept.
- **Failures.** GitHub outages, 5xx, 429 and secondary rate limits are PENDING (infrastructure),
  checked by a rate-limit preflight and bounded deadlines on every poll; there are no fixed
  sleeps.
- **Evidence scans have positive controls.** Each negative scan first proves it can find a needle:
  the scanner reads the needle into a variable that is never printed or written and prints only
  match counts. For the planted pair (E31, E33) the planted access token must be found
  base64-encoded in the Secret before the scan for the planted refresh token counts. The real
  refresh token is unknown to everyone, so it is never a needle.
- **The scheduled refresh path** is shown by a unit row on a fake `RoundTripper` (U182). The rig proves
  `refresh-now` rotation (E32) and revocation (E33). The real grant is never revoked.

**The tracer (E28)**, per run, unattended once seeded: preflight and sweep (the oauth pair shows
`refresh_state ok`, else PENDING); generate a per-run deploy key and register its public half;
deliver it with `--item privateKey=id_ed25519 --item publicKey=id_ed25519.pub` and the oauth pair
with the CLI defaults into a per-run namespace, expecting `Ready=True Delivered` on both and
`CredentialValid=True Valid` on the oauth one, with an in-leg negative control (`--item value=x`
on the oauth entry gives `Ready=False ProjectionInvalid`); one pod mounts both as volumes (no
`subPath`, `defaultMode: 0400`), pushes a branch over ssh and opens a pull request with the
access token read from its file, never from argv; `k3sm keys refresh` then rotates the pair and a
bounded poll sees the pod's access-token hash change with `restartCount` 0 (E32); the evidence is
the audit log's `generate`, `deliver`, `deliver-write`, `refresh-now`, refresher, `pod-mount` and
`pod-refresh` lines, the Pod's `KeystoreSecretMounted` Events, and positive-controlled scans that
find neither the access token nor the deploy private key anywhere they should not be. Without
projection the oauth delivery sets `ProjectionInvalid`; without the mount audit there is no
`pod-mount` line; without the refresher the hash never changes.

### Threats, and what this does not do

**New residuals**, added to `limitations.md`:

- **Rotation loss.** A SIGKILL or power loss after the token endpoint rotates a refresh token and
  before `RotateIf` commits loses the new token. The next refresh gets a revoked code, the pair
  shows `Revoked`, and the owner signs in again. The SIGTERM drain covers ordinary restarts; no
  write-ahead is possible for the rest.
- A pod holding an access token holds it until it expires. Access-only narrows the exposure from
  the refresh lifetime to the access lifetime; it does not remove it. An SSH key or a `token` in a
  Secret is long-lived: revocation means rotating and unregistering it at the provider. Every
  process in every native pod runs as the service uid, so `defaultMode` protects nothing between
  pods, and rendered files stay on the pod's data volume until the pod is reaped.
- The server dials the token endpoints root declared. A compromised endpoint receives refresh
  tokens for the pairs that name it. TLS uses the system roots; there is no proxy support.
- Conditions use the server's clock. A skewed clock gives a false `Expiring` or `Expired`, which
  never deletes anything, or a `clock-skew` TLS failure.
- The Pod `KeystoreSecretMounted` Event and the node log are not audit-grade: a namespace editor
  can forge or delete the Event. The server's line is the record, and it is an observation, not
  proof of the bytes read. `env`, `envFrom` and `subPath` consumers keep the old value until
  restarted.
- A profile's `system/` client secret is used by the server on users' behalf. Users never receive
  it.
- `keystore-refresh-profiles.json` is readable by root and the `_k3sm` group (the service user,
  which every native pod process shares; pods are kept out only by the prefix deny). It reveals
  each profile's name, token URL, client ID, client-secret entry name, auth style, revoked error
  codes and `allowPrivate` flag. It holds no secret.

**Defended:** no refresh token in any Secret, verb, Event, log or audit line, by type and by
schema (U140, U149, U160, E31); SSRF by users, since profiles are root's and the post-DNS guard
denies private, mesh, metadata and translated ranges with no ambient proxy (U177, U178, E36);
parser abuse, by fuzzed, size-capped envelope, token-response and profile parsers (U143, U156,
U175, U154); log exhaustion by refreshes or pod churn (U172, U174, U183); a suppressed first read
(U172); a double refresh across servers, including a server joining mid-run (U187); an unsupported
kind deleting Secrets (U164); a silent downgrade across version skew (U155).

**What this does not do:** sign-in flows in k3sm (a client signs in and pipes the response); token
revocation at the provider (RFC 7009), or revoking a real grant in tests; GitHub App private keys
or installation tokens; exec or plugin refresh hooks; a per-profile CA or HTTP proxies; RSA, ECDSA
or certificate SSH keys, or an ssh-agent; templated outputs such as `.git-credentials`; a
pod-reachable refresh endpoint; multi-server refresh; isolation between pods; `status -o json`
fields; anything that names a service in code.

### One-way doors

| door | choice |
|---|---|
| kind bytes | 3 token, 4 ssh, 5 oauth; 6 to 0xFC unassigned; no format bump; kind fixed per entry |
| envelope v1 | version byte; TLV; tags 0x10–0x12, 0x20–0x22, 0x30–0x36; sealed `issuedAt`/`accessIssuedAt`; field bounds |
| pointer low-water mark | a 24-byte pointer `{version, sequence, low}` after a prune; 16 bytes means `low = 1`; committed range `low..current` |
| refresh-owner grammar | `local` or `server/<profile>` |
| write-only refresh token | `typed.Credential` has no refresh field; one opener, one importer |
| CRD | `spec.items[{field,key}]`, required, no default, `field` enum, key pattern with the `.` and `..` refusal, immutable as a map, `listType=map`; no `dataKey`; `observedGeneration` on every condition |
| public names | `k3sm.io/apis/keystore/credential`: kinds, fields, item type, validities, Event reasons and types, `refresh_state`, metadata keys |
| condition and reasons | `CredentialValid`: `Valid`, `Expiring`, `RefreshFailing` (all True), `Expired`, `Revoked`, `Indeterminate`; `ProjectionInvalid`; `Ready` means delivered |
| target digest | binds `entry`, `namespace`, `secretName` and canonical, key-sorted `items` |
| root files | `keystore-delivery.json` `items`; `keystore-refresh-profiles.json` v1, `0640 root:_k3sm` |
| wire additions | ops `generate`, `pubkey`, `refresh-now`; HELLO capabilities; must-understand headers on mutating ops; seven error codes |
| `list -o json` | `kind`, `expires_at`, `access_expires_at`, `refresh_expires_at`, `refresh_owner`, `refresh_state`, `last_refresh_at`; snake_case, like the existing keys |
| audit | new `op` values; `via: refresher`, `via: mountaudit`; `via` open; the server class; the mount-line fields |
| CLI | `--kind token\|ssh\|oauth`, `--expires-at`, `--refresh-owner`, `--item`, `generate`, `pubkey`, `refresh`, `refresh-profile add\|rm\|list\|test`, `--allow-private`, `--revoked-error-codes` |

### Deployment

One binary and one deploy, with no flag and no phased rollout. No proto, no kine encoding and no provider-to-runtimed contract changes
(`mount.SourceData` is unchanged). The CRD drops `spec.dataKey` only from an untagged shape: no
`apis` tag has carried a KeyDelivery type before `items`, so there is no published field, no
stored object and no consumer that could go first. The socket protocol is internal and unshipped;
the HELLO capability check closes the upgrade window. A dev build without typed kinds shows typed
entries as `corrupt`, and its reconciler leaves their Secrets alone.

Pre-deploy: `sudo k3sm keys refresh-profile add`, then `refresh-profile test`, before any
`server/` pair is put; the server needs direct outbound HTTPS to profile endpoints (no proxy).
Rollback is revert, rebuild, reinstall; rolling back past typed kinds or the refresher means
owners sign in again for their `server/` pairs after rolling forward ("Unknown kinds, ownership
and rollback").

### Gate mechanics

- **Every U row here is a hermetic, unit-tier Go test run by `--check`** (fake seams, no network,
  no privilege). Root-file checks reuse the floor's owner-check helper and stat seam, so no row
  needs root.
- **Row ids** continue after U137 and E27: U138 to U191, and the rig legs E28 to E36. `--listed`
  refuses a duplicated U or E id, in the script's rows, its expected-row list, one mode's row list
  or the design's tables (U138).
- New gate modes, each in `keystore.sh`'s `MODES`, usage and `mode_rows`: `--credential` (U18, U19,
  U139 to U142), `--typed` (U143 to U154), `--typed-cli` (U155 to U159), `--projection` (U160 to
  U164), `--expiry` (U165 to U168), `--mount-audit` (U169 to U174), `--refresh-profiles` (U175 to
  U181), `--refresh` (U182 to U190) and `--typed-docs` (U191). Each leg maps to one mode (the last
  feature to land), or to plain `--lab`.
- **Fuzz targets** (`FuzzEnvelopeParse`, `FuzzTokenResponseParse`, `FuzzProfileFile`) each assert
  that an accepted input re-encodes identically (for the token response, re-parses to the same
  stored fields) and that an error never contains input bytes; a lint keeps each
  `testdata/fuzz/<Name>/` non-empty (U154).

## Non-goals

Beyond Phases B and C: isolating one native Pod's delivered Secret from another; protecting
key material from root on the host; a KMS- or HSM-backed master (the master is a file,
protected the same way the existing `secretbox` key is — a hardware-backed master is a
later proposal, as issue 731 already notes for the existing key); a network service or new
IPC surface; bounded version retention or a point-in-time rollback verb in Phase A;
changes to `k3sm install`; importing existing Secrets. These are Phase A's non-goals. The
user scope adds a local unix socket and changes `k3sm install`, and lists its own exclusions
under "What the user scope does not do".

## Acceptance gate

The gate is `hack/acceptance/keystore.sh`, written with the implementation. This section is
its specification, so that what review approves here is what the gate checks. Each row is a
requirement from this document and the test that must exist for it; the gate runs them and
fails if any row has no test or any test fails.

The implementation lands as a series of pull requests in dependency order, each one
checkable on its own: the core store (G2 to G4, G10, G11, G14, G15 and the library half of
G16), then Rotate with the pointer sequence and floor (G5 to G9), then Rewrap (G12, G13),
then the `k3sm keys` verbs (the CLI half of G16, G17, G21), then delivery (G18 to G20). The
first pull request adds the gate script with every row listed; a row whose pull request has
not landed is reported as pending, not passed. Each pull request cites a test name for the
rows it delivers, and G1 and G22 are checked on every one. Phase A is complete when the
last pull request lands and no row is pending.

| # | Requirement | Validated by |
|---|---|---|
| G1 | Standard library only: `go.mod` and `go.sum` unchanged by the implementation | the gate diffs both against the base |
| G2 | The AAD is length-prefixed and covers format, scope, kind, name, version, generation; a record moved to another scope, name, version or generation fails to open | unit: swap each field, expect `ErrCorrupt` |
| G3 | Every seal draws a fresh 96-bit nonce, including Rewrap | unit: two seals of one plaintext differ; Rewrap changes every nonce |
| G4 | Delete then Put of the same name does not reopen the old `v1` | unit: replay the old file onto the new entry, expect `ErrCorrupt` |
| G5 | A previously valid `current` copied back over the current one is refused, with a message that names the floor and does not tell the operator to restore from backup; a floor file with no entry for the name, or no floor file, accepts an authenticating pointer | unit: Rotate, restore the earlier `current`, expect `ErrCorrupt` whose text names the floor and omits "restore it from backup"; one case each for the missing entry and the missing file |
| G6 | The floor is root-owned and checked on the opened descriptor; a floor that is group- or other-writable, a symlink, or not root-owned is refused. The floor file names the `system` scope and is parsed strictly, and a verb that cannot write it changes nothing | unit with a fake FS for each case; a missing, other or unknown-field scope; a fuzz target over the parser with committed seeds; a read-only data root on a first Put |
| G7 | The floor is raised by every mutating verb (Delete only when the master opens) and by the start of every root verb (`list` and `show` through `RaiseFloor`), and a floor one behind the pointer is accepted. Each floor write re-reads the floor under the data-root lock and applies only its own change, and a held data-root lock times out within the bound | unit: crash after the flip, before the floor write; a floor moved on during a Rotate or a Delete keeps its newer entries; a held data-root lock on a real `flock` |
| G8 | Rotate flips the pointer last; a crash at each of its steps leaves the old version current | unit: fault injection between each step |
| G9 | A Rotate retry discards an orphaned next version and seals the value it was given | unit: orphan with value A, retry with value B, expect B |
| G10 | The master is minted only by the first `put`, never over existing entries, and never by an operator-supplied value | unit: absent master with entries is `ErrMasterMissing`; no verb accepts an operator-made key: `rewrap --key-in` refuses a key that is neither the recorded `master.next.sha256` nor one some record already opens under |
| G11 | The master is opened with O_NOFOLLOW and judged by fstat on the open descriptor; wrong mode, owner or fingerprint is `ErrMasterUntrusted` | unit: one case each |
| G12 | Rewrap resumes after a crash at every step, trying the old then the new key, and leaves no record readable by neither; a `master.next` that disagrees with its fingerprint is discarded only when no `.new` file exists, and refused with `ErrMasterUntrusted` otherwise | unit: fault injection at each of steps 2 to 5, then rerun; a corrupted `master.next` with and without a `.new` file |
| G13 | A crash between the two master renames leaves a master that passes its trust check, and the next verb completes the swap | unit: stop after the first rename |
| G14 | One lock serializes Rewrap, Rotate, Put and reads, with a bounded wait | unit: a held lock gives a timeout error within the bound, not a hang |
| G15 | Files a root-run verb writes under `server/` are owned by the service user at the layout's modes | unit with a fake owner seam |
| G16 | `list` returns every entry, marks an unreadable one with `Err`, and exits 1. A directory holding nothing, `generation`, or `generation` and `v1`, with or without leftover `.tmp` files, is an incomplete Put unless the floor records its generation: not listed, `ErrNotFound` from `Current`, `Get` and `Delete` (Delete removes it too, and leaves the floor alone; with a live record for the name it buries that record and succeeds), discarded by the next Put. A directory with no `current` and any other file (`v1` without `generation` included), or in one of those shapes with its generation recorded in the floor, is damage: listed with `Err` wrapping `ErrCorrupt`, removed by `rm`, its floor entry replaced by a tombstone, and `ErrExists` from Put with every file left in place | unit: each incomplete-Put shape with no floor entry, an empty directory, a `generation`-and-`.tmp` directory standing in for a crash while writing `v1`, no floor file, a floor of another generation; damage: `v1` without `generation`, `v2` without `v1`, a `v1`-and-`v2` directory with `current` removed, and the one-version entry that lost `current` (`generation` and `v1`, or `current` renamed to a temporary name) with its generation in the floor; a retried `rm` after an interrupted one; a CLI exit-code test for `list` and `rm` |
| G17 | `show` prints a value only with `--reveal`, and then writes exactly the stored bytes with no trailing newline; no verb takes a value as an argument | CLI test over the usage strings; a `--reveal` test comparing stdout to the stored bytes for an opaque value and for 32- and 64-byte Ed25519 values |
| G18 | Delivery is refused while encryption is off unless the override flag was set at server start; a delivered target stays when the override is removed | unit over the reconciler with a fake client |
| G19 | The delivery declaration is root-owned and not shared-writable, and is refused otherwise | unit, the same cases as the manifest directory |
| G20 | The reconciler only Gets, creates and updates its labelled `Opaque` Secrets, and leaves an unlabelled or foreign Secret alone | unit over a fake client that records every call |
| G21 | The rollback recipe in this document runs as written and is a byte-exact round trip | a script test that pipes `show --reveal` into `rotate --in -`, then compares the new current version's value byte for byte (`cmp`) with version N's, for an opaque entry and an Ed25519 entry |
| G22 | `hack/ci.sh` passes | the gate runs it |
| G23 | A deleted entry's directory put back before a new Put of the name is refused by every reader and verb, never recorded in the floor, and removed by `rm`, which keeps the tombstone | unit: Delete, put the old directory back, expect `ErrCorrupt` from `Current`, `Get`, `List`, Rotate and Rewrap, `ErrExists` from Put, the floor unchanged by `RaiseFloor`; the same for a put-back directory with no `current`; a directory planted with a changed generation file and removed by `rm`, a delete, re-create, delete cycle, a decoy swapped in before `rm`, the entry's directory or `keystore/` hidden during `rm` and moved back, a symlink or an incomplete Put in its place, a Delete crashed before its floor write and run again, a crashed Delete followed by a Put and a Delete, a Delete faulted after its burial and before its removal (an error naming the directory left behind; a retried `rm` removes it with no floor change), a `uchg` flag on an entry file, the entry directory or `keystore/` (removed), a flagged file hard-linked into the entry from outside it (its flag kept, the entry left behind), `keystore/.lock` held past the bounded wait or replaced by a directory (the burial lands first; a retry once the lock is free removes the tree), and more planted names under `keystore/` than a read takes, each leaving the original copy refused |

Phase A is complete when the gate passes with no row pending. A row can be reworded or dropped only by a change
to this document, reviewed like any other.

### User-scope rows

The user scope adds the U rows below (unit tier unless the row says otherwise) and the rig legs
under "Rig legs". U138 to U191 and the legs E28 to E36 are the typed credentials' ("Typed credentials", "Gate
mechanics"); their ids continue after U137 and E27, and `--listed` refuses a duplicated id. U192 is the system floor's tombstone ("Pointer sequence and floor"), checked in `--check`
and in no unit mode. The gate runs each row's named tests in the repo the row names (`k3sm/…`,
`runtimed/…`, `apis/…`, package paths relative to the module), and fails a row whose named
test is absent or skipped. Each change runs the rows it delivers in its own gate mode, and the
rig rows as an explicit, recorded step. Every row below is pending until the change named in
its last column lands; a pending row fails its mode. A row whose change has landed says
`checked`, or `partial` with the part still pending. G1 holds for the Phase A changes; the user
scope's only module changes are k3sm's requirements on its own `apis` and `runtimed` modules,
each stated in the change that makes it. U15 is held for a K0 amendment, and U39 and U117 are unused.

**When the user scope is complete.** Every U row passes under `--check` with none pending,
and `--root` passes with no SKIP, every root-run row included; the gate checks both. Every U
row is also meant to be red first: each slice records, in its pull request's `## Gate`
section, its rows' tests run red on a build without the feature and then green. The gate
cannot check that record; it rests on the slice's author and reviewer. The rig legs are
integration, and their fails-without runs below are their own record; the red-first rule is
carried by the unit rows.

| # | Requirement | Validated by | Status |
|---|---|---|---|
| U1 | `rotate --from-version N` writes version N's bytes as a new version server side; no value leaves the store | `k3sm/cmd/k3sm::TestKeysRotateFromVersionNoValueOut` | pending: the `k3sm keys` verbs |
| U2 | AAD scope: a record moved between scopes fails to open, and two users derive different keys; a record opened as another user is refused | `k3sm/pkg/keystore::TestScopeBindsRecords`, `TestDerivedKeysDifferByScope` | partial: the first two checked (the core store's scope binding); pending: a record opened as another user is refused (the user-scope store) |
| U3 | KDF labels take the scope; `checkScope` accepts only `system` and `user/<decimal uid>`; kinds 0xFE and 0xFD are reserved | `k3sm/pkg/keystore::TestDerivedKeysDifferByScope`, `TestCheckScope`, `TestParseRecordRefusesMalformed` | checked: the core store's scope binding |
| U4 | the first-Put mint refuses with `.user` present and the master missing | `k3sm/pkg/keystore::TestMintCountsReservedUserName` | checked: the core store's scope binding |
| U5 | replaced by U12: Rewrap no longer refuses with `ErrScopeUnsupported` while `.user` exists; a `.user` that is a file or a symlink, which no user scope can be, refuses with `ErrCorrupt`, writing nothing | `k3sm/pkg/keystore::TestRewrapRefusesDamagedUserScopes` | checked: scope-key Rewrap |
| U6 | `scope.key` is sealed under `W`, bound to the GeneratedUID; a mismatch is `ErrScopeOwnerChanged` | `k3sm/pkg/keystore::TestScopeKeyGeneratedUIDMismatch` | checked: the user-scope store |
| U7 | the GeneratedUID lookup past its deadline, 250 ms everywhere, or in error fails closed; `mbr_uid_to_uuid` is in the symbol canary (seams: GeneratedUID lookup, clock) | `k3sm/pkg/keystore::TestGeneratedUIDLookupDeadlineFailsClosed`; `k3sm/internal/hostacl::TestMbrUIDToUUIDSymbolCanary` (integration) | checked: the user-scope store |
| U8 | a scope's records open only under its `K_u`; a copied `.user/<uid>/` without the master opens nothing | `k3sm/pkg/keystore::TestScopeCopyWithoutMasterOpensNothing` | checked: the user-scope store |
| U9 | per-scope fingerprints differ for equal values in two scopes | `k3sm/pkg/keystore::TestFingerprintsDifferAcrossScopes` | checked: the user-scope store |
| U10 | `user/<other>/…` is `ErrNotFound`, same text as an absent entry; a short name resolves to the uid and is printed | `k3sm/pkg/keystore::TestOtherUserIsNotFound`, `TestShortNameResolvesToUID` | checked: the user-scope store |
| U11 | the Go resolver takes the grammar from `apis/keystore/entry` and passes the shared entry-grammar vectors; `checkScope` refuses `user/0`; an all-digit second segment resolves as a uid even when an account of that name exists; `pkg/keystore` imports no Kubernetes package; Phase A's `checkName`, as a fourth consumer, gives every valid-scope vector's verdict on its name part | `k3sm/pkg/keystore::TestEntryGrammarVectorsResolver`, `TestEntryGrammarVectorsCheckName`, `TestCheckScopeRefusesUserZero`, `TestAllDigitSegmentIsAlwaysUID`, `TestKeystoreIsKubernetesFree` | checked: the user-scope store |
| U12 | master Rewrap re-wraps every `scope.key` and leaves user records byte-identical; resumable at every step | `k3sm/pkg/keystore::TestRewrapRewrapsScopeKeysResumable` (fault injection, as G12), `TestRewrapRefusesDamagedScopeTree`, `TestRewrapVerifiesScopeKeysBeforeSwap`, `TestRewrapRefusesStrayScopeDirs`, `TestRewrapPinsScopeKeyFromPlan` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U13 | quotas: the 257th entry and the byte budget answer `ErrQuota`; the 65th live delivery answers `ErrQuota` to `deliver`; `rm` and `withdraw` still work | `k3sm/pkg/keystore::TestUserScopeQuota`, `TestUserScopeQuotaCountsDeliveriesAndGeneration`, `TestDeliveryRecordQuota`, `TestRevocationIsUnconditional`, `TestWithdrawFloorFaults`, `TestWithdrawRefusesRollbackBelowSeen`, `TestWithdrawBelowReadableFloorRefused`, `TestDeleteOwnerChanged`, `TestRmLookupRefusalKinds`, `TestDeliveriesSeenIsProcessWide` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U14 | the delivery record stores UID, the full target tuple (`entry`, `namespace`, `secretName`, `items`, `requestedBy`) under its seal, and the target digest; add, look up and withdraw round-trip under the floor; the plaintext starts with the format version byte and the digest with the `k3sm-keystore-delivery-target/v1` label; the digest covers `entry`, `namespace`, `secretName` and the key-sorted `items`, and a reorder of `items` leaves it unchanged | `k3sm/pkg/keystore::TestDeliveryRecordDigestRoundTrip`, `TestDeliveryRecordVersionByteAndDigestLabel`, `TestDeliveryDigestCoversTargetAndItems`, `TestDeliveryFieldGrammarAtAdd`, `TestDeliveryFieldGrammarAtParse` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U15 | (reserved for the K0 amendment if leg 5 finds a second Pod-uid path) | none | pending: K0 amendment |
| U16 | every Pod profile variant (native, vm, container-vm, xcode, expose-paths, wasm (a native Pod whose process is the `k3sm-wasmhost` helper, `runtimed/pkg/wasmhost/doc.go:20`), the profile an exec-session process runs under (`runtimed/pkg/execsession/doc.go:17`), a custom Pod root distinct from the data root) denies every `keystore-*` name in the data root and the `keystore-sock/` tree; the keystore names are in `DataRootDenyTrees` and so in `protectedPrefixes`; `ReadOnlyPaths`, `ExposePaths` or a hostPath naming the data root or a keystore path is refused; an empty `Posture.DataRoot` still gets the denies under the work dir; a vm or container-vm guest gets no data-root share; over the whole rendered profile of every variant, including a Pod root equal to the data root and a Pod root that is a parent of it, no emitted allow matches any keystore path; the keystore stanza is the profile's last rule, written in the `/var`, `/private/var` and `/System/Volumes/Data` spellings, and the `keystore-` prefix deny is a regex rule in either letter case; a caller path naming a keystore path is refused with `ErrProtectedPath` and a pods root under a `keystore-*` name is refused; beside the read and connect cases, a file write, create, unlink and rename and a `network-bind` on `keystore-sock/`, on `keys.sock` and on every `keystore-*` name are each refused; every case also holds through `/System/Volumes/Data/private/var/lib/k3sm/...` and through the data volume's mount path | `runtimed/pkg/sandbox::TestDataRootDeniesKeystorePathsEveryProfile`, `TestShimProfileKeepsTheKeystoreDeniesLast`, `TestKeystoreDenyStanzaShape`, `TestDataRootRefusesPodRootUnderKeystoreName`, `TestValidateRefusesKeystoreExtraPaths`, `TestEmptyDataRootFailsClosed`, `TestDataRootRefusesWhatCannotHoldTheDeny`, `TestKeystoreDeniesUnderSandboxExec`; rig leg E10 | checked: runtimed's sandbox change |
| U17 | runtimed refuses a Pod identity it may not hold through `Credential.CheckPodIdentity` (`pkg/supervisor/privdrop.go`), not in `resolveCredential`: at `startContainer`, at `Exec` (an exec session), at the resident shim's `dropShim` and in `RunLaunchSequence`. A drop target uid is refused if it is 0, negative, 501 or above, or the service uid; groups are refused if they are 0, 20, 80, the privileged system groups (wheel, daemon, kmem, sys, tty, operator, procview, procmod, _developer), the service gid, negative or out of range, and a gid of 501 or above is refused unless it is an admitted `fsGroup`; a missing group defaults to `nobody`; a gid-only drop that leaves uid 0 is refused; an inherited uid with no drop (the daemon's own euid: the service uid, a rootless server's login uid or root on a root daemon) is allowed. The system gids (1, 2, 3, 4, 5, 8, 9, 204) are refused as the primary gid and as a supplemental gid (`runtimed/pkg/supervisor::TestRunLaunchSequenceRefusesPodGroups`, `runtimed/pkg/runtime::TestPodGroupsRefused`, `runtimed/pkg/supervisor::TestFSGroupGidAllowList`). A gid in 1..500 is refused for a Pod drop, as the primary or a supplemental group, when the host assigns it; an unassigned gid is allowed, and so is `nobody`; the never-list is always refused, a lookup error refuses, and an operator-admitted `fsGroup` the host assigns is still refused (`runtimed/pkg/supervisor::TestPodGroupsHostAssigned`). The service identity (the `_k3sm` lookup and the owners of the installed directories) is resolved again on every drop check (`runtimed/pkg/runtime::TestStartContainerResolvesTheServiceOwnerEachStart`), and a symlink at an installed path refuses every drop (`runtimed/pkg/runtime::TestSymlinkedWorkDirRefusesDrops`). When the account lookup returns not-found, a drop to the owner of the installed work dir or the keystore socket dir is refused (the installed service-uid fallback: `runtimed/pkg/supervisor::TestResolveServiceIdentityInstalledOwner`, `runtimed/pkg/runtime::TestServiceUIDFromInstalledDirs`). The live check is strict, a denial is an EPERM and planting is included (`runtimed/pkg/sandbox::TestKeystoreDeniesUnderSandboxExec`, `runtimed/pkg/sandbox::TestShimProfileKeepsTheKeystoreDeniesLast`) | `runtimed/pkg/runtime::TestStartContainerRefusesAPodIdentity`, `TestExecRefusesAPodIdentity`, `TestPodUIDInLoginRangeRefused`, `TestPodGroupsRefused`, `TestServiceUIDFromInstalledDirs`; `runtimed/internal/execshim::TestDropShim`; `runtimed/pkg/runtime::TestStartContainerResolvesTheServiceOwnerEachStart`, `TestSymlinkedWorkDirRefusesDrops`; `runtimed/pkg/supervisor::TestRunLaunchSequenceRefusesPodUID`, `TestRunLaunchSequenceRefusesPodGroups`, `TestFSGroupGidAllowList`, `TestResolveServiceIdentityInstalledOwner`, `TestPodGroupsHostAssigned`; `runtimed/pkg/sandbox::TestKeystoreDeniesUnderSandboxExec`, `TestShimProfileKeepsTheKeystoreDeniesLast`; rig legs E21, E22 | checked: runtimed's sandbox change |
| U18 | CRD: `entry`, `secretName`, `items`, `requestedBy` required with no default and immutable by CEL transition rules (`items` as a map); `requestedBy` matches its pattern and, for a user entry, equals `k3sm:local:` plus the entry's uid; `conditions` is `listType=map` keyed by `type`; status subresource on; reasons listed; a `system/…` entry is refused | `apis/config/crd::TestKeyDeliveryCRDMatchesTheGoTypes`, `TestKeyDeliveryImmutableFields`, `TestKeyDeliveryRequiredFields`, `TestKeyDeliveryRequestedByMatchesEntryUID`, `TestKeyDeliveryConditionsListMap`, `TestKeyDeliveryRefusesSystemEntry` | pending: the `KeyDelivery` API |
| U19 | the CRD pattern, its `maxLength` of 269, the uid range rule and the 253-byte name-length rule pass the shared entry-grammar vectors, `user/1/` and `system/` each with a 254-byte name refused | `apis/config/crd::TestEntryGrammarVectors` | pending: the `KeyDelivery` API |
| U20 | a user-scope `current` copied back is refused against the floor log, with the user-scope floor message, which names `floor --rebuild`, not removing `keystore-floor.json` | `k3sm/pkg/keystore::TestUserFloorRefusesCopiedBackCurrent`; rig leg E9 | pending: the append-only files |
| U21 | install creates both logs service-user-owned 0600 and flagged; the listener refuses to start when a flag is clear or a log is not the service user's (seams: chflags flag source, file-attribute writer, euid source) | `k3sm/pkg/install::TestKeystoreAppendOnlyFilesAtInstall`, `k3sm/pkg/keystore::TestFlagCheckRefusesUnflagged`; rig leg E1 | pending: the append-only files |
| U22 | `floor --rebuild` and `audit --rotate` write the marker `keystore-maintenance` and stage `keystore-user-floor.log.new` and `keystore-audit.log.new` in the root-owned data root, stop the listener, hold the lock, write the new file before touching the old, clear the old file's flag before any rename, and flag the new file on its held descriptor after the rename; a crash at each step leaves the marker, so the listener stays down until a rerun leaves a flagged file; every audit and floor append, the reconciler's and the pre-frame lines included, takes the store lock that maintenance holds exclusively, so a reconciler append during an `audit --rotate` waits and lands in the new log; after maintenance, under the exclusive lock, the server reopens its audit and floor append descriptors and recounts the per-uid shares before releasing it, and the counts reset (seams: file-attribute writer, euid source) | `k3sm/cmd/k3sm::TestKeysFloorRebuildCrashOrder`, `TestKeysAuditRotateCrashOrder`, `k3sm/pkg/keystore/reconcile::TestReconcilerAppendWaitsForAuditRotate`, `k3sm/pkg/keystore/socket::TestMaintenanceReopensLogsAndResetsShares`; rig leg E17 | pending: the append-only files, the socket listener and the KeyDelivery reconciler (lifecycle), run in the lifecycle's mode, the last to land |
| U23 | every audited operation writes one `v:1` line; no line carries a value or its length; readers ignore unknown fields | `k3sm/pkg/keystore::TestAuditLineNeverCarriesValue`, `TestAuditReaderIgnoresUnknownFields` | pending: the append-only files |
| U24 | soft cap shows in `doctor`; past the hard cap every mutating user op is `ErrLogFull`, except the revocation class, which draws on its uid's revocation budgets; a line over 1 KiB is refused | `k3sm/pkg/keystore::TestLogHardCapRefusesMutations`, `TestAuditLineBoundedAtOneKiB` | pending: the append-only files |
| U25 | backup and restore round trip: a restored tree with cleared flags is refused until `floor --rebuild`, then opens; the rebuild writes a line for every entry directory holding a `generation` file, an authenticated pointer's sequence or, with none, sequence 0, so a damaged entry stays `ErrCorrupt` and never becomes `ErrNotFound` | `k3sm/pkg/keystore::TestBackupRestoreRoundTripRebuild`, `TestRebuildKeepsDamagedEntryCorrupt`; rig leg E17 | pending: the append-only files |
| U26 | peers uid 0, the service uid and uid < 501 are refused before any frame is read (seam: peer-credential source) | `k3sm/pkg/keystore/socket::TestPeerEligibility` | pending: the socket listener |
| U27 | framing: an oversize frame, unknown type, a sub-length past the frame length or missing `HELLO` closes; `HELLO` past the 10-second bound closes; an unknown header field is ignored; `HELLO` picks the highest common version and the reply carries it and the server's frame cap; no common version sends `unsupported-version` then closes; an unknown `op` answers `unknown-op` and keeps the connection; the frame cap covers the largest value, header and framing | `k3sm/pkg/keystore/socket::FuzzFrameReader` (committed seeds), `TestFramingBounds`, `TestSubLengthsWithinFrame`, `TestHelloReadDeadline`, `TestUnknownHeaderFieldsIgnored`, `TestHelloVersionRange`, `TestHelloReplyCarriesVersionAndMaxFrame`, `TestHelloNoOverlapSendsUnsupportedVersion`, `TestUnknownOpKeepsConnection`, `TestFrameCapCoversMaxValue` | pending: the socket listener |
| U28 | 64 connections in all, 2 per uid; a request past 10 s is cut; a connection idle 30 s after `HELLO` or between requests is closed | `k3sm/pkg/keystore/socket::TestConnectionCapsPerUID`, `TestRequestTimeout`, `TestIdleTimeoutAfterHelloAndBetweenRequests` (`testing/synctest`) | pending: the socket listener |
| U29 | a listener panic is recovered and restarted; the apiserver is untouched; a stale socket is unlinked only if a service-user socket; a lock wait past 2 s fails the request (seam: clock) | `k3sm/pkg/keystore/socket::TestListenerRecoversPanic`, `TestStaleSocketUnlinkChecksOwner`, `TestBoundedLockWait` | pending: the socket listener |
| U30 | with two servers registered, the listener does not start and `doctor` says why | `k3sm/pkg/keystore/socket::TestUserScopeRefusedWithTwoServers` | pending: the socket listener |
| U31 | a missing or unflagged file logs the install Warn at start and on each retry; `doctor` reports user scope off (seams: chflags flag source, clock) | `k3sm/pkg/keystore/socket::TestListenerWarnsOnEveryRetry`, `k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow` | pending: the socket listener |
| U32 | the order is commit, append, reply, so the audit line is written before the reply; a failed append refuses user mutations and reads, except the revocation class (U109, U112) | `k3sm/pkg/keystore/socket::TestAuditBeforeReply`, `TestAuditFailureRefusesOps` | pending: the socket operations |
| U33 | `refused` lines are rate-limited per uid with a summary of the dropped count | `k3sm/pkg/keystore/socket::TestRefusedLinesRateLimited` | pending: the socket operations |
| U34 | 5 mutating ops a second per uid; 30 `read-for-exec` a minute per uid, each audited `exec-read` | `k3sm/pkg/keystore/socket::TestMutationRateLimit`, `TestExecReadCapPerUID` | pending: the socket operations |
| U35 | the socket server's store interface has no reveal, show or rewrap method | `k3sm/pkg/keystore/socket::TestStoreInterfaceHasNoRevealMethod` | pending: the socket operations |
| U36 | the client refuses a socket whose connected peer uid is not the service uid, whatever the path checks said (seam: peer-credential source, client side) | `k3sm/cmd/k3sm::TestClientRefusesForeignServerUID` | pending: the non-root CLI and `exec` |
| U37 | `exec` sets the variable only in the child; nothing on stdout, nothing on disk; the value never enters argv; no non-root verb writes a value to stdout | `k3sm/cmd/k3sm::TestKeysExecEnvOnlyInChild`, `TestNoNonRootVerbWritesValue` | pending: the non-root CLI and `exec` |
| U38 | an unknown error code prints the code; a connect failure names `sudo k3sm install` | `k3sm/cmd/k3sm::TestUnknownErrorCodeFallback`, `TestConnectErrorNamesInstall` | pending: the non-root CLI and `exec` |
| U39 | (unused: there are no system grants) | none | none |
| U40 | the admission policy checks `requestedBy` against the requester and refuses a ServiceAccount creator; its CEL passes the shared grammar vectors | `k3sm/pkg/policy::TestKeyDeliveryPolicyChecksRequestedBy`, `TestEntryGrammarVectorsCEL` | pending: KeyDelivery authoring |
| U41 | `deliver` creates impersonating only `k3sm:local:<uid>` and `k3sm:local-users`, refusing any other impersonation and never sending `Impersonate-Uid` or `Impersonate-Extra-*`; the impersonated uid equals the peer uid; a request naming another user's entry impersonates the peer, not the owner; it writes the UID and digest; `withdraw` deletes the object; `undeliver` prints the hint | `k3sm/pkg/keystore/socket::TestDeliverImpersonatesUIDPrincipalOnly`, `TestDeliverImpersonatesPeerUIDNotOwner`, `TestImpersonationSendsNoUidOrExtra`, `TestDeliverWritesDigestRecord`, `k3sm/cmd/k3sm::TestUndeliverPrintsRotationHint` | pending: KeyDelivery authoring |
| U42 | an unrecorded UID, a digest mismatch, or a denied SAR gets no Secret; the SARs ask `create keydeliveries` and `create secrets` with no name, and `update` and `delete` secrets with `resourceNames` `spec.secretName`; encryption off refuses (G18 for KeyDelivery); each SAR carries the user `k3sm:local:<uid>` and the groups the impersonated create carried, so a grant bound to `k3sm:local-users` passes the create and every sweep alike | `k3sm/pkg/keystore/reconcile::TestUnrecordedOrRetargetedDeliveryGetsNoSecret`, `TestSARCreateUnnamedUpdateDeleteNamed`, `TestSARCarriesImpersonatedUserAndGroups`, `TestGroupBoundGrantHonouredConsistently`, `TestEncryptionOffRefusesKeyDelivery`; rig leg E23 | pending: the KeyDelivery reconciler (authority) |
| U43 | reasons are the closed set, each on the condition type and status the reason table gives; "absent" and "not yours" both read `EntryUnavailable`; a pre-existing Secret not claimed by a KeyDelivery (unlabelled, or Phase A's) is `SecretExists`; a second declaration is `SecretClaimed`, the oldest honoured record by `creationTimestamp`, then name, winning; `observedGeneration` tracks; `Ready=False` for any authority failure carries the one reason `NotAuthorized` with the `Authorized` reason in its message; `Ready` is `Unknown`, `Pending` before the first sweep and while `Authorized` is `Unknown`; each `Authorized=False` reason is tied to its action (`EntryUnavailable`, `NotRecorded` for a withdrawn UID or a digest mismatch, and `NotAuthorized` delete; `NotRecorded` for a UID never recorded retains), and a Secret kept under `Authorized=False` sets `SecretRetained=True` (`DeletePending` or `Unowned`) | `k3sm/pkg/keystore/reconcile::TestConditionReasonsClosedSet`, `TestReasonConditionTable`, `TestOneDeclarationPerSecret`, `TestReadyFalseCarriesNotAuthorized`, `TestReadyUnknownPending`, `TestAuthorizedFalseReasonActionMap`, `TestSecretRetainedWhenKept` | pending: the KeyDelivery reconciler (authority) |
| U44 | losing authority (a definitive denial) deletes exactly the owned Secret; the crash order is Secret, record, finalizer at every interruption point; ownership is the label, the owner annotation and that UID in the sealed record, not the ownerReference; the Secret's namespace and name must equal the record's target for that UID, and the record's entry must match the owner annotation; the orphan sweep removes a labelled Secret only when its owner annotation names a KeyDelivery UID the sealed record holds, it is that UID's recorded target, and that object no longer exists or is withdrawn, and never one with the label and owner annotation alone, an unlabelled or a foreign one; a forged label and a real UID on another Secret are left alone, charged to no share and logged as one `refused` line under the reconciler, against the reconciler budget, never as the owner's `deliver-delete` | `k3sm/pkg/keystore/reconcile::TestLostAuthorityDeletesOnlyOwnedSecret`, `TestFinalizerCrashOrder`, `TestOrphanSweep`, `TestForgedOwnerAnnotationOnOtherSecretIsLeftAlone` | pending: the KeyDelivery reconciler (lifecycle) |
| U45 | cross-user refusal with a fake peer-credential source: a peer with uid B asks for `list`, `read-for-exec`, `rotate`, `rm`, `deliver`, `withdraw` and `deliveries` of uid A's entries and objects, and for any `system/…` name; every call is `ErrNotFound` with text identical to an absent entry of B's own, and the `refused` audit lines carry uid B | `k3sm/pkg/keystore/socket::TestCrossUserRefusedFakePeerCred`, `TestNonRootCannotNameSystemEntries` | pending: the socket operations |
| U46 | `baseSocketDenies` derives the `keys.sock` path from `runtimed/pkg/keystorepaths` (`SocketPath(dataRoot)`, `<dataRoot>/keystore-sock/keys.sock`) and denies `connect(2)` to it | `k3sm/pkg/provider::TestBaseSocketDeniesKeystoreSocket`; `runtimed/pkg/keystorepaths::TestNames` | pending: the socket listener |
| U47 | seam guard: `pkg/keystore`'s `TestMain` installs a panicking stub on each of its seams, so no unit test reaches a real primitive | `k3sm/pkg/keystore::TestRealPrimitivesUnreachable` | pending: the user-scope store |
| U48 | seam guard: `pkg/keystore/socket`'s `TestMain` installs a panicking stub on each of its seams, so no unit test reaches a real primitive; the server-side peer-credential source is a constructor parameter of the listener, not a package variable, and the constructor refuses nil | `k3sm/pkg/keystore/socket::TestRealPrimitivesUnreachable`, `TestListenerRequiresPeerCredSource` | pending: the socket listener |
| U49 | `runtimed/pkg/keystorepaths` builds with `CGO_ENABLED=0` and imports only the standard library; `k3sm/pkg/keystore` imports that leaf and never `runtimed/pkg/sandbox` | `runtimed/pkg/keystorepaths::TestLeafImportsOnlyTheStandardLibrary`; `k3sm/pkg/keystore::TestKeystoreImportsNoSandbox` | pending: runtimed's sandbox change, the append-only files |
| U50 | the defeat list, run as the service user against both flagged logs (integration, a root-run row: `--root` runs it by name and fails it on SKIP, and `--check` prints it uncounted, as pending; flag variant): `chflags nosappnd`, `O_TRUNC`, `ftruncate`, `pwrite` at an offset, a shared writable `mmap` write, `F_PUNCHHOLE`, `link()`, `fclonefileat` then a swap, a `renamex_np` swap through the parent, `exchangedata`, `unlink` and `rename` through the parent, a second open with `O_TRUNC`, and owner `chmod`; each fails, the bytes and the flag are unchanged, and an `O_APPEND` write still succeeds | `k3sm/pkg/keystore::TestAppendOnlyDefeatListAsServiceUser` | pending: the append-only files |
| U51 | per-uid log fairness: the share is a fixed byte count, 16 MiB by default, and a share above 1/16 of the hard cap is refused at start; every line is charged to the uid it acts for, reads (`list`, `read-for-exec`, `deliveries`) included; a uid past its share has its own mutations and reads refused with `ErrLogFull` (`log-full`) while another uid's succeed, and that refusal is never the global append failure that refuses every uid's reads; a uid past its share cannot get another uid's mutations, reads or revocations refused, though it can delay them through the store lock (U89); `list` and `deliveries` are rate-limited per uid | `k3sm/pkg/keystore/socket::TestLogSharePerUIDRefusesOnlyThatUID`, `TestLogShareAtMostOneSixteenthOfHardCap`, `TestShareRefusalIsNotGlobalAppendFailure`, `TestReadRateLimitPerUID`, `TestReadsChargedToShare`, `TestShareExhaustionIsolatedPerUID` | pending: the socket operations |
| U52 | every root verb writes one audit line with `via` `root` once the log exists, and none before it | `k3sm/cmd/k3sm::TestEveryRootVerbWritesAuditLine` | pending: the append-only files |
| U53 | every reconciler Secret write and delete, and every record withdrawal, writes one audit line with `via` `reconciler`, except drift repairs, coalesced to one line per delivery per 10 minutes (U86) | `k3sm/pkg/keystore/reconcile::TestEveryReconcilerWriteAndDeleteAudited` | pending: the KeyDelivery reconciler (lifecycle) |
| U54 | a pre-frame refusal (uid 0, the service uid, a uid below 501) writes a `refused` line with the peer uid, rate-limited per uid, drawing on the reconciler budget with its once-a-minute dropped-count summary | `k3sm/pkg/keystore/socket::TestPreFrameRefusalsAudited`, `TestPreFrameRefusalLinesRateLimited` | pending: the socket listener |
| U55 | a transient lookup, SAR or apiserver error leaves the Secret and sets Unknown: a failed SAR call, an API server error, `ErrScopeOwnerUnknown`, `ErrBusy` and `ErrLogFull` each leave the Secret, the record entry and the finalizer, set `Authorized=Unknown` with reason `Indeterminate`, and retry with backoff; a SAR answer is a definitive denial when the call succeeded, `allowed=false` and `evaluationError` is empty, whatever `denied` says (the RBAC authorizer refuses with no opinion, reported as `allowed=false`), and each other answer is `Indeterminate`; no sweep runs before `readyz` and the sync of the RBAC, KeyDelivery and Secret informers; every deleting outcome, not only a denial, deletes only when two consecutive sweeps see it for the same generation; only the allow-list (`ErrNotFound` for an entry missing from a scope that opened, a withdrawn record, a digest mismatch on a readable record, a definitive SAR denial) deletes, and a table over every store sentinel (`ErrScopeOwnerChanged` until a K7a amendment (U127), `ErrScopeAbsent`, `ErrCorrupt`, the floor refusal, `ErrMasterMissing`, `ErrScopeUnsupported`, `ErrBusy`, `ErrLogFull`, `ErrScopeOwnerUnknown`), a cancelled ctx, the audit read refusal, an unknown record version and an unlisted error finds each `Indeterminate`; against the real store, on `ErrScopeOwnerChanged` the reconciler reads the `deliveries` record under `W` without the GeneratedUID check only to find recorded targets for a lifecycle delete (the object's deletion, the orphan sweep), deletes them by the target-matching rule, and never delivers, rotates or opens an entry | `k3sm/pkg/keystore/reconcile::TestTransientErrorLeavesSecretSetsUnknown`, `TestSAREvaluationErrorIsIndeterminate`, `TestSARAllowedFalseWithoutErrorIsDenial`, `TestNoSweepBeforeReady`, `TestDenialNeedsTwoSweeps`, `TestEverySentinelBesidesNotFoundIsIndeterminate`, `TestOwnerChangedRecordReadFindsTargetsAgainstRealStore` | pending: the KeyDelivery reconciler (lifecycle) |
| U56 | a delivery record with an unknown format version is refused by the store and read by the reconciler as `Indeterminate`, never as a denial: no Secret is deleted | `k3sm/pkg/keystore::TestDeliveryRecordUnknownVersionRefused`, `k3sm/pkg/keystore/reconcile::TestUnknownRecordVersionIsIndeterminate` | pending: the KeyDelivery reconciler (lifecycle) |
| U57 | `apis/keystore/entry` imports only the standard library, exports the pattern, the `maxLength` and the parse, and holds the shared vector table, which it passes | `apis/keystore/entry::TestGrammarVectors`, `TestImportsStdlibOnly` | pending: the entry grammar in `apis` |
| U58 | seam guard, repo level: the seam-bearing packages are a closed list (`pkg/keystore`, `pkg/keystore/socket`, `pkg/keystore/reconcile`, `cmd/k3sm`, `pkg/install`); each listed package has its `TestMain` stub install and its `TestRealPrimitivesUnreachable`, a missing guard fails, and a package outside the list that declares a seam fails; fakes restore through `t.Cleanup` | `k3sm/pkg/keystore::TestEverySeamPackageHasAGuard` | pending: the user-scope store, its list extended by each change that adds a seam package |
| U59 | seam guard: `pkg/keystore/reconcile`'s `TestMain` installs a panicking stub on its clock seam | `k3sm/pkg/keystore/reconcile::TestRealPrimitivesUnreachable` | pending: the KeyDelivery reconciler (authority) |
| U60 | seam guard: `cmd/k3sm`'s `TestMain` installs a panicking stub on each of its seams (clock, uid resolver, client-side peer-credential source, server code identity, exec, euid source, file-attribute writer) | `k3sm/cmd/k3sm::TestRealPrimitivesUnreachable` | pending: the append-only files, extended by the non-root CLI and `exec` |
| U61 | seam guard: `pkg/install`'s `TestMain` installs a panicking stub on its euid source and file-attribute writer | `k3sm/pkg/install::TestRealPrimitivesUnreachable` | pending: the append-only files |
| U62 | reconciler lines are charged to the delivery's owner uid: a `deliver-write` of a new version past the owner's share is refused and read as `Indeterminate`, the Secret keeping its last version, unless it is the rotation write that follows a `rotate`; a `deliver-delete`, the `deliver-write` and floor line of a withdrawal, and the rotation write are charged but never refused for the share, and past it draw on the owner's 256 KiB reconciler allowance, never on the owner's socket margin or another uid's budgets | `k3sm/pkg/keystore/reconcile::TestReconcilerLinesChargedToOwner`, `TestDeliverWritePastShareIsIndeterminate`, `TestDeliverDeleteNeverRefusedForShare` | pending: the KeyDelivery reconciler (lifecycle) |
| U63 | entries live under `.user/<uid>/entries/`: entries named `deliveries` and `scope.key` are ordinary, `put`, `rotate`, `list` and `rm` work on them, and neither touches the scope's `deliveries` record or `scope.key` | `k3sm/pkg/keystore::TestEntriesNamedDeliveriesAndScopeKeyAreOrdinary` | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U64 | a missing `.user/<uid>/` or `scope.key` answers `ErrScopeAbsent`, never `ErrNotFound`; inside a scope whose `scope.key` opens, a missing `entries/` directory or a missing `deliveries` record is `ErrScopeAbsent` too; `ErrNotFound` only for an entry missing from an `entries/` that exists and opened; a read (`list`, `read-for-exec`, `deliveries`, a reconciler read) on a uid with no scope creates no directory and mints no `K_u`; the first mutating operation does, writing `entries/` and an empty `deliveries` record before `scope.key` | `k3sm/pkg/keystore::TestReadDoesNotMintScope`, `TestMissingScopeIsScopeAbsent`, `TestMissingEntriesDirIsScopeAbsent`, `TestMissingDeliveriesRecordIsScopeAbsent` | pending: the user-scope store |
| U65 | the reconciler reads `ErrScopeAbsent` as `Indeterminate` and deletes nothing; every outcome on the allow-list, not only a SAR denial, deletes only on two consecutive sweeps for the same generation; the single-server check is re-run from a fresh List before every sweep, and a second server or a failed List runs no sweep | `k3sm/pkg/keystore/reconcile::TestAbsentScopeIsIndeterminate`, `TestEveryDeletingOutcomeNeedsTwoSweeps`, `TestSingleServerRecheckedBeforeEverySweep` | pending: the KeyDelivery reconciler (lifecycle) |
| U66 | the GeneratedUID lookup recognises the synthesized compatibility form (prefix `FFFFEEEE-DDDD-CCCC-BBBB-AAAA`) and answers `ErrScopeOwnerUnknown`, never a changed owner, and no mint binds it; `ErrScopeOwnerChanged` only when a real, non-synthesized GeneratedUID differs from the bound one (seam: GeneratedUID lookup) | `k3sm/pkg/keystore::TestSynthesizedGeneratedUIDIsUnknown` | pending: the user-scope store |
| U67 | the revocation class (`withdraw`, `rm`, `rotate`, the withdrawal's floor line, the reconciler's `deliver-delete`, its `deliver-write` of a withdrawal and its rotation write) is charged to the share while it has room and past it bypasses the share and the hard cap, drawing on its uid's own budgets per log, counted per uid from the log: a 256 KiB reconciler allowance for the reconciler's lines and a separate 64 KiB socket margin for the uid's own `withdraw`, `rm` and `rotate` and their floor lines; neither budget can draw on the other; only the budget a line draws on running out refuses it, so one uid's revocations are never refused because of another uid: uid A uses up its budgets and uid B's revocation still succeeds; a uid with 64 live deliveries past its share still revokes from its socket margin, and spending that margin leaves the reconciler allowance whole; a no-op `rm`, `withdraw` or `rotate` is charged like any line and refused past the share; a log passes the hard cap by at most 320 KiB per user scope, plus the 1 MiB reconciler budget | `k3sm/pkg/keystore/socket::TestRevocationBypassesShareUsesReserve`, `TestNoOpRevocationChargedToShare`, `TestReserveKeepsReconcilerPart`, `TestRevocationAllowanceIsPerUID`, `TestSocketMarginSeparateFromReconcilerAllowance` | pending: the socket operations |
| U68 | root never acts by path where the service user can write: run as root (a root-run row, `--root`), the maintenance verbs refuse a symlink or a swapped file planted at the marker, either staging name or the old log, create through one data-root descriptor with `O_CREAT\|O_EXCL\|O_NOFOLLOW`, `fchflags` on the held descriptor after the `renameat` and `fchown` to the service user on it only after the flag, never renaming a flagged file or over one, and leave every byte of both logs unchanged on a refusal | `k3sm/cmd/k3sm::TestMaintenanceRefusesPlantedSymlinkAndSwap` (integration, root-run) | pending: the append-only files |
| U69 | the client pins the server: it reads the peer's audit token (`LOCAL_PEERTOKEN`) and refuses, writing nothing, unless the peer's cdhash equals the cdhash of the installed `/Library/k3sm/k3sm`; a service-user peer that is another binary, a reused pid, a code lookup error, an old server after an upgrade (which prints the restart message) and a listener inherited or passed to another process are each refused (seams: peer-credential source, client side; server code identity) | `k3sm/cmd/k3sm::TestClientPinsServerByInstalledCDHash`, `TestClientRefusesServiceUIDPeerOfOtherCode`, `TestClientRefusesReusedPeerPID`, `TestClientCDHashMismatchNamesRestart`, `TestClientPinWithInheritedOrPassedListener` | pending: the non-root CLI and `exec` |
| U70 | (helper variant only) the floor helper admits only a peer that runs as the service uid and whose audit token resolves to the installed binary's cdhash, and the server admits only a helper that runs as root and is that binary; it refuses every request but `append` and `read` | `k3sm/pkg/keystore/floorhelper::TestFloorHelperPeerPinned`, `TestFloorHelperRefusesOtherRequests` | pending: the K0 amendment (helper variant only) |
| U71 | (helper variant only) every Pod profile variant denies the helper's socket path, for connect, bind and every file operation | `runtimed/pkg/sandbox::TestFloorHelperSocketPodDenied` | pending: the K0 amendment (helper variant only) |
| U72 | an orphan-cascade delete (`propagationPolicy: Orphan`) of a KeyDelivery, whose Secret has lost its ownerReference, still deletes the Secret, found by its label, owner annotation and the sealed record's UID | `k3sm/pkg/keystore/reconcile::TestOrphanCascadeStillDeletesSecret` | pending: the KeyDelivery reconciler (lifecycle) |
| U73 | only an honoured KeyDelivery (UID recorded, digest matching) can claim a target for `SecretClaimed`: an older unrecorded object claims nothing, and the recorded one is delivered; precedence comes only from honoured records plus `creationTimestamp`, then name; an `Indeterminate` object counts as honoured and keeps the claim until a definitive deleting outcome, so an indeterminate sweep keeps the claim; the owner annotation never decides (U111) | `k3sm/pkg/keystore/reconcile::TestUnrecordedObjectDoesNotClaimTarget`, `TestIndeterminateOwnerKeepsClaim` | pending: the KeyDelivery reconciler (authority) |
| U74 | `withdraw` by namespace and name deletes the caller's own unrecorded object after checking `requestedBy` against the peer uid, impersonating that principal with a UID precondition; an object of another uid answers `not-found`, worded as for an absent object, and is left | `k3sm/pkg/keystore/socket::TestWithdrawRemovesOwnUnrecordedObject`, `TestWithdrawOtherUIDsObjectIsNotFound` | pending: KeyDelivery authoring |
| U75 | the finalizer's withdraw step counts a scope that cannot be opened because the owner changed, or that `rm-scope` removed, as withdrawn and drops the finalizer after the Secret is gone; `ErrScopeOwnerUnknown` and other errors keep it | `k3sm/pkg/keystore/reconcile::TestFinalizerDropsWhenScopeUnopenable` | pending: the KeyDelivery reconciler (lifecycle) |
| U76 | k3sm's CA refuses a CN `k3sm:local:*` and an Organization `k3sm:local-users` in every issuing path, in `issueLeaf`, so `IssueClient`, both CSR signers and the join exchange's CSR approvals are covered; the controller-manager runs with no cluster-signing key | `k3sm/pkg/certs::TestReservedLocalPrincipalsRefusedInCSR`, `TestReservedLocalPrincipalsRefusedEveryIssuer`; `k3sm/pkg/executor::TestControllerManagerHasNoClusterSigningKey` | pending: KeyDelivery authoring |
| U77 | `rm-scope` revokes first: under the exclusive store lock it reads the sealed `deliveries` record, deletes each recorded delivery's Secret through the reconciler's admin client by the target-matching rule (namespace, name, label, owner annotation and recorded entry), and only then removes the scope; with the API server unreachable it refuses and changes nothing, no Secret and no file; with the record unopenable it refuses unless `--orphan-secrets`, which lists the labelled Secrets naming this scope's entries, each marked `unauthenticated (annotation only)`, deletes none and then removes the scope (seams: euid source) | `k3sm/cmd/k3sm::TestRmScopeDeletesDeliveredSecretsFirst`, `TestRmScopeRefusesWithoutAPI`, `TestRmScopeOrphanSecretsListsAndLeaves` | pending: the KeyDelivery reconciler (lifecycle) |
| U78 | `SecretRetained` is `True` whenever a labelled Secret stays while `Authorized` is `Unknown` or `False`: under `Unknown` with reason `Indeterminate`, the Secret at its last version; `NoneRetained` only when none stays or `Authorized` is `True` | `k3sm/pkg/keystore/reconcile::TestSecretRetainedTrueUnderUnknown` | pending: the KeyDelivery reconciler (authority) |
| U79 | the rotation write, the `deliver-write` that follows a `rotate`, is in the revocation class: past the owner's share it draws on the owner's reconciler allowance, once per live delivery per log, and reaches the Secret; a further rotation write for that delivery past the share is `Indeterminate`; the reconciler's need for one uid, 64 deliveries × 4 lines × 1 KiB, is 256 KiB, the whole allowance | `k3sm/pkg/keystore/reconcile::TestRotationWriteUsesReserve` | pending: the KeyDelivery reconciler (lifecycle) |
| U80 | root walks service-user trees by descriptor: run as root (a root-run row, `--root`), `rm-scope`, `floor --rebuild` and Rewrap of each `scope.key` (U128) walk `.user/<uid>/` with `openat` and `unlinkat` and `O_NOFOLLOW`, refuse a planted symlink, FIFO or other non-regular file and a directory where the layout has none, read with a bounded size, re-check `SameFile` after each open and never follow a swapped directory | `k3sm/cmd/k3sm::TestRootWalksRefusePlantedNames` (integration, root-run) | pending: the append-only files |
| U81 | a KeyDelivery never touches a Phase A Secret: the user-scope label value is the constant `keydelivery` and the entry is in the annotation `k3sm.io/keystore-entry`; a target that is present and not claimed by a KeyDelivery, unlabelled or delivered by Phase A, is `SecretExists` and is never overwritten or deleted; the Phase A reconciler leaves alone a Secret carrying `k3sm.io/keystore-entry` | `k3sm/pkg/keystore/reconcile::TestKeyDeliveryNeverTouchesPhaseASecret` | pending: the KeyDelivery reconciler (authority) |
| U82 | eligible peer uids are 501 to 2147483647: `nobody` (4294967294), 2147483648 and every uid at 2^31 or above are refused before any frame, with a `refused` line, as uid 500 is; 501 and 2147483647 are admitted; no scope is minted outside the range (seam: peer-credential source) | `k3sm/pkg/keystore/socket::TestPeerUIDRangeRefusesNobodyAndHighUIDs` | pending: the socket listener |
| U83 | the reconciler checks the user-scope floor log: a missing or unflagged floor log is `Indeterminate` for writes, so no `deliver-write` runs until `floor --rebuild`; the floor holds writes and absence-driven deletes: an `ErrNotFound` delete is `Indeterminate` while the floor is missing or unflagged, a revocation-driven delete (a withdrawn record, a digest mismatch, a SAR denial) still deletes the Secret without the floor, and only the record withdrawal waits for it (U107; the store's flag check, faked at the reconciler's store interface) | `k3sm/pkg/keystore/reconcile::TestReconcilerHoldsWritesWithoutFloor` | pending: the KeyDelivery reconciler (lifecycle) |
| U84 | when a log's size is past the hard cap, `doctor` shows a Warn with the overshoot in bytes and the `audit --rotate` or `floor --rebuild` hint, and none at or below it; the overshoot is at most 320 KiB per user scope, plus the 1 MiB reconciler budget | `k3sm/cmd/k3sm::TestDoctorWarnsOnLogOvershoot` | pending: the socket operations |
| U85 | a reconciler line charged to no uid (a forged-Secret `refused` line, a drift repair, their summaries) draws on the reconciler budget, 1 MiB per log, separate from every uid and excluded from the hard-cap test; forged Secrets are counted in a bounded LRU of 1024 (namespace, name) pairs with no per-`resourceVersion` set, new pairs' lines at most 10 a minute and at most one summary `refused` line a minute carrying the dropped count; past the budget the lines are dropped and counted and `doctor` warns; N forged updates leave every uid able to read and mutate | `k3sm/pkg/keystore/reconcile::TestForgedSecretFloodLeavesEveryUIDServed`, `TestUnchargedLinesHaveOwnBudget` | pending: the KeyDelivery reconciler (lifecycle) |
| U86 | a drift repair (the reconciler re-creating or repairing a delivered Secret that someone other than the reconciler edited or deleted, at the version already delivered) is reconciler-class: it draws on the reconciler budget and is never charged to the owner's share or budgets; repairs are coalesced to one audit line per delivery per 10 minutes with a count, and rate-limited per delivery with exponential backoff capped at 10 minutes; a write of a new version after the owner's own `rotate` or `put` stays charged to the owner; `Ready=Delivered` compares `k3sm.io/keystore-digest`, the sha256 of the Secret's `data`, each sweep, so a substituted `data` under an intact version annotation is drift | `k3sm/pkg/keystore/reconcile::TestDriftRepairNotChargedToOwner`, `TestSubstitutedDataIsDrift` | pending: the KeyDelivery reconciler (lifecycle) |
| U87 | the admission policy also matches UPDATE and DELETE of `keydeliveries` and admits one only when the requester equals `oldObject.spec.requestedBy`, is the k3sm server's identity, or is in `system:masters` (and, for DELETE only, the namespace controller's ServiceAccount); a finalizer edit is an UPDATE, so another author can neither delete the object nor strip its finalizer; the reconciler's and `withdraw`'s own writes pass; on a DELETE `object` is null and only `oldObject` is read; `failurePolicy` is `Fail` | `k3sm/pkg/policy::TestVAPRefusesDeleteByOtherAuthor`, `TestVAPRefusesFinalizerStripByOtherAuthor`; rig leg E23 | pending: KeyDelivery authoring |
| U88 | `floor --rebuild` never lowers: it reads every scope whose `scope.key` opens under `W` without the GeneratedUID check, so an owner change or a departed account is rebuilt from its pointers (U129); if any scope's `scope.key` does not open under `W` or any other error stops it (`ErrBusy` included), it refuses to finish, names the scope and changes nothing; the `deliveries` record's AAD is scope, kind 0xFD, name `deliveries`, generation and sequence, its floor key is `(user/<uid>, .deliveries, generation, seq)`, and the rebuild writes that key's line; a copied-back older `deliveries` record is refused against the floor, before and after a rebuild | `k3sm/cmd/k3sm::TestRebuildRefusesOnUnopenableScope`, `k3sm/pkg/keystore::TestCopiedBackDeliveriesRecordRefused` | pending: the append-only files |
| U89 | reads take the store lock shared and mutations exclusive, through a writer-preferring in-process lock; a server exclusive hold does at most 50 ms of work per operation, larger work chunked, no hold across an API call (the bound measured in K7a); a reconciler revocation that gets `ErrBusy` retries up to 3 times with jitter in the same sweep before it is `Indeterminate`; under a sustained read load from other uids a revocation completes | `k3sm/pkg/keystore/reconcile::TestRevocationCompletesUnderOtherUIDReadLoad` | pending: the KeyDelivery reconciler (lifecycle) |
| U90 | no unflagged window for the new file (integration, a root-run row: `--root`): it stays root-owned 0600 while written, and the order is write, fsync, clear the old file's flag, rename, set `sappnd` on the held descriptor, then `fchown` to the service user, so the service user never holds a descriptor from before the flag; a crash that leaves the canonical file unflagged or root-owned keeps the listener refused until the verb is rerun; the maintenance wait is the exclusive `.lock`, bounded at 30 s | `k3sm/cmd/k3sm::TestMaintenanceHandsOverOnlyAfterFlag` (integration, root-run) | pending: the append-only files |
| U91 | `audit --rotate` keeps four archives, `.1` to `.4`, and refuses, changing nothing, when `.4` exists unless `--discard-oldest`; each shifted archive is re-flagged on its own descriptor; the `doctor` hint says to export first; rotation resets the shares, bounded by the archive count | `k3sm/cmd/k3sm::TestAuditRotateKeepsFourArchives` | pending: the append-only files |
| U92 | a `rotate` whose delivery will stall (owner past share, the delivery's rotation write used) is stored and answered `stored; delivery pending: past your log share`; the CLI prints the warning line and exits 0 | `k3sm/cmd/k3sm::TestRotateReportsDeliveryStall` | pending: the non-root CLI and `exec` |
| U93 | the sweep period is 30 s by default; two consecutive deleting observations count only when at least 60 s apart on the clock seam, however many sweeps run between them | `k3sm/pkg/keystore/reconcile::TestDeletingObservationsSpacedOnClock` | pending: the KeyDelivery reconciler (lifecycle) |
| U94 | `withdraw` opens the caller's scope and so runs the GeneratedUID check: a reused uid with a changed GeneratedUID gets `scope-owner-changed` and deletes nothing (seams: GeneratedUID lookup, peer-credential source) | `k3sm/pkg/keystore/socket::TestWithdrawChecksGeneratedUID` | pending: KeyDelivery authoring |
| U95 | `rm-scope` lists every RoleBinding and ClusterRoleBinding with the subject `k3sm:local:<uid>` and refuses, changing nothing, unless none exist or `--keep-bindings` is given | `k3sm/cmd/k3sm::TestRmScopeRefusesWithBindings` | pending: the KeyDelivery reconciler (lifecycle) |
| U96 | the `deliveries` record is exempt from the 64 KiB value cap and bounded at 64 live entries plus 256 withdrawn tombstones, 3,328 bytes an entry (8 items), 1,056 KiB sealed; at the bound `deliver` answers `quota` and a withdrawal still succeeds, in place; a tombstone is pruned only after its Secret is seen gone (Get not found) on two sweeps at least 60 s apart | `k3sm/pkg/keystore/reconcile::TestDeliveriesRecordBoundAndPrune`, `TestRevocationNeverRefusedAtRecordBound` | pending: the KeyDelivery reconciler (lifecycle) |
| U97 | when `rotate` answers `ErrQuota`, `rm` then `put` recovers: `rm` frees every version and `put` stores the value as version 1 of a new generation; the `quota` error names that recovery | `k3sm/pkg/keystore::TestRotateQuotaRecoveredByRmThenPut` | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U98 | the sealed `deliveries` record stores each delivery's KeyDelivery `metadata.name`; the orphan sweep checks the object with a live Get by that name sent to the API server, never an informer cache and never a List; not found, or another UID, deletes only on two consecutive observations at least 60 s apart, and any other answer in between resets the count; no sweep runs before the KeyDelivery and Secret informers sync | `k3sm/pkg/keystore/reconcile::TestOrphanSweepUsesLiveGetByName`, `TestOrphanSweepNeedsTwoObservations` | pending: the KeyDelivery reconciler (lifecycle) |
| U99 | under the store lock, before every audit or floor append, the server compares its descriptor's `(dev, ino)` with the canonical name's and reopens on a mismatch, recounting the per-uid shares from the new file; `audit --rotate` and `floor --rebuild` each complete while the server never saw the marker, and every later line lands in the new canonical file, none in an archive or an unlinked file (seam: chflags flag source) | `k3sm/pkg/keystore/socket::TestAppendReopensOnInodeMismatch` | pending: the socket listener (the server append path) |
| U100 | a departed account with an unreused uid is reported, not acted on: `doctor` lists every scope whose uid has no directory record (a synthesized GeneratedUID) with its delivery count; each of that scope's deliveries gets `SecretRetained=True` with reason `OwnerUnresolvable`, and no Secret is deleted (seam: GeneratedUID lookup) | `k3sm/cmd/k3sm::TestDoctorListsUnresolvableScopes`, `k3sm/pkg/keystore/reconcile::TestOwnerUnresolvableRetainedCondition` | pending: the KeyDelivery reconciler (lifecycle) |
| U101 | `rewrap` prints a warning whenever `.user/` exists, before it starts and when it finishes, saying Rewrap does not re-key `K_u` and naming the procedure: each user re-puts their values after a suspected master exposure; with no `.user/` it prints none (seam: euid source) | `k3sm/cmd/k3sm::TestRewrapWarnsWhenUserScopesExist` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U102 | the sealed record stores the last delivered version per delivery, raised after the Secret write succeeds; the repair-versus-owner classifier uses only that recorded version: a Secret whose version annotation is rewritten and a KeyDelivery whose `status.deliveredVersion` is rewritten each leave the charge unchanged, a repair stays on the reconciler budget and an owner's new version stays charged to the owner | `k3sm/pkg/keystore/reconcile::TestChargingIgnoresTamperedVersionAnnotationAndStatus` | pending: the KeyDelivery reconciler (lifecycle) |
| U103 | a Secret at a recorded target whose label or owner annotation was removed is never overwritten or deleted, under a revocation, the object's deletion and `rm-scope` alike; the KeyDelivery gets `SecretRetained=True` with reason `LabelRemoved`, and `doctor` names the Secret and the KeyDelivery | `k3sm/pkg/keystore/reconcile::TestStrippedLabelReportedNotDeleted` | pending: the KeyDelivery reconciler (lifecycle) |
| U104 | the socket's directory is root's: run as root (a root-run row, `--root`), install creates `keystore-sock/` root:wheel 0755 and the server plist carries a `Sockets` listener for `keystore-sock/keys.sock`; a process running as the service uid cannot unlink, replace or bind `keys.sock`, whether or not the server runs, and gets `EACCES` | `k3sm/pkg/install::TestSocketDirRootOwnedServiceUIDCannotBind` (integration, root-run); rig leg E24 | pending: the socket listener |
| U105 | every root path walks the keystore trees by descriptor: run as root (a root-run row, `--root`), `sudo k3sm install` over an existing tree, `uninstall --purge` and `doctor` each refuse a planted symlink, FIFO or swapped directory under `.user/` and at every `keystore-*` name, with `openat`, `O_NOFOLLOW`, bounded reads and a `SameFile` re-check, and change nothing they were not meant to | `k3sm/pkg/install::TestInstallOverExistingTreeWalksByDescriptor`, `TestPurgeWalksKeystoreByDescriptor`, `k3sm/cmd/k3sm::TestDoctorWalksKeystoreByDescriptor` (integration, root-run) | pending: the append-only files |
| U106 | every root verb refuses a non-root caller: one table test runs `rm-scope`, `floor --rebuild`, `audit --rotate`, `rewrap` and `deliver system/…` with a non-root euid through the euid source, and each is refused with the same message and exit code, changing nothing (seam: euid source) | `k3sm/cmd/k3sm::TestRootVerbsRefuseNonRootEUID` | pending: the KeyDelivery reconciler (lifecycle), each verb's case added by the change that adds the verb |
| U107 | with the user floor missing or unflagged, an absence-driven delete (`ErrNotFound`) is `Indeterminate` and deletes nothing, while a revocation-driven delete (a withdrawn record, a digest mismatch, a SAR denial) deletes the Secret after its two spaced observations | `k3sm/pkg/keystore/reconcile::TestNotFoundDeleteWaitsForFloor`, `TestRevocationDeleteProceedsWithoutFloor` | pending: the KeyDelivery reconciler (lifecycle) |
| U108 | the exclusive hold bound on a fake clock: no server exclusive hold does more than 50 ms of work; the GeneratedUID lookup runs before the lock is taken and its answer is cached for the hold, so a lookup that takes its whole 250 ms deadline adds nothing to the hold (seams: clock, GeneratedUID lookup) | `k3sm/pkg/keystore::TestExclusiveHoldBound` | pending: the user-scope store |
| U109 | with every audit append failing (a full disk), revocation deletes go ahead: the reconciler's `deliver-delete` and a socket `withdraw`, `rm` or `rotate` still act, their lines dropped and counted in memory and shown by `doctor`, while user mutations and reads stay refused | `k3sm/pkg/keystore/reconcile::TestRevocationDeleteProceedsOnAppendFailure` | pending: the KeyDelivery reconciler (lifecycle) |
| U110 | when a second server registers at runtime, the next single-server check stops the listener, closing its connections, and each KeyDelivery gets `Ready=False` and `SecretRetained=True` with reason `UserScopeOff`; the delivered Secrets stay, nothing rotates or deletes them, and `doctor` says they must be deleted by hand | `k3sm/pkg/keystore/reconcile::TestSecondServerAtRuntimeStopsListenerAndReports` | pending: the KeyDelivery reconciler (lifecycle) |
| U111 | the owner annotation never decides precedence: a Secret whose owner annotation is rewritten to name another recorded UID of the same target stays with the object that holds the claim by honoured record, `creationTimestamp` and name; an `Indeterminate` object counts as honoured | `k3sm/pkg/keystore/reconcile::TestAnnotationRewriteCannotTakeOverTarget` | pending: the KeyDelivery reconciler (authority) |
| U112 | the order is commit, then append, then reply: an append that fails after the commit answers `ok` with the warning `committed; audit failed`, the server then refuses user mutations except the revocation class, and `doctor` counts the unaudited operations | `k3sm/pkg/keystore/socket::TestAuditFailureAfterCommitRepliesCommittedAuditFailed`, `k3sm/cmd/k3sm::TestDoctorCountsUnauditedOps` | pending: the socket operations |
| U113 | the listener refuses to start unless the server's effective uid is the service uid (the `_k3sm` uid install creates): a rootless `k3sm server`, whose Pods inherit the daemon's login uid, runs no listener, and the server log and `doctor` say "user scope needs the installed server" (seam: euid source) | `k3sm/pkg/keystore/socket::TestListenerRefusesUnlessServiceUID` | pending: the socket listener |
| U114 | `rm-scope` writes `keystore-removed-scopes.json` in the data root, root-owned, through the data-root descriptor rules, listing the removed scope's uid and bound GeneratedUID before it removes the scope; only a scope listed there counts as removed for the finalizer, and a plain `ErrScopeAbsent` stays non-definitive and keeps the finalizer (seam: euid source) | `k3sm/cmd/k3sm::TestRmScopeRecordsRemovedScope`, `k3sm/pkg/keystore/reconcile::TestOnlyRecordedRemovalCountsAsWithdrawn` | pending: the KeyDelivery reconciler (lifecycle) |
| U115 | `rm-scope` names each blocking binding, a RoleBinding with its namespace; `--remove-bindings` deletes each listed binding through the admin client before anything else changes, and a failed delete stops the verb, changing nothing further | `k3sm/cmd/k3sm::TestRmScopeNamesBindingsAndRemovesThem` | pending: the KeyDelivery reconciler (lifecycle) |
| U116 | the Pod uid refusal applies to native Pods only: a vm Pod with `runAsUser: 1000` is allowed, since a guest uid has no host meaning, while a native Pod with the same drop target is refused; the guest's groups skip the host group rules the same way | `runtimed/pkg/runtime::TestVMPodGuestUIDNotRefused` (the refusal sits on the native spawn path, `checkPodUID` in `pkg/runtime/security.go`; the same test, in `pkg/runtime/vmcontainers_test.go`, also pins that a vm Pod's `runAsGroup` of 1000 reaches the guest's GID and SupplementalGIDs unrefused) | checked: runtimed's sandbox change |
| U118 | the old log is never service-user-owned while unflagged (integration, a root-run row: `--root`): in `audit --rotate` and `floor --rebuild` the step that clears `sappnd` on the old file, and on each archive rotate shifts, also `fchown`s it to root and `fchmod`s it 0600 on the verb's descriptor; the service user's `open(O_WRONLY\|O_TRUNC)` of each, between the clear and the re-flag, gets EACCES and changes no byte | `k3sm/cmd/k3sm::TestMaintenanceOldFileRootOwnedWhileUnflagged` (integration, root-run) | pending: the append-only files |
| U119 | the floor lock is `keystore-lock`, a root 0600 file in the data root that only root can open, taken by every root verb that writes the floor or a keystore file in the data root (`put`, `rotate`, `rm`, `rewrap`, `deliver system/…`, the floor raise of `list` and `show`, `rm-scope`, `floor --rebuild`, `audit --rotate`); run as root (a root-run row, `--root`), a non-root process other than the service user holding the old data-root flock blocks none of them | `k3sm/pkg/keystore::TestNonRootDataRootFlockBlocksNoRootVerb` (integration, root-run) | checked as a root-run row (`--root`) for the verbs that exist: `put`, `rotate`, `rm`, `rewrap` and the floor raise; `rm-scope`, `floor --rebuild` and `audit --rotate` take it as they land (the append-only files) |
| U120 | the activated listening descriptor reaches no child (integration): the server spawns each child type, an `exec.Command` child, the runtimed helper and a Pod through the exec shim, lists each one's open descriptors, and the listening socket is among none of them | `k3sm/pkg/keystore/socket::TestActivatedListenerReachesNoChild` (integration) | pending: the socket listener |
| U121 | under activation, a client whose connected peer reads as uid 0 or as launchd's code refuses and writes nothing; U36 is never relaxed to accept uid 0, and if K7a finds the client-side peer names launchd the self-bind form ships (seams: peer-credential source, client side; server code identity) | `k3sm/cmd/k3sm::TestClientRefusesLaunchdAsPeer` | pending: the socket listener |
| U122 | when K7a finds that a Pod can obtain the server's listener from launchd, the self-bind form ships and every rendered Pod profile denies the launchd socket-activation lookup | `k3sm/pkg/provider::TestPodProfileDeniesLaunchdSocketActivation`; rig leg E27 | pending: the socket listener |
| U123 | same-target cross-record deletion: the orphan sweep, a lost-authority delete and `rm-scope` never delete a Secret that another honoured record claims at the same `(namespace, secretName)`; a forged owner annotation naming one uid's tombstone on another uid's live Secret deletes nothing; the owner annotation never selects which record's tombstone governs a delete; nothing is charged to the victim | `k3sm/pkg/keystore/reconcile::TestForgedTombstoneAnnotationOnOtherUsersLiveSecretIsNotDeleted` | pending: the KeyDelivery reconciler (lifecycle) |
| U124 | a tombstone is pruned when its target is not this UID's owned Secret on two observations at least 60 s apart, not only on a Get that answers not found: a target occupied by another Secret still prunes; a failed Get keeps it | `k3sm/pkg/keystore/reconcile::TestTombstonePrunesWhenTargetOccupied` | pending: the KeyDelivery reconciler (lifecycle) |
| U125 | every reconciler Secret delete or update and every `rm-scope` delete passes `Preconditions{UID, ResourceVersion}` from the ownership read: a fake client swaps the Secret between the read and the delete, the delete is refused, and the outcome is `Indeterminate` | `k3sm/pkg/keystore/reconcile::TestDeleteRefusedWhenSecretSwappedAfterRead` | pending: the KeyDelivery reconciler (lifecycle) |
| U126 | the reconciler budget is split by source, 384 KiB for forged-Secret lines, 384 KiB for repairs, 256 KiB for pre-frame refusals, the forged and repair parts capped at 64 KiB per namespace; one source or one namespace spending its part leaves every other part whole; the dropped count is persisted in the next summary line written for that source, not kept only in memory | `k3sm/pkg/keystore/reconcile::TestReconcilerBudgetSplitBySource`, `TestDroppedCountPersistedInNextSummary` | pending: the KeyDelivery reconciler (lifecycle) |
| U127 | `ErrScopeOwnerChanged` is Indeterminate plus a `doctor` report, not a deleting outcome, until a K7a amendment records GeneratedUID stability across Migration Assistant, a macOS upgrade and a directory rebind: no Secret is deleted on it, however many spaced observations see it, and `doctor` names the scope (seam: GeneratedUID lookup) | `k3sm/pkg/keystore/reconcile::TestScopeOwnerChangedIsIndeterminate`, `k3sm/cmd/k3sm::TestDoctorReportsOwnerChangedScope` | pending: the user-scope store |
| U128 | Rewrap of each `scope.key`, and every root write under `server/keystore/`, walks by descriptor (integration, a root-run row: `--root`): a planted symlink, FIFO or swapped directory under `.user/` refuses Rewrap and changes no record | `k3sm/pkg/keystore::TestRewrapWalksScopeKeysByDescriptor` (integration, root-run) | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U129 | `floor --rebuild` reads every scope whose `scope.key` opens under `W` without the GeneratedUID check: a departed account (`ErrScopeOwnerUnknown`) and an owner change each get their lines and block nothing (seam: GeneratedUID lookup) | `k3sm/cmd/k3sm::TestRebuildReadsScopeWithoutOwnerCheck` | pending: the user-scope store |
| U130 | a scope listed in `keystore-removed-scopes.json` for its bound GeneratedUID is definitive for claims, so its stale objects lose their claim; `rm-scope` deletes that scope's KeyDeliveries, each by its recorded namespace and name with a UID precondition | `k3sm/pkg/keystore/reconcile::TestRemovedScopeLosesClaim`, `k3sm/cmd/k3sm::TestRmScopeDeletesScopeKeyDeliveries` | pending: the KeyDelivery reconciler (lifecycle) |
| U131 | the listener refuses to start on a data root mounted with `MNT_IGNORE_OWNERSHIP`, read with `fstatfs` on the data-root descriptor | `k3sm/pkg/keystore/socket::TestStartRefusesIgnoreOwnershipMount` | pending: the socket listener |
| U132 | `.user/<uid>/` is 0700 and `scope.key` and `deliveries` are 0600, all the service user's; a scope whose directory or files have another owner or a wider mode is refused | `k3sm/pkg/keystore::TestUserScopeFileModes` | pending: the user-scope store |
| U133 | `keystore-removed-scopes.json` is root-owned 0644, under the `keystore-` prefix the Pod denies cover; a file that is not root's or is group- or other-writable is refused, and the parse is strict (an unknown field, a duplicate uid or trailing data refuses it, and a refused file counts as no listing) | `k3sm/cmd/k3sm::TestRemovedScopesFileRootOwnedAndMode`, `TestRemovedScopesFileStrictParse` | pending: the KeyDelivery reconciler (lifecycle) |
| U134 | the reconciler's store interface reads a value only for an authorised delivery: its value read takes the authorisation the checks produced, and no other method returns a value | `k3sm/pkg/keystore/reconcile::TestStoreInterfaceReadsValueOnlyForAuthorisedDelivery` | pending: the KeyDelivery reconciler (lifecycle) |
| U135 | the KeyDelivery admission policy's `failurePolicy` is `Fail`, and the namespace-controller exemption admits DELETE only: the namespace controller's UPDATE of another author's object is refused | `k3sm/pkg/policy::TestKeyDeliveryVAPFailurePolicyFail`, `TestNamespaceControllerExemptOnlyForDelete` | pending: KeyDelivery authoring |
| U136 | every root verb and `doctor` line that prints annotation text strips control characters first: an owner or entry annotation carrying terminal escapes prints without them | `k3sm/cmd/k3sm::TestRootVerbsStripAnnotationControlChars` | pending: the socket operations, the KeyDelivery reconciler (lifecycle) |
| U137 | the listener refuses a sandboxed peer before the first frame: it calls `sandbox_check` on the peer's audit token through the peer-sandbox source, a constructor parameter that refuses nil, so a Pod process is refused whatever its uid (seam: peer-sandbox source) | `k3sm/pkg/keystore/socket::TestListenerRefusesSandboxedPeer`; rig leg E26 | pending: the socket listener |
| U138 | `--listed` fails on a duplicated U or E id: in the script's rows, its expected-row list, one mode's row list, or the design's gate and leg tables | `hack/acceptance/keystore.sh --listed` (its duplicate-id lint, `lint_unique_ids`) | pending: the typed-credential design |
| U139 | `items` required, no default, 1 to 8, unique keys, the key pattern with `.` and a `..` prefix refused, both `maxLength`s, immutable as a map (a reorder accepted, a change refused), CEL cost within budget; no `dataKey` | `apis/config/crd::TestKeyDeliveryItemsSchema`, `TestItemKeyMatchesIsConfigMapKey`, `TestKeyDeliveryHasNoDataKey`, `TestItemsReorderAcceptedChangeRefused`, `TestItemsCELCostWithinBudget` | pending: the typed KeyDelivery API |
| U140 | the `field` enum equals the credential table's union; a KeyDelivery naming `refreshToken` is refused by the schema; rig leg E31 | `apis/config/crd::TestFieldEnumEqualsCredentialTable`, `TestSchemaRefusesRefreshTokenField` | pending: the typed KeyDelivery API |
| U141 | the credential leaf: kind names, field table vectors, no refresh field, the item type, the refresh-owner vectors, closed validity, Event and `refresh_state` sets, the metadata keys; stdlib only | `apis/keystore/credential::TestFieldTableVectors`, `TestNoRefreshField`, `TestRefreshOwnerGrammarVectors`, `TestNameSetsClosed`, `TestImportsStdlibOnly` | pending: the typed KeyDelivery API |
| U142 | the CRD descriptions list the `CredentialValid` reasons and `ProjectionInvalid`, say `Ready` means delivered and that Valid, Expiring and RefreshFailing share True; every condition has `observedGeneration` | `apis/config/crd::TestKeyDeliveryReasonDescriptions`, `TestConditionsCarryObservedGeneration` | pending: the typed KeyDelivery API |
| U143 | the envelope matches committed per-kind golden vectors; unknown tag, duplicate, disorder, missing field or out-of-bound field is `ErrCorrupt`; the fuzz invariants hold | `k3sm/pkg/keystore/typed::TestEnvelopeGoldenVectors`, `TestEnvelopeRejectsUnknownTagDuplicateAndOrder`, `FuzzEnvelopeParse` | pending: the typed store |
| U144 | token and oauth require a sealed `issuedAt`/`accessIssuedAt` stamped from the clock seam; editing the `created` header changes no typed time | `k3sm/pkg/keystore::TestTypedIssuedAtStampedAndSealed`, `TestCreatedHeaderEditChangesNoTypedTime` | pending: the typed store |
| U145 | a relabelled typed record fails to open; kind-byte table: 6 to 0xFC and an unknown envelope version are `ErrKindUnsupported`, 0xFD and 0xFE `ErrCorrupt`; `list` shows `unsupported` | `k3sm/pkg/keystore::TestTypedKindRelabelFailsOpen`, `TestKindByteTable` | pending: the typed store |
| U146 | `rotate` and `put` over an existing entry cannot change its kind (`ErrKindMismatch`) | `k3sm/pkg/keystore::TestRotateAndPutCannotChangeKind` | pending: the typed store |
| U147 | token needs `expiresAt`; oauth needs access token, access expiry, refresh token and an owner in the grammar | `k3sm/pkg/keystore::TestTypedPutValidation` | pending: the typed store |
| U148 | SSH generate uses the random seam; import accepts unencrypted OpenSSH ed25519 only; the fingerprint equals a committed `ssh-keygen -l` vector | `k3sm/pkg/keystore/typed::TestSSHGenerateAndImport`, `TestSSHFingerprintMatchesOpenSSH` | pending: the typed store |
| U149 | write-only, structurally: a planted refresh token appears in no result of any exported method or consumer interface, raw, base64 or URL-encoded; `Get` returns a `typed.Credential` for kinds 3 to 5; only `refresh` (and the installing `pkg/keystore`) imports `internal/refreshopen` | `k3sm/pkg/keystore::TestPlantedRefreshTokenNeverReturned`, `TestGetReturnsRedactedCredential`, `TestRefreshOpenerImportGraph` | pending: the typed store |
| U150 | `RotateIf` refuses a stale version | `k3sm/pkg/keystore::TestRotateIfStaleVersionRefused` | pending: the typed store |
| U151 | oauth keeps current and one previous; the low-water mark is in the sealed pointer (24 bytes only after a prune, 16 means `low = 1`); crash-safe at every step, prune included (the prune cases of the crash test) | `k3sm/pkg/keystore::TestOAuthPruneKeepsTwo`, `TestPointerLowWaterMark`, `TestRotateCrashAtEveryStep` | pending: the typed store |
| U152 | a pruned oauth entry: List shows it healthy, Rewrap re-seals `low..current`, Delete removes leftovers, a gap inside the range is damage, a copied-back pointer is caught | `k3sm/pkg/keystore::TestListPrunedOAuthEntryNotCorrupt`, `TestRewrapHandlesPrunedOAuth`, `TestDeletePrunedOAuthEntry`, `TestGapInsideCommittedRangeIsCorrupt`, `TestCopyBackAcrossPruneCaught` | pending: the typed store |
| U153 | `--from-version` is refused for oauth | `k3sm/pkg/keystore::TestFromVersionRefusedForOAuth` | pending: the typed store |
| U154 | every `Fuzz*` target in the keystore packages has a non-empty committed seed directory | `k3sm/pkg/keystore::TestEveryFuzzTargetHasSeeds` | pending: the typed store |
| U155 | HELLO lists capabilities; mutating ops refuse an unknown header (`unknown-header`), non-mutating ops tolerate it; the CLI refuses a typed request to a daemon without the capability | `k3sm/pkg/keystore/socket::TestHelloListsCapabilities`, `TestMutatingOpRefusesUnknownHeader`, `TestNonMutatingOpToleratesUnknownHeader`, `k3sm/cmd/k3sm::TestCLIRefusesTypedAgainstOldDaemon` | pending: the typed verbs |
| U156 | an oauth put takes an RFC 6749 response, stamps times from the clock, drops `id_token` and unknown fields; an `error` response is refused printing only the code | `k3sm/pkg/keystore/socket::TestPutOAuthTokenResponse`, `TestTokenResponseWithErrorRefused`, `FuzzTokenResponseParse` | pending: the typed verbs |
| U157 | `generate` returns only the public key; `pubkey` prints only the public line | `k3sm/pkg/keystore/socket::TestGenerateReturnsPublicKeyOnly`, `k3sm/cmd/k3sm::TestKeysPubkeyPrintsOnlyPublicKey` | pending: the typed verbs |
| U158 | the kind flags; per-kind `exec` field defaults, ssh needs a field; `show --field` and `exec --field` refuse `refreshToken`; `kind-mismatch` on the wire | `k3sm/cmd/k3sm::TestKeysPutKindFlags`, `TestKeysExecFieldDefaults`, `TestFieldSelectionRefusesRefreshToken`, `k3sm/pkg/keystore/socket::TestRotateKindMismatch` | pending: the typed verbs |
| U159 | `list -o json` and the socket `list` carry the typed metadata (snake_case) and no token bytes (planted) | `k3sm/cmd/k3sm::TestKeysListJSONTypedMetadata` | pending: the typed verbs |
| U160 | `typed.Project` is exact per kind and supports exactly the `apis` table's fields; a planted refresh token is in no projection for any item set | `k3sm/pkg/keystore/typed::TestProjectFieldsPerKind`, `TestProjectSupportsExactlyCredentialTable`, `TestProjectNeverEmitsRefreshToken` | pending: typed projection |
| U161 | the Secret's data keys equal `items`; a field wrong for the kind gives `ProjectionInvalid` with the Secret unchanged; digest golden vectors over entry, namespace, secretName and key-sorted items, order-insensitive | `k3sm/pkg/keystore/reconcile::TestItemsProjectExactKeys`, `TestProjectionInvalidLeavesSecret`, `TestDigestGoldenVectors` | pending: typed projection |
| U162 | root-file `items` are parsed strictly and use the same projection | `k3sm/pkg/keystore/reconcile::TestRootFileItemsStrictAndProjected` | pending: typed projection |
| U163 | `--item`, `--data-key` shorthand, per-kind defaults; an ssh delivery without items is refused | `k3sm/cmd/k3sm::TestDeliverItemDefaultsPerKind`, `TestDeliverSSHWithoutItemsRefused` | pending: typed projection |
| U164 | `ErrKindUnsupported` and `ErrCorrupt` on a typed entry are `Indeterminate`; encryption off refuses every typed kind (G18) | `k3sm/pkg/keystore/reconcile::TestTypedEntryErrorsAreIndeterminate`, `TestEncryptionOffRefusesTypedKinds` | pending: typed projection |
| U165 | the `CredentialValid` table on a fake clock, thresholds from `issuedAt`, the oauth rules, the nil-`RefreshStatus` fallback, `observedGeneration` set | `k3sm/pkg/keystore/reconcile::TestCredentialValidConditionTable`, `TestExpiringThresholdUsesIssuedAt`, `TestNilRefreshStatusUsesStoredExpiry` | pending: expiry and revocation |
| U166 | Events: `events.k8s.io`, `related` the Secret, Warning or Normal per reason, once per real transition with hysteresis; prior state from persisted status, so a restart re-emits none | `k3sm/pkg/keystore/reconcile::TestCredentialEventsOncePerTransition`, `TestCredentialEventTypesAndRelated`, `TestRestartReemitsNoCredentialEvent` | pending: expiry and revocation |
| U167 | messages carry names, times and a closed cause only (planted token and error body absent) | `k3sm/pkg/keystore/reconcile::TestCredentialEventsCarryNamesOnly` | pending: expiry and revocation |
| U168 | expiry never deletes the Secret and never changes `Ready`; requeue at the next threshold | `k3sm/pkg/keystore/reconcile::TestExpiredKeepsSecret`, `TestRequeueAtNextThreshold` | pending: expiry and revocation |
| U169 | the mount observer is level-based: one baseline line at start, a relist emits nothing, tombstones and terminal pods unmount | `k3sm/pkg/keystore/mountaudit::TestStartupBaselineOneLine`, `TestRelistEmitsNothing`, `TestTombstoneAndTerminalPodsUnmount` | pending: the mount audit |
| U170 | `pod-refresh` only for volume and projected refs without `subPath`; env, envFrom and `subPath` get `refreshes: false` and never `pod-refresh` | `k3sm/pkg/keystore/mountaudit::TestPodRefreshOnlyForRefreshingRefs` | pending: the mount audit |
| U171 | the mount-line field set is closed; lines are built from metadata only, on the error path too (planted token) | `k3sm/pkg/keystore/mountaudit::TestMountLineFieldsClosed`, `TestMountLinesMetadataOnly` | pending: the mount audit |
| U172 | a first-seen pair is never rate-limited; repeats are limited per namespace and globally, with a summary; all stop at the soft cap; never `ErrLogFull`; an append failure fails nothing; server class | `k3sm/pkg/keystore/mountaudit::TestFirstSeenNeverDropped`, `TestRepeatsRateLimitedAndGlobalCap`, `TestMountLinesStopAtSoftCap`, `TestMountLinesNotCharged` | pending: the mount audit |
| U173 | the provider's `MountObserver`: at the caller of `Secret()`, metadata from the lister, once per pod per version, labelled Secrets only, bounded per pod track, no re-emit after a restart, no value in the Event | `k3sm/pkg/provider::TestKeystoreSecretMountedOncePerVersion`, `TestMountObserverReadsListerNotData`, `TestMountObserverRestartReplay`, `TestKeystoreMountEventCarriesNoValue` | pending: the mount audit |
| U174 | a `doctor` row and a server Warn at 80% of the soft cap | `k3sm/cmd/k3sm::TestDoctorAuditSoftCapWarnAt80` | pending: the mount audit |
| U175 | the profile file is strict and fuzzed; owner and mode `0640 root:_k3sm` through the floor helper's stat seam; `--client-secret-entry` checks; `revokedErrorCodes` default | `k3sm/pkg/keystore/refresh::TestProfileFileStrict`, `TestProfileFileOwnerAndMode`, `FuzzProfileFile`, `TestRevokedErrorCodesDefault` | pending: refresh profiles |
| U176 | `refresh-profile add` validates the URL: https, no userinfo, no fragment, no IP literal without `--allow-private` | `k3sm/cmd/k3sm::TestRefreshProfileAddValidatesURL` | pending: refresh profiles |
| U177 | `Proxy` is nil; a redirect is `response-invalid`; 64 KiB cap; timeout; a 200 with an `error` field is an error (fake `RoundTripper`) | `k3sm/pkg/keystore/refresh::TestRefreshClientProxyNil`, `TestRefreshClientRefusesRedirect`, `TestRefreshResponseCap`, `TestHTTP200WithErrorIsError` | pending: refresh profiles |
| U178 | the dial guard's deny table on synthetic addresses, the `--allow-private` override, and a rebind to 169.254.169.254 through a fake resolver; rig leg E36 | `k3sm/pkg/keystore/refresh::TestDialGuardDenyTable`, `TestDialGuardAllowPrivate`, `TestDialGuardRefusesRebindToLinkLocal` | pending: refresh profiles |
| U179 | error mapping against golden response fixtures; the cause set is closed (`dns`, `clock-skew` included); a `RetrieveError` body never reaches a log or error | `k3sm/pkg/keystore/refresh::TestErrorMappingGoldenFixtures`, `TestRefreshCausesClosedSet`, `TestRetrieveErrorBodyNeverSurfaces` | pending: refresh profiles |
| U180 | the refresh package's `TestMain` stubs its `RoundTripper` factory, resolver, `Control` and clock seams; refresh and mountaudit are on U58's seam-package list | `k3sm/pkg/keystore/refresh::TestRealPrimitivesUnreachable`, `k3sm/pkg/keystore::TestEverySeamPackageHasAGuard` | pending: refresh profiles |
| U181 | `refresh-profile test` sends a random refresh token, never a stored one, and passes only on a revoked-code answer | `k3sm/cmd/k3sm::TestRefreshProfileTestSendsNoStoredToken` | pending: refresh profiles |
| U182 | schedule at half of `accessExpiresAt − accessIssuedAt`, lead, jitter, minimum interval, nearest-expiry first, backoff bound, retry at the maximum past access expiry (`synctest`, in-bubble fake `RoundTripper`) | `k3sm/pkg/keystore/refresh::TestRefreshSchedule`, `TestRetriesPastAccessExpiry` | pending: the refresher |
| U183 | success rotates via `RotateIf` and prunes; a missing `refresh_token` keeps the old one; one compacted summary line per entry per UTC day, at most 512 bytes, charged to no uid | `k3sm/pkg/keystore/refresh::TestRefreshRotatesEntry`, `TestRefreshKeepsRefreshTokenWhenNotReturned`, `TestRefreshOkCompactedPerDay`, `TestRefresherLinesServerClass` | pending: the refresher |
| U184 | a revoked code parks; unpark by a new version at most once per 10 minutes; `refresh-state.json` holds names and states only; losing it costs one retry | `k3sm/pkg/keystore/refresh::TestRevokedCodeParks`, `TestUnparkRateLimited`, `TestRefreshStateFileHoldsNoSecret`, `TestLostRefreshStateCostsOneRetry` | pending: the refresher |
| U185 | an owner's rotate during a refresh wins | `k3sm/pkg/keystore/refresh::TestOwnerRotateDuringRefreshWins` | pending: the refresher |
| U186 | `local` is never server-refreshed; per-uid-per-profile fairness; global and per-user caps | `k3sm/pkg/keystore/refresh::TestLocalOwnerNeverServerRefreshed`, `TestRefreshFairnessPerUIDPerProfile`, `TestRefreshCaps` | pending: the refresher |
| U187 | a second server joining mid-run pauses the refresher before its next refresh; removing it resumes with no restart | `k3sm/pkg/keystore/refresh::TestSecondServerPausesAndRemovalResumes` | pending: the refresher |
| U188 | SIGTERM stops new refreshes and drains in-flight ones within 10 s; no refresh starts under the maintenance marker or exclusive lock; the lock order holds | `k3sm/pkg/keystore/refresh::TestShutdownDrainsWithin10s`, `TestNoRefreshUnderMaintenance`, `TestLockOrderLeaseThenLock` | pending: the refresher |
| U189 | `refresh-now` is owner-only, rate-limited, `refresh-not-owned` for `local`, sends nothing for a parked pair | `k3sm/pkg/keystore/socket::TestRefreshNowOwnerOnly` | pending: the refresher |
| U190 | the refresher `doctor` rows; every state change logs at Warn or Error under `io.k3sm.keystore`, names and causes only | `k3sm/cmd/k3sm::TestDoctorRefresherRows`, `k3sm/pkg/keystore/refresh::TestStateChangesLogAtWarn` | pending: the refresher |
| U191 | `examples/keydelivery-github.yaml` validates against the `apis` CRD schema; `limitations.md` lists the typed-credential residuals | `k3sm/examples::TestKeyDeliveryExamplesValidateAgainstCRD`, `TestLimitationsListTypedResiduals` | pending: the typed-credential docs |
| U192 | the floor's tombstones: a completed Delete buries the floor's live generation for the name (with no live record, the directory's only when its pointer authenticates under it with the master, so a planted generation buries nothing) with a delete sequence, without the master too; a later Put keeps the buried set; at most 64 buried generations a name; tombstones use at most 1 MiB of the 4 MiB floor and are pruned oldest first, never a live entry, each prune logged at Warn; a floor with no `tombstones` field parses, and a burial is parsed as strictly as an entry; `keys floor merge` carries every burial of the moved-aside floor into a restored one, burying a generation it holds live and each moved-aside live generation it does not hold live (--keep spares only the restored generation; an unmatched --keep refuses), fencing a restored generation, and recording a kept one the restored floor does not record, with a high-water mark one past the higher of the moved-aside sequence and mark (+1) that readers and the raise honour and Rotate seals above, under keystore-lock alone, reading only the data root's keystore-floor.json.pre-restore (no path; a guard file replaced during the merge refuses it), reading the restored pointers only from the root-only pre-restore.d/restored the recipe stages (anything at the keystore directory, a symlink counted, refuses; with nothing staged a merge that would change the floor refuses), fencing above the moved-aside tree's authenticated pointer too (pre-restore.d/keystore), handing the staged tree to the service user through descriptors (fchownat, never followed) and moving it into place with renameatx_np RENAME_EXCL after the floor write (a failed move exits 5 and a rerun completes it), raising a restored record to its authenticated pointer by at most one sequence (a higher pointer is unverified and fenced), refusing an absent live floor, the live floor itself and a merge that would retire every moved-aside live record, renaming its input to keystore-floor.json.merged-<unix> (a rerun after a failed rename writes nothing and renames it; that failure exits 5), pruned and reported, refusing a write that would drop a burial it adds or one rm wrote under the guard (numbered above guardEraSeq, kept newer than the merged ones), naming keys rm only when the floor size binds and --accept-drops (which writes it, prints each drop and exits 4) when the tombstone budget or the per-name cap does, --dry-run writing nothing; while keystore-floor.json.pre-restore is in the data root Put, Rotate and Rewrap refuse, Delete refuses with no live floor, RaiseFloor raises nothing and the delivery reconciler delivers nothing (guarded delivery); a committed change whose floor write evicted a burial exits 4, and list and show warn of it and exit 0 | `k3sm/pkg/keystore::TestTombstoneKeptByPut`, `TestDeleteWithoutMasterTombstones`, `TestTombstonePrune`, `TestTombstoneNeverRefusesPut`, `TestPruneLogsAtWarn`, `TestParseFloorTombstones`, `TestFloorOpsProperty`, `TestDeleteSequenceNeverWraps`, `TestDeleteIgnoresPlantedGeneration`, `TestPerNameCapIsBackstop`, `TestDeleteWithoutMasterWarnsUnrecorded`, `TestDeleteReportsEvictedTombstone`, `TestDeleteWarnsUnrecordedWithMaster`, `TestFloorMergeSemantics`, `TestFloorMergeCapsAndPrune`, `TestFloorMergeRefusesUntrusted`, `TestFloorMergeBuriesRevokedLive`, `TestMergeFloorKeep`, `TestFloorMergeRetiresAsideLive`, `TestFloorMergeRefusesUntrustedPlace`, `TestDeleteReportsAnyEvictedTombstone`, `TestFloorHighWaterEncoding`, `TestFloorHighWaterCheckRaise`, `TestFloorMergeFencesAbandonedHistory`, `TestMergeFloorIgnoresEntryLock`, `TestMergeFloorRefusesWrongInput`, `TestPendingMergeGuard`, `TestEvictionReportedCommitted`, `TestMergeFloorRefusesUnmatchedKeep`, `TestMergeFloorRefusesDroppingItsOwnBurials`, `TestFloorMergeKeepRecordsAsideLive`, `TestDeleteNotFoundReportsEviction`, `FuzzParseFloor`, `FuzzMergeFloor`, `TestMergeFloorReadsOnlyTheGuardFile`, `TestFloorMergeBoundsRestoredRaise`, `TestGuardEraBurialSurvivesPressuredMerge`, `TestGuardEraTombstoneBudget`, `TestGuardEraBurialPerNameCap`, `TestPendingMergeDeleteNeedsLiveFloor`, `TestMergeFloorRefusesRetiringEverything`, `TestFloorMergeRefusesExistingTarget`, `TestFloorMergeFencesAboveAsidePointer`, `TestFloorMergeMovesStagedTree`, `TestFloorMergeNeedsStagedTree`, `k3sm/cmd/k3sm::TestKeysEvictionExitsCommitted`, `TestKeysPendingMergeGuard`, `TestKeysReadVerbsWarnEviction`, `TestKeysFloorMergeTakesNoFile`, `TestKeysFloorMergeAcceptDrops`, `TestKeysFloorMergeDryRun` | checked: the floor's tombstone |

### Rig legs

The end-to-end gate is `hack/acceptance/keystore.sh --lab` on the two-Mac lab rig, from a
recorded build, with both nodes' `k3sm version` in the log, public surfaces only (`k3sm`,
`kubectl`, a Pod), every test object deleted at the end and the rig left with both nodes
Ready. The server is one Mac and the old worker the other. "The user" is the operator's own
login user over SSH, the only real login user on the rig; no second account is created, and
the cross-user refusal is covered by U45, not on the rig. **Rig-only** says whether a unit row
also covers the property or only the rig can show it. **Fails without** names what the leg
shows on a build lacking the feature; every leg must go red there, and the gate runs each leg
once against the previous release's build to record that red. Every leg is pending until the
end-to-end rig gate lands. The user scope is complete only when every leg passes on the rig,
E20 attended.

| leg | what | expected | rig-only | fails without |
|---|---|---|---|---|
| E1 | preconditions | secrets encryption on; one server; `keystore-sock/` root:wheel 0755 with `keys.sock` from launchd, both logs present, service-user 0600, `SF_APPEND` set; `doctor` user-scope row on; `keystore.sh --check` exits 0 on the build | no (U21) | the append-only files: no files, `doctor` row off |
| E2 | the user, no sudo: `printf … \| k3sm keys put user/<me>/e2e-token` (short-name form) | exit 0; the CLI prints the resolved `user/<uid>`; `k3sm keys list` shows it; the audit log has a `put` line with no value | yes | the socket operations: connect refused, error names `sudo k3sm install` |
| E3 | an admin binds `k3sm:keystore-delivery-author` and the built-in `edit` ClusterRole for `k3sm:local:<uid>` in `ks-e2e`; the user runs `k3sm keys deliver user/<uid>/e2e-token --namespace ks-e2e --secret e2e-token --data-key TOKEN` | `KeyDelivery` `Ready`, reason `Delivered`, `observedGeneration` current; the object's `requestedBy` is `k3sm:local:<uid>`; a Pod mounting Secret `e2e-token` reads exactly the stored bytes | yes | the KeyDelivery reconciler (authority): no Secret, no status |
| E4 | the user rotates (`rotate --in -`), then `rotate --from-version 1` | the Pod's mounted file moves to v2, then to v1's bytes as v3, within one sweep each | yes | the `k3sm keys` verbs: `--from-version` unknown flag |
| E5 | `k3sm keys exec user/<uid>/e2e-token --env TOKEN -- /usr/bin/env` | the child sees `TOKEN`; the CLI wrote nothing else; `ps` during the run shows no value in argv; one `exec-read` audit line | no (U37) | the non-root CLI and `exec`: unknown verb |
| E6 | as the operator's login user only: `list`, `exec`, `rotate`, `rm` and `deliver` of `user/<an unused other uid>/e2e-token` and of `system/e2e-sys`; then a connect to `keys.sock` as root and as the service user | `not found` each time for the names, text identical to an absent entry of the user's own, and `refused` audit lines attributed to the user's uid; root and the service user are refused at accept, before any frame | partly (U26, U45): the rig runs only what one real user can reach, the cross-user case is unit-tested | the socket operations: the other uid's or the system entry's ops are answered (U45 red); the socket listener: root or the service uid is served |
| E7 | admin copies E3's KeyDelivery YAML into `ks-e2e-2` (where the user also has the role) | `Authorized=False`, reason `NotRecorded`, no Secret: the UID is not in the user's record | no (U42) | the KeyDelivery reconciler (authority): a Secret appears in `ks-e2e-2` |
| E8 | admin strips the CRD's transition rules (a test patch, restored at the end) and edits E3's `spec.secretName` | `Authorized=False`, `NotRecorded` (digest mismatch); the original Secret deleted; no Secret under the new name | yes | the target digest: a Secret appears under the new name |
| E9 | `sudo cp` saves `current`, the user rotates, `sudo cp` puts the old `current` back; then the same for a `system/` entry | user `list` and `sudo k3sm keys list` each mark the entry `corrupt` with the floor message; `floor --rebuild` is not run | no (U20) | the append-only files: the old value is served |
| E10 | a native Pod (pinned by `nodeName`, darwin selector) tries `connect(2)` to `keys.sock` and to read `server/keystore`, `keystore-sock/`, both logs and Phase A's two files, then a file write, a create, an unlink and a rename on `keystore-sock/`, `keys.sock` and every `keystore-*` file, and a `network-bind` of a unix socket in `keystore-sock/`, each through the canonical path, `/System/Volumes/Data/private/var/lib/k3sm/...` and the data volume's mount path; then a vm Pod on the same node tries to reach `keys.sock` and the data root from the guest | EPERM for each from the native Pod; the guest has no path to the data root and cannot reach the socket | no (U16) | runtimed's sandbox change: the Phase A files read (the red result K0 leg 4 records) |
| E11 | admin removes the user's RoleBinding in `ks-e2e` | the Secret is deleted after two spaced observations, so the leg waits at least 90 s (two observations 60 s apart, plus a 30 s sweep) before it judges; `Authorized=False`, `NotAuthorized` | no (U44) | the KeyDelivery reconciler (lifecycle): the Secret stays |
| E12 | root scope: `sudo k3sm keys put system/e2e-sys`, `sudo k3sm keys deliver system/e2e-sys --namespace ks-e2e`; then the user, with no sudo, tries `k3sm keys deliver`, `list` and `exec` on `system/e2e-sys` | root's Secret is delivered and stays (G20); each of the user's attempts answers `not found` and nothing reaches `ks-e2e-2`: the user cannot read or deliver the system entry. The leg does not claim the user cannot discover the name, which Phase A's 0644 files show (residual 11) | partly (U45): the root delivery is rig-only | root delivery: root delivery missing; the socket operations: a non-root user can name a system entry |
| E13 | a ServiceAccount token creates a KeyDelivery | refused at admission | no (U40) | KeyDelivery authoring: the object is created |
| E14 | `k3sm keys undeliver` on E3's object, then `kubectl delete` of a second one | each Secret deleted before its object goes; the hint printed; no orphan Secret once the leg has waited at least 90 s (two observations 60 s apart, plus a 30 s sweep) | no (U44) | the KeyDelivery reconciler (lifecycle): the object hangs or the Secret stays |
| E15 | **upgrade** from the previous release's install tree (its signed build installed, then this build over it, then `sudo k3sm install`) | system scope intact; user scope comes on after the install, off with the Warn and `doctor` row before it | yes | upgrade visibility: user scope silently off |
| E16 | **rollback** to the previous release, then forward again | the old build runs with the keystore files unused; after rolling forward the user's entries, records and Secrets are intact and re-adopted | yes | the rollback guard: entries unreadable after the round trip |
| E17 | **backup and restore** round trip: copy the data root's keystore set aside with `cp`, remove it, copy it back, then `floor --rebuild` and `audit --rotate` | before the rebuild the listener refuses (flags clear); after it every entry opens and both logs are flagged | no (U25) | the flag check: the listener runs on unflagged logs |
| E18 | an **old worker**: the second Mac on the previous release joins this server | worker Ready; Pods there mount delivered Secrets; no keystore listener or reconciler on the worker | yes | server-only listener: a listener on an agent node |
| E19 | `sudo launchctl kickstart -k system/io.k3sm.server` while a client is connected mid-request | the client gets a clean error, not a hang; the listener is back within its backoff; kine and the apiserver come back; no partial record | yes | the listener lifecycle: the client hangs or the store holds a torn write |
| E20 | **reboot of the server node**: an operator-attended leg (automation never reboots the rig), run by the operator with the script's `--attended reboot` step | after boot the flags are still set, the listener starts, E2's entry opens, E3's Secret is still current | yes | the flag check: a flag lost across a reboot |
| E21 | a native Pod with `securityContext.runAsUser: 501` | refused at spawn: the container never starts, and its status carries the uid refusal | no (U17) | runtimed's sandbox change: the Pod runs as uid 501 |
| E22 | a native Pod with `securityContext.runAsUser: 0` on a node whose runtimed runs as root; then, from a root shell on the node, a connect to `keys.sock` | the Pod runs: `runAsUser: 0` sets no drop and an inherited uid is allowed (residual 17); the root connect is refused before any frame (U26) | no (U17, U26) | none: a guard that the refusal does not reach an inherited uid, which passes on the previous release too |
| E23 | against the real authorizer: an admin binds, for `k3sm:local:<uid>` in `ks-e2e-3`, `k3sm:keystore-delivery-author` and a Role with `create` on `secrets` and `update` and `delete` on `secrets` with `resourceNames: [e2e-named]`; the user delivers `user/<uid>/e2e-token` as `e2e-named`, then as `e2e-other`; then an admin, impersonating another principal (`kubectl --as k3sm-e2e-other`, bound to the built-in `edit` ClusterRole in `ks-e2e-3`), deletes `e2e-named`'s KeyDelivery and, separately, patches its finalizer away | `e2e-named`: `Ready`, `Delivered`; `e2e-other`: `Authorized=False`, `NotAuthorized`, no Secret: the reconciler allows exactly what the API server allows the user; the other principal's delete and finalizer patch are each refused at admission, and the object, its finalizer and the Secret stay | yes | the KeyDelivery reconciler (authority): `e2e-other` is delivered, or `e2e-named` is refused; KeyDelivery authoring: another principal deletes the object or strips its finalizer |
| E24 | first, with the server running, the operator, as the service user (`sudo -u _k3sm`), runs a program that is not k3sm and tries to unlink `keystore-sock/keys.sock` and to bind a socket at that path; then, with the listener stopped by the maintenance marker, a native Pod execs the real installed `/Library/k3sm/k3sm` and that process tries the same bind; in the deny-plus-pin fallback only, the service-user program binds `keys.sock` while the listener is stopped and the user runs `k3sm keys list` and `k3sm keys put user/<me>/e2e-pin` | the service-user unlink and bind each fail with `EACCES` and `keys.sock` is still launchd's; the bind from the Pod gets `EPERM` and no socket appears; in the fallback, the CLI refuses each before writing a frame, naming the server pin, and the stand-in receives no bytes past the connect; after the marker goes, the real server is accepted | yes | the root-owned socket directory (U104): the service-user program replaces `keys.sock`; the server pin (U69): the CLI talks to the stand-in; the Pod bind deny (U16): the installed binary in a Pod binds `keys.sock` |
| E25 | (helper variant only) a native Pod tries `connect(2)` to the floor helper's socket, and the login user and a non-k3sm service-user program each send it an `append` | `EPERM` for the Pod; the helper refuses the user by uid and the program by the pin, and no line is appended | yes | the helper pin (U70): a line from an unpinned peer is appended |
| E26 | a native Pod on a test build whose Pod profile omits the keystore deny stanza (restored at the end) tries `connect(2)` to `keys.sock` | the listener refuses the connection before any frame, since the peer is sandboxed, and writes a `refused` line | yes | the sandboxed-peer refusal (U137): the Pod's connection reaches the frame reader |
| E27 | a native Pod calls `launch_activate_socket` for the server's socket name | no descriptor is returned, and nothing in the Pod can accept on `keys.sock` | yes | the launchd lookup deny (U122): the Pod obtains the server's listener |
| E28 | **the typed-credential tracer** ("Rig credentials and custody"): a generated deploy key and a server-refreshed oauth pair delivered into one pod, which pushes over ssh and opens a pull request; then `k3sm keys refresh` | push and pull request succeed; the access-token file's hash changes in the same pod with `restartCount` 0; mount lines; the positive-controlled scans find nothing they should not; PENDING (exit 3) if the oauth pair is missing or not `ok` | yes | typed projection, the mount audit or the refresher |
| E29 | a synthetic `token` put with `--expires-at` now+8 m, delivered | `Valid`, then `Expiring` after about 6 m, then `Expired` at 8 m; one Warning Event each, `related` the Secret; the Secret kept; `Ready` unchanged | no (U165, U166, U168) | expiry and revocation |
| E30 | `generate --kind ssh`; deliver `--item privateKey=id_ed25519 --item publicKey=id_ed25519.pub` (`defaultMode` 0400); the pod runs `ssh-keygen -y -f id_ed25519`; a delivery without items is refused | the output equals `k3sm keys pubkey`; the fingerprint matches | no (U148, U163) | typed projection |
| E31 | a synthetic oauth pair (`local`, planted access and refresh tokens) put from a token-response JSON, then delivered with the CLI default | positive control: the planted access token is found base64-encoded in the Secret; then every Secret, Event, pod log and `keystore-audit.log` holds no planted refresh-token bytes (raw, base64, URL-encoded); a KeyDelivery naming `refreshToken` is refused by the schema | no (U140, U149, U160) | typed projection |
| E32 | on the real `server/github-e2e` pair, `k3sm keys refresh` (recorded during E28) | the pod's `access_token` hash changes without a restart; one `refresh-now` and one refresher line; `refresh_state ok`; `CredentialValid=True Valid`; PENDING (exit 3) if the pair is missing or not `ok` | yes | the refresher |
| E33 | a separate entry holding a planted random refresh token against the real token endpoint, delivered; `k3sm keys refresh` | `Revoked` through the profile's `revokedErrorCodes` (the endpoint answers HTTP 200 with an `error` field); one `CredentialRevoked` Warning Event; parked: a second `refresh-now` sends nothing; a positive-controlled scan as E31 | no (U184) | the refresher |
| E34 | two pods mount a delivered Secret; delete one; churn 200 short pods; rotate the entry 40 times in a minute | `pod-mount` for every first-seen pod, `pod-unmount`s, `pod-refresh` lines with one rate summary; no `ErrLogFull`; `put` still works | no (U169, U172) | the mount audit |
| E35 | precondition: `refresh-profile list` shows a profile; a pod reads a sibling non-keystore file in the same directory (positive control), then `keystore-refresh-profiles.json` and `keystore-run/refresh-state.json` | the sibling read succeeds; both keystore reads are EPERM; a regression guard, which cannot fail before refresh profiles land | no (U16) | the `keystore-*` prefix deny |
| E36 | a profile with `https://localhost:<port>/token`, a loopback listener on that port counting accepted connections, a pair naming it, `k3sm keys refresh` | `RefreshFailing` with cause `dial-refused`; the listener counted 0 connections; the redirect case is unit-only (U177) | no (U178) | refresh profiles |

## Open questions

The maintainer's answers to the four questions asked in issue 731:

1. Is the direction welcome? Yes.
2. How does design review run? As this document, by pull request, with maintainer
   review on that pull request.
3. What happens when secrets encryption is off? The reconciler refuses delivery, with
   an explicit override flag, as proposed.
4. In what order do the phases land? Phase A first. Phases B and C are filed as
   separate issues after Phase A lands.

The maintainer's three rulings on this pull request: the delivery target is declared by a
`k3sm keys` verb, not a file; the master pair lives under `server/cred/` in its own
subdirectory; the pointer rollback residual is not accepted.

Settled in this revision:

- The master directory: `server/cred/keystore-master/`.
- The delivery-target mechanism: the `k3sm keys deliver` verb, writing a root-owned file.
- The pointer floor: recorded in a root-owned file directly under the data root, written
  only by root-run verbs, with the restore procedure in "Backup and snapshots".
- The reconciler's identity: the admin client the server process already holds, with no new
  role, binding or ServiceAccount.
- The verbs `rewrap` and `deliver`, beside `put`, `list`, `show`, `rotate` and `rm`.
- `Entry.Err`: the contract change for per-entry listing, made in this pull request.
- The `Rewrap` argument check: a plain error, no sentinel.
- Retention: unbounded in Phase A.
- The floor does not defend against a process that can read the master; it refuses a
  pointer put back by a writer that cannot ("Pointer sequence and floor").
- `show --reveal` writes the stored bytes and nothing else, so the rollback recipe is a
  byte-exact round trip, checked by G21.
- A floor refusal has its own message, wrapping `ErrCorrupt`; a floor with no entry for the
  name accepts an authenticating pointer.

The review of the user scope asked three questions, answered here:

1. Is a Pod's drop target fixed, or can the Pod choose it? The Pod chooses it: runtimed takes
   the uid from the container's or the Pod's `runAsUser`, then `PodBox.uid`. So the uid
   refusal checks the final effective uid after any drop ("Pod denies", layer 2; U17).
2. Is a grant bound to the group `k3sm:local-users` honoured the same way at create and at
   every sweep? Yes: the reviews carry the impersonated create's user and groups, and the docs
   recommend binding the user, not the group ("The reviews ask about the principal the create
   used"; U42).
3. Can `rewrap --key-in` adopt a key the operator made? It must not: `--key-in` only re-reads
   a key whose SHA-256 equals the fingerprint k3sm recorded when `--key-out` saved it (G10).

Owed by the implementation: `hack/acceptance/keystore.sh`, specified above. There are no
open questions.
