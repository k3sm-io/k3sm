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
      .preframe-dropped                 0600, written by the server only: the server-counts file.
                                        Its name says pre-frame, but it carries three kinds of
                                        count: the pre-frame refusals counted as dropped and not
                                        yet in the audit log ("Per-uid fairness"), the post-frame
                                        refused lines dropped and not yet summarized, and the
                                        committed revocations with no audit line ("The audit
                                        log"); a restore's staged tree may hold it, and its
                                        temporary file, judged and parsed strictly
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
value. A root or system-scope `list` therefore opens each version once; that is one small
AES-GCM open per version (values are capped at 64 KiB), and `list` is an operator command, not
a hot path. A user scope's `list` opens only each entry's current version ("List, when one
entry is corrupt").
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
fix (restore from backup) would be the wrong one. One exception, stated here as the decision:
a user scope's `list` opens only each entry's current version (below), so a user-scope
version older than the current one that no longer opens is not reported by `list`. A system-scope `rm` reads nothing inside an entry, so it
removes one `list` reports as corrupt; a user-scope `rm` reads each version record's header for its burial ("Lock modes and fairness"). The contract changes: `Entry` gains `Err error`,
non-nil exactly when the entry could not be opened, and `Current` and `Versions` are then
zero. `List` returns a non-nil error for the whole call only for a failure that is not
about one entry: the master missing or untrusted, or the lock timing out.

A user scope's `list` (the socket's) checks less, to keep its shared hold short: it opens and
authenticates the current version only, and checks every other version of the pointer's
committed range for presence, by one listing of the entry's directory and no record opened. A
version missing from the range, or whose name is not a regular file (a symlink, a directory),
marks the entry with `Err` (`ErrCorrupt`) (`TestUserListVersionNotRegularIsAbsent`). Damage to
an older user-scope version whose file is present is found only by a `rotate --from-version`
of that version, which opens it and refuses it, or by a user-scope `rm`, whose burial reads each
version's header and reports one naming another generation. No `list` reports it, and neither
does a Rewrap, which re-seals each `scope.key` and opens no user record. Stated as the
decision: an older user version matters only to a rollback to it, which then refuses with
`ErrCorrupt`; nothing checks it ahead of that.

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
and its floor entry, since a system-scope `rm` reads nothing inside an entry. Put of that name answers
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

The reason is what an operator running `list` needs: every entry, with the ones its
checks find wrong marked, not a refusal that hides the healthy ones. What it checks differs by
scope. Root's `list` (`FileStore.List`, the system scope) opens and authenticates every
version of every entry. A user scope's `list` authenticates only each entry's current version
and checks the rest of the pointer's range for presence, so it reports a missing older
version but not a damaged one that is still present (below). A consumer that
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
  `current`, for every entry. An interrupted Put is not an entry that anything reads; it is
  left as it is, and the next Put discards it. A version above `current` that does not
  authenticate is left too, and the next Rotate discards it. `created` is kept.
- *A sealed version above `current`* (an interrupted Rotate's orphan, or a newer version
  behind a copied-back pointer) refuses the Rewrap before anything is written, with
  `ErrOrphanVersion` naming the entry and the version. Rewrap re-seals only the committed
  range, so it would leave that version under the retired master, where it no longer
  authenticates and the next Rotate unlinks it as a true orphan: for oauth, the only valid
  refresh token. The break-glass procedure: the operator adopts it (`k3sm keys adopt`), or
  removes that entry with `rm` (for a kind other than oauth, removing only the named version
  file also clears it); then the Rewrap proceeds.
- *An entry that does not open* (one root `list` reports with `Err`; a user scope's `list`
  authenticates only the current version and checks the rest for presence) refuses the Rewrap before
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
  65,537 records, each a value of at most 64 KiB. An oauth entry is the exception: it keeps
  only its current version and one previous, so it has at most three records whatever its
  number, and its pointer may name up to version 2^32 (`maxOAuthVersion`), in the same
  pointer format (the 24-byte pruned form, the only one an oauth pointer past version 2 has).
  The choice, made for the refresher's cadence: at 65,536 a pair refreshed every minute stops
  after 45 days, every 5 minutes after 227 days, and hourly after 7.5 years; at 2^32 a pair
  refreshed every minute lasts over 8,000 years, so the ceiling needs no `doctor` warning. A
  rotation at the ceiling is refused with `ErrCorrupt` before anything is written; the
  recovery is `rm` and `put` of the pair, which restarts it at version 1.
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
with a key other than the one supplied (`ErrRewrapResumed`), so it must run again. 4 is
`put`, `rotate` and `adopt` on `ErrCommitted`: the change was made and a step after its
commit point failed, so the new version is current. 4 is also `put`, `rotate`, `adopt`, `rm`,
`list`, `show` (their floor raise) or `floor merge` done, but its floor write
dropped a recorded deletion to stay within the floor's limits (a committed
`ErrTombstoneEvicted`: `Committed` and `ErrTombstoneEvicted` both match; or a merge that reports
a drop), so a copy of that deleted entry put back is accepted. Put, Rotate, Adopt and RaiseFloor
report their writes' prunes that way, as Delete does, and a Delete whose burial evicted one and
whose tree removal then failed (the entry already deleted, its directory left behind) is
committed too, so `rm` exits 4, not 1. `ErrCommitted` takes precedence: a write whose later
step fails after an eviction returns `ErrCommitted` alone, with the eviction in its message,
and `Committed` matches it too. Every verb
in this list requires root (the non-root path is under "User scope"). The human output is not
stable; `list -o json` and the exit codes are the stable surface. Value input is `--in FILE` or
stdin only, never an argument: argv is visible to every local user via `ps` and lands in shell
history. Opaque values are capped at 64 KiB; Ed25519 values are checked against the two valid
lengths exactly at Put time.

## Delivery reconciler

A reconciler beside the embedded add-on reconciler in `pkg/addons`: converges one
labelled Secret per declared target, never LISTs, never prunes anything it did not itself
apply, deletes the Secret it delivered once its entry is deleted, log-and-continue on a per-target failure (the same posture `pkg/addons/doc.go`
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
Secret per declared target, labelled as below; delete only an owned Secret, under a UID
precondition (an immutable one to re-deliver it, or one whose entry is deleted); and nothing else — no list, no other delete, no other kind, no Secret it
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
UID, logging both steps without the value. It is safe because the precondition proves the
object is the one this server created; a failed precondition deletes and creates nothing.

**Revocation on delete:** a `keys rm` must not leave the deleted value readable in the
cluster, so a sweep deletes the Secret of a target whose entry is gone, declared or withdrawn
(an `undeliver` after the `rm` does not stop it: the withdrawn record is kept until the
revocation is done). The recorded UID decides, as for an update: the Secret must carry it, and the
delete carries it as `DeleteOptions{Preconditions: {UID: <recorded UID>}}`, so a Secret replaced
after the Get is not the one deleted. A Secret missing the label or an annotation is still
deleted and the missing mark logged at Warn; one of another UID is left alone and logged, and
so is one that is not `Opaque`, withdrawn or declared. A delete is done only when its effect is
seen: after a Delete that succeeds, a Get by name must answer NotFound or another UID. A Secret
still there with the recorded UID (a tenant finalizer holds it terminating) is a stuck
revocation, not a done one: its record is kept, it Warns, and every sweep checks it again
until it is gone, when the record is dropped.

*Which entry.* The state record stores the entry a Secret delivers (`entry`, an optional
field: a record written before it has none), set on create and brought up to date when a
declared target's owned Secret is seen (root re-pointing a target updates it). A withdrawn
target is checked against the record's entry, never the label: the label is on an object any
namespace writer can edit, and relabelled to a live entry it would keep a deleted entry's value
readable, or relabelled to another deleted entry get the Secret deleted early. A record without
the field falls back to the label, with a Warn; that fallback is confined to the upgrade window,
since a declared target's record gets its entry on the first sweep that sees its Secret and
every record written since names one, so only a target withdrawn before this build's first
sweep is decided by its label. A label that disagrees with the record is logged
at Warn and keeps the record, whatever the entry's state, so the target is never silently
dropped. The field is additive for this build, which reads an older file; an older build reads
the state file strictly and refuses one carrying it, so a rollback past this change delivers
nothing until the state file is removed, which fails closed.

*Gone.* The entry must be gone by two reads: `Store.Current` answers `ErrNotFound`, and
`Store.Absent` confirms it. `Absent` (`keystore.FileStore.Absent`) is a read added for this:
`Current` answers `ErrNotFound` both for a name with no entry and for an entries' directory that
is not there, and only the first is an answer about the name. `Absent` is true only when the
entries' directory opens and is trusted under the shared lock, the floor reads, the name has no
directory, **and the floor holds no live record for the name** (only burials, or nothing).
Any other state is false with its error,
and the Secret is kept. It reads no record and loads no master key. Revocation writes no value,
so it runs while plaintext delivery is refused too (a refused target is only read for it: one
Get, one `Absent`).

Because a delete cannot be undone, these stand between an absent entry and a delete:

- *The floor as the durable witness.* `Delete` buries the name's live generation in
  `keystore-floor.json` (`fl.bury`): the name stays in the floor with its burials (tombstones)
  and no live record. So the floor tells the two states of a missing directory apart. A name
  the floor holds only burials for was removed with `rm` (or by `keys floor merge`): `Absent`
  is true, and the Secret is revoked under the guards below. A name the floor still records
  live whose directory is missing is not an `rm`: it is a restored or rolled-back `keystore/`
  (a tree put back without its floor, or an entry `--keep` kept that the restored tree lacks).
  `Absent` answers `ErrFloorRecordsEntry`, the reconciler keeps that name's Secrets for as long
  as it lasts, not for one sweep, and logs a Warn once per name. A name buried and put again
  has a live record beside its burials, so a restore without it holds too. An interrupted Put
  (a directory with no pointer, in the shape a crashed Put leaves) is not an entry for
  `Current`, and not a proven deletion either: `Absent` answers false with its error. Where
  the floor proves nothing, the identity hold below is what stands: a floor that is absent and
  rebuilt (the "Restoring an older keystore/" procedure removes it, and the next root verb
  writes it from the restored pointers), full (it records only the entries it has room for),
  or unreadable (`Absent` fails, and the Secret is kept). While a restore is unfinished
  (`MergePending`, the floor merge has not run), the sweep returns before it reads the
  declaration, so it neither delivers nor revokes: the restored floor lacks the deletions since
  the backup, and the restored tree the entries made since it. The residual: a `Delete` from an
  earlier build, interrupted after it removed the directory but before its floor write, leaves
  a live record and holds that name's revocation; it fails closed, the Warn names the entry,
  and a second `rm` clears it (with the directory gone, `Delete` still buries the live record).
- *Keystore identity and the restore hold.* `keystore.FileStore.Identity` names the entries'
  directory by device and inode; a Put, Rotate or Delete inside it leaves that alone, and a
  restore that moves `keystore/` aside, or a keystore deleted and created again, changes it.
  Each sweep reads it. The first sweep after start, and a sweep that sees it changed (logged at
  Error, naming both), start the restore hold: no revocation is made until **both** that sweep
  has passed **and** `revokeHold` (10 minutes) has elapsed. The hold's start is logged at Warn
  naming the time it ends, so the operator has 10 minutes after `start` (or after the swap) to
  put back an entry the restored keystore lacks. `Absent` returns the identity it read under the
  lock, and a delete needs it to be the sweep's, so a swap in the middle of a sweep deletes
  nothing. The identity is held in memory, not in the state file: every start holds, which is
  stricter than comparing with a recorded value. The duration is a seam of the reconciler;
  there is no override verb.
- *Breaker.* It counts distinct entries, not Secrets: one `rm` of an entry delivered into many
  namespaces is a single fresh revocation. When the entries one sweep would revoke are above 3
  **and** above a quarter of the live delivered entries (`max(3, entries/4)`), none of their
  Secrets is deleted; an Error carries the count, and repeats at most hourly while it holds,
  until the absent set is back within the limit (entries put back, or the Secrets deleted by
  hand with kubectl). The base counts live deliveries only: a revoked target's record is dropped
  with its Secret (a record a failed write left is dropped on a later sweep), so old records do
  not widen the limit; a record an older build wrote, with no entry, counts as an entry of its
  own. A stuck revocation does not count toward the breaker: a Secret already terminating, one
  whose Delete failed on an earlier sweep and is retrying, or one still there after a Delete
  that succeeded, so a few that never finish cannot hold every later `rm` back. A Warn marks
  each when it first gets stuck and each time its state changes. The limit is a seam of the
  reconciler; there is no override verb.
- *Held states repeat.* A revocation held for a reason that names it (the floor, by entry; an
  absence `Absent` cannot confirm, an entry found again, a keystore swapped during the sweep, a
  refused target's Secret that cannot be read, a withdrawn target whose entry cannot be
  confirmed, each by namespace/name) Warns once when it is first held and again only if its
  reason changes, never every sweep. The held and the stuck repeat together in one summary at
  most hourly while any lasts, each with its count and every name, why, and for how long. A
  refused target's unreadable Secret Warns only when a record exists for it, naming its entry,
  namespace and Secret: the revocation pending on it.
- *Re-check before the delete.* Gathering and deleting are a sweep apart, so `revokeOne` asks
  `Absent` again, and compares the identity it read with the sweep's, immediately before each
  Delete; an entry put back in between keeps its Secret.

The guarantee is the delete from the API only. A tenant that can read a Secret already has its
value, and a copy a Pod already read, the datastore's history and its backups keep it, so
revoking a credential still means rotating it where it is accepted. The re-check and the delete
are not atomic: an entry put back between them loses its Secret, and the next sweep creates it
again; that race is accepted. A revoked target whose entry stays gone logs nothing on later
sweeps (after a restart, its first sweep logs once that the entry cannot be read).

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
retroactively delete a Secret an operator may be relying on, unless its entry is deleted
(revocation, above). A refusal is logged at Warn
once per target per state change (there is no Kubernetes object for a keystore entry to
attach an Event to in Phase A), and `k3sm keys deliver` prints the same refusal when it
declares a target on a data root with encryption off, from the files alone: it cannot see
a running server's flag, so it says "unless the server was started with the override".

## Rotation and rollback

**Crash-safe write order:** Rotate writes the new version file first (durable, not yet
referenced), flips the current pointer, then raises the floor. The version file is renamed
into place and its directory fsynced as two steps, as the pointer is, so a failure at
either, or anywhere else before the flip, leaves the old version current and removes the
next-version file it wrote (best effort), and the retry seals fresh from the value it was
given. Only a crash, or a failed removal, leaves that file behind. **oauth is the exception**:
once its version file is in place (renamed, with or without its directory fsync), a failure
before the flip keeps the file, since it holds the provider's new pair whose refresh token
the provider may already have rotated, and returns an error matching `ErrOrphanVersion`
(never `ErrCommitted`); the file is then an orphan for `Orphan` and `Adopt`. The refresher's
contract on a failure that did not commit (documented beside `ErrCommitted`): retry `RotateIf`
with the new pair held in memory, never refresh again from the stored pair; a retry over a
kept file is refused with `ErrOrphanVersion`, and the refresher stops there. **A version file above the
one `current` names is never reused**: it holds whatever value an interrupted attempt
carried, and promoting it would publish a value the retry did not supply. Before it writes,
a system-scope Rotate (`FileStore`) looks at every such file under the exclusive lock, by one
listing of the entry's directory. A user-scope Rotate looks only at `v<cur+1>`, the name it is
about to write, in one `Lstat` and at most one record open, whatever the entry's size. The
invariant both keep: every version file is examined before a rotate writes over its name. In
the user scope a file planted further up is not examined until the pointer reaches the
version below it, and the rotate to its version then examines it first. One that does not open as this
entry's sealed record of the version its name says (it fails authentication, is another
generation's or another version's) is a true orphan and is unlinked. One that does open is
refused, as `ErrCorrupt` and `ErrOrphanVersion`, and nothing is unlinked: see the floor-lag
window below. A real crash between the version write and the flip leaves such a file, so the
retry after that crash is refused, and the refusal names both causes. A crash leaves only
the version after the current one, so a sealed version further out can only be behind a
copied-back pointer, and the refusal then says only that: restore the newer pointer from
backup. At the next version it says "inspect with `k3sm keys adopt system/NAME`"; for oauth
it adds "do not delete the file: it may hold the only valid refresh token", and for the
other kinds it offers removing the named version file as the alternative to adopting it.

**Adopting an orphaned version.** `FileStore.Orphan(ctx, name)` reports the lowest sealed
version above the pointer next to the current one: each one's version number, kind and
created time, and the pointer's sequence, never a value (a version file has no sequence of
its own; adopting gives it the next pointer sequence, the one its rotation would have
written). It also lists any further sealed versions. The orphan it reports is a `Version`
carrying the orphan's identity, which covers its record digest (see the refresher's store
interface). `FileStore.Adopt(ctx, name, orphan)` takes that `Version` and makes the orphan
current, refusing with `ErrVersionStale` when the file at that version is no longer the record
`Orphan` reported (replaced between inspection and adoption by another sealed record of the
same version): it seals a pointer naming it at the next sequence, raises the
floor, and for oauth keeps the retention rule (low becomes the old current, and the versions
below are unlinked). It refuses unless the version is exactly the one after the current one,
authenticates under this entry's generation, is of the entry's kind, and is the only sealed
version above the pointer; it is root-only, as every write is (the floor is root's), and a
failure after its pointer flip returns `ErrCommitted`. Adopting is right for both causes: it
completes the flip a crash interrupted, and it rewrites the newer pointer a copy-back
replaced. `sudo k3sm keys adopt system/NAME [--yes]` prints both sides from `Orphan`, then
adopts with `--yes` or an interactive confirmation; without either, and without a terminal,
it changes nothing.

**Every read reports the orphan.** `CurrentCredential` and `GetCredential` of an oauth
entry with a sealed version above its pointer refuse with `ErrOrphanVersion` rather than
return the older pair: its refresh token may already be spent at the provider, and spending
it again can make the provider revoke the grant. This is part of the refresher's contract:
a refresher that gets `ErrOrphanVersion` stops refreshing the entry and leaves it to an
operator's adopt; it never rotates around it (the rotation would be refused anyway). Token
and ssh reads, and raw `Current` and `Get` of opaque and ed25519, refuse the same way: the
orphan may be a newer committed version behind a copied-back pointer the floor still
accepts, and reading the older one would be a silent downgrade. The check's cost is bounded:
a read lists the entry's directory once and opens only the version after the current one. A
version file numbered further out is refused by its name alone, as `ErrCorrupt` (a crash
never leaves one), and a file at the next version whose kind byte this build does not know
is refused by name as `ErrCorrupt`, never with the "newer k3sm" advice of
`ErrKindUnsupported`: nothing newer writes above the pointer. A file at the next version that
does not authenticate is a true orphan, which the next Rotate discards; it does not stop a
read.

**The downgrade note for opaque and ed25519 orphans.** These kinds keep every version, and
an orphan of one may be removed rather than adopted. Removing it keeps the older version
current, which is a downgrade when the orphan was a newer committed version behind a
copied-back pointer. Before choosing, the operator compares both sides `k3sm keys adopt`
prints; removal is right only for a version the operator knows was never committed.

**Residual: the pointer does not commit its record's digest.** A version's identity covers
its record digest (the first 16 bytes of the SHA-256 of the record's nonce and ciphertext),
so `RotateIf` and `Adopt` cannot pass across two different records sharing a version number.
The pointer itself still names a version by number only: a failed attempt's sealed file,
saved and copied over the committed version of the same number, opens and is read as that
version. Sealing the digest into the pointer was deferred because Rewrap re-seals every
record under a fresh nonce, so the pointer would have to be re-sealed in step with its
version, and a Rewrap crashed between the two renames would leave every reader refused
until the Rewrap is finished. The copy needs write access to the entry's directory, which
already permits the copied-back pointer this design's floor addresses; it is accepted until
the pointer and its version are re-sealed as one step.

**A write reports its commit outcome without ambiguity.** The pointer's rename is the
commit point, for a Put (`Put`, `PutCredential`, `GenerateSSH`) as for a rotation (`Rotate`,
`RotateCredential`, `RotateIf`, `RotateFrom`). The pointer is renamed into place first and
its directory fsynced after, as a separate step, so a failed rename (nothing committed) is
told apart from a failed fsync after it (committed). A failure after the rename, at the
directory fsync, the floor write or the oauth prune, returns the committed `Version` (the
new one, now current; `GenerateSSH` also returns its public key line) with an error matching
the exported `ErrCommitted` (`errors.Is`), never a zero `Version` beside a bare error, which
would read as nothing written. `ErrCommitted` takes precedence: the error matches no other
sentinel, `ErrCorrupt` included, even when its cause is a floor refusal that does; the cause
is in the message only. A refresher that gets `ErrCommitted` reads the entry again and works from what it
reads; it never retries from the pair it held, which is no longer current and whose refresh token
the provider may already have rotated. A failed prune is reported the same way rather than
swallowed as best-effort: the change still stands and the next write prunes, but one rule for
every post-commit step is simpler for a caller than a step that is silently skipped.

**The floor-lag window can no longer delete a newer committed version.** If a Rotate flips
`current` and then fails to write the floor (`ErrCommitted`), the floor is one behind the
pointer until the next root-run verb raises it. If, inside that window, a writer that cannot
read the master copies the previous `current` back, the floor check passes it (its sequence
equals the floor's). The next Rotate then finds the newer version, which the live pointer
named, above `current`, and it authenticates as this entry's, so the Rotate refuses with
`ErrCorrupt`, naming the copied-back pointer, and unlinks nothing, for every kind. For oauth
that version holds the only valid refresh token. Restoring the newer `current` from backup
and raising the floor reads it again. A Rotate that crashed before its flip leaves the same
files (a version above `current` that authenticates, a pointer at the floor's sequence), and
no cheap guard tells the two apart, so that crash is refused the same way rather than have
its orphan discarded.

**Retention:** an `ed25519`, `opaque`, `token` or `ssh` entry keeps every version, up to the
version ceiling; nothing deletes a single old version short of `rm` of the whole entry. An
oauth entry keeps its current version and one previous: each rotation records the oldest
retained version in the sealed pointer and unlinks the versions below it (the oauth prune,
"Record kinds, the typed envelope and retention"), and `Adopt` keeps the same rule.

**Delivered-Secret movement:** covered above under "Re-delivery on rotation" — automatic
on the next sweep after a Rotate.

**Rollback:** `sudo k3sm keys rotate system/NAME --from-version N` (`FileStore.RotateFrom`)
writes version N's value forward as a *new* version inside k3sm, so the value never leaves the
store; it is refused for oauth (`ErrFromVersionOAuth`) and for a source version of another kind
(`ErrKindMismatch`). Nothing points `current` backward at an existing version. The same new
version can also be written through a pipe:

```
sudo k3sm keys show system/NAME --version N --reveal | sudo k3sm keys rotate system/NAME --in -
```

`--from-version` is row U1; the pipe stays the recipe G21 checks.

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
floor is the system store's, so what the merge keeps refused is the system store's deletions:
until the user-scope floor lands, a user-scope deletion since the backup is not carried over, and
when the staged tree holds `.user` entries the report says so (`MergeReport.UserScoped`) and
the verb exits 4 (`TestKeysFloorMergeReportCodes`). The
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
`keystore-floor.json.pre-restore` is in the data root, Put, Rotate and Rewrap refuse
under `keystore-lock`, before they write anything, with a message naming `keys floor merge`
(`errMergePending`); Delete runs and writes only its burials (below); and RaiseFloor, which the
read verbs call first, raises nothing and logs that at Warn, so no pointer put back before the
merge is recorded. The user scope is off for the same window, in code: the server's start step
(`startUserScopes`) and its store-directory step (`EnsureDir`, which so makes no `keystore/` the
merge would move aside as planted) refuse with `errMergePending`, as doctor's start step does,
and every user write verb (put, rotate, rm, deliver, withdraw) asks `FileStore.MergePending` first
under `keystore-lock` (`userWriteAllowed`) and refuses with it, writing nothing
(`TestUserScopeOffWhileMergePending`, `TestKeystoreListenerOffWhileMergePending`). `list` and `show` run with a warning on stderr and, until the merge, find no
entry, since the restored tree is staged (below). A successful merge renames its input to
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
`keystore-floor.json.pre-restore`, any answer but not found counting as pending; a store
configured with an empty data root has no floor, so no restore can be pending and it is nil, no
hold), and while it is set the sweep delivers nothing, reads no entry and makes no apiserver call, logs at Error and
tries again on the next sweep (`TestDeliveryRefusedWhileMergePending`). `list` and `show` still
read, and print a warning on stderr; until the merge they find no entry, since the restored tree
is staged. Before
anything moves, the recipe checks that nothing runs as the service user (`! pgrep -u _k3sm`),
that the backup's directory and its parent are owned by root with no group or other write (a
`find -maxdepth 0 -user root ! -perm +022` that must match both), so the service user cannot swap
the source between the checks and the copy, and, just before `ditto`, `test ! -L` on its source,
which `ditto` would follow (`TestKeysRollbackRoundTrip`, the recipe-steps subtest). The save
recipe makes those directories so (`install -d -o root -g wheel -m 0755`). The
recipe moves the live `keystore/` into `pre-restore.d/` in the data root, a directory it creates
root:wheel 0700 with `mkdir` (which fails on an existing name) under a parent only root can
write, so the service user cannot reach the moved-aside entries to copy one back, nor rename the
directory, as it could under `server/`. It changes no file inside: a rename changes no inode's
owner. Root's `ditto` copies the backup into `pre-restore.d/restored` (after `test ! -e`), and
`server/keystore` is left absent. The merge opens `pre-restore.d` through the data root the lock
judged, never followed, and refuses it unless root owns it and it grants nothing to group or
others, by its mode or by an extended ACL (`hasExtendedACL` on the descriptor;
`TestOpenStagingRefusesACL`): `ditto` keeps the backup's owner inside, so the directory's
permissions are what keep the service user out of the staged tree. It reads the restored pointers only from
`pre-restore.d/restored`, bytes only root copied (the raise is still by at most one sequence), and
authenticates the moved-aside tree's pointers, `pre-restore.d/keystore`, under the master, so the
fence is one past the highest of the moved-aside floor's sequence, its mark and that pointer: a
moved-aside floor that lagged its pointer by two or more is fenced above the pointer
(`TestFloorMergeFencesAboveAsidePointer`). A moved-aside pointer above 2^62 is reported unverified and not fenced above
(`TestFloorMergeBoundsAsidePointer`): no entry rotates that far, and fencing above it would leave the
mark at the sequence limit, where no Rotate can seal above it. With the moved-aside tree present, each name whose
pointer there does not authenticate (no entry, another generation, a refused record), or every
name when the master does not load, is reported unverified (`AsideUnverified`, logged at Warn):
its fence is one past the moved-aside floor's record and mark only, and the CLI prints an
`unverified ... the moved-aside pointer` line and exits 4, dry run included
(`TestFloorMergeAsideUnverified`). An absent moved-aside tree holds no pointer, and is no failure. Anything at `server/keystore` while a tree is staged,
a symlink counted, was planted: the recipe leaves it absent. The merge renames it, after its
refusals and before the floor write, into `pre-restore.d/planted-<unix>` (the first free second
from now) through the two directory descriptors with `renameatx_np` `RENAME_EXCL`
(`moveTargetAside`): never followed, never read, and out of the service user's reach in the
root-only directory. It logs that at Warn, reports it (`MovedAside`, `MovedAsideType`; the CLI's
`moved aside` line and a stderr warning) and goes on; a dry run reports the name it would use and
moves nothing (`TestFloorMergeRefusesExistingTarget`). A rerun after a committed merge
(exit 5) finds the live floor already holding every burial and fence the input records, judged
without the trees' pointers (`planMerge` with none), so a refusal after that, of the staged
tree's shape, of opening `pre-restore.d`, of its pointers, or of the move aside, is committed and
worded so (`committedShape`), never "nothing is written", and the CLI exits 5, dry run included
(`TestFloorMergeRerunCommittedWording`, `TestKeysFloorMergeCommittedRerunRefused`). The tree's own `RENAME_EXCL` move still
guards the race: something planted after the move aside fails it, committed, and a rerun moves
that aside too,
and with nothing staged a merge that would change the floor refuses (`TestFloorMergeNeedsStagedTree`).
Before anything is read from it or planned, dry run included, the merge walks the staged tree
read-only (`checkStaged`) and refuses it as `ErrCorrupt`, naming the path inside the tree, unless
every node is one the store writes, in the shape it writes it. The names come from the code: at
the top, `.lock` (a regular file, empty), `.user` and directories named by `checkName`; in an
entry's directory, `generation`, `current`, `v<N>` up to `maxVersion`, the `.new` sibling Rewrap
seals `current` and `v<N>` into, and the `.<name>.<16 hex>.tmp` file `writeFile` makes for each;
in `.user`, directories named by an eligible uid in canonical decimal; in a scope, `entries`
(directories named by `checkName`, each an entry's directory), `scope.key`, `scope.key.new`,
`deliveries` and their temporary files. Each file is a regular file with one link, at most its
kind's record maximum (`generationFileSize`, `maxRecordSize`, `maxScopeKeyRecordSize`,
`maxDeliveriesRecordSize`, 0 for `.lock`); each directory is a directory; no node has a setuid,
setgid or sticky bit, a file flag, or an extended ACL (`acl_get_fd_np`), and each is owned by the
service user or by uid 99, the unknown owner a volume that ignores ownership reports. A
root-owned node is refused: a `ditto` keeps the service user's owner, so a root file there is a
copied link to one of root's. The walk is at most five levels deep, `maxDirNames` names a
directory and 2^22 nodes in all, checks its context as it goes, and runs read-only once before
the handover, which judges each node again on its descriptor (`TestFloorMergeStagedNodeBudget`,
`TestChownStagedRefusesShape`, `TestChownStagedRefusesACL`,
`TestChownStagedRefusesForeignOwner`, `TestChownStagedNameBound`,
`TestFloorMergeShapeDryRunParity`). Before the floor write the merge then hands the staged tree to
the service user in Go, through descriptors: each node is opened `O_NOFOLLOW|O_NONBLOCK`, judged
again on the descriptor (`fstat`), set to the mode Put writes (`fchmod`, 0700 or 0600), handed
over (`fchown`), and `fstat`ed again; a file that gained a link has its owner and mode put back
and refuses the tree, so no by-name change reaches another inode (`TestChownStagedRecheckSeam`,
`TestChownStagedSetsModes`). Each node handed over is fsynced on that descriptor (`syncStaged`;
`F_FULLFSYNC` on darwin), a file at once and a directory once its children are, all before the
tree's rename, so a crash after the rename leaves no truncated key file and no directory missing
a name (`TestFloorMergeSyncsStagedTree`).
After the floor write it renames `pre-restore.d/restored` to `server/keystore` through the two
directory descriptors with `renameatx_np(RENAME_EXCL)` (from `golang.org/x/sys/unix`), which
refuses an existing name, a symlink included, in the same step; a failed fsync after it is
logged at Warn and the rename stands. Only then is the guard file renamed. A failed move after
the floor write exits 5, and a rerun, which writes nothing more, completes the move and the
rename (`TestFloorMergeMovesStagedTree`). The undo stages the trees the other way round inside
`pre-restore.d` (the moved-aside tree as `restored`, the restored one as `keystore`) and swaps the floors:
the moved-aside floor goes back in place and the restored floor becomes
`keystore-floor.json.pre-restore`, then runs the merge in that reverse direction, so a deletion
made after the restore survives the undo. Every first run writes, root-owned at the floor's mode
and in one canonical encoding, its commit marker `keystore-floor.json.pre-restore.retired` before
the floor write: the sha256 of its input (the guard file's bytes), of the live floor it read and of
the floor bytes it writes, and the names it retired, buried live, kept and dropped; it renames the
record with its input to `keystore-floor.json.merged-<unix>.retired` (the first second from now
with both names free). A run that finds a pending record of its input whose floor is the live one
is a rerun: it never plans the floor again (a prune an `--accept-drops` run made would be undone
and another made), only finishes the staged tree's handover and move and the rename, and reports
from the record (`TestFloorMergeRerunAfterAcceptDrops`, `TestFloorMergeRerunKeepsRetiredSets`).
A record whose base is the live floor is a first run that stopped before the floor write, which
runs again and unions the record; any other floor fails closed, committed
(`TestFloorMergeRerunFloorChanged`). No pending record means nothing is written, so a refusal
before the write says so (`TestFloorMergePointerOnlyRefusalNotCommitted`). While the record is
pending, rm is never refused, since revocation always succeeds: the record also holds the floor
read and the floor written (`read`, `written`), and a rerun whose live floor is the floor written
plus only burials added since (a new burial or one numbered higher; no burial removed, no live
record lowered, of another generation or newly live, and a live record gone only with its
generation buried) finishes from the record, keeps those burials and removes their staged
directories, while one whose live floor is the floor read plus only rm's burials above
`guardEraSeq` is a first run that stopped before the floor write and runs again. The floors are
parsed and compared structurally, the sha256 only the fast path for an exact match. A live record
kept counts only at the recorded sequence with a mark at or above the recorded one, or above both
(`TestBuriedSinceFence`, `FuzzRerunPredicates`). An rm under the pending record can drop a burial
either floor holds, at the per-name cap or in the prune (certain after `--accept-drops`): before its
floor write it appends each burial dropped to a root-owned
`keystore-floor.json.pre-restore.rm-dropped`, bound to the pending record by its input and base
sha256 and capped at 4096 burials (one of another record is ignored, one untrusted or not in its
one encoding refuses the rerun), and the rerun accepts those burials gone; the Delete still reports
`ErrTombstoneEvicted` (`TestFloorMergeRerunAfterRmPrune`). The record never refuses the rm: when
it would list more than 4096 burials, does not read, or cannot be written, the Delete replaces it
with a root-owned mark bound to the pending record (`"unusable": true`, no burials) and buries
regardless, still before the floor write and under `keystore-lock` alone. A rerun or first run
that finds the mark accepts no drops and stops, committed, for the operator to inspect the floor
against the record; one whose mark could not be written refuses too, since the floor then lacks a
burial the record does not list, or the record does not read
(`TestDeleteUnderGuardNeverRefusedBySidecar`, `TestParseRmDroppedMark`). Either run passes the
listed burials to the staged-directory removal, so a first run that plans again from the floor rm
left removes the staged directory of a generation whose burial rm pruned
(`TestFloorMergeFirstRunRemovesRmDroppedStaged`). A live floor that is the floor read with
a change rm does not make is refused as not written (`TestPendingSinceReadFloorNotCommitted`). A
run with no pending record whose renamed `merged-<unix>.retired` has this input and the live
floor stopped between the two renames: it only renames the input, writing no second record, and
removes the rm-dropped record as the rename it finishes does (`TestFloorMergeCrashBetweenRenames`,
`TestFloorMergeCrashBetweenRenamesClearsRmDropped`). Anything else
fails closed, committed (`TestFloorMergeRerunAfterDelete`, `TestFloorMergeDeleteBeforeFloorWrite`,
`TestFloorMergeRerunNonMonotone`). The merge
refuses up front when `pre-restore.d` and the keystore's parent directory are on different
devices (`TestFloorMergeRefusesTwoDevices`), and before the floor write removes the staged
directory of every entry whose staged generation the merged floor buries or whose burial the
write drops (`TestFloorMergeRemovesAsideBuriedStaged`, `TestFloorMergeRemovesDroppedStaged`); a
directory fsync that fails after the tree's rename is committed (exit 5,
`TestFloorMergeMoveSyncCommitted`). The reverse merge, run with `--undo`, reads only the
`.merged-<unix>.retired` record whose input sha256 is the live floor's (in an undo the live floor
is the first merge's input), never choosing by the `<unix>` in its name, so a clock stepped back
cannot pick another merge's record, and refuses with no record or none matching
(`TestFloorMergeUndoRecord`); its report splits the buried-live names into those the first merge retired ("retired by the
restore": `--keep` brings it back) and those deleted since the restore ("stays deleted"), and it
refuses `--keep` on one of the latter (`TestKeysRollbackRoundTrip`, `TestParseRetired`). No recipe changes owner,
mode or flags recursively (`chown -R`, `chmod -R`, `chflags -R`) over a tree the service user
wrote: root would follow a hard link planted in it to an unrelated inode
(`TestKeysRollbackRoundTrip`). The merge keeps every live record of
the restored floor not buried above. The write is pruned as every floor write is, the per-name cap
included, and each burial dropped is logged at Warn and reported. As Put and Rotate ask for room
before they write, the merge first decides on in-memory floors (`planMerge`: the merge and the
prune on a copy), computing every burial the write would drop. Without `--accept-drops` any drop
refuses it with the floor-full error, writing nothing and leaving its input in place, so the
guard stays, a burial the restored floor already held included
(`TestMergeFloorRefusesDroppingItsOwnBurials`, `TestMergeFloorRefusesDroppingRestoredBurials`).
`--accept-drops` never drops a buried-live burial, one whose name the merge cleared to no live
record: the restored copy would be accepted again with nothing refusing it. That merge is refused
with or without the flag, naming the entries to `keys rm` first; the rm's own burial, a guard-era
one, then stands in for it (`TestMergeFloorNeverDropsBuriedLive`). `FuzzPlanMerge` drives
`planMerge` and checks that a merge allowed without `AcceptDrops` drops nothing, that no cleared
name ends with neither a record nor a burial, that no raise exceeds the record's sequence plus one,
that merging twice equals merging once (the same floor, nothing more written, each kept name kept
again; `TestPlanMergeKeepTwiceWritesNothing`), and that a reverse merge after it keeps every guard-era
deletion and one made since the restore, each the rm's own write did not evict at the per-name cap
or in its prune, which that Delete reports (`TestFuzzRmReportsCapEviction`). A guard-era burial is one `rm` wrote while the guard was
set. A Delete under the guard numbers each burial above
`guardEraSeq`, half the delete-sequence limit, which no floor reaches by counting deletions, so
the merge tells those burials from the restored floor's from the live floor alone, with no
record beside it and nothing more for the Delete to write. The merge moves the guard-era
burials to just above `guardEraSeq`, the others from 1, inserts each burial it adds between the
two, oldest first, and renumbers every burial from 1 at the end, order kept, which the parser's
distinct-and-increasing rule accepts. So the burials it carries over, older in real time than
any written during the guard, are pruned first, and a guard-era burial is never pruned before
them (`TestGuardEraBurialSurvivesPressuredMerge`, and `FuzzMergeFloor`: none ends above
`guardEraSeq`, and every added burial ends below every guard-era one). A floor with a burial
above `guardEraSeq` and no guard (the guard file removed by hand) is renumbered back to ordinary
numbering, order kept, by the next Delete with no guard pending (`TestDeleteRenormalisesStaleBand`)
and by any merge. At the sequence limit a Delete under the guard renumbers through
`renumberGuard` and numbers its burial above `guardEraSeq`, so the band survives
(`FuzzDeleteUnderGuardAtLimit`, seeded at 2^52 and 2^53-1). An `rm` under the guard buries the
restored entry while its files are staged in `pre-restore.d/restored`, out of its reach, and
leaves its cluster Secret in place until the merge. The merge removes the staged directory of
each entry a guard-era burial buries that the merged floor does not hold live, and of each entry
it buries live itself (a name `--keep` keeps is not buried live), so a later prune of the burial
brings no copy back (`TestFloorMergeRemovesBuriedLiveStaged`), through the
descriptor-opened tree's `os.Root.RemoveAll` (a symlink is removed itself, never followed), before
the floor write and the tree's move, so no second `rm` is needed
(`TestFloorMergeRemovesGuardBuriedStaged`). The refusal names what binds. When only the
floor's size does, it names `keys rm`, which frees a live record. When the tombstone budget or
the per-name cap binds, `rm` cannot help, since each deletion records one more, so it names the
budget, or the cap and its names, and `--accept-drops` (`MergeOptions.AcceptDrops`), which writes
the merge anyway: the write prunes oldest first, as every floor write does, reports and prints
each burial dropped, exits 4 and renames the input, so the guard has an exit. `--dry-run`
(`MergeOptions.DryRun`) stops after the merge on a copy and prints that report, drops included,
writing and renaming nothing, and exits with the code the merge itself would
(`TestKeysFloorMergeDryRun`)
(`TestGuardEraTombstoneBudget`, `TestGuardEraBurialPerNameCap`, `TestPendingMergeDeleteMakesRoom`,
`TestKeysFloorMergeAcceptDrops`). A
fence is a mark on a live record, which no prune removes. The verb prints `merged N`,
`already present N`, `buried live N`, `kept N`, `retired N`, `dropped N` and `fenced N`, one per line, then `buried live
system/<name>: ...` for each name whose live generation it buried (whose directory `rm` removes;
the line also names `--keep`, since in an undo it may be a version the first merge retired, which
the floors cannot tell apart), `kept system/<name>: revoked, kept live ...` for each name kept
whose restored generation the moved-aside floor buries (warned of on stderr too) and `kept
system/<name>: recorded the moved-aside version ...` for one the restored floor does not record
(`MergeReport.Recorded`), `retired system/<name>: ...` for each name whose moved-aside live
generation it retired, `unverified system/<name>: ...` and `dropped system/<name>: ...` for each
burial dropped. Its exit codes: 0 once the merge is written with nothing below; 1 refused; 4
written, but it dropped a burial, kept an entry, left one unverified, moved a target aside, or
carried over the staged tree's user-scope entries without a floor check
(`MergeReport.UserScoped`, a line saying so); 5 written, but the staged
tree was not moved or the input not renamed, which wins over 4 (`TestKeysFloorMergeReportCodes`). The saved floor must come from a
root-owned, root-only location: the floor decides what is live, and a planted floor marks
revoked entries live. Removing the floor, the older-keystore procedure above, discards every
burial.

Amended by the user scope's append-only files: the matched set also includes `keystore/.user/`,
`keystore-user-floor.log` and `keystore-audit.log`. The append-only flag does not survive
`cp`, rsync or Time Machine, so every restore ends with `sudo k3sm keys floor --rebuild`, and
`sudo k3sm keys audit --rotate` swaps in a fresh flagged audit log ("User scope", "The user-scope floor").

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
  keystore-logs/                        NEW: root 0755, the logs' directory
    floor/                              NEW: root 0755, the floor log's own directory
      keystore-user-floor.log           NEW: the user-scope floor, append-only
    audit/                              NEW: root 0755, the audit log's own directory
      keystore-audit.log                NEW: the audit log, append-only
      keystore-audit.log.1 … .4         NEW: the previous audit logs after `audit --rotate`, `.1` the newest; root 0600 unflagged
  keystore-lock                         NEW: root 0600, the floor lock only root can open (Open requirement 2)
  keystore-removed-scopes.json          NEW: root 0644, written by `rm-scope`, parsed strictly; Pod-denied (Open requirement 13)
  keystore-maintenance                  NEW: root 0644, the marker, present only while a maintenance verb runs
  keystore-maintenance-runs             NEW: root 0644, the lossy-run record: one line per committed maintenance run that dropped anything, the newest 64
  keystore-staging/                     NEW: root 0700, present only while a maintenance verb or install runs
    floor.new/, audit.new/              NEW: a replacement log directory being built, then the retired one after the swap
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
and a refused file counts as no listing for the finalizer (U133), while every open of a scope
key refuses until it reads ("A removed scope stays removed").

The owner and mode of the two logs depend on the floor variant ("The user-scope floor"): with
the append-only flag they are the service user's, mode 0600, flagged `sappnd`; with the floor
helper they are root's, mode 0600. K0 picks; dated amendment. Each log is judged on its open descriptor, and so is the data
root holding it: a log whose `st_flags` carry any bit beside `SF_APPEND` (`uchg`, `uappnd`,
`schg`), or either one with a non-empty extended ACL, is refused as untrusted, since an ACL can
grant what the mode does not show and an owner who set a user flag could clear it. The ACL is
read with `fgetattrlist(2)` for `ATTR_CMN_EXTENDED_SECURITY` on the descriptor, which any
caller that can stat the file may ask: `x/sys/unix` wraps no `acl_get_fd`, and `fgetxattr` of
`com.apple.system.Security` is `EPERM` for every caller but root, so the service user could not
use it (U24, U50).

`.user` is a dot name, so a Phase A build's `List` skips it, and every build before the
scope-key Rewrap refuses Rewrap while it exists. The run directory is not reused for the
socket: it is 0700 (`RunDirMode`), so a login user cannot reach a socket there, and the mesh
key directory already holds the name `keys`, hence `keystore-sock`.

**The socket's directory is root's, so the service uid cannot bind there.** `sudo k3sm install`
creates `keystore-sock/` root:wheel 0755. The socket in it is a launchd `Sockets` socket of the
server's own job: `ServerPlist` (`pkg/install/plist.go:218`) gains a `Sockets` dictionary with
one listener, `SockPathName` `/var/lib/k3sm/keystore-sock/keys.sock` and `SockPathMode` 0666,
rendered by `renderPlist` (`pkg/install/plist.go:609`) from a new field of `launchdPlist`
(`pkg/install/plist.go:573`). launchd records the socket at the job's bootstrap and binds it at
the path, as root, when the job takes it with `launch_activate_socket` (K7a amendment
2026-11-23); the server confirms `FD_CLOEXEC` on the descriptor and passes it to no child (Open
requirement 3, U120). No service-uid process can create, unlink or
replace a name in a root-owned 0755 directory, so no service-uid process, the server's
children and a Pod's processes included, can bind `keys.sock`, whether or not the server is
running (U104, E24). That launchd activates a `Sockets` socket for a job with `UserName` set,
and that the server, as the service user, receives it, was a K7a measurement; the fallback,
had it failed, was deny plus pin: install makes `keystore-sock/` the service user's, 0755, the
server binds `keys.sock` itself, and the bind is kept from Pods by the Seatbelt deny and from
other service-uid code by the client's server pin ("The client pins the server"). **The K7a
amendment of 2026-11-23 records that the activated form ships**: launchd activated the socket
for a `UserName` job, root:daemon 0666 in the root 0755 directory; the job got one descriptor,
`FD_CLOEXEC` already set; no process tried but the job, a Pod's included, obtained the
listener, since launchd answered each with `ESRCH` (measured on macOS 27.2.1 only: a bonus
barrier, not a guarantee, Open requirement 5); and the client-side peer reads as launchd
(`LOCAL_PEERCRED` uid 0) while the audit token names the accepting server, which the client check of Open requirement 4 accepts.
A server launchd did not start, or whose plist has no `Sockets` key, gets `ESRCH` (both
measured); one for which launchd has no `keys` socket, because its loaded definition has no
such entry or a parent of the socket path is missing at the activation call (measured with
three missing levels), gets `ENOENT`. Each keeps the user scope off for the life of the
process; the server never binds `keys.sock` itself. **The server checks its Pod profile at
start.** Before the supervisor serves, the server renders a Pod profile with the embedded
runtimed's own generator (`sandbox.Generate`) over a posture whose pod root, data root and
state dir are the ones the provider derives for its runtime from the same flags
(`serverPodPosture`, `cmd/k3sm/keystoreprofile.go`, over `provider.RuntimePosture`, which is
the provider's own `dataRootOf`, `ownRootStateDir` and `podLogsDirOf`). What is proven is
narrow: `TestServerPodPostureMatchesRuntime` shows those three fields equal to the provider's
for a `/private/var` data root under a `/var` pod root (both become the runtime root's
spelling), a `/System/Volumes/Data` data root, a symlinked `server` state dir (its resolved
target) and the default (runtimed's default pod root), and
`TestRuntimePostureIsTheRuntimesConfig` shows the provider's derivation is what `NewRuntimed`
hands runtimed. The fields runtimed fills from its own state (`Home`, `WorkVolume`, the VIPs)
are not in it, and no test reads a built runtime's posture back. A posture the provider
refuses (as it refuses the node) is the configuration state below, retried
(`TestServerPodPostureFailureIsConfiguration`). The check requires that the text deny
`file-read*`, `file-write*` and unix-socket `network-outbound` on `keystore-sock/` under the
data root it serves, in each spelling the generator writes (`/var`, `/private/var`,
`/System/Volumes/Data`), with no overlapping allow after the deny (`socket.ProfileDeniesSocket`),
and, for the same operations and every spelling of the data root, a deny carrying the
case-folding `regex` filter the generator writes for the data root's `keystore-` names (one that
matches `keystore-`, `KEYSTORE-` and each spelling with a letter replaced by a rune the data volume
folds onto it, U+212A for `k` and U+017F for `s`, and not `xeystore-`): a profile without it fails
the check (`TestProfileDeniesSocket`). The check is lexical and narrower than Seatbelt: it reads
top-level `(allow ...)` and `(deny ...)` forms only, so a rule nested in any other form is not
seen; only an exact `(subpath "P")` filter, bare or under `(remote unix-socket ...)`, covers the
socket's directory, so a `literal`, `prefix` or `regex` filter, or one under `require-any` or
`require-all`, does not; paths are compared as text in the spellings above, with no symlink
resolved; and the `regex` is judged by the strings it matches as a Go regexp, not by how SBPL
reads it. It proves the text the linked generator renders carries the deny; it does not prove
what libsandbox enforces.
A profile that does not, as from a k3sm built against a runtimed older than the deny or a data
root the posture does not name, keeps the user scope off for the life of the process with `this
build's Pod profile does not deny the keystore socket`; the server logs one warning naming
`install a k3sm built with a matching runtimed` and keeps running. A render the generator
refuses for a posture value the server's flags set (an invalid pod logs dir, pod root, status
record dir, data root or state dir, or a pods root under a `keystore-*` name:
`podPostureErrors`, `cmd/k3sm/keystoresocket.go`) is the node's configuration, not the build's:
the user scope is off with `the Pod profile does not render for this node's configuration`,
naming the render error and "fix the flag, then `sudo k3sm restart`", and the check is retried
with the start-check backoff, running no other start check until it passes
(`TestPodProfileRemedyNamesConfiguration`, `TestPodProfileConfigIsRetried`). Any other render
error stays the build's state above. The barriers relied on are
that Seatbelt deny and the listener's sandboxed-peer refusal (Open requirement 15); launchd's
`ESRCH` to a Pod is not one of them. A data root on a volume that is not
mounted was not measured; a default-layout data root that is not mounted is refused earlier,
by the shadowed-work-dir check (`refuseShadowedWorkDir`, `cmd/k3sm/server.go`), before the
server reaches this step.

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
that scope with `rm-scope` and nothing more recovers only a user who never delivered (its
owner loses its values and re-puts them): for one who did, the user-scope floor records the
`deliveries` record past its first sequence, and the owner's next put refuses to mint a fresh
scope over it. For that user `rm-scope` refuses while the record names a delivery, until the
KeyDelivery reconciler (lifecycle) builds its revocation ("`rm-scope` revokes first"). The
recovery is `sudo k3sm keys rm-scope user/<uid> --yes`, then `floor --rebuild`, which drops
every key of the removed scope ("Rebuild drops a removed scope's keys", U194), the
`deliveries` line among them, so the owner's next put mints a fresh scope; the scope's
delivered Secrets stay until root deletes them. Rewrap's refusal is correct either way and
stays.

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

**The quota is judged without a walk under the lock.** The server keeps, per scope and in
memory, a usage figure: every entry name with its sealed bytes, as the byte budget counts them.
A `put` or `rotate` judges the quota on that figure plus the `deliveries` record's size (one
`Lstat`), so a scope of many versions costs its judgement nothing under the store lock, and one
already at quota is refused before any walk (`TestRotateAtQuotaNoFullWalk`). The figure's crash
recovery: it is never persisted, so a restart, a crash included, starts with none, and a lost
or possibly stale figure is recomputed from the files, never trusted. The figure is built by a
walk of the scope before the store lock, under the uid's own mutation lock, which its `put`,
`rotate` and `rm` hold, so no write of the server lands in the scope during the walk; under the
store lock it is trusted only while the scope it was built in is still on disk, by two
bindings: the scope's `scope.key` byte for byte the one it was built beside, and the scope's
`entries/` directory the same directory, by device and inode. `entries/` is bound rather than
`.user/<uid>/` because it is the tree the figure counts: a scope directory renamed into place
brings its own `entries/`, and an `entries/` replaced inside a scope directory that stayed
changes it too, while no user operation creates or replaces it (a mint creates it with
`scope.key`). An `rm-scope` and a new mint, or a Rewrap's re-seal, changes the first binding; a
scope tree renamed into place under the same `scope.key` bytes changes the second
(`TestUsageFigureBoundToEntriesDirectory`, `TestUsageFigureScopeKeyReplacedOnDisk`; an
unchanged tree keeps its figure, `TestUsageFigureKeptForUnchangedTree`). Either makes it stale,
and that judgement walks the scope once and keeps the result; the walk before the lock checks
both bindings too, so
a stale figure is rebuilt there, outside the hold, and that walk stops when its request's
context ends, leaving no figure, and the request then returns its context's error before the
store lock, taking no hold and writing nothing). That walk under the lock is the one scope walk
left in a `put` or `rotate` hold, a fallback: the figure is still absent or stale at the lock
when the walk before it failed, when a root `rm-scope` and a new mint, a Rewrap, a tree put
in place, a `forgetAll` (a listener start pass or a merge in this process), or a first mint of the
scope by a `deliver` (which takes no uid lock) landed between that walk and the lock, or when the
`put` minted the scope in this hold. That walk does not stop when the request's context ends. The hold does
not release the lock to walk outside it and retry: that walk is documented, not removed. A `put`, `rotate` or `rm` takes the figure out of the table
before its first write to the scope's entries and puts it back, changed by what it wrote or
removed, only through its own confirm after the update, so a failure, an outcome not known, or
a panic the socket's listener recovers, anywhere in between, leaves no figure and the next one
walks again (`TestUsagePanicAtWriteDropsFigure`, `TestUsageFailedWriteDropsFigure`). `rm` takes
it out only at the removals from the entry's tree, so one that only buries keeps it too. A
refusal that writes nothing to the entries keeps it: `ErrExists`, a quota refusal, a log-room
refusal, an `rm` of a name not there, `ErrScopeOwnerChanged`, a lookup not run, and an `rm`
refused with nothing removed (`TestUsageRefusalKeepsFigure`); the mutation rate limit is the
socket's and refuses before the store is reached, so it never touches the figure. The order before the store lock is the uid's mutation lock,
that walk, then the GeneratedUID lookup, so the lookup's answer is not spent waiting for either.
Only the server writes a user scope's entries; a file written behind it is out of this model:
one planted under the same `scope.key` stays uncounted until a restart, a listener start, or a
figure dropped for another reason makes the next `put` or `rotate` walk the scope
(`TestUsageFigureMatchesWalk` shows a figure bound to another `scope.key` re-walked, not a
planted file counted). So is a second server process
over the same tree: the listener serves only after the single-server check at its start has
passed, and a second server registered while one serves is caught at the next count, up to 30
seconds later (U110), during which the figure's model does not hold. Every listener start pass
runs the store's start step, which drops every figure first, so a listener started again (a
rebuild, a run after a recovered panic, a second server gone) holds none from before
(`TestStartUserScopesForgetsUsageFigures`); a figure an operation or a walk took before that
drop is never put back after it, the table's generation having moved
(`TestForgetAllDuringOpLeavesNoFigure`). A restore puts a tree back under the same
`scope.key`s with the server stopped, as its recipe requires: the stopped server is the
procedure and the protection, since the restart holds no figure. The `entries/` binding is a
second line behind it, for a scope tree renamed into place while a server runs; it does not see
files changed inside an `entries/` that stayed, which the paragraph above leaves out of the
model. The restore's merge also forgets every figure
of the process that runs it (`TestFloorMergeForgetsUsageFigures`), which covers only a figure
held in that process.

**When `rotate` gets `ErrQuota`.** Retention is unbounded, so an entry rotated often fills the
byte budget. `rm` then `put` recovers: `rm` frees every version of the entry and `put` stores
the new value as version 1 of a new generation. No `quota` text recommends it, though: `rm` is
a deletion that cannot be undone, and the `put` after it can itself be refused (the floor's key
bound or free-space margin), which leaves the entry gone; the error says only that an `rm` of
an entry no longer needed makes room. A user who takes that path runs `put` at once, since `rm`
is a deletion: the entry's deliveries are deleted only when two
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
  live `W` or `master.next`'s, so it runs at every step of a Rewrap. It writes the tombstone
  at the record's sequence plus 1 only over a floor it has checked the record against. Over a
  floor it cannot verify (absent, untrusted, unflagged or unreadable: the shape a restore
  leaves) it **seals nothing**: re-sealing would give whatever record is on disk, perhaps an
  older copy put back, a fresh authentic sequence and launder it. It refuses instead with a
  named error saying the delivered Secret must be deleted anyway, which the reconciler's rule
  for a withdrawal that errors (below) covers, and root's `floor --rebuild` then lets the
  withdrawal be sealed. Before that it still checks the record against the highest sequence
  the store process has read or written for that scope and generation, an in-memory mark
  raised on every successful read and write and shared by every store handle in the process
  (keyed by the keystore directory too, so two keystores keep apart), and refuses a record
  below it with `ErrCorrupt`, naming the rollback. That mark is checked over a readable floor
  too, against the larger of the two: a withdrawal whose floor line failed leaves the floor one
  behind the record, and an earlier copy put back at the floor's sequence is still refused
  in-process rather than re-sealed with its tombstone lost. A withdrawal of a UID already withdrawn appends the record's floor line
  again when the floor it reads is below the record's sequence, so a floor line an earlier
  withdrawal could not append is written by the next one; that catch-up is in the revocation
  class (admitted past the hard cap on the uid's revocation budget, its line held only to the
  revocation's free-space slack), since it finishes a revocation. It appends nothing when the
  floor already holds that sequence, so a repeat adds no line, and its audit line is not
  marked a revocation: only a withdrawal that sealed its tombstone or appended a catch-up line
  is, whether or not its floor line then failed (`errCommitted`), as for `rm`. More
  generally, every operation that holds the exclusive store lock and reads the authenticated
  delivery record against a floor it can read (`deliver`, and `withdraw` whatever it finds,
  an unknown UID included) appends the catch-up line, in the revocation class, before it
  serves, when the floor is behind the record. The process's mark does not survive a restart;
  the catch-up line does, so after a restart the earlier record copied back at the floor's
  one-behind sequence is refused, not re-sealed. A user entry's floor line is always at
  sequence 1, so it needs no sequence catch-up, but a `put` can lose the line itself after its
  commit (a crash between the pointer and the floor line, or a floor that refused it), and
  then the entry's generation rests only on its tree, which a tree-writer can rewrite before
  the user runs `rm`. So the server-start catch-up (`catchUpUser`, below) also appends, scope
  by scope and best effort, a live floor line at the pointer's sequence for every user entry
  whose pointer authenticates under `K_u` and whose authenticated generation has no floor
  line; a generation a tombstone buries is never given one, and a line the floor refuses is
  logged at Warn and named in the error. `rm` also buries the generation its pointer
  authenticates under `K_u`, when `W` and `K_u` load (best effort: `rm` needs neither). A
  tree-writer who rewrites the pointer's header breaks its authentication, so only the start
  catch-up covers a lost line whose tree was then rewritten throughout. `rm` is a revocation too: it
  only removes files, so it needs neither `W` nor `K_u`, and is never refused for a lookup
  that ran and failed or timed out, or for `ErrRewrapInProgress`. A lookup refused at once for
  capacity, where none ran (eight already outstanding, or an earlier call for the uid stuck past
  its deadline), refuses `rm` with a retryable error and removes nothing: going ahead on it would
  let a burst of stuck lookups stand in for the owner check. A withdrawal does no lookup, so it
  goes ahead in every case. A lookup that answers a real
  GeneratedUID other than the one `scope.key` records refuses it with `ErrScopeOwnerChanged`:
  the uid was reused, and its new holder must not delete the former owner's values (root
  removes such a scope).
  *Residual (floor unverifiable at a withdrawal).* With the floor absent, untrusted, unflagged
  or unreadable, a withdrawal of a live delivery is refused and seals nothing, so the
  delivery stays live in the record until root repairs the floor and the withdrawal is run
  again; the value leaves the cluster by the reconciler's delete-anyway rule meanwhile. A
  restored older record is never re-sealed at a fresh sequence: once the floor reads again it
  stays below it and refused. A withdrawal of a UID the record already holds withdrawn changes
  nothing and succeeds.
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
  A line is `<scope> <name> <generation> <seq> <crc>` and a newline: a `user/<uid>` scope, an
  entry name or `.deliveries`, the generation in 32 lowercase hex digits, the sequence in
  decimal with no leading zero, and the line's **checksum**, 8 lowercase hex digits of CRC-32C
  (Castagnoli, the standard library's `hash/crc32`) over the bytes before ` <crc>`; one space
  between fields, parsed strictly: the field must be there, canonical, and match. A
  **tombstone** is the same line with the literal `rm` in place of the sequence, for an entry
  name only (`.deliveries` is never deleted): `<scope> <name> <generation> rm <crc>`. The
  checksum makes every line self-delimiting: a line torn or flipped in place fails it, so a
  tear an append closed can never parse as a lower sequence (`… 123 <crc>` torn to `… 12`
  is damage, not sequence 12), and CRC-32C detects every error burst of up to 32 bits, every
  single flipped byte among them (`TestEveryTruncationAndFlipNeverParses`,
  `TestClosedTearRefusesKnownGeneration`, `TestDeliveryTearClosedKeepsTaint`,
  `FuzzParseFloorLine`, `FuzzLogSyncDifferential`). The audit log's JSON lines carry no
  checksum: they gate charging only (the past-cap per-uid charge), never a refusal of a key,
  and a torn or flipped audit line is either skipped as damage, which charges nobody, or a
  line in its strict grammar, charged to the uid it names; neither can resurrect an entry, so
  the checksum would protect nothing the floor relies on. A line at sequence 0 is **present**: the
  reader records its key on the first line for it, whatever the sequence, counts it against
  the key bound and lists its generation as live (so `rm` buries it), since `floor --rebuild`
  writes sequence 0 for an entry with no authenticated pointer and that line is what keeps
  the entry damage; no server write uses sequence 0. **Absent is not
  malformed.** A floor that is absent or cannot be read (a clear flag, a wrong owner, an I/O
  error) refuses every grant and read, and lets a revocation go ahead as far as it seals
  nothing: `rm` is refused before it removes anything, since it must bury first, and a `withdraw` of a live delivery is refused with the
  named error that says to delete the Secret anyway (see "Revocation always succeeds"). A read I/O error is
  that transient case, never damage: the reader does not keep it, and the next read tries the
  file again from the last whole line it read. **A line that does not parse is skipped.** A
  line outside the canonical grammar, a line over 1 KiB, or a last line with no newline (a torn
  or forged tail) is never applied to the state and never refuses the floor: the reader skips
  it and counts it as damage, which root reads through `FloorDamage` for `doctor` and which the
  server logs at Warn when first seen. Skipping never removes a tombstone already read, and
  a forged valid line is the accepted same-uid model, but **a skipped line can be a
  tombstone**: a line the reader cannot parse may be the one that buried a generation. So
  damage is classified, and scoped where it can be (**damage and taint**,
  `userfloor_taint.go`): a skipped line, the torn last line included, is classified by what
  of it still parses, its leading fields read strictly, each followed by its space.
  **Whether a line could be a tear decides how it is read, never whether it looks whole**: shape is itself data a flip can change. A tear only shortens an append
  buffer, and every buffer is `"\n" + line₁ + "\n" + line₂ …`, so a torn line is a strict
  prefix of one line in the grammar, the last of its buffer (`couldBeTear`: a scope prefix,
  then a name prefix, a generation prefix, a sequence or `rm` prefix, then a prefix of the
  checksum of the bytes before it, each field before the last whole and canonical, at most
  four spaces). Such a line is classified by the prefix it is, the ladder below. A line that
  could be a tear but whose last field is checksum-shaped and that parses with one or two
  bytes flipped back to a space is not read as one: two separators flipped to `0` merge a
  name, a generation and `rm` into one valid name, a prefix of a line for another key.
  **Any other line was flipped, and is corrected.** CRC-32C detects and locates every
  single-bit error in a line this short, so it is tried against every single-bit correction
  (a flip that restores a separator, removes one flipped in, or restores a byte of a field,
  the checksum's digits included; a body flip is found through the checksum's syndrome, so
  the search is linear in the line), and against every byte one bit from a newline flipped
  back to one: a newline flipped away merges two lines into one with up to eight spaces, and
  the correction splits it into pieces that are each empty or a line that parses. When
  exactly one candidate parses with a matching checksum, the key of each line it recovers,
  that generation, is tainted: a tombstone flipped in its scope, its name, a separator or
  the newline between it and the next still refuses the generation it buried. A line that
  is neither a tear nor uniquely corrected is an **unrecovered flip**, whatever its shape,
  garbage and a line with more than the grammar's four spaces included: it counts as
  unattributable damage and, while it counts, refuses every generation of every key, known
  ones included, for `current`, a catch-up line and every grant; only the acknowledgement's
  watermark lifts it, as it lifts other unattributable damage (`TestEveryTombstoneFlipRefusesKnownGeneration`,
  `TestFlippedTombstoneScopeRefusesCopyBack`, `TestUnrecoveredFlipRefusesKnownGenerations`,
  `TestEveryBurialBufferFlipRefusesEveryBuried`,
  `TestEveryTwoBitTombstoneFlipTaintsTrueKeyOrUnrecovered`, `TestCouldBeTearMatchesOracle`,
  `FuzzCouldBeTear`, `FuzzBurialFlips`). A two-bit flip that leaves a line a valid tear
  prefix of a live line for another key (a separator flipped to a digit before an all-digit
  checksum, and a second bit in the scope or name) is indistinguishable from a tear; a
  tombstone, whose fourth field is `rm`, has no such pair.
  Otherwise: `<scope> <name> ` followed by a whole 32-digit generation,
  then a space or nothing, **taints** `(scope, name, generation)`; `<scope> <name> ` with no
  whole generation taints `(scope, name)`, every generation (`TestFlippedGenerationDigitTaintsName`).
  A line torn
  inside its name, `<scope> <partial-name>` with the scope's space and no space after the
  name, taints **by name prefix**: every key of that scope whose name starts with the
  partial name (the empty partial covers the whole scope), the delivery record's included
  when it matches; the partial must be a prefix of the delivery record's name or of some
  valid entry name. `<scope> ` followed by anything else taints the scope, every name of it.
  A line torn inside its scope, a prefix of `user/<uid>` with no space,
  taints **by scope prefix**: every scope whose canonical text starts with it; it must be
  `user/` and at least one digit, with no leading zero, and extend to a uid in range. A key
  a prefix covers is refused exactly as a name taint refuses it. The delivery
  record's name is taintable like any other, so a torn `withdraw` line taints the delivery
  record. A tainted key is refused for every generation, known or not (`errFloorDegraded`):
  `current` of it, a `put` or `deliver` line for it, and any catch-up line for it (the
  delivery record's catch-up, whether the start step's or a repeated `withdraw`'s, goes
  through the one check, `liveRefused`, so a repeated `withdraw` whose line it refuses
  changes nothing, `TestDeliveryCatchUpPathsCheckLiveRefused`); a
  corrupted tombstone of a known generation so still refuses its copy
  (`TestCorruptTombstoneOfKnownGenerationRefused`). Anything
  else, a scope that does not parse and is no valid prefix, or a line
  over 1 KiB, is **unattributable** and keeps the floor-wide fail-closed rule: no `put` or
  `deliver` line is written (refused before the first write), no catch-up line for a
  generation the floor holds no line for, and `current` of such an entry generation is
  refused. The taint set, prefix taints included, is capped at 64 entries (each entry's
  scope and name are a line's fields, so the count bounds the bytes too). A taint past the
  cap **overflows** the set, which sticks for the file and fails toward more refusal: every
  generation of every key, known or not, is refused for grants and reads, as though each
  key were tainted. The overflow is never demoted to unattributable damage, so the
  acknowledgement never lifts it; `rm` and `withdraw` still run
  (`TestFloorTaintOverflowRefusesEveryKey`). A known, untainted generation is served over damage, logged at
  Warn once per process for each damaged file. `rm` and `withdraw` still work: a tombstone
  and a withdraw's delivery-record line can only revoke (`TestTornBurialTaintsOnlyItsKey`,
  `TestTornBurialEveryCutRefusesKnownGeneration`, `TestClassifyEveryPrefixTaintsItsKey`,
  `TestPrefixTaintMatches`, `TestPrefixTaintCapped`, `TestSkippedScopePrefixTaintsItsScopes`,
  `TestTornWithdrawLineTaintsDeliveryRecord`,
  `TestUnattributableDamageKeepsFloorWideRefusal`, `TestFloorDamageDegradesLiveLines`).
  **The damage acknowledgement** is the exit that keeps revocations: root writes
  `keystore-user-floor.ack` in the data root, root-owned, not group- or other-writable,
  a regular file, no file flag and no extended ACL (anything else is ignored, which fails
  closed); a second link is a Warn, never a refusal (§ "Root-written files and hard links"). It is one line,
  `k3sm-user-floor-ack v1 <ino> <birth-sec> <birth-nsec> <watermark>`, in canonical
  decimal: the floor file's inode and birth time and its size when root acknowledged it.
  For that file, unattributable damage that starts before the watermark no longer counts,
  so the floor-wide rule and the start step's quarantine it caused are lifted; a taint is
  never lifted, so a torn tombstone stays in force; damage at or past the watermark counts
  again; and an acknowledgement for another file is ignored
  (`TestFloorDamageAckLiftsOnlyUnattributable`). It is written by the unexported,
  root-only `ackFloorDamage`, a compare-and-set under the exclusive store lock and the
  floor's mutex: it refuses unless the floor's size, its count of unattributable damaged
  lines and its count of unrecovered lines are still the figures root reviewed, and writes
  through the data-root descriptor it judged, never a second open by path
  (`TestFloorDamageAckRefusesChangedFloor`, `TestFloorDamageAckRefusesStaleUnrecovered`).
  Root reviews through `floorAckView`, which reports the size, the unattributable count
  (the torn last line and the unrecovered lines included), the unrecovered count on its own,
  and the byte offset where each unrecovered line starts (the first 64, in file order; the
  count is never capped) (`TestFloorAckViewGivesUnrecoveredOffsets`). Acknowledging
  unrecovered lines accepts that a tombstone one of them held may stay lost: below the
  watermark every known generation is served again, and a copy back of a generation whose
  tombstone was in such a line is no longer refused by it. Still under
  the store lock it then runs the catch-up again so a scope quarantined only by acknowledged
  damage is served; that catch-up writes a live line only for a generation with an
  authenticated pointer and no damaged line that could name its key
  (`TestFloorDamageAckCatchUpSkipsAttributable`); no verb writes it yet, and `errFloorDegraded` names it
  only as root maintenance. The audit log's damage gates nothing (it is counted and logged,
  never refused on), so it has no acknowledgement. Only a floor past the reader's bounds (larger than its size bound, or holding
  more keys than its key bound), which the server never writes, is damage that refuses with
  `ErrCorrupt` naming the matched-set restore, which brings back every entry deleted since the
  backup, then `floor --rebuild` and `doctor`: every grant and read, and a
  revocation that re-seals a record (a `withdraw`), since that revocation would re-seal it
  checked against no floor (U20). An `rm` over a floor that is absent, unreadable or past its
  bounds is refused before it removes anything (see "Bury, or remove nothing" below). `floor --rebuild`
  and `audit --rotate` are built (the append-only files): each remedy names the verb that
  recovers, or the matched-set restore (`keystore/`, `keystore/.user/` and both logs, from
  one backup) followed by them, and `doctor`; no string says a verb is not yet available
  (`TestErrorsNameNoUnbuiltVerb`).
- **`rm` buries.** A user entry's floor line is always at sequence 1, so a sequence alone
  cannot refuse a tree copied back after an `rm`. So `rm` appends a tombstone for the entry's
  `(scope, name, generation)` under the exclusive lock, before it removes anything: bury
  first, so an `rm` whose removal fails part way leaves the entry refused. The `generation`
  file is not authenticated, and a tree-writer who cannot read the master can swap it to
  another valid value, so the entry reads as damage and the user runs `rm`. So `rm` trusts no
  one source: it buries every generation the floor holds a live line for under
  `(scope, name)`, the `generation` file's value, the generation in the current
  pointer's header and the generation in each `v<N>` version record's header, the headers
  parsed without a key, and, when `W` and `K_u` load and the pointer authenticates, the
  generation the pointer authenticates, which is no tree claim and counts against the same
  reservation. A source that does not read or parse adds nothing (a tree a
  crashed `put` left has no pointer). Those tree sources are unauthenticated, so one `rm`
  buries at most 4 distinct generations (`maxTreeGenerations`) named only by them beyond
  the floor's live ones: past that, it stops reading headers, buries the floor's live
  generations, the authenticated pointer's and the pointer header's, removes the tree and reports, as after a commit
  (`errCommitted`), that the tree was altered, so a planted tree of many `v<N>` headers cannot
  spend the floor's revocation headroom through one `rm`. The floor's live generations are taken first and
  buried **whatever stands at the name**: a directory (with the tree's sources added); a
  file or a symlink, which `rm` buries, then removes (the symlink itself, never what it
  names) and reports as after a commit (`errCommitted`) naming the shape; or nothing, when
  `rm` buries the live generations and succeeds, so an `rm` is idempotent and an `rm`
  retried after a failed burial, once the tree is gone, still closes the window. A
  directory `rm` cannot open is not read for its sources: `rm` buries the floor's live
  generations first, then returns the open's error with the tree left standing (as after a
  commit when it buried any), and is refused if the floor does not take the tombstone. So
  does an `rm` whose `scope.key` reads and whose owner check passes but whose `entries/`
  cannot be opened (missing, `ErrScopeAbsent`, or not what the store made) or whose name
  cannot be judged (an `Lstat` error other than not-found): it buries the floor's live
  generations for the name, then returns that error, as after a commit when it buried any. A
  `scope.key` that cannot be read still refuses the `rm`, with nothing written. An
  absent name with no live generation is `ErrNotFound`. A name that stands with no source
  naming any generation (no live floor line, no `generation` file and no record header that
  reads) is refused before anything is removed, wrapping `ErrCorrupt`, naming the remedy:
  root's `floor --rebuild`, which records the entry's generation, then `rm` again, or removing
  the entry's directory by hand. An entry directory with nothing sealed in it (no `current`
  and no `v<N>` file, as a crash between the put's `mkdir` and its `generation` write
  leaves) holds nothing a copy could be served from, so `rm` removes it instead. When the ones that read disagree, `rm` still buries
  them all and removes the tree, and reports the mismatch, naming each source's generation,
  as after a commit (`errCommitted`), so the operator learns the tree was altered (U20). `current` and
  `list` refuse a buried generation as deleted, wrapping `ErrCorrupt`, with a message whose
  normal action is "the entry was deleted; rm it and put it again" and which names root's
  `floor --rebuild` only as the last resort, for a deliberate restore. A later `put` of the
  name mints a fresh generation, which no tombstone names. **Bury, or remove nothing.** If the
  floor is absent, cannot be read, or does not take a tombstone (too little free space, a
  write error), `rm` is refused with a named, retryable error before it removes
  anything, so no tree is ever removed without its tombstone; the user retries once root has
  repaired the floor. **A burial is one write.** `rm` builds every tombstone of its burial
  into one buffer, the generation a reader serves first (the one the pointer authenticates
  under K_u, or, when that is not read, the pointer header's), and appends it with the
  writer's checks over the whole buffer (`appendLines`, the same admission and key checks a
  single line gets): past the hard cap, every tombstone line that starts there against its
  uid's revocation budget, and the buffer against the reader's bound; the tombstones that add
  a key (a generation the floor does not hold) against the key bound plus the revocation
  headroom; and the buffer's block-rounded reservation (the whole 4 KiB blocks it takes),
  plus the 1 KiB audit line the `rm` appends after it, plus the revocation slack against the
  free space, so the audit line's own preflight, the revocation slack plus its line on what
  the burial leaves, passes too: for every free space the burial is refused before anything
  is written or the burial and its audit line both land
  (`TestRmBurialFreeSpaceCoversItsAuditLine`). Then one `F_PREALLOCATE` reserves the
  whole buffer and one `write(2)` on one descriptor appends it, so a burial lands whole or not
  at all, short of a crash. A refusal, a refused reservation, or a write that fails or lands
  short before its first whole tombstone refuses the `rm` with nothing removed; short bytes
  are a torn tail, which the reader skips as damage, and a retried `rm` buries again (U20).
  A write that fails or lands short after one or more whole, newline-terminated tombstones
  has put them in force: the writer re-reads the tail on its descriptor (falling back to the
  byte count the write reported) to count them, and the `rm` is committed, `errCommitted`,
  audited as a revocation, its tree kept and the rest buried by a retry; it never answers
  "nothing removed" while a tombstone stands. Its text says the entry is refused as deleted
  only when the served generation's tombstone landed; otherwise it names the generations
  whose tombstones did (`TestRmBurialServedPointerFirstWithoutKu`,
  `TestRmBurialPartialNamesLandedWithoutServed`). No server path leaves a name with two live floor
  generations (put is create-only, a put after `rm` mints a new generation over the buried
  one, and a catch-up writes the tree's own), so the burial bound needs no room for a
  second live one (`TestServerPathsLeaveOneLiveGeneration`). (A floor that takes tombstones one by one, as the test
  fakes do, keeps the older rule: once any tombstone has landed the entry is revoked, so a
  later one that fails is after the commit, `errCommitted`, audited as a revocation with
  result `committed`, its text saying the entry is refused as deleted and its tree stays.) A removal that
  fails once the tombstones are written is after the commit (`errCommitted`, audited as a
  revocation), and its text says the entry is refused as deleted with its tree not fully
  removed, never that nothing was removed. Here `rm` departs from "revocation always succeeds", as a `withdraw`
  over an unverified floor already does: removing the tree anyway would open the window in
  which a copy put back is served. Only when no generation reads from any source (the floor
  holds none and the tree names none) does `rm` remove the tree with nothing to bury, and it
  reports that as after a commit (U20).
- **A torn tail.** Every append is one `write(2)` of one whole line, and before it the server
  reads the free space of the log's file system with `fstatfs` on the log's descriptor and
  refuses, with a named, retryable error and nothing written, when less than 1 MiB plus the
  line is free: a refusal, never damage. A revocation's line (`rm`'s tombstones, a revoking
  `withdraw`'s floor line, and their `revoke` audit lines) is exempt from that margin and keeps
  only a minimal check, the line plus the revocation slack (two 4 KiB blocks plus the
  1,024-byte longest line, 9 KiB), so a nearly full volume still records a
  revocation; below that it is refused: a `withdraw` is reported as after a commit, and an
  `rm`, which buries before it removes, is refused with nothing removed. Nor
  does the floor's key bound ever refuse a revocation's line for a key the floor already holds
  (U24). Past the preflight, and still before the write, the server reserves the line's
  blocks on the descriptor it appends through: `fcntl(F_PREALLOCATE)` with `F_ALLOCATEALL`
  and `F_PEOFPOSMODE`, sized to the bytes it writes rounded up to whole 4 KiB blocks, which is
  the most new blocks an append of that size can take past the file's physical end. The
  reservation is all or nothing; a refused one is the same named, retryable no-space error,
  and nothing is written. This closes the disk-filler race: the free space the `fstatfs`
  saw can be taken by another writer before the write, but the reserved blocks cannot, so the
  `write(2)` that follows on the same descriptor never runs out of space part way, and an
  `ENOSPC` can no longer leave a torn tail. The 9 KiB revocation slack stays a margin over
  the reservation, not the guarantee. The residual is an `EIO` mid-write or a crash
  mid-write: either can still leave partial bytes the flag makes unremovable. A last line with
  no newline is skipped, counted damage, never an outage: the next append closes it with a
  newline of its own, and the floor keeps serving reads and revocations, in the degraded mode
  above for live lines. What is lost is the torn line's own record,
  and that operation was not reported as done. That residual is accepted. Off darwin no log is append-only, none is appended to, and the reservation is
  refused.
  So no append merges into a torn or foreign line: in either log **every append leads with a
  newline**, in the same `write(2)`, never judged from the tail, since a foreign writer
  could still add an unterminated fragment between any check of the last byte and the
  write. Torn or foreign bytes before it become a line of their own, which the reader skips
  as damage and charges to no uid, and every line of the append parses (U20, U23,
  `TestForeignFragmentBeforeWriteIsOwnLine`); with no such bytes the newline is an empty
  line, which the reader passes over as benign, never damage. **A torn tail is frozen where
  it was first read.** A foreign writer's bytes with no leading newline could still complete
  a torn last line into one that parses (a torn tombstone into a live line, a torn sequence
  into a lower one) or grow it into one that names another key, so the reader keeps the torn
  fragment's bytes by offset: while the tail stays torn it is classified by those bytes, and
  the line that later starts there is skipped as damage, classified by the fragment, unless
  it is exactly the fragment and a newline, the server's own close
  (`TestForeignCompletionOfTornTailStaysTainted`, `TestForeignGrowthOfTornTailKeepsTaint`).
  Within a process, freezing was chosen over writing a lone newline when a tear is seen: a
  seal is one more write a foreign append can land just before, so it is exact only with a
  check of where it landed, while the frozen bytes are exact for every read after the first
  by this server. **At each start the tail is sealed**, because the freeze lives only in the
  process's memory and does not survive a restart: the start step, under the exclusive store
  lock and before the delivery catch-up, writes to the floor and to the audit log the one
  leading newline the next append would write, when the log's last byte is not one, before
  any foreign byte can follow it. That newline closes the fragment; it never makes it parse,
  and the closed fragment is still counted as damage (on the floor, classified by
  `taintLine`), so nothing is hidden and nothing is repaired into a valid line. A tail torn
  only at its newline, whose bytes would parse once closed, is left as it is, since no
  foreign byte can complete it into another line. A seal that fails is logged at Warn and
  that process reads the tail frozen
  (`TestStartSealsTornFloorTail`, `TestStartSealsTornAuditTail`,
  `TestStartSealLeavesTailTornAtNewline`, `TestForeignCompletionAcrossRestartStaysTainted`).
  A tail torn and completed before the server first reads it reads as the bytes say. The
  leading newline costs one
  byte per append: past the hard cap it is charged to the uid with the append's lines, and
  every bound that sums appends counts it (one append of one line is at most 1,025 bytes,
  `maxAppendLine`, which is what `room`, a grant's pre-check and the store-open spent test
  charge). An append whose `fsync` fails is not known durable, but the lines it left visible are
  what every reader holds in force: the tail is re-read from the file's real end (a fresh
  `fstat`, not the size the open saw), and when whole lines of the append are visible in
  order an `rm` is committed, says "durability uncertain; run rm again" and is audited as a
  revocation (`TestRmBurialSyncFailureVisibleCommits`); with no whole line visible it counts
  as nothing landed, so the `rm` is refused with nothing removed and says to run it again
  (`TestRmBurialSyncFailureRefuses`). A write that failed or landed short counts the whole
  lines it left the same way. Either way the append's bytes are found by searching back from
  the real end of the file, so a foreign append between the open and the write does not hide
  them (`TestRmBurialForeignAppendBeforeShortWriteCommits`). A torn floor tail needs no
  restore, which would bring back every entry deleted since the backup: it taints the key
  it could name, or, when no key can be read from it, holds the floor-wide rule until root
  acknowledges it (the damage acknowledgement above).
  The recovery is root's `floor --rebuild` (or `audit --rotate` for the audit log), which
  stops the listener, rewrites the log from the entries on disk and the old floor's lines that
  parse, and resets every uid's share ("Rebuild carries the old floor forward"); its cost is
  the user-scope downtime of the run and the lines it drops because they do not parse (the
  torn tail among them, which the reader already skips), which it counts and names, never a
  tombstone or a sequence that parses, so a crash followed by a rebuild brings back no deleted
  entry (U193). A torn or garbage line needs no rebuild: the reader skips it.
- **Write order.** Phase A's: the record, the pointer, then the floor line. A crash between
  the last two leaves the floor one behind, which the rule accepts, and the next user-scope
  write to that entry appends the line. A `put` refuses, before its first write, a floor
  line the floor would refuse after the commit: under the lock it reads the floor and
  refuses with `ErrLogFull` when one of its lines (two when it mints the scope: the delivery
  record's, then the entry's) would start at or past the hard cap, take the floor past the
  reader's bound or past its key bound, and with the named free-space error when the 1 MiB
  margin would not hold them together with the entry files the `put` writes before them
  (version 1, its pointer and its `generation` file), so the margin is judged for the value
  too, on the data root's volume. A `deliver` runs the same check before it seals anything, for
  its delivery record's line (and, when it mints the scope, the mint's line for the same key).
  Every floor line is appended after its change has committed, as that change's integrity
  record, so the append itself is held only to the 9 KiB revocation slack, whatever its class
  (the key bound, the hard cap and the revocation budget still follow the class): a volume
  filled between the check and the append past the 1 MiB margin does not cost a committed
  `put` its line. So a committed `put` or `deliver` without its floor line is left only by a
  crash, an I/O error, or a volume filled past the slack as well between that check and the
  append.
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
     2026-11-22: K0 picked the flag variant, so `keystore.sh` prints U70 and U71 as N/A, counted neither pending nor passed.
- **The flag is checked, not assumed** (flag variant). The server reads `st_flags &
  SF_APPEND` on both logs at start and at every `doctor` run, through the chflags flag source,
  and refuses to start the listener if either flag is clear or either file is not the
  service user's (U21).
- **Root maintenance verbs.** `sudo k3sm keys floor --rebuild` (the restore procedure) and
  `sudo k3sm keys audit --rotate` run as root only, and need no server stop. Each first takes
  the floor lock `keystore-lock`, which only root can open (Open requirement 2), and then the
  store `.lock` exclusively, the order every verb that takes both keeps ("Concurrency"). The
  wait for `.lock` is bounded at 30 s: the verb gets it once no server operation holds it, and
  past 30 s it refuses, changing nothing. The verb already holds `keystore-lock`, which every
  root verb takes first, so the holder is a process running as the service user, and the
  refusal says so and names the remedy: stop the server (`sudo k3sm stop`) or that process.
  Only then, holding both locks, does the verb write the marker `keystore-maintenance`, so no
  marker stands while a verb waits. The listener stops while the marker stands (it closes its
  connections and stops accepting; launchd keeps the socket bound). The verb **builds the
  whole replacement before it touches the live set**: rebuild writes the new floor from the
  old floor and the scopes' entries, walking `.user/` by descriptor ("Root walks service-user
  trees by descriptor"); rotate writes an empty new log and its archives; each inside its own
  replacement directory in `keystore-staging/` ("The swap").
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
- **Rebuild carries the old floor forward.** Before it writes the new file, rebuild reads the
  old floor line by line, as root, on its own descriptor ("Rebuild reads a flooded floor":
  streamed, with no size bound). It keeps every tombstone and every key's highest sequence that
  its admission classes admit. It drops the lines that do not parse (a torn tail, a line
  outside the grammar), the lines over 1 KiB, the lines past a uid's share, the lines of absent
  scopes past their share or the key bound, and the keys of scopes root removed and recorded,
  and counts each class in its output, never their bytes.
  The audit line has no field for a count: a rebuild that dropped anything exits 4 and its
  audit line's result is `committed`, so the counts are in the verb's output. The new file holds, per key, the higher of
  the carried-forward sequence and the one on disk, and every carried tombstone, which the
  entry lines never override, so a buried generation stays buried and a copied-back older
  record stays refused across a rebuild. *Residual (the dropped lines).* What a dropped line
  recorded is lost: a tombstone on a line that does not parse no longer buries its
  generation, and a dropped sequence line lowers that key's floor to what is on disk, so a
  tree or record copied back for that key after the rebuild is served. A server crash can
  only tear the last line, so the loss after a crash is at most the one line a revocation or
  a grant was appending, and that operation was not reported as done; any wider loss is
  damage done to the file while its flag was clear, which the count names. A deliberate
  restore that lowers is the matched-set restore ("Backup and snapshots"): the restored floor
  log is the old floor rebuild carries forward, so the floor lowers to the backup's, and every
  entry deleted since the backup comes back. A floor
  that cannot be opened or read at all refuses the rebuild, which changes nothing (U193).
- **Rebuild reads a flooded floor.** The service user can append to the floor without limit,
  so it can push the floor past the steady-state reader's bounds (`logReadBound`, the key
  bound) at will. The steady-state reader keeps those bounds: a floor past them is damage that
  refuses grants and withdraws. The audit reader's memory is bounded the same way: beside the line
  buffer it keeps, per uid, the bytes charged past the hard cap, and it charges at most
  `maxRevokeUIDs` + 64 (1,088) distinct uids; a log charging more is sticky damage, as a log
  past its size bound is, so forged lines of many uids grow nothing. Rebuild is the repair for a floor past them, so it never
  refuses for size: it streams the old floor with no size bound, one line at a time through a
  buffer of the per-line bound (1 KiB), and its memory is the admitted keys, at most the
  reader's key bound, plus that buffer, whatever the file's size. A line over the per-line bound is skipped
  to its newline and counted; a line that does not parse is dropped and counted. It reads the
  floor in passes and admits its lines by four rules: (1) for a scope present on disk, every
  line whose key is on disk, and every tombstone, whatever the uid's share: the writer takes a
  revocation's tombstone past the per-uid share (only the global bound is checked then), so a
  real scope's tombstones can lie past its share, and dropping one would reopen a copy-back;
  (2) for a scope present on disk, its other live lines (other generations with no entry),
  oldest first, up to the uid's lifetime key share (`uidKeyShare`, 4,112 keys), within its
  class's room; the excess is dropped and counted as "past the uid's share"; (3) for a scope
  absent from disk and not recorded as removed, its tombstones first, per uid up to the share,
  uids in first-appearance order, within its class's room; then, only once every tombstone of
  every absent uid is in, their live lines, per uid up to the share less its tombstones, in the
  same order, in whatever room is left under the key bound; the rest is dropped and counted as
  "absent scopes"; (4) for a scope root removed and recorded, its lines before the recorded
  offset are dropped ("Rebuild drops a removed scope's keys"), and later lines, a re-minted
  scope's, fall under (1) to (3). Rule (1) is admitted first, and rule (4)'s drops apply, by
  identity, throughout. The room rule (1) leaves under the key bound is then split evenly
  between the two classes no line of which is authenticated: (a) rule (3)'s tombstones and (b)
  rule (2)'s live lines. A class that needs less than its half gives the rest to the other.
  Rule (3)'s live lines come last. An absent scope's tombstone is what refuses its copy-back,
  and a present scope's live line with no entry directory is its rollback protection for an
  entry whose directory was removed outside `rm`; the service user can forge either, so
  neither class may crowd the other out: a forger of one class spends at most its half, and
  the real lines in the other half are safe. Counting each class's need is one more pass,
  holding at most the room's keys. Any drop exits 4 with the counts by class. Two bounds govern admission. Rules (2) and (3), the trimmable
  classes, stop admitting at the key bound (`keyBound`). Rule (1) is held only to the
  reader's key bound (`readKeyBound`: the key bound plus the revocation headroom,
  `keyBound` / 16), the bound the steady-state reader enforces: the writer lets a revocation's
  line add a key into that headroom, so a floor the writer produced, and the server reads, can
  hold real tombstones past the key bound, and rebuild must carry it. The new floor therefore
  holds at most the larger of rule (1)'s keys and the key bound, never past the reader's key
  bound, and rebuild checks that before it writes. The one refusal left is rule (1) alone
  passing the reader's key bound:
  rebuild refuses, changing nothing, names the scopes with the most keys, and `rm-scope` of
  one is the repair, which works whatever the scope's delivery record holds once it does not
  name a delivery, and also when that record does not read ("rm-scope revokes first"). Rebuild
  bounds what it collects from disk the same way: while it walks the scopes (a walk bounded by
  the listing bound of `.user/`), it checks the keys and entry names it has collected against
  the key bound, stops once they pass it, and refuses before reading the old floor, naming the
  scopes with the most entries, so its memory is the key bound's whatever the tree holds.
  *Residual (forged lines).*
  Floor lines are CRC-checked only, so the service user can write any line. Forged live lines
  of a real uid are held to that uid's share and to their class's half of the room, and forged
  tombstones of absent uids to each uid's share and to theirs, so neither class evicts the
  other's real lines past its own half. What it can still do: fill one class's half with forged
  lines of uids that appear earlier in the file, so real lines of that class (an absent
  scope's tombstones after a directory deleted by hand or a full record; a present scope's
  live lines whose entry directory was removed outside `rm`) can be dropped behind them, and a
  copy put back, or a rolled-back entry, is then served at what is on disk; spend a real uid's share with forged keys, which the writer
  already charges to that uid, so its later grants are refused (the self-lockout of "Per-uid
  fairness"); and, since a present scope's tombstones are never dropped, write forged
  tombstones for a present uid past the reader's key bound, which forces the one refusal; its repair,
  `rm-scope` of the scope it names, removes that uid's scope. Rebuild never drops a tombstone
  of a scope present on disk.
- **Rebuild drops a removed scope's keys.** Once root has removed a user scope with
  `rm-scope`, which lists the scope key's identity in `keystore-removed-scopes.json` with the
  floor's byte size at that moment and then deletes the scope directory, `floor --rebuild`
  carries none of that scope's keys forward, live or buried: no line of the recorded
  `user/<uid>` that starts before the recorded size reaches the new floor. It drops by
  position, not by uid: every line of the uid before the recorded size was written while a
  removed scope stood (rm-scope holds the store lock, so no legitimate line lands between the
  size and the removal), and every line at or after it is a later scope's, a re-minted one,
  which is kept whether its directory stands or was deleted by hand. That is safe because the record, not the deleted directory, is what
  keeps the scope removed: K_u is not gone, since a copy of the old directory put back still
  holds a `scope.key` wrapped under the unchanged master, but every open of a scope key the
  record lists is refused ("A removed scope stays removed"), so no old tree, record or
  copied-back entry is served, and none needs a tombstone to be refused. A re-minted scope for
  the same uid gets a fresh K_u, which the record does not list. It is what frees the uid's
  lifetime key share and those keys in the global key bound ("Per-uid fairness", residual
  self-lockout) (U194). An absent scope the record does not list (a full record, or a
  directory deleted by hand) keeps its keys, and so does a re-minted scope whose directory is
  later deleted by hand: its tombstones still refuse a copy-back of it. The offset names a
  position in one floor file, so each removal records it with that floor log's identity, its
  device, inode and birth time, as the floor ack binds its file (`floor_dev`, `floor_ino`,
  `floor_birth_sec`, `floor_birth_nsec`, beside `floor_size`), and rebuild applies a removal's
  drop only when the old floor it reads matches all three, so a file put at a freed inode
  number never takes a drop. The floor a rebuild swaps in is a new file, so an offset never
  applies to a floor it does not describe, and the record is written only by `rm-scope`:
  rebuild never rewrites it, so a refused or crashed rebuild has changed nothing and a later
  rebuild of the same floor still drops the removed scope's lines. A record without the whole
  identity (written before it existed, or with `floor_ino` alone) drops nothing (fail closed).
- **A removed scope stays removed.** `rm-scope` records the removed scope in
  `keystore-removed-scopes.json` in the data root before it removes the directory: root's,
  mode 0644 (the service user's opens read it; it is closed to group and other writes),
  written to a temporary name, fsynced and renamed through the judged data-root descriptor, the
  data root fsynced; read with `O_NOFOLLOW` and judged on its descriptor (a regular file of the
  data root's owner, not group- or other-writable, no file flag, no extended ACL, at most
  256 KiB; a second link is a Warn, never a refusal); parsed
  strictly (one JSON object `{"version":1,"scopes":[{"uid":…,"keys":[…],"floor_size":…,"floor_ino":…,"floor_dev":…,"floor_birth_sec":…,"floor_birth_nsec":…}]}`,
  no unknown field, no trailing data, each uid listed once, each key 64 lowercase hex digits
  listed once, at most 1024 keys in all, `floor_size` not negative and 0 when absent, the identity fields 0 when absent, the birth
  nanoseconds under 10^9). A record holds per uid the identity of each scope key removed and
  the user-scope floor log's identity (device, inode, birth time) and byte size when rm-scope
  last listed a key of the uid, which rebuild, reading the floor of that identity, drops the uid's lines before
  ("Rebuild drops a removed scope's keys"): a labelled
  SHA-256 of the scope and K_u, which Rewrap leaves as it is (it re-seals the same K_u) and a
  re-minted scope never shares; rm-scope already holds the master to open `scope.key`. Every
  open of a scope key (a read, a grant, the start step's catch-up, rebuild) refuses one the
  record lists, saying root removed the scope and naming the one repair, `sudo k3sm keys
  rm-scope user/<uid> --yes` built from the integer uid, which removes the copy; a record that
  does not read or parse refuses every open, rm-scope and rebuild (fail closed). When the
  record is full, rm-scope still removes the scope, says so, exits 4, and leaves it unlisted, and
  rebuild keeps that scope's floor keys instead of dropping them, so a copy-back is still held
  to the floor. rm-scope removes the tree by descriptor and cannot be blocked by a name the
  service user plants in it: a regular file, FIFO, symlink, device or socket is removed with
  `unlinkat`, which never follows; a directory is opened `O_DIRECTORY|O_NOFOLLOW`, re-checked
  `SameFile`, taken from the service user, emptied and removed with `AT_REMOVEDIR`;
  `scope.key` goes last on every path, once nothing else is left beside it, so a run that stops
  part-way leaves the key a rerun reads to list the removal.

  *The rerun rule.* The service user owns `.user` and can rename another of its scope
  directories onto the name after rm-scope judged it, so before the scope directory held by
  descriptor is taken, its owner is checked (the service user's, or root's at 0700, on `.user`'s
  device) and its `scope.key` is read inside it by descriptor (`fstatat`, then `O_NOFOLLOW`
  re-checked as that file, bounded, opened under W). So rm-scope removes only the directory it
  judged, or a root-owned leftover an earlier run took, with one exception: an empty directory
  renamed onto the name between the final `rmdir`'s `fstatat` and its `unlinkat` can be
  removed, and is reported ("another directory was removed at the name"), never as the scope's
  removal.

  *The measured premise.* What the service user can put at the name, measured on macOS (APFS,
  non-root): it cannot create a root-owned directory; moving a directory it cannot write to
  another parent fails (`EACCES`); a rename within one parent needs no rights on the directory
  moved, so another uid's leftover that an earlier rm-scope took can be renamed within `.user`
  onto the name; and an ACL entry granting it `add_subdirectory` on a root-owned directory,
  also one inherited from its parent, lets it move that directory to another parent. A root
  verb creates directories inside the service user's `keystore/` (`mkdirAt`) root-owned at 0700
  before it hands them over, so an inheritable entry the service user put on `keystore/` would
  be copied onto one and let it move that root-owned directory to `.user/<uid>` and put a
  freshly minted key in it. U195 pins these facts root-run (`TestRmScopeMeasuredPremiseAsRoot`).
  Three closures:

  1. `mkdirAt` removes any inherited extended ACL from the new directory on its descriptor
     right after it is opened and checked, before anything else is done with it.
  2. A root-owned held directory with an extended ACL (which a take stopped between its
     `fchown` and its ACL removal also leaves) is still finished, its ACL removed on the
     descriptor first, but never proves the removal.
  3. A root-owned held directory proves the removal (exit 0) only when it carried no ACL and
     its `scope.key` was listed before this run (an interrupted run lists its key before its
     walk, so it still finishes with exit 0), and never on the judged path, where a root-owned
     directory is never the directory judged.

  No open ever serves a root-owned scope directory, so finishing the removal of any root-owned
  leftover is safe, whatever it holds; only the report's claims need proof. The result says the
  scope was removed and listed (exit 0) only when the `scope.key` read in the held directory
  opens as this uid's, its identity is in the record, and the rules below allow it. A directory
  gone from its name when the walk opens it is never reported removed.

  | Held at the name | What rm-scope does | Result |
  |---|---|---|
  | root's 0700, no ACL, key already listed | rewrites the record, removes it | exit 0 |
  | root's 0700, ACL present, key already listed | strips the ACL, rewrites the record, removes it | exit 4 (not confirmed) |
  | root's 0700, a key that opens as this uid's but was not listed before this run | strips any ACL, lists the key, removes it | exit 4 |
  | root's 0700, no key, or a key that does not open as this uid's | strips any ACL, removes it; record unchanged | exit 4 |
  | root's, met on the judged path | removes it | exit 4 ("the directory rm-scope judged was not at its name") |
  | the service user's, on the judged path | the held key must be the judged one, read again after the take | exit 0 only if the judged key is in the record; record full: exit 4 |
  | the service user's, on the no-key or untrusted path | must be the directory the judge opened (device, inode), else refuses; removes it | exit 0 only if a listed key was read; else exit 4 |
  | any row above that gives exit 0, with a line of `user/<uid>` in the floor after the proving key's listing, or a floor that cannot be judged | as that row | exit 4 (the newest-scope rule) |
  | any row above that gives exit 0, with more than one sequence-1 delivery-record line of `user/<uid>` in the floor since the uid's last listing before this run | as that row | exit 4 (the created-twice rule) |
  | the service user's with a valid unlisted key, or not what its path found | refuses | exit 1 (exit 4 if this run added a key to the record) |
  | absent at the walk's open | removes nothing | exit 4 "found absent" if this run added a key, else exit 1 |

  *Exit 4* means: this run changed something (added a key to the record, removed an ACL,
  unlinked an entry, took a directory, cleared a flag), or the durability of the record is
  uncertain. "Added a key" is the record this run changed; removing the ACL of a root-owned
  directory at the name is a change too, so a stop after it is exit 4, never "nothing was
  changed". A rerun that rewrites a record already listing the key, to make it durable again,
  writes identical bytes: that rewrite by itself never turns a later stop into exit 4, but a
  rewrite that fails leaves the record's durability uncertain, which is exit 4 by the
  definition. Before the walk, a scope directory simply absent is found absent,
  exit 1, with no repair advice and no rerun line; a directory the judge refuses (another
  owner, not a directory) is named for reading, exit 1, with no command and no rerun line,
  since a rerun meets the same state.

  *The newest-scope rule.* The record proves that a key is listed, not that it is the uid's
  newest scope: a tree-writer that kept a copy of a listed `scope.key`, or parked an
  interrupted run's root-owned leftover, can put it at the name while the uid's live scope is
  renamed away, and the judge would find the key listed and report exit 0 while the live scope
  survives unlisted. Only the real server mints a scope, and every mint writes a floor line of
  the scope (its delivery record's). So every exit 0, on every path, passes one more gate
  (`newestScope`): the user-scope floor holds no line of `user/<uid>` written after the
  listing of the key that proves the run. For a key this run listed, the position is the
  floor's identity and size read under the store lock at the listing; for a key an earlier run
  listed, the uid's `floor_size` in the record, in the floor file of the recorded identity
  (device, inode, birth time), which is the uid's latest listing. A floor of another identity
  (rebuilt since), or a recorded identity that is not whole (no birth time), makes every line
  of `user/<uid>` in the current floor count as later. The floor is opened and judged as
  rebuild reads it (root's descriptor, `O_NOFOLLOW`, a regular file flagged `SF_APPEND` or
  root's) and streamed once, bounded by its size at the open and one line's buffer; a line
  that does not parse is no mint's and is skipped. A later line, a floor that cannot be
  opened, judged or read, or a recorded position past the floor's end is not exit 0: exit 4
  when the run changed something (it always has by then: the removal succeeded), else exit 1,
  saying the floor shows activity of this uid after the listed key, so rm-scope cannot confirm
  that the uid's current scope is the one removed, and that the current scope may have been
  moved away from its name; it names no path and offers no command. rm-scope holds the floor
  lock and the exclusive store lock while it reads, so no server write runs: a hostile append
  to the floor can only add a line, which turns exit 0 into exit 4, never the reverse. A first
  removal can trip it too: when the floor cannot be opened, judged or read, or when a line of
  the uid is appended to the floor during the run (the service user's processes can append to
  the floor without the store lock). Exit 4 there means the scope at the name is removed and
  listed; only the confirmation is withheld, and a rerun finds the name absent (exit 1, found
  absent), so the confirmation cannot be obtained later. A rerun trips it when the uid had any
  floor activity after the listing, or, on a floor rebuilt since, when the rebuild kept a line
  of the uid (a floor without a whole identity, as on a file system with no birth time, keeps
  the listed scope's own lines and so always trips it).

  *The created-twice rule.* Inside the same scan, a partial detection of the open limit below.
  Every mint of a scope appends the same floor line for the uid, its empty delivery record at
  sequence 1 (`user/<uid> .deliveries <GeneratedUID> 1`), before `scope.key` is written, with no
  de-duplication, and the append-only floor keeps it. One such line since the uid's last listing
  is the judged scope's own mint; more than one means the uid's scope was created more than once
  since, so another scope of this uid may be held away from its name. The rule counts the uid's
  sequence-1 delivery-record lines in its own window: from the uid's `floor_size` in the record
  as this run read it before any write, when that position's identity is whole and is the
  current floor's, else from byte 0 (the record does not list the uid, the floor was rebuilt
  since, or the identity has no birth time), to the floor's end at the open. For a key this run
  listed, that window starts before the listing, not at it, since the judged scope's own mint
  line lies before the listing position; the later-line rule keeps its own window (from the
  listing). For a key an earlier run listed both windows start at the recorded position. More
  than one line in the window is not exit 0 (exit 4, as the newest-scope rule accounts it),
  saying the floor shows this uid's scope was created more than once since its last listing, so
  another scope of this uid may be held away from its name, and that rm-scope removed and listed
  the one at the name; when a later line also exists, the later-line text is the one given. The
  rule is fail-closed: an extra line only turns exit 0 into exit 4, so a forged line costs a
  false exit 4, never a false exit 0. It is partial: a `floor --rebuild` between the mints and
  the rm-scope drops the earlier scope's lines and erases the evidence, and it does nothing when
  the name is left empty (there is no scope to judge: exit 1, found absent). A torn or over-long
  line before a mint's line does not hide it, since the writer leads every append with a
  newline.

  *Directory mode.* rm-scope, and only it, reads through the mode of `keystore/`, of `.user`
  and of the scope directory, which the service user can set (a judge that refused it would
  let the principal being revoked veto its revocation): each is opened by descriptor whatever
  its mode, its owner still the service user's, and the take forces the scope directory to 0700;
  the serving path still refuses any mode wider than 0700. So a take stopped at any step, the
  first `fchmod` included, leaves a directory a rerun finishes.

  *The command rule.* rm-scope's output holds exactly these commands and no other: its own
  rerun line, `sudo k3sm keys rm-scope user/<uid> --yes`, built from the integer uid, only where
  a rerun can finish the removal; the follow-up `sudo k3sm keys floor --rebuild` the verb prints
  on success; and whatever the shared store-lock and root-file helpers print (`sudo k3sm stop`
  when a service-user process held the store lock, and the flag repair `sudo chflags 0` on a
  root-owned file in the data root, such as the removed-scopes record, whose path is root's).
  It suggests no by-hand action over the service user's tree (no `rm`, no flag to clear, no
  file to restore, no restore advice from a rolled-back record), and never prints a name from
  that tree in a command. Errors about the root-owned removed-scopes record come from the
  shared root-file helper and reader and keep their wording, repair advice included. The text
  tests hold every rm-scope result to that set (`checkRmScopeCommands`).

  *Binding the paths without a key.* On the no-key and untrusted paths there is no key identity
  to bind the held directory to, so the judge pins the device and inode of the scope directory
  it opened, and the walk takes the directory held at the name only when it is that one; any
  other is refused, nothing taken (exit 1, or exit 4 when this run already changed the record).

  *Honest limits.* Each below is accepted; none is a revocation failure. One more, after the
  list, is open:

  - A tree nested deeper than 32 directories below the scope directory stops the walk after the
    scope directory is taken. Root owns the directory, so no open serves it, and only the cleanup
    is blocked; but its key is listed only when this run listed one: always on the judged path,
    and on the other paths only when the held directory's `scope.key` opened as this scope's. On
    the no-key and untrusted paths nothing is listed, so the stop leaves the scope unlisted as
    those paths' results already say.
  - A full disk refuses the record write. That costs availability only: nothing was removed,
    and the scope is not reported removed.
  - A replaced `keystore/.lock` refuses every verb, rm-scope included, until it is repaired;
    no verb runs, so none serves a removed scope either.
  - `mkdirAt` creates a directory root's at 0700 and strips any inherited ACL right after its
    open and check; in the window between the two, a writer holding an inherited
    `add_subdirectory` entry can move that root-owned directory out. A directory moved out of
    that window and put at a scope's name cannot produce exit 0: a root-owned held directory
    proves the removal only with no ACL and a key listed before the run (the unlisted-key
    rule), and a key so listed still passes the newest-scope rule, which refuses exit 0 when
    the floor shows a scope of the uid minted after that listing.
  - `mkdirAt`'s ACL removal (`fchmodx_np` with `_FILESEC_REMOVE_ACL`) fails closed on any
    error, on the serving path too, as rm-scope's take and the audit rotation's removal do: no
    caller in the package treats `ENOTSUP` or `EOPNOTSUPP` as "no ACL". What that call returns
    for a directory with no ACL on a volume without ACL support is an open question, not
    established from the code or measured (no such volume was made for it). If it errors there,
    a root verb that creates a directory under `keystore/` on such a volume refuses: an
    availability cost, never a directory handed over with an ACL. The data root measured so far
    is APFS, which supports ACLs.
  - The final `rmdir` races a rename at the name, which the probe below reports but cannot
    prevent; a race it cannot judge is exit 4, never exit 0.
  - A legitimate rerun can exit 4 although the removal it finishes is the uid's newest scope:
    the newest-scope rule counts any line of `user/<uid>` after the listing, so a uid with floor
    activity after the listing, or a floor rebuilt since that kept a line of the uid, turns the
    rerun's exit 0 into exit 4. That costs a confirmation, never a removal.
  - On a file system without birth time (any build off darwin) the recorded floor identity is
    never whole, so a rerun counts every line of `user/<uid>` in the floor as later, and, while
    the listed scope's own lines remain (until `floor --rebuild`), every rerun exits 4.
  - A veto of the report, not of the revocation: the service user's processes can append a
    line of the uid to the floor without the store lock, during any run, the first included,
    and a floor that cannot be opened, judged or read is never exit 0. Either turns exit 0 into
    exit 4 while the scope at the name is removed and listed; only the confirmation is
    withheld, and since a rerun finds the name absent, it cannot be obtained later.

  *Open limit: a scope kept away from its name.* Not accepted; no test pins it as correct.
  rm-scope can list only a key it reads at the scope's name, so a scope kept away from its name
  is not revoked by this verb at all. A tree-writer that can rename within `.user` moves the
  uid's scope directory K_a out of its name before an rm-scope judges that scope; this applies
  to a uid never removed and equally after earlier removals of the uid. Then:

  - the name left empty: rm-scope finds the scope absent (exit 1, "found absent");
  - a file or a symlink held at the name: rm-scope refuses (exit 1); the serving path refuses
    it too, so nothing serves the scope meanwhile, but K_a is not listed;
  - a freshly created scope K_b at the name: the server's next grant for the uid mints K_b
    there (a `put`, or a grant that records a delivery, mints on `errNoScopeKey`); the mint
    consults neither the removed-scopes record nor the uid's earlier floor lines as a sign of
    another scope, and refuses only when the floor records the delivery record past sequence 1
    under the user's GeneratedUID, or when `entries/` at the name holds names, so this needs
    K_a's delivery record never to have advanced past sequence 1. rm-scope judges K_b, lists it
    and removes it: exit 0 when no second creation line of the uid is in the floor since its
    last listing, exit 4 when the created-twice rule finds K_a's own creation line too (it does
    not when a `floor --rebuild` between the mints dropped it, or, on a key an earlier run
    listed, when K_a was minted before the uid's latest listing: the record keeps one floor
    position per uid, the latest listing's, not one per key, so a line written between that
    key's listing and the latest one is not counted).

  In each case the writer later moves K_a back. Its open compares its key identity only with
  the removed-scopes record, which does not list it, and its record's generation with the live
  GeneratedUID, which still matches; its entries' pointers are checked against floor lines
  keyed by each entry's own random generation, which K_a's lines still satisfy. K_a is served.
  A floor line carries the scope, the name, a generation (the entry's random one, or the
  GeneratedUID for the delivery record) and a sequence, and nothing that names a scope key, so
  "a line of this uid that belongs to no listed key" cannot be told from the floor as it is
  written. Exit 0 therefore proves that the directory at the name is removed and its key is
  listed; it does not prove that no other scope of this uid is held elsewhere. Closing it needs
  revocation by uid (an authenticated per-uid epoch bound into the key record, a serving-path
  change) or a server-side refusal to create a second scope for a uid whose creation line lies
  past its last listing (a mint-path change, with an availability cost). Both are follow-up
  work, not in this change.

  *The delivery check.* The judged path reads the delivery record through the floored reader a
  withdraw uses: a record below the floor (a rolled-back authentic copy) is a rollback, which
  rm-scope treats as a damaged record (it removes the scope, exit 4, saying the scope's
  deliveries were not checked), and a floor that cannot be read leaves a record naming no
  delivery unverified: exit 4, saying the deliveries are not confirmed, never exit 0. A floor
  past the steady-state reader's key bound (the flooded floor rebuild names rm-scope as the
  repair for) is one that reader refuses, so there the record is read without the floor and is
  unverified the same way: the repair still lists and removes the scope, with exit 4. The
  no-key, untrusted and taken paths never read the delivery record, and their results say so.

  The scope directory's descriptor stays open through

  its final `unlinkat(AT_REMOVEDIR)`, which runs only while the name's `fstatat` matches it;
  since the name can still change between the two, rm-scope then asks the held directory
  whether it was the one removed. On macOS (APFS) `fstat` of a removed directory still held
  open reports its link count unchanged (2, measured), so the link count cannot say; a
  `mkdirat` of a probe name in it fails with `ENOENT` once it is removed, on macOS and Linux
  alike, and a probe that is created is removed again (a failure to remove it is said in the
  error). A name moved away, holding another directory, or holding a non-empty one is
  reported, never as removed, with no rerun offered. A probe that fails for any other cause
  (`ENOSPC`, `EDQUOT`, `EROFS`, `EIO`) cannot tell, so rm-scope exits 4 saying it could not
  confirm the removal, never that the directory moved and never success, with no rerun offered:
  a rerun finds the name empty either way. Each directory, the scope directory first, is taken
  before any of its entries is listed or touched: its user locking flags cleared if it carries
  any, then `fchmod` 0700, `fchown` to root, `fchmod` 0700 again and its extended ACL removed,
  all on the held descriptor, and an `fstat` that must show it root's at 0700, so a take that
  stops part-way leaves the service user's directory at 0700 or root's at 0700, and while
  rm-scope handles its entries the directory is root's and no service-user process can create
  a name in it or rename one into it (on macOS an entry carrying an ACL entry that allows its
  deletion can still be renamed out of it or unlinked; the walk takes each name as it finds it).
  A subdirectory is descended into only when its
  `fstatat` and `fstat` show the service user as owner, or root at 0700 (rm-scope's own earlier
  work), on the scope directory's device. Any other, such as a directory another user owns
  renamed into the tree from a shared parent, is left in place with everything in it, and the
  removal fails naming it for reading only and saying who owns it, with no command; the scope is
  already listed. Each directory is emptied a batch of names at a time (256), read again from
  its start after each batch until a read returns none, so memory stays bounded by the batch
  and no count is refused; a root-owned directory cannot be refilled meanwhile. A crash leaves
  root-owned 0700 directories in the tree, which no open of the scope accepts: a rerun that
  finds the scope directory root's at 0700 removes it with no open, whatever it holds, and
  reports it as the rerun rule's table says. The record is renamed
  into place and the data root then fsynced; when that fsync fails, rm-scope exits 4, saying
  the record lists the scope but its durability is unknown, and a failure before the rename
  refuses, the record unchanged. A stop after rm-scope cleared a flag on `.user` carries that
  note in its error. A user locking
  flag (`uchg`, `uappnd`, `uunlnk`), which makes root's `unlinkat` fail with `EPERM`, is cleared
  first on any entry in the tree, whoever owns it, when the entry carries no system flag and has
  one link: a flagged file cannot be hard-linked (measured as root, U195, for `UF_IMMUTABLE`,
  `UF_APPEND` and `SF_APPEND`, whoever owns the file), so a flagged entry with one link is debris
  of the tree being removed. The service user's own regular file or symlink is cleared at any
  link count too: a link outside the tree shares the flag, but its owner could clear it itself,
  so refusing would only let it stall the removal. A directory, a regular file and a symlink are
  changed with `fchflags` on a descriptor opened `O_NOFOLLOW` (`O_SYMLINK` for a symlink) and
  re-checked as the name, never by path, keeping their other flags; at most 4096 clears per run.
  A FIFO or device is not opened (an open can unblock a writer or start a driver), and macOS
  refuses to open a socket (`EOPNOTSUPP`), so a FIFO, socket or device is changed without an
  open: `setattrlistat(dirfd, name, ATTR_CMN_FLAGS, FSOPT_NOFOLLOW)` writes exactly `0`, only
  when its `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` shows one link and no system flag. The
  directory is root's while its entries are handled, so no service-user process can swap
  another file in at the name between the `fstatat` and the write. The write is still exactly
  `0`, so it can never set a flag (a write of the entry's flags less the locking ones would set
  `hidden` or `nodump` on whatever file is at the name), and still re-checked, as defence in
  depth; U195 measured the link refusal for `UF_IMMUTABLE`, `UF_APPEND` and `SF_APPEND` only,
  not for every flag. Clearing the entry's other user flags costs nothing: it is about to be
  unlinked. A second `fstatat` then checks the device, inode and owner: a changed name logs a
  warning naming the scope, counts as not cleared, and is read again by the rescan. Measured as root (U195): the
  call clears `uchg` on a FIFO and on a socket by directory descriptor and name, and at a
  symlink it changes the link, never the target. What is left fails its `unlinkat` with
  `EPERM`, and rm-scope stops with an error that names the entry for reading only, Go-quoted
  (`%q`) with its control bytes removed and labelled as not for pasting, says which flag it
  carries, who owns it, that rm-scope left it, whether the scope is already listed as removed,
  and that the leftover directory blocks a fresh scope for that uid, and offers **no action by
  hand**. For an entry carrying a system flag, which only root sets, and a multiply-linked
  flagged entry rm-scope does not clear (another user's, or a FIFO, socket or device; linked
  before it was flagged, its other name may be outside the tree), a rerun meets the same flag,
  so no rerun is offered either. An entry whose flag rm-scope cleared (one link, or the service
  user's own regular file or symlink) and that was set again before the `unlinkat` is the one
  flag stop a rerun can finish: the message says rm-scope cleared it and it was set again while
  rm-scope ran, to rerun once nothing sets the flag, and carries the rerun line. A directory
  that is not the scope's stops the removal with no rerun offered either: a rerun meets it
  again. The command rule above holds: the rerun line only where a rerun can finish the
  removal (a system flag on `.user` gets none), and no name from the service user's tree in a
  command. A recursive flag change over the tree would be the pattern banned above, and stopping the server
  does not stop other service-user processes, so none is offered. The flag budget is per run: a
  tree with more flagged entries says to run rm-scope again, each run unlocking up to 4096
  more. A name left in a directory rm-scope emptied after taking it, which only root could put
  there, stops it with an error naming the directory. An rm-scope that stops after it changed
  something (it added a key to the record, removed an ACL, unlinked an entry, took a directory
  or cleared a flag) exits 4, audited `committed`, since the change stands; one that stops
  before changing anything refuses, exit 1, and a rewrite of a record that already listed the
  key counts as no change. An rm-scope that stops after
  the record is written says so (the scope listed as removed, its directory partly or wholly
  present), and a rerun finishes it: a listed key is removed without the delivery check, and a
  directory left without `scope.key` is removed as it stands. A directory without `scope.key`
  is an interrupted earlier run, or tampering: rm-scope removes the tree but exits 4. When the
  record lists no key for the uid it says the scope was removed without being listed because
  its key file was absent; when it lists some, that it could not confirm the removed
  directory's key is listed, and how many keys the record lists for the uid (another key of the
  uid proves nothing of this directory). Either way a copy of its directory put back by the
  service user may open again, held only to the scope's floor lines, which are kept, so the
  floor still refuses rolled-back or deleted entries; it never speaks of a full record for this. A
  `scope.key` the judge refuses only for a second link or a mode wider than 0600, which any
  local user can cause, still carries a key the master accepts, so removing it unlisted would
  let a copy put back open: rm-scope alone reads it again by descriptor (`O_NOFOLLOW`, a
  regular file, bounded at a scope key record's size, the service user's) without those two
  checks and opens it under W; when it authenticates, its identity is listed and the tree
  removed, and rm-scope exits 4 noting that the key file's link count or mode was wrong.
  A `scope.key` that is present but does not parse or authenticate, which the service user
  can cause, is treated as a missing one: there is no key identity to list, so rm-scope
  removes the tree unlisted, keeps its floor lines and exits 4, saying the scope was removed
  without being listed because its key file could not be trusted, and that a copy of its
  directory put back by the service user opens again, held only to the scope's floor lines,
  which are kept.
  Rebuild refuses such a scope and names rm-scope, so refusing it here too would leave a
  repair loop. *Residual (a full record).* An
  unlisted removed scope copied back opens: its floor keys hold it to its last floor, and
  nothing more. *Residual (one uid, two removals).* The offset is per uid, the latest removal's
  size: a removal left unlisted for a full record after a listed one of the same uid is not
  recorded, so its lines written after the listed removal are kept (fail closed). *Residual
  (a hostile append).* A line the service user appends to the floor, bypassing the store lock,
  before rm-scope reads the size is dropped with the removed scope's; one appended after it is
  kept. *Residual (a deep planted tree).* rm-scope descends at most 32 directories below the
  scope directory, one descriptor a level, and stops at a deeper tree: the error names the
  directory past the limit relative to the scope directory, for reading only, says rm-scope
  removed nothing below it, and offers no command, not even a rerun, which would stop there
  again. The later rows (U114,
  U130, U133) extend this record with the bound GeneratedUID and the delivered Secrets; this
  slice holds only the uid, the key identities and the floor offset.
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
    old file, so it changes nothing: it cleans `keystore-staging/`, leaves the old log as it
    was and removes the marker.
  - *The `deliveries` record gets its line.* For each scope rebuild writes the line for the key
    `(user/<uid>, .deliveries, generation, seq)` with the record's authenticated sequence ("Key
    hierarchy"), so a copied-back older record is refused after a rebuild as before it (U88).
- **SF_APPEND, as measured.** Two probes run as root on 2026-11-23 (macOS 27.2.1, APFS, the
  service user `_k3sm`) measured what the flag refuses. The swap below rests on both tables,
  and U195 pins them, root-run: `TestSappndMeasuredFacts` the first, `TestSappndDirectorySwap`
  the second.

  The first probe, on files:

  | Operation | Result |
  |---|---|
  | root `fchown` of a flagged file | `EPERM` |
  | root `fchmod` of a flagged file | `EPERM` |
  | root `rename` of a flagged file | `EPERM` |
  | root `link` of a flagged file | `EPERM` |
  | root `unlink` of a flagged file | `EPERM` |
  | root `open(O_WRONLY\|O_TRUNC)` of a flagged file | `EPERM` |
  | `fchown` to the service user, then set `sappnd` | works |
  | root `fchown` back to root while flagged | `EPERM` |
  | `pwrite` at offset 0 through a non-append descriptor opened before the flag was set | `EPERM` |
  | `ftruncate` through that descriptor | `EPERM`, content unchanged |
  | the service user's `link(2)` of a root-owned 0600 unflagged file into its own directory | succeeds (`nlink` 2) |
  | the service user's `link(2)` of a flagged file | fails (`nlink` 1) |
  | root's `fclonefileat` (`CLONE_NOFOLLOW\|CLONE_NOOWNERCOPY`, rotate's flags) of the service user's flagged file carrying an extended attribute and an extended ACL, into a root-only directory with no ACL | works; the clone carries the extended attribute and not the ACL (no `CLONE_ACL`) |

  So a file is handed to its owner first and flagged second; an owner change of a flagged file
  needs its flag cleared first; once the flag is set, a descriptor opened without `O_APPEND`
  before it can neither rewrite nor truncate; and a hard link needs an unflagged file and a
  searchable path to it.

  The second probe, on a directory swap: a live directory (root 0755) holding the service
  user's 0600 flagged log, and a root-only 0700 staging directory holding a replacement
  directory with its own flagged log. A service-uid process opened the old log
  `O_WRONLY|O_APPEND` and a descriptor on the live directory before the swap.

  | Operation | Result |
  |---|---|
  | root `rename` of a directory holding a flagged file | works |
  | root `renameatx_np(RENAME_SWAP)` of two directories, each holding a flagged file | works; the canonical path reads the new log at once |
  | root clears the flag on the retired log, now inside staging | works |
  | the service user, held descriptor on the retired log: `F_SETFL` clearing `O_APPEND` | works |
  | the same descriptor: `pwrite` at offset 0, `ftruncate` | works (the retired log was emptied) |
  | the service user, held directory descriptor: `openat` the retired log for write | works |
  | the service user, by path: open the new canonical log `O_WRONLY` without `O_APPEND` | `EPERM` |
  | the service user, by path: open the new canonical log `O_TRUNC` | `EPERM` |
  | the service user, by path: `O_APPEND` write to the new canonical log | works |
  | the service user: list the staging directory | `EACCES` |

  After every attempt the canonical log held its content and the one legitimate append, flags
  `0x40000`, `nlink` 1. So an old log whose flag was cleared is writable through any descriptor
  the service user held from before, whatever its directory's mode, and is never read again;
  and swapping whole directories leaves no reachable unflagged window: the replacement is
  flagged before it is reachable, and the old log is unflagged only once it is unreachable by
  path and no longer an input. While a log is flagged, every write through a held descriptor
  but an append is refused, `F_SETFL` clearing `O_APPEND` included (U50).
- **The layout.** Each log lives alone in its own directory in `keystore-logs/`:
  `keystore-logs/floor/keystore-user-floor.log`, and `keystore-logs/audit/keystore-audit.log`
  with rotate's archives `keystore-audit.log.1` to `.4` in `keystore-logs/audit/archives/`.
  `keystore-logs/` and each log's directory are root's 0755 with no flag and no ACL, judged on
  their descriptors; `archives/` is root's 0700, judged the same way at that mode, so no other
  user can reach an archive, hard-link it or pin its blocks. Install creates it empty with the
  audit directory; an `archives/` that is absent holds no archive. Each
  log is the service user's, 0600, flagged `SF_APPEND` alone, one link. `keystore-staging/` is
  root's 0700, judged on its descriptor, present only while a verb or install runs, on the data
  root's volume so a directory built in it is swapped out of it; only root can reach a name in
  it. The server refuses a log at the top of the data root or directly in `keystore-logs/`,
  naming `sudo k3sm install`.
- **The swap.** `floor --rebuild` and `audit --rotate` replace a log's whole directory in the
  same numbered steps; each step's function is named in `pkg/keystore/logswap.go`, and the
  step seam (`SwapSteps`) names the points a test stops at:
  1. **Locks, then the marker** (`beginMaintenance`). Take `keystore-lock`, then the exclusive
     store `.lock` (above). Open and judge `keystore-staging/` and clean it (`cleanStaging`:
     whatever a crashed run left is removed, never read), then open and judge `keystore-logs/`.
     Write the marker (`writeMarker`): the verb and a random run id, written in staging,
     fsynced and renamed into the data root, which is fsynced.
  2. **One bounded read of the old log** (`openOldLog`, `judgeOldLog`). Open the old log
     `O_NOFOLLOW` in its judged directory and judge it on its descriptor: a regular file,
     flagged `SF_APPEND`, or unflagged and root's (a restore); an unflagged log the service
     user owns is refused, since any descriptor it held could have rewritten it. A second link
     is a Warn, and so is an extended ACL: the swap carries no ACL forward (the new log is
     created in root-only staging and judged with none; rotate's archive is a clone that leaves
     none, measured in U195, or a copy into a fresh file), and refusing would name `chmod -N`,
     which fails with `EPERM` on a flagged log. Read it once, bounded by its size at open: rebuild streams it; rotate copies it.
  3. **The replacement, built and flagged in staging** (`buildLogDir`). Create
     `keystore-staging/<dir>.new`, open it `O_DIRECTORY|O_NOFOLLOW` and judge it; create the
     new log in it `O_CREAT|O_EXCL|O_NOFOLLOW`, write it, fsync it, `fchown` it to the service
     user, `fchmod` it 0600, set `SF_APPEND`, each on the held descriptor, and judge it. Rotate
     adds a fresh root 0600 `.1` holding the old log's bytes read in step 2, and hard-links the
     live `.1` to `.3` in as `.2` to `.4` (the old `.4` is not linked, so the swap drops it). Set
     the directory to root's 0755 and fsync it.
  4. **The report** (`writeMarker`). Rewrite the marker with the new log's device and inode and
     the verb's report.
  5. **The commit** (`swapLogDir`, `renameSwap`). Exchange `keystore-staging/<dir>.new` and
     `keystore-logs/<dir>` with one `renameatx_np(RENAME_SWAP)`, then fsync both parents. The
     canonical path reads the new log at once; the old directory is now in staging.
  6. **The retired set, cleaned unread** (`cleanStaging`). Each entry of the retired directory
     is removed by descriptor: a regular file carrying a flag, with one link, has it cleared on
     a descriptor opened `O_NOFOLLOW` and re-checked as the entry named; a file with a flag and
     another link refuses; everything else is unlinked with `unlinkat`, which never follows.
     Nothing in staging is read.
  7. **The marker removed** (`end`). The CLI then prints the report and writes the audit line.

  No flagged file is renamed, chowned or renamed over, and no file is flagged after it is
  reachable. Every attribute call goes on a held descriptor. The canonical directory is always
  one complete, flagged, judged set: the old one before step 5, the new one after it (U90).
  The old log takes one attribute call, its flag clear, in step 6, once the swap has made it
  unreachable by path; it is never chowned or chmodded and never read again (U118). An archive
  is root's 0600 and unflagged, and an alias of it gives the service user nothing, so a link
  to one is a Warn.
- **A swap that committed and then failed is committed, never refused.** Every error from
  the `RENAME_SWAP` on (the parents' fsync, the clean and end steps) is marked committed: the
  CLI prints the verb's report (a rebuild's drop counts included), exits 4 and audits
  `committed`. Its marker stays and holds the report. A later run of the *other* verb, or
  install, that finds a marker recording a committed run (its log's live inode is the one it
  recorded) first prints that saved report to stderr as "an earlier `<verb>` committed and
  was not reported: …" and appends its audit line (op that verb, via root, result
  `committed`), then replaces or removes the marker. When that saved report shows drops,
  the text says the earlier run committed and dropped N lines, and the verb that reported it
  exits at least 4, even when its own work was clean, so a lossy run is never left
  unreported behind a clean exit. Install is the exception: it keeps its own exit codes, so
  its line adds that install does not exit 4 for it and that the earlier run's drop counts
  are kept in `keystore-maintenance-runs`, which `doctor` reads (below); when that record
  could not be read or written, the line says so and why, that the counts are in this line
  only (the audit log holds a `committed` line for that run), and that the operator should
  copy the line down. A same-verb rerun that only prints the saved report says
  "an earlier run committed; this run did not rebuild" (or "did not rotate"), never that it
  rebuilt. `doctor`'s `keystore-maintenance` row is WARN while a marker stands, naming the
  verb that left it and the verb to run (that verb again; `install` for a marker naming no
  verb this build knows). A marker whose swap never committed reports nothing.
- **A lossy report outlives the marker.** The marker holds a report only until the next run
  replaces or removes it. So a committed run whose report drops any line or key appends one
  record to `keystore-maintenance-runs` in the data root, after the swap committed and before
  the marker goes: the run id, the verb, the UTC time to the second, the drop counts by
  reason (`dropped`, `overlong`, `past-share`, `absent`, `removed`) and the new log's inode as
  the marker records it, never a value, an entry's name or a path. A same-verb rerun that
  prints a saved report, and the other verb that reports an earlier run, append that run's
  record too; a record already holding the run id is left as it is, so a run is recorded
  once. A clean run appends nothing. The file is root's 0644, written as the removed-scopes
  record is (a temporary file in the data root, `O_EXCL|O_NOFOLLOW`, fsynced, renamed, the
  data root fsynced), read by descriptor with `O_NOFOLLOW` and judged as a root-written file,
  and the `keystore-` prefix puts it under every Pod's data-root deny. It is bounded: a header
  line, then at most 64 records of at most 256 bytes each, the newest kept, oldest evicted.
  It is parsed strictly: a wrong header, field, order, verb, non-canonical number, a record
  that dropped nothing, a repeated run id, a torn last line or an over-long one refuses the
  whole file. A file that does not read is reported and never reset: the run that would
  append is committed, exits 4 naming the file and the counts it could not record, and
  leaves the file as found, and the marker still goes, since a rerun would meet the same
  file. `doctor`'s `keystore-maintenance-runs` row reads it: "keystore maintenance: N lossy
  run(s), latest <time> dropped <total> line(s)" (WARN), PASS when none, WARN when the file
  does not read. Install appends too: when the marker it removes records a committed run
  whose report drops anything, it appends that run's record, by the same run-id rule, before
  it removes the marker, so an install that dies between the two records the run once when
  it runs again. A record file that does not read is left as found there too, and the
  marker still goes. No record is written that would not parse (a marker whose run id is not
  16 lowercase hex digits): that run's counts are reported as not recorded.
- **Crash and rerun.** The live set is always one complete set, so a crash at any step leaves
  a valid log, and the rerun never finishes a half-done swap: it cleans staging, which it
  never trusts, and reads the marker. A failure before step 4 cleans staging, removes the
  marker and changes nothing. From step 4 on a failure keeps the marker, and the verb names
  itself to rerun. A marker of the same verb whose recorded inode is the live log is a run
  whose swap committed: the rerun prints that marker's saved report (a rebuild that dropped
  lines exits 4 with the same counts) and does not run again. Any other marker, the other
  verb's or one whose swap never committed, is replaced: the live set is valid, and the rerun
  runs from step 1. A marker that is not a regular file of the data root's owner, closed to
  group and other writes, with no file flag and no extended ACL, refuses the verb, naming
  `sudo k3sm install`, which removes it unread; a second link on it is a Warn.
  *Root-written files and hard links.* Any local user can `link(2)` a root-owned unflagged
  file into a directory of its own (measured, U195). The removed-scopes record, the marker
  and the floor acknowledgement are root's, written only by rename and closed to group and
  other writes, so an alias gives nobody write power: it keeps an old copy, never a way in.
  Their judge (type, owner, mode, flags, ACL) therefore never refuses on the link count, and
  warns once per process of an extra link; refusing would let any user block every scope
  open, every maintenance verb and the acknowledgement. The service-owned flagged logs keep
  their one-link rule: a flagged file cannot be linked. A planted symlink, FIFO or directory at the marker, at
  `keystore-staging/` or at a log's directory refuses the verb before anything changes; one
  inside `keystore-staging/` is removed unread (U68).
- **Install builds a missing log the same way.** Install builds each missing log's directory
  in `keystore-staging/` as step 3 does, the log empty, and places it in `keystore-logs/` with
  `renameatx_np(RENAME_EXCL)`, so nothing is renamed over. A log that passes the judge is left
  alone; anything else, an unflagged log among them, is refused and left as found. Install
  refuses, changing nothing, while a maintenance verb holds `keystore-lock`, and removes a
  stale marker once the live set is ensured (U21; root-run, U90). `keystore-run/` is the
  service user's, so it can set a user flag (`uchg`, `uappnd`) on it, which would make root's
  fchmod and fchown fail and wedge install: install clears the user-settable flags (`UF_*`) on
  its judged descriptor first, for a directory the service user or root owns, and makes the
  chmod and chown only when the mode or owner is not already right. The logs, the other
  service-owned paths the step touches, are never chmodded or chowned once they exist: one
  carrying a user flag fails the judge and is refused and left as found, as any other log the
  judge refuses is (`floor --rebuild` or `audit --rotate` replaces it).
- **The hand-over order was not measured before 2026-11-23.** The order this design first
  named, flag the new file and then `fchown` it to the service user, rested on an unmeasured
  assumption (K0 measured the service user's operations on a flagged file, not root's). The
  first root run of the verbs on 2026-11-23 failed at that hand-over, and the first probe
  measured why; the second probe measured the directory swap that replaced the design.
- **Root never acts by path where the service user can write.** `server/` and `.user/` are
  the service user's (and so is `keystore-sock/` in the deny-plus-pin fallback), so a name
  root created there could be a symlink or a swapped file the service user planted. The
  marker, `keystore-logs/` and `keystore-staging/` therefore live in the root-owned data root
  (root:wheel 0755), where only root creates names, under `keystore-`-prefixed names that the
  Pod prefix deny covers ("Pod denies"). Every step goes through one descriptor on the data
  root, opened `O_DIRECTORY|O_NOFOLLOW` and judged by `fstat` (root-owned, not group- or
  other-writable), and descriptors on `keystore-logs/`, each log's directory and
  `keystore-staging/` opened and judged the same way; each create is `O_CREAT|O_EXCL|O_NOFOLLOW`.

  *A hard link does not strand the logs.* A flagged file cannot be linked, but a link may
  stand on a restored log. The verbs take an old log with more than one link as input, with a
  Warn naming it: they always swap in a fresh inode, and the other link keeps only the old
  file. The steady-state check (`judgeLog`) still refuses a canonical log with more than one
  link, and its error, and `doctor`, name the verb that repairs it: `floor --rebuild` for the
  floor, `audit --rotate` for the audit log. Rebuild is the user-scope twin of Phase A's
  "remove `keystore-floor.json`, then run any root verb".
- **The residuals of the swap.**
  - *Lines appended after the read.* The read in step 2 is bounded by the old log's size at
    open. A line appended to the old log after that is dropped with the retired log. Every
    legitimate writer holds the store lock, which the verb holds, so only a hostile process
    appends then, and what it could append is its own lines.
  - *The service user can block `floor --rebuild`.* It can flood the floor with tombstones past
    the key bound, or make one of its scopes unopenable; rebuild then refuses, naming the scope
    ("Rebuild never lowers"). The repair is `sudo k3sm keys rm-scope user/<uid> --yes` for that
    scope, then `floor --rebuild`. It needs only the scope's `scope.key` to open: a delivery
    record that names a delivery still refuses (withdraw first), but one that does not read,
    corrupt or missing beside `entries/`, which the service user can cause in its own tree, does
    not. `rm-scope` then lists the scope key, removes the tree and exits 4, saying the delivery
    record could not be read, so deliveries from this scope were not checked, and any Secret it
    delivered stays until it is withdrawn. It proceeds only for a damaged
    record (`ErrCorrupt`, the judge's refusal, a planted name, a record missing beside
    `scope.key`): if a scope's `scope.key` is present but untrusted, rm-scope removes the scope
    unlisted (exit 4) as for a missing one. A transient failure to read the record (a cancelled
    context, `EINTR`, `EMFILE`, `EIO`) refuses, saying nothing was changed and to run it again.
  - *Root's audit line comes after the verb.* The CLI writes the verb's audit line once the
    verb has returned, so a crash between the commit and that line leaves the change without
    its line; the rerun writes one.
  - *A bounded descent.* `rm-scope` descends at most 32 directories below the scope directory
    and refuses a deeper tree ("A removed scope stays removed").
- **`audit --rotate` keeps four archives.** The previous logs are `keystore-audit.log.1` (the
  newest) to `keystore-audit.log.4`, in `keystore-logs/audit/archives/`, root's 0700. Rotate refuses, changing
  nothing, when `.4` exists, unless `--discard-oldest` is given, so evidence is never discarded
  without root saying so; the `doctor` hint past the soft cap says to export the archives first
  (as root, copy them off the Mac), then rotate. The archives are root's evidence: the
  replacement directory gets a fresh `archives/`, root's 0700, in which `.1` is a fresh
  root-owned, unflagged inode holding the old log's bytes up to its size at open in step 2, 0600
  with one link. It is made by cloning the old log (`fclonefileat`, no symlink follow, the clone
  the caller's), so rotate needs no free space the size of a log the service user can grow:
  the clone holds the whole file and keeps the flag, so on its own descriptor, in the root-only
  directory, its flag is cleared, it is made root's 0600, and, reopened for writing and checked
  as the same inode, truncated to the size at open (the snapshot rule still holds) and
  verified (measured as root, U195). The clone carries everything the source's owner could
  set that clonefile copies: measured, it carries the source's extended attributes and not its
  ACL. Whatever it carries, every extended attribute is removed on the clone's descriptor
  (`flistxattr`, then `fremovexattr` of each, skipping none; one that cannot be removed, or any
  left, refuses the rotate), any extended ACL is removed (`fchmodx_np`, as `chmod -N`), and the
  clone is judged with the logs' flags-and-ACL judge. Rotate also refuses an old log that
  carries an extended ACL, as the steady-state judge does, and an archive that carries one,
  read on the archive's descriptor, as it refuses one on `archives/`. When the volume refuses the clone, rotate copies instead,
  and first checks the volume's free space and size (one `fstatfs`): short of the log's size
  plus the larger of 1 GiB and 2% of the volume's size, so the margin scales with the volume,
  it refuses up front, saying so, with nothing changed. The
  older archives are carried in by hard link from the live `archives/`; the service user never
  appends to an archive, and cannot reach one. Rotate requires every archive to be a regular file, root's, 0600,
  unflagged, with no extended ACL, and refuses anything else before it changes anything; an archive with a second
  link is a Warn, not a refusal, since an alias of a root 0600 file gives the service user
  nothing. A rerun after a crash past the swap prints the crashed run's report and does not
  rotate twice. While the marker stands a root verb's audit line refuses rather than skipping a
  missing audit log. Rotation resets every uid's audit share and budgets to 0 (below). That is
  deliberate: only root rotates, and what a uid wrote before is kept in the archives, so the
  evidence a reset share can push out of the live log is bounded by the four archives (U91).
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
  one. A longer line past the hard cap in the audit log, which only another writer could have
  put there, is read through to its newline, skipped and charged to no uid, never sticky damage,
  as the audit reader skips any line it cannot read, counting it as damage charged to no uid;
  in the floor it is damage. The audit reader ignores fields it does not know, but decodes
  strictly for charging: a known key spelled in another case, or any key given twice, fails
  the line, which is uncharged damage, so a line is never charged to whichever scope a
  lenient decoder would pick (`FuzzParseAuditLine` checks the charged uid is the exact
  `scope` key's). In `pkg/keystore` the caps are `Config.LogSoftCap` and `Config.LogHardCap`, and the
  user scope's own revocations past the hard cap (an `rm` or a `withdraw` that revokes) draw on
  the socket margin, `Config.LogRevocationBudget`, counted per uid from the lines that start at
  or past the hard cap; only a revocation's line draws on it, and any other line found past
  the hard cap at append time is refused, never charged to the budget. The reconciler
  allowance and the per-uid shares arrive with the reconciler and the socket (U51, U67).
  **The user scope must not be exported, to the socket or any other caller outside
  `pkg/keystore`, before the per-uid shares (U51) are built:** until then one uid can fill
  either log to the hard cap for everyone. `TestUserScopeIsUnexported` holds that gate, and
  holds it mechanically: once any exported identifier reaches the user scope, it fails
  unless the tests of U51 (the per-uid byte shares, in `pkg/keystore/socket`), of U193
  (the rebuild, `pkg/keystore::TestRebuildCarriesTombstonesForward`) and of U194 (the rebuild
  after `rm-scope`, `pkg/keystore::TestRebuildDropsRemovedScopeKeys`) exist, found with `go/ast`
  over each package's test files; the test and its comment list them. A prerequisite counts
  only if its body calls `t.Error*` or `t.Fatal*` and never `t.Skip`, `t.SkipNow` or
  `t.Skipf`, so an empty or skipped stub does not satisfy the gate. An exported identifier
  reaches the user scope when a file outside `pkg/keystore` references a banned name, and
  also when an exported function, method, or package-level `var`, `const` or type declared
  in `pkg/keystore` references `UserScope`, `startUserScopes`, `catchUpUser`, `ResolveEntry`,
  `ParseEntry`, `Deliver`, `Withdraw` or `Delivery`, directly or through same-package calls
  (a call graph built with `go/ast` alone, functions resolved by name and method calls on
  package types by name, a call on the method's own receiver to its own type first), so an
  in-package wrapper at any depth is an export too, and so is a dot-import of the package
  outside it; the names that already do (the scope's constructor and the entry resolver)
  are an explicit allowlist in the test, each with its reason, and the methods on
  `UserScope` are left out by their receiver. A prerequisite test counts only if it calls
  `t.Error*` or `t.Fatal*` on its `*testing.T` parameter outside a constant-false branch.
  The scan is a guardrail, not a proof; the socket slice's mandatory security review is the
  backstop. The socket slice lifts
  its ban on references, never that check. The
  `ErrLogFull` texts name the log and which bound was met (the hard cap, the key bound, the
  reader's bound or the caller's revocation budget), never a size, a key count, a cap or a
  uid: they reach the socket, and the figures are root's, through `doctor` (`LogSizes`). So
  do the other log errors a socket caller can see: a nearly full volume's names no free
  bytes, a log past the reader's bound names no size or bound, and a floor line that does not
  parse, or a torn tail, reaches no error at all: the reader skips it and keeps its byte offset
  and the damage count for root, logged at Warn and read through `FloorDamage`; nor does a read I/O error name its offset, nor an untrusted log or data
  root its link count, owner uid, mode or flag bits: each names only what is wrong, and the
  figures go to the Debug log. A `deliver` whose line adds no key (its delivery-record key is
  in the floor) is not held to the key bound or share, and a withdraw of an unknown UID that
  appends a catch-up line is admitted in the revocation class before it appends it. A
  configuration whose reader's bounds sit below what an existing log already holds (a log
  larger than the size bound, or a floor with more keys than the reader's key bound, after
  the caps were lowered) is refused at store open by `FileStore.CheckLogBounds`, as an invalid
  configuration whose root-only error names the current figures, rather than reading that
  log as damage. `CheckLogBounds` fails closed: a log that is missing, untrusted (not a
  regular file of one link, the service user's at 0600) or unflagged, one that cannot be
  read, or one whose state is damage that refuses it whole, is an error, so the start step
  does not start the user scope. Bounded damage, lines the reader skips, is no error: it
  returns their count across both logs, which the start step logs at Warn. **Server start owes two calls before the listener serves:**
  `FileStore.CheckLogBounds`, then `catchUpUser` (unexported), which, under the exclusive store
  lock, appends the catch-up floor line of every user scope whose authenticated delivery
  record sits above its floor line (a withdraw whose floor line failed leaves one behind, and
  the process's own mark of the record's sequence does not survive a restart), so the
  catch-up does not wait for that scope's next mutation, and the live floor line of every
  user entry whose authenticated pointer's generation has none (a `put` that lost it). Without
  a restart, a `put` that returns its commit with the floor line lost marks the name in the
  process, and the next `put`, `deliver` or `withdraw` on that scope catches the entry up under
  the exclusive store lock, before it serves, at the authenticated pointer and under the
  same refusals (`TestRuntimeCatchUpRestoresLostEntryLine`). `New` only constructs the store and
  reads neither log, so neither call runs there; the server start that exports the user
  scope makes both, through the unexported `startUserScopes`, which runs `CheckLogBounds`
  and then `catchUpUser`, in that order, and then marks the user scope started. Until it
  has, the store's user-scope accessor refuses every uid (`errUserScopesNotStarted`), so the
  order is held by the code, not by the caller's care: a refused `CheckLogBounds`, or a
  catch-up that could not run at all, leaves the user scope unstarted and returns the
  error, fail-closed. A scope whose live catch-up line the floor refused
  (`errCatchUpRefused`: a tainted key, or a generation the floor has no line for while
  unattributable damage counts) is **quarantined**: the accessor still returns that uid's
  view, whose grants and reads (`put`, `deliver`, `current`, `list`, the delivery lookup)
  refuse with `errFloorDegraded` and whose `rm` and `withdraw` run, since quarantine and
  taint never block a revocation; every other scope starts, and the refusal is named in the
  returned error, so unattributable damage in the shared floor quarantines only the scopes
  that have something to catch up (`TestTornPutLineQuarantinesOnlyItsScope`,
  `TestQuarantinedScopeRevokes`). Only the floor's damage (`errFloorDegraded`) quarantines:
  a transient refusal of the catch-up line (`ErrLogFull`, `errLogNoSpace`, an I/O error) is
  named in the returned error and the scope starts, and the next start step, and for the
  delivery record every operation's own catch-up, tries the line again
  (`TestFullVolumeAtStartDoesNotQuarantine`). The socket's supervisor runs the start step
  on every pass, and the same split holds on every one: only the named per-scope catch-up
  errors (`ScopesNotCaughtUp`) are logged at Warn while the listener serves; a refused
  `CheckLogBounds` or a catch-up that failed as a whole fails the step on any pass, the
  first or a later one after the user scope has started, so the listener stays off on the
  supervisor's backoff (`TestStartUserScopesStepRefusesOnLaterPass`). A `withdraw` whose delivery record a damaged
  line taints still runs: it checks the record against the highest sequence the floor's
  whole lines hold, seals the tombstone and writes its floor line, which is never refused
  for damage; it only removes, so it cannot bring anything back
  (`TestWithdrawRunsUnderDeliveryRecordTaint`). Under that taint the record copy may be
  older than a lost line, which could have withdrawn any delivery the copy still holds
  live, so the withdraw seals every delivery withdrawn (it keeps none live), at one above
  the larger of the record's and the floor's sequence: a lost withdraw is never undone
  (`TestWithdrawUnderTaintNeverRevivesLostWithdraw`). A scope the catch-up
  could not open has no line to write, is named in its error and still starts. Every test that
  builds a user scope runs the start step first, and `TestUserScopeIsUnexported` holds the
  export until the server start calls it.
  `catchUpUser` runs every scope: a scope it cannot open, or whose floor does not take a
  line, is logged at Warn and named in its error, the refused lines are counted in one Warn,
  and the others are caught up, though a line the damage refused then quarantines its scope; a
  refused catch-up line during any operation is logged at Warn too, never dropped unseen.
  `FileStore.LogSizes` gives the sizes and caps to the
  `doctor` row. **The reader is bounded**, since the service user can append to either log
  without limit: a log larger than the hard cap plus 1024 uids' revocation budgets plus 1 MiB
  (1,233 MiB at the defaults) is damage (`logReadBound`; the configuration is bounded from
  above, a hard cap of at most 2^40 bytes and a revocation budget of at most 2^30, refused
  at `checkConfig` past either, so the sum cannot overflow). *`logReadBound` grows with the
  budgets still to land.* Today it holds the hard cap, `maxRevokeUIDs` (1024) uids' two
  revocation budgets (the 720 KiB socket margin and the 256 KiB reconciler allowance) and
  the 1 MiB margin, 1,233 MiB at the defaults; the reconciler's 1 MiB budget, all but its
  pre-frame part, is still to land. With the socket's 720 KiB margin, the
  reconciler's 256 KiB per-uid allowance and its 1 MiB budget ("Per-uid fairness"), each
  is a line class written past the hard cap, so the bound becomes the hard cap plus 1024 ×
  (720 KiB + 256 KiB) plus the 1 MiB reconciler budget plus the 1 MiB margin: the most the
  server itself can write past the hard cap, 1024 uids at both their budgets and the
  reconciler at its own, with the margin above it, so no log the server wrote reads as
  damage. Each budget's change raises the bound in the same change. The first to land is the
  reconciler budget's 256 KiB pre-frame part (`keystore.PreFrameBudget`): the audit log's bound
  is `logReadBound` plus `PreFrameBudget`, and the floor's, to which no pre-frame line is
  written, stays `logReadBound` (`readBoundOf`). A floor holding more distinct
  `(scope, name, generation)` keys than its key bound is damage too, the key bound being that size bound over the shortest line
  that adds a key (55 bytes, its checksum included), held to a ceiling of 2^18 (262,144) keys whatever the caps are
  configured to (larger caps do not raise it), plus the revocation headroom of 1/16 of that ("Per-uid fairness"): 278,528
  keys for the reader. The size alone would allow about 23.5 million keys at the defaults, so
  the ceiling is met first there, and it is what bounds the reader's memory. The reader
  interns scope strings and indexes each key's generations by `(scope, name)`, so `rm`'s
  read of a name's live generations does not scan the floor. Measured on an M1 Ultra, read
  from scratch: the heap worst case, 278,528 keys with 253-byte names and the longest scope
  (86 MiB of lines), holds about 128 MiB of heap and takes about 0.41 s
  (`BenchmarkFloorReadLongNames`); the time worst case, the most lines the size bound holds
  (measured at about 7.3 million, 321 MiB, under the former 64 KiB revocation budget), holds
  about 69 MiB and takes about 3.9 s (`BenchmarkFloorReadLineCount`); at today's 1,233 MiB
  bound, about 23.5 million lines of 55 bytes, the time scales to about 12.6 s (not re-measured), and the
  heap, bounded by the key ceiling, does not grow; 262,144 keys of the shortest lines hold about 64 MiB and
  take about 0.23 s (`BenchmarkFloorReadAtKeyBound`). At a ceiling of 2^20 the long-name case
  held about 494 MiB, over the 200 MiB the reader is allowed, so the ceiling was lowered. The
  writer refuses a new key at that bound, so a floor the server wrote never reaches it as
  damage.
  The server never appends past either bound itself: an append that would take the log past
  the size bound, or a floor line that would add a key past the key bound, is refused
  (`ErrLogFull`), and the floor's key count is the one the reader keeps, read on the append's
  own descriptor. A line for a key the floor already holds, a revocation's tombstone or
  withdrawal line included, is still written, and a revocation's line that adds a key is
  written into the revocation headroom. A grant is refused at admission, before its
  first write, while the floor has no room for the two keys a grant can add (a put that mints
  its scope adds the delivery record's and the entry's), with `ErrLogFull`, whose text names
  `floor --rebuild` and `audit --rotate`; `rm`/`put` churn alone so stops at the key bound and
  never makes the floor damage (U24). A line straddling the hard cap is read through however long it is. `room`
  (admission, before the line exists, at the 1 KiB a line can be) and the append (at the
  line's real length) judge the revocation budget through one predicate. Each log is opened
  `O_NONBLOCK`, so a FIFO at its name is refused on its descriptor instead of blocking the
  open (U24).
- **Per-uid fairness.** The logs are shared, so one user must not be able to fill them for
  everyone. Each uid gets a budget in each log, a fixed byte count: `keystore.logUIDShare`,
  default 16 MiB, which is 1/16 of the default hard cap. The share is at most 1/16 of the hard
  cap: a configured share above `logHardCap / 16` is refused at server start. At the default
  caps, fewer than 16 uids cannot by themselves bring a log to the hard cap: 15 uids at their
  shares and both their revocation budgets, with the reconciler budget below, come to
  15 × (16 MiB + 976 KiB) + 1 MiB = 261,424 KiB, about 255.3 MiB, under the 256 MiB. Root's own lines, charged to
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
    For the pre-frame part the server persists its dropped counts in `.preframe-dropped`, the
    server-counts file, in the store directory it owns (`server/keystore/`, 0700; the audit
    log's directory is root's): one header line, then lines `<uid> <class> <count>` for at most
    256 uids, each line at most 64 bytes, with the uids past 256 folded into one
    `others <class> <count>` line per class. The same file, in the same format, carries the
    server's two other counts that must outlast it, each as its own class beside the five
    pre-frame ones: `post-frame`, a uid's post-frame refused lines dropped and not yet
    summarized ("The audit log", refused lines), and `unaudited`, the committed revocations
    whose audit line could not be written, which names no uid and is written only as its
    `others unaudited <count>` line (a uid line naming it does not parse). Neither is a
    pre-frame class: no pre-frame line or summary carries it, and it draws on no budget. The
    file's size bound counts a line for each class a named uid may carry, so the encoder's
    output always fits it. It is written temp,
    fsync, rename and directory fsync through a descriptor of the store directory, `O_NOFOLLOW`,
    0600, when any of its counts changes, at most once a second on the server's clock, and
    emptied to its header once every count has reached the audit log; it is read, owner and mode
    checked and strictly parsed, and merged when the server opens its logs and again on each
    reopen. It is written under the server's in-process mutex **without** the store lock, which
    may be what the dropped line timed out on. A file that does not parse is reported, never
    reset: the counts stay in memory, the server stops writing the file, and `doctor`'s
    `keystore-logs` row says the persisted count is unreadable. The `others` lines name no uid,
    so no summary line can carry them; they wait for root's next `audit --rotate`. That rotate
    reads the file through the store directory it judged and holds, and writes at the start of
    the new audit log one line per class with a count, the server's summary-line form with
    `"via":"root"` and caller uid 0 (so it is charged to no uid and to no pre-frame part):
    `{"v":1,…,"op":"refused","via":"root","caller":{"uid":0},…,"result":"dropped","charge":"reconciler","source":"pre-frame","dropped":<total>,"class":"<class>"}`,
    the pre-frame classes first, then `post-frame`, whose line carries its own name as its
    `source`. The `unaudited` count is last and is no refusal and nothing dropped: the
    revocations it counts committed and only their lines are missing, so its line is its own
    op, `unaudited`, written only by root's `audit --rotate`:
    `{"v":1,…,"op":"unaudited","via":"root","caller":{"uid":0},"scope":"","name":"","namespace":"","result":"committed","count":<total>}`.
    It carries no `charge` or `source`, so it is charged to no uid and to no pre-frame part;
    the strict audit reader takes it like any line and the pre-frame recount skips it
    (`TestRotateAuditWritesDroppedCounts`).
    Only once the swap committed does it take the counts it wrote out of the file, leaving what
    the server added since; the server's next reopen moves its in-memory counts by what the file
    lost, so no count is written twice. A run that stops between the swap and that step leaves
    the counts in the file, and the next rotate writes them again: counted twice, never lost.
    One race does lose a count: the server writes the file without the store lock, so a server
    write that lands between rotate's re-read of the file and its rewrite is overwritten, and
    that one window's increment is counted once too few, at most one second's refusals. Both
    limits hold for the post-frame and unaudited counts the same way: a rotate that stops at
    that point can report one twice, and a server write landing during a rotate can lose one
    second's increment.
    The persisted counts file is therefore **best-effort evidence**, not an exact ledger.
    Besides that race, a count can be lost three ways: the service user, which owns the
    store directory and is trusted, can edit or truncate the file; root's clear after a
    rotate can race the server's own write of the file, so one side's update overwrites the
    other's; and a crash between a revocation's commit and its audit append leaves neither
    the line nor an `unaudited` count (as does a crash after a failed append and before the
    server's next write of the file). Each loss undercounts; none hides a line that was
    written, and the audit log itself stays the record of what was.
    The count in that `via: root` line is the service user's persisted claim, which root
    carries without vouching for it: the service user owns the store directory and can write
    any count there, the same residual as forged pre-frame lines (below), with a root label.
    The server keeps the file within the bounds its own reader enforces: a uid line that would
    name more than 256 uids, pass the line bound or overrun the size bound folds, with every
    line after it, into the per-class `others` lines (the `unaudited` count is only ever on its
    `others` line), so a written file always reads back and keeps each class's total.
  - *The pre-frame part is split so a login user cannot spend it for everyone.* A login user
    can be refused at will (a self-sandboxed process is refused as `sandboxed` under its own
    uid), so the 256 KiB pre-frame part is not one pool. A **login line** is a pre-frame line
    whose uid is from 501 to 2147483647 and whose `result` is not a uid-range reason (`root`,
    `service-uid`, `system-uid`, `high-uid`): the `sandboxed`, `sandbox-unknown` and
    `token-mismatch` refusals, `cred-unreadable` when a uid was read, and the summaries of such
    a uid. Login lines draw on at most 8 KiB per uid (`keystore.PreFrameLoginUIDShare`) and at
    most 128 KiB for all login uids together (`keystore.PreFrameLoginBudget`), for the life of
    the log. Every other pre-frame line draws on the remaining 128 KiB
    (`keystore.PreFrameReserved`), which no login line can consume, and that part is split by
    class too, so one ineligible source cannot silence the others:

    | class | lines | budget | per uid |
    |---|---|---|---|
    | `service-uid` | result `service-uid` | 32 KiB (`keystore.PreFrameServiceUIDBudget`) | (one uid) |
    | `root` | result `root` | 32 KiB (`keystore.PreFrameRootBudget`) | (one uid) |
    | `no-uid` | uid 4294967295, no uid read (`cred-unreadable`) | 16 KiB (`keystore.PreFrameNoUIDBudget`) | (one uid) |
    | `system-high` | result `system-uid` or `high-uid` | 48 KiB together (`keystore.PreFrameSystemHighBudget`) | 8 KiB (`keystore.PreFrameSystemHighUIDShare`) |

    The four add up to the reserved 128 KiB (a compile-time check), and no class draws on
    another's bytes. A refusal line's class is read off its uid and `result`; a dropped-count
    summary line carries its class in its own `class` field, a closed set (`login`, `root`,
    `service-uid`, `no-uid`, `system-high`) that the recount reads, so a summary is charged to
    the class of the refusals it summarises and a service uid inside the login range could not
    move bytes across classes. A summary with no `class`, or a refusal with one, is not a
    pre-frame line. A line past its class is dropped and counted as any other. Every class is
    recounted from the log at start, on every append and after maintenance, by the one charging
    rule the running count uses, never from memory. *Residual:* a class can still be spent by
    its own sources: any process running as root spends `root` (and the service user can append
    forged pre-frame lines of any class); any unsandboxed process of the service uid that merely
    connects, a native Pod past its Seatbelt deny included, spends `service-uid`; whatever can
    make its credentials unreadable spends `no-uid`; and system and high uids together, such as
    a person logged in under a uid below 501 (the macOS Guest account, uid 201) together with
    five other such uids, spend `system-high`, each one at most its 8 KiB. What each source
    silences is its own class, until root rotates the log.
  - *Past the share, reads are refused too.* A uid past its share has its own mutations and
    its own reads refused with `ErrLogFull` (code `log-full`) before any line is written, so
    no read is a way around the share. Its `refused` lines and their summaries are not written
    either: the server counts that uid's dropped lines as its `post-frame` count, persisted in
    the server-counts file `.preframe-dropped` ("Per-uid fairness"), `doctor` shows the count,
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
    - the **socket margin**, 720 KiB (`defaultLogRevocationBytes`), used only by that uid's
      own socket `withdraw`, `rm` and `rotate` lines and their floor lines. It holds one
      scope's full revocation under the longest scope (`user/2147483647`) and a 253-byte name.
      Each of its 256 entries `rm`'d is a burial of at most 6 tombstones (the floor's live
      generation, the one the pointer authenticates, and the 4 the tree alone may name,
      `maxBurialTombstones`) of 315 bytes (15 + 1 + 253 + 1 + 32 + 1 + 2 + 1 + 8 + 1: scope,
      name, generation, `rm`, checksum and newline, each field after the first led by its
      space) and an `rm` audit line of at most 444 bytes (the
      longest result, a full RFC3339Nano timestamp, and the socket's `via` and `caller` with the
      longest uid and pid), each of the two appends charged its
      leading newline: 256 × (6 × 315 + 1 + 444 + 1) = 598,016 bytes.
      Each of its 320 deliveries withdrawn (`maxDeliveries`) is a 91-byte floor line
      (15 + 1 + 11 + 1 + 32 + 1 + 20 + 1 + 8 + 1) and a
      `withdraw` audit line of at most 310 bytes, `via` and `caller` included: 320 × (91 + 1 + 310 + 1) = 128,960 bytes. In
      all 726,976 bytes, rounded up to 720 KiB (737,280), which the checksum leaves as it was. With it `logReadBound` at the default
      caps is 256 MiB + 1024 × (720 KiB + 256 KiB) + 1 MiB = 1,233 MiB, and at the configuration's upper
      bounds still 2^40 + 1024 × (2^30 + 2^18) + 2^20, which cannot overflow. A configured budget under
      one worst-case burial plus its audit line, 6 × 315 + 1 + 444 + 1 = 2,336 bytes
      (`minLogRevokeBudget`), is refused at `checkConfig`. The budget is kept per log, so
      a burial, charged to the floor's, never takes the room of its audit line, charged to the
      audit log's, which the revocation's admission found for a whole append (`room`,
      `maxAppendLine`) before the burial: a revocation whose floor budget left over is just
      below the burial plus its audit line still buries and audits, and one whose audit-log
      budget cannot hold an append is refused before anything is written
      (`TestRmBurialNeverLosesItsAuditLine`). One a uid's
      lines past the hard cap exceed in either log, which the writer never produces, so only
      lowered caps make it, is refused at store open by `CheckLogBounds`
      (`errLogRevokeBudgetSpent`), naming the remedy: configure the caps the
      log was written under, or restore the caps and rotate the audit log, the rotate verb
      being not yet available, so until it is, restore the log from a backup and run
      `doctor`. Either would otherwise disable that uid's revocations without a word. A
      uid the writer took honestly to under one whole append (1,025 bytes) of its budget is that
      uid's state alone, never a start failure: `CheckLogBounds` logs it at Warn and counts
      it in its `spent` return, the store starts, every other uid's `rm` and `withdraw`
      succeed, and that uid's own revocations keep being refused at run time
      (`TestSpentRevocationBudgetIsPerUID`).

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
    deliveries, still has its 720 KiB socket margin for `withdraw`, `rm` and `rotate`, about 360
    of them at two lines of at most 1 KiB each (the operation's line and its floor line). A uid
    that spends its margin, for instance by rotating without end, refuses only its own further
    socket revocations, until root rotates the log.
  - *How far a log can pass the hard cap.* Only revocation lines are written past the hard
    cap, and each uid's are bounded by its two budgets, so a log can grow past the hard cap by
    at most 976 KiB (256 KiB plus 720 KiB) times the number of user scopes, plus the 1 MiB
    reconciler budget, whose lines the hard cap does not test either. User scopes are
    bounded by the host's eligible local accounts: a scope is minted only for an eligible uid
    (501 to 2147483647) with a real, non-synthesized GeneratedUID ("Key hierarchy", "Eligible
    peers"), so a local user cannot create scopes beyond the accounts root made. When a log's
    size is past the hard cap at all, `doctor` shows a Warn with the overshoot in bytes and the
    `audit --rotate` or `floor --rebuild` hint (U84, residual 5).
  - *The floor's keys are shared per uid too.* Besides the byte shares, each floor key is
    charged to its scope's uid, counted by the reader on every read and append. The key share
    is a **lifetime share**: every key a uid's lines add is charged to it, buried or live,
    because a buried key stays in the floor for good (no server write frees one, and
    `floor --rebuild` carries every tombstone forward), so it holds `keyBound` for good too. A
    grant line that adds a key is refused (`ErrLogFull`, the caller's key share) once its uid
    has added `uidKeyShare` keys. A tombstone for a key the floor already holds adds no key, so
    `rm` is never refused by the share; a revocation line that adds a key is charged but never
    refused by it. *The arithmetic.* A scope holds at most `maxScopeEntries` (256) live entries
    and one delivery record, 257 live keys (`put` over an existing name keeps its generation,
    so only a new name, or a name re-created after `rm`, adds a key). `uidKeyShare` is 16 times
    that, 16 × 257 = 4,112 keys, so a uid can replace its whole live quota about 15 times
    before its share is spent, well above honest churn. The global key bound is the 2^18
    (262,144) ceiling, met first at every cap setting the server accepts, and it is not
    configurable: 63 uids at their shares hold 63 × 4,112 = 259,056 keys, under it, so filling
    the global key bound takes at least 64 uids (262,144 / 4,112 ≈ 63.8). Past the key bound
    sits a **revocation headroom** of `keyBound / 16` keys that only revocation lines
    (tombstones, withdrawal lines and catch-up lines) may add: such a line is refused only past
    `keyBound` plus the headroom, and the reader's key bound includes the headroom, so a floor
    the server filled to it still reads. However many grant keys stand, they stop at
    `keyBound`, which no revocation line is held to: no uid's grants can refuse any uid's
    revocation short of the headroom, which only revocations spend.
    *Residual (self-lockout), accepted.* A uid whose churn spends its lifetime share is refused
    every further grant that adds a key, though its `rm` still succeeds. Larger caps do not
    help, since the ceiling is fixed. The remedy is root's: once root removes that user scope
    (with `rm-scope`), `floor --rebuild` drops every key of that scope, live or buried.
    `rm-scope` lists the scope key in `keystore-removed-scopes.json`, so a copied-back old
    directory, whose K_u still opens under the unchanged master, is refused at every open, and
    a re-minted scope gets a fresh K_u; no tombstone of the old scope is needed to refuse it. That frees the uid's share and its keys in the global bound (U194,
    pending). Short of that, no server write frees a key; compacting buried keys of a scope
    that still stands is an open question.
  - The hard cap and the per-uid budgets bound the whole log (U51, U62, U67).
- **A missing log while scopes exist.** A log that does not exist is `errLogMissing`, which
  names `sudo k3sm install` only while no user scope exists. Once `keystore/.user/` exists, a
  new, empty floor would lower every scope's floor, so the error names the matched-set
  restore ("Backup and snapshots": `keystore/`, `keystore/.user/` and both logs from one
  backup, then `floor --rebuild`), never `install`; and `install` refuses to create a floor
  while user scopes exist, unless root gives it an explicit flag that says it lowers the
  floor (`TestLogMissingWithScopesNamesRestore`; the install side lands with install).
  *Residual (the guard reads through the service user's directory).* Install's "floor missing
  while scopes exist" guard decides whether scopes exist by reading `.user` through
  `keystore/`, which the service user owns, so that user can hide its scopes from the guard.
  It only matters when the floor is already absent, which only root can cause: the floor's
  directory is root's.
- **A log at a location no release keeps one.** A log at the top of the data root, or
  directly in `keystore-logs/`, is not a supported layout: no release wrote one there. Install
  and the store refuse it, saying it is not a supported layout, that the logs belong under
  `keystore-logs/floor/` and `keystore-logs/audit/`, and to restore the data root from a
  backup. They never tell the operator to unflag or delete it.
- **Backup and restore.** The flag does not survive `cp`, rsync or Time Machine, so a restore
  always ends with `floor --rebuild`, and `audit --rotate` swaps in a fresh flagged audit log.
  Until then
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
  `show`, `exec-read`, `deliver`, `withdraw`, `rewrap`, `rm-scope`, `floor-rebuild`,
  `floor-merge`, `floor-merge-dry-run`, `audit-rotate`, `deliver-write`, `deliver-delete`,
  `refused`, `unaudited` (root's `audit --rotate` line for the committed revocations whose
  lines were not written, with result `committed`); and `ok`, `committed` or a sentinel name: a
  user-scope operation's result is one of a closed set (`keystore.auditResult`): `ok`,
  `committed`, `quota`, `not-found`, `exists`, `scope-absent`, `corrupt`, `log-full`,
  `invalid-name`, `kind-mismatch`, `quarantined` (the start step quarantined the scope),
  `floor-degraded` (the floor's damage refused a grant or read), and `error` for any refusal
  with no name of its own (`TestAuditResultNamesRefusals`). `ok` is a change committed whole,
  `committed` a revocation committed in part and reported after its commit, such as an `rm`
  whose burial stopped part way or a `withdraw` whose floor line failed; a root verb that
  exits 4 or 5, its change made and its report to read, is `committed` too). When such a partial commit's own audit line then fails, the reply
  keeps both failures, still reported as after a commit, and the server logs the scope and
  verb at Warn, with no figures. A `withdraw` under a delivery-record taint seals every
  delivery withdrawn (see "Damage and taint"), so it writes one `withdraw` line for the
  requested delivery and one more for each other delivery that seal withdrew, each naming
  that delivery and its namespace, with the operation's result, in the revocation class:
  past the hard cap each draws on the uid's revocation budget. Before it seals anything the
  withdraw admits all of them on the audit log, `(1 + live deliveries) × maxAppendLine`
  bytes of the uid's revocation budget, one whole append each, and is refused with
  `ErrLogFull`, nothing sealed, when the budget does not hold them
  (`TestWithdrawMassSealAuditsEveryDeliveryAtBudgetEdge`). It then attempts every sealed
  delivery's line, keeps going past one that fails, and reports how many it wrote with
  every failure, as an audit failure after the commit
  (`TestWithdrawUnderTaintAuditsEverySealed`, `TestAuditSealedKeepsGoingPastFailure`). `via` is
  `socket`, `root` or `reconciler`. `caller.user` is display-only beside the uid, and `pid` is
  advisory. Readers ignore unknown fields, and `v` bumps only on a breaking change (U23). The
  user docs specify the format.
  As built: every line of a socket operation carries `via` `socket` and `caller` with the
  peer's `uid` (the scope's own) and its `pid` when the peer credentials gave one; `caller.user`
  is not written yet, since the store has no bounded source for it and the socket margin is
  sized for the line without it. `version` and `fingerprint` are on the lines of the operations
  that write a version, and only those: a `put`'s `ok` line (version 1, and the fingerprint
  when its scope already exists; a put that mints its scope has no key when its line is
  written, so it names no fingerprint) and a committed `rotate`'s line (the new version).
  `rm`, `withdraw`, `list`, `exec-read` and every refusal carry neither. The `caller` object
  is parsed as strictly as the line: a key given twice or spelled in another case makes the
  line damage, charged to no uid.
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
  is not audited rather than appended without it; that line is counted in the uid's
  post-frame dropped count, which its next refused-line summary or root's next
  `audit --rotate` writes and `doctor` shows (`TestAuditBrieflyCountsLineLockKeptOut`). An
  operation whose work inside its hold panics (a panic the socket's listener recovers and
  logs) has an outcome that is not known. A revocation (`rotate`, `rm`, `withdraw`) then
  writes no line: an `ok` line would record an operation that never finished, and a refused
  line could hide an `rm` whose burial committed. It is counted with the unaudited operations
  instead (`UnauditedOps`, U112), the one count of a change that may stand without its line,
  which `doctor` shows and root's `audit --rotate` writes; the count names no uid or entry,
  and the socket's Error line for the panicked operation, with its op, uid and
  `requested_entry`, written as the panic leaves the operation and before the listener
  recovers it, is where they are found (`TestPanickedOperationLogged`). A grant (`put`, a minting `put`,
  `deliver`) has already written its `ok` line before its first write, so it follows the
  grant's own rule for a commit that fails after the line ("Order", below): a second line,
  with result `error`, and no count, since the grant is not unrecorded
  (`TestPanicInHoldWritesNoOKLine`).
- **Lock modes and fairness.** Reads (`list`, `read-for-exec`, `deliveries` and the
  reconciler's reads) take the store lock shared, and their audit lines are appended under that
  shared hold (a read is admitted against the share first, then reads, then appends its line,
  then replies; a read whose line is not written returns no value), which excludes the maintenance verbs as an exclusive hold does; the server
  serialises its own appends and share counts in process. Mutations take the lock exclusive.
  In the server both modes go through one in-process reader-writer lock with writer preference
  (a waiting writer blocks new readers, as Go's `sync.RWMutex` does) in front of the `flock`, so
  a stream of reads cannot starve a mutation.
  As built: `pkg/keystore`'s store lock takes the in-process lock, then the `.lock` `flock`, both
  within the one lock wait. A `put`, `rotate` or `rm` first waits for its uid's mutation lock,
  under a lock wait of its own; a `put` or `rotate` then walks the scope when it holds no fresh
  usage figure ("Quotas"), a walk bounded only by its request's context, and each of the three
  runs the GeneratedUID lookup, under its own 250 ms deadline. So the longest it waits before
  its hold is twice the lock wait (4 s at the default), plus 250 ms, plus that walk; only
  another operation of the same uid makes it wait for the uid's lock. A request whose context
  ends during the walk, or before the store lock, takes no store lock and writes nothing. As `sync.RWMutex` does, a waiting writer blocks new readers and a
  writer's release hands the lock to every reader already waiting before the next writer, so
  neither mode starves the other; a writer that gives up its wait readmits readers
  (`TestWriterPreferringLock`, `TestPrefLockAdmitsReaderUnderWriterStream`). Every store the
  server opens over the tree shares that one lock (`Config.Tree`). The order every hold keeps is the uid's mutation lock (a `put`,
  `rotate` or `rm`, so only the uid's own operations wait on it), then the in-process lock, then
  the `.lock` `flock`, then the user-scope floor's lock; a system-scope verb, run as root in a
  process of its own, takes `keystore-lock` before the store lock. A user `list` authenticates
  each entry's current version only and checks the others for presence with one listing of the
  entry's directory ("List, when one entry is corrupt").
  - *A hold-time target.* The design's target for an exclusive hold by the server is at most
    50 ms of work per operation; larger work (a sweep, a scope's many deliveries) is chunked into
    separate holds, and no hold spans a call to the API server or a directory lookup. The
    GeneratedUID lookup runs before the lock is taken, with its own 250 ms deadline, and its
    answer is cached for that hold, so a slow directory service never stretches a hold. The root
    verbs that hold the lock for their whole run (`rm-scope`, `floor --rebuild`, `audit
    --rotate`, Rewrap) are outside the target. The 50 ms is a target K7a measures, not a
    guarantee any test checks: on the wall clock a `rotate` holds the lock about 21 ms, bound by
    its fsyncs, and that is measured only when a test runs with `K3SM_KEYSTORE_MEASURE` set.
    As built, the fake clock (U108, `TestExclusiveHoldBound`) checks that no hold of a `put`,
    `rotate`, `rm`, `deliver`, `withdraw` or read spans any fake time: none contains a
    GeneratedUID lookup or any other wait the clock can see. The lookup is taken before the
    lock, inside the uid's mutation lock, and its one answer, an error included, serves the
    whole hold. It proves nothing about the work a hold does, which the fake clock does not
    count. That work is bounded for `put` and `rotate`,
    but for one fallback: the quota is judged on the usage figure ("Quotas") and `rotate`'s
    orphan check reads only the version above the pointer. The remaining in-hold walk is that
    fallback: when the figure is still absent or stale at the lock (the cases "Quotas" lists:
    the walk before it failed, or a root `rm-scope` and a new mint, a Rewrap, a tree put in place,
    a `forgetAll`, or a first mint by a `deliver`, landed between that walk and the lock, or the
    `put` minted the scope), the quota judgement walks the scope under the lock, whatever the
    request's context. On the wall clock their holds are dominated by fsyncs: a `rotate`
    holds the lock about 21 ms on a developer Mac whether its entry keeps one version or 20,000,
    and a user `list` of an entry of 20,000 versions about 11 ms (720 ms when it opened every
    version). Not bounded yet: an `rm` reads each version record's header for its burial and
    unlinks each file under one exclusive hold, so its hold grows with the versions of the entry
    it removes, up to an entry's 65,536; U108 stays partial until that is chunked.
  - *Revocations retry.* A reconciler revocation (a `deliver-delete`, a withdrawal, a rotation
    write) that gets `ErrBusy` retries within the same sweep, up to 3 times with jittered
    waits, before the result is `Indeterminate` (U89).
  - *What one uid can do to another through the lock.* It cannot be refused for another uid's
    log lines ("Per-uid fairness"), but it can delay another uid. Its exclusive holds through
    the socket are, in any second: up to 5 for its mutations (the mutation rate limit, "The
    socket"; each takes one hold, for its work or, refused before its lock, for its refusal
    line); up to 5 more for the refusal lines of `list` requests refused before their shared
    hold (`auditBriefly`, under the 5-a-second limit `list` and `deliveries` share); up to 30
    for the refusal lines of `read-for-exec` requests refused the same way (30 a minute, a
    sliding window, so all 30 can fall in one second); and the socket's post-frame refused
    lines, at most 10 a minute with their dropped-count summary. Each refusal-line hold appends
    one line. None of these counts is a time bound: a `put`'s or `rotate`'s hold has no checked
    work bound (the hold-time target above), and an `rm`'s hold grows with the versions of the
    entry it removes, up to an entry's 65,536. A waiting writer also sits behind shared holds:
    the reads admitted before it began to wait, among them a user `list`, whose shared hold
    grows with the scope's entries and their versions (one listing of each entry's directory),
    and root's `list`, which opens every version of every entry. Writers are not FIFO among
    themselves: a release wakes every waiting writer and whichever takes the lock first wins, and the
    `flock` behind it promises no order either; writer preference only keeps new readers
    out while a writer waits. A `put` or `rotate` lists no entry
    under the lock, and walks the scope there only in the fallback "Quotas" names (a figure
    still absent or stale at the lock): on synctest's clock, another uid's `rm` that waits
    behind a `rotate` of an entry padded with thousands of files is served within its lock wait
    once the rotation's hold ends (`TestRotateHoldServesOtherUIDWithinLockWait`);
    `TestLockHoldBoundPerUID` measures the same on the wall clock through the socket, run with
    `K3SM_KEYSTORE_MEASURE` set. Many uids together can push another uid's wait past the
    2-second bound, which is `busy`, never a refusal for the share and never a deletion.
- **Order: a grant appends first; a revocation commits first.** A grant (a user `put`, and
  `deliver`, each with the scope's mint) appends its audit line before its first write, after
  every refusal it can give, and only then commits: a failed append refuses it and nothing is
  written, the mint's directories included, so no grant takes effect unrecorded. The
  user-scope floor is among those refusals: just before its `ok` line, a grant opens the floor,
  checks its flag and owner, and parses it, and a floor that is absent, unflagged, unreadable
  or malformed refuses the grant with nothing written and no `ok` line, so no grant commits a
  write whose floor line cannot follow (U20). A refusal
  before that point is audited best effort with its result, and a commit that fails after the
  line gets a second line with its result; a panic in the hold after the line is such a
  failure, and its second line names `error`. Every other socket operation, and the revocation
  class above all (`withdraw`, `rm`, `rotate`), commits its change to the store, then appends
  its audit line, then replies. If the append fails after the commit, the change stands and the
  reply says so: `ok` with the warning `committed; audit failed`, which the CLI prints. The
  server counts every such unaudited operation as its `unaudited` count, persisted in the
  server-counts file `.preframe-dropped` and read back when the server opens its logs, so it
  outlasts a clean restart, whose close writes any change still unwritten. The file is written
  at most once a second, by the next change past that second or by the close, so a crash
  before that write loses the counts changed since the last one; `doctor` shows the count, and root's next `audit --rotate` writes it as
  one line charged to no uid (U112). The two limits of the pre-frame counts hold for it
  ("Per-uid fairness"): a rotate that stops between its swap and its rewrite of the file can
  report it twice, and a server write landing during a rotate can lose one second's increment.
  An audit line carries only validated fields; a field that failed its grammar is a fixed
  placeholder.
- **Root verbs append after they run (deviation).** The root `k3sm keys` verbs that change
  state (`put`, `rotate`, `rm`, `adopt`, `rewrap`, `deliver`, `undeliver`, `floor merge`,
  `floor --rebuild`, `audit --rotate`, `rm-scope`) write their one audit line, `via` `root`,
  after the verb has run, with its result (`ok`, `committed`, `resumed` or `refused`), not
  before their first change as a grant's is. An intent line before the first change cannot be
  written in the v1 format with its existing fields: `result` is the outcome and has no value
  for "about to run", and an `ok` written first would claim an outcome not yet known. So the
  order stays as built, and a root verb whose append fails after it ran keeps what it did and
  warns on stderr that its line was not written (U52). Moving the line first takes a format
  change (a new `result` value), which is out of v1.
- **Fail closed, except for revocations.** While appends fail (a full disk, an I/O error), the
  server refuses user mutations and reads (`list`, `read-for-exec`, `deliveries`) until an
  append succeeds (U32). The revocation class is the exception: a socket `withdraw`, `rm` or
  `rotate` and the reconciler's revocation deletes still go ahead, their lines dropped and
  counted (the socket's as the persisted `unaudited` count above), and `doctor` shows the
  count. A full disk must not keep a revoked
  credential delivered (U109). As built: the failure is the store's own account of its
  appends (`FileStore.AuditFailing`), set by an append the file system or the hard cap
  refused and cleared by the next one that succeeds, and the socket refuses a request while
  it is set, after the request's header, value and rate limit pass and before the store is
  called (the deliver and deliveries placeholders too; `withdraw` is in the revocation
  class): with `log-full` when the store reports the failure's cause is the audit log past
  its hard cap (`FileStore.AuditFailingFull`), which tells the client a rotation ends it,
  and with `refused` for every other cause. Past the hard cap a grant's own refusal line
  cannot be written, so a `put` refused `log-full` there sets the failure, and later puts
  and reads answer `log-full` too until an append succeeds. Two appends can still succeed while it is set, so the
  state recovers without a restart: a revocation's line (which, past the hard cap, draws on
  its uid's margin) and a refused request's own post-frame `refused` line (rate-limited per
  uid as below); either ends the failure for every uid. A read whose line fails is refused
  even when its answer is that the scope does not exist, so a `list` for a uid with no
  scope is never served as an empty list without its line. The user docs recommend, without requiring, a data volume with
  an APFS reserve (`diskutil apfs addVolume … -reserve`), so that other writers on the Mac
  cannot fill the keystore's disk.
- **Coverage.** Three sources write lines besides the socket's operations, so no act on the
  keystore goes unrecorded:
  - *every root verb* (`put`, `rotate`, `rm`, `adopt`, `rewrap`, `deliver`, `undeliver`,
    `floor --rebuild`, `floor merge` and its dry run, `audit --rotate`, `rm-scope`, and the reads `list` and `show`),
    with `via` `root`, once
    `sudo k3sm install` has created the log; before that the system scope works as in Phase A
    and writes no line (U52);
  - *every reconciler write and delete* of a Secret and every withdrawal of a sealed record
    entry, with `via` `reconciler` and the KeyDelivery's namespace and UID (U53);
  - *each pre-frame refusal*: a connection from uid 0, from the service uid or from a uid
    below 501 is refused before any frame is read, and the refusal writes a `refused` line
    carrying the peer uid (U54).
- **`refused` lines are rate-limited per uid**, at most 10 a minute, with one summary line
  giving the count dropped, so a hostile local user cannot fill the log with refusals (U33).
  A post-frame line is the line of a request the socket refused itself, after the peer was
  admitted and before the store was called: `{"v":1,"ts":…,"op":"refused","via":"socket","caller":{"uid":<peer
  uid>,"pid":<pid>},"scope":"user/<peer uid>","name":"","namespace":"","request":"<op>","result":"<reason>"}`,
  `request` naming the operation as the log names it (`put`, `rotate`, `rm`, `list`,
  `exec-read`, `deliver`, `withdraw`, `deliveries`) and `result` one of a closed set:
  `bad-header` (a header field of the wrong type, a kind the socket does not store, a header
  over its cap), `bad-value` (a value missing, empty, oversize, or where the operation takes
  none), `not-served` (a delivery placeholder), `rate-limited`, `audit-failing` (the
  fail-closed rule below), and `ineligible-uid` (a peer the listener admitted whose uid the
  store gives no user scope, outside the login range or the store's own service uid: the
  store refuses it before any view, so the socket answers `refused`, not `internal`, and
  writes this line, which names no scope, `"scope":""`, and is charged to no uid's share;
  its dropped count waits in the persisted count for root's next `audit --rotate`,
  `TestIneligibleUIDRefusedWithLine`). It carries no entry name, value or other text the peer sent, is
  appended under the store lock taken for it alone, and is charged to the caller's share,
  so a line past the share is not written. The 10 a minute are counted per uid on a sliding
  minute, rate-limited answers included, before the line is written; every line not written
  (past the limit or the share, the lock not had, the append failed) is counted, and so is
  a store operation's refusal line that came before its lock and could not have it
  (`auditBriefly`), in the same per-uid count, which `doctor` names as the socket's and the
  store's refusal lines, and the
  count is written as one summary, `"result":"dropped"` with a `dropped` count and no
  `request`, at most once a minute (the first a minute after the uid's first refusal), the
  next time that uid is refused, before that refusal's own line. So a uid writes at most 11
  such lines a minute however many of its requests are refused. The count is the store's
  `post-frame` count, persisted in the server-counts file `.preframe-dropped` ("Per-uid
  fairness"), not the limiter's: a count still pending when the server stops is read back at
  its next start, shown by `doctor`, and written by the next summary for that uid or root's
  next `audit --rotate`, whichever comes first (`keystore/socket.FileStoreBridge`,
  `keystore.FileStore.AddPostFrameDropped`, `keystore.UserScope.Refused`).
  Pre-frame refusals are rate-limited the same way, per peer uid, with their own dropped-count
  summary (U54).
  A pre-frame line is `{"v":1,"ts":…,"op":"refused","via":"socket","caller":{"uid":<peer
  uid>},"scope":"","name":"","namespace":"","result":"<reason>","charge":"reconciler","source":"pre-frame"}`,
  the reason one of the listener's closed set (`root`, `service-uid`, `system-uid`, `high-uid`,
  `sandboxed`, `cred-unreadable`, `sandbox-unknown`, `token-mismatch`); its summary has `result` `dropped` and a
  `dropped` count, one line per uid, carrying every line of that uid's not written since its
  last summary (rate-limited, past the budget, or the lock not had within 2 seconds). Each is
  charged to the pre-frame part its length, its newline and its append's leading newline, and
  only a line that reads strictly with exactly those `op`, `via`, empty `scope`, `charge` and
  `source` is counted (`keystore.ServerLogs`).
- **What it claims.** The log is append-only against truncation and deletion by the service
  user, except that bytes it appends to the old log after a maintenance verb's one read of it
  are dropped (residual 12); the old log is unflagged only once the swap has made it
  unreachable by path and it is no longer an input, and the archives are root 0600 ("The
  swap"). A service-user process outside Seatbelt can append forged lines, because it shares the
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
  shows, "user scope needs the installed server" (U113). The next check refuses a service uid
  at 501 or above: the service user is a system account, and one in the login range would make
  a login user indistinguishable from it and its refusal lines login lines; the off reason is
  "the service uid is in the login range", which `doctor` shows. The socket's eligible range
  (`socket.MinPeerUID`, `socket.MaxPeerUID`) is the store's (`keystore.MinLoginUID`,
  `keystore.MaxLoginUID`), one copy of 501 and 2147483647.
- The server never creates, unlinks or replaces `keys.sock`; launchd owns the name. In the
  deny-plus-pin fallback only, it unlinks a stale `keys.sock` at start only after an `lstat`
  shows a socket owned by the service user; anything else at that path is refused with a Warn.
- Each request waits for the store `.lock` at most 2 seconds; a timeout fails that request
  (`ErrBusy`), not the server.
- The start check also refuses a data root on a file system mounted with
  `MNT_IGNORE_OWNERSHIP` (read with `fstatfs` on the data-root descriptor, `f_flags`), since
  every owner check in this design means nothing there (U131). The data root is opened afresh
  (`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`) at every start-check pass, never kept from an earlier
  one, and closed when the pass ends, so a volume mounted over the path since is judged as it
  is now. The install check and the log reopen open their objects by path; in the same pass the
  socket directory, `keystore-logs/` and each log's directory are opened again through that
  descriptor, one component at a time with `O_NOFOLLOW`, and the reopened logs' descriptors are
  compared too: any on another device than the freshly opened data root (a volume mounted over
  one of them) fails the pass closed, as the install reason or `logs-unavailable`.
- While the maintenance marker `keystore-maintenance` exists in the data root the listener
  stays down: it accepts nothing, and a client that connects meanwhile waits in launchd's
  backlog until its 10-second `HELLO` wait ends and it reports the server unavailable.
- **Upgrade visibility.** If the directory or either append-only file is absent, wrong or
  unflagged, the listener does not start: fail fast, no fallback. The server logs a Warn naming
  `sudo k3sm install` once at start and again on every listener retry; `k3sm doctor` shows
  "keystore user scope: off (<reason>); run `sudo k3sm install`"; and the CLI's connect error
  names `sudo k3sm install` (U31, U38, E15).
- **Supervision details.** The start checks run at start and before every retry, in this order:
  the effective uid, the data root's mount flags, the installed files, the maintenance marker
  (read only), the store directory, the reopen of both append-only logs (its own step: a reopen
  that fails keeps the listener off as `logs-unavailable`, with the error), the peer-sandbox
  self-check, and a server count of exactly one (a count that cannot be read, or of none, keeps
  the listener off too).
- **The server creates the store directory at start.** The log reopen takes the store lock,
  whose `.lock` is in `server/keystore/`, so the store-directory step runs before it. When
  `server/keystore/` is missing, the server, which runs as the service user and owns `server/`,
  creates it with the store's own helper, the one a first `keys put` uses (`mkdirOwned`: the
  service user's, 0700, any inherited ACL removed, `server/` fsynced). A directory that exists
  is judged as every open of the store judges it (a directory, the service user's, granting
  nothing to group or others), and as carrying no extended ACL, read on the opened directory's
  descriptor with the check `pre-restore.d` gets (`judgeDirACL`), and one that fails is never repaired: the listener stays off as
  `the store directory is missing or refused`, with the open's refusal and its repair (as root,
  make it the service user's at 0700 with no extended ACL, or remove it if it holds nothing), on
  every pass. So a
  fresh install's user scope comes up without a root `keys put`. Only the installed server
  creates it: the step runs after the effective-uid check, and a worker builds no listener. A
  root `put` racing the step is safe: whichever `mkdir` lands first makes the directory and the
  other only judges it; the server's `mkdir` makes a directory the service user already owns,
  which the put's judgement accepts, and a put's `mkdir` makes one root owns until its
  handover, which the server refuses for that pass only, finding it handed over on the next.
  The race's one-pass errors (the directory cannot be opened, as a root-owned one before its
  handover cannot; or a directory the server has just made already holds a name a racing put
  wrote, `ErrCorrupt` "is not empty") name no repair: they say `a root keys put may be creating
  it; retried` (`keystore.StoreDirRace`). Only a refusal of an existing directory on what it is
  (not a directory, its owner, its mode, an extended ACL: `keystore.StoreDirRefused`) names the
  repair (`TestStoreDirRaceTextIsTransient`, `TestEnsureDirClassifiesRefusals`,
  `TestEnsureDirRefusesExtendedACL`).
  Doctor runs the same judgement read-only: before the server's first start it shows the
  user scope off for the store directory, saying the server creates it at start.
  Nothing is opened on the data root before its mount flags and the installed files are
  vetted, so an install that predates the logs is reported as the install reason, naming
  `sudo k3sm install`. A failed check retries on a doubling backoff from 1 second to 5 minutes,
  which starts again from 1 second whenever every check passes, except the marker, which is
  polled every 2 seconds, both while it stands and while the listener serves, and a failed log
  reopen, which is retried every 2 seconds 15 times in a row before it falls to the backoff, so
  the listener is back within a poll of a maintenance verb's end; a marker that appears, or that
  cannot be read, stops the listener and cuts its connections. While it serves, the listener also
  counts the servers every 30 seconds, each count bounded by its own 10-second timeout and run
  beside the marker poll, never in its way; more than one server, or three failed counts in a
  row, stops it with that reason and cuts its connections. A rootless server's reason is logged
  once, at Info, and not again while it stands; every other reason is a Warn on every retry. A
  listener that cannot be built (the service user not found, say) is retried on the same
  backoff. A panic out of the supervisor itself, or out of building it, is recovered in the
  goroutine that runs it and never ends the process: it is logged, 1 second (the minimum
  backoff) passes, and the supervisor runs again. The server's shutdown waits at most 10 seconds
  for the listener, then logs and goes on; the listener's descriptors are closed only once it
  has stopped. Doctor's log step judges what this reopen judges, read-only: it opens both logs
  read-only through the data root, applies the same flag, owner, mode and link checks and the
  same recount of the audit log with its reader bound, and takes no lock and writes nothing, so
  a log the server's reopen refuses shows the same `logs-unavailable` detail in doctor.
  Between runs the activated descriptor stays open and bound: accept is stopped by expiring
  the descriptor's deadline, not by closing it. A run that served for a minute before failing
  starts the backoff again from 1 second. A panic serving one connection is recovered and ends
  that connection only. A lock taken after the 2-second wait is released at once, and `busy`
  fails the request, never the connection. A lock call that ignores its deadline holds a
  goroutine until it returns; at most 16 store-lock calls are outstanding at once, waiting or
  abandoned (`MaxLockWaits`): each request reserves its slot before it calls the lock, so
  requests arriving together cannot all pass the bound, and past it a request is `busy` at once
  and starts no wait; a slot is given back when its lock call returns.

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
process is refused by a check that does not rest on its uid (Open requirement 15, U137). A peer
whose credentials or sandbox state cannot be read is refused as well, its `refused` line naming
uid 4294967295 when no uid was read. The uid range is judged as soon as `LOCAL_PEERCRED`
answers, before the pid and the token are read, so an ineligible peer that closes right after
connecting is still refused and audited under its own uid; an eligible uid whose pid or token
read then fails is refused as `cred-unreadable` under that uid. The audit token must name the
same process: its euid (`audit_token_to_euid`) must equal the `LOCAL_PEERCRED` uid and its pid
(`audit_token_to_pid`) the `LOCAL_PEERPID` pid, or the peer is refused as `token-mismatch`.
`sandbox_check_by_audit_token` is private and is not linked: it is resolved with
`dlsym(RTLD_DEFAULT)` at first use, so a macOS that drops it still launches the binary and every
peer is refused as `sandbox-unknown`. At start the server asks the check about its own audit
token (`task_info(TASK_AUDIT_TOKEN)`) and requires 0; any other answer or an error keeps the
user scope off (`sandbox-check-unusable`). That control cannot show that a sandboxed peer still
reads as 1; the rig leg shows that, on each supported macOS.

*Measured on macOS 27.2.1 (26B131), without root, 2026-11-23* (`-tags integration`,
`TestIntegrationDeadPeerRefused`, `TestIntegrationSandboxedPeerRefused`). A peer that connects,
writes a HELLO and exits before the accept: on the accepted descriptor `LOCAL_PEERCRED` still
answers (xucred version 0, the peer's uid 501), while `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` each
fail with `ENOTCONN`, so no token reaches the sandbox check and the listener refuses the peer as
`cred-unreadable` under uid 501; its buffered bytes are never read. A child that sandboxes itself
with `sandbox-exec -p '(version 1)(allow default)'` and stays connected reads as sandboxed (1)
through the real sandbox source, and the listener refuses it as `sandboxed`. Still owed on the
rig: a real Pod's connection, and the other supported macOS version.

**What each layer is.** A Pod is kept from the socket by three layers, in this order. The
Seatbelt deny on `keys.sock` (Pod denies, layer 1) is the first barrier: a Pod's `connect(2)`
fails before the listener sees it. The uid refusal is the second: every native Pod runs as the
service uid, which the listener refuses at accept. The sandboxed-peer refusal is a backstop
behind both: it decides the outcome only for a sandboxed process at a login uid, which neither
of the others refuses, and that a sandboxed peer reads as sandboxed is measured on one macOS
build. The start-time self-check proves only that the check is reachable and reads the
unsandboxed server as 0; it does not prove that a sandboxed peer reads as 1. Refused before any
frame is read: uid 0 (root uses the direct-file verbs, as in Phase A), the service uid (every
native Pod shares it), every uid below 501 (system accounts) (U26, E6), and every uid at
2^31 (2147483648) or above, `nobody` (4294967294) among them, which is no login user and
which a signed 32-bit reading of the uid would turn negative (U82). The store mints no scope
for a uid outside that range either. The entry grammar still parses a uid as a uint32, so
such a name is well formed and simply has no scope.

**The client's checks are advisory.** The CLI opens the socket through an `os.Root` on the
data root, checks by realpath that `keystore-sock/` is root's, mode 0755, under the root-owned
data root, and that `keys.sock` is a socket, then judges the peer of the connected descriptor
by the client check (Open requirement 4): `LOCAL_PEERCRED` reads uid 0, since under activation
it names launchd, the socket's creator (K7a amendment 2026-11-23); the audit token
(`LOCAL_PEERTOKEN`) names a process whose euid is the service uid; and that process's code has
the installed binary's cdhash (below). **The connected descriptor is the authority in both
directions**: a value is never written to a socket whose peer fails any of the three, whatever
the path checks said (U36). The uid 0 is accepted only beside the token's euid and the cdhash,
never alone: a peer whose token names root, launchd or any other uid is refused.

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
  the socket, and the server only accepts on the descriptor it was given. K7a measured
  (amendment 2026-11-23) that the client-side `LOCAL_PEERTOKEN` names the accepting server, its
  pid and euid, while `LOCAL_PEERCRED` names launchd (uid 0). U69 holds either way: a listener
  inherited or passed to another process must not let that process pass the pin, and the
  server marks the activated descriptor `FD_CLOEXEC` as it takes it and passes it to no one
  (Open requirement 3, U120). The uid 0 of `LOCAL_PEERCRED` is accepted only with the token's
  euid and cdhash (Open requirement 4).
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
- *Precondition P-uid250 (the same-uid residual).* For the same reason the data root has
  no uid barrier against a Pod: a native Pod runs as uid 250, the service user that owns
  both logs, every scope directory and every entry, so the file modes that stop other users
  do not stop it, and the Seatbelt denies of runtimed's sandbox change are the only barrier
  between a Pod and the data root ("Pod identity refusal", item 1: "That a Pod with these
  denies cannot `connect(2)` to the socket or read any of these paths is `[K0 leg 4:
  pending]` (the K5 rig leg)"). This design names that as a precondition, not a property it
  delivers: the user scope's logs, floor and shares assume it, and it is discharged only by
  the sandbox lane's test, rig leg E10 (a native Pod gets EPERM on `keys.sock`, `server/keystore`,
  `keystore-sock/`, both logs and every `keystore-*` file, through every path) with U16.
  Until E10 passes, the user scope does not ship.

**Protocol `k3sm-keys/1`.** Internal, not a public API; the public interface is the `k3sm
keys` CLI, which other programs call as a subprocess with the value on stdin. The CLI's human
output is not stable and may change in any release; `-o json` and the exit codes are the stable
surface, and the app consumes only those.

- A frame is a 4-byte big-endian length (at most 128 KiB), a 1-byte type, a length-prefixed
  JSON header (at most 8 KiB, never a value) and an optional length-prefixed binary value. Each
  prefix is 4 bytes, big-endian. Each sub-length must be at most the frame length, checked
  before anything is allocated; a frame that breaks this closes the connection.
- **The reply header cap.** A reply's header alone may pass 8 KiB, up to `MaxReplyHeader`
  (128,818 bytes): the list of a full scope, 256 rows each at its widest (a 269-byte API name,
  a 7-byte kind, a 20-digit version, a 20-character versions count, a 29-byte RFC 3339 time, a
  64-hex-digit fingerprint, a 7-byte status, the field names and punctuation, and the comma
  that separates it from the next: 503 bytes), plus
  the wrapper and the `committed; audit failed` warning. So one list call names every entry
  of a full scope, and no cursor is needed. The cap is computed from those widths and a
  compile check holds it inside the 128 KiB frame cap with the type and header prefix; a test
  marshals the worst-case list and holds it under the cap. Only the client's reader
  (`ReadReply`) takes a reply header past 8 KiB; the server's reader holds every frame,
  a reply included, to 8 KiB. A reply the server cannot encode (a header that does not
  marshal, or one past its cap) is answered with an error frame, code `internal`, and the
  connection stays open: the request's audit line and share charge are already spent, and
  the client gets an answer rather than a dropped connection.
- **Frame layout, exactly.** The frame length counts the type byte, both prefixes, the header
  and the value, never its own 4 bytes, and must equal them exactly: the value is present iff
  bytes remain after the header, and then its prefix must account for every one of them (a
  present value may be empty). Frame types: `0x01` HELLO, `0x02` request, `0x03` reply,
  `0x04` error; any other byte is an unknown type. The client sends HELLO first and requests
  after it; any other type from the client, a second HELLO included, closes the connection. A
  request header names its operation in `op` (missing, empty, null or not a string closes); an
  error header is `{"code":"<code>"}`. A HELLO or request header that is not a JSON object, or a
  HELLO whose `proto` is not `k3sm-keys`, closes the connection. The dispatcher reads `op`, and
  the HELLO its `proto`, `min` and `max`, by their exact names, as the operations read their
  fields ("Strict enough"), never through a case-insensitive, last-key-wins decode: such a field
  spelled in another case (`{"OP":"rm"}`, `{"Proto":…}`), given twice in any case
  (`{"op":"list","Op":"rm"}`) or of the wrong JSON type closes the connection
  (`TestDispatchOpExactKey`, `TestHelloProtoExactKey`, `FuzzRequestHeader`, whose oracle
  tokenizes each header with `encoding/json`'s Decoder, so a key given twice that a reader
  accepted is seen rather than folded by a last-key-wins decode, and holds the HELLO reader to
  the same strict rule). The names live in one place,
  `pkg/keystore/socket` (U27).
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
- **Store errors on the wire.** Each error the store returns to a socket operation maps to
  one code of the set; the set does not grow for them. The table lives in one place,
  `pkg/keystore/socket` (`outcomeOf`), checked in this order:

  | Store error | Reply |
  |---|---|
  | none; or a change that committed (`ErrCommitted`) with a later step failed | `ok` |
  | a change that committed whose audit line failed (`keystore.AuditLost`) | `ok` with the warning `committed; audit failed` |
  | the store lock not taken within the 2-second wait (`keystore.LockBusy`, the socket's `ErrBusy`) | `busy` |
  | the uid's rate limit | `rate-limited` |
  | `ErrLogFull`: the uid's own share or revocation budget (`keystore.LogShareRefused`), or the log past its hard cap; and the socket's fail-closed refusal while the global append failure's cause is the hard cap (`socket.ErrAuditFailingFull`, from `keystore.FileStore.AuditFailingFull`) | `log-full` |
  | the start step not run (`keystore.UserScopeOff`) | `user-scope-off` |
  | `ErrNotFound`, `ErrVersionNotFound`, `ErrScopeAbsent` | `not-found` |
  | `ErrQuota` | `quota` |
  | `ErrScopeOwnerChanged`, `ErrScopeOwnerUnknown` | the code of the same name |
  | a request the socket refuses before the store (`socket.ErrRequestRefused`, below); the socket's fail-closed refusal while the global append failure has any cause but the hard cap (`socket.ErrAuditFailing`); an operation refused because its audit line could not be written, the global append failure (`keystore.AuditRefused`); `ErrExists`; `ErrInvalidName`; `ErrKindMismatch`; a value its kind does not take, an Ed25519 key of the wrong length or with a foreign public half (`keystore.InvalidValue`); `ErrTypedCredential`; `ErrRewrapInProgress`; a uid the store gives no user scope (`keystore.IneligibleUID`, with an `ineligible-uid` refused line); a sealed version above the entry's pointer (`ErrOrphanVersion`, which also matches `ErrCorrupt`); the floor's damage or the scope's quarantine (`keystore.FloorDegraded`) | `refused` |
  | anything else: `ErrCorrupt`, `ErrMasterMissing`, `ErrMasterUntrusted`, `ErrKindUnsupported`, a cancelled request | `internal` |

  `ErrCorrupt` is judged before the `refused` row: damage read back from the store answers
  `internal` whatever else its chain matches, so a stored Ed25519 version that authenticates
  and fails its check, which also matches `keystore.InvalidValue`, is `internal`; only
  `ErrOrphanVersion` among the errors that match `ErrCorrupt` is `refused`
  (`TestReadSideDamageAnswersInternal`, `TestStoredEd25519FailingCheckIsCorrupt`).

  `refused` is a request the store will not carry out as it stands, which the client can
  change (another name, rotate rather than put, root finishing a rewrap or acknowledging the
  floor's damage, or appends that succeed again); `internal` is damage or a missing key only
  root can repair, so the client says to run `doctor`. A user rotate that finds a sealed
  version at `v<cur+1>`, the one above the pointer, which is the only one it examines (a rotation that crashed before its flip, or an older pointer
  copied back inside the floor's lag window) is `refused`, not `internal`: the scope's owner
  cannot adopt it (`adopt` is root's, for the system scope) and cannot reach the file, but
  can repair the entry itself, with `rm` and then `put` of the value. The store never
  discards an orphan that authenticates (it may be the newer committed version), so the
  refusal stands until the owner does that; the error the server logs names the entry and
  that remedy. `ErrScopeAbsent` is `not-found` on the
  socket: the peer's own scope holds nothing it can read, and nothing on the socket path
  deletes on that answer, so it is never taken as a definitive absence. `list` alone answers
  an empty list rather than `not-found`, and only for a uid with no scope key yet (no scope
  directory, or one with no `scope.key` and no entry in its `entries/`, which is what a mint
  that crashed before its `scope.key` leaves: `keystore.NoScopeKey`). A scope directory whose
  `entries/` holds a name and which has no `scope.key` lost its key: a mint over it would
  orphan those entries and is refused, so every read (`read-for-exec`, `list`, `rotate`, `rm`)
  answers it `not-found` as an incomplete scope (`keystore.ScopeIncomplete`), never an empty
  list, and logs it (`TestNotFoundDamageLogged`, `TestCrashedMintIsNoScopeKey`); a scope whose `scope.key`
  is there but whose `entries/` directory or `deliveries` record is gone is damage, and its
  `list` answers that error's own code, `not-found` (`ErrScopeAbsent`), never an empty list
  (`TestListDamagedScopeIsNotEmpty`).
  A `log-full` from the
  uid's own share is never the global append failure: that one is answered alike for every
  uid, `log-full` when its cause is the audit log past its hard cap and `refused` for any
  other cause (a full disk, an I/O error).
  *The server's log.* The reply carries only the code, so the request boundary
  (`Handler.serveRequest`) logs each store error that is damage at Warn, to the supervisor's
  logger (`SupervisorConfig.Log`, which `NewSupervisor` gives the handler, so the lines reach
  the server's log; the handler is then that supervisor's alone, set before anything serves,
  and a second supervisor is refused it; `TestSupervisorLogReceivesDamage`): the op, the peer's
  uid, `requested_entry` when the request header names a valid entry (by its exact name, in
  the API grammar), a class from a closed set and that class's fixed remedy. The classes are
  `orphan-version` (answered `refused`; the owner can `rm` the entry and `put` it again),
  `floor-records-entry`, `floor-degraded` (the floor's damage or the scope's quarantine,
  answered `refused`), `corrupt`, `unsupported-kind` (`ErrKindUnsupported`, a record of a kind
  or envelope version this build cannot read: its remedy names the upgrade first, then a
  restore or `rm` and `put` when this k3sm is current, never `doctor`; judged before `corrupt`,
  so an unsupported envelope version a typed decode wraps in `ErrCorrupt` never gets the
  corrupt class's `rm` and `put`), `scope-incomplete`
  (an `ErrScopeAbsent` that is damage, `keystore.ScopeIncomplete`: a `scope.key` with no
  `entries/` directory or `deliveries` record beside it, or entries with no `scope.key`, as a
  partial restore leaves; still answered `not-found`, and never a uid with no scope yet,
  `keystore.NoScopeKey`; `doctor` has no check of a scope's shape, so its remedy is the
  recovery the design gives instead: restore the whole scope from one backup, or `sudo k3sm
  keys rm-scope user/<uid> --yes` and then `floor --rebuild`, after which the owner puts its
  values again, as for a scope whose key was lost to a Rewrap, above), and `internal` for any other error answered `internal` (a missing
  or untrusted master). The store's interrupted put (`errInterruptedPut`, a `not-found`) is
  not damage, a put that never committed which the next put discards ("Settled by the
  implementation"), and it is the system scope's: no socket operation meets it. A user entry
  directory with no `current`, whatever its shape, is `ErrCorrupt`, answered `internal` and
  logged `corrupt` (`TestNotFoundDamageLogged`, `TestScopeIncompleteIsNotNoScopeKey`). The class is judged inside the reply this table gives, in its
  order, so the log and the reply never disagree on a chain that matches more than one row:
  the floor's damage with `ErrCorrupt` answers `internal` and logs `corrupt`, and damage
  behind a row that is not damage (`busy`, `not-found`) logs nothing. That agreement holds by
  construction: `damageClass` calls `outcomeOf` first and picks a class only among those its
  code can carry. What `TestDamageClassAgreesWithOutcome` pins is each error kind's reply and
  class: every sentinel of the table, every predicate `outcomeOf` branches on, each made by
  the real store where it is unexported (`LockBusy`, `UserScopeOff`, `AuditRefused`,
  `AuditLost`, `InvalidValue`, `IneligibleUID`, `FloorDegraded`, `ScopeIncomplete`), and the
  chains read-side damage takes; and, over every pair of those joined in one chain, that the
  class is one logged beside the reply and that an internal reply is never left unlogged. The error's own text is never logged: a chain can carry text a
  decoder built from a decrypted value. That is the control on the reply path: an operation's
  error reaches the client only as its code (`answer`), a reply the server cannot encode
  (`marshalFrame`'s error) is dropped and answered `internal`, the listener discards the error
  `Serve` returns, and the damage line carries the class and remedy, never the text. The
  error texts themselves are kept free of a value's numbers as a second line, not the control.
  `TestNoErrorCarriesValueDerivedNumbers` is a tripwire for the common shapes only: a `len`,
  an index or a `tag` written inside an error constructor in `pkg/keystore` must be on a
  reviewed list keyed by file and function; it cannot see a number that reaches an error
  through a variable. The sites found that way are fixed and each has its own test: a quota
  refusal names the cap and not the total that counts the value, a refused refresh-owner
  change names neither owner, and no frame error, read or written, names a number that counts
  a value (no frame length, no value length, no count of bytes after a header; only a cap or a
  header length) (`TestValueNumbersNotInErrorTexts`, `TestFrameValueLengthErrorNamesNoLength`,
  `TestFrameErrorsNameNoValueLength`). The ordinary outcomes
  (`not-found`, `exists`, `quota`, `rate-limited`, `busy`, `log-full`, and the socket's own
  refusals), a change that committed, and a cancelled or timed-out request are not logged.
  Standing damage cannot flood the log: each (uid, op, class) key logs at most one line every
  10 seconds (`socket.DamageLogInterval`), and its next line carries the count it suppressed
  meanwhile as `suppressed`. The key carries the uid, so one login user's standing damage
  never suppresses another uid's line (`TestStoreErrorLogPerUID`). One uid's keys are bounded
  by the closed sets of ops and classes, and the table holds at most 1024 keys across uids: a
  new key past that evicts the key whose last line is the oldest. `suppressed` counts the
  whole key's suppressed lines, those of every entry its requests named, not only the
  `requested_entry` the line names. An evicted key's next line passes at once and carries no
  `suppressed` figure: the count it held moves to `evicted`, which the next line to pass, of
  any key, reports once (`TestStoreErrorLogged`, `TestStoreErrorLogBounded`,
  `TestDamageLimiterBounded`, `TestDamageLimiterReportsEvicted`).
- **Operations on the wire.** The request and reply headers are named Go types in
  `pkg/keystore/socket` (`PutRequest`, `RotateRequest`, `ListRequest`, `RmRequest`,
  `ReadForExecRequest`; `VersionReply`, `ListReply` with `ListEntry`, `RmReply`,
  `ReadForExecReply`), and these are their definitions. Every request header carries `op`.

  | `op` | request header | request value | reply header | reply value |
  |---|---|---|---|---|
  | `put` | `entry`, `kind` (optional; `opaque`, the only kind the socket stores) | the value, required | `version`, `fingerprint` | none |
  | `rotate` | `entry`, and `from_version` (optional) | the value when `from_version` is absent; none when it is present | `version`, `fingerprint` | none |
  | `list` | nothing more | none | `entries`: each `name`, `kind`, `version`, `versions`, `created` (RFC 3339, UTC), `fingerprint`, `status` | none |
  | `rm` | `entry` | none | `{}` | none |
  | `read-for-exec` | `entry` | none | `version` | the entry's current value |
  | `deliver`, `withdraw`, `deliveries` | (the delivery slice defines them) | | answered `refused` until that slice serves them, never `unknown-op`, with a post-frame `refused` line, `not-served` | |

  - *Names.* `entry` is the API form only, `user/<uid>/<name>` ("Scope strings and names":
    no bare name, and the short name is CLI input, resolved before it reaches the API). The
    socket hands it to the store unparsed; the store's entry parser judges it, so a bare name,
    a short name or any malformed name is `ErrInvalidName`, `refused`, and another uid's or a
    `system/` name is `not-found` as below. `list` names each entry in the same form, built
    from the grammar package's own `Entry.String`. A list field that means what a field of
    `k3sm keys list -o json` means carries that field's name; `status` is `ok`, `corrupt` or
    `error`, and the error text stays in the server. No reply carries a value's length.
  - *Fingerprints.* `put` and `rotate` return the fingerprint the store computed as it sealed
    the value, never by reading it back; it is per scope (U9).
  - *Strict enough.* Unknown fields are ignored and a field set to `null` is absent. Field
    names match exactly, never case-folded: every header, HELLO and request alike, is read
    under the keystore's one strict-object rule (`keystore/internal/strictjson.Object`, the
    audit log's reader's rule too), so any key given twice in any case, unknown keys included,
    or a request field (`op`, `entry`, `kind`, `from_version`) spelled in another case closes
    the connection at the dispatcher, whichever op the request names (`TestDispatchOpExactKey`). A known field of the wrong JSON type (a string
    where a number is expected, a negative or fractional `from_version`) is `refused`, and so
    is a header over the 8 KiB cap, judged before it is parsed. A value that is missing or
    empty where one is required, over the store's 64 KiB value cap, or present on an
    operation that takes none (`list`, `rm`, `read-for-exec`, and `rotate` with
    `from_version`), and a `rotate` with both a value or neither, are `refused` before the
    store is reached, so they write no store line, only the socket's post-frame `refused`
    line ("The audit log", refused lines); they are never `internal`. A value is
    zeroed once its reply is written, whatever the outcome.
  - *A uid with no scope.* `list` for a peer whose scope does not exist yet answers an empty
    `entries` list, not `not-found` ("A read never mints a scope"). The store has already
    written its `list` line, with the result `scope-absent`, charged to the peer; nothing was
    read and nothing is minted.
  - *Another uid's name, a `system/` name.* `read-for-exec`, `rotate` (either form) and `rm`
    of such a name answer exactly the bytes an absent entry of the peer's own answers, the
    error frame `{"code":"not-found"}`; the store refuses it before it opens any scope, and
    its line is the operation's own, with the result `not-found`, the peer as `caller` and
    the peer's scope, never the other uid's (U45). `list` names no entry: a name in its header
    is an unknown field. The answers are byte-identical only in the peer's normal state (a
    started scope, under its rate limit and share, the store lock had, the scope not
    quarantined). Outside it an absent entry of the peer's own answers from the peer's own
    state, a spent share `log-full`, a lock held past its wait `busy`, a quarantine `refused`;
    so another uid's or a `system/` name need not answer as the peer's own absent entry then.
    With the share spent it still answers `not-found` (`TestCrossUserRefusedShareSpent`). What
    differs tells the peer about its own state only, never about the other scope.
- CLI and server are one binary, so version skew exists only between an upgrade's install
  and the server's restart; the server pin refuses that window first ("The client pins the
  server"), and the CLI prints "the server is not running the installed build; restart it" and
  exits 1.

**Bounds.** 64 concurrent connections in all, at most 2 per uid among them; 10 seconds per request;
an idle timeout of 30 seconds after `HELLO` and between requests, so a connection that sends no
next request frame within 30 seconds is closed and frees its slot (a request's 10 seconds run from
its first byte to the end of its reply's write, and the idle wait from the start of the reply
before it; a connection past either connection cap is closed at accept with nothing written and
no `refused` line);
5 mutating operations a second per uid; `list` and `deliveries` rate-limited per uid like
mutations, at 5 a second; `read-for-exec` at most 30 a minute per uid, each audited as
`exec-read` (U28, U34, U51). As built (`socket.MutationsPerSecond`, `ListsPerSecond`,
`ExecReadsPerMinute`): each is a sliding window per uid on the server's clock; the 5
mutations count `put`, `rotate` (either form), `rm`, `deliver` and `withdraw` together; the
5 a second of `list` and `deliveries` count the two together; the delivery placeholders
take their operation's limit before they answer `refused`. A request is judged in this
order: its header and value, then its uid's rate limit, then the fail-closed rule, then the
store; a request past its limit is `rate-limited` and the store is not called, and one
refused by the fail-closed rule has used its place in the limit. Reads are limited too because each one writes an audit line; that
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
   the archives `keystore-audit.log.1` to `.4` (in `keystore-logs/audit/archives/`), the floor lock `keystore-lock`, the removal
   record `keystore-removed-scopes.json` (Open requirement 13), the maintenance marker
   `keystore-maintenance` and the staging directory `keystore-staging/`), the logs'
   directory `keystore-logs/`, and the whole `keystore-sock/`
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
with no record left to find them by. `sudo k3sm keys rm-scope user/<uid> --yes` holds the floor
lock `keystore-lock` (Open requirement 2) and, taken after it, the store lock exclusively, for its whole run,
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

*What the append-only files build of it.* `rm-scope` lands with the append-only files without
steps 0 to 2: it reads the `deliveries` record as step 1 does and refuses, changing nothing, a
scope whose record names any delivery, so no delivered Secret is left without a record to find
it by; a scope whose record names none it removes (step 3). The binding listing,
`--keep-bindings`, `--remove-bindings`, the Secret deletes, `keystore-removed-scopes.json` and
`--orphan-secrets` land with the KeyDelivery reconciler (lifecycle), which owns their rows:
U75, U77, U95, U103, U106, U114, U115, U123, U125 and U130.

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
`doctor` reports "keystore user scope: off (more than one server registered)", naming the
servers, and KeyDeliveries get `UserScopeOff` (U30). The check is not only at start: a serving
listener counts the servers every 30 seconds, and the single-server check the reconciler runs
before every sweep gates the KeyDeliveries, so when a second server registers at runtime the
listener stops, closing its connections, and each KeyDelivery gets
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
the user scope stays off: a missing or wrong directory or log Warns at start and on every
retry; a server plist without the `Sockets` entry, which launchd fixed at the job's bootstrap,
is the terminal "launchd activated no socket for this server", Warned once and never retried;
`doctor` names `sudo k3sm install` for both, and "mount the data root, then `sudo k3sm
restart`" when the plist has the entry but the socket's parent was missing at the server's start, and the CLI's error names the command; the
system scope works.

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
| the service user (the server, runtimed, kine, the control plane, and any of its processes outside Seatbelt) | read `M` and every `K_u`, hence every value; append to the floor log and the audit log, including forged audit lines | lower the user floor, truncate or delete audit lines (outside residual 12: bytes appended late in a maintenance verb through a descriptor held on the old log are dropped), write the system floor |
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
   above the hard cap: a 720 KiB socket margin for its own revocations and a 256 KiB reconciler
   allowance for the reconciler's. It cannot fill a log for other users, and its log lines
   cannot get another uid's mutations, reads or revocations refused, since those draw on that
   uid's own share and budgets. It can delay them through the shared store lock, by the
   exclusive holds its rate limits allow ("Lock modes and fairness"), and enough uids together can make another
   uid's operation `busy` (a revocation retries 3 times first). The isolation is of log
   shares, not of the disk: when the file system itself refuses an append (a full disk), every
   uid's mutations and reads are refused alike, and only revocations go ahead, unaudited and
   counted. It cannot refuse the reconciler's revocations of its own Secrets either, since its
   socket revocations never draw on the reconciler allowance. What it can exhaust is its own
   socket margin, by rotating past its share; that refuses only its own further socket
   revocations, until root rotates the log. Each scope can push a log past the hard cap by at
   most 976 KiB (its 720 KiB socket margin and 256 KiB reconciler allowance), and the
   reconciler budget by 1 MiB more, so the overshoot is bounded by the
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
12. During `audit --rotate` and `floor --rebuild`, lines appended to the old log after the
    verb's one read of it (step 2, bounded by its size at open) are dropped with the retired
    log. Every legitimate writer holds the store lock the verb holds, so only a hostile process
    can write then. What a descriptor the service user held from before does to the retired log
    once its flag is cleared (step 6) never reaches the new log, which was flagged before it was
    reachable, and the retired log is never read again ("The swap").
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
20. **The service user is trusted for availability.** A process running as the service uid
    can append to the user-scope floor, so it can block every `withdraw` with one malformed
    line (a floor that does not parse refuses a re-sealing revocation until root's
    `floor --rebuild`), spend a victim uid's revocation budget past the hard cap with lines
    naming that uid's scope, and bury any entry with a tombstone, so the entry reads as
    deleted. None of this reaches a value, and nothing narrower is promised: the service user
    holds `M`, so it could delete the records outright. Per-uid shares, which keep one uid's
    lines from spending another's budget for writers other than the server, arrive with the
    socket (U51). A `withdraw` of an already withdrawn delivery appends no floor line once the
    floor holds the record's sequence ("Revocation always succeeds"), so repeating one costs
    no budget.
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
   service-user process can open it by path with `O_TRUNC` and truncate it. *Fix (as built,
   2026-11-23):* the flag refuses root's `fchown`, so the old log is not re-owned: it is
   retired. The whole log directory is swapped out with `RENAME_SWAP` into the root-only
   `keystore-staging/`, and only then is the old log's flag cleared and the retired set removed
   unread; `.1` is a fresh root-owned unflagged copy, and the older archives are carried by hard
   link, never unflagged ("The swap"). *Test:* U118, root-run: the old log's one attribute call
   is its flag clear, after the swap; U90, root-run: at every step the canonical log by path is a
   complete judged log, and nothing the service user's held descriptors do to the retired log
   reaches the new one.
2. **Any local user can hold the floor lock (K8, and merged Phase A code).** Phase A's floor
   writers take `flock(2)` on the data-root directory itself (`pkg/keystore/floor.go:368` to
   `:375`); the data root is root:wheel 0755, so any local user can open it, take the lock and
   hold it, and every root verb that writes the floor, the revocation and recovery verbs
   included, then fails with the lock timeout. *Fix:* the floor lock moves to a file
   `keystore-lock` in the data root, root-owned 0600, created by the first root verb through
   the data-root descriptor rules ("Root never acts by path where the service user can write"),
   which only root can open. Every root verb that writes the system floor or a keystore file in
   the data root takes it, before the store `.lock` (§ "Concurrency") and with the same bounded wait: `put`,
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
4. **Under activation the client sees launchd as the credential peer (K9a, measured in K7a).**
   K7a measured (amendment 2026-11-23), from a login user's process, that the client-side
   `LOCAL_PEERCRED` reads euid 0 gid 0 (launchd, which created the socket) for every client,
   while `LOCAL_PEERTOKEN` names the accepting server (euid the service uid, its pid) and the
   code lookup from the token resolves the server's code and cdhash. *Binding rule, the client
   check:* the client writes to the socket only when all three hold: `LOCAL_PEERCRED` uid 0,
   the audit token's euid equal to the service uid, and the token's code the installed
   binary's cdhash (U69). uid 0 is never accepted on its own, and a token naming root, launchd
   or any uid but the service uid is refused. *Test:* U121: a client whose peer reads as uid 0
   with a token naming launchd, root or another uid, or other code, refuses and writes
   nothing; one whose token names the service uid and the installed cdhash proceeds.
5. **A Pod might obtain the listener from launchd, or reach the socket by path (K9a, measured
   in K7a).** A process descended from the server's job can ask launchd for the job's sockets
   with `launch_activate_socket`, and Pods descend from it (`runtimed/pkg/runtime/podreap.go:40`).
   Two denies are in question, and they differ:
   (i) *No launchd activation-lookup deny is added, and launchd's answer is not relied on.* In
   K7a (amendment 2026-11-23) launchd answered `ESRCH` to a Pod process and to every other
   process but the job. That is measured on macOS 27.2.1 only; it is a bonus barrier, not a
   guarantee, and another macOS release may answer otherwise. The activated form ships because
   the barriers relied on do not depend on it: the Seatbelt deny of (ii) and the listener's
   sandboxed-peer refusal (Open requirement 15). No Pod profile carries a lookup deny. *Test:*
   rig leg E27 (a Pod's `launch_activate_socket` for the server's socket name gets no
   descriptor), which also owes the macOS 26 measurement; U122.
   (ii) *The Seatbelt path deny on `keystore-sock/` is required and stays.* It is the first
   barrier between a Pod and the socket: without it a native Pod connected to `keys.sock` (K0
   leg 4). Every Pod profile carries runtimed's keystore stanza
   (`runtimed/pkg/sandbox/keystore.go`, `keystoreDenyStanza`), which denies connect and bind on
   `keystore-sock/` and `keys.sock` (U16), and the provider's socket denies name `keys.sock`
   (U46, `k3sm/pkg/provider::TestRuntimedSocketDeniedToPods`). The server checks at start that
   the Pod profile its embedded runtime renders for its own posture carries this deny for the
   data root it serves, in every spelling, and keeps the user scope off if it does not (K7a
   amendment; `this build's Pod profile does not deny the keystore socket`). *Test:*
   `k3sm/cmd/k3sm::TestServerPodProfileDeniesKeystoreSocket`, which renders the profile with
   the linked runtimed for the default and for custom data roots, so a k3sm built against a
   runtimed without the deny fails it; `TestKeystorePodProfileMismatchTurnsScopeOff`.
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
16. **launchd keeps the socket listening while the server does not accept (K9a).** Under
    activation launchd holds `keys.sock` bound and listening whether the server is serving,
    paused by the maintenance marker, backing off, off or not running, so a client's connect
    succeeds into the backlog and then waits. *Fix:* the client (the non-root CLI) puts a
    deadline on the connect and on `HELLO`, and reports the server unavailable when either
    passes, rather than hang. *Test:* the non-root CLI's change names it.

### Facts from the rig spike

A script-only spike on the rig's server measured these before any code depends on them. A
spike never counts as proof. Its result is quoted here as a dated amendment, which also picks
the floor variant.

**K0 amendment, 2026-11-21.** The spike ran on the rig's server (macOS 27, APFS data volume,
`kern.securelevel` 0) from a recorded build, as root, and cleaned up after itself. Evidence:
the K0 spike's evidence of 2026-11-21 (`status.txt`, `leg1.txt` to `leg4-*.txt`,
`leg3b-unresolved-uid.txt`).

**K0 note, 2026-11-23.** K0 measured the service user's operations on a flagged file, not
root's. The order the maintenance verbs first used, flag the new log and then hand it to the
service user, was not measured before 2026-11-23; that day's probe (§ "SF_APPEND, as
measured") found root's `fchown` of a flagged file refused, and that day's second probe
measured the directory swap: the swap now hands the new log to its owner first and flags it
second, inside the root-only `keystore-staging/`, before it is reachable.

| leg | the fact | result | where it applies |
|---|---|---|---|
| 1 | `sappnd` on an APFS data volume as the service user: append works, the whole defeat list fails, owner `chmod` widens nothing; the securelevel, whether root can clear the flag, whether a rename over an `sappnd` target needs the clear first | **Measured.** Append works. All 12 defeat attempts fail with EPERM and leave the inode intact: truncate, ftruncate, open-truncate, `pwrite` at offset 0, `F_PUNCHHOLE`, `link`, `fclonefileat` then rename over, rename over, rename away, unlink, `chflags nosappnd`, and `chmod`. At securelevel 0 root can clear the flag. Root's rename over a flagged target fails with EPERM, so maintenance clears the old file's flag before the rename. **The flag variant is chosen**; the floor helper variant is not built. | "The user-scope floor" |
| 2 | `LOCAL_PEERCRED` both ways, a login uid over SSH; `LOCAL_PEERTOKEN` and the code lookup on the client side | **`LOCAL_PEERCRED` measured both ways**: the server saw root (euid 0) and the login user (euid 501), and each client saw the server as the service user (euid 250). **Pending:** `LOCAL_PEERTOKEN` and resolving the server's code and cdhash from it were not in the spike; K7a measures them before the client's server pin is built, and the pin's rows (U69, E24) stay pending until then. If either is unusable from a login user's process, the user scope does not ship ("The client pins the server"). | "The socket" |
| 3 | `mbr_uid_to_uuid` is stable across a server restart; its cold latency; what it returns for a uid with no record | **Measured.** The GeneratedUID equals `dscl`'s and is stable across processes. Cold first lookup about 1.4 ms, worst of 20 cold processes 2.8 ms, warm median 0.17 ms, so a 250 ms deadline has wide margin. A uid with no record returns the synthesized form `FFFFEEEE-DDDD-CCCC-BBBB-AAAA<uid hex>` with status 0, and so does root; the synthesized-prefix rule is required. | "Key hierarchy" |
| 4 | a Pod with the data-root denies cannot reach the socket or any `keystore-*` path; without them, what a Pod reaches today | **Without the denies, measured:** a native Pod on the server connected to `keys.sock` (two accepts), so the denies are a hard prerequisite of any keystore file or socket (K5 before K8). Phase A's two data-root files did not exist on the rig, so their readability today is unmeasured. **Pending:** the Pod with the denies is the K5 rig leg (E10). | "Pod denies", "Threat model" |
| 5 | which uid a native Pod's processes run as; whether a Pod spec field or runtimed path can make it 501 or above | **Measured for a default Pod:** uid 250 (the service user), below 501, and the socket saw peer euid 250. **Pending:** the spec-field and runtimed-path half (`runAsUser` and the other fields) is K5's row U15. Pods and the server share uid 250, which is why the client pins the server by more than its uid. | "Pod denies" (layer 2, row U15) |

**K7a amendment, 2026-11-23: socket activation ships.** Every fact below was measured on
macOS 27.2.1 only; rig leg E27 owes the same measurements on macOS 26, the oldest supported
release. The activation probe (`hack/acceptance/keystore-activation-probe`) ran on a worker lab
Mac as root, with a test job carrying `UserName` and a `Sockets` entry at mode 0666, and cleaned
up after itself; the missing-parent run used the same probe on 2026-11-24, as root, with its own
test job (evidence: `missing-parent-2026-11-24/RESULT.md` and `probe.log` in the keystore
evidence set, beside the probe's 2026-11-23 logs); the respawn run did too, on the worker lab
Mac, with the probe exec'd directly by launchd (evidence: `activation-respawn-2026-11-24/RESULT.md`
and `probe.log` in the same set). Measured on macOS 27.2.1:

- At bootstrap launchd records the socket but has not bound it at the path (`launchctl print`
  shows `needs_rename = 1`). It binds it, root:daemon 0666 in the root 0755 directory, when the
  job calls `launch_activate_socket`; the job (euid the service uid) gets one descriptor,
  `FD_CLOEXEC` already set, whose address reads launchd's bind name,
  `/var/run/com.apple.launchd.<random>/<entry>`, not the plist's path.
- On the server side each peer's `LOCAL_PEERCRED`, `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` agree.
- On the client side `LOCAL_PEERCRED` reads euid 0 gid 0 (launchd) for every client, while
  `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` name the accepting server, whose code and cdhash the
  lookup from the token resolves from a login user's process.
- No other process (a login user, the service user, a child of the job before and after it
  took the socket, with and without `setsid`, a Pod process) obtains the listener:
  `launch_activate_socket` returns `ESRCH`.
- A missing socket directory never fails the bootstrap and never stops the job. When one level
  is missing, launchd creates it root:wheel 0755 at the job's `launch_activate_socket` and
  hands over the socket; with three levels missing it answers `ENOENT` with no descriptor and
  creates nothing, and the job runs on. A real unmounted volume was not measured. `<launch.h>`
  words `ENOENT` as no socket of the specified name owned by the caller: launchd has no `keys`
  socket for this job, because its loaded definition has no such entry, or a parent of the
  socket path is missing at the activation call.
- A job whose plist has no `Sockets` key, running the probe itself, gets `ESRCH`, as does any
  process that is not the job: `ESRCH` names `sudo k3sm install`, measured.
- With `KeepAlive` true, a `SIGKILL` respawn and a `kickstart -k` each activate again: rc 0,
  one descriptor, the same socket inode. launchd holds the socket across the job's runs, so a
  restarted server gets the socket back (`sudo k3sm restart`).
- The activated descriptor's address is always launchd's bind name, never the `SockPathName`.
- `launchctl bootout` leaves `keys.sock` on disk, root:daemon 0666. Uninstall removes the whole
  `keystore-sock/` once the server's bootout succeeded; until then, and after a bootout that
  is not an uninstall, `doctor`'s lstat can find a socket of a job that is not loaded. Its pass
  text therefore states path facts only (a root-owned socket at the plist's mode is at the
  path), never that a server is listening.

On that evidence the activated form ships, not the deny-plus-pin fallback, and the client check
changes: the client accepts the `LOCAL_PEERCRED` uid 0 that activation produces only beside an
audit token whose euid is the service uid and whose code has the installed binary's cdhash.
U36, U121 and Open requirement 4 are reworded to that check. Open requirement 5 splits in two:
the launchd activation-lookup deny is not needed, since a Pod gets `ESRCH`; the Seatbelt path
deny on `keystore-sock/` stays required. Open requirement 16 is new.

Delivered with this amendment: the server plist's `Sockets` entry `keys` at
`<dataRoot>/keystore-sock/keys.sock`, mode 0666; install's `keystore-sock/`, root:wheel 0755
(set through its descriptor when install creates it, whatever the umask), removed by uninstall
only once the server's bootout succeeded; and the server's one activation per process, for one
work dir (a second work dir is refused). It calls `launch_activate_socket` outside
`syscall.ForkLock`, because holding that lock across a launchd call would block every new Go
socket in the server (net takes its read lock per socket on darwin, and a waiting `os/exec`
writer blocks new readers), and then confirms `FD_CLOEXEC` on every descriptor under the read
lock. The tradeoff: launchd sets the flag (measured on macOS 27.2.1); were it ever unset, a Go
fork in the window between the call and the confirm could inherit the descriptor, which the
confirm cannot take back, so the server closes what it holds and refuses to serve for the life
of the process, and the release gate requires E27's macOS 26 measurement of the flag. It
requires one listening `SOCK_STREAM` socket whose address has the shape of launchd's bind name
(a shape check only, since that is all an activated descriptor reports), and then judges the
path clients connect to, `keystorepaths.SocketPath(dataRoot)`, with `doctor`'s rule: a
root:daemon socket at the plist's mode in a root:wheel 0755 directory. It checks that only root
could have put a socket at the clients' path; the descriptor's own address is launchd's
private bind name, so the descriptor cannot be tied to the path. It serves a close-on-exec
duplicate, held until the process exits. A process-wide holder makes the one call, so it never
asks launchd twice; the result of a second call would be `<launch.h>`'s documented `EALREADY`,
which was not measured. Every other outcome is a terminal off state, logged once at Warn and
never retried: `ESRCH` "launchd activated no socket for this server", naming `sudo k3sm
install` (it rewrites the server plist and re-bootstraps the job); `ENOENT` "launchd has no
`keys` socket for this job: its loaded definition has no such entry, or a parent of the socket
path is missing (measured with three missing levels)", naming "run `sudo k3sm install` (it
rewrites and reloads the server's definition); if the data root is on a volume that is not
mounted, mount it first"; a wrong descriptor or path, naming `sudo k3sm install`, which
rewrites and reloads the definition so launchd binds the socket afresh; `EALREADY`, naming
`sudo k3sm restart`; and a descriptor without `FD_CLOEXEC`, which a restart does not change,
naming "report it: launchd handed the server an inheritable descriptor; the user scope stays
off". `doctor` judges the same path rule, and with no socket there names `sudo k3sm install`
in both cases: when the installed plist lacks the `Sockets` entry, and otherwise with the
`ENOENT` text, saying the state is also seen while the server has not started yet or is
restarting. Its pass text states path facts only: whether the server is serving the socket is
not checked.

**What is reachable meanwhile.** Until the non-root CLI ships with the client check (U36,
U121) and the connect and `HELLO` deadlines (Open requirement 16), the socket's only clients are
ones that speak the raw protocol themselves. In that window the barriers are the server's own
refusals: the eligible-uid floor and ceiling, the refusal of the service uid and of root, the
refusal of a sandboxed peer, and the per-uid rate limits, budgets and caps. Rig leg E27 must
pass on macOS 26 before any release that includes this change. Not measured here: the 50 ms
exclusive hold bound and GeneratedUID stability.

**Owed to K7a.** K7a is the measurement run before the changes that depend on it, recorded
as a dated amendment like K0's. It measures: `LOCAL_PEERTOKEN` and the code lookup from it on
the client side (leg 2's pending half); root's `fchown` of a file it has just flagged `sappnd`;
the 50 ms exclusive hold target ("The audit log", lock modes); whether the client-side
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
  always means "it expires", and a put or rotation refuses (`ErrInvalidCredential`) an
  `expiresAt` that is not after the `issuedAt` the store stamps, which would seal a token
  already expired. The two are compared as the envelope seals them, in whole seconds, so an
  expiry within the issue second is refused; an oauth `accessExpiresAt` is held to the same
  rule against `accessIssuedAt`. `typed.Encode` and `typed.Decode` both enforce the ordering
  (`ErrInvalidCredential` and `ErrCorrupt`), so a sealed envelope that breaks it never reads. `RotateFrom` re-stamps nothing and checks nothing against the clock (see
  "Rotation and rollback").
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
  refresh-owner grammar. Times are Unix seconds, int64 big-endian, from the Unix epoch to
  9999-12-31T23:59:59Z (the range RFC 3339 renders). The whole envelope fits
  `MaxValueSize` (64 KiB).
- **One encoding per envelope.** Every byte-string field is at least 1 byte; an optional field
  (`comment`, `refreshExpiresAt`, `tokenType`) is absent rather than empty, and an absent
  `tokenType` means `Bearer` without being written. So decode then encode is the identity, which
  `FuzzEnvelopeParse` asserts. Any envelope version byte other than 1, 0 included, is
  `ErrKindUnsupported`.
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
  input re-encodes byte-identically and that an error never contains input bytes: no 16-byte
  window slid over the input appears in the error text (the sentinels' fixed texts aside), and
  `TestEnvelopeRefusalsNeverCarryRefreshToken` plants a marker refresh token and triggers every
  refusal around it; its seeds live
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
  quota and keep dead refresh tokens forever; a pruned version's file is unlinked, which is
  the point. Unlinked is not erased: on APFS the unlink frees the file's blocks without
  overwriting them, a local snapshot (Time Machine's included) taken before the prune still holds
  the sealed file, and a copy-on-write clone shares its blocks. The record stays sealed under the
  master, so reading it needs the master too; the provider's refresh-token rotation, not the
  unlink, is what makes the old token useless.
- **The mark lives in the current-pointer plaintext.** Today that is 16 bytes (`version`,
  `sequence`). A pointer that records a prune carries 24 bytes: `version`, `sequence`, `low`,
  where `low` is the oldest retained version and `1 ≤ low ≤ version`. A 16-byte pointer means
  `low = 1`, so every existing pointer and every `token` or `ssh` pointer stays byte-identical.
  Any other size, or `low` out of range, is `ErrCorrupt`. So is a pointer outside its one
  canonical form: a 24-byte pointer recording `low = 1` (the 16-byte form says that), or a
  24-byte pointer over a version that is not `oauth`, which never prunes; otherwise a forged mark
  could hide a `token` entry's committed versions. The read accepts exactly what the rotation
  writes, which records `low = version - 1` for `oauth`: an `oauth` pointer is 16 bytes only at
  versions 1 and 2, and from version 3 it is 24 bytes with `low = version - 1`. Any other `oauth`
  window, wider or narrower, is `ErrCorrupt` on every read, not only once List opens a missing
  version. `FuzzPointerPlaintext` holds the decoder to the writer's output.
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
- `rotate --from-version N` refuses, with `ErrKindMismatch`, a version N whose kind is not the
  entry's current kind, and writes nothing (U146). It copies version N's sealed value as it is:
  a `token` keeps the `issuedAt` and `expiresAt` it was sealed with, nothing is re-stamped or
  checked against the clock, so a token restored past its expiry becomes the current version
  already expired and reads as expired until a new value is rotated in.

**The refresh token is write-only after `put`, and the store enforces it by type.**

- For kinds 3 to 5, the store returns the kind and a `typed.Credential`, decoded inside the
  store: `FileStore.CurrentCredential` and `GetCredential`. The raw reads `Store.Get` and
  `Current` refuse a typed entry with `ErrTypedCredential`, so no raw read can carry an
  envelope; a reconciler meeting one takes the unknown-kind path below. `typed.Credential` has no refresh field to fill, so the socket, both
  reconcilers, `exec`, `show --reveal` and `typed.Project` never hold the refresh token's bytes.
- `typed.Envelope` and `typed.Credential` redact themselves wherever they are formatted:
  `String`, `GoString`, `Format` (every `fmt` verb and flag, `%v`, `%+v`, `%#v`, `%s`, `%q`
  and `%x` included, inside a slice or map too, and in a wrapped error) and `LogValue` (a
  `log/slog` attribute) print the kind, each present field's name and its length, and never a
  byte of `RefreshToken`, `AccessToken`, `Value` or `Seed`. A value logged by mistake shows its
  shape, not its secret. The reflection encoders get the same redaction: `MarshalJSON`
  (`encoding/json`, and so `slog`'s JSON handler for a slice or map of them), `MarshalText` and
  `GobEncode`, with no matching decoder, so nothing round-trips a secret through them. One
  path no method closes: `fmt` and the encoders cannot call a method on an unexported struct
  field, so a struct with an unexported field of either type prints its bytes under `%v`.
  No file in `pkg/keystore` declares one, and an AST test (`TestNoUnexportedSecretField`)
  fails the build on one: an unexported field of either type, or a pointer, slice, array or
  map of one.
- Typed plaintext the store makes is cleared once it is no longer needed, best effort (Go
  may have copied it, and only the buffers named here are cleared): the encoded envelope a
  `PutCredential`, `RotateCredential` or `RotateIf` seals, on every outcome; both tokens
  `sameRefreshOwner` decodes to compare the owner; and the field copies a `typed.Decode`
  refused part way had already made. A buffer the caller passed in (a raw `Put` or `Rotate`
  value, a `typed.Envelope`) is the caller's and is never cleared by the store
  (`TestTypedPlaintextZeroedAfterSeal`, `TestDecodeRefusalClearsClones`). U149's clearing
  covers the store's own buffers only: copies made inside `golang.org/x/crypto/ssh` while it
  parses or marshals a key are that library's, and are not cleared.
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
  envelope version, is `ErrKindUnsupported`: "this entry was written by a newer k3sm, or the file
  was altered; upgrade, or, if this k3sm is current, restore it from backup". A single flipped
  byte can make a record read as a newer kind, so the text never steers an operator to upgrade
  alone; for an `oauth` entry the restore is followed by the re-login below. It
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
  untrusted input, which stays on the maintained library, behind k3sm's own limits: at most
  4 KiB of input, exactly one `OPENSSH PRIVATE KEY` PEM block with no headers and nothing but
  whitespace around it, an ed25519 key whose private half matches its seed, and one fixed
  refusal message that quotes no input byte. `FuzzSSHImport` covers it, asserting that no 16-byte
  window of the PEM body appears in a refusal, with seeds in
  `testdata/fuzz/FuzzSSHImport/`. The key's own comment is not kept; `--comment` sets it.
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
- **The owner is fixed per entry**, like the kind. `rotate`, `RotateIf` and the refresher's
  write refuse a pair naming another owner with `ErrRefreshOwnerFixed`, which the socket answers
  as `invalid-value` (the wire set does not grow); `local` to `server/<p>`, `server/<p>` to
  `local` and one profile to another are all refused. `rotate --from-version` is refused for
  `oauth` before any owner is compared. Changing owner is `rm` and `put` again, so a rotation can
  neither hand a `local` pair to the server nor take a `server/` pair away from it. `pkg/keystore`
  names the error itself rather than reusing `ErrKindMismatch`, whose text tells the operator the
  entry holds another kind.
- **A pod is never a refresh owner in this release.** Pods cannot reach the socket, and a
  pod-reachable write endpoint is deferred.
- **No exec hooks.** The only refresh procedure built in is RFC 6749 §6, the `refresh_token`
  grant. A "hook" is a declared profile (data), never a program.
- **The store interface.** The refresher is not a socket peer. Its consumer interface,
  `OAuthRefreshStore`, has the opener for a `server/`-owned pair's current version and
  `RotateIf(name, expect, value)`, a compare-and-swap Rotate, with bytes taken only from a
  token-endpoint response. `expect` is the `Version` the refresher read, which carries an opaque,
  unexported identity besides its number: a digest of the entry's generation, name, version and
  record digest. The record digest makes two different sealed records of one version number
  (a failed attempt's file copied over its retry's) two identities; a Rewrap re-seals every
  record, so a `Version` read before a Rewrap is stale after it.
  `RotateIf` refuses with `ErrVersionStale` unless both the number and the identity match the
  current version, so an entry deleted and put again (a new generation, versions restarting at 1)
  never matches a version read from the old one, even where the number and the fingerprint
  repeat. A `Version` the caller builds has no identity and is always stale. The identity reveals
  no generation, and `pkg/keystore` still exposes none. It has no reveal, show, list or rewrap method (U150).
  The identity's limits: it is an in-process guard against a stale or recreated read, not a
  capability. It is an unkeyed digest of values that are not secret, so anything that can see
  or guess an entry's generation could compute it; it protects only because no code outside
  the package can set the unexported field. It therefore never crosses the socket. If a
  compare-and-swap ever does, the token on the wire must become a keyed MAC under the store's
  key (over the name, generation and version), checked in constant time, and a remote caller
  must present the token from its own read, never one it built or was handed
  (`TestRotateIfRefusesVersionBuiltOutside`).
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
and rollback"). A build from before typed records reads them as corrupt and advises removing the
entry with `rm`: do not follow that advice for a typed entry; upgrade again instead.

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
| G7 | The floor is raised by every mutating verb (Delete only when the master opens) and by the start of every root verb (`list` and `show` through `RaiseFloor`), and a floor one behind the pointer is accepted. Each floor write re-reads the floor under the data-root lock and applies only its own change, and a held data-root lock times out within the bound. A verb that takes both locks, a maintenance verb (`floor --rebuild`, `audit --rotate`, `rm-scope`) included, takes `keystore-lock` before `keystore/.lock` | unit: crash after the flip, before the floor write; a floor moved on during a Rotate or a Delete keeps its newer entries; a held data-root lock on a real `flock`; a maintenance verb waiting for a held `.lock` already holds `keystore-lock` |
| G8 | Rotate flips the pointer last; a crash at each of its steps leaves the old version current | unit: fault injection between each step |
| G9 | A Rotate retry never promotes an orphaned next version: a failed Rotate removes its own, the version's fsync failure included, a sealed one a crash left is refused (`ErrCorrupt` and `ErrOrphanVersion`, nothing removed, oauth told not to delete it), one that does not authenticate is discarded, and the retry seals the value it was given; every version file is examined before a rotate writes over its name: a system-scope Rotate examines every file above the pointer, a user-scope Rotate only `v<cur+1>`, so a file planted further up in a user scope is examined when the pointer reaches the version below it; only the attended, root-only `Adopt` (`k3sm keys adopt`) promotes a sealed orphan, at exactly the next version | unit: orphan with value A, refused; removed, retry with value B, expect B; a fault after the version's rename; an oauth crash, then adopt, then the new pair is current; adopt's refusals; the CLI verb |
| G10 | The master is minted only by the first `put`, never over existing entries, and never by an operator-supplied value | unit: absent master with entries is `ErrMasterMissing`; no verb accepts an operator-made key: `rewrap --key-in` refuses a key that is neither the recorded `master.next.sha256` nor one some record already opens under |
| G11 | The master is opened with O_NOFOLLOW and judged by fstat on the open descriptor; wrong mode, owner or fingerprint is `ErrMasterUntrusted` | unit: one case each |
| G12 | Rewrap resumes after a crash at every step, trying the old then the new key, and leaves no record readable by neither; a `master.next` that disagrees with its fingerprint is discarded only when no `.new` file exists, and refused with `ErrMasterUntrusted` otherwise | unit: fault injection at each of steps 2 to 5, then rerun; a corrupted `master.next` with and without a `.new` file |
| G13 | A crash between the two master renames leaves a master that passes its trust check, and the next verb completes the swap | unit: stop after the first rename |
| G14 | One lock serializes Rewrap, Rotate, Put and reads, with a bounded wait | unit: a held lock gives a timeout error within the bound, not a hang |
| G15 | Files a root-run verb writes under `server/` are owned by the service user at the layout's modes | unit with a fake owner seam |
| G16 | `list` returns every entry, marks an unreadable one with `Err`, and exits 1 (a user scope's `list` authenticates the current version and checks the others for presence only: "List, when one entry is corrupt"). A directory holding nothing, `generation`, or `generation` and `v1`, with or without leftover `.tmp` files, is an incomplete Put unless the floor records its generation: not listed, `ErrNotFound` from `Current`, `Get` and `Delete` (Delete removes it too, and leaves the floor alone; with a live record for the name it buries that record and succeeds), discarded by the next Put. A directory with no `current` and any other file (`v1` without `generation` included), or in one of those shapes with its generation recorded in the floor, is damage: listed with `Err` wrapping `ErrCorrupt`, removed by `rm`, its floor entry replaced by a tombstone, and `ErrExists` from Put with every file left in place | unit: each incomplete-Put shape with no floor entry, an empty directory, a `generation`-and-`.tmp` directory standing in for a crash while writing `v1`, no floor file, a floor of another generation; damage: `v1` without `generation`, `v2` without `v1`, a `v1`-and-`v2` directory with `current` removed, and the one-version entry that lost `current` (`generation` and `v1`, or `current` renamed to a temporary name) with its generation in the floor; a retried `rm` after an interrupted one; a CLI exit-code test for `list` and `rm` |
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
| U13 | quotas: the 257th entry and the byte budget answer `ErrQuota`; the 65th live delivery answers `ErrQuota` to `deliver`; `rm` and `withdraw` still work | `k3sm/pkg/keystore::TestUserScopeQuota`, `TestUserScopeQuotaCountsDeliveriesAndGeneration`, `TestDeliveryRecordQuota`, `TestRevocationIsUnconditional`, `TestWithdrawFloorFaults`, `TestWithdrawRepeatAppendsNoFloorLine`, `TestWithdrawRefusesRollbackBelowSeen`, `TestWithdrawRefusesRollbackAfterFloorLineFailed`, `TestRepeatWithdrawCatchUpIsRevocation`, `TestWithdrawAuditRevokeFlag`, `TestDeliveriesCatchUpSurvivesRestart`, `TestDeliverCatchesUpFloor`, `TestCatchUpUserAtStartSurvivesRestart`, `TestUserScopeRefusedBeforeStart`, `TestStartUserScopesChecksBoundsFirst`, `TestCheckLogBoundsFailsClosed`, `TestCheckLogBoundsReportsDamage`, `TestExportPrereqsChecked`, `TestWithdrawBelowReadableFloorRefused`, `TestDeleteOwnerChanged`, `TestRmLookupRefusalKinds`, `TestDeliveriesSeenIsProcessWide` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U14 | the delivery record stores UID, the full target tuple (`entry`, `namespace`, `secretName`, `items`, `requestedBy`) under its seal, and the target digest; add, look up and withdraw round-trip under the floor; the plaintext starts with the format version byte and the digest with the `k3sm-keystore-delivery-target/v1` label; the digest covers `entry`, `namespace`, `secretName` and the key-sorted `items`, and a reorder of `items` leaves it unchanged | `k3sm/pkg/keystore::TestDeliveryRecordDigestRoundTrip`, `TestDeliveryRecordVersionByteAndDigestLabel`, `TestDeliveryDigestCoversTargetAndItems`, `TestDeliveryFieldGrammarAtAdd`, `TestDeliveryFieldGrammarAtParse` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U15 | (reserved for the K0 amendment if leg 5 finds a second Pod-uid path) | none | pending: K0 amendment |
| U16 | every Pod profile variant (native, vm, container-vm, xcode, expose-paths, wasm (a native Pod whose process is the `k3sm-wasmhost` helper, `runtimed/pkg/wasmhost/doc.go:20`), the profile an exec-session process runs under (`runtimed/pkg/execsession/doc.go:17`), a custom Pod root distinct from the data root) denies every `keystore-*` name in the data root and the `keystore-sock/` tree; the keystore names are in `DataRootDenyTrees` and so in `protectedPrefixes`; `ReadOnlyPaths`, `ExposePaths` or a hostPath naming the data root or a keystore path is refused; an empty `Posture.DataRoot` still gets the denies under the work dir; a vm or container-vm guest gets no data-root share; over the whole rendered profile of every variant, including a Pod root equal to the data root and a Pod root that is a parent of it, no emitted allow matches any keystore path; the keystore stanza is the profile's last rule, written in the `/var`, `/private/var` and `/System/Volumes/Data` spellings, and the `keystore-` prefix deny is a regex rule in either letter case; a caller path naming a keystore path is refused with `ErrProtectedPath` and a pods root under a `keystore-*` name is refused; beside the read and connect cases, a file write, create, unlink and rename and a `network-bind` on `keystore-sock/`, on `keys.sock` and on every `keystore-*` name are each refused; every case also holds through `/System/Volumes/Data/private/var/lib/k3sm/...` and through the data volume's mount path | `runtimed/pkg/sandbox::TestDataRootDeniesKeystorePathsEveryProfile`, `TestShimProfileKeepsTheKeystoreDeniesLast`, `TestKeystoreDenyStanzaShape`, `TestDataRootRefusesPodRootUnderKeystoreName`, `TestValidateRefusesKeystoreExtraPaths`, `TestEmptyDataRootFailsClosed`, `TestDataRootRefusesWhatCannotHoldTheDeny`, `TestKeystoreDeniesUnderSandboxExec`; rig leg E10 | checked: runtimed's sandbox change |
| U17 | runtimed refuses a Pod identity it may not hold through `Credential.CheckPodIdentity` (`pkg/supervisor/privdrop.go`), not in `resolveCredential`: at `startContainer`, at `Exec` (an exec session), at the resident shim's `dropShim` and in `RunLaunchSequence`. A drop target uid is refused if it is 0, negative, 501 or above, or the service uid; groups are refused if they are 0, 20, 80, the privileged system groups (wheel, daemon, kmem, sys, tty, operator, procview, procmod, _developer), the service gid, negative or out of range, and a gid of 501 or above is refused unless it is an admitted `fsGroup`; a missing group defaults to `nobody`; a gid-only drop that leaves uid 0 is refused; an inherited uid with no drop (the daemon's own euid: the service uid, a rootless server's login uid or root on a root daemon) is allowed. The system gids (1, 2, 3, 4, 5, 8, 9, 204) are refused as the primary gid and as a supplemental gid (`runtimed/pkg/supervisor::TestRunLaunchSequenceRefusesPodGroups`, `runtimed/pkg/runtime::TestPodGroupsRefused`, `runtimed/pkg/supervisor::TestFSGroupGidAllowList`). A gid in 1..500 is refused for a Pod drop, as the primary or a supplemental group, when the host assigns it; an unassigned gid is allowed, and so is `nobody`; the never-list is always refused, a lookup error refuses, and an operator-admitted `fsGroup` the host assigns is still refused (`runtimed/pkg/supervisor::TestPodGroupsHostAssigned`). The service identity (the `_k3sm` lookup and the owners of the installed directories) is resolved again on every drop check (`runtimed/pkg/runtime::TestStartContainerResolvesTheServiceOwnerEachStart`), and a symlink at an installed path refuses every drop (`runtimed/pkg/runtime::TestSymlinkedWorkDirRefusesDrops`). When the account lookup returns not-found, a drop to the owner of the installed work dir or the keystore socket dir is refused (the installed service-uid fallback: `runtimed/pkg/supervisor::TestResolveServiceIdentityInstalledOwner`, `runtimed/pkg/runtime::TestServiceUIDFromInstalledDirs`). The live check is strict, a denial is an EPERM and planting is included (`runtimed/pkg/sandbox::TestKeystoreDeniesUnderSandboxExec`, `runtimed/pkg/sandbox::TestShimProfileKeepsTheKeystoreDeniesLast`) | `runtimed/pkg/runtime::TestStartContainerRefusesAPodIdentity`, `TestExecRefusesAPodIdentity`, `TestPodUIDInLoginRangeRefused`, `TestPodGroupsRefused`, `TestServiceUIDFromInstalledDirs`; `runtimed/internal/execshim::TestDropShim`; `runtimed/pkg/runtime::TestStartContainerResolvesTheServiceOwnerEachStart`, `TestSymlinkedWorkDirRefusesDrops`; `runtimed/pkg/supervisor::TestRunLaunchSequenceRefusesPodUID`, `TestRunLaunchSequenceRefusesPodGroups`, `TestFSGroupGidAllowList`, `TestResolveServiceIdentityInstalledOwner`, `TestPodGroupsHostAssigned`; `runtimed/pkg/sandbox::TestKeystoreDeniesUnderSandboxExec`, `TestShimProfileKeepsTheKeystoreDeniesLast`; rig legs E21, E22 | checked: runtimed's sandbox change |
| U18 | CRD: `entry`, `secretName`, `items`, `requestedBy` required with no default and immutable by CEL transition rules (`items` as a map); `requestedBy` matches its pattern and, for a user entry, equals `k3sm:local:` plus the entry's uid; `conditions` is `listType=map` keyed by `type`; status subresource on; reasons listed; a `system/…` entry is refused | `apis/config/crd::TestKeyDeliveryCRDMatchesTheGoTypes`, `TestKeyDeliveryImmutableFields`, `TestKeyDeliveryRequiredFields`, `TestKeyDeliveryRequestedByMatchesEntryUID`, `TestKeyDeliveryConditionsListMap`, `TestKeyDeliveryRefusesSystemEntry` | pending: the `KeyDelivery` API |
| U19 | the CRD pattern, its `maxLength` of 269, the uid range rule and the 253-byte name-length rule pass the shared entry-grammar vectors, `user/1/` and `system/` each with a 254-byte name refused | `apis/config/crd::TestEntryGrammarVectors` | pending: the `KeyDelivery` API |
| U20 | a user entry tree copied back after `rm` is refused as deleted against the floor log's tombstone (real, not synthetic), a later `put` of the name is served, and an `rm` whose removal fails still leaves the entry refused; an `rm` buries every generation it can name (the floor's live ones, the `generation` file's, the pointer header's and each `v<N>` record header's), so a swapped `generation` file, or a `generation` file and pointer both rewritten, does not let the original tree back, and it reports the mismatch after the commit; a planted tree naming more than 4 generations beyond the floor's live ones has only the floor's and the pointer header's buried, is removed and is reported altered; whatever stands at the name it buries the floor's live generations first: a file or a symlink there is buried, removed and reported after the commit, a directory that cannot be opened is buried first and kept, refused when the floor does not take the tombstone, a burial is one write of every tombstone, the served generation first (the authenticated one, or the pointer header's without K_u), under one block reservation, and one whose reservation is refused or whose write lands short inside its first tombstone refuses the `rm` with nothing removed (the short bytes are a torn tail the reader skips), while one whose write lands short after a whole tombstone is committed and audited as a revocation, while a floor that takes tombstones one by one reports a burial that fails after its first tombstone landed after the commit, audited as a revocation, a name no source names a generation for is refused before anything is removed, and an `rm` of an absent tree with live generations buries them and succeeds, so a retry after a failed burial closes the window; an absent floor refuses an `rm`, which removes nothing, a withdraw over a floor that is absent, unflagged or unreadable seals nothing and is refused naming the Secret's deletion, so a restored record is never re-sealed, a floor line that does not parse, or a torn tail, is skipped and counted as damage (root reads the count), so an `rm` and a withdraw of two uids after garbage each succeed while a grant is refused before its first write naming `CheckLogBounds` and the root acknowledgement (a skipped line can be a tombstone, so damage writes no live line for a key it could name: a torn line whose scope and name parse taints that key, or that generation, for every generation, the delivery record included, a line torn inside its name or its scope taints every key whose name or scope starts with the partial text, and other names keep working, while unattributable damage keeps the floor-wide rule; no catch-up or `put` writes one for a generation whose tombstone was lost, `current` of it is refused, and every floor line carries a CRC-32C checksum, so a truncated or flipped line never parses, a truncated one taints its key or counts as unattributable, and a damaged line that could be a tear, a prefix of a line in the grammar, taints by that prefix, and any other is corrected to the keys it taints, a flipped-away newline's two lines included, or, with no unique single-bit correction, refuses every known generation until the acknowledgement, the start step quarantines only a scope whose live catch-up line the damage refused, its grants and reads refused while its rm and withdraw still run, and a full volume quarantines nothing; a taint past the taint set's cap refuses every key's grants and reads, which no acknowledgement lifts; the acknowledgement is a compare-and-set against the floor root reviewed, its unrecovered count included, and the review gives each unrecovered line's offset; a withdraw under a delivery-record taint seals every delivery withdrawn and audits each one it withdrew, admitting every audit line on the audit log before it seals and attempting each one past a failure), every append writes a newline first, so a foreign fragment landing just before the server's write is one damaged line and every server line parses, and a torn tail is frozen where first read, so a foreign append that completes it stays damage that keeps its key tainted, an empty line is benign, a burial's free-space preflight also holds its audit line's after the burial's block-rounded reservation, an `rm` whose burial fsync fails is committed, durability uncertain, and audited as a revocation when its tombstones are visible, found from the file's real end, and refused with nothing removed when none is, and the tombstones read before the garbage still refuse their copies; an `rm` over a torn floor tail buries and removes; a floor past the reader's bound refuses a withdraw with `ErrCorrupt` naming the matched-set restore, which brings back every entry deleted since the backup, and a read I/O error is not damage; a grant over a floor that is absent, unflagged, unreadable or past its bound is refused before its first write, with no `ok` line. A `current` below a floor line is refused with the user-scope floor message, which names the matched-set restore, not removing `keystore-floor.json`; until user rotate exists that half is proved against a synthetic later floor line, and becomes a real "older `current` than a later write" check with rotate | `k3sm/pkg/keystore::TestUserFloorRefusesCopyBackAfterRm`, `TestUserPutAfterRmServed`, `TestUserRmBuriesBeforeRemoval`, `TestUserRmAbsentFloorRemovesNothing`, `TestUserRmSwappedGenerationStillBuries`, `TestUserRmNonDirectoryBuries`, `TestUserRmRetryAfterTreeGoneBuries`, `TestUserRmBuriesVersionHeaderGeneration`, `TestUserRmOpenFailureBuriesFirst`, `TestUserRmOpenFailureRefusedWithoutTombstone`, `TestUserRmMissingEntriesBuriesFirst`, `TestUserRmRemovalFailureIsCommitted`, `TestUserRmChargesEveryTombstone`, `TestRmBurialReservedBeforeFirstTombstone`, `TestRmBurialIsOneWrite`, `TestRmBurialWriteFailureRefuses`, `TestRmBurialShortWriteAfterWholeLineCommits`, `TestRmBurialServedPointerFirstWithoutKu`, `TestRmBurialPartialNamesLandedWithoutServed`, `TestServerPathsLeaveOneLiveGeneration`, `TestRmBurialSyncFailureRefuses`, `TestRmBurialSyncFailureVisibleCommits`, `TestRmBurialForeignAppendBeforeShortWriteCommits`, `TestForeignFragmentBeforeWriteIsOwnLine`, `TestRmPartialBurialIsCommitted`, `TestUserRmUnreadableScopeKeyBuriesNothing`, `TestUserRmNoGenerationRefusesFirst`, `TestUserRmCapsTreeGenerations`, `TestUserFloorRefusesCopiedBackCurrent`, `TestWithdrawAbsentFloorProceeds`, `TestWithdrawUnverifiedFloorSealsNothing`, `TestRmOverTornFloorTailBuries`, `TestFloorGarbageTailIsSkippedDamage`, `TestFloorDamageDegradesLiveLines`, `TestTornBurialTaintsOnlyItsKey`, `TestTornBurialEveryCutRefusesKnownGeneration`, `TestSkippedScopePrefixTaintsItsScopes`, `TestTornWithdrawLineTaintsDeliveryRecord`, `TestUnattributableDamageKeepsFloorWideRefusal`, `TestTornPutLineQuarantinesOnlyItsScope`, `TestQuarantinedScopeRevokes`, `TestFullVolumeAtStartDoesNotQuarantine`, `TestWithdrawRunsUnderDeliveryRecordTaint`, `TestFloorLineCarriesChecksum`, `TestEveryTruncationAndFlipNeverParses`, `TestClosedTearRefusesKnownGeneration`, `TestDeliveryTearClosedKeepsTaint`, `TestFlippedGenerationDigitTaintsName`, `TestCorruptTombstoneOfKnownGenerationRefused`, `TestFloorDamageAckLiftsOnlyUnattributable`, `TestFloorTaintOverflowRefusesEveryKey`, `TestFloorDamageAckRefusesChangedFloor`, `TestFloorDamageAckRefusesStaleUnrecovered`, `TestFloorAckViewGivesUnrecoveredOffsets`, `TestFloorDamageAckCatchUpSkipsAttributable`, `TestRuntimeCatchUpRestoresLostEntryLine`, `TestWithdrawUnderTaintNeverRevivesLostWithdraw`, `TestFloorTornMiddleLineIsSkipped`, `TestWithdrawMalformedFloorRefused`, `TestFloorReadErrorIsNotDamage`, `TestGrantRefusesUntrustedFloorFirst`, `TestEveryTombstoneFlipRefusesKnownGeneration`, `TestFlippedTombstoneScopeRefusesCopyBack`, `TestUnrecoveredFlipRefusesKnownGenerations`, `TestForeignCompletionOfTornTailStaysTainted`, `TestForeignGrowthOfTornTailKeepsTaint`, `TestWithdrawUnderTaintAuditsEverySealed`, `TestWithdrawMassSealAuditsEveryDeliveryAtBudgetEdge`, `TestAuditSealedKeepsGoingPastFailure`, `TestRmBurialNeverLosesItsAuditLine`, `TestRmBurialFreeSpaceCoversItsAuditLine`, `TestDeliveryCatchUpPathsCheckLiveRefused`, `FuzzParseFloorLine`, `TestEveryBurialBufferFlipRefusesEveryBuried`, `TestEveryTwoBitTombstoneFlipTaintsTrueKeyOrUnrecovered`, `TestCouldBeTearMatchesOracle`, `TestReadBurialEverySingleFlip`, `FuzzCouldBeTear`, `FuzzBurialFlips`; rig leg E9 | checked: the append-only files (the store side) |
| U21 | install creates each missing log with its own directory, as the maintenance verbs build one: the directory is built in the root-only keystore-staging/, the log created root's 0600 with O_EXCL\|O_NOFOLLOW and nothing written, handed to the service user, set 0600 and flagged SF_APPEND on its descriptor and judged, all before the directory is placed in keystore-logs/ with RENAME_EXCL, so the log is flagged before it is reachable; a log that passes the judge is left alone, and an unflagged one is refused and left as found; it judges the data root's flags and ACL as the keystore does, refuses, changing nothing, while a maintenance verb runs, and removes a stale keystore-maintenance marker once the live set is ensured; the listener refuses to start when a flag is clear or a log is not the service user's (seams: chflags flag source, file-attribute writer, euid source) | `k3sm/pkg/install::TestKeystoreAppendOnlyFilesAtInstall`, `TestKeystoreFilesRefuseDuringMaintenance`, `TestKeystoreFilesJudgeDataRootFlags`, `k3sm/pkg/keystore::TestFlagCheckRefusesUnflagged`; rig leg E1 | pending: the append-only files |
| U22 | `floor --rebuild` and `audit --rotate` take `keystore-lock` and the store lock, then write the marker `keystore-maintenance` in the root-owned data root, which stops the listener; they build the replacement log directory in the root-only `keystore-staging/` (`buildLogDir`), its new log handed to the service user, set 0600 and flagged `SF_APPEND` on its held descriptor before it is reachable, record its inode and the report in the marker, and swap the directory in with one `renameatx_np(RENAME_SWAP)`; the old log's flag is cleared only after the swap, in staging, and the retired directory is removed unread ("The swap"); a crash before the report removes the marker and changes nothing, and from the report on keeps it, so the listener stays down until a rerun cleans staging and prints the committed swap's saved report or runs again ("Crash and rerun"); every audit and floor append, the reconciler's and the pre-frame lines included, takes the store lock that maintenance holds exclusively, so a reconciler append during an `audit --rotate` waits and lands in the new log; after maintenance, under the exclusive lock, the server reopens its audit and floor append descriptors and recounts the per-uid shares before releasing it, and the counts reset (seams: file-attribute writer, euid source) | `k3sm/cmd/k3sm::TestKeysFloorRebuildCrashOrder`, `TestKeysAuditRotateCrashOrder`, `k3sm/pkg/keystore/reconcile::TestReconcilerAppendWaitsForAuditRotate`, `k3sm/pkg/keystore/socket::TestMaintenanceReopensLogsAndResetsShares`, `TestFailedReopenRetriedAtMarkerPoll`; rig leg E17 | pending: the append-only files, the socket listener and the KeyDelivery reconciler (lifecycle), run in the lifecycle's mode, the last to land |
| U23 | every audited operation writes one `v:1` line; no line carries a value or its length; readers ignore unknown fields; an append after a torn tail writes a newline first, so the torn bytes are a dropped line of their own and the new line parses; a change committed whole is audited ok and one committed in part committed; a partial commit whose audit line fails keeps both failures and logs the scope and verb at Warn | `k3sm/pkg/keystore::TestAuditLineNeverCarriesValue`, `TestAuditReaderIgnoresUnknownFields`, `TestAuditTornTailAppendParses`, `FuzzParseAuditLine`, `TestAuditLineChargedStrictly`, `TestAuditResultCommitted`, `TestCommittedChangeKeepsAuditFailure` | checked: the append-only files (the store side) |
| U24 | the logs' sizes and soft cap are exposed for `doctor` (`LogSizes`); past the hard cap every mutating user op is `ErrLogFull`, except the revocation class, which draws on its uid's revocation budget; a line over 1 KiB is refused, and one found past the hard cap in the audit log is skipped and charged to no uid, while in the floor it is damage; the reader is bounded in size and floor keys, and the writer never appends past either bound: a floor line adding a key past the key bound is ErrLogFull, a grant without room for its keys is refused before its first write naming doctor, and a revocation of a key the floor holds still goes through, so put/rm churn never makes the floor damage; the reader reads through a line straddling the cap, and never blocks on a FIFO; a log or data root carrying a file flag beside `SF_APPEND` or a non-empty extended ACL is refused as untrusted; an append preflights free space and refuses, retryably, below 1 MiB plus the line, except a revocation's line, which keeps only a minimal check of the line plus 9 KiB; a put whose floor line would be refused after its commit (at the key bound, at a cap straddle where a minting put's second line would start past the hard cap, or below the free-space margin) is refused before its first write, and so is a deliver's; a grant line adding a key is refused once its uid has added its lifetime share of keys, buried or live (uidKeyShare, 4,112), while its rm still succeeds and another uid's grant succeeds, and a revocation line adding a key lands in a revocation headroom past the key bound, which the reader's bound includes; a configuration whose bounds sit below what an existing log holds is refused at store open; an append reserves its line's blocks on the log's descriptor before it writes, and a refused reservation is refused for space with the log byte-identical; a configuration under which a uid's lines past the hard cap already exceed its revocation budget is refused at store open naming the remedy, a budget under two lines is refused, and the default budget holds one scope's full revocation | `k3sm/pkg/keystore::TestLogHardCapRefusesMutations`, `TestAuditLineBoundedAtOneKiB`, `TestLogReaderSizeBound`, `TestLogReadBoundAuditCarriesPreFrameBudget`, `TestFloorKeyBound`, `TestFloorKeyBoundChurnRefusesGrants`, `TestFloorWriterRefusesKeyPastBound`, `TestFloorKeyBoundDerivedFromCaps`, `TestAuditStraddlingLineCharged`, `TestLogOpenFIFORefused`, `TestLogAppendPreflightsFreeSpace`, `TestRevocationLinesSkipFreeMargin`, `TestRevocationLineAtKeyBound`, `TestLogRefusesExtraFlags`, `TestLogDataRootRefusesExtraFlags`, `TestLogRefusesExtendedACL`, `TestAuditOverlongLineSkipped`, `TestPutRefusedFirstBelowFloorMargin`, `TestPutRefusedFirstAtKeyBound`, `TestPutRefusedFirstAtCapStraddle`, `TestDeliverRefusedFirstBelowFloorMargin`, `TestPutFloorLineSurvivesVolumeFiller`, `TestPutPreflightReservesValueRoom`, `TestFloorLineBudgetFollowsClass`, `TestLogFullTextNamesNoNumbers`, `TestLogErrorsNameNoFigures`, `TestFloorSeqZeroLineIsPresent`, `TestFloorKeyShareRefusesOneUID`, `TestFloorKeyShareChargesBuriedKeys`, `TestFloorKeyShareLifetimeArithmetic`, `TestFloorDeliverRoomExistingKeyPastBound`, `TestFloorTombstoneLandsInHeadroom`, `TestFloorReaderAcceptsHeadroom`, `TestCheckLogBoundsRefusesShrunkCaps`, `TestCheckLogBoundsRefusesKeysPastBound`, `TestCheckConfigBoundsCapsAbove`, `TestLogMissingWithScopesNamesRestore`, `TestLogAppendReservesBlocks`, `TestReserveLogBlocksRounds`, `TestCheckLogBoundsRefusesSpentRevocationBudget`, `TestCheckLogBoundsRefusesAtSpent`, `TestSpentRevocationBudgetIsPerUID`, `TestCheckConfigRevocationBudgetFloor`, `TestDefaultRevocationBudgetHoldsFullRevocation` | checked: the append-only files (the store side) |
| U25 | backup and restore round trip: a restored tree with cleared flags is refused until floor --rebuild, which takes the restored root-owned unflagged floor as input, then opens; the rebuild writes a line for every entry directory holding a generation file, an authenticated pointer's sequence or, with none, sequence 0, so a damaged entry stays ErrCorrupt and never becomes ErrNotFound; the maintenance verbs take the locks, keystore-lock then the store lock, before they write the marker, build the replacement directory in a root-only 0700 keystore-staging/, swap it in with RENAME_SWAP, and leave the live set one complete set at every step; they take a log with a second link as input, which the steady-state check refuses naming the verb, leaving a fresh canonical log with one link, and refuse an unflagged old log the service user owns; past the 30 s wait they name the service-user holder and k3sm stop | `TestBackupRestoreRoundTripRebuild`, `TestRebuildKeepsDamagedEntryCorrupt`, `TestSwapCallOrder`, `TestSwapRerunFromEachStep`, `TestMaintenanceRepairsHardLinkedLog`, `TestMaintenanceStagingDirIsRootOnly`, `TestMaintenanceLocksBeforeMarker`, `TestOldLogUnflaggedServiceOwnedRefused`; rig leg E17 | done: the append-only files (floor --rebuild) |
| U26 | peers uid 0, the service uid and uid < 501 are refused before any frame is read (seam: peer-credential source) | `k3sm/pkg/keystore/socket::TestPeerEligibility` | checked: the socket listener (peer admission) |
| U27 | framing: an oversize frame, unknown type, a sub-length past the frame length or missing `HELLO` closes; `HELLO` past the 10-second bound closes; an unknown header field is ignored; `HELLO` picks the highest common version and the reply carries it and the server's frame cap; no common version sends `unsupported-version` then closes; an unknown `op` answers `unknown-op` and keeps the connection; a known request header field of the wrong type is `refused`; the frame cap covers the largest value, header and framing | `k3sm/pkg/keystore/socket::FuzzFrameReader` (committed seeds), `FuzzRequestHeader` (committed seeds), `TestFramingBounds`, `TestSubLengthsWithinFrame`, `TestHelloReadDeadline`, `TestUnknownHeaderFieldsIgnored`, `TestHelloVersionRange`, `TestHelloReplyCarriesVersionAndMaxFrame`, `TestHelloNoOverlapSendsUnsupportedVersion`, `TestUnknownOpKeepsConnection`, `TestFrameCapCoversMaxValue` | checked: the socket listener (framing and HELLO) |
| U28 | 64 connections in all, 2 per uid; a request past 10 s is cut; a connection idle 30 s after `HELLO` or between requests is closed | `k3sm/pkg/keystore/socket::TestConnectionCapsPerUID`, `TestRequestTimeout`, `TestIdleTimeoutAfterHelloAndBetweenRequests` (`testing/synctest`) | checked: the socket listener (caps and timeouts) |
| U29 | a listener panic is recovered and restarted; the apiserver is untouched; a stale socket is unlinked only if a service-user socket; a lock wait past 2 s fails the request (seam: clock) | `k3sm/pkg/keystore/socket::TestListenerRecoversPanic`, `TestStaleSocketUnlinkChecksOwner`, `TestBoundedLockWait`, `TestAbandonedLockWaitsBounded`, `TestLockWaitSlotsReservedUpFront`, `TestCheckBackoffResetsOnPassingChecks`, `k3sm/cmd/k3sm::TestKeystoreSocketWiring`, `TestKeystoreSocketRecoversSupervisorPanic` | checked: the socket listener (lifecycle) |
| U30 | with two servers registered, the listener does not start and `doctor` says why | `k3sm/pkg/keystore/socket::TestUserScopeRefusedWithTwoServers`, `TestSecondServerStopsServingListener`, `k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow`, `TestKeystoreServerCountNames` | checked: the socket listener (lifecycle) |
| U31 | a missing or unflagged file logs the install Warn at start and on each retry; `doctor` reports user scope off (seams: chflags flag source, clock) | `k3sm/pkg/keystore/socket::TestListenerWarnsOnEveryRetry`, `TestInstallMissingLogNamesInstall`, `TestPreconditionsCheck`, `k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow`, `TestDoctorKeystoreSocketLstat`, `TestDoctorKeystoreKubeconfigPermission`, `TestDoctorKeystoreReopenJudgement` | checked: the socket listener (server wiring and doctor) |
| U32 | a grant (put, deliver) appends its audit line before its first write, and every other operation's order is commit, append, reply, so the audit line is written before the reply; a failed append refuses user mutations and reads, except the revocation class (U109, U112) | `k3sm/pkg/keystore/socket::TestAuditBeforeReply`, `TestAuditFailureRefusesOps`, `k3sm/pkg/keystore::TestExecReadRefusedWhenAuditFails`, `TestUserRotateCrashOrder` | checked: the socket operations (the bridge's fail-closed rule) |
| U33 | `refused` lines are rate-limited per uid with a summary of the dropped count | `k3sm/pkg/keystore/socket::TestRefusedLinesRateLimited` | checked: the socket operations (the post-frame refused line) |
| U34 | 5 mutating ops a second per uid; 30 `read-for-exec` a minute per uid, each audited `exec-read` | `k3sm/pkg/keystore/socket::TestMutationRateLimit`, `TestExecReadCapPerUID`, `k3sm/pkg/keystore::TestExecReadAudited` | checked: the socket operations (the bridge's rate limits) |
| U35 | the socket server's store interface has no reveal, show or rewrap method | `k3sm/pkg/keystore/socket::TestStoreInterfaceHasNoRevealMethod` | checked: the socket operations (the store bridge) |
| U36 | the client refuses a socket whose connected peer fails the client check, whatever the path checks said: `LOCAL_PEERCRED` uid 0 (launchd, under activation), the audit token's euid equal to the service uid, and the installed binary's cdhash (seam: peer-credential source, client side) | `k3sm/cmd/k3sm::TestClientRefusesForeignServerUID` | pending: the non-root CLI and `exec` |
| U37 | `exec` sets the variable only in the child; nothing on stdout, nothing on disk; the value never enters argv; no non-root verb writes a value to stdout | `k3sm/cmd/k3sm::TestKeysExecEnvOnlyInChild`, `TestNoNonRootVerbWritesValue` | pending: the non-root CLI and `exec` |
| U38 | an unknown error code prints the code; a connect failure names `sudo k3sm install` | `k3sm/cmd/k3sm::TestUnknownErrorCodeFallback`, `TestConnectErrorNamesInstall` | pending: the non-root CLI and `exec` |
| U39 | (unused: there are no system grants) | none | none |
| U40 | the admission policy checks `requestedBy` against the requester and refuses a ServiceAccount creator; its CEL passes the shared grammar vectors | `k3sm/pkg/policy::TestKeyDeliveryPolicyChecksRequestedBy`, `TestEntryGrammarVectorsCEL` | pending: KeyDelivery authoring |
| U41 | `deliver` creates impersonating only `k3sm:local:<uid>` and `k3sm:local-users`, refusing any other impersonation and never sending `Impersonate-Uid` or `Impersonate-Extra-*`; the impersonated uid equals the peer uid; a request naming another user's entry impersonates the peer, not the owner; it writes the UID and digest; `withdraw` deletes the object; `undeliver` prints the hint | `k3sm/pkg/keystore/socket::TestDeliverImpersonatesUIDPrincipalOnly`, `TestDeliverImpersonatesPeerUIDNotOwner`, `TestImpersonationSendsNoUidOrExtra`, `TestDeliverWritesDigestRecord`, `k3sm/cmd/k3sm::TestUndeliverPrintsRotationHint` | pending: KeyDelivery authoring |
| U42 | an unrecorded UID, a digest mismatch, or a denied SAR gets no Secret; the SARs ask `create keydeliveries` and `create secrets` with no name, and `update` and `delete` secrets with `resourceNames` `spec.secretName`; encryption off refuses (G18 for KeyDelivery); each SAR carries the user `k3sm:local:<uid>` and the groups the impersonated create carried, so a grant bound to `k3sm:local-users` passes the create and every sweep alike | `k3sm/pkg/keystore/reconcile::TestUnrecordedOrRetargetedDeliveryGetsNoSecret`, `TestSARCreateUnnamedUpdateDeleteNamed`, `TestSARCarriesImpersonatedUserAndGroups`, `TestGroupBoundGrantHonouredConsistently`, `TestEncryptionOffRefusesKeyDelivery`; rig leg E23 | pending: the KeyDelivery reconciler (authority) |
| U43 | reasons are the closed set, each on the condition type and status the reason table gives; "absent" and "not yours" both read `EntryUnavailable`; a pre-existing Secret not claimed by a KeyDelivery (unlabelled, or Phase A's) is `SecretExists`; a second declaration is `SecretClaimed`, the oldest honoured record by `creationTimestamp`, then name, winning; `observedGeneration` tracks; `Ready=False` for any authority failure carries the one reason `NotAuthorized` with the `Authorized` reason in its message; `Ready` is `Unknown`, `Pending` before the first sweep and while `Authorized` is `Unknown`; each `Authorized=False` reason is tied to its action (`EntryUnavailable`, `NotRecorded` for a withdrawn UID or a digest mismatch, and `NotAuthorized` delete; `NotRecorded` for a UID never recorded retains), and a Secret kept under `Authorized=False` sets `SecretRetained=True` (`DeletePending` or `Unowned`) | `k3sm/pkg/keystore/reconcile::TestConditionReasonsClosedSet`, `TestReasonConditionTable`, `TestOneDeclarationPerSecret`, `TestReadyFalseCarriesNotAuthorized`, `TestReadyUnknownPending`, `TestAuthorizedFalseReasonActionMap`, `TestSecretRetainedWhenKept` | pending: the KeyDelivery reconciler (authority) |
| U44 | losing authority (a definitive denial) deletes exactly the owned Secret; the crash order is Secret, record, finalizer at every interruption point; ownership is the label, the owner annotation and that UID in the sealed record, not the ownerReference; the Secret's namespace and name must equal the record's target for that UID, and the record's entry must match the owner annotation; the orphan sweep removes a labelled Secret only when its owner annotation names a KeyDelivery UID the sealed record holds, it is that UID's recorded target, and that object no longer exists or is withdrawn, and never one with the label and owner annotation alone, an unlabelled or a foreign one; a forged label and a real UID on another Secret are left alone, charged to no share and logged as one `refused` line under the reconciler, against the reconciler budget, never as the owner's `deliver-delete` | `k3sm/pkg/keystore/reconcile::TestLostAuthorityDeletesOnlyOwnedSecret`, `TestFinalizerCrashOrder`, `TestOrphanSweep`, `TestForgedOwnerAnnotationOnOtherSecretIsLeftAlone` | pending: the KeyDelivery reconciler (lifecycle) |
| U45 | cross-user refusal with a fake peer-credential source: a peer with uid B, in its normal state (a started scope, under its rate limit and share), asks for `read-for-exec`, `rotate` and `rm` of uid A's entries, for `list`, and for any `system/…` name; every call answers byte for byte as for an absent entry of B's own (`list` shows B's own scope only), and the audit lines carry uid B. The byte-identical answer holds in that normal state only: a spent share, a lock held past its wait or a quarantine answers B's own absent entry from B's own state (`log-full`, `busy`, `refused`), so it need not match the answer for A's name; with B's share spent, A's and `system/…` names still answer `not-found` (`TestCrossUserRefusedShareSpent`). The delivery operations (`deliver`, `withdraw` and `deliveries`) answer `refused` to every caller until they are served, so they are not part of this claim yet | `k3sm/pkg/keystore/socket::TestCrossUserRefusedFakePeerCred`, `TestCrossUserRefusedShareSpent`, `TestNonRootCannotNameSystemEntries`, `k3sm/pkg/keystore::TestUserRotateNotFoundIsNoOp`, `TestExecReadAudited` | pending: the socket operations |
| U46 | `baseSocketDenies` derives the `keys.sock` path from `runtimed/pkg/keystorepaths` (`SocketPath(dataRoot)`, `<dataRoot>/keystore-sock/keys.sock`) and denies `connect(2)` to it | `k3sm/pkg/provider::TestBaseSocketDeniesKeystoreSocket`, `TestBaseSocketDeniesResolvesDataRoot`; `runtimed/pkg/keystorepaths::TestNames` | checked: the socket listener (pod denies) |
| U47 | seam guard: `pkg/keystore`'s `TestMain` installs a panicking stub on each of its seams, so no unit test reaches a real primitive | `k3sm/pkg/keystore::TestRealPrimitivesUnreachable` | pending: the user-scope store |
| U48 | seam guard: `pkg/keystore/socket`'s `TestMain` installs a panicking stub on each of its seams, so no unit test reaches a real primitive; the server-side peer-credential source is a constructor parameter of the listener, not a package variable, and the constructor refuses nil | `k3sm/pkg/keystore/socket::TestRealPrimitivesUnreachable`, `TestListenerRequiresPeerCredSource` | checked: the socket listener (seam guard) |
| U49 | `runtimed/pkg/keystorepaths` builds with `CGO_ENABLED=0` and imports only the standard library; `k3sm/pkg/keystore` imports that leaf and never `runtimed/pkg/sandbox` | `runtimed/pkg/keystorepaths::TestLeafImportsOnlyTheStandardLibrary`; `k3sm/pkg/keystore::TestKeystoreImportsNoSandbox` | pending: runtimed's sandbox change, the append-only files |
| U50 | the defeat list, run as the service user against both flagged logs (integration, a root-run row: `--root` runs it by name and fails it on SKIP, and `--check` prints it uncounted; flag variant): `chflags nosappnd`, `O_TRUNC`, `ftruncate`, `pwrite` at an offset, a shared writable `mmap` write, `F_PUNCHHOLE`, `link()`, `fclonefileat` then a swap, a `renamex_np` swap through the parent, `exchangedata`, `unlink` and `rename` through the parent, a second open with `O_TRUNC`, owner `chmod` and `fchmod`, and `F_SETFL` clearing `O_APPEND` then a `pwrite` at 0, in a root-owned 0755 directory (a name operation is refused by the flag or by the directory, `EPERM` or `EACCES`) and in a service-owned 0700 one (refused by the flag, `EPERM`), then an owner `chflags uchg` beside `sappnd` (`EPERM`, or if it lands `judgeLog` refuses the log) and an owner `chmod +a` ACL write (refused, or if it lands `judgeLog` refuses the log); each fails, the bytes and the flag are unchanged, and an `O_APPEND` write, and a seek-then-write that lands at the end, still succeeds | `k3sm/pkg/keystore::TestAppendOnlyDefeatListAsServiceUser` | checked as a root-run row (`--root`): the append-only files |
| U51 | per-uid log fairness: the share is a fixed byte count, 16 MiB by default, and a share above 1/16 of the hard cap is refused at start; every line is charged to the uid it acts for, reads (`list`, `read-for-exec`, `deliveries`) included; a uid past its share has its own mutations and reads refused with `ErrLogFull` (`log-full`) while another uid's succeed, and that refusal is never the global append failure that refuses every uid's reads; a uid past its share cannot get another uid's mutations, reads or revocations refused, though it can delay them through the store lock (U89); `list` and `deliveries` are rate-limited per uid | `k3sm/pkg/keystore/socket::TestLogSharePerUIDRefusesOnlyThatUID`, `TestLogShareAtMostOneSixteenthOfHardCap`, `TestShareRefusalIsNotGlobalAppendFailure`, `TestReadRateLimitPerUID`, `TestReadsChargedToShare`, `TestShareExhaustionIsolatedPerUID`, `k3sm/pkg/keystore::TestShareRefusalNotGlobalAppendFailureInStore`, `TestExecReadPastShareRefused` | partial: all but the `deliveries` rate limit checked, through the socket's store bridge (the socket operations); pending: `deliveries` rate-limited per uid (the deliveries operation) |
| U52 | every root verb writes one audit line with `via` `root` once the log exists, and none before it; `adopt`, `floor merge` and its dry run included, a change made with exit 4 or 5 audited `committed`, a put, rotate or adopt whose later step failed (`ErrCommitted`) included, and an rm-scope whose removed-scopes record was renamed into place but whose data-root fsync failed (rm-scope's exit 4: this run changed something, or the record's durability is uncertain) | `k3sm/cmd/k3sm::TestEveryRootVerbWritesAuditLine`, `TestAdoptWritesAuditLine`, `TestFloorMergeWritesAuditLine`, `TestKeysAuditResult`, `TestKeysRmScopePartialExitsFour`, `k3sm/pkg/keystore::TestRmScopeRecordFsyncFailureIsCommitted` | pending: the append-only files |
| U53 | every reconciler Secret write and delete, and every record withdrawal, writes one audit line with `via` `reconciler`, except drift repairs, coalesced to one line per delivery per 10 minutes (U86) | `k3sm/pkg/keystore/reconcile::TestEveryReconcilerWriteAndDeleteAudited` | pending: the KeyDelivery reconciler (lifecycle) |
| U54 | a pre-frame refusal (uid 0, the service uid, a uid below 501) writes a `refused` line with the peer uid, rate-limited per uid, drawing on the reconciler budget with its once-a-minute dropped-count summary; a dropped count is persisted in `.preframe-dropped` in the store directory, not kept only in memory, survives a reopen, is emptied once in the audit log, folds uids past 256 into `others`, is reported unreadable rather than reset, is shown by `doctor`, and is written by the next `audit --rotate` | `k3sm/pkg/keystore/socket::TestPreFrameRefusalsAudited`, `TestPreFrameRefusalLinesRateLimited`, `TestPreFrameReservedClassLimits`, `k3sm/pkg/keystore::TestPreFrameFsyncFailureIsWrittenNotDropped`, `TestPreFrameDroppedSurvivesReopen`, `TestPreFrameDroppedClearedOnceWritten`, `TestPreFrameDroppedCoalesced`, `TestPreFrameDroppedFoldsOthers`, `TestPreFrameDroppedCorruptFile`, `TestPreFrameDroppedParseStrict`, `TestPreFrameDroppedEncodeFits`, `TestPreFrameDroppedRoundTrip`, `TestRotateAuditWritesDroppedCounts`, `TestRotateAuditKeepsDroppedOnRefusal`, `TestRotateAuditIgnoresHostileDropped`, `k3sm/cmd/k3sm::TestDoctorKeystorePreFrameDropped` | checked: the socket listener (the server append path) |
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
| U67 | the revocation class (`withdraw`, `rm`, `rotate`, the withdrawal's floor line, the reconciler's `deliver-delete`, its `deliver-write` of a withdrawal and its rotation write) is charged to the share while it has room and past it bypasses the share and the hard cap, drawing on its uid's own budgets per log, counted per uid from the log: a 256 KiB reconciler allowance for the reconciler's lines and a separate 720 KiB socket margin for the uid's own `withdraw`, `rm` and `rotate` and their floor lines; neither budget can draw on the other; only the budget a line draws on running out refuses it, so one uid's revocations are never refused because of another uid: uid A uses up its budgets and uid B's revocation still succeeds; a uid with 64 live deliveries past its share still revokes from its socket margin, and spending that margin leaves the reconciler allowance whole; a no-op `rm`, `withdraw` or `rotate` is charged like any line and refused past the share; a uid whose budget is spent to under one line is counted and logged per uid and never refuses the store start, so after a restart uid B's `rm` and `withdraw` succeed while uid A's next revocation is refused, and only a log over a uid's budget (lowered caps) is refused at store open; a log passes the hard cap by at most 976 KiB per user scope (its 720 KiB socket margin and 256 KiB reconciler allowance), plus the 1 MiB reconciler budget | `k3sm/pkg/keystore::TestRevocationBypassesShareUsesReserve`, `TestNoOpRevocationChargedToShare`, `TestReserveKeepsReconcilerPart`, `TestRevocationAllowanceIsPerUID`, `TestSocketMarginSeparateFromReconcilerAllowance`, `TestShareLimitRefusesOnlyThatUID`, `TestShareLimitInTheFloor`, `TestShareRunningCountIsTheRecount`, `TestShareResetAfterAuditRotate`, `TestShareConfigAtMostOneSixteenthOfHardCap`, `TestLogReadBoundHoldsBothBudgets`, `TestSpentRevocationBudgetIsPerUID`, `TestUserRotateNoOpChargedToShare` | checked: the socket operations |
| U68 | root-run: floor --rebuild and audit --rotate meet a symlink, a FIFO and a swapped directory at the marker, at keystore-staging/ and at their log's directory in keystore-logs/, and refuse before anything changes; a symlink, FIFO or directory inside keystore-staging/ is removed unread and the verb finishes; the verb never follows a planted name, the decoy it points at does not change, and no log byte changes on a refusal (integration, a root-run row: `--root`) | `k3sm/cmd/k3sm::TestMaintenanceRefusesPlantedNames` (integration, root-run) | checked as a root-run row (`--root`): the append-only files |
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
| U80 | root walks service-user trees by descriptor: run as root (a root-run row, `--root`), `rm-scope`, `floor --rebuild` and Rewrap of each `scope.key` (U128) walk `.user/<uid>/` with `openat` and `unlinkat` and `O_NOFOLLOW`; `floor --rebuild` refuses a planted symlink, FIFO or other non-regular file and a directory where the layout has none, and `rm-scope` removes each with `unlinkat` (a directory by descriptor, `AT_REMOVEDIR`) without following it; read with a bounded size, re-check `SameFile` after each open and never follow a swapped directory | `k3sm/pkg/keystore::TestRootWalksRefusePlantedNames`, `TestRemoveScopeWalksJudgedRoot` | partial: rm-scope and floor --rebuild (non-root, and as root in `--root`'s R1); owed: Rewrap of each `scope.key` (U128) |
| U81 | a KeyDelivery never touches a Phase A Secret: the user-scope label value is the constant `keydelivery` and the entry is in the annotation `k3sm.io/keystore-entry`; a target that is present and not claimed by a KeyDelivery, unlabelled or delivered by Phase A, is `SecretExists` and is never overwritten or deleted; the Phase A reconciler leaves alone a Secret carrying `k3sm.io/keystore-entry` | `k3sm/pkg/keystore/reconcile::TestKeyDeliveryNeverTouchesPhaseASecret` | pending: the KeyDelivery reconciler (authority) |
| U82 | eligible peer uids are 501 to 2147483647: `nobody` (4294967294), 2147483648 and every uid at 2^31 or above are refused before any frame, with a `refused` line, as uid 500 is; 501 and 2147483647 are admitted; no scope is minted outside the range (seam: peer-credential source) | `k3sm/pkg/keystore/socket::TestPeerUIDRangeRefusesNobodyAndHighUIDs` | checked: the socket listener (peer admission) |
| U83 | the reconciler checks the user-scope floor log: a missing or unflagged floor log is `Indeterminate` for writes, so no `deliver-write` runs until `floor --rebuild`; the floor holds writes and absence-driven deletes: an `ErrNotFound` delete is `Indeterminate` while the floor is missing or unflagged, a revocation-driven delete (a withdrawn record, a digest mismatch, a SAR denial) still deletes the Secret without the floor, and only the record withdrawal waits for it (U107; the store's flag check, faked at the reconciler's store interface) | `k3sm/pkg/keystore/reconcile::TestReconcilerHoldsWritesWithoutFloor` | pending: the KeyDelivery reconciler (lifecycle) |
| U84 | when a log's size is past the hard cap, `doctor` shows a Warn with the overshoot in bytes and the `audit --rotate` or `floor --rebuild` hint, and none at or below it; the overshoot is at most 976 KiB per user scope (its 720 KiB socket margin and 256 KiB reconciler allowance), plus the 1 MiB reconciler budget | `k3sm/cmd/k3sm::TestDoctorWarnsOnLogOvershoot` | checked: the socket operations (doctor's overshoot Warn) |
| U85 | a reconciler line charged to no uid (a forged-Secret `refused` line, a drift repair, their summaries) draws on the reconciler budget, 1 MiB per log, separate from every uid and excluded from the hard-cap test; forged Secrets are counted in a bounded LRU of 1024 (namespace, name) pairs with no per-`resourceVersion` set, new pairs' lines at most 10 a minute and at most one summary `refused` line a minute carrying the dropped count; past the budget the lines are dropped and counted and `doctor` warns; N forged updates leave every uid able to read and mutate | `k3sm/pkg/keystore/reconcile::TestForgedSecretFloodLeavesEveryUIDServed`, `TestUnchargedLinesHaveOwnBudget` | pending: the KeyDelivery reconciler (lifecycle) |
| U86 | a drift repair (the reconciler re-creating or repairing a delivered Secret that someone other than the reconciler edited or deleted, at the version already delivered) is reconciler-class: it draws on the reconciler budget and is never charged to the owner's share or budgets; repairs are coalesced to one audit line per delivery per 10 minutes with a count, and rate-limited per delivery with exponential backoff capped at 10 minutes; a write of a new version after the owner's own `rotate` or `put` stays charged to the owner; `Ready=Delivered` compares `k3sm.io/keystore-digest`, the sha256 of the Secret's `data`, each sweep, so a substituted `data` under an intact version annotation is drift | `k3sm/pkg/keystore/reconcile::TestDriftRepairNotChargedToOwner`, `TestSubstitutedDataIsDrift` | pending: the KeyDelivery reconciler (lifecycle) |
| U87 | the admission policy also matches UPDATE and DELETE of `keydeliveries` and admits one only when the requester equals `oldObject.spec.requestedBy`, is the k3sm server's identity, or is in `system:masters` (and, for DELETE only, the namespace controller's ServiceAccount); a finalizer edit is an UPDATE, so another author can neither delete the object nor strip its finalizer; the reconciler's and `withdraw`'s own writes pass; on a DELETE `object` is null and only `oldObject` is read; `failurePolicy` is `Fail` | `k3sm/pkg/policy::TestVAPRefusesDeleteByOtherAuthor`, `TestVAPRefusesFinalizerStripByOtherAuthor`; rig leg E23 | pending: KeyDelivery authoring |
| U88 | `floor --rebuild` never lowers: it reads every scope whose `scope.key` opens under `W` without the GeneratedUID check, so an owner change or a departed account is rebuilt from its pointers (U129); if any scope's `scope.key` does not open under `W` or any other error stops it (`ErrBusy` included), it refuses to finish, names the scope and changes nothing; the `deliveries` record's AAD is scope, kind 0xFD, name `deliveries`, generation and sequence, its floor key is `(user/<uid>, .deliveries, generation, seq)`, and the rebuild writes that key's line; a copied-back older `deliveries` record is refused against the floor, before and after a rebuild | `k3sm/pkg/keystore::TestRebuildRefusesOnUnopenableScope`, `k3sm/pkg/keystore::TestCopiedBackDeliveriesRecordRefused` | done: the append-only files (floor --rebuild) |
| U89 | reads take the store lock shared and mutations exclusive, through a writer-preferring in-process lock; a server exclusive hold targets at most 50 ms of work per operation, larger work chunked, no hold across an API call (the target measured in K7a, not checked); a reconciler revocation that gets `ErrBusy` retries up to 3 times with jitter in the same sweep before it is `Indeterminate`; under a sustained read load from other uids a revocation completes | `k3sm/pkg/keystore::TestWriterPreferringLock`, `TestPrefLockWriterTimeoutAdmitsReaders`, `TestPrefLockAdmitsReaderUnderWriterStream`, `TestRotateHoldServesOtherUIDWithinLockWait` | partial: lock handoff checked, and no walk in a `put` or `rotate` hold but U108's named fallback (`pkg/keystore`, on synctest's clock); the work bound measured, not checked; `rm` pending (the user-scope store); pending: the per-uid hold bound for an `rm` of a large entry (U108's pending part), the reconciler's retries and `k3sm/pkg/keystore/reconcile`'s revocation under other uids' read load (the KeyDelivery reconciler (lifecycle)) |
| U90 | root-run: the directory swap. A process running as the service user holds, from before floor --rebuild, audit --rotate or install's log creation, an O_APPEND descriptor on the old log, a descriptor on the log's live directory and one on keystore-logs/. Before every step and after, by path on the canonical log its open(O_WRONLY), open(O_WRONLY\|O_TRUNC) and link() into its own directory each fail EPERM, and through the held descriptors F_SETFL clearing O_APPEND, pwrite and ftruncate fail EPERM while the file is flagged and openat for write fails EPERM, or ENOENT once the name is gone; at every hook the canonical log by path is a complete judged log, the whole old content or the whole new content, flags exactly SF_APPEND, the service user's, 0600, one link; at the end the new log holds what the verb wrote and the service user's O_APPEND lines, nothing the held descriptors did reaches the new log, and staging and the retired directory are empty. A crash at every step and a rerun of the same verb end valid, a rebuild that dropped lines exiting 4 with the same counts; the other verb run first harms nothing, and the first verb's rerun still finishes; the maintenance wait is the exclusive .lock, bounded at 30 s (integration, a root-run row: `--root`) | `k3sm/cmd/k3sm::TestMaintenanceSwapRefusesServiceUser`, `TestMaintenanceCrashAtEverySwapStepReruns`, `k3sm/pkg/install::TestKeystoreLogCreationRefusesServiceUserAtEveryStep`, `k3sm/pkg/keystore::TestStoreReadsSwappedLogDirAsRoot` (integration, root-run) | checked as a root-run row (`--root`): the append-only files |
| U91 | audit --rotate keeps four archives, .1 to .4, and refuses, changing nothing, when .4 exists unless --discard-oldest; the replacement directory holds an empty flagged log, a fresh root 0600 unflagged .1 holding the old log's bytes up to its size at open, made by cloning the old log, removing every extended attribute and any ACL from the clone (when one cannot be removed the clone is discarded and the archive is a copy), judging it with the logs' flags-and-ACL judge and truncating it to that size, or, when the volume refuses the clone, by a copy that first checks the volume's free space and refuses up front, changing nothing, short of the log's size plus the larger of 1 GiB and 2% of the volume's size, and the older archives carried by hard link as .2 to .4; every archive is root's 0600, unflagged, with no ACL, in keystore-logs/audit/archives/, root's 0700 (a 0755 one refuses), and an old log with an ACL is a Warn, never a refusal (the swap copies no ACL, and chmod -N fails on a flagged log), as a second link on one is; a marker with a second link is read, with a Warn, and a stale staging file is cleaned; a rerun after a crash past the swap prints the crashed run's report and does not rotate twice, and while the marker stands a missing audit log is never skipped; the doctor hint says to export first, as root, from archives/; rotation resets the shares, bounded by the archive count | `k3sm/cmd/k3sm::TestAuditRotateKeepsFourArchives`, `k3sm/pkg/keystore::TestMaintenanceJudgesMarkerAndStale`, `TestSwapRerunFromEachStep`, `TestAuditRootRefusesMissingLogInMaintenance`, `TestRotateAuditClonesArchive`, `TestCloneArchiveTruncatesToSnapshot`, `TestRotateAuditCopyChecksFreeSpace`, `TestCopyArchiveMarginScalesWithVolume`, `TestCloneArchiveStripsXattrsAndACL`, `TestCloneArchiveProtectedXattr`, `TestCloneArchiveRefusesRemainingACL`, `TestJudgeArchiveRefusesACL`, `TestOldLogUnflaggedServiceOwnedRefused` | checked: the append-only files |
| U92 | a `rotate` whose delivery will stall (owner past share, the delivery's rotation write used) is stored and answered `stored; delivery pending: past your log share`; the CLI prints the warning line and exits 0 | `k3sm/cmd/k3sm::TestRotateReportsDeliveryStall` | pending: the non-root CLI and `exec` |
| U93 | the sweep period is 30 s by default; two consecutive deleting observations count only when at least 60 s apart on the clock seam, however many sweeps run between them | `k3sm/pkg/keystore/reconcile::TestDeletingObservationsSpacedOnClock` | pending: the KeyDelivery reconciler (lifecycle) |
| U94 | `withdraw` opens the caller's scope and so runs the GeneratedUID check: a reused uid with a changed GeneratedUID gets `scope-owner-changed` and deletes nothing (seams: GeneratedUID lookup, peer-credential source) | `k3sm/pkg/keystore/socket::TestWithdrawChecksGeneratedUID` | pending: KeyDelivery authoring |
| U95 | `rm-scope` lists every RoleBinding and ClusterRoleBinding with the subject `k3sm:local:<uid>` and refuses, changing nothing, unless none exist or `--keep-bindings` is given | `k3sm/cmd/k3sm::TestRmScopeRefusesWithBindings` | pending: the KeyDelivery reconciler (lifecycle) |
| U96 | the `deliveries` record is exempt from the 64 KiB value cap and bounded at 64 live entries plus 256 withdrawn tombstones, 3,328 bytes an entry (8 items), 1,056 KiB sealed; at the bound `deliver` answers `quota` and a withdrawal still succeeds, in place; a tombstone is pruned only after its Secret is seen gone (Get not found) on two sweeps at least 60 s apart | `k3sm/pkg/keystore/reconcile::TestDeliveriesRecordBoundAndPrune`, `TestRevocationNeverRefusedAtRecordBound` | pending: the KeyDelivery reconciler (lifecycle) |
| U97 | when `rotate` answers `ErrQuota`, `rm` then `put` recovers: `rm` frees every version and `put` stores the value as version 1 of a new generation; no `quota` text recommends that recovery | `k3sm/pkg/keystore::TestRotateQuotaRecoveredByRmThenPut` | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U98 | the sealed `deliveries` record stores each delivery's KeyDelivery `metadata.name`; the orphan sweep checks the object with a live Get by that name sent to the API server, never an informer cache and never a List; not found, or another UID, deletes only on two consecutive observations at least 60 s apart, and any other answer in between resets the count; no sweep runs before the KeyDelivery and Secret informers sync | `k3sm/pkg/keystore/reconcile::TestOrphanSweepUsesLiveGetByName`, `TestOrphanSweepNeedsTwoObservations` | pending: the KeyDelivery reconciler (lifecycle) |
| U99 | under the store lock, before every audit or floor append, the server compares its descriptor's `(dev, ino)` with the canonical name's and reopens on a mismatch, recounting the per-uid shares from the new file; `audit --rotate` and `floor --rebuild` each complete while the server never saw the marker, and every later line lands in the new canonical file, none in an archive or an unlinked file (seam: chflags flag source) | `k3sm/pkg/keystore/socket::TestAppendReopensOnInodeMismatch` | checked: the socket listener (the server append path) |
| U100 | a departed account with an unreused uid is reported, not acted on: `doctor` lists every scope whose uid has no directory record (a synthesized GeneratedUID) with its delivery count; each of that scope's deliveries gets `SecretRetained=True` with reason `OwnerUnresolvable`, and no Secret is deleted (seam: GeneratedUID lookup) | `k3sm/cmd/k3sm::TestDoctorListsUnresolvableScopes`, `k3sm/pkg/keystore/reconcile::TestOwnerUnresolvableRetainedCondition` | pending: the KeyDelivery reconciler (lifecycle) |
| U101 | `rewrap` prints a warning whenever `.user/` exists, before it starts and when it finishes, saying Rewrap does not re-key `K_u` and naming the procedure: each user re-puts their values after a suspected master exposure; with no `.user/` it prints none (seam: euid source) | `k3sm/cmd/k3sm::TestRewrapWarnsWhenUserScopesExist` | checked: user-scope quotas, scope-key Rewrap and the delivery record |
| U102 | the sealed record stores the last delivered version per delivery, raised after the Secret write succeeds; the repair-versus-owner classifier uses only that recorded version: a Secret whose version annotation is rewritten and a KeyDelivery whose `status.deliveredVersion` is rewritten each leave the charge unchanged, a repair stays on the reconciler budget and an owner's new version stays charged to the owner | `k3sm/pkg/keystore/reconcile::TestChargingIgnoresTamperedVersionAnnotationAndStatus` | pending: the KeyDelivery reconciler (lifecycle) |
| U103 | a Secret at a recorded target whose label or owner annotation was removed is never overwritten or deleted, under a revocation, the object's deletion and `rm-scope` alike; the KeyDelivery gets `SecretRetained=True` with reason `LabelRemoved`, and `doctor` names the Secret and the KeyDelivery | `k3sm/pkg/keystore/reconcile::TestStrippedLabelReportedNotDeleted` | pending: the KeyDelivery reconciler (lifecycle) |
| U104 | the socket's directory is root's: run as root (a root-run row, `--root`), install creates `keystore-sock/` root:wheel 0755 and the server plist carries a `Sockets` listener for `keystore-sock/keys.sock`; a process running as the service uid cannot unlink, replace or bind `keys.sock`, whether or not the server runs: the unlink, a rename over it and a bind of a new name (`keys.sock` once it is gone) get `EACCES`, and a bind of the existing `keys.sock` gets `EADDRINUSE` with root's name left in place (measured in rig leg E24) | `k3sm/pkg/install::TestServerPlistActivatesKeystoreSocket`, `TestKeystoreSockDirAtInstall`, `TestSocketDirRootOwnedServiceUIDCannotBind` (integration, root-run); rig leg E24 | partial: the plist entry and the directory are delivered and unit-tested, and `--root` runs the root-run test, built with `-tags integration`, a SKIP failing it; pending: rig leg E24 |
| U105 | every root path walks the keystore trees by descriptor: run as root (a root-run row, `--root`), `sudo k3sm install` over an existing tree, `uninstall --purge` and `doctor` each refuse a planted symlink, FIFO or swapped directory under `.user/` and at every `keystore-*` name, with `openat`, `O_NOFOLLOW`, bounded reads and a `SameFile` re-check, and change nothing they were not meant to | `k3sm/pkg/install::TestInstallOverExistingTreeWalksByDescriptor`, `TestPurgeWalksKeystoreByDescriptor`, `k3sm/cmd/k3sm::TestDoctorWalksKeystoreByDescriptor` (integration, root-run) | pending: the append-only files |
| U106 | every root verb refuses a non-root caller: one table test runs `rm-scope`, `floor --rebuild`, `audit --rotate`, `rewrap` and `deliver system/…` with a non-root euid through the euid source, and each is refused with the same message and exit code, changing nothing (seam: euid source) | `k3sm/cmd/k3sm::TestRootVerbsRefuseNonRootEUID` | pending: the KeyDelivery reconciler (lifecycle), each verb's case added by the change that adds the verb |
| U107 | with the user floor missing or unflagged, an absence-driven delete (`ErrNotFound`) is `Indeterminate` and deletes nothing, while a revocation-driven delete (a withdrawn record, a digest mismatch, a SAR denial) deletes the Secret after its two spaced observations | `k3sm/pkg/keystore/reconcile::TestNotFoundDeleteWaitsForFloor`, `TestRevocationDeleteProceedsWithoutFloor` | pending: the KeyDelivery reconciler (lifecycle) |
| U108 | the exclusive hold bound on a fake clock: no server exclusive hold spans any fake time, so no wait the clock sees runs inside a hold; the GeneratedUID lookup runs before the lock is taken and its answer is cached for the hold, so a lookup that takes its whole 250 ms deadline adds nothing to the hold (seams: clock, GeneratedUID lookup) | `k3sm/pkg/keystore::TestExclusiveHoldBound`, `TestRotateAtQuotaNoFullWalk`, `TestUsageFigureMatchesWalk`, `TestUsagePanicAtWriteDropsFigure`, `TestUsageRefusalKeepsFigure`, `TestUserListOpensOnlyCurrentVersion`, `TestUserRotateOrphanCheckReadsOnlyNextVersion`, `TestDoneCtxAfterPreWalkTakesNoHold` | partial: no lookup or wait inside a hold, no entry listing in a `put` or `rotate` hold, and no scope walk in one but the fallback walk when the usage figure is still absent or stale at the lock (the walk before it failed, a root `rm-scope` and a new mint or a Rewrap landed between that walk and the lock, or the `put` minted the scope), checked (the user-scope store); pending: an `rm` hold bounded however many versions its entry keeps (its burial's header reads and its unlinks chunked) |
| U109 | with every audit append failing (a full disk), revocation deletes go ahead: the reconciler's `deliver-delete` and a socket `withdraw`, `rm` or `rotate` still act, their lines dropped and counted in memory and shown by `doctor`, while user mutations and reads stay refused | `k3sm/pkg/keystore/reconcile::TestRevocationDeleteProceedsOnAppendFailure` | pending: the KeyDelivery reconciler (lifecycle) |
| U110 | when a second server registers at runtime, the next single-server check stops the listener, closing its connections, and each KeyDelivery gets `Ready=False` and `SecretRetained=True` with reason `UserScopeOff`; the delivered Secrets stay, nothing rotates or deletes them, and `doctor` says they must be deleted by hand | `k3sm/pkg/keystore/reconcile::TestSecondServerAtRuntimeStopsListenerAndReports` | pending: the KeyDelivery reconciler (lifecycle) |
| U111 | the owner annotation never decides precedence: a Secret whose owner annotation is rewritten to name another recorded UID of the same target stays with the object that holds the claim by honoured record, `creationTimestamp` and name; an `Indeterminate` object counts as honoured | `k3sm/pkg/keystore/reconcile::TestAnnotationRewriteCannotTakeOverTarget` | pending: the KeyDelivery reconciler (authority) |
| U112 | outside a grant (put, deliver), which appends before its first write, the order is commit, then append, then reply: an append that fails after the commit answers `ok` with the warning `committed; audit failed`, the server then refuses user mutations except the revocation class, and `doctor` counts the unaudited operations: those that committed or may have committed with no line, a revocation that panicked in its hold counted whether or not it committed, the socket's Error line for the panicked operation (op, uid, `requested_entry`) being where its uid and entry are found | `k3sm/pkg/keystore/socket::TestAuditFailureAfterCommitRepliesCommittedAuditFailed`, `k3sm/cmd/k3sm::TestDoctorCountsUnauditedOps`, `k3sm/pkg/keystore::TestUnauditedOpsCountsCommittedRevocations`, `TestUserRotateCrashOrder` | checked: the socket operations (the persisted unaudited count) |
| U113 | the listener refuses to start unless the server's effective uid is the service uid (the `_k3sm` uid install creates): a rootless `k3sm server`, whose Pods inherit the daemon's login uid, runs no listener, and the server log and `doctor` say "user scope needs the installed server" (seam: euid source) | `k3sm/pkg/keystore/socket::TestListenerRefusesUnlessServiceUID` | checked: the socket listener (lifecycle) |
| U114 | `rm-scope` writes `keystore-removed-scopes.json` in the data root, root-owned, through the data-root descriptor rules, listing the removed scope's uid and bound GeneratedUID before it removes the scope; only a scope listed there counts as removed for the finalizer, and a plain `ErrScopeAbsent` stays non-definitive and keeps the finalizer (seam: euid source) | `k3sm/cmd/k3sm::TestRmScopeRecordsRemovedScope`, `k3sm/pkg/keystore/reconcile::TestOnlyRecordedRemovalCountsAsWithdrawn` | pending: the KeyDelivery reconciler (lifecycle) |
| U115 | `rm-scope` names each blocking binding, a RoleBinding with its namespace; `--remove-bindings` deletes each listed binding through the admin client before anything else changes, and a failed delete stops the verb, changing nothing further | `k3sm/cmd/k3sm::TestRmScopeNamesBindingsAndRemovesThem` | pending: the KeyDelivery reconciler (lifecycle) |
| U116 | the Pod uid refusal applies to native Pods only: a vm Pod with `runAsUser: 1000` is allowed, since a guest uid has no host meaning, while a native Pod with the same drop target is refused; the guest's groups skip the host group rules the same way | `runtimed/pkg/runtime::TestVMPodGuestUIDNotRefused` (the refusal sits on the native spawn path, `checkPodUID` in `pkg/runtime/security.go`; the same test, in `pkg/runtime/vmcontainers_test.go`, also pins that a vm Pod's `runAsGroup` of 1000 reaches the guest's GID and SupplementalGIDs unrefused) | checked: runtimed's sandbox change |
| U118 | root-run: the old log is retired, never re-owned: in audit --rotate and floor --rebuild the new log gets, in staging, its fchown to the service user, its fchmod 0600 and then its flag, between the build and report steps; the old log's one attribute call is its flag clear, made after the swap has made it unreachable by path, in the retired directory in keystore-staging/, which is then removed unread; it is never chowned or chmodded, ends unlinked with its owner, mode and bytes unchanged; rotate's archives, in archives/, are fresh root-owned unflagged copies, 0600 with one link, and the older archives carried by link are the same inodes and bytes (integration, a root-run row: `--root`) | `k3sm/cmd/k3sm::TestMaintenanceOldLogRetiredNeverReowned` (integration, root-run) | checked as a root-run row (`--root`): the append-only files |
| U119 | the floor lock is `keystore-lock`, a root 0600 file in the data root that only root can open, taken by every root verb that writes the floor or a keystore file in the data root (`put`, `rotate`, `rm`, `rewrap`, `deliver system/…`, the floor raise of `list` and `show`, `rm-scope`, `floor --rebuild`, `audit --rotate`); run as root (a root-run row, `--root`), a non-root process other than the service user holding the old data-root flock blocks none of them | `k3sm/pkg/keystore::TestNonRootDataRootFlockBlocksNoRootVerb` (integration, root-run) | checked as a root-run row (`--root`) for the verbs that exist: `put`, `rotate`, `rm`, `rewrap` and the floor raise; `rm-scope`, `floor --rebuild` and `audit --rotate` take it as they land (the append-only files) |
| U120 | the activated listening descriptor reaches no child: the server spawns each child type, an `exec.Command` child, the runtimed helper and a Pod through the exec shim, lists each one's open descriptors, and the listening socket is among none of them | `k3sm/pkg/keystore/socket::TestActivatedListenerIsCloseOnExecAndHeld` (integration); rig | partial: the activation confirms the descriptor's `FD_CLOEXEC` under `syscall.ForkLock`, refusing one without it, closes launchd's original, and an `exec.Command` child does not hold it; pending (rig): the runtimed helper and a Pod through the exec shim |
| U121 | under activation, the client accepts a `LOCAL_PEERCRED` uid 0 only when the audit token's euid is the service uid and its code the installed binary's cdhash; a uid-0 peer whose token names launchd, root or another uid, or other code, is refused and nothing is written (seams: peer-credential source, client side; server code identity) | `k3sm/cmd/k3sm::TestClientRefusesLaunchdAsPeer` | pending: the non-root CLI and `exec` |
| U122 | a Pod cannot obtain the server's listener from launchd: its `launch_activate_socket` for the server's socket name gets `ESRCH` (measured on macOS 27.2.1), so no Pod profile needs a launchd lookup deny; the Seatbelt path deny on `keystore-sock/` (U16, U46) is a separate deny and stays required | rig leg E27 | pending (rig): leg E27, which also owes macOS 26 |
| U123 | same-target cross-record deletion: the orphan sweep, a lost-authority delete and `rm-scope` never delete a Secret that another honoured record claims at the same `(namespace, secretName)`; a forged owner annotation naming one uid's tombstone on another uid's live Secret deletes nothing; the owner annotation never selects which record's tombstone governs a delete; nothing is charged to the victim | `k3sm/pkg/keystore/reconcile::TestForgedTombstoneAnnotationOnOtherUsersLiveSecretIsNotDeleted` | pending: the KeyDelivery reconciler (lifecycle) |
| U124 | a tombstone is pruned when its target is not this UID's owned Secret on two observations at least 60 s apart, not only on a Get that answers not found: a target occupied by another Secret still prunes; a failed Get keeps it | `k3sm/pkg/keystore/reconcile::TestTombstonePrunesWhenTargetOccupied` | pending: the KeyDelivery reconciler (lifecycle) |
| U125 | every reconciler Secret delete or update and every `rm-scope` delete passes `Preconditions{UID, ResourceVersion}` from the ownership read: a fake client swaps the Secret between the read and the delete, the delete is refused, and the outcome is `Indeterminate` | `k3sm/pkg/keystore/reconcile::TestDeleteRefusedWhenSecretSwappedAfterRead` | pending: the KeyDelivery reconciler (lifecycle) |
| U126 | the reconciler budget is split by source, 384 KiB for forged-Secret lines, 384 KiB for repairs, 256 KiB for pre-frame refusals, the forged and repair parts capped at 64 KiB per namespace; one source or one namespace spending its part leaves every other part whole; the dropped count is persisted in the next summary line written for that source, not kept only in memory | `k3sm/pkg/keystore/reconcile::TestReconcilerBudgetSplitBySource`, `TestDroppedCountPersistedInNextSummary` | pending: the KeyDelivery reconciler (lifecycle) |
| U127 | `ErrScopeOwnerChanged` is Indeterminate plus a `doctor` report, not a deleting outcome, until a K7a amendment records GeneratedUID stability across Migration Assistant, a macOS upgrade and a directory rebind: no Secret is deleted on it, however many spaced observations see it, and `doctor` names the scope (seam: GeneratedUID lookup) | `k3sm/pkg/keystore/reconcile::TestScopeOwnerChangedIsIndeterminate`, `k3sm/cmd/k3sm::TestDoctorReportsOwnerChangedScope` | pending: the user-scope store |
| U128 | Rewrap of each `scope.key`, and every root write under `server/keystore/`, walks by descriptor (integration, a root-run row: `--root`): a planted symlink, FIFO or swapped directory under `.user/` refuses Rewrap and changes no record | `k3sm/pkg/keystore::TestRewrapWalksScopeKeysByDescriptor` (integration, root-run) | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U129 | `floor --rebuild` reads every scope whose `scope.key` opens under `W` without the GeneratedUID check: a departed account (`ErrScopeOwnerUnknown`) and an owner change each get their lines and block nothing (seam: GeneratedUID lookup) | `k3sm/cmd/k3sm::TestRebuildReadsScopeWithoutOwnerCheck` | pending: the user-scope store |
| U130 | a scope listed in `keystore-removed-scopes.json` for its bound GeneratedUID is definitive for claims, so its stale objects lose their claim; `rm-scope` deletes that scope's KeyDeliveries, each by its recorded namespace and name with a UID precondition | `k3sm/pkg/keystore/reconcile::TestRemovedScopeLosesClaim`, `k3sm/cmd/k3sm::TestRmScopeDeletesScopeKeyDeliveries` | pending: the KeyDelivery reconciler (lifecycle) |
| U131 | the listener refuses to start on a data root mounted with `MNT_IGNORE_OWNERSHIP`, read with `fstatfs` on the data-root descriptor | `k3sm/pkg/keystore/socket::TestStartRefusesIgnoreOwnershipMount`, `k3sm/cmd/k3sm::TestKeystoreSocketDataRootPerPass` | checked: the socket listener (lifecycle) |
| U132 | `.user/<uid>/` is 0700 and `scope.key` and `deliveries` are 0600, all the service user's; a scope whose directory or files have another owner or a wider mode is refused | `k3sm/pkg/keystore::TestUserScopeFileModes` | pending: the user-scope store |
| U133 | `keystore-removed-scopes.json` is root-owned 0644, under the `keystore-` prefix the Pod denies cover; a file that is not root's or is group- or other-writable is refused, and the parse is strict (an unknown field, a duplicate uid or trailing data refuses it, and a refused file counts as no listing) | `k3sm/cmd/k3sm::TestRemovedScopesFileRootOwnedAndMode`, `TestRemovedScopesFileStrictParse` | pending: the KeyDelivery reconciler (lifecycle) |
| U134 | the reconciler's store interface reads a value only for an authorised delivery: its value read takes the authorisation the checks produced, and no other method returns a value | `k3sm/pkg/keystore/reconcile::TestStoreInterfaceReadsValueOnlyForAuthorisedDelivery` | pending: the KeyDelivery reconciler (lifecycle) |
| U135 | the KeyDelivery admission policy's `failurePolicy` is `Fail`, and the namespace-controller exemption admits DELETE only: the namespace controller's UPDATE of another author's object is refused | `k3sm/pkg/policy::TestKeyDeliveryVAPFailurePolicyFail`, `TestNamespaceControllerExemptOnlyForDelete` | pending: KeyDelivery authoring |
| U136 | every root verb and `doctor` line that prints annotation text strips control characters first: an owner or entry annotation carrying terminal escapes prints without them | `k3sm/cmd/k3sm::TestRootVerbsStripAnnotationControlChars` | pending: the socket operations, the KeyDelivery reconciler (lifecycle) |
| U137 | the listener refuses a sandboxed peer before the first frame: it calls `sandbox_check` on the peer's audit token through the peer-sandbox source, a constructor parameter that refuses nil, so a Pod process is refused whatever its uid (seam: peer-sandbox source) | `k3sm/pkg/keystore/socket::TestListenerRefusesSandboxedPeer`, `TestSandboxSelfCheckKeepsListenerOff`; rig leg E26 | checked: the socket listener (peer admission) |
| U138 | `--listed` fails on a duplicated U or E id: in the script's rows, its expected-row list, one mode's row list, or the design's gate and leg tables | `hack/acceptance/keystore.sh --listed` (its duplicate-id lint, `lint_unique_ids`) | pending: the typed-credential design |
| U139 | `items` required, no default, 1 to 8, unique keys, the key pattern with `.` and a `..` prefix refused, both `maxLength`s, immutable as a map (a reorder accepted, a change refused), CEL cost within budget; no `dataKey` | `apis/config/crd::TestKeyDeliveryItemsSchema`, `TestItemKeyMatchesIsConfigMapKey`, `TestKeyDeliveryHasNoDataKey`, `TestItemsReorderAcceptedChangeRefused`, `TestItemsCELCostWithinBudget` | pending: the typed KeyDelivery API |
| U140 | the `field` enum equals the credential table's union; a KeyDelivery naming `refreshToken` is refused by the schema; rig leg E31 | `apis/config/crd::TestFieldEnumEqualsCredentialTable`, `TestSchemaRefusesRefreshTokenField` | pending: the typed KeyDelivery API |
| U141 | the credential leaf: kind names, field table vectors, no refresh field, the item type, the refresh-owner vectors, closed validity, Event and `refresh_state` sets, the metadata keys; stdlib only | `apis/keystore/credential::TestFieldTableVectors`, `TestNoRefreshField`, `TestRefreshOwnerGrammarVectors`, `TestNameSetsClosed`, `TestImportsStdlibOnly` | checked: the credential names in apis |
| U142 | the CRD descriptions list the `CredentialValid` reasons and `ProjectionInvalid`, say `Ready` means delivered and that Valid, Expiring and RefreshFailing share True; every condition has `observedGeneration` | `apis/config/crd::TestKeyDeliveryReasonDescriptions`, `TestConditionsCarryObservedGeneration` | pending: the typed KeyDelivery API |
| U143 | the envelope matches committed per-kind golden vectors; unknown tag, duplicate, disorder, missing field or out-of-bound field is `ErrCorrupt`; the fuzz invariants hold | `k3sm/pkg/keystore/typed::TestEnvelopeGoldenVectors`, `TestEnvelopeRejectsUnknownTagDuplicateAndOrder`, `FuzzEnvelopeParse`; each kind's field table is strictly increasing by tag, `TestFieldTablesSortedByTag` | checked: the typed envelope |
| U144 | token and oauth require a sealed `issuedAt`/`accessIssuedAt` stamped from the clock seam; editing the `created` header changes no typed time | `k3sm/pkg/keystore::TestTypedIssuedAtStampedAndSealed`, `TestCreatedHeaderEditChangesNoTypedTime`, `TestExpiryCheckedOnSealedSeconds`, `k3sm/pkg/keystore/typed::TestExpiryOrderEnforced` | checked: the typed store |
| U145 | a relabelled typed record fails to open; kind-byte table: 6 to 0xFC and an unknown envelope version are `ErrKindUnsupported`, 0xFD and 0xFE `ErrCorrupt`; `list` shows `unsupported` | `k3sm/pkg/keystore::TestTypedKindRelabelFailsOpen`, `TestKindByteTable`, `TestListShowsUnsupportedKind` | checked: the typed envelope and the typed store |
| U146 | `rotate` and `put` over an existing entry cannot change its kind (`ErrKindMismatch`), nor can `rotate --from-version` from a version of another kind | `k3sm/pkg/keystore::TestRotateAndPutCannotChangeKind`, `TestRotateFromRefusesOtherKind` | checked: the typed store |
| U147 | token needs `expiresAt`, after its stamped `issuedAt`; oauth needs access token, access expiry, refresh token and an owner in the grammar | `k3sm/pkg/keystore::TestTypedPutValidation` | checked: the typed store |
| U148 | SSH generate uses the random seam; import accepts unencrypted OpenSSH ed25519 only; the fingerprint equals a committed `ssh-keygen -l` vector | `k3sm/pkg/keystore/typed::TestSSHGenerateAndImport`, `TestSSHFingerprintMatchesOpenSSH`, `TestSSHImportRefusesMalformed`, `k3sm/pkg/keystore::TestStoreGenerateSSHUsesRandomSeam` | checked: the typed envelope and the typed store |
| U149 | write-only, structurally: a planted refresh token appears in no result of any exported method or consumer interface, raw, base64 or URL-encoded; `Get` returns a `typed.Credential` for kinds 3 to 5; only `refresh` (and the installing `pkg/keystore`) imports `internal/refreshopen` | `k3sm/pkg/keystore::TestPlantedRefreshTokenNeverReturned`, `TestGetReturnsRedactedCredential`, `k3sm/pkg/keystore/typed::TestEnvelopeRefusalsNeverCarryRefreshToken`, `TestShortSecretNeverInRefusals`, `TestSecretTypesRedactWhenFormatted`, `TestNoUnexportedSecretField`, `TestDecodeRefusalClearsClones`, `k3sm/pkg/keystore::TestTypedPlaintextZeroedAfterSeal` | partial: every exported method of `*FileStore` and `*UserScope`, enumerated by reflection (a method neither called by hand, callable with built arguments nor allowlisted with a reason fails the test), the typed reads and the deliveries path checked (the typed store); pending: the consumer interfaces and `internal/refreshopen`'s import graph, `TestRefreshOpenerImportGraph` (the refresher) |
| U150 | `RotateIf` refuses a stale version, and a version read from an entry since deleted and put again; a rotation never changes an oauth entry's refresh owner | `k3sm/pkg/keystore::TestRotateIfStaleVersionRefused`, `TestRotateIfRefusesRecreatedEntry`, `TestRotateIfRefusesVersionBuiltOutside`, `TestRefreshOwnerFixedPerEntry`, `TestRotateIfRefusesSameNumberDifferentRecord` | checked: the typed store |
| U151 | oauth keeps current and one previous; the low-water mark is in the sealed pointer (24 bytes only after a prune, 16 means `low = 1`); crash-safe at every step, prune included (the prune cases of the crash test); a failure after the pointer flip reports the commit | `k3sm/pkg/keystore::TestOAuthPruneKeepsTwo`, `TestPointerLowWaterMark`, `TestRotateCrashAtEveryStep`; a failure after the flip returns the new version with `ErrCommitted`, `TestRotateReportsCommitAfterFlip`, and so does a failure after any write's pointer rename (the directory fsync, the floor, the prune; put, rotate and generate alike), never also `ErrCorrupt`, `TestCommitPointReported`; the floor-lag window refuses rather than unlink a newer committed version, `TestFloorLagNeverDeletesCommittedVersion`; the pointer has one canonical form, `TestPointerCanonicalForm`, the oauth retention window is checked on read, `TestOAuthRetentionWindowOnRead`, and the decoder accepts only the writer's output, `FuzzPointerPlaintext`; an oauth entry's version ceiling is 2^32 and every other kind's 2^16, `TestOAuthVersionCeiling` | checked: the typed store |
| U152 | a pruned oauth entry: List shows it healthy, Rewrap re-seals `low..current`, Delete removes leftovers, a gap inside the range is damage (to a user scope's `list` too, which checks the range for presence), a copied-back pointer is caught | `k3sm/pkg/keystore::TestListPrunedOAuthEntryNotCorrupt`, `TestRewrapHandlesPrunedOAuth`, `TestDeletePrunedOAuthEntry`, `TestGapInsideCommittedRangeIsCorrupt`, `TestCopyBackAcrossPruneCaught` | checked: the typed store |
| U153 | `--from-version` is refused for oauth | `k3sm/pkg/keystore::TestFromVersionRefusedForOAuth` | checked: the typed store |
| U154 | every `Fuzz*` target in the keystore packages has a non-empty committed seed directory | `k3sm/pkg/keystore::TestEveryFuzzTargetHasSeeds` | checked: the typed envelope |
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
| U192 | the floor's tombstones: a completed Delete buries the floor's live generation for the name (with no live record, the directory's only when its pointer authenticates under it with the master, so a planted generation buries nothing) with a delete sequence, without the master too; a later Put keeps the buried set; at most 64 buried generations a name; tombstones use at most 1 MiB of the 4 MiB floor and are pruned oldest first, never a live entry, each prune logged at Warn; a floor with no tombstones field parses, and a burial is parsed as strictly as an entry; keys floor merge carries every burial of the moved-aside floor into a restored one, burying a generation it holds live and each moved-aside live generation it does not hold live (--keep spares only the restored generation; an unmatched --keep refuses), fencing a restored generation, and recording a kept one the restored floor does not record, with a high-water mark one past the higher of the moved-aside sequence and mark (+1) that readers and the raise honour and Rotate seals above, under keystore-lock alone, reading only the data root's keystore-floor.json.pre-restore (no path; a guard file replaced during the merge refuses it), reading the restored pointers only from the root-only pre-restore.d/restored the recipe stages (pre-restore.d refused with an extended ACL; anything at the keystore directory, a symlink counted, is moved aside into pre-restore.d/planted-<unix> through directory descriptors with RENAME_EXCL and reported, a dry run moving nothing; with nothing staged a merge that would change the floor refuses), fencing above the moved-aside tree's authenticated pointer too (pre-restore.d/keystore), refusing a staged tree holding anything the store does not write (a name outside the entry-file allowlist, a non-regular file, a second link, a setuid, setgid or sticky bit, a flag, an ACL, a file over its cap, an owner but the service user or the unknown owner), dry run included, handing it to the service user through descriptors (openat O_NOFOLLOW, fstat, fchmod, fchown, fstat again; a link gained refuses it) and fsyncing every file and directory of it before the rename and moving it into place with renameatx_np RENAME_EXCL after the floor write (a failed move exits 5 and a rerun completes it; a rerun that finds the floor written words a refusal of the staged tree or of the move aside as committed and exits 5, dry run included), raising a restored record to its authenticated pointer by at most one sequence (a higher pointer is unverified and fenced), refusing an absent live floor, the live floor itself and a merge that would retire every moved-aside live record, renaming its input to keystore-floor.json.merged-<unix> (a rerun after a failed rename writes nothing and renames it; that failure exits 5), pruned and reported, refusing a write that would drop any burial, the restored floor's own included (rm's under the guard numbered above guardEraSeq, kept newer than the merged ones, the band kept at the sequence limit and renumbered back by a Delete with no guard), naming keys rm only when the floor size binds and --accept-drops (which writes it, prints each drop and exits 4) when the tombstone budget or the per-name cap does, never dropping a buried-live burial even with --accept-drops (that refusal names keys rm), removing the staged directory of each entry whose staged generation the merged floor buries or whose burial the write drops, recording before the floor write, as its commit marker, the input's and the written floor's sha256 and what it retired, buried live, kept and dropped in a root-owned keystore-floor.json.pre-restore.retired renamed with the input to keystore-floor.json.merged-<unix>.retired (a rerun finding that record and that floor, or that floor with only burials added since, never plans the floor again and reports from the record, keeping those burials and removing their staged directories, any other floor fails closed, and rm runs while the record is pending, first recording each burial its write drops in a root-owned keystore-floor.json.pre-restore.rm-dropped bound to the record, which a rerun accepts gone, and never refused for it: a record full, unreadable or unwritable is marked unusable and the rerun stops committed; a rerun after the record's rename and before the input's renames only the input), refusing --keep of an entry rm deleted after the restore, that --undo reads only when its input is the live floor to report a version the restore retired apart from one deleted since (refusing --keep on the latter, and refusing with no matching record), refusing pre-restore.d on another device than the keystore's directory, exiting 4 too when it keeps an entry, leaves one unverified (with pre-restore.d/keystore absent, each moved-aside live entry), moves a planted target aside or carries over user-scope entries without a floor check, and 5 when a directory fsync after the tree's rename fails (a restored pointer, or a moved-aside one that does not authenticate or has no master to load), --dry-run writing nothing and exiting as the merge would; while keystore-floor.json.pre-restore is in the data root Put, Rotate and Rewrap refuse, Delete refuses with no live floor, RaiseFloor raises nothing and the delivery reconciler delivers nothing (guarded delivery); a committed change whose floor write evicted a burial exits 4, and list and show warn of it and exit 0 | `k3sm/pkg/keystore::TestTombstoneKeptByPut`, `TestDeleteWithoutMasterTombstones`, `TestTombstonePrune`, `TestTombstoneNeverRefusesPut`, `TestPruneLogsAtWarn`, `TestParseFloorTombstones`, `TestFloorOpsProperty`, `TestDeleteSequenceNeverWraps`, `TestDeleteIgnoresPlantedGeneration`, `TestPerNameCapIsBackstop`, `TestDeleteWithoutMasterWarnsUnrecorded`, `TestDeleteReportsEvictedTombstone`, `TestDeleteWarnsUnrecordedWithMaster`, `TestFloorMergeSemantics`, `TestFloorMergeCapsAndPrune`, `TestFloorMergeRefusesUntrusted`, `TestFloorMergeBuriesRevokedLive`, `TestMergeFloorKeep`, `TestFloorMergeRetiresAsideLive`, `TestFloorMergeRefusesUntrustedPlace`, `TestDeleteReportsAnyEvictedTombstone`, `TestFloorHighWaterEncoding`, `TestFloorHighWaterCheckRaise`, `TestFloorMergeFencesAbandonedHistory`, `TestMergeFloorIgnoresEntryLock`, `TestMergeFloorRefusesWrongInput`, `TestPendingMergeGuard`, `TestEvictionReportedCommitted`, `TestMergeFloorRefusesUnmatchedKeep`, `TestMergeFloorRefusesDroppingItsOwnBurials`, `TestFloorMergeKeepRecordsAsideLive`, `TestDeleteNotFoundReportsEviction`, `FuzzParseFloor`, `FuzzMergeFloor`, `TestMergeFloorReadsOnlyTheGuardFile`, `TestFloorMergeBoundsRestoredRaise`, `TestGuardEraBurialSurvivesPressuredMerge`, `TestGuardEraTombstoneBudget`, `TestGuardEraBurialPerNameCap`, `TestPendingMergeDeleteNeedsLiveFloor`, `TestMergeFloorRefusesRetiringEverything`, `TestFloorMergeRefusesExistingTarget`, `TestFloorMergeFencesAboveAsidePointer`, `TestFloorMergeMovesStagedTree`, `TestFloorMergeNeedsStagedTree`, `TestMergeFloorNeverDropsBuriedLive`, `TestMergeFloorRefusesDroppingRestoredBurials`, `FuzzPlanMerge`, `TestPlanMergeKeepTwiceWritesNothing`, `TestFuzzRmReportsCapEviction`, `TestPlanMergeUnmatchedKeepRefusedFirst`, `FuzzDeleteUnderGuardAtLimit`, `TestDeleteRenormalisesStaleBand`, `TestFloorMergeRemovesGuardBuriedStaged`, `TestChownStagedRefusesShape`, `TestChownStagedRefusesACL`, `TestChownStagedRefusesForeignOwner`, `TestChownStagedRecheckSeam`, `TestChownStagedNameBound`, `TestChownStagedSetsModes`, `TestFloorMergeShapeDryRunParity`, `FuzzStagedChild`, `TestFloorMergeRemovesBuriedLiveStaged`, `TestParseRetired`, `TestFloorMergeRerunCommittedWording`, `TestFloorMergeAsideUnverified`, `TestFloorMergeSyncsStagedTree`, `TestOpenStagingRefusesACL`, `TestFloorMergeRerunAfterAcceptDrops`, `TestFloorMergeKeptOnlyWritesRecord`, `TestFloorMergePointerOnlyRefusalNotCommitted`, `TestFloorMergeRerunKeepsRetiredSets`, `TestFloorMergeRerunFloorChanged`, `TestFloorMergeUndoRecord`, `TestFloorMergeAbsentAsideTree`, `TestFloorMergeRerunAfterMoveNotUnverified`, `TestFloorMergeRemovedStagedNamed`, `TestFloorMergeMoveSyncCommitted`, `TestFloorMergeRemovesAsideBuriedStaged`, `TestFloorMergeRemovesDroppedStaged`, `TestFloorMergeRefusesTwoDevices`, `TestFloorMergeRerunAfterDelete`, `TestFloorMergeDeleteBeforeFloorWrite`, `TestFloorMergeRerunNonMonotone`, `TestFloorMergeRerunAfterRmPrune`, `TestPendingSinceReadFloorNotCommitted`, `TestFloorMergeCrashBetweenRenames`, `TestFloorMergeCrashBetweenRenamesClearsRmDropped`, `TestFloorMergeFirstRunRemovesRmDroppedStaged`, `TestDeleteUnderGuardNeverRefusedBySidecar`, `TestParseRmDroppedMark`, `TestMergeFloorRefusesKeepAfterRm`, `TestClassifyUndoDeletedSince`, `FuzzRerunPredicates`, `TestBuriedSinceFence`, `TestFloorMergeBoundsAsidePointer`, `TestFloorMergeStagedNodeBudget`, `TestStagedHoldsUserScopes`, `TestStagedPreFrameDroppedAccepted`, `TestStagedPreFrameDroppedRefused`, `TestStagedPreFrameDroppedUnknownOwner`, `TestStagedPreFrameDroppedTempNotParsed`, `k3sm/cmd/k3sm::TestKeysEvictionExitsCommitted`, `TestKeysPendingMergeGuard`, `TestKeysReadVerbsWarnEviction`, `TestKeysFloorMergeTakesNoFile`, `TestKeysFloorMergeAcceptDrops`, `TestKeysFloorMergeDryRun`, `TestKeysFloorMergeReportCodes`, `TestKeysFloorMergeMovesPlantedAside`, `TestKeysFloorMergeCommittedRerunRefused` | checked: the floor's tombstone |
| U193 | `floor --rebuild` carries the old floor forward: over an old floor holding tombstones, sequence lines and a torn last line (which the reader already skips as counted damage, so the floor served throughout), it keeps every tombstone and every key's highest sequence that parses, writes the higher of that and the sequence on disk, drops the lines that do not parse and names their count (U196 holds the other classes it drops); a tree copied back after an `rm`, a crash and a rebuild is refused as deleted, and a copied-back older record is refused; a floor that cannot be read refuses the rebuild, changing nothing | `k3sm/pkg/keystore::TestRebuildCarriesTombstonesForward` | done: the append-only files (the rebuild verb) |
| U194 | once root removes a user scope (`rm-scope`), `floor --rebuild` drops every key of that scope, live or buried, by position: the uid's lines before the floor size rm-scope recorded, keeping every line after it, so a re-minted scope whose directory is later deleted by hand keeps its tombstones and a copy-back of it is refused; a re-minted scope gets a fresh K_u, and rm-scope's record refuses the old scope key (U197); the rebuild frees the uid's lifetime key share and its keys in the global key bound | `k3sm/pkg/keystore::TestRebuildDropsRemovedScopeKeys`, `TestRebuildKeepsReMintedScopeTombstones` | done: the append-only files (the rebuild verb, after rm-scope) |
| U195 | root-run: the SF_APPEND facts measured on 2026-11-23: on a flagged file root's fchown, fchmod, rename, link, unlink and O_TRUNC open are each EPERM; chown then flag works, and root's fchown back is then EPERM; a descriptor opened without O_APPEND before the flag can neither pwrite nor ftruncate once it is set; the service user's link() of a root-owned 0600 unflagged file into its own directory succeeds, and of a file flagged UF_IMMUTABLE, UF_APPEND or SF_APPEND fails with EPERM, whether root or the service user owns it. The second probe: root's rename and RENAME_SWAP of directories holding flagged files work; once the retired log is unflagged a descriptor held from before can clear O_APPEND, pwrite and ftruncate it, and a held directory descriptor can openat it; the new canonical log refuses non-append and O_TRUNC opens with EPERM and takes an O_APPEND write; staging is EACCES; root's fclonefileat of the service user's flagged file into a root-only directory works, and the clone is root's (CLONE_NOOWNERCOPY), 0600, whole and flagged, refusing a read-write open and fchown until fchflags clears it on a read-only descriptor, after which fchown, a read-write open and ftruncate work and the source is unchanged; root's setattrlistat of ATTR_CMN_FLAGS with FSOPT_NOFOLLOW by directory descriptor and name clears uchg on the service user's FIFO and socket, and at a symlink changes the link, not its target; root's fclonefileat of the service user's flagged file carrying an extended attribute and an ACL carries the attribute and not the ACL, and cloneArchive leaves the archive with neither; and rm-scope's premise: a service-user thread cannot rename a root-owned 0700 directory into another parent it owns, can rename it within the same parent, and, with an inheritable add_subdirectory entry on the parent at creation, can move a root-created directory out, while the directory mkdirAt makes there carries no ACL (integration, a root-run row: `--root`; § "SF_APPEND, as measured") | `k3sm/pkg/keystore::TestSappndMeasuredFacts`, `TestSappndDirectorySwap`, `TestRmScopeMeasuredPremiseAsRoot` (integration, root-run) | checked as a root-run row (`--root`): the append-only files |
| U196 | floor --rebuild reads a flooded floor: it streams the old floor with no size bound and memory bounded by the reader's key bound and one line, so a floor past the steady-state reader's size bound, which the service user can reach at will, rebuilds; over-long and unparseable lines are dropped and counted, every real tombstone is kept; a present scope's lines are admitted all for keys on disk and every tombstone, whatever the share (a revocation's tombstone past the share survives), and its other live lines oldest first up to the uid's key share (excess counted past the share); an absent, unrecorded scope's tombstones per uid up to the share, uids in first-appearance order, and its live lines only once every absent tombstone is in, per uid up to the share (rest counted as absent scopes); the room the present scopes' keys on disk and tombstones leave under the key bound is split evenly between the absent scopes' tombstones and the present scopes' other live lines, a class needing less than its half giving the rest to the other, so a flood of forged lines of either class never evicts the other's lines within its half; so forged tombstones for uids with no scope, or a forged live flood for one real uid, never wedge it and every real line is kept; only the present scopes' keys on disk and tombstones past the reader's key bound (the key bound plus the revocation headroom, the bound the steady-state reader enforces) refuse, naming the scopes with the most keys and rm-scope, so real tombstones a revocation wrote into the headroom rebuild and are all kept, and the new floor never passes the reader's key bound, and rm-scope of the named scope lets the rebuild run; each removal's floor offset is bound to the floor log's device, inode and birth time it was recorded against, so rebuild never rewrites the record: a refused rebuild leaves it byte-identical and a later rebuild still drops the removed scope's lines, while a committed rebuild's new floor (a new file) gets no stale drop; a record without that whole identity drops nothing | `k3sm/pkg/keystore::TestRebuildStreamsFloorPastReadBound`, `TestRebuildDropsForgedLiveFlood`, `TestOldFloorReaderMemoryBounded`, `TestOldFloorReaderRefusesTombstonesPastBound`, `TestRebuildForgedAbsentTombstoneFlood`, `TestRebuildForgedLiveFloodOneRealUIDTrimmed`, `TestOldFloorReaderAbsentFirstAppearanceOrder`, `TestOldFloorReaderAbsentLiveAfterTombstones`, `TestOldFloorReaderPresentLiveFloodKeepsAbsentTombstones`, `TestOldFloorReaderAbsentTombFloodKeepsPresentLive`, `TestOldFloorReaderPresentLiveFloodKeepsAbsentTombsHalf`, `TestRebuildKeepsRevocationTombstonePastShare`, `TestRebuildForgedTombstoneFloodPresentUIDRefusesThenRmScope`, `TestOldFloorReaderRefusesRealScopesPastBound`, `TestRebuildRefusedLeavesRecordAndStillDrops`, `TestRebuildKeepsTombstonesInHeadroom`, `TestRebuildRefusesPastReadKeyBound`, `TestOldFloorReaderAdmitsAtMostReadBound` | done: the append-only files (the rebuild verb) |
| U197 | rm-scope lists the removed scope key's identity in keystore-removed-scopes.json in the data root, with the floor log's device, inode, birth time and byte size at the removal (root's, by temp, fsync and rename, parsed strictly, bounded), so the old scope directory copied back is refused at every open (read, put, the start step, rebuild) while a re-minted scope opens; a full record still removes the scope and rebuild keeps its floor keys; a record that does not read fails closed; a scope whose delivery record is damaged is still removed and listed, exit 4, saying its deliveries were not checked, while a transient failure to read it refuses, changing nothing; the delivery record is read against the floor, so a rolled-back authentic copy is damage, and a floor that cannot be read leaves a record naming no delivery unverified, exit 4, deliveries not confirmed; the no-key and untrusted paths, which never read it, say the scope's deliveries were not checked; a repair text names the record's mode, 0644; every name from the service user's tree in an error prints quoted with control bytes removed and labelled as not for pasting, and no text offers an action by hand: the only commands rm-scope's output holds are its own rerun line built from the integer uid, the floor --rebuild follow-up on success, and what the shared store-lock and root-file helpers print; it never prints a name from the service user's tree in a command; a system flag it leaves and a multiply-linked flagged entry it does not clear are named, with the flag and the owner, and left, and a run past its flag budget says to run rm-scope again; a refusal of a copied-back removed scope names sudo k3sm keys rm-scope user/<uid> --yes; a locking flag is cleared on any entry with one link and no system flag, whoever owns it; a flagged FIFO, socket or device is written exactly 0 by name without an open, so a name swapped for a hard link to another file never gains a flag, and the re-stat leaves a changed name for the rescan; each directory, the scope directory first, is taken from the service user (fchmod 0700, fchown to root, fchmod 0700 again, its ACL removed, then an fstat that must show root's at 0700, on the held descriptor) before any of its entries is listed, so a service-user process's create and rename in there then fail with EACCES (on macOS an entry carrying an ACL entry that allows its deletion can still be renamed out); a subdirectory another user owns, or root at another mode than 0700, or on another device, is left in place with its contents, and the removal fails naming it for reading only and its owner, stopping once it has left 16 such directories, none entered; a directory nested more than 32 below the scope directory stops it, named relative to the scope directory for reading only, nothing below it removed, no command offered; a directory is emptied a bounded batch at a time, so a huge one is removed with no count refused; an rm-scope stopped part-way names the state it left and a rerun finishes it, root-owned 0700 directories included; one that stopped after it changed something (added a key to the record, removed an ACL, unlinked an entry, took a directory or cleared a flag) exits 4, audited committed, and one that changed nothing refuses, a rewrite of a record that already listed the key counting as no change; a stop after this run added a key to the record is never a refusal; the tree is removed only while the directory held at the scope's name is root's taken leftover at 0700, or holds, read by descriptor, the scope.key rm-scope judged and listed, so another service-user scope directory renamed onto the name is refused with nothing in it taken or listed; the final rmdir keeps the emptied directory's descriptor and checks it is the directory removed, and a name moved away or holding another directory, empty or not, is reported, never as removed; a probe that fails for another cause than ENOENT is reported as a removal rm-scope could not confirm, exit 4, never as moved, and a probe it could not remove again is said; a record renamed into place whose data-root fsync fails exits 4, saying the record lists the scope but its durability is unknown, and one that fails before its rename refuses; a stop after rm-scope cleared a flag on .user still carries that note; a stop a rerun would meet the same way (a scope directory moved from its name, a planted name, another user's flag on .user, a system flag on .user, a directory that is not the judged scope, a foreign or too-deep directory, a system flag or a multiply-linked flagged entry rm-scope leaves, a take the file system does not keep, an rmdir it could not confirm) offers no rerun and no command, a scope directory absent before the walk is found absent with no advice, a directory the judge refuses is named for reading with no command and no rerun line, no text rm-scope builds says to restore a file of the service user's tree, the errors about the root-owned record keep the shared reader's wording and name nothing from the service user's tree, and a flag set again on an entry rm-scope cleared stops it saying to rerun once nothing sets the flag, with the rerun line | `k3sm/pkg/keystore::TestRemovedScopeCopiedBackRefused`, `TestRemovedScopesFullKeepsFloorKeys`, `TestRemovedScopesMalformedFailsClosed`, `TestRemovedScopesFloorSizeParse`, `TestRemoveScopeRerunFinishesPartialRemoval`, `TestRemoveScopeUnreadableDeliveryRecord`, `TestRemoveScopeTransientDeliveryReadRefuses`, `TestRemovedScopesBadNamesAcceptedMode`, `TestRmScopeHostileNameInert`, `TestRmScopeOffersNoCommand`, `TestRemoveScopeClearsUserFlags`, `TestRemoveScopeClearsForeignFlags`, `TestRemoveScopeSwappedNameGetsZero`, `TestClearScopeFlagsSocketTypeUnopened`, `TestRemoveScopeTakesEachDirBeforeListing`, `TestRemoveScopeLeavesForeignDir`, `TestRemoveScopeBatchesHugeDir`, `TestReadBatchBounded`, `TestRmScopePartialRemovalIsCommitted`, `TestRemoveScopeForeignDirCap`, `TestRemoveScopeDepthLimit`, `TestRemoveScopeFlagBudget`, `TestRemoveScopeRefusesSwappedScope`, `TestRemoveScopeDirMovedBeforeRmdir`, `TestRemoveScopeSharedDirFlags`, `TestRmScopeRecordFsyncFailureIsCommitted`, `TestRmScopeErrorTextsOfferNoCommand`, `TestRemoveScopeFlagResetThenRerunFinishes`, `TestRemoveScopeRmdirProbeFailures`, `TestRmScopeFailureAfterWriteIsCommitted`, `TestRmScopeRecordErrorsNameNoServiceUserPath`, `TestRmScopeRolledBackDeliveriesIsNotExitZero`, `TestRmScopeUnverifiedDeliveriesIsNotExitZero`, `TestRmScopeKeylessPathsSayDeliveriesUnchecked`, `TestRmScopeCommandSet` | done: the append-only files (rm-scope) |
| U198 | the log reader charges at most maxRevokeUIDs plus 64 distinct uids past the hard cap; forged lines of more distinct uids are sticky damage, with no growth of its per-uid map | `k3sm/pkg/keystore::TestAuditReaderBoundsChargedUIDs` | done: the append-only files (the reader) |
| U199 | floor --rebuild that dropped any line or key exits 4, lists the counts by class and audits committed; doctor's keystore-floor row warns of floor damage naming floor --rebuild | `k3sm/cmd/k3sm::TestKeysMaintenanceVerbs`, `TestDoctorChecksTable` | done: the append-only files (the rebuild verb, doctor) |
| U200 | a second link on a root-written data-root file (the removed-scopes record, the maintenance marker, the floor acknowledgement) is a Warn, never a refusal: each still reads, judged on type, owner, mode, flags and ACL, so a link any local user can make blocks no scope open, verb or acknowledgement; a flag on one is refused with, as the first repair, sudo chflags 0 on that exact root-owned path, and restoring from a backup (or install, for the marker) only second | `k3sm/pkg/keystore::TestRemovedScopesSecondLinkReads`, `TestMarkerSecondLinkReads`, `TestFloorAckSecondLinkReads`, `TestRootFileModeStillJudged`, `TestRootFileFlagNamesChflags`, `TestMaintenanceJudgesMarkerAndStale` | done: the append-only files (root-written files) |
| U201 | root-run: the service user link(2)s root's removed-scopes record and floor acknowledgement into its own directory; the record still reads and rm-scope still writes it, and the acknowledgement still lifts the damage it acknowledged (integration, a root-run row: `--root`) | `k3sm/pkg/keystore::TestRootFileServiceLinkReadsAsRoot` (integration, root-run) | checked as a root-run row (`--root`): the append-only files (root-written files) |
| U202 | a maintenance verb that fails after its RENAME_SWAP is committed, never refused: it exits 4, audits committed and still prints its report (a rebuild's drop counts); a later run of the other verb, or install, that finds a marker recording a committed run prints its saved report to stderr as an earlier committed run that was not reported and audits it (op that verb, result committed) before it replaces or removes the marker; when that report shows drops the text says the earlier run dropped N lines and the verb exits at least 4, except install, which keeps its exit codes and adds to the line that the drop counts are kept in keystore-maintenance-runs, which doctor reads, or, when that record does not read or write, that they are in that line only and why, the audit log holding a committed line for that run, and to copy the line down; a same-verb rerun that only prints the saved report says the earlier run committed and this run did not rebuild; doctor WARNs on a standing marker, naming its verb; a marker whose swap never committed reports nothing; a committed run whose report drops any line or key, its own or a saved one a rerun, the other verb or install reports, appends one record (run id, verb, UTC time, the drop counts by reason, the new log's inode) to keystore-maintenance-runs in the data root before the marker goes, root's 0644 through the data-root descriptor, the newest 64 kept, parsed strictly, and a record that does not read is reported and left as found; doctor's keystore-maintenance-runs row counts the lossy runs | `k3sm/pkg/keystore::TestSwapFailureAfterCommitIsCommitted`, `TestEarlierCommittedRunReported`, `TestStandingMaintenanceNamesVerb`, `TestSwapRerunFromEachStep`, `k3sm/cmd/k3sm::TestKeysMaintenanceCommittedAfterSwap`, `TestKeysRebuildRerunSaysEarlierRun`, `TestDoctorKeystoreMaintenanceNamesVerb`, `k3sm/pkg/install::TestKeystoreFilesReportsCommittedMarker`, `k3sm/pkg/keystore::TestMaintenanceReportDurable`, `k3sm/cmd/k3sm::TestDoctorKeystoreMaintenanceRow`, `k3sm/pkg/install::TestInstallRecordsLossyEarlierRun`, `TestEarlierRunDropHint` | done: the append-only files (the swap) |
| U203 | rm-scope of a scope directory with no scope.key, for a uid the record does not list, removes the tree but exits 4, audited committed, saying it was removed without being listed because its key file was absent, so a copy of its directory put back by the service user opens again, held only to the scope's floor lines, which are kept; it never says the record is full; a scope.key the judge refuses only for a second link or a mode wider than 0600 that still authenticates under the master is listed, exit 4 noting the link count or mode, and a copy put back is refused; one whose content does not parse is removed unlisted, saying its key file could not be trusted, and floor --rebuild then runs; a full record also exits 4, with its own text; a scope directory already gone when rm-scope opens it is reported as found absent, not removed, exit 4 when this run added a key to the record and a refusal otherwise, also when the fsync of .user that follows fails; a directory root owns at 0700 at the name (another uid's leftover an earlier run took and renamed within .user, or a root-owned directory an ACL entry granting add_subdirectory let the service user move there from another parent; never served) is always removed, whatever scope.key it holds, its ACL removed first: one that opens as this uid's is listed first, or the record rewritten for durability, and the result says listed (exit 0) only when the key read in the held directory is in the record, the directory carried no ACL and its key was listed before this run, and never on the judged path, where it says the directory rm-scope judged was not at its name and never that the scope's directory was removed; otherwise exit 4 saying how many keys the record lists for the uid; mkdirAt removes an inherited ACL from a directory a root verb makes; on the judged path exit 0 needs the judged key in the record and scope.key read again after the take as the same key; rm-scope's judge reads through the mode of .user and of the scope directory, so the principal being revoked cannot veto it with a mode; a service user's directory is accepted on these paths only when it holds what its path judged (no scope.key, or one that cannot be trusted) or a key already listed for the uid, never a valid unlisted scope.key; scope.key goes last on every path, and a take stopped at any step, its first fchmod included, leaves a directory a rerun finishes, its text carrying the rerun line; every exit 0 also needs the newest-scope rule: the user-scope floor, read through rebuild's root-judged reader, holds no line of the uid written after the listing of the key that proves the run (a floor rebuilt since counts every line of the uid, and one that cannot be judged is never exit 0), so a directory holding a kept copy of a listed key, or a parked leftover, put at the name with the live scope renamed away is exit 4 with the live scope untouched, while a genuine rerun still exits 0; more than one sequence-1 delivery-record line of the uid in the floor since its last listing before the run (its scope created more than once) is exit 4 too, saying so, the scope at the name removed and listed and a scope moved away untouched, while exactly one such line, also after an earlier listed removal, still exits 0, and a torn or over-long line before a mint's line does not hide it; on the no-key and untrusted paths the directory held at the name must be the one the judge opened (device and inode), else it is refused with nothing taken; rm-scope reads through the mode of keystore/ too; a stop after it removed the ACL of a root-owned leftover is committed | `k3sm/pkg/keystore::TestRemoveScopeMissingKeyUnlistedCommitted`, `TestRemoveScopeUntrustedKeyUnlisted`, `TestRemoveScopeRerunFinishesPartialRemoval`, `TestRemovedScopesFullKeepsFloorKeys`, `TestRemoveScopeRerunAcceptsOwnLeftover`, `TestRemoveScopeRerunFinishesAnyTakenLeftover`, `TestRemoveScopeRerunRefusesServiceUserLeftover`, `TestRmScopeListedNeedsThisKey`, `TestRmScopeAbsentAtOpenIsNotRemoved`, `TestRemoveScopeTakeStopAtEachStepRerunFinishes`, `TestRmScopeErrorTextsOfferNoCommand`, `TestRemoveScopeRootLeftoverWithACLIsUnproven`, `TestRemoveScopeRootLeftoverUnlistedKeyIsNotExitZero`, `TestRmScopeDirectoryModeCannotVeto`, `TestRmScopeJudgedProofNeedsJudgedKey`, `TestMkdirAtStripsInheritedACL`, `TestRmScopeDecoyOfListedKeyIsNotExitZero`, `TestRmScopeParkedLeftoverIsNotExitZero`, `TestRmScopeGenuineRerunStillExitsZero`, `TestRmScopeRebuiltFloorCountsEveryLine`, `TestRmScopeUnjudgedFloorIsNotExitZero`, `TestRmScopeTwoMintsSinceListingIsNotExitZero`, `TestRmScopeOneMintSinceListingExitsZero`, `TestRmScopeTwoMintsAfterListedRemovalIsNotExitZero`, `TestRmScopeHostileLineBeforeMintDoesNotHideIt`, `TestRmScopePinsJudgedDirectory`, `TestRemoveScopeACLStrippedThenStopIsCommitted`, `k3sm/cmd/k3sm::TestKeysRmScopeUnlistedExitsCommitted` | done: the append-only files (rm-scope) |
| U204 | floor --rebuild bounds what it collects from disk: it checks the keys and entry names of the scopes on disk against the key bound while collecting, stops once they pass it and refuses before reading the old floor, naming the scopes with the most entries and rm-scope, changing nothing; the scope walk is bounded by the listing bound | `k3sm/pkg/keystore::TestRebuildRefusesDiskPastBound` | done: the append-only files (the rebuild verb) |
| U205 | install clears a user flag on keystore-run/ on its judged descriptor before any chmod or chown, and makes the chmod and chown only when the mode or owner is not already right, so the service user cannot wedge install with uchg on the directory it owns | `k3sm/pkg/install::TestKeystoreRunDirClearsUserFlag` | done: the append-only files (install) |
| U206 | root-run: the service user sets uchg on keystore-run/, which makes root's chmod fail EPERM; install clears the flag first and finishes, leaving the directory the service user's 0700 with no user flag (integration, a root-run row: `--root`) | `k3sm/pkg/install::TestKeystoreRunDirUserFlagAsRoot` (integration, root-run) | checked as a root-run row (`--root`): the append-only files (install) |

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
| E24 | first, with the server running, the operator, as the service user (`sudo -u _k3sm`), runs a program that is not k3sm and tries to unlink `keystore-sock/keys.sock`, to bind a socket at that path and to bind a socket at a new name in `keystore-sock/`; then, with the listener stopped by the maintenance marker, a native Pod execs the real installed `/Library/k3sm/k3sm` and that process tries the same bind; in the deny-plus-pin fallback only, the service-user program binds `keys.sock` while the listener is stopped and the user runs `k3sm keys list` and `k3sm keys put user/<me>/e2e-pin` | the service-user unlink and the bind of a new name each fail with `EACCES`, the bind of `keys.sock` fails with `EADDRINUSE` (the name is root's and stays in place), and `keys.sock` is still launchd's; the bind from the Pod gets `EPERM` and no socket appears; in the fallback, the CLI refuses each before writing a frame, naming the server pin, and the stand-in receives no bytes past the connect; after the marker goes, the real server is accepted | yes | the root-owned socket directory (U104): the service-user program replaces `keys.sock`; the server pin (U69): the CLI talks to the stand-in; the Pod bind deny (U16): the installed binary in a Pod binds `keys.sock` |
| E25 | (helper variant only) a native Pod tries `connect(2)` to the floor helper's socket, and the login user and a non-k3sm service-user program each send it an `append` | `EPERM` for the Pod; the helper refuses the user by uid and the program by the pin, and no line is appended | yes | the helper pin (U70): a line from an unpinned peer is appended |
| E26 | a native Pod on a test build whose Pod profile omits the keystore deny stanza (restored at the end) tries `connect(2)` to `keys.sock` | the listener refuses the connection before any frame, since the peer is sandboxed, and writes a `refused` line | yes | the sandboxed-peer refusal (U137): the Pod's connection reaches the frame reader |
| E27 | on macOS 26 and 27, a native Pod calls `launch_activate_socket` for the server's socket name, and the server's activated descriptor is read | the Pod gets `ESRCH` with no descriptor and nothing in it can accept on `keys.sock`; launchd set `FD_CLOEXEC` on the activated descriptor | yes | launchd answering a Pod's `launch_activate_socket` with `ESRCH` and setting `FD_CLOEXEC` on the activated descriptor, measured on macOS 26 and 27 (U122) |
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
