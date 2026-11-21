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
every `keystore-*` name in the data root and the whole `keystore-run/` tree; the data-root
denies are used, not `DaemonTreeSubdirs`, because a node's Pod root can differ from its data
root. Both files are root 0644, so a local login user can still read them (residual 11). Whether a Pod can read Phase A's two data-root files
before that change is `[K0 leg 4: pending]`; the denies land either way. And the user scope
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
  master key, to any verb, and no verb takes one as input.
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
  always passes a freshly minted key.
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

The file is bounded at 4 MiB, on read and on write. A floor write whose result would be
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
  leaves (`current` written, floor not yet), and the state after a Delete. The pointer is
  accepted if it authenticates, and the next root-run verb records its sequence and
  generation. The residual is a stale backup of a deleted entry restored under the same
  name: it is accepted, which is the deliberate-restore case the procedure under "Backup and
  snapshots" already covers, and it reopens nothing the generation check (G4) does not
  already refuse for an entry that was re-created.

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
- **Delete:** remove `current`, then the entry directory, then the floor entry.

**A deleted entry put back is accepted in this phase.** A completed Delete removes the
name's floor entry, so nothing records that the name was deleted. An old copy of the deleted
entry's directory, put back before any new Put of the name, therefore authenticates, is
accepted by every reader, and is recorded by the next root verb's raise. The floor refuses
such a copy (the generation refusal) only once a Put after the Delete has recorded a new
generation for the name. This is accepted for this phase: putting a directory back under
`keystore/` already takes a writer the floor does not defend against for an absent name,
and the result is the entry as it stood before its Delete, not a forged value. Closing it
needs a tombstone, a floor record that the name's last generation was deleted, which is
left to a later change.

A crash after the pointer flip but before the floor write leaves the floor one behind the
pointer, which the rule above accepts (pointer at or above floor). So that the lag does not
become a window, **Put, Rotate and `RaiseFloor` begin by raising each entry's floor to its
authenticated pointer's sequence**, under the lock, and so does Delete when the master
opens. Delete must work without the master, and with none it raises nothing: it changes
only its own entry's floor. The read verbs (`k3sm keys list` and `show`) take no lock that
writes, so they raise the floor by calling `RaiseFloor` at their start; until the CLI that
does so lands, a floor that lags its pointer is raised by the next write verb or
`RaiseFloor`, and readers meanwhile accept the lag. A floor entry for a name with no
directory (a crash during Delete) is harmless and is overwritten by a later Put.

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

Two kind bytes are reserved for user scope: `0xFE`, a wrapped scope key, and `0xFD`, a sealed
per-user delivery list. No record carries either yet, and a reader refuses them, like every
kind byte not in "Record encoding", as `ErrCorrupt`. The entries'-directory name `.user` is
reserved for user scopes too, and nothing creates it yet. The first-Put mint counts it as an
entry, whatever its type, so a missing master with only `.user` present is
`ErrMasterMissing`, never a new master. Rewrap refuses with `ErrScopeUnsupported`, writing
nothing, while `.user` exists, whatever its type: this build cannot re-wrap user scopes, and a
master rewrapped under them would leave them unreadable. The refusal names the reserved path,
and says that a `.user` that is not a user scope must be removed by root. A user scope's store, its own key wrapped by the master, its
non-root API, RBAC, delivery and on-disk location are specified under "User scope"; the
scope is in the format now so that adding one needs no format change.

Amended by the user scope: the user-scope store writes kind `0xFE` records (`scope.key`)
and creates `.user`; the change that adds the sealed delivery record writes kind `0xFD`.
The same change that adds the delivery record re-wraps scope keys in Rewrap and lifts the
`ErrScopeUnsupported` refusal; every build before it keeps the refusal, so a rollback to one
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
`v1`), and the next Put of the name discards it and starts over. A directory with no `current` that holds
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
- Every verb that writes the floor also takes `flock(2)` on the data root directory itself,
  opened `O_NOFOLLOW|O_DIRECTORY` and judged root-owned and not shared on that descriptor,
  after `keystore/.lock` and with the same bounded wait. Under it each verb re-reads
  `keystore-floor.json` and applies only its own change to what it read (Rotate and the
  start of a verb raise a sequence of the same generation, Put sets sequence 1 for a new
  generation, Delete removes the entry only if it records the deleted generation), holding
  the lock through the rename and the directory fsync. This lock defends against a writer
  under a swapped `.lock` writing the floor; it does not stop racing entry files under a
  swapped `.lock`. The data root is root:wheel 0755, so any local process able to open it,
  not only the service user, can take this lock and hold it. A root verb that writes the
  floor then fails with the lock timeout after the bounded wait; while the lock is held,
  Delete and Rotate fail too, so a compromised secret cannot be removed or replaced until
  the holder lets go. That is a denial of
  service against the root write verbs and nothing more: holding the lock writes nothing,
  so the floor, the entries and the readers (which do not take it) lose no integrity.
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
root-owned addition is `keystore-run/maintenance`.

### Rewrap

Rewrap re-seals every record under a new master. It is `k3sm keys rewrap`, root-run: the
verb mints a new 32-byte master from `crypto/rand`, takes the exclusive lock, and runs the
steps below. "A crash leaves nothing unreadable" needs the *records*, not only the two
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
- *A `.user` created during the run* is caught by one more check, right before step 5: the
  Rewrap stops with `ErrScopeUnsupported`, the master not swapped and `master.next` still
  agreeing, every record readable, and a rerun with the same key completes it once `.user`
  is gone. This refusal, and the `.user` refusal in the list below, are lifted by the change
  that re-wraps scope keys ("User scope", "Rewrap of scope keys").
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

The verbs `sudo k3sm keys put|list|show|rotate|rm|rewrap|deliver`, modeled on
`cmd/k3sm/secretsencrypt.go`'s dispatch (a `flag.FlagSet` per verb, a fixed usage string,
named exit codes). The verb for declaring a delivery target is the maintainer's ruling:
beside the existing subcommands, as k3s does with `k3s secrets-encrypt`, so one place
validates input and the store's layout stays private.

Amended by the user scope: names are scope-qualified from the verbs' first change. A root
verb names `system/<name>` (`sudo k3sm keys put system/signer-key`); `<name>` below is that
qualified form, and the part after `system/` keeps the entry-name rule above. The verbs
change also adds `rotate --from-version N`. The non-root path, the root maintenance verbs
and `k3sm keys exec` are under "User scope".

```
put <name> [--kind ed25519|opaque] [--in FILE|-]
      Create at version 1. Value from --in or stdin ("-", the default), never an
      argument. --kind defaults to opaque; ed25519 is validated as a 32- or
      64-byte key on the way in. Creates the master on first use.

list
      One line per entry: name, kind, current version, created, fingerprint.
      Values never printed. An entry that cannot be opened prints "corrupt" and
      the command exits 1 after listing the rest.

show <name> [--version N] [--reveal]
      Metadata only by default. With --reveal, stdout carries exactly the
      stored bytes and nothing else: no trailing newline, no encoding, no
      label; no metadata is printed in that mode, so a pipe sees only the
      value. An opaque value comes back at its stored length and an Ed25519
      value at exactly 32 or 64 bytes, which is what `rotate` accepts, so
      `show --reveal` into `rotate --in -` is a byte-exact round trip. When
      stdout is a terminal the verb still writes the raw bytes; it does not
      add a newline for the operator's prompt.

rotate <name> [--in FILE|-] [--from-version N]
      A new version from the same value source as put; flips current. Refuses
      a name that does not exist. With --from-version N the new version holds
      version N's bytes, copied inside the store: no value leaves it.

rm <name> [--yes]
      Deletes every version. Irreversible; refuses without --yes.

rewrap
      Mint a new master and re-seal every record under it. Takes no key and no
      value. Prints that entry backups taken earlier no longer open.

deliver <name> --namespace NS [--secret NAME] [--data-key KEY] [--remove]
      Declare (or, with --remove, withdraw) delivery of an existing entry as
      a Secret. Refuses a name that does not exist. Warns when secrets
      encryption is off on this data root.
```

Exit codes: 0 success, 1 refused (the sentinel's message), 2 bad usage — the same
three-value shape `secrets-encrypt` uses. Every verb in this list requires root (the
non-root path is under "User scope"). Value input is
`--in FILE` or stdin only, never an argument — argv is visible to every local user via
`ps` and lands in shell history. Opaque values are capped at 64 KiB; Ed25519 values are
checked against the two valid lengths exactly at Put time.

## Delivery reconciler

A reconciler beside the embedded add-on reconciler in `pkg/addons`: converges one
labelled Secret per declared target, never LISTs, never prunes anything it did not itself
apply, log-and-continue on a per-target failure (the same posture `pkg/addons/doc.go`
already documents and justifies).

**Target declaration.** `k3sm keys deliver` writes `/var/lib/k3sm/keystore-delivery.json`,
root:wheel 0644, atomically (temp-and-rename), and nothing else writes it:

```json
{"version": 1, "targets": [
  {"entry": "system/signer-key", "namespace": "payments", "secretName": "signer-key", "dataKey": "private.key"}
]}
```

`entry` is the scope-qualified name (amended by the user scope's naming rule: the file only
ever names `system/` entries, since a user entry reaches a namespace only through a
`KeyDelivery`). `secretName` defaults to the entry name without its `system/` prefix and
`dataKey` to `value`. The file is root-owned
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
client is narrower than the client allows: Get, create and update of one named `Opaque`
Secret per declared target, labelled as below, and nothing else — no list, no delete, no
other kind, no Secret it does not own. The set of principals who can cause a write stays
{root on the node} because only root can edit the declaration. A bounded ServiceAccount in
the manner of `kube-system/k3sm-manifests` would need a new Role granting Secret write,
which widens what the control plane can do; Phase A does not add one. This paragraph holds
for the root-file delivery. The user scope's `KeyDelivery` reconciler is separate and
differs on purpose: it deletes the Secrets it owns when authority is lost, and an unbound
ClusterRole ships for admins to bind ("User scope", "KeyDelivery").

**Ed25519 encoding in the Secret:** the stored seed or expanded key, base64 under
`dataKey` exactly as Kubernetes already base64-encodes every Secret `data` value — no PEM
wrapping, no bundled public key.

**Ownership label:** `k3sm.io/keystore-delivery: <entry-name>`, distinct from
`k3sm.io/managed` (reusing that label would make this reconciler's Secrets
indistinguishable from the embedded add-on set's objects for "which reconciler may touch
this," the exact hazard `pkg/addons/doc.go` warns a label-selector prune into). Ownership
is checked by reading the existing Secret first: present and labelled for this entry name
→ update; present without the label or for a different entry → left alone, skipped with a
logged reason, never forced.

**Re-delivery on rotation:** the sweep compares the target's current version
(`Store.Current`) against the version recorded in the Secret's own
`k3sm.io/keystore-version` annotation; a mismatch re-applies `data` and bumps the
annotation — content-derived, like the embedded reconciler's own checksum-skip.

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

The verbs change also adds `sudo k3sm keys rotate system/NAME --from-version N`, which
writes the same new version without the value leaving the store (row U1); the pipe stays
the recipe G21 checks.

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
creates any keystore file, and the API is tagged before KeyDelivery authoring opens.

Facts only a spike on the lab rig can settle are marked `[K0 leg N: pending]` where they
apply; "Facts pending the rig spike" lists them. A marker is replaced by a dated amendment to
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
  outcome is "a person stores a credential without sudo and only their namespaces' Pods
  receive it". The end-to-end rig gate (the legs under "Rig legs") is its tracer and the only proof of that
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

**The entry grammar lives once**, as the OpenAPI `pattern` on `spec.entry` in the `apis` CRD:

```
^(system|user/(0|[1-9][0-9]{0,9}))/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$
```

The admission policy's CEL cites the same string, the Go resolver uses the exported constant,
and one shared vector table in `apis` tests all three (U11, U19, U40).

### On-disk layout

Phase A's paths are unchanged. Added:

```
/var/lib/k3sm/                          data root, root:wheel 0755
  keystore-floor.json                   Phase A: root 0644, system floor; now Pod-denied
  keystore-delivery.json                Phase A: root 0644, root-declared deliveries; now Pod-denied
  keystore-user-floor.log               NEW: the user-scope floor, append-only
  keystore-audit.log                    NEW: the audit log, append-only
  keystore-audit.log.1                  NEW: the previous audit log after `audit --rotate`
  keystore-run/                         NEW: service user 0755, the socket's directory, Pod-denied
    keys.sock                           srw-rw-rw-: access is decided by peer credentials
    maintenance                         NEW: root 0644, present only while a maintenance verb runs
    user-floor.new, audit.new           NEW: staging files of `floor --rebuild` and `audit --rotate`
  server/                               already Pod-denied
    cred/keystore-master/master …       Phase A, unchanged
    keystore/                           Phase A: 0700, service user
      .lock                             Phase A: the one store lock, also taken by user-scope operations
      <name>/ generation v1 … current   Phase A: system entries, unchanged
      .user/                            NEW: 0700, service user (the reserved name)
        <uid>/                          NEW: 0700, service user, one per user who has stored anything
          scope.key                     sealed record, kind 0xFE: the user's scope key, wrapped
          deliveries                    sealed record, kind 0xFD: per delivery, its UID and target digest
          <name>/ generation v1 … current  same shape as a system entry, sealed under the scope key
```

The owner and mode of the two logs depend on the floor variant ("The user-scope floor"): with
the append-only flag they are the service user's, mode 0600, flagged `sappnd`; with the floor
helper they are root's, mode 0600. K0 picks; dated amendment.

`.user` is a dot name, so a Phase A build's `List` skips it, and every build before the
scope-key Rewrap refuses Rewrap while it exists. The run directory is not reused for the
socket: it is 0700 (`RunDirMode`), so a login user cannot reach a socket there, and the mesh
key directory already holds the name `keys`, hence `keystore-run`.

### Key hierarchy

| key | made by | stored | derived or wrapped by | used for |
|---|---|---|---|---|
| master `M` | the first root `put` (Phase A) | `cred/keystore-master/master` | none | HMAC only, under fixed labels |
| system seal and fingerprint keys | derived | nowhere | `HMAC(M, label ‖ 0x00 ‖ "system")` | system records |
| scope-wrap key `W` | derived | nowhere | `HMAC(M, "k3sm-keystore-scope-wrap-v1")` | sealing each `scope.key` |
| scope key `K_u` | the first operation on that user's scope, 32 bytes from `crypto/rand` | `.user/<uid>/scope.key`, a kind-0xFE record sealed under `W` | none | HMAC only |
| user seal and fingerprint keys | derived | nowhere | `HMAC(K_u, label ‖ 0x00 ‖ "user/<uid>")` | that user's records and their opaque fingerprints |
| delivery-record key | derived | nowhere | `HMAC(K_u, "k3sm-keystore-deliveries-v1" ‖ 0x00 ‖ "user/<uid>")` | the `deliveries` record |

The `scope.key` record uses the Phase A encoding with AAD scope `user/<uid>`, name `scope`,
version equal to the key epoch (1), and **generation equal to the account's 16-byte
GeneratedUID**.

- **The GeneratedUID binding** closes a recycled uid. Before trusting `scope.key`, the store
  reads the uid's live GeneratedUID with `mbr_uid_to_uuid` and refuses with
  `ErrScopeOwnerChanged` when it differs from the record's generation. A deleted account whose
  uid is reused opens nothing of the old account's. Root removes such a scope with `sudo k3sm
  keys rm-scope user/<uid> --yes`.
- **The lookup has a deadline.** It goes through the GeneratedUID-lookup seam with a deadline
  of 2 seconds; a timeout or an error fails closed with `ErrScopeOwnerUnknown`, and nothing in
  that scope opens. Whether the GeneratedUID is stable across a server restart, and how long
  the cold lookup takes (which sets the deadline), is `[K0 leg 3: pending]`.
  `mbr_uid_to_uuid` joins k3sm's SPI symbol canary (U7).
- **Fingerprints are per scope**, so equal values in two users' scopes have different
  fingerprints, and `list` is no equality oracle across users (U9).
- **Who can hold which key.** Root and the service user can read `M`, hence `W`, hence every
  `K_u`: "a process that holds the master has the keystore" stands. A copy of `.user/<uid>/`
  without the master opens nothing, and neither does a copy of one user's records with its
  `scope.key` (U8).

**Rewrap of scope keys.** The change that adds quotas and the delivery record extends
Rewrap's two-phase procedure with one class of record: each `scope.key`, re-sealed under the
new `W`. User records stay sealed under their `K_u`, byte for byte unchanged, and the run is
resumable at every step as G12 requires (U12). Until that change, Rewrap refuses with
`ErrScopeUnsupported` while a `.user` directory exists (U5), which is what keeps a rollback
to an earlier build from orphaning user scopes. A per-user re-key (a new `K_u`, re-sealing that
user's records) is not part of this design.

### Quotas

Each user scope holds at most 256 entries and 16 MiB of sealed records. Over either, `put`
and `rotate` answer `ErrQuota`; `rm` still works (U13). Phase A's unbounded retention stays
for the system scope.

### The user-scope floor

Phase A's floor is root-owned and written only by root verbs ("Pointer sequence and floor").
User-scope writes run in the server process as the service user, which cannot write a
root-owned file, and a floor in the service user's tree would reopen the copied-back pointer
residual the maintainer did not accept. So the user-scope floor is an append-only log the
service user can only add to.

- **Lines.** The log holds `(scope, name, generation, seq)` lines. A reader takes, per
  `(scope, name)`, the highest `seq` among the lines whose generation matches the entry's, so
  the floor can only rise. A copied-back older `current` is refused with Phase A's floor
  message, wrapping `ErrCorrupt` (U20).
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
     widens nothing `[K0 leg 1: pending]`. The kernel securelevel (`sysctl kern.securelevel`)
     and whether root can clear the flag at it are recorded too `[K0 leg 1: pending]`.

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
- **The flag is checked, not assumed** (flag variant). The server reads `st_flags &
  SF_APPEND` on both logs at start and at every `doctor` run, through the chflags flag source,
  and refuses to start the listener if either flag is clear (U21).
- **Root maintenance verbs.** `sudo k3sm keys floor --rebuild` (the restore procedure) and
  `sudo k3sm keys audit --rotate` run as root only. Each writes `keystore-run/maintenance`,
  waits for the listener to stop (it closes connections and unlinks `keys.sock` when it sees
  the file), takes the store `.lock` exclusively, then **creates and flags the new file before
  it touches the old one**. Rebuild writes `keystore-run/user-floor.new` from the
  authenticated pointers, sets `sappnd`, clears the old file's flag and renames the new one
  over it; rotate does the same through `keystore-run/audit.new`, renaming the old log to `.1`
  and flagging it again. Staging files live inside `keystore-run/`, never loose in the data
  root, so a staging name is denied by the `keystore-run/` tree deny whatever it is called
  ("Pod denies"). A crash
  leaves either the old flagged file or the new flagged file at the canonical path. The only
  unflagged moment is the old file's, between its `chflags nosappnd` and the rename, under the
  exclusive lock with the listener stopped; whether a rename over an `sappnd` target needs that
  clear at all is `[K0 leg 1: pending]`. The verb removes `maintenance` last (U22). Rebuild is
  the user-scope twin of Phase A's "remove `keystore-floor.json`, then run any root verb".
- **Size caps.** Each log has a soft cap (`keystore.logSoftCap`, default 64 MiB) and a hard cap
  (`keystore.logHardCap`, default 256 MiB). Past the soft cap `doctor` shows the size and the
  rotate hint; past the hard cap the server refuses every mutating user operation with
  `ErrLogFull` until root rotates or rebuilds (U24).
- **Per-uid fairness.** The logs are shared, so one user must not be able to fill them for
  everyone. Each uid gets a budget in each log, a fixed share of that log's hard cap. The
  server counts each uid's bytes per log from the log at start and on every append. A uid past
  its share has its own mutations refused with `ErrLogFull`; every other uid is unaffected and
  keeps its own share. The hard cap above still bounds the whole log. Lines written for root
  verbs and for the reconciler are not charged to any uid (U51).
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
- **Fail closed.** The line is written before the reply. If an append fails, mutating
  operations are refused, and so are the reads (`list`, `read-for-exec`, `deliveries`), until
  an append succeeds (U32).
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
  user. A service-user process outside Seatbelt can append forged lines, because it shares the
  trust domain with the master; a hash chain would not stop that writer, so there is none.
- `audit --rotate` moves the log aside under the maintenance procedure above.

### The socket

**Listener.** The k3sm server process, as the service user, on server nodes only, and only on
a single-server cluster ("Single-server clusters only"), listens on
`/var/lib/k3sm/keystore-run/keys.sock`. A worker node runs no listener (E18).

**Lifecycle.**

- The listener runs in a supervised goroutine with `recover`. A panic or accept error is
  logged, the socket closed and the listener restarted with backoff from 1 second to 5
  minutes. **A listener failure never takes down the apiserver or kine** (U29).
- At start it unlinks a stale `keys.sock` only after an `lstat` shows a socket owned by the
  service user; anything else at that path is refused with a Warn.
- Each request waits for the store `.lock` at most 2 seconds; a timeout fails that request
  (`ErrBusy`), not the server.
- While `keystore-run/maintenance` exists the listener stays down.
- **Upgrade visibility.** If the directory or either append-only file is absent, wrong or
  unflagged, the listener does not start: fail fast, no fallback. The server logs a Warn naming
  `sudo k3sm install` once at start and again on every listener retry; `k3sm doctor` shows
  "keystore user scope: off (<reason>); run `sudo k3sm install`"; and the CLI's connect error
  names `sudo k3sm install` (U31, U38, E15).

**Peer identity.** At accept, `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` on the connected
descriptor gives the peer's **effective uid at connect time**, and that is the authority. A
setuid binary that connects therefore acts as its effective uid (residual 7). `LOCAL_PEERPID`
is read for the audit line only and is advisory. The read sits behind the peer-credential
source, in a `*_darwin.go` file; it is a deliberate leaf copy of about 40 lines, because the
two existing copies (in darwin-net's `pkg/netd` and runtimed's `pkg/sandbox`) are unexported
in their repos and `apis` cannot import `x/sys`, and the file cites both. That
`LOCAL_PEERCRED` reports a non-root login uid on the server side, for a socket in a service-user
0755 directory under the root-owned data root, is `[K0 leg 2: pending]`.

**Eligible peers** are uids of 501 and above that are not the service uid. Refused before any
frame is read: uid 0 (root uses the direct-file verbs, as in Phase A), the service uid (every
native Pod shares it) and every uid below 501 (system accounts) (U26, E6).

**The client's checks are advisory.** The CLI opens the socket through an `os.Root` on the
data root, checks by realpath that `keystore-run/` is the service user's under the root-owned
data root, then reads the server's uid off the connected descriptor (`LOCAL_PEERCRED` from the
client side). **The connected-descriptor peer uid is the authority in both directions**: a
value is never written to a socket whose peer is not the service user, whatever the path
checks said (U36). That `LOCAL_PEERCRED` reports the service uid on the client side
is `[K0 leg 2: pending]`.

**Protocol `k3sm-keys/1`.** Internal, not a public API; the public interface is the `k3sm
keys` CLI, which other programs call as a subprocess with the value on stdin.

- A frame is a 4-byte big-endian length (at most 128 KiB), a 1-byte type, a length-prefixed
  JSON header (at most 8 KiB, never a value) and an optional length-prefixed binary value.
- **Strict frames, tolerant headers.** An oversize frame, an unknown frame type or a missing
  `HELLO` closes the connection; unknown header fields are ignored (U27).
- The first frame is `HELLO {"proto":"k3sm-keys","min":1,"max":1}`. The server picks the
  highest common version or closes.
- Error codes are a reserved closed set: `not-found`, `quota`, `busy`, `log-full`,
  `scope-owner-changed`, `scope-owner-unknown`, `user-scope-off`, `rate-limited`, `refused`,
  `internal`. A client maps any code it does not know to a generic failure that prints the
  code (U38).
- CLI and server are one binary, so version skew exists only between an upgrade's symlink flip
  and the server's restart; the CLI then prints "the server is an older build; restart it" and
  exits 1.

**Bounds.** 16 concurrent connections, at most 2 per uid among them; 10 seconds per request;
5 mutating operations a second per uid; `list` and `deliveries` rate-limited per uid like
mutations, at 5 a second; `read-for-exec` at most 30 a minute per uid, each audited as
`exec-read` (U28, U34, U51). Reads are limited too because each one writes an audit line, so
an unlimited read would be a way around the per-uid log share.

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

Pods cannot reach the socket or the keystore's files, in two layers. **The peer check is never
the first layer.**

1. **Seatbelt.** The data-root denies cover two things, by prefix rather than by a list: every
   name in the data root that begins `keystore-` (today `keystore-floor.json`,
   `keystore-delivery.json`, `keystore-user-floor.log`, `keystore-audit.log` and
   `keystore-audit.log.1`), and the whole `keystore-run/` tree, which also holds the
   maintenance verbs' staging files. A prefix means a keystore file a later change adds is
   denied without a runtimed change. The keystore names join `DataRootDenyTrees`, the list of
   data-root trees runtimed denies, which also feeds `protectedPrefixes`. Not
   `DaemonTreeSubdirs`, which is under the work dir and misses a node whose Pod root differs
   from its data root.

   **What protects the keystore is the validator, not the order.** The profile emits the
   data-root denies first, and narrow re-allows follow for the Pod volume, exposed paths,
   `ReadOnlyPaths` and views; in Seatbelt a later allow wins over an earlier deny for the paths
   it matches, so the order alone protects nothing. The protection is that the protected-prefix
   validator (`validateExtraPaths` and `validateExposePaths`, over `protectedPrefixes`) refuses
   any caller-supplied re-allow under the data root or a keystore name, so no re-allow can
   reach a keystore path, and the Pod is refused rather than started with one. A
   `ReadOnlyPaths` entry, an `ExposePaths` entry or a hostPath naming the data root or a
   keystore path is refused (U16).

   **An empty `Posture.DataRoot` fails closed.** runtimed refuses to render a Pod profile
   without one, so a posture that lost its data root cannot produce a profile with no data-root
   denies (U16).

   **vm and container-vm Pods.** The guest is given no share of the data root, so nothing in
   the guest names the socket or a keystore file (U16, E10).

   **One home for the names.** runtimed owns the keystore path names as exported constants in
   a cgo-free leaf package, `runtimed/pkg/keystorepaths`, which imports only the standard
   library. `pkg/sandbox` and k3sm's provider import it; k3sm's `pkg/keystore` imports only
   that leaf, never `pkg/sandbox`, so the store takes on none of the sandbox's dependencies
   (U49). k3sm's `baseSocketDenies` derives the `keys.sock` path from the leaf and adds a
   `(deny network-outbound (remote unix-socket …))` for it, so there is one spelling (U46,
   E10). That a Pod with these denies cannot `connect(2)` to the socket or read any of these
   paths, and whether a Pod can read Phase A's two data-root files before them, is `[K0 leg 4:
   pending]`.
2. **Pod uid refusal, the second layer.** Native Pods run as the service user, below 501. The
   sandbox change adds a second layer: runtimed refuses any resolved Pod process uid of 501 or
   above, and uid 0 without a drop when the daemon runs as root, both when it resolves the
   credential and again at spawn (U17, E21, E22). With that refusal in place, a Pod that got
   past Seatbelt would connect under a uid the socket's peer check refuses. Until the rig
   spike measures which uid a native Pod's processes run as, and whether any Pod spec field or
   runtimed path can make it 501 or above (`[K0 leg 5: pending]`), this design does not claim
   that a Pod is refused by peer uid; it claims the refusal the sandbox change adds. Row U15 is
   held for a second path if the spike finds one.

### KeyDelivery

A namespaced declaration, `KeyDelivery` in `keystore.k3sm.io/v1alpha1`, delivers a user
entry into a namespace as a Secret. It borrows ExternalSecret's explicit target and policy
fields (a named target Secret, a data key), not its code, since reusing ExternalSecret would
add a dependency and a provider model k3sm does not have. The CRD is alpha: the user docs say
it may change and that a conversion is owed if it does.

**Shape.**

- `metadata.name` is free.
- `spec.secretName` (required, the target Secret), `spec.entry` (scope-qualified, the entry
  pattern above), `spec.dataKey` (default `value`) and `spec.requestedBy` (stamped) are all
  immutable through CRD CEL transition rules (`self == oldSelf`), so the CRD is safe without
  the admission policy (U18).
- The status subresource is on: `observedGeneration`, `conditions` (`Authorized`, `Ready`) as
  the source of truth, and `deliveredVersion`; no value and no fingerprint of an opaque value.
- Condition reasons are a closed set listed in the schema description: `Delivered`,
  `EntryUnavailable`, `NotRecorded`, `NotAuthorized`, `SecretExists`, `SecretClaimed`,
  `EncryptionOff`, `UserScopeOff`. "No such entry" and "not yours" share one reason,
  `EntryUnavailable`, so status reveals nothing about existence; `NotRecorded` is reported
  only after the entry's owner has matched `requestedBy`. `SecretExists` covers an unlabelled
  Secret already holding the target name; `SecretClaimed` covers a second KeyDelivery naming a
  Secret another one already owns: one declaration per target Secret, and the oldest object by
  `creationTimestamp`, then name, wins (U43).

**Admission is a shape check only.** A `ValidatingAdmissionPolicy` in `pkg/policy`, the shape
of the existing ones, adds only what CRD CEL cannot see: on create, `spec.requestedBy ==
request.userInfo.username`, and a requester under `system:serviceaccount:` is refused (U40,
E13). That `request.userInfo.username` reports the impersonated user under impersonation is
not yet checked; U40 and E3 check it. **Neither admission layer is the authority.** The
authority is the sealed delivery record plus the reconciler-time SubjectAccessReviews below;
`requestedBy` is informational.

**Who creates one.** The owner, through the socket: `k3sm keys deliver user/<uid>/<name>
--namespace NS --secret S [--data-key K]` (the short-name form is accepted).

- The server creates the object with the admin client **impersonating `k3sm:local:<uid>`**
  with the group `k3sm:local-users`. The admin client's impersonation is limited to users
  `k3sm:local:*` and the group `k3sm:local-users`: a wrapper refuses any other
  `Impersonate-User` or `Impersonate-Group` before the request leaves (U41). The API server's
  own RBAC then decides whether that principal may create `keydeliveries` in `NS`.
- After the create, the server appends to the caller's sealed `deliveries` record (kind
  0xFD, under the user-scope floor) the object's `metadata.uid` and the **target digest**
  `sha256(LP(entry) ‖ LP(namespace) ‖ LP(secretName) ‖ LP(dataKey))` (U14, U41).
- `withdraw` (CLI `k3sm keys undeliver`) deletes the object; the record entry is withdrawn by
  the reconciler after the Secret is gone. `undeliver` prints "a pod that read this value
  keeps it; rotate the entry to revoke it".
- Only an entry in the caller's own `user/<uid>` scope can be declared. A system entry reaches
  a namespace only through root's `deliver system/…`, never through a KeyDelivery.

**The reconciler honours a KeyDelivery only when all of these hold, re-checked every sweep:**

1. The entry exists, is a `user/<uid>` entry (a `system/…` entry never is), and `requestedBy`
   (`k3sm:local:<uid>`) is its owner; otherwise `EntryUnavailable`.
2. Its UID is in that uid's sealed `deliveries` record and the digest recomputed from the live
   object matches the recorded one; otherwise `NotRecorded`.
3. Name-scoped SubjectAccessReviews for `requestedBy` pass for `create keydeliveries`
   (`resourceNames` the object's name) and for `create`, `update` and `delete` on `secrets`
   (`resourceNames` `spec.secretName`) in that namespace; otherwise `NotAuthorized`. The
   secrets checks are required: without them, a principal allowed to declare deliveries
   but not to write Secrets could plant or remove a Secret a workload expects to mount, under a
   name of its choosing (U42).

Encryption-off refusal (G18) applies unchanged, as `EncryptionOff`.

**Why the sealed record binds the whole target.** The installing user's own kubeconfig
carries the admin context, and admin can impersonate anyone. Without a record only the service
user and root can write, that holder could create, copy or replay a KeyDelivery for any user's
entry. A UID alone is not enough: an object whose spec is changed under its UID (a CRD edited
to drop the transition rules) would keep it. With the UID and the digest, a copied or replayed
object has a UID the owner never recorded, a retargeted one fails the digest, and a forged one
has no record: each is refused (E7, E8). Admin can still delete any KeyDelivery and read any
delivered Secret, as today.

**Writes.** One labelled `Opaque` Secret per honoured object, with Phase A's label
`k3sm.io/keystore-delivery` and version annotation, an owner annotation naming the
KeyDelivery's UID, and an ownerReference to the KeyDelivery as the garbage-collection
backstop.

**Finalizer and lost authority.** The reconciler adds the finalizer
`keystore.k3sm.io/delivery`. On deletion of the object, or when authority is lost (a
RoleBinding removed, the entry removed, the record withdrawn, a digest mismatch), the
reconciler deletes the Secret it owns (label, ownerReference and owner annotation all
matching) and sets `Authorized=False`. The crash order is fixed: **delete the Secret, then
withdraw the sealed record entry, then drop the finalizer**, so a crash at any point leaves a
state the next sweep finishes. An **orphan sweep** deletes Secrets that carry the label and an
owner annotation but have no live KeyDelivery, and never an unlabelled or foreign one (U44,
E11, E14). This differs on purpose from Phase A's root-file delivery, which never deletes
(G20): a revocation that leaves a long-lived token in place is not a revocation.

**Revocation is rotation.** Deleting the Secret does not un-share a value a Pod already read.
The docs and the CLI say so (residual 8).

**Identity.** The reconciler uses the admin client the server already holds for `pkg/addons`,
as Phase A decided; the impersonated create is the only new use of it. A ClusterRole
`k3sm:keystore-delivery-author` (keydeliveries create, get, list, delete; secrets create, get,
update, delete) ships **unbound**; an admin binds it per user and namespace to
`k3sm:local:<uid>`. No ServiceAccount is granted anything.

### Single-server clusters only

Each server would hold its own keystore, so the user scope is supported only on a cluster
with exactly one server. When the apiserver lists more than one node with the
`node-role.kubernetes.io/control-plane` label, the server does not start the listener,
`doctor` reports "keystore user scope: off (more than one server registered)", and
KeyDeliveries get `UserScopeOff` (U30). The system scope keeps Phase A's behaviour. The
limitations page says so. Replicating the keystore across servers is a later design.

### Package layout and seams

- `pkg/keystore` stays Kubernetes-free: it imports no client-go package, and a `go list -deps`
  test asserts it (U11).
- The socket server is `pkg/keystore/socket` and the KeyDelivery reconciler
  `pkg/keystore/reconcile`, siblings that import `pkg/keystore`, never the reverse.
- Each consumer declares the small interface it needs at its own site. The socket server's has
  no reveal, show or rewrap method; the reconciler's reads a value only for a delivery it has
  authorised.
- The entry grammar lives once, in `apis`.

**The named seams.** Each replaces one real primitive, and the primitive is banned at unit
tier: a unit test that reaches one fails. Integration and rig tests use the real one.

| seam | the real primitive it replaces | what the unit fake gives |
|---|---|---|
| clock | `time.Now`, timers and tickers (rate limits, request timeout, listener backoff, lock waits) | a controlled clock, or `testing/synctest` |
| uid resolver | `getpwnam` and `getpwuid` | a fixed name-to-uid table |
| peer-credential source | `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` and `LOCAL_PEERPID` on the connected descriptor, both sides | any uid and pid per connection, which is how cross-user refusal is tested (U45) |
| chflags flag source | `fstat` `st_flags & SF_APPEND` on the two logs, and `chflags` in the maintenance verbs | a flag set or clear per file |
| GeneratedUID lookup | `mbr_uid_to_uuid`, with its deadline | a fixed GeneratedUID, a changed one, an error, or a lookup past the deadline |
| audit sink | the append to `keystore-audit.log` | an in-memory log, and one whose append fails |

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
after the upgrade, since it creates `keystore-run/` and the two append-only files. Without it
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
| the service user (the server, runtimed, kine, the control plane, and any of its processes outside Seatbelt) | read `M` and every `K_u`, hence every value; append to the floor log and the audit log, including forged audit lines | lower the user floor, truncate or delete audit lines, write the system floor |
| a native Pod (the service uid, under Seatbelt) | read a Secret delivered into a namespace it may read, like any Secret | reach `keys.sock`, `keystore-run/`, `server/`, the logs or Phase A's files (Seatbelt first); run under a uid of 501 or above, or as root without a drop, which is the second layer the sandbox change adds ("Pod denies") |
| the entry's owner (a login uid of 501 or above) | put, rotate (including from a version), list, rm and exec its own entries; declare deliveries where RBAC lets `k3sm:local:<uid>` write keydeliveries and that Secret | reveal a value through any verb but exec; touch another uid's scope or any system entry; see another user's names through any verb |
| another login user | the same for its own scope | list, read, rotate, delete or deliver the owner's entries; learn their names |
| a holder of the admin kubeconfig (by default the installing user) | delete any KeyDelivery, read any delivered Secret, bind RBAC | create a working delivery for someone else's entry (a replayed, copied or retargeted object fails the UID and digest check, a forged one has no sealed record); read an undelivered value |
| the server's admin client | impersonate `k3sm:local:*` and `k3sm:local-users` for a create | impersonate any other user or group |

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
   connections, and its own share of each shared log. Past that share only its own mutations
   are refused with `ErrLogFull`; it cannot fill a log for other users.
6. A user account deleted and recreated under the same uid loses its old scope, by design
   (U6), and root must clear it.
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

### What the user scope does not do

Phase B direct mounts; a ServiceAccount rotate transport, deferred to a new endpoint with its
own design; grants of system entries to non-root users; a per-user re-key of `K_u`; a per-user
kubeconfig or any Kubernetes identity for local users (the socket is the path); the user scope
on a worker node or across several servers; a hash chain on the audit log; un-sharing a value
a Pod already read; a hardware-backed master; a `k3sm status` field or app change (the `doctor`
rows are not a contract).

### Facts pending the rig spike

A script-only spike on the rig's server measures these before any code depends on them. A
spike never counts as proof; its result is quoted here as a dated amendment, which also picks
the floor variant.

| marker | the fact | where it applies |
|---|---|---|
| `[K0 leg 1: pending]` | `sappnd` on an APFS data volume as the service user: append works, and the whole defeat list fails; owner `chmod` widens nothing; the kernel securelevel and whether root can clear the flag at it; whether a rename over an `sappnd` target needs the clear first | "The user-scope floor" (the variant and the maintenance verbs) |
| `[K0 leg 2: pending]` | `LOCAL_PEERCRED` both ways, for a socket in a service-user 0755 directory under the root-owned data root and a login uid over SSH: the login uid on the server side, the service uid on the client side | "The socket" (peer identity, the client's checks) |
| `[K0 leg 3: pending]` | `mbr_uid_to_uuid` returns a stable 16-byte GeneratedUID across a server restart, and its cold latency, which sets the deadline | "Key hierarchy" (the GeneratedUID binding) |
| `[K0 leg 4: pending]` | a Pod with the data-root denies cannot `connect(2)` to the socket or read `keystore-run/` or any `keystore-*` file; and, without them, whether a Pod can read Phase A's two data-root files today | "Pod denies", "Threat model" |
| `[K0 leg 5: pending]` | which uid a native Pod's processes run as, and whether any Pod spec field or runtimed path can make it 501 or above | "Pod denies" (layer 2, row U15) |

Two facts are open but are not spike legs: whether the admission policy sees the impersonated
user in `request.userInfo.username` (U40 and E3), and whether the rig runs with
`--secrets-encryption` (E1).

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
| G10 | The master is minted only by the first `put`, never over existing entries, and never by an operator-supplied value | unit: absent master with entries is `ErrMasterMissing`; no verb accepts a key |
| G11 | The master is opened with O_NOFOLLOW and judged by fstat on the open descriptor; wrong mode, owner or fingerprint is `ErrMasterUntrusted` | unit: one case each |
| G12 | Rewrap resumes after a crash at every step, trying the old then the new key, and leaves no record readable by neither; a `master.next` that disagrees with its fingerprint is discarded only when no `.new` file exists, and refused with `ErrMasterUntrusted` otherwise | unit: fault injection at each of steps 2 to 5, then rerun; a corrupted `master.next` with and without a `.new` file |
| G13 | A crash between the two master renames leaves a master that passes its trust check, and the next verb completes the swap | unit: stop after the first rename |
| G14 | One lock serializes Rewrap, Rotate, Put and reads, with a bounded wait | unit: a held lock gives a timeout error within the bound, not a hang |
| G15 | Files a root-run verb writes under `server/` are owned by the service user at the layout's modes | unit with a fake owner seam |
| G16 | `list` returns every entry, marks an unreadable one with `Err`, and exits 1. A directory holding nothing, `generation`, or `generation` and `v1`, with or without leftover `.tmp` files, is an incomplete Put unless the floor records its generation: not listed, `ErrNotFound` from `Current`, `Get` and `Delete` (Delete removes it too, and leaves the floor alone), discarded by the next Put. A directory with no `current` and any other file (`v1` without `generation` included), or in one of those shapes with its generation recorded in the floor, is damage: listed with `Err` wrapping `ErrCorrupt`, removed by `rm` with its floor entry when that records the directory's generation, and `ErrExists` from Put with every file left in place | unit: each incomplete-Put shape with no floor entry, an empty directory, a `generation`-and-`.tmp` directory standing in for a crash while writing `v1`, no floor file, a floor of another generation; damage: `v1` without `generation`, `v2` without `v1`, a `v1`-and-`v2` directory with `current` removed, and the one-version entry that lost `current` (`generation` and `v1`, or `current` renamed to a temporary name) with its generation in the floor; a retried `rm` after an interrupted one; a CLI exit-code test for `list` and `rm` |
| G17 | `show` prints a value only with `--reveal`, and then writes exactly the stored bytes with no trailing newline; no verb takes a value as an argument | CLI test over the usage strings; a `--reveal` test comparing stdout to the stored bytes for an opaque value and for 32- and 64-byte Ed25519 values |
| G18 | Delivery is refused while encryption is off unless the override flag was set at server start; a delivered target stays when the override is removed | unit over the reconciler with a fake client |
| G19 | The delivery declaration is root-owned and not shared-writable, and is refused otherwise | unit, the same cases as the manifest directory |
| G20 | The reconciler only Gets, creates and updates its labelled `Opaque` Secrets, and leaves an unlabelled or foreign Secret alone | unit over a fake client that records every call |
| G21 | The rollback recipe in this document runs as written and is a byte-exact round trip | a script test that pipes `show --reveal` into `rotate --in -`, then compares the new current version's value byte for byte (`cmp`) with version N's, for an opaque entry and an Ed25519 entry |
| G22 | `hack/ci.sh` passes | the gate runs it |

Phase A is complete when the gate passes with no row pending. A row can be reworded or dropped only by a change
to this document, reviewed like any other.

### User-scope rows

The user scope adds the U rows below (unit tier unless the row says otherwise) and the rig legs
under "Rig legs". The gate runs each row's named tests in the repo the row names (`k3sm/…`,
`runtimed/…`, `apis/…`, package paths relative to the module), and fails a row whose named
test is absent or skipped. Each change runs the rows it delivers in its own gate mode, and the
rig rows as an explicit, recorded step. Every row below is pending until the change named in
its last column lands; a pending row fails its mode. G1 holds for the Phase A changes; the user
scope's only module changes are k3sm's requirements on its own `apis` and `runtimed` modules,
each stated in the change that makes it. U15 is held for a K0 amendment and U39 is unused.

| # | Requirement | Validated by | Status |
|---|---|---|---|
| U1 | `rotate --from-version N` writes version N's bytes as a new version server side; no value leaves the store | `k3sm/cmd/k3sm::TestKeysRotateFromVersionNoValueOut` | pending: the `k3sm keys` verbs |
| U2 | AAD scope: a record moved between scopes, or between two users, fails to open | `k3sm/pkg/keystore::TestRecordMovedAcrossScopesFailsOpen` | pending: the core store's scope binding |
| U3 | KDF labels take the scope; `checkScope` accepts only `system` and `user/<decimal uid>`; kinds 0xFE and 0xFD are reserved | `k3sm/pkg/keystore::TestScopedLabelsAndReservedKinds`, `TestCheckScopeGrammar` | pending: the core store's scope binding |
| U4 | the first-Put mint refuses with `.user` present and the master missing | `k3sm/pkg/keystore::TestFirstPutRefusesMintOverUserDir` | pending: the core store's scope binding |
| U5 | Rewrap refuses with `ErrScopeUnsupported` while `.user` exists (replaced by U12 when scope keys are re-wrapped) | `k3sm/pkg/keystore::TestRewrapRefusesWhileUserScopesExist` | pending: Rewrap |
| U6 | `scope.key` is sealed under `W`, bound to the GeneratedUID; a mismatch is `ErrScopeOwnerChanged` | `k3sm/pkg/keystore::TestScopeKeyGeneratedUIDMismatch` | pending: the user-scope store |
| U7 | the GeneratedUID lookup past its deadline or in error fails closed; `mbr_uid_to_uuid` is in the symbol canary | `k3sm/pkg/keystore::TestGeneratedUIDLookupDeadlineFailsClosed`; `k3sm/internal/hostacl::TestMbrUIDToUUIDSymbolCanary` (integration) | pending: the user-scope store |
| U8 | a scope's records open only under its `K_u`; a copied `.user/<uid>/` without the master opens nothing | `k3sm/pkg/keystore::TestScopeCopyWithoutMasterOpensNothing` | pending: the user-scope store |
| U9 | per-scope fingerprints differ for equal values in two scopes | `k3sm/pkg/keystore::TestFingerprintsDifferAcrossScopes` | pending: the user-scope store |
| U10 | `user/<other>/…` is `ErrNotFound`, same text as an absent entry; a short name resolves to the uid and is printed | `k3sm/pkg/keystore::TestOtherUserIsNotFound`, `TestShortNameResolvesToUID` | pending: the user-scope store |
| U11 | the Go resolver passes the shared entry-grammar vectors; `pkg/keystore` imports no Kubernetes package | `k3sm/pkg/keystore::TestEntryGrammarVectorsResolver`, `TestKeystoreIsKubernetesFree` | pending: the user-scope store |
| U12 | master Rewrap re-wraps every `scope.key` and leaves user records byte-identical; resumable at every step | `k3sm/pkg/keystore::TestRewrapRewrapsScopeKeysResumable` (fault injection, as G12) | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U13 | quotas: the 257th entry and the byte budget answer `ErrQuota`; `rm` still works | `k3sm/pkg/keystore::TestUserScopeQuota` | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U14 | the delivery record stores UID and target digest; add, look up and withdraw round-trip under the floor | `k3sm/pkg/keystore::TestDeliveryRecordDigestRoundTrip` | pending: user-scope quotas, scope-key Rewrap and the delivery record |
| U15 | (reserved for the K0 amendment if leg 5 finds a second Pod-uid path) | none | pending: K0 amendment |
| U16 | every Pod profile variant (native, vm, container-vm, xcode, expose-paths, a custom Pod root distinct from the data root) denies every `keystore-*` name in the data root and the `keystore-run/` tree; the keystore names are in `DataRootDenyTrees` and so in `protectedPrefixes`; `ReadOnlyPaths`, `ExposePaths` or a hostPath naming the data root or a keystore path is refused; an empty `Posture.DataRoot` refuses to render; a vm or container-vm guest gets no data-root share | `runtimed/pkg/sandbox::TestDataRootDeniesKeystorePathsEveryProfile`, `TestProtectedPrefixesRefuseKeystoreReallow`, `TestEmptyDataRootFailsClosed`, `TestVMGuestGetsNoDataRootShare`; rig leg E10 | pending: runtimed's sandbox change |
| U17 | runtimed refuses a resolved Pod process uid of 501 or above, and uid 0 without a drop on a root daemon, at credential resolution and again at spawn | `runtimed/pkg/runtime::TestResolveCredentialRefusesLoginRangeUID`, `TestResolveCredentialRefusesRootWithoutDrop`; `runtimed/pkg/supervisor::TestSpawnRefusesLoginRangeUID`, `TestSpawnRefusesRootUIDWithoutDrop`; rig legs E21, E22 | pending: runtimed's sandbox change |
| U18 | CRD: `entry`, `secretName`, `dataKey`, `requestedBy` immutable by CEL transition rules; status subresource on; reasons listed | `apis/config/crd::TestKeyDeliveryCRDMatchesTheGoTypes`, `TestKeyDeliveryImmutableFields` | pending: the `KeyDelivery` API |
| U19 | the CRD pattern passes the shared entry-grammar vectors | `apis/config/crd::TestEntryGrammarVectors` | pending: the `KeyDelivery` API |
| U20 | a user-scope `current` copied back is refused against the floor log, with Phase A's floor message | `k3sm/pkg/keystore::TestUserFloorRefusesCopiedBackCurrent`; rig leg E9 | pending: the append-only files |
| U21 | install creates both logs service-user-owned 0600 and flagged; the listener refuses to start when a flag is clear | `k3sm/pkg/install::TestKeystoreAppendOnlyFilesAtInstall`, `k3sm/pkg/keystore::TestFlagCheckRefusesUnflagged`; rig leg E1 | pending: the append-only files |
| U22 | `floor --rebuild` and `audit --rotate` stop the listener, hold the lock, flag the new file before touching the old; a crash at each step leaves a flagged file | `k3sm/cmd/k3sm::TestKeysFloorRebuildCrashOrder`, `TestKeysAuditRotateCrashOrder`; rig leg E17 | pending: the append-only files |
| U23 | every audited operation writes one `v:1` line; no line carries a value or its length; readers ignore unknown fields | `k3sm/pkg/keystore::TestAuditLineNeverCarriesValue`, `TestAuditReaderIgnoresUnknownFields` | pending: the append-only files |
| U24 | soft cap shows in `doctor`; past the hard cap every mutating user op is `ErrLogFull` | `k3sm/pkg/keystore::TestLogHardCapRefusesMutations` | pending: the append-only files |
| U25 | backup and restore round trip: a restored tree with cleared flags is refused until `floor --rebuild`, then opens | `k3sm/pkg/keystore::TestBackupRestoreRoundTripRebuild`; rig leg E17 | pending: the append-only files |
| U26 | peers uid 0, the service uid and uid < 501 are refused before any frame is read | `k3sm/pkg/keystore/socket::TestPeerEligibility` | pending: the socket listener |
| U27 | framing: an oversize frame, unknown type or missing `HELLO` closes; an unknown header field is ignored; `HELLO` picks the highest common version | `k3sm/pkg/keystore/socket::FuzzFrameReader` (committed seeds), `TestFramingBounds`, `TestUnknownHeaderFieldsIgnored`, `TestHelloVersionRange` | pending: the socket listener |
| U28 | 16 connections in all, 2 per uid; a request past 10 s is cut | `k3sm/pkg/keystore/socket::TestConnectionCapsPerUID`, `TestRequestTimeout` (`testing/synctest`) | pending: the socket listener |
| U29 | a listener panic is recovered and restarted; the apiserver is untouched; a stale socket is unlinked only if a service-user socket; a lock wait past 2 s fails the request | `k3sm/pkg/keystore/socket::TestListenerRecoversPanic`, `TestStaleSocketUnlinkChecksOwner`, `TestBoundedLockWait` | pending: the socket listener |
| U30 | with two servers registered, the listener does not start and `doctor` says why | `k3sm/pkg/keystore/socket::TestUserScopeRefusedWithTwoServers` | pending: the socket listener |
| U31 | a missing or unflagged file logs the install Warn at start and on each retry; `doctor` reports user scope off | `k3sm/pkg/keystore/socket::TestListenerWarnsOnEveryRetry`, `k3sm/cmd/k3sm::TestDoctorKeystoreUserScopeRow` | pending: the socket listener |
| U32 | the audit line is written before the reply; a failed append refuses mutating ops and reads | `k3sm/pkg/keystore/socket::TestAuditBeforeReply`, `TestAuditFailureRefusesOps` | pending: the socket operations |
| U33 | `refused` lines are rate-limited per uid with a summary of the dropped count | `k3sm/pkg/keystore/socket::TestRefusedLinesRateLimited` | pending: the socket operations |
| U34 | 5 mutating ops a second per uid; 30 `read-for-exec` a minute per uid, each audited `exec-read` | `k3sm/pkg/keystore/socket::TestMutationRateLimit`, `TestExecReadCapPerUID` | pending: the socket operations |
| U35 | the socket server's store interface has no reveal, show or rewrap method | `k3sm/pkg/keystore/socket::TestStoreInterfaceHasNoRevealMethod` | pending: the socket operations |
| U36 | the client refuses a socket whose connected peer uid is not the owner of `keystore-run/`, whatever the path checks said | `k3sm/cmd/k3sm::TestClientRefusesForeignServerUID` | pending: the non-root CLI and `exec` |
| U37 | `exec` sets the variable only in the child; nothing on stdout, nothing on disk; the value never enters argv; no non-root verb writes a value to stdout | `k3sm/cmd/k3sm::TestKeysExecEnvOnlyInChild`, `TestNoNonRootVerbWritesValue` | pending: the non-root CLI and `exec` |
| U38 | an unknown error code prints the code; a connect failure names `sudo k3sm install` | `k3sm/cmd/k3sm::TestUnknownErrorCodeFallback`, `TestConnectErrorNamesInstall` | pending: the non-root CLI and `exec` |
| U39 | (unused: there are no system grants) | none | none |
| U40 | the admission policy stamps `requestedBy` and refuses a ServiceAccount creator; its CEL passes the shared grammar vectors | `k3sm/pkg/policy::TestKeyDeliveryPolicyStampsRequestedBy`, `TestEntryGrammarVectorsCEL` | pending: KeyDelivery authoring |
| U41 | `deliver` creates impersonating only `k3sm:local:<uid>` and `k3sm:local-users`, refusing any other impersonation; it writes the UID and digest; `withdraw` deletes the object; `undeliver` prints the hint | `k3sm/pkg/keystore/socket::TestDeliverImpersonatesUIDPrincipalOnly`, `TestDeliverWritesDigestRecord`, `k3sm/cmd/k3sm::TestUndeliverPrintsRotationHint` | pending: KeyDelivery authoring |
| U42 | an unrecorded UID, a digest mismatch, or a failed name-scoped SAR (`create keydeliveries`; `create`, `update`, `delete` secrets with `resourceNames`) gets no Secret; encryption off refuses (G18 for KeyDelivery) | `k3sm/pkg/keystore/reconcile::TestUnrecordedOrRetargetedDeliveryGetsNoSecret`, `TestSARsAreNameScopedAndIncludeDelete`, `TestEncryptionOffRefusesKeyDelivery` | pending: the KeyDelivery reconciler (authority) |
| U43 | reasons are the closed set; "absent" and "not yours" both read `EntryUnavailable`; a pre-existing unlabelled Secret is `SecretExists`; a second declaration is `SecretClaimed`; `observedGeneration` tracks | `k3sm/pkg/keystore/reconcile::TestConditionReasonsClosedSet`, `TestOneDeclarationPerSecret` | pending: the KeyDelivery reconciler (authority) |
| U44 | losing authority deletes exactly the owned Secret; the crash order is Secret, record, finalizer at every interruption point; the orphan sweep removes labelled, owner-annotated Secrets with no live object and never an unlabelled or foreign one | `k3sm/pkg/keystore/reconcile::TestLostAuthorityDeletesOnlyOwnedSecret`, `TestFinalizerCrashOrder`, `TestOrphanSweep` | pending: the KeyDelivery reconciler (lifecycle) |
| U45 | cross-user refusal with a fake peer-credential source: a peer with uid B asks for `list`, `read-for-exec`, `rotate`, `rm` and `deliver` of uid A's entries, and for any `system/…` name; every call is `ErrNotFound` with text identical to an absent entry of B's own, and the `refused` audit lines carry uid B | `k3sm/pkg/keystore/socket::TestCrossUserRefusedFakePeerCred`, `TestNonRootCannotNameSystemEntries` | pending: the socket operations |
| U46 | `baseSocketDenies` derives the `keys.sock` path from `runtimed/pkg/keystorepaths` and denies `connect(2)` to it | `k3sm/pkg/provider::TestBaseSocketDeniesKeystoreSocket` | pending: the socket listener |
| U49 | `runtimed/pkg/keystorepaths` builds with `CGO_ENABLED=0` and imports only the standard library; `k3sm/pkg/keystore` imports that leaf and never `runtimed/pkg/sandbox` | `runtimed/pkg/keystorepaths::TestLeafImportsStdlibOnly`; `k3sm/pkg/keystore::TestKeystoreImportsNoSandbox` | pending: runtimed's sandbox change, the append-only files |
| U50 | the defeat list, run as the service user against both flagged logs (integration, root-run in the gate's `--root` mode, flag variant): `chflags nosappnd`, `O_TRUNC`, `ftruncate`, `pwrite` at an offset, a shared writable `mmap` write, `F_PUNCHHOLE`, `link()`, `fclonefileat` then a swap, a `renamex_np` swap through the parent, `exchangedata`, `unlink` and `rename` through the parent, a second open with `O_TRUNC`, and owner `chmod`; each fails, the bytes and the flag are unchanged, and an `O_APPEND` write still succeeds | `k3sm/pkg/keystore::TestAppendOnlyDefeatListAsServiceUser` | pending: the append-only files |
| U51 | per-uid log fairness: a uid past its share of a log's hard cap has its own mutations refused with `ErrLogFull` while another uid's succeed; `list` and `deliveries` are rate-limited per uid | `k3sm/pkg/keystore/socket::TestLogSharePerUIDRefusesOnlyThatUID`, `TestReadRateLimitPerUID` | pending: the socket operations |
| U52 | every root verb writes one audit line with `via` `root` once the log exists, and none before it | `k3sm/cmd/k3sm::TestEveryRootVerbWritesAuditLine` | pending: the append-only files |
| U53 | every reconciler Secret write and delete, and every record withdrawal, writes one audit line with `via` `reconciler` | `k3sm/pkg/keystore/reconcile::TestEveryReconcilerWriteAndDeleteAudited` | pending: the KeyDelivery reconciler (lifecycle) |
| U54 | a pre-frame refusal (uid 0, the service uid, a uid below 501) writes a `refused` line with the peer uid, rate-limited per uid with a dropped-count summary | `k3sm/pkg/keystore/socket::TestPreFrameRefusalsAudited`, `TestPreFrameRefusalLinesRateLimited` | pending: the socket listener |

### Rig legs

The end-to-end gate is `hack/acceptance/keystore-e2e.sh --lab` on the two-Mac lab rig, from a
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
| E1 | preconditions | secrets encryption on; one server; `keystore-run/`, both logs present, service-user 0600, `SF_APPEND` set; `doctor` user-scope row on; `keystore.sh --check` exits 0 on the build | no (U21) | the append-only files: no files, `doctor` row off |
| E2 | the user, no sudo: `printf … \| k3sm keys put user/<me>/e2e-token` (short-name form) | exit 0; the CLI prints the resolved `user/<uid>`; `k3sm keys list` shows it; the audit log has a `put` line with no value | yes | the socket operations: connect refused, error names `sudo k3sm install` |
| E3 | an admin binds `k3sm:keystore-delivery-author` for `k3sm:local:<uid>` in `ks-e2e`; the user runs `k3sm keys deliver user/<uid>/e2e-token --namespace ks-e2e --secret e2e-token --data-key TOKEN` | `KeyDelivery` `Ready`, reason `Delivered`, `observedGeneration` current; the object's `requestedBy` is `k3sm:local:<uid>`; a Pod mounting Secret `e2e-token` reads exactly the stored bytes | yes | the KeyDelivery reconciler (authority): no Secret, no status |
| E4 | the user rotates (`rotate --in -`), then `rotate --from-version 1` | the Pod's mounted file moves to v2, then to v1's bytes as v3, within one sweep each | yes | the `k3sm keys` verbs: `--from-version` unknown flag |
| E5 | `k3sm keys exec user/<uid>/e2e-token --env TOKEN -- /usr/bin/env` | the child sees `TOKEN`; the CLI wrote nothing else; `ps` during the run shows no value in argv; one `exec-read` audit line | no (U37) | the non-root CLI and `exec`: unknown verb |
| E6 | as the operator's login user only: `list`, `exec`, `rotate`, `rm` and `deliver` of `user/<an unused other uid>/e2e-token` and of `system/e2e-sys`; then a connect to `keys.sock` as root and as the service user | `not found` each time for the names, text identical to an absent entry of the user's own, and `refused` audit lines attributed to the user's uid; root and the service user are refused at accept, before any frame | partly (U26, U45): the rig runs only what one real user can reach, the cross-user case is unit-tested | the socket operations: the other uid's or the system entry's ops are answered (U45 red); the socket listener: root or the service uid is served |
| E7 | admin copies E3's KeyDelivery YAML into `ks-e2e-2` (where the user also has the role) | `Authorized=False`, reason `NotRecorded`, no Secret: the UID is not in the user's record | no (U42) | the KeyDelivery reconciler (authority): a Secret appears in `ks-e2e-2` |
| E8 | admin strips the CRD's transition rules (a test patch, restored at the end) and edits E3's `spec.secretName` | `Authorized=False`, `NotRecorded` (digest mismatch); the original Secret deleted; no Secret under the new name | yes | the target digest: a Secret appears under the new name |
| E9 | `sudo cp` saves `current`, the user rotates, `sudo cp` puts the old `current` back; then the same for a `system/` entry | user `list` and `sudo k3sm keys list` each mark the entry `corrupt` with the floor message; `floor --rebuild` is not run | no (U20) | the append-only files: the old value is served |
| E10 | a native Pod (pinned by `nodeName`, darwin selector) tries `connect(2)` to `keys.sock` and to read `server/keystore`, `keystore-run/`, both logs and Phase A's two files; then a vm Pod on the same node tries to reach `keys.sock` and the data root from the guest | EPERM for each from the native Pod; the guest has no path to the data root and cannot reach the socket | no (U16) | runtimed's sandbox change: the Phase A files read (the red result K0 leg 4 records) |
| E11 | admin removes the user's RoleBinding in `ks-e2e` | within one sweep the Secret is deleted; `Authorized=False`, `NotAuthorized` | no (U42) | the KeyDelivery reconciler (lifecycle): the Secret stays |
| E12 | root scope: `sudo k3sm keys put system/e2e-sys`, `sudo k3sm keys deliver system/e2e-sys --namespace ks-e2e`; then the user, with no sudo, tries `k3sm keys deliver`, `list` and `exec` on `system/e2e-sys` | root's Secret is delivered and stays (G20); each of the user's attempts answers `not found` and nothing reaches `ks-e2e-2`: the user cannot read or deliver the system entry. The leg does not claim the user cannot discover the name, which Phase A's 0644 files show (residual 11) | partly (U45): the root delivery is rig-only | root delivery: root delivery missing; the socket operations: a non-root user can name a system entry |
| E13 | a ServiceAccount token creates a KeyDelivery | refused at admission | no (U40) | KeyDelivery authoring: the object is created |
| E14 | `k3sm keys undeliver` on E3's object, then `kubectl delete` of a second one | each Secret deleted before its object goes; the hint printed; no orphan Secret after one sweep | no (U44) | the KeyDelivery reconciler (lifecycle): the object hangs or the Secret stays |
| E15 | **upgrade** from the previous release's install tree (its signed build installed, then this build over it, then `sudo k3sm install`) | system scope intact; user scope comes on after the install, off with the Warn and `doctor` row before it | yes | upgrade visibility: user scope silently off |
| E16 | **rollback** to the previous release, then forward again | the old build runs with the keystore files unused; after rolling forward the user's entries, records and Secrets are intact and re-adopted | yes | the rollback guard: entries unreadable after the round trip |
| E17 | **backup and restore** round trip: copy the data root's keystore set aside with `cp`, remove it, copy it back, then `floor --rebuild` and `audit --rotate` | before the rebuild the listener refuses (flags clear); after it every entry opens and both logs are flagged | no (U25) | the flag check: the listener runs on unflagged logs |
| E18 | an **old worker**: the second Mac on the previous release joins this server | worker Ready; Pods there mount delivered Secrets; no keystore listener or reconciler on the worker | yes | server-only listener: a listener on an agent node |
| E19 | `sudo launchctl kickstart -k system/io.k3sm.server` while a client is connected mid-request | the client gets a clean error, not a hang; the listener is back within its backoff; kine and the apiserver come back; no partial record | yes | the listener lifecycle: the client hangs or the store holds a torn write |
| E20 | **reboot of the server node**: an operator-attended leg (automation never reboots the rig), run by the operator with the script's `--attended reboot` step | after boot the flags are still set, the listener starts, E2's entry opens, E3's Secret is still current | yes | the flag check: a flag lost across a reboot |
| E21 | a native Pod with `securityContext.runAsUser: 501` | refused at spawn: the container never starts, and its status carries the uid refusal | no (U17) | runtimed's sandbox change: the Pod runs as uid 501 |
| E22 | a native Pod with `securityContext.runAsUser: 0` | refused at spawn: the container never starts as root, and its status carries the uid refusal | no (U17) | runtimed's sandbox change: the Pod runs as uid 0 |

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

Owed by the implementation: `hack/acceptance/keystore.sh`, specified above. There are no
open questions.
