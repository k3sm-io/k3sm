# Keystore design

Status: under review. This fills in the sections issue 731 and PR #743 left open, for
review on this pull request; the contract sketch in `pkg/keystore/keystore.go` may still
change as that review runs. The second revision answers the review on this pull request
(items 1 to 8) and the maintainer's three rulings on the delivery declaration, the master
directory and the pointer rollback.

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

One consequence shapes the design: every file the service user owns is writable by every
native Pod. Anything whose integrity must hold against a Pod therefore either carries an
authenticated record, or lives where only root can write it. Both are used below.

## Storage format and master key

The fixed decisions:

- Standard library only.
- The master key is a mode 0600 file owned by the service user, with a fingerprint beside
  it, in a directory separate from the entries: its own subdirectory of the server's
  credential directory, `/var/lib/k3sm/server/cred/keystore-master/` (the maintainer's
  ruling).
- Each version is sealed with AES-256-GCM. The additional data is a length-prefixed
  encoding of (record-format version, kind, name, version, generation), never a bare
  concatenation.
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
- Entry names are validated before they become file names: not empty, no path separator,
  not made only of dots.
- The fingerprint of an Ed25519 entry is a digest of its public key; that of an opaque
  entry is keyed (an HMAC under a key derived from the master) or truncated, never a plain
  hash of the value, so List output is not a guessing oracle for a low-entropy value.
- An Ed25519 value is the 32-byte seed or the 64-byte expanded private key, and is
  validated on Put.

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
        master                          0600: 32 random bytes
        master.sha256                   0600: hex SHA-256 of the master bytes
        master.next                     present only mid-Rewrap
        master.next.sha256
    keystore/                           0700, service user, a SIBLING of cred/
      .lock                             0600, the one lock file (see "Concurrency")
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
service user, using the same root-writes-a-service-user-owned-file seam the installer
already uses for the encryption pair. The two root-owned files under the data root are
the exception to "owned by the service user": they exist because a Pod must not be able to
write them.

### Master key lifecycle

- **Who mints it.** Only k3sm, from `crypto/rand`, 32 bytes. An operator never supplies a
  master key, to any verb, and no verb takes one as input.
- **When it is created.** By the first root-run `k3sm keys put` that finds no master and
  an empty or absent `keystore/`. There is no install step: Phase A changes nothing in
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

**Associated data** is five fields:

```
AAD = LP(record-format-version) ‖ LP(kind) ‖ LP(name) ‖ LP(version, 8B BE) ‖ LP(generation, 16B)
```

`LP(x)` is a 4-byte big-endian length followed by `x`, so no field's bytes can be shifted
into its neighbor. `created` is intentionally **not** in the AAD: it is display metadata,
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
{"version": 1, "entries": {"signer-key": {"generation": "<hex>", "seq": 7}}}
```

A reader that opens `current` refuses it, as `ErrCorrupt` with a message that says the
pointer is older than the recorded floor, unless **both** hold: the pointer's generation
equals the floor's generation for that name, and the pointer's sequence is at least the
floor's. So an older `current` that still authenticates is refused.

**Where the floor lives is the load-bearing choice.** A floor kept in the service user's
tree would be one more file a Pod can copy back, and the check would only be as strong as
the attacker's patience. `keystore-floor.json` is therefore root:wheel 0644 in the
root-owned data root, written only by root-run verbs, and read with the same check
`pkg/addons` applies to the manifest directory (`rootOwnedNotShared`, judged on the opened
descriptor with O_NOFOLLOW): refused unless root-owned and not group/other-writable. Every
mutating verb is already root-run, so no write path loses anything by this; the service
user, which only reads, never needed to write it.

The write order on a change is: the record, then the pointer, then the floor.

- **Put:** write `generation`, `v1`, `current` (sequence 1), then set the floor entry.
- **Rotate:** write the new version file, flip `current` (sequence + 1), then raise the
  floor to that sequence.
- **Delete:** remove the entry directory, then remove the floor entry.

A crash after the pointer flip but before the floor write leaves the floor one behind the
pointer, which the rule above accepts (pointer at or above floor). So that the lag does not
become a window, **every root-run verb begins by raising each entry's floor to its
authenticated pointer's sequence**, under the lock. A floor entry for a name with no
directory (a crash during Delete) is harmless and is overwritten by a later Put.

What this does not do, stated plainly: root can replace the pointer and the floor together,
and the threat model does not defend against root. A deliberate restore of an older
`keystore/` from backup is the same act, so it is refused until root removes
`keystore-floor.json`, which a root-run verb then rebuilds from the restored pointers.
"Backup and snapshots" gives that procedure.

### Fingerprint construction

Ed25519: `hex(sha256(publicKey))` — a plain digest is fine since a public key is not
secret, mirroring `EncryptionKeyFingerprint` in `pkg/executor/secretsencryption.go`.
Opaque: `hex(HMAC-SHA256(fpKey, value))` truncated to 16 bytes, where
`fpKey = HMAC-SHA256(master, "k3sm-keystore-fingerprint-v1")` — a fixed-label HMAC under
the master, computed once per master rather than per entry, so the master is never used
directly both as a raw AES-GCM key on one path and an HMAC key on another.

**Where it is stored: nowhere.** It is computed when a version is read, from the decrypted
value. `list` therefore opens each version once; that is one small AES-GCM open per version
(values are capped at 64 KiB), and `list` is an operator command, not a hot path.
**It changes across a Rewrap** for opaque entries, because its key derives from the master;
an Ed25519 fingerprint does not. A fingerprint copied into a runbook goes stale after a
Rewrap, and the verb says so when it finishes.

### Master file trust

`keystore-master/master` is opened `O_RDONLY|O_NOFOLLOW`; owner and mode are read off the
*same open descriptor* (fstat, not a separate lstat — the same TOCTOU closure
`pkg/install/install.go`'s `ReadRegularFile` already documents), checked against the
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
An entry whose `current` fails to open (corrupt, stale, or truncated) is still returned,
carrying the error. The contract changes: `Entry` gains `Err error`, non-nil exactly when
the entry could not be opened, and `Current` and `Versions` are then zero. `List` returns a
non-nil error for the whole call only for a failure that is not about one entry: the
master missing or untrusted, or the lock timing out.

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
  indefinite block: a Pod owns the lock file and could hold it, which is a denial of
  service the same-user model already permits (that Pod can delete the entries), and a
  reconciler that times out simply tries again on its next sweep.
- Each file write is still temp-and-rename, so a process that dies releases the lock and
  leaves a state the next operation can finish or discard. The lock is for serialization,
  not for crash safety.
- An entry directory with no `current` is an incomplete Put. Put under the lock discards
  it and starts over, so one crash does not leave a name that can never be reused.

### Ownership of what root writes

Every verb requires root, because the master and the entries belong to the service user.
Every file or directory a verb creates under `server/` is chowned to the service user
before the verb returns, at the modes in the layout. A file left owned by root would fail
the service user's own read, and a read as the service user is what the reconciler does.
The two files under the data root are the deliberate exception: root:wheel.

### Rewrap

Rewrap re-seals every record under a new master. It is `k3sm keys rewrap`, root-run: the
verb mints a new 32-byte master from `crypto/rand`, takes the exclusive lock, and runs the
steps below. "A crash leaves nothing unreadable" needs the *records*, not only the two
master files, to move in two phases:

1. Validate `newMaster` is 32 bytes (the verb always passes one; a wrong length from a
   library caller is a plain error, not a sentinel, since no caller can act on it
   differently, and an empty argument is `ErrMasterMissing`).
2. Write `master.next`, fsync, then `master.next.sha256`, fsync, then fsync the directory.
   If a `master.next` already exists and agrees with its fingerprint, **reuse it** so a
   resumed Rewrap does not mint a second key; if it exists and does not, and no `.new`
   file exists anywhere (step 3 only starts after step 2 is durable), discard it and mint
   again.
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

**Consequence for backups.** The old master does not survive step 5, so an entry backup
taken before a Rewrap can no longer be opened with the live master. See "Backup and
snapshots": entry and master backups are a matched pair, and a Rewrap starts a new pair.

## CLI (`k3sm keys`)

The verbs `sudo k3sm keys put|list|show|rotate|rm|rewrap|deliver`, modeled on
`cmd/k3sm/secretsencrypt.go`'s dispatch (a `flag.FlagSet` per verb, a fixed usage string,
named exit codes). The verb for declaring a delivery target is the maintainer's ruling:
beside the existing subcommands, as k3s does with `k3s secrets-encrypt`, so one place
validates input and the store's layout stays private.

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
      Metadata only by default; the value is printed, alone on stdout, only
      with --reveal.

rotate <name> [--in FILE|-]
      A new version from the same value source as put; flips current. Refuses
      a name that does not exist.

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
three-value shape `secrets-encrypt` uses. Every verb requires root. Value input is
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
  {"name": "signer-key", "namespace": "payments", "secretName": "signer-key", "dataKey": "private.key"}
]}
```

`secretName` defaults to the entry name and `dataKey` to `value`. The file is root-owned
and outside the service user's tree for the reason `pkg/addons/doc.go` gives for the
manifest directory: a Pod can write the service user's tree, and a declaration a Pod could
write would let a Pod choose which namespace gets a Secret. It is read with the manifest
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
{root on the node} because only root can edit the declaration. If the maintainer would
rather this run as a bounded ServiceAccount in the manner of `kube-system/k3sm-manifests`,
that needs a new Role granting Secret write, which widens what the control plane can do,
and so it is listed under "Open questions" for a ruling and not assumed here.

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

**Retention:** every version is kept indefinitely in Phase A; nothing deletes a single old
version short of `rm` of the whole entry. Settled in this document: the simplest correct
answer, left for a later phase to bound once real usage shows it matters.

**Delivered-Secret movement:** covered above under "Re-delivery on rotation" — automatic
on the next sweep after a Rotate.

**Rollback:** no dedicated verb. An operator rolls back by writing the old version's value
forward as a *new* version, never by pointing `current` backward at an existing version:

```
sudo k3sm keys show NAME --version N --reveal | sudo k3sm keys rotate NAME --in -
```

A pipe, not a process substitution: `sudo` closes inherited descriptors, so a `<( … )`
path would not open, and each side of the pipe runs its own `sudo`. This keeps rotation
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

## Non-goals

Beyond Phases B and C: isolating one native Pod's delivered Secret from another; protecting
key material from root on the host; a KMS- or HSM-backed master (the master is a file,
protected the same way the existing `secretbox` key is — a hardware-backed master is a
later proposal, as issue 731 already notes for the existing key); a network service or new
IPC surface; bounded version retention or a point-in-time rollback verb in Phase A;
changes to `k3sm install`; importing existing Secrets.

## Acceptance gate

The gate is `hack/acceptance/keystore.sh`, written with the implementation and named in
the implementation pull request. This section is its specification, so that what review
approves here is what the gate checks. Each row is a requirement from this document and the
test that must exist for it; the gate runs them and fails if any row has no test or any
test fails. The implementation pull request cites a test name per row.

| # | Requirement | Validated by |
|---|---|---|
| G1 | Standard library only: `go.mod` and `go.sum` unchanged by the implementation | the gate diffs both against the base |
| G2 | The AAD is length-prefixed and covers format, kind, name, version, generation; a record moved to another name, version or generation fails to open | unit: swap each field, expect `ErrCorrupt` |
| G3 | Every seal draws a fresh 96-bit nonce, including Rewrap | unit: two seals of one plaintext differ; Rewrap changes every nonce |
| G4 | Delete then Put of the same name does not reopen the old `v1` | unit: replay the old file onto the new entry, expect `ErrCorrupt` |
| G5 | A previously valid `current` copied back over the current one is refused | unit: Rotate, restore the earlier `current`, expect `ErrCorrupt` naming the floor |
| G6 | The floor is root-owned and checked on the opened descriptor; a floor that is group- or other-writable, a symlink, or not root-owned is refused | unit with a fake FS for each case |
| G7 | The floor is raised by every mutating verb and by the start of every root verb, and a floor one behind the pointer is accepted | unit: crash after the flip, before the floor write |
| G8 | Rotate flips the pointer last; a crash at each of its steps leaves the old version current | unit: fault injection between each step |
| G9 | A Rotate retry discards an orphaned next version and seals the value it was given | unit: orphan with value A, retry with value B, expect B |
| G10 | The master is minted only by the first `put`, never over existing entries, and never by an operator-supplied value | unit: absent master with entries is `ErrMasterMissing`; no verb accepts a key |
| G11 | The master is opened with O_NOFOLLOW and judged by fstat on the open descriptor; wrong mode, owner or fingerprint is `ErrMasterUntrusted` | unit: one case each |
| G12 | Rewrap resumes after a crash at every step, trying the old then the new key, and leaves no record readable by neither | unit: fault injection at each of steps 2 to 5, then rerun |
| G13 | A crash between the two master renames leaves a master that passes its trust check, and the next verb completes the swap | unit: stop after the first rename |
| G14 | One lock serializes Rewrap, Rotate, Put and reads, with a bounded wait | unit: a held lock gives a timeout error within the bound, not a hang |
| G15 | Files a root-run verb writes under `server/` are owned by the service user at the layout's modes | unit with a fake owner seam |
| G16 | `list` returns every entry, marks an unreadable one with `Err`, and exits 1 | unit plus a CLI exit-code test |
| G17 | `show` prints a value only with `--reveal`; no verb takes a value as an argument | CLI test over the usage strings |
| G18 | Delivery is refused while encryption is off unless the override flag was set at server start; a delivered target stays when the override is removed | unit over the reconciler with a fake client |
| G19 | The delivery declaration is root-owned and not shared-writable, and is refused otherwise | unit, the same cases as the manifest directory |
| G20 | The reconciler only Gets, creates and updates its labelled `Opaque` Secrets, and leaves an unlabelled or foreign Secret alone | unit over a fake client that records every call |
| G21 | The rollback recipe in this document runs as written | a script test that pipes `show --reveal` into `rotate --in -` |
| G22 | `hack/ci.sh` is green | the gate runs it |

Phase A is complete when the gate passes. A row can be reworded or dropped only by a change
to this document, reviewed like any other.

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

Settled in this revision: the master directory; the delivery-target mechanism (a verb); the
`Rewrap` argument check (a plain error, no sentinel); retention (unbounded in Phase A).

Owed by the implementation: `hack/acceptance/keystore.sh`, specified above.

Still open, raised by this revision, for a ruling before implementation:

- **Where the pointer floor is recorded.** This document puts it in a root-owned file under
  the data root, because a floor in the service user's tree can be copied back like the
  pointer. That is a new root-owned file and an operator step on restore. If a different
  home is preferred, the requirement (an older pointer refuses even when it authenticates)
  does not change.
- **The reconciler's identity.** This document reuses the admin client the server process
  already holds and adds no role. A bounded ServiceAccount would need a new Role granting
  Secret write.
- **`k3sm keys rewrap` and `k3sm keys deliver` as verbs.** Both follow from the rulings,
  but each is an operator-facing surface the issue did not name.
- **`Entry.Err`.** A contract change to `pkg/keystore`, made in this pull request.
