# Keystore design

Status: under review. This fills in the sections issue 731 and PR #743 left open, for
review on this pull request; the contract sketch in `pkg/keystore/keystore.go` may still
change as that review runs.

One point worth stating up front because it resolves an apparent tension elsewhere: this
design needs no operator passphrase and no KDF. The master key is a file minted at install,
the same way the existing `secretbox` encryption key is — so `docs/GO-STANDARDS.md`'s
"standard library only" for Phase A and its "cryptography … stay on maintained libraries"
exception are the same answer here, because every primitive this needs (AES-256-GCM,
Ed25519, HMAC, SHA-256, `crypto/rand`) is already in the standard library.

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
rest, rotation, list, delete, master key re-wrap, the `k3sm keys` verbs and the delivery
reconciler.

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

## Storage format and master key

The fixed decisions (unchanged):

- Standard library only.
- The master key is a mode 0600 file owned by the service user, with a fingerprint
  beside it, in a directory separate from the entries.
- Each version is sealed with AES-256-GCM. The additional data is a length-prefixed
  encoding of (record-format version, kind, name, version), never a bare concatenation.
- The nonce is 96 bits from crypto/rand, fresh on every seal including Rewrap, never
  derived from the name or the version.
- The current pointer flips last on rotation. It is written to a temporary file and
  renamed into place, with the file and its directory fsynced, and its target version is
  covered by the same authenticated record, so a writer of the files cannot roll an entry
  back by editing the pointer alone.
- Rewrap is two-phase: the new master is written beside the old one, every version is
  re-sealed, then the pointer to the master flips. A crash leaves both masters present and
  nothing unreadable.
- A Delete followed by a new Put of the same name at version 1 must not reopen a
  replayed old record: the record carries a per-entry generation, or this document states
  why replay is accepted under the same-user model.
- The master file is opened with O_NOFOLLOW and checked with fstat on the open
  descriptor (owner, mode) and against its fingerprint. The fingerprint detects a wrong
  file, not tampering. `sudo k3sm keys` runs as root against a file owned by the service
  user, so ownership is checked, not assumed.
- Entry names are validated before they become file names: not empty, no path
  separator, not made only of dots.
- The fingerprint of an Ed25519 entry is a digest of its public key; that of an opaque
  entry is keyed (an HMAC under a key derived from the master) or truncated, never a plain
  hash of the value, so List output is not a guessing oracle for a low-entropy value.
- An Ed25519 value is the 32-byte seed or the 64-byte expanded private key, and is
  validated on Put.

### On-disk layout

```
<server work dir>/
  cred/
    encryption-config.yaml        existing secretbox pair, unchanged
    encryption-config.sha256
    keystore-master                0600, service-user-owned: 32 random bytes
    keystore-master.sha256         0600: hex SHA-256 of the master key bytes
    keystore-master.next           present only mid-Rewrap
    keystore-master.next.sha256
  keystore/                        0700, service-user-owned, a SIBLING of cred/
    <name>/                        one directory per entry; created by Put with a bare
                                    Mkdir (never MkdirAll), so existence and creation are
                                    one atomic check
      generation                   0600, 16 random bytes, hex; written once by Put, never
                                    rewritten by Rotate
      v1, v2, …                    sealed records, one per version
      current                      sealed pointer record naming the current version
```

The master pair stays in the existing `cred/` directory — already the home for small,
singular, security-critical control-plane files — while entries get their own top-level
directory. This is deliberate rather than nesting entries under `cred/`: an operator's
habitual `cp -r cred/ backup/` must not also sweep up every entry's version history, and a
backup of `keystore/` alone must not also carry the one file that unlocks all of them.
**Open for review:** whether `cred/` is the right home for the master pair versus its own
`keystore-master/` directory one level further away; `cred/` is already exactly this
pattern and a new directory for two files adds its own small surface (mode, ownership,
creation order) to get right for no clear benefit `cred/` doesn't already give.

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

A version record's plaintext is the stored value. The pointer record's plaintext is the
8-byte version number it names — deliberately tiny, so the pointer carries no information
an attacker without the master key could use even if every other record were absent.

**`created` is a fixed-width integer, not text, specifically to avoid a known failure
class.** An unrelated from-scratch keystore build this month used RFC 3339 text for the
same field; an independent review found a crafted-but-parseable out-of-range timestamp
that, once normalized, re-encoded as something the writer's own parser could not read back
— a self-inflicted denial of service on the ring's next write. A fixed 8-byte Unix-seconds
integer has no string to parse and so no such failure mode at all.

**Associated data** extends the fixed four fields with a fifth, to resolve the open replay
question below:

```
AAD = LP(record-format-version) ‖ LP(kind) ‖ LP(name) ‖ LP(version, 8B BE) ‖ LP(generation, 16B)
```

`LP(x)` is a 4-byte big-endian length followed by `x`, so no field's bytes can be shifted
into its neighbor. `created` is intentionally **not** in the AAD: it is display metadata,
and binding it would turn an honest clock difference (a restored backup, a changed system
clock) into an authentication failure indistinguishable from real tampering of the value.

**Generation closes the replay question.** Entry files are named by version number inside
a per-name directory, so after a Delete and a later Put of the same name, the new entry's
`v1` occupies the exact path the old entry's `v1` once did. If an operator restores a stale
backup of just that one file onto the live keystore, an AAD built only from (format, kind,
name, version) is identical between the old, deleted entry's `v1` and the new entry's —
same name, same kind, same version — so the restored ciphertext opens cleanly and silently
reintroduces key material the operator believed was gone. A 16-byte random generation,
minted fresh by every Put (including one that follows a Delete) and carried unchanged
through an entry's whole life, breaks that: the restored file's AAD names the old
generation, the live AAD construction for that name now uses a new one, and the GCM tag
fails to verify — refused as `ErrCorrupt`, correctly, since it is corrupt relative to the
entry that exists now. This is a random value rather than a counter so there is no
persisted "next generation" state that could itself drift out of sync with reality.

**Fingerprint construction.** Ed25519: `hex(sha256(publicKey))` — a plain digest is fine
since a public key is not secret, mirroring `EncryptionKeyFingerprint` in
`pkg/executor/secretsencryption.go` exactly. Opaque:
`hex(HMAC-SHA256(fpKey, value))` truncated to 16 bytes, where
`fpKey = HMAC-SHA256(master, "k3sm-keystore-fingerprint-v1")` — a fixed-label HMAC under
the master, computed once per master rather than per entry, so the master is never used
directly both as a raw AES-GCM key on one path and an HMAC key on another.

**Master file trust.** `keystore-master` is opened `O_RDONLY|O_NOFOLLOW`; owner and mode
are read off the *same open descriptor* (fstat, not a separate lstat — the same TOCTOU
closure `pkg/install/install.go`'s `ReadRegularFile` already documents), checked against
the service uid and mode 0600, and its content's SHA-256 checked against the fingerprint
file. Any of the three failing is `ErrMasterUntrusted`; the file being entirely absent
while `keystore/` holds entries is `ErrMasterMissing` — the same two-refusal split
`pkg/executor/secretsencryption.go` already makes for the encryption pair
(`ErrEncryptionKeyFileMode`/`ErrEncryptionKeyFileOwner` vs. `ErrEncryptionKeyMissing`).

**List, when one entry is corrupt.** Not specified by the contract as given. Decided here:
if one entry's `current` pointer fails to open, `List` returns `ErrCorrupt` naming that
entry, for the whole call, rather than silently omitting it from an otherwise-successful
list — an operator running `list` to learn what exists must be told the truth about what
is wrong, not a shorter list that looks complete.

### Rewrap, concretely

"A crash leaves both masters present and nothing unreadable" needs the *records*, not only
the two master files, to move in two phases:

1. Validate `newMaster` is 32 bytes. (The scaffold's `fakeStore.Rewrap` already treats an
   empty argument as `ErrMasterMissing`; kept. Open: whether a non-empty, wrong-length
   argument deserves its own sentinel.)
2. Write `keystore-master.next` (+ fingerprint) if it does not already exist — so a
   **resumed** Rewrap after a crash reuses the same new key rather than minting a second
   one.
3. For every entry, every version file and the current pointer: decrypt under the old
   master, re-seal under the new one (fresh nonce, unchanged plaintext, unchanged AAD
   fields including generation), write the result to a sibling file (`v1.new`, …) without
   touching the canonical file. Idempotent and resumable — a crash here is resolved by
   re-running step 3 from scratch.
4. Once every `*.new` sibling exists and is fsynced: rename each over its canonical name,
   per entry, fsync that entry's directory.
5. Rename `keystore-master.next → keystore-master` (+ fingerprint), fsync `cred/`.

**Reader's rule for the whole window:** open under the master named by `keystore-master`;
if that fails to authenticate *and* `keystore-master.next` is present, retry once under
that key. This single bounded fallback is what makes steps 4 and 5's relative order not
matter for correctness — whichever of the two files a given record is sealed under at any
point, one of the two keys a reader is willing to try is the right one — and the fallback
stops being tried the moment step 5 removes `.next` from existence, so it never becomes a
second key this keystore must support indefinitely.

## CLI (`k3sm keys`)

The verbs `sudo k3sm keys put|list|rotate|rm|show`, modeled on
`cmd/k3sm/secretsencrypt.go`'s dispatch (a `flag.FlagSet` per verb, a fixed usage string,
named exit codes):

```
put <name> [--kind ed25519|opaque] [--in FILE|-]
      Create at version 1. Value from --in or stdin ("-", the default), never an
      argument. --kind defaults to opaque; ed25519 is validated as a 32- or
      64-byte key on the way in.

list
      One line per entry: name, kind, current version, created, fingerprint.
      Values never printed. A corrupt entry is reported as "corrupt" in the
      listing, not omitted, and the command exits non-zero.

show <name> [--version N] [--reveal]
      Metadata only by default; the value is printed, alone on stdout, only
      with --reveal.

rotate <name> [--in FILE|-]
      A new version from the same value source as put; flips current. Refuses
      a name that does not exist.

rm <name> [--yes]
      Deletes every version. Irreversible; refuses without --yes.
```

Exit codes: 0 success, 1 refused (the sentinel's message), 2 bad usage — the same
three-value shape `secrets-encrypt` uses. Every verb requires root, since the entries and
the master are owned by the service user. Value input is `--in FILE` or stdin only, never
an argument — argv is visible to every local user via `ps` and lands in shell history.
Opaque values are capped at 64 KiB; Ed25519 values are checked against the two valid
lengths exactly at Put time.

## Delivery reconciler

A reconciler beside the embedded add-on reconciler in `pkg/addons`: converges one
labelled Secret per declared target, never LISTs, never prunes anything it did not itself
apply, log-and-continue on a per-target failure (the same posture `pkg/addons/doc.go`
already documents and justifies).

**Target declaration — open for review, proposed here:** a small operator-authored file,
`keystore-delivery.yaml`, root:wheel 0644, read on every sweep the way `ManifestDir`
re-reads its directory (start, debounced fsnotify, a periodic backstop):

```yaml
targets:
  - name: signer-key       # a keystore entry name (must already exist)
    namespace: payments
    secretName: signer-key # defaults to the entry name
    dataKey: private.key   # the key inside the Secret's data map
```

Neither the issue nor the maintainer's acceptance names a sixth CLI verb for this, so a
declarative file (matching how `ManifestDir` already solves "an operator declares
something the control plane keeps converged") is proposed rather than a new verb; this is
the one section of this document with no prior steer to anchor against, flagged plainly as
open.

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

**Refusal while secrets encryption is off:** per the maintainer's answer, refused by
default. The override is `--allow-plaintext-secrets-delivery` on `k3sm server`, carried the
same way `--secrets-encryption` already is, read fresh at the start of every sweep (not
decided once at install) and applied per-target — a target already delivered before the
flag was removed is left as it is; this converge-only reconciler does not retroactively
delete a Secret an operator may be relying on. The refusal is logged at Warn (there is no
Kubernetes object representing a keystore entry itself to attach an Event to in Phase A)
and reflected in `k3sm keys list`'s output as a per-target delivery-blocked note.

## Rotation and rollback

**Crash-safe write order:** Rotate writes the new version file first (durable, not yet
referenced) and flips the current pointer last. A crash between the two leaves the old
version current and an unreferenced new version file; a retry either reuses that file (if
never promoted) or removes it first rather than risk two different plaintexts under the
same (name, version, generation) identity.

**Retention:** every version is kept indefinitely in Phase A; nothing deletes a single old
version short of `rm` of the whole entry. The simplest correct answer, left open for a
later phase to bound once real usage shows it matters, rather than guessed now.

**Delivered-Secret movement:** covered above under "Re-delivery on rotation" — automatic
on the next sweep after a Rotate.

**Rollback:** no dedicated verb. An operator rolls back with
`k3sm keys rotate <name> --in <(k3sm keys show <name> --version N --reveal)` — writing the
old version's value forward as a *new* version, never pointing `current` backward at an
existing version file. This keeps rotation the one write path to reason about; a direct
point-current-backward operation would be safe to add later (an old version's generation
always still matches) but is not needed for Phase A since re-rotating the old value already
covers the need.

## Backup and snapshots

Not in datastore snapshots (fixed). What an operator backs up instead:

- `keystore/` (including every entry's `generation` file — always a sibling of the
  version files it belongs with, under the same entry directory).
- `cred/keystore-master` and its fingerprint, **separately** — ideally to a different
  location or schedule than the entries, for the same reason they live in a different
  directory on the live host: a backup of "the keys" that does not also hand over "the one
  file that unlocks them" is one a less-trusted location can hold without becoming a full
  compromise if it leaks.
- A restore is checked the same way a live read is: mode, ownership and fingerprint
  verified on the restored master before anything is trusted to open under it, so a
  mismatched restore fails loudly (`ErrMasterUntrusted`, or every entry `ErrCorrupt`)
  rather than silently decrypting into garbage.
- `k3sm snapshot restore`'s existing group/other-readable warning for a handed-in file
  (`docs/user/backup-restore.md`) is the right model for a restored master too, rather than
  a differently-worded warning for the same operator mistake.

## Non-goals

Beyond Phases B and C: isolating one native Pod's delivered Secret from another; protecting
key material from root on the host; a KMS- or HSM-backed master (the master is a file,
protected the same way the existing `secretbox` key is — a hardware-backed master is a
later proposal, as issue 731 already notes for the existing key); a network service or new
IPC surface; bounded version retention or a point-in-time rollback verb in Phase A.

## Open questions

The maintainer's answers to the four questions asked in issue 731:

1. Is the direction welcome? Yes.
2. How does design review run? As this document, by pull request, with maintainer
   review on that pull request.
3. What happens when secrets encryption is off? The reconciler refuses delivery, with
   an explicit override flag, as proposed.
4. In what order do the phases land? Phase A first. Phases B and C are filed as
   separate issues after Phase A lands.

Owed by the implementation: the acceptance gate script for Phase A, under
`hack/acceptance/`, named in the implementation pull request.

Still open, raised by this revision, for review on this pull request:

- The master key pair's exact directory (`cred/` vs. its own `keystore-master/`
  directory one level further away).
- The delivery-target declaration mechanism (a file vs. a new `k3sm keys` verb, and the
  file's exact name/path/schema if a file).
- Whether `Rewrap` needs a distinct sentinel for a non-empty, wrong-length new-master
  argument, beyond the scaffold's existing `ErrMasterMissing` for the empty case.
- Whether bounded version retention is wanted now or deferred to real-usage evidence.
