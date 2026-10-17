# Keystore design

Status: draft. The contributor who opened issue 731 fills in the sections below
by pull request; the package scaffold is `pkg/keystore`, and its contract sketch
in `pkg/keystore/keystore.go` may change as this document is reviewed.

## Problem

What key material operators need k3sm to hold today, where it lives without a
keystore, and what goes wrong as a result.

## Scope

Phase A only: named, versioned entries (Ed25519 keys and opaque bytes),
encryption at rest, rotation, list, delete, master key re-wrap, the
`k3sm keys` verbs and the delivery reconciler.

Out of scope here: keys that never enter the datastore (Phase B) and KMS v2
envelope encryption of the datastore (Phase C). Each is a separate issue after
Phase A lands.

## Threat model

This statement is fixed. One node is one trust domain, and every native Pod
runs as the same service user. The keystore provides encryption at rest,
rotation, and delivery gated by RBAC. It does not isolate one native Pod from
another, and it does not protect key material from root on the host.

## Storage format and master key

The fixed decisions:

- Standard library only.
- The master key is a mode 0600 file owned by the service user, with a
  fingerprint beside it, in a directory separate from the entries.
- Each version is sealed with AES-256-GCM. The additional data is a
  length-prefixed encoding of (record-format version, kind, name, version),
  never a bare concatenation.
- The nonce is 96 bits from crypto/rand, fresh on every seal including Rewrap,
  never derived from the name or the version.
- The current pointer flips last on rotation. It is written to a temporary
  file and renamed into place, with the file and its directory fsynced, and
  its target version is covered by the same authenticated record, so a writer
  of the files cannot roll an entry back by editing the pointer alone.
- Rewrap is two-phase: the new master is written beside the old one, every
  version is re-sealed, then the pointer to the master flips. A crash leaves
  both masters present and nothing unreadable.
- A Delete followed by a new Put of the same name at version 1 must not reopen
  a replayed old record: the record carries a per-entry generation, or this
  document states why replay is accepted under the same-user model.
- The master file is opened with O_NOFOLLOW and checked with fstat on the open
  descriptor (owner, mode) and against its fingerprint. The fingerprint
  detects a wrong file, not tampering. `sudo k3sm keys` runs as root against a
  file owned by the service user, so ownership is checked, not assumed.
- Entry names are validated before they become file names: not empty, no path
  separator, not made only of dots.
- The fingerprint of an Ed25519 entry is a digest of its public key; that of
  an opaque entry is keyed (an HMAC under a key derived from the master) or
  truncated, never a plain hash of the value, so List output is not a
  guessing oracle for a low-entropy value.
- An Ed25519 value is the 32-byte seed or the 64-byte expanded private key,
  and is validated on Put.

To answer: the on-disk layout and file names, the record encoding and its
version field, the exact fingerprint construction, and which refusal each
corrupt or missing file produces.

## CLI (`k3sm keys`)

The verbs `sudo k3sm keys put|list|rotate|rm|show`. To answer: each verb's
arguments and output, how values are read in without landing in shell history,
and that no value is printed unless `--reveal` is given.

## Delivery reconciler

A control-plane reconciler in the style of `pkg/addons` that writes one
labelled Secret per declared target. To answer: how targets are declared, the
fixed encoding of an Ed25519 key in the delivered Secret, the label that marks
a Secret as keystore-owned, and how the reconciler proves ownership so it
modifies only Secrets it created.

It refuses delivery while secrets encryption is off. To answer: the name and
shape of the explicit override, and how the refusal is surfaced to the
operator.

## Rotation and rollback

To answer: the write order that keeps rotation crash safe, how many old
versions are kept and for how long, how a delivered Secret moves to a new
version, and how an operator rolls back to an earlier one.

## Backup and snapshots

The keystore is not in datastore snapshots. To answer: what an operator backs
up, where the master key backup goes relative to the entries, and how a restore
is checked against the recorded fingerprint.

## Non-goals

To answer: what this design deliberately does not do, beyond Phases B and C,
for example isolation between native Pods or protection from root on the host.

## Open questions

The maintainer's answers to the four questions asked in issue 731:

1. Is the direction welcome? Yes.
2. How does design review run? As this document, by pull request, with
   maintainer review on that pull request.
3. What happens when secrets encryption is off? The reconciler refuses
   delivery, with an explicit override flag, as proposed.
4. In what order do the phases land? Phase A first. Phases B and C are filed as
   separate issues after Phase A lands.

Owed by the implementation: the acceptance gate script for Phase A, under
`hack/acceptance/`, named in the implementation pull request.

Still open: (add questions here as review raises them)
