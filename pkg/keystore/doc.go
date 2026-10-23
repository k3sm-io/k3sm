/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package keystore is k3sm's in-repo keystore: named, versioned key material
// kept encrypted at rest on a server, rotated without a window in which no
// version is current, and delivered into the cluster as Secrets.
//
// # Status
//
// This package is a scaffold. The implementation is contributed under issue
// k3sm#731 against the design in docs/design/keystore.md, and the contract in
// keystore.go is a sketch that design review may still change.
//
// # Scope (Phase A)
//
// Phase A covers:
//
//   - named, versioned entries of two kinds, Ed25519 private keys and opaque
//     bytes;
//   - encryption at rest, rotation, listing, deletion, and re-wrapping every
//     entry under a new master key;
//   - the operator verbs `sudo k3sm keys put|list|rotate|rm|show` (planned, not
//     yet present), which will never print a value unless asked with --reveal;
//   - a control-plane reconciler, in the style of pkg/addons, that writes one
//     labelled Secret per declared target, refuses delivery while secrets
//     encryption is off unless the operator overrides that explicitly, and
//     modifies only Secrets it created.
//
// Keys that never enter the datastore (Phase B) and KMS v2 envelope encryption
// of the datastore (Phase C) are separate, later work and are out of scope here.
//
// # Threat model
//
// The keystore inherits the threat model k3sm already documents: one node is
// one trust domain, and every native Pod runs as the same service user. The
// keystore therefore provides encryption at rest, rotation, and delivery gated
// by RBAC. It does not isolate one native Pod from another, and it does not
// protect key material from root on the host.
//
// # Fixed storage decisions
//
// These are settled and are not reopened by the design review:
//
//   - Standard library only. No new module enters the graph for the keystore.
//   - The master key is a mode 0600 file owned by the service user, with a
//     fingerprint beside it, in a directory separate from the entries, so a
//     copy of the entries alone decrypts nothing.
//   - Every entry version is sealed with AES-256-GCM. The additional data is
//     a length-prefixed encoding of (record-format version, kind, name,
//     version), never a bare concatenation, so a ciphertext moved to another
//     name, version or kind fails to open.
//   - The nonce is 96 bits from crypto/rand, fresh on every seal, Rewrap
//     included, and never derived from the name or the version.
//   - Rotation is crash safe: the new version is written and made durable
//     first, and the pointer to the current version flips last. The pointer
//     is written to a temporary file and renamed into place, with the file and
//     its directory fsynced. The pointer's target version is covered by the
//     same authenticated record, so a writer of the files cannot roll an entry
//     back by editing the pointer alone. A crash at any point leaves either the
//     old or the new version current, never neither.
//   - Rewrap is two-phase: the new master key is written beside the old one,
//     every version is re-sealed under it, and then the pointer to the master
//     flips. A crash leaves both masters present and nothing unreadable.
//   - A Delete followed by a new Put of the same name at version 1 must not
//     reopen a replayed old record: each record carries a per-entry
//     generation, or the implementation states why replay is accepted under
//     the same-user threat model.
//   - The master key file is opened with O_NOFOLLOW and checked with fstat on
//     the open descriptor (owner, mode) and against its fingerprint. The
//     fingerprint detects a wrong file, not tampering. `sudo k3sm keys` runs
//     as root against a file owned by the service user, so ownership is
//     checked, never assumed.
package keystore
