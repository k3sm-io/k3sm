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

// Package deliver delivers keystore entries into the cluster as Secrets: the
// delivery declaration `k3sm keys deliver` writes, and the reconciler the
// server runs over it (docs/design/keystore.md § "Delivery reconciler").
//
// # The declaration
//
// /var/lib/k3sm/keystore-delivery.json (FileName in the data root) lists the
// targets, {"version":1,"targets":[{"entry","namespace","secretName","dataKey"}]},
// entry being system/<name>; a user/ entry is refused.
// Only `sudo k3sm keys deliver|undeliver` writes it, root:wheel 0644, by
// temp-and-rename with the directory fsynced. It decides which namespace the
// server's admin client writes a Secret into, so it is read the way the
// manifest directory's files are: opened with O_NOFOLLOW and judged on the
// opened descriptor by addons.RootOwnedNotShared. A file that fails that check,
// is over MaxFileBytes, names more than MaxTargets targets, carries an unknown
// field or another version is refused whole and logged, and nothing is
// delivered from it.
//
// # The reconciler
//
// It runs in the server process with the admin client the embedded add-on
// reconciler already holds, and adds no role, binding or ServiceAccount. What
// it does with that client is narrower than the client allows: per target it
// Gets the one named Secret, then
//
//   - absent: creates an Opaque Secret labelled LabelKey=<entry> and
//     annotated with the version and fingerprint, holding the entry's current
//     value under the data key (an Ed25519 entry's stored seed or key bytes,
//     with no PEM), and records the UID the apiserver gave it in the state
//     file (StateFileName, 0600, in the server's work dir and owned by the
//     server's euid; see StateFileName for why that owner adds no trust);
//   - present with the recorded UID, whatever its label says (a missing or
//     other label is put back): updates it when its label is not this
//     entry's, or its VersionAnnotation or FingerprintAnnotation differs from
//     Store.Current's version or fingerprint, or its data is not exactly the
//     declared key holding the stored bytes (compared in constant time, so a
//     hand edit with the annotations left intact is re-applied and logged,
//     without the value). When only the label or the annotations differ and
//     the data is current, only the metadata is updated, immutable or not.
//     An immutable one whose data is not current cannot be updated, so once
//     the state file is proven writable it is deleted under a precondition
//     on the recorded UID, created again and the new UID recorded, both
//     steps logged once without the value; while it is already being
//     deleted, it is left to finish;
//   - present with the recorded UID and its entry deleted: once Store.Absent
//     confirms the entry is definitively gone (Current's ErrNotFound alone is
//     not enough: a missing entries' directory answers it too), deletes it
//     under a precondition on the recorded UID and logs the names, never a
//     value; a missing label or annotation is logged at Warn. A withdrawn
//     target's entry is the one its state record names, not its label. The
//     keystore floor, the restore hold and the breaker (revoke.go) hold the
//     delete after a restore, for 10 minutes after a start, and when many
//     entries go at once; the delete is done once a Get no longer finds it;
//   - anything else (no recorded UID, or a UID other than the recorded one,
//     whatever its label): leaves it alone and logs why. The
//     label is forgeable by anyone who can write Secrets in the namespace;
//     the UID a create returned is not, and a recreated Secret gets a new one.
//
// An update of the value writes data, type, the label and the two
// annotations, and strips any immutable flag. A target withdrawn from a declaration that exists and
// parses loses its state record, so declaring it again leaves the old Secret
// alone; an absent declaration withdraws nothing and keeps every record,
// and warns once with the number of Secrets rotations no longer reach.
//
// It never lists, deletes only an owned Secret under a UID precondition (an
// immutable one to re-deliver it, or one whose entry is deleted, declared or
// withdrawn) and touches no other kind, so withdrawing a target of a live
// entry (`k3sm keys undeliver`) leaves its Secret in place. A per-target
// failure is logged and the sweep moves on; each target's calls have their
// own ten-second deadline, so one hung call cannot stall the rest. The data
// root holding the declaration, the state file and the lock is itself judged
// on its descriptor (O_NOFOLLOW|O_DIRECTORY, root's, not shared-writable)
// before any of them is read or written. It sweeps on start, on a
// debounced change to the declaration, and every addons.ManifestSweepInterval.
//
// # Encryption
//
// While secrets encryption is off, a delivered Secret would sit in plaintext
// in the datastore, so every target is refused unless the server was started
// with --allow-plaintext-secrets-delivery. Whether encryption is on is the
// server's own start-time verdict (executor.EncryptionAtStart), handed in at
// construction, so the reconciler cannot disagree with the apiserver. A
// refusal is logged at Warn once per target per state change. A target
// delivered before the override was removed is left as it is, but revoked
// when its entry is deleted: a delete writes no value.
package deliver
