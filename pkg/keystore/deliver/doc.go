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
// targets, {"version":1,"targets":[{"name","namespace","secretName","dataKey"}]}.
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
//     file (StateFileName, root:wheel 0600, beside the declaration);
//   - present, labelled for this entry and with the recorded UID: updates it
//     only when its VersionAnnotation or FingerprintAnnotation differs from
//     Store.Current's version or fingerprint, or its data is not exactly the
//     declared key holding the stored bytes (compared in constant time, so a
//     hand edit with the annotations left intact is re-applied and logged,
//     without the value). An immutable one cannot be updated: it is left
//     as it is and logged at Warn once per state change, for the operator to
//     delete;
//   - anything else (no label, another entry's label, no recorded UID, or a
//     UID other than the recorded one): leaves it alone and logs why. The
//     label is forgeable by anyone who can write Secrets in the namespace;
//     the UID a create returned is not, and a recreated Secret gets a new one.
//
// An update writes data, type, the label and the two annotations, and strips
// any immutable flag. A target withdrawn from the declaration loses its state
// record, so declaring it again leaves the old Secret alone.
//
// It never lists, never deletes and touches no other kind, so withdrawing a
// target (`k3sm keys undeliver`) leaves its Secret in place. A per-target
// failure is logged and the sweep moves on. It sweeps on start, on a
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
// delivered before the override was removed is left as it is.
package deliver
