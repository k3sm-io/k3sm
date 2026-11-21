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
//     annotated VersionAnnotation=<version>, holding the entry's current
//     value under the data key (an Ed25519 entry's stored seed or key bytes,
//     with no PEM);
//   - present and labelled for this entry: updates it only when its
//     VersionAnnotation differs from Store.Current's version;
//   - present without the label, or labelled for another entry: leaves it
//     alone and logs why.
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
