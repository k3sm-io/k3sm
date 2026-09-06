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

// Package dataroot inspects k3sm's data root (/var/lib/k3sm) so the daemons can
// tell three postures apart before they write anything into it:
//
//   - a plain directory (the default install) — create and own it;
//   - a MOUNTED volume — use it;
//   - a DECLARED but UNMOUNTED volume — refuse, because anything written now
//     lands in the bare mountpoint on the boot disk and shadows the real data.
//
// The only sanctioned way to put the data root on its own volume is an
// /etc/fstab line whose mount-point field is the data root itself:
//
//	UUID=<volume-uuid> /var/lib/k3sm apfs rw
//
// That file is therefore the one declaration this package reads. Any other
// mechanism for mounting a volume there (a login item, a hand-run diskutil, an
// automounter map) is out of contract: k3sm cannot distinguish "the operator
// meant this to be a volume" from "this is a plain directory", so it will treat
// an unmounted root as plain and populate it.
//
// The shadow posture is not hypothetical. On 2026-09-05 the declared volume
// failed to mount at boot; the root netd helper created <root>/run inside the
// empty mountpoint, the unprivileged control plane could not create its own
// work-dir beside it, and the server crash-looped ~500 times. Had the shadow
// been writable instead, the control plane would have built a fresh, empty
// datastore over a perfectly good one — the worse of the two outcomes, and the
// reason the check refuses rather than repairs.
//
// The package is a leaf: it imports nothing from k3sm.io beyond the standard
// library and golang.org/x/sys/unix, so both pkg/install and cmd/k3sm can use
// it without an import cycle.
package dataroot
