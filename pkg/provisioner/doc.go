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

// Package provisioner is the k3sm APFS local-path PersistentVolume provisioner
// (k3sm:M3.2): an in-process, API-object-only controller — NOT a
// kube-controller-manager controller — that registers the local-path
// StorageClass and, for each PersistentVolumeClaim bound to it once the scheduler
// has selected a node, creates the backing PersistentVolume object. The embedded
// kube-controller-manager's in-tree persistentvolume-binder then binds the PVC to
// the PV, and runtimed mounts the directory into the pod.
//
// # No filesystem I/O at the PV path
//
// The provisioner creates PV *objects* only; it does NO filesystem work at the
// volume path. The per-(namespace, claim) directory is empty-created by runtimed
// on the CONSUMING node when the pod mounts the volume, keyed identically via
// storagev1.DataDir. This is deliberate: the control-plane Mac that runs the
// provisioner must never touch a path that lives on a worker Mac (it would EACCES,
// and the path may not exist there). The PV's local.path is therefore ADVISORY —
// correctness rests on two things that do not depend on it:
//
//   - the PV's required nodeAffinity (storagev1.NodeTopology), which pins the
//     consuming pod to the provisioning/selected node so it reschedules to the
//     SAME Mac that holds its data; and
//   - runtimed's own per-(namespace, claim) directory derivation on that node.
//
// The advisory path is computed from the RESOLVED storage root (ClassForRoot:
// <runtime-root>/storage — the same root runtimed derives against, see
// runtimed/pkg/runtime), NOT the root-only storagev1.DefaultBasePath, so it is
// accurate under the unprivileged _k3sm home.
//
// # Idempotency and restart safety
//
// The PV object name is derived from the immutable PVC UID (storagev1.PVName), so
// a duplicate reconcile — a stale watch-cache re-delivery, load-bearing under
// kine's watch-staleness posture — re-derives the same name and the duplicate
// Create returns AlreadyExists, a no-op. On control-plane restart the informer's
// initial sync re-delivers every existing PVC as an Add, so each is reconciled
// check-before-create and nothing is stranded.
//
// # Reclaim policy: Retain only
//
// The class is registered with reclaimPolicy: Retain, explicit — NOT the
// Kubernetes Delete default. k3sm has no volume-delete path (no RPC root-rmdir's a
// pod-owned dir), so a Delete class would strand PVs Released and leak their
// directories onto the APFS volume kine's SQLite shares. WaitForFirstConsumer
// binding makes the scheduler pick the node before the PV is created and pinned.
//
// # Honest gaps (dev/CI scope; production mitigations noted)
//
//   - SHARED VOLUME: PV storage lives on the same APFS volume as the kine
//     state.db (<runtime-root>/storage beside the control-plane db). An unbounded
//     PV can ENOSPC the datastore. Acceptance is dev/CI scope; the production
//     mitigation is a separate volume for /var/lib/k3sm/storage.
//   - BEST-EFFORT CAPACITY: capacity.storage is echoed from the PVC request but
//     not enforced against free space (there is no per-dir quota), so an
//     over-commit surfaces as a write-time ENOSPC — the same honesty as the
//     best-effort-CPU resource gap (DESIGN §5a).
//   - RETAINED BYTES ON RECREATE: because the backing dir is keyed by
//     (namespace, claim) and survives under Retain, a deleted-and-recreated PVC of
//     the SAME name inherits the prior bytes. This is INTENDED for a StatefulSet's
//     stable per-replica storage (the whole point of stable identity) and is
//     bounded by k3sm's single _k3sm trust domain (one uid owns every pod dir).
//
// # StatefulSet support (excluded subset)
//
// Stable STORAGE and stable NAME identity work: a StatefulSet's per-replica PVC
// gets a node-pinned PV, and the pod reschedules to its data. Stable NETWORK
// identity is GAPPED on the hostprocess runtime — every hostprocess pod reports
// podIP = nodeIP (pkg/provider/hostprocess.go), so per-pod stable DNS via a
// headless Service does not resolve to distinct addresses. Headless-Service peer
// discovery is therefore an explicit excluded subset of M3.2; it needs per-pod
// IPs (the runtimed lo0-alias path). See docs/DESIGN.md §5c.
package provisioner
