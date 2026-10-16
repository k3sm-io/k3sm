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

// Package updatectl is the server's update controller: it rolls the cluster to
// the release an updates.k3sm.io/v1alpha1 Update names, one node at a time,
// every worker first and the server last.
//
// # The singleton
//
// Only the Update named updatesv1alpha1.UpdateName ("current") is reconciled.
// Any other Update gets its Reconciled condition set False with the reason
// NotTheSingleton, and no node is touched for it.
//
// # The roll
//
// The first reconcile of the singleton records the plan in status.nodes: every
// node that is not a server, sorted by name, then every other server, then the
// server this controller runs on, last. Each entry records the release the node
// ran (From) and the target (To). The roll then visits the entries in order,
// one at a time (Spec.Strategy.MaxUnavailable is honoured as 1, the only value
// the server-last order allows):
//
//   - A node whose kubeletVersion already carries the target is Skipped.
//   - Before the first node is touched, the target is resolved once against
//     the release index (the darwin/arm64 archive and its sha256 from the
//     release's checksums file) and recorded in status.resolved. A release
//     that does not exist, or whose checksums name no archive, fails the roll
//     before any node is cordoned.
//   - The node is cordoned. A node an operator had already cordoned stays
//     cordoned after the update: only a cordon this controller made (marked by
//     the CordonedAnnotation) is lifted.
//   - With Spec.Strategy.Drain, a node other than the server is drained. Its
//     pods are listed first: a pod with no controller owner would not come
//     back, so the node fails with the list and nothing is evicted. The rest
//     are evicted through the eviction API, so PodDisruptionBudgets hold;
//     DaemonSet-owned, mirror and finished pods stay. A drain still blocked
//     after the drain timeout fails the node. The server is never drained: the
//     install recreates its native pods anyway. Drain on a one-node cluster is
//     refused before anything starts.
//   - The node is handed over: the Node annotations k3sm.io/update-version (the
//     tag) and k3sm.io/update-payload (a JSON Payload: the archive URL, its
//     sha256, the signature policy and the downgrade permission) are set, a
//     stale k3sm.io/update-phase is cleared and the handover time is recorded,
//     in one patch. The node timeout counts from the handover.
//   - The node-side applies the release and reports k3sm.io/update-phase as
//     "<phase>[: <message>]". The controller mirrors the phase into status;
//     Failed fails the node. The node is done once it reports Done, its
//     kubeletVersion carries the target and it is Ready, and has stayed so for
//     SettlePeriod; then its cordon is lifted and the roll moves on.
//
// Every node phase transition is an Event on the Update and on the Node and an
// Info log line; node messages and the Progressing condition end in "last
// progress <RFC3339>". A transient release-index failure is retried for
// ResolveBound, then fails the Update.
//
// A failed node stops the roll: status.phase is Failed, the failed node stays
// cordoned with its annotations for the operator, and every later node stays
// Pending. Spec.Cancel lets a node that has been handed over finish, lifts the
// cordon of a node that has not, and marks every node not started Cancelled;
// the Update ends Cancelled. A finished Update (Succeeded, Failed or
// Cancelled) is never resumed: Spec.Version is immutable, so a retry is a new
// "current".
//
// # Restart safety
//
// Every step is idempotent over the persisted status and the Node objects, so a
// restarted controller resumes where the last one stopped. That restart is part
// of the design, not an accident: the server updates itself last, through the
// same node-side path, and its controller restarts on the new release while its
// own entry is in progress. The timeouts and the settle count from
// status.nodes[].startedAt and the controller's own Node annotations, which
// survive the restart. On an HA control plane the controller runs under a
// Lease, so one server rolls at a time.
package updatectl
