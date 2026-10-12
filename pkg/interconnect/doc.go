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

// Package interconnect is the domain logic of the cable interconnect: the
// Thunderbolt cable between cluster Macs used as a named network beside the
// wireguard mesh (net.k3sm.io/v1alpha1 Interconnect). cmd/k3sm only wires it.
//
// # The three parts
//
//   - The node REPORTER (Reporter) runs on every node. It discovers the node's
//     Thunderbolt ports and their cabled peers, probes each peer node's slot-0
//     interconnect address, and writes an InterconnectReport on its OWN Node as
//     the k3sm.io/interconnect-report annotation. It writes only when the stable
//     content changes, and at most once per InterconnectReportMinInterval; a
//     change inside that window is written when the window ends, never dropped.
//   - The node DESIRED HANDLER (DesiredHandler) runs on every node. It reads the
//     k3sm.io/interconnect-desired annotation the server writes on the same
//     Node and asks the root network helper for the node's slot-0 alias, or for
//     its removal. It is level-triggered: the alias is ensured again on a timer,
//     so a helper restart or a reboot restores it with no operator action.
//   - The server RESOLVER (Resolver, with the pure Resolve at its core) runs in
//     the server process on the server's own client, as the single writer chosen
//     by a coordination.k8s.io Lease. It auto-creates Interconnect "thunderbolt"
//     with Enabled false the first time a node reports a cabled peer, validates
//     every report as untrusted input, computes members, segments and loops,
//     and owns the desired annotation on every Node.
//
// # Addresses
//
// Every address comes from netv1alpha1.InterconnectSlotAddress(idx, slot): one
// connected /24 (netv1alpha1.InterconnectCIDR) on bridge0 and no route. A node
// whose cluster index is above netv1alpha1.MaxInterconnectNodeIndex is reported
// down with ReasonInterconnectIndexOutOfRange; it never fails the object.
//
// # Authority (no new RBAC)
//
// A node never reads the Interconnect object. It reads and writes only
// annotations on its own Node, which it already may, and lists MeshPeers, which
// the node-datapath grant already allows. The resolver uses the server's admin
// client.
//
// A node editing its own desired annotation can at most make netd add its own
// in-policy derived alias on its own host; arming is enforced by the resolver
// plus netd's recomputation, not by the apiserver. The resolver also reverts any
// desired value that disagrees with policy on its next pass.
//
// # Seams left for later work
//
//   - Pod attach (slots 1..7) is not here; AttachedPods stays as written and the
//     attached-pods gauge stays 0 until the provider opt-in sets it
//     (Metrics.SetAttachedPods).
//   - A node with an attached MLX rank also probes peers' slot-1 addresses; the
//     Reporter's ExtraTargets hook is where that probe set joins.
package interconnect
