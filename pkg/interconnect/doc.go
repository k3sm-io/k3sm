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

// Package interconnect is the domain logic of the net.k3sm.io Interconnect: the
// Thunderbolt cable between Macs as an opt-in, admin-armed network beside the
// wireguard mesh. cmd/k3sm only wires it.
//
// Three loops share it:
//
//   - The node Reporter (every node) discovers the local Thunderbolt ports, probes
//     the peers' slot-0 interconnect addresses, and writes the
//     k3sm.io/interconnect-report annotation on its OWN Node, only when the
//     report changes and at most once per InterconnectReportMinInterval.
//   - The node DesiredHandler (every node) reads the k3sm.io/interconnect-desired
//     annotation on its own Node and, level-triggered, asks the root helper to
//     ensure or remove the node's slot-0 alias on bridge0.
//   - The server Resolver (servers only, one leader at a time) validates every
//     report, resolves members, segments, loops and hysteresis into the
//     Interconnect status, auto-creates the object disabled, and owns the desired
//     annotation on every Node.
//
// Every interconnect address is derived with netv1alpha1.InterconnectSlotAddress
// from the node's cluster index (its pod /24's index in the cluster pod
// aggregate): one connected /24 on bridge0 and no route. Nothing here ever
// derives an address any other way, and a node whose index is beyond
// netv1alpha1.MaxInterconnectNodeIndex is never a member.
//
// # The desired annotation is advisory (plan I6)
//
// A node can edit its own Node object, so it can rewrite its own desired
// annotation. That is not an escalation: the most a node editing its desired
// annotation can achieve is that the root helper adds the node's own in-policy
// derived alias on the node's own host, which the node already controls. The
// arming decision is enforced by the server Resolver, which overwrites any
// desired value that disagrees with the Interconnect's spec on every reconcile,
// and by the root helper, which recomputes every address from its own adopted
// node identity and accepts nothing but a slot from the client. The apiserver
// does not enforce it, and nothing here pretends it does.
//
// Nodes never read the Interconnect object (that would widen what a node
// identity may LIST/WATCH); they patch only annotations on their own Node, which
// the Node authorizer and NodeRestriction already allow.
package interconnect
