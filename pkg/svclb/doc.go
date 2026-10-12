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

// Package svclb is k3sm's klipper-lite LoadBalancer implementation, in two
// roles. It is DISTINCT from pkg/loadbalancer, the client-side HA apiserver LB.
//
// # Two roles
//
// The Decider runs in the server process on the admin client. For every
// claimed LoadBalancer Service (Claims) it selects the hosting nodes
// (selectHosts: the svclb.k3sm.io node-pool labels, k3s' nodePoolAffinity over
// k3sm-owned keys), stamps them on the Service (HostsAnnotation), and writes
// the Service's whole status.loadBalancer.ingress (computeIngress). It is the
// ONLY writer of both.
//
// A Hoster runs in every node process (each joined worker and the server's
// own node) on that node's own system:node identity. It binds
// BindAddr:servicePort for each Service whose stamp names it and splices every
// accepted connection to the Service's ClusterIP VIP (a plain two-way TCP
// forward; the node's L4 Service proxy behind the VIP keeps EndpointSlice
// tracking, affinity, and mesh-egress discipline). It writes no Service. It
// reports the Services whose every TCP port it holds on its OWN Node
// (BoundAnnotation), a self-write the Node authorizer and NodeRestriction
// already admit, so the split adds no RBAC.
//
// # Status honesty
//
// The status lists a node only when the node is in the stamp, is Ready, and
// its trusted report names this incarnation (uid) of the Service: never
// advertise a dead address. The decider REPLACES the whole slice on every
// write and recomputes it on every resync, so a node leaving a pool loses only
// its own entry, a lost write is repaired, and a previous life's address is
// never stranded. An empty result is the honest pending state, with a
// NoEligibleNodes Event when no node qualifies and a HostNotBound Event naming
// a Ready stamped node that has not bound every port (a port taken by a pod or
// another Service, a k3sm-RESERVED port the hoster refuses outright, or invalid
// source ranges). UDP LoadBalancer ports are DEFERRED (the userspace splice is
// TCP-only today): they are skipped with a throttled Warn and do not gate the
// TCP ports. Services carrying IgnoreLabel (the canonical
// kube-system/k3sm-ingress, whose listeners the in-process ingress Server owns)
// are skipped entirely.
//
// Report trust: a hoster writes a fresh incarnation with no Services at start,
// before binding anything, and re-issues its report under a new incarnation
// when it sees its own node turn Ready. The decider ignores a report whose
// incarnation the node already held before turning Ready, until it changes or
// for at most the hold-down, so a report left by a dead process does not
// vouch for a restarted one. A newly started decider also defers status
// changes for a Service for the hold-down unless every stamped host reports
// it, so a server restart does not retract every LoadBalancer in the cluster.
//
// # Addresses
//
// Listeners bind the WILDCARD (0.0.0.0): every interface answers, matching
// Docker Desktop's vpnkit and k3s' klipper-lb. On Darwin a wildcard bind needs
// NO privilege at any port (it is the SPECIFIC-address privileged bind that
// returns EACCES, inverted from Linux), so there is ONE in-process binder and
// the root netd helper is off the LoadBalancer datapath entirely.
//
// The status publishes SERVER-HELD addresses only: each node's mesh address
// from its MeshPeer record (written only through the server's guarded enroll
// path), and the server's own derived address for its own node. Never
// Node.status.addresses, which the node writes itself. A node with no
// server-held address is never selected.
//
// Two consequences the assembler and the operator docs own: pods share the
// node's port space (darwin has no network namespaces), so a wildcard LB
// listener can collide with a pod's own listen(); and the advertised address
// is reachable over lo0 and the mesh only, while the listener answers on every
// LAN interface.
//
// # Trust posture
//
// The pool and allow-list labels live on Node objects, and NodeRestriction lets
// a node edit non-kubernetes.io labels on itself. A compromised node can
// therefore label itself into a pool and attract that pool's traffic, the same
// posture as k3s ServiceLB. Allow-list mode triggers only on the value "true",
// so a node cannot starve the others by labelling itself "false". A node's
// report can only narrow the decider's choice: it never adds the node to a
// stamp or puts an address it chose into a status.
//
// # externalTrafficPolicy: Local
//
// Not narrowed: every host splices to the ClusterIP, so a Local Service is
// hosted like a Cluster one and the client source address is lost.
//
// # Source ranges
//
// spec.loadBalancerSourceRanges (else the legacy annotation, else allow-all) is
// enforced the k3s/klipper-lb way: on LoadBalancer traffic only, never on
// nodePorts, as an accept-time close of a denied peer BEFORE the backend dial.
// SourceRanges is the one home of the rule; the ingress host applies the same
// rule to the canonical Service it owns. A set that does not parse fails closed
// on first provisioning (no listener, the node is not reported); on an edit the
// last valid set stays in force and the listeners keep serving. The
// SourceRangesInvalid Warning Event is the decider's, written with the server
// process's client: a node identity records no Service Events.
package svclb
