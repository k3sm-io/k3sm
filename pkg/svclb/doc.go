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

// Package svclb is k3sm's klipper-lite LoadBalancer implementation (M10.3,
// closes B32): a server-side controller that, for every Service of type
// LoadBalancer, binds BindAddr:servicePort listeners and splices each accepted
// connection to the Service's ClusterIP VIP (a plain two-way TCP forward —
// the L4 Service proxy behind the VIP keeps EndpointSlice tracking, affinity,
// and mesh-egress discipline). It is DISTINCT from pkg/loadbalancer, the M6
// client-side HA apiserver LB.
//
// # Bind and advertise are different addresses (B116)
//
// Listeners bind the WILDCARD (0.0.0.0) — every interface answers, matching
// Docker Desktop's vpnkit and k3s' klipper-lb — while status advertises the
// node's derived globally-unicast InternalIP. On Darwin a wildcard bind needs
// NO privilege at any port (it is the SPECIFIC-address privileged bind that
// returns EACCES — inverted from Linux), so there is ONE in-process binder and
// the root netd helper is off the LoadBalancer datapath entirely.
//
// Two consequences the assembler and the operator docs own, not this package:
// pods share the node's port space (darwin has no network namespaces), so a
// wildcard LB listener can collide with a pod's own listen(); and the advertised
// address is reachable over lo0 and the mesh only, while the listener answers on
// every LAN interface.
//
// # Status honesty
//
// status.loadBalancer.ingress = [{ip: AdvertiseAddr}] is written ONLY once every
// TCP port's listener is actually bound — never advertise a dead address. An
// un-bindable port (conflict, or a k3sm-RESERVED port this controller refuses
// outright) leaves the status empty with a throttled Warn; a Service that loses
// its listeners has this node's entry retracted (see Retractable). A zero
// AdvertiseAddr means the node address could not be derived: listeners still
// bind, and NO status is ever written. UDP
// LoadBalancer ports are DEFERRED (the userspace splice is TCP-only today):
// they are skipped with a throttled Warn and do not gate the TCP ports'
// status. Services carrying IgnoreLabel (the canonical kube-system/
// k3sm-ingress, whose listeners the in-process ingress Server owns) are
// skipped entirely.
package svclb
