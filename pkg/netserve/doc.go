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

// Package netserve hosts k3sm's pod-networking services inside the server
// process by consuming darwin-net's seams — it does NOT reimplement Service/VIP
// translation or DNS ndots/search.
//
// It runs, per node:
//   - the userspace Service proxy: a proxy.Proxy driven by proxy.NewWatcher off
//     the cluster's Services + EndpointSlices, owning one lo0-alias socket per
//     ClusterIP:port (the macOS-native kube-proxy analog), sourced from the node's
//     mesh-egress /32 for cross-node backend dials (proxy.WithMeshEgressSource),
//     with the NetworkPolicy L4-subset verdict table wired into its accept paths
//     (proxy.WithPolicyTable, driven by proxy.PolicyWatcher — VIP-mediated
//     ingress only; the always-allow set is seeded from the node/mesh /32s so
//     node-origin dialers are never policy-denied);
//   - the per-node cluster DNS resolver (resolver.go): an in-process authoritative
//     server bound to the DNS VIP (53/UDP+TCP) answering Service A records and
//     forwarding off-cluster names upstream. It also renders the reference Corefile
//     from dns.CorefileOptions and exposes the dns.PodDNSConfig the getaddrinfo
//     shim consumes inside each pod.
//
// # Infra VIPs are answered node-locally, never steered over the mesh (M3.3)
//
// The infra VIPs — kube-dns (10.43.0.10) and kubernetes (10.43.0.1) — are not in
// any pod's podCIDR, so a podCIDR router would steer them over the wireguard mesh
// where no peer's AllowedIPs cover them (a blackhole). Both stay node-local:
//   - The DNS VIP is owned by THIS package's per-node resolver. The Service proxy
//     is exempted from it (proxy.WithInfraVIPExemptions) so it never races the
//     resolver for 10.43.0.10:53 (EADDRINUSE); the resolver ensures the VIP's lo0
//     alias (via the netd helper when unprivileged) and binds the socket itself.
//   - The API VIP is owned by the Service proxy as a normal ClusterIP Service and
//     L4-forwarded to the apiserver endpoint over the mesh. It is NOT exempted and
//     the default/kubernetes Endpoints are NOT rewritten (the apiserver's
//     endpoint-reconciler owns that singleton); the node-local property comes from
//     each node's proxy owning the VIP locally. The apiserver serving cert SANs
//     10.43.0.1, so in-cluster TLS still validates.
//
// # Why an in-process resolver, not CoreDNS-the-binary (and the native-binary follow-up)
//
// CoreDNS is pure Go, so a native darwin/arm64 binary builds cleanly (GOOS=darwin
// GOARCH=arm64, the way pkg/executor builds kine from source + ad-hoc-signs it).
// Running the REAL CoreDNS natively — full SRV/PTR/headless records, no Linux, no
// OCI artifact — is the faithful k3s realization and the intended FOLLOW-UP. It is
// BLOCKED today by the <1024 VIP bind in the unprivileged _k3sm posture: binding
// 10.43.0.10:53 needs root, so the netd helper binds it (root) and passes the socket
// back over SCM_RIGHTS — but CoreDNS-the-binary creates its OWN sockets (mainline
// CoreDNS has no systemd socket-activation / LISTEN_FDS), so it cannot adopt the
// helper-passed fd, and darwin-net exposes no embeddable DNS server to bind it
// in-process. (In root/direct mode CoreDNS could bind the VIP itself, but the
// production posture is unprivileged, and a root-only resolver would be a SECOND DNS
// code path.) So k3sm runs a minimal authoritative resolver (clusterResolver), which
// DOES adopt the helper-passed fd (net.FileListener / net.FilePacketConn) — see
// resolver.go. ExternalName Services are resolved by chasing the target through the
// upstream forwarder, FLATTENED CNAME→A (the resolver is A-only — no upstream CNAME
// RR is returned, and an ExternalName target inside the cluster domain is unsupported
// → NXDOMAIN, never forwarded). Its other divergence (no SRV/PTR/pod/headless, IPv4
// only) is MOOT on the native hostprocess path — every pod reports podIP == nodeIP,
// so there are no per-pod / headless addresses to serve — and becomes material only
// on the per-pod-IP vm path, which is exactly where the native-CoreDNS-binary
// follow-up (a supervised native process owning the VIP) pays off.
package netserve
