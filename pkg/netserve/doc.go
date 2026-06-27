// Package netserve hosts k3sm's pod-networking services inside the server
// process by consuming darwin-net's seams — it does NOT reimplement Service/VIP
// translation or DNS ndots/search.
//
// It runs, per node:
//   - the userspace Service proxy: a proxy.Proxy driven by proxy.NewWatcher off
//     the cluster's Services + EndpointSlices, owning one lo0-alias socket per
//     ClusterIP:port (the macOS-native kube-proxy analog), sourced from the node's
//     mesh-egress /32 for cross-node backend dials (proxy.WithMeshEgressSource);
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
// # Why an in-process resolver, not CoreDNS-the-binary
//
// darwin-net supplies only Corefile rendering (for an external CoreDNS deployment)
// and a client-side dns.Resolver — no embeddable DNS server. CoreDNS-the-binary
// cannot inherit the netd-helper-passed socket fd under launchd, and the
// unprivileged posture binds the <1024 DNS VIP only via that fd; embedding
// CoreDNS-the-library over a passed fd is intractable. So k3sm runs a minimal
// authoritative resolver (clusterResolver) instead — see resolver.go for the
// deliberate, documented divergence (no SRV/PTR/pod/headless records, IPv4 only).
package netserve
