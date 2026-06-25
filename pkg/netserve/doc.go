// Package netserve hosts k3sm's pod-networking services inside the server
// process by consuming darwin-net's seams — it does NOT reimplement Service/VIP
// translation or DNS ndots/search.
//
// It runs:
//   - the userspace Service proxy: a proxy.Proxy driven by proxy.NewWatcher off
//     the cluster's Services + EndpointSlices, owning one lo0-alias socket per
//     ClusterIP:port (the macOS-native kube-proxy analog);
//   - the CoreDNS cluster resolver wiring: it renders the Corefile from
//     dns.CorefileOptions and writes it to the workdir so CoreDNS can be launched
//     on the DNS VIP, and exposes the dns.PodDNSConfig the getaddrinfo shim
//     consumes inside each pod.
//
// The actual CoreDNS process and the C getaddrinfo shim dylib are external
// artifacts (darwin-net renders their config / ships the shim source); netserve
// owns the config + the in-process proxy goroutine. The DNS VIP itself is a
// ClusterIP Service (kube-dns), so the same Service proxy that serves every
// other VIP also binds the DNS VIP's lo0 alias.
package netserve
