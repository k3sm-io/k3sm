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

package registrysvc

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// THE NODEPORT NAMES. A tool on a Mac outside the cluster that dials the opt-in
// NodePort (--registry-node-port) reaches the relay end to end: the node's
// Service proxy forwards TCP, so the TLS handshake is with the relay, and the
// tool verifies the address IT dialled against the relay's certificate. The
// in-cluster names and the mesh address are no help to it, so with the NodePort
// on the certificate also names the server as such a tool knows it: the server
// Node's InternalIP addresses, the host's name, and its .local name. Without the
// NodePort none of these is added, and the certificate is exactly the in-cluster
// one. The CA and the key usage are unchanged either way.

// NodePortSANs is the extra SAN set the relay's serving certificate carries when
// the registry is exposed on a NodePort. The zero value adds nothing.
type NodePortSANs struct {
	// DNS is the host's name and its .local name, lowercased, each once.
	DNS []string
	// IPs is the server Node's InternalIP addresses, each once.
	IPs []netip.Addr
}

// Equal reports whether s and o name the same SANs in the same order, so a
// caller re-minting on change compares the set it would mint with.
func (s NodePortSANs) Equal(o NodePortSANs) bool {
	return slices.Equal(s.DNS, o.DNS) && slices.Equal(s.IPs, o.IPs)
}

// NodePortServingSANs derives the NodePort SANs from the server's own Node
// object and the host's name (os.Hostname). node may be nil (the Node is not
// registered yet), and hostname may be empty; whatever is missing adds nothing.
//
// The IPs are the Node's InternalIP addresses that are usable unicast: loopback
// and unspecified addresses are left out, since no other Mac dials them. The
// names are the hostname and, when the hostname or a Hostname address on the
// Node is a .local name, both that .local name and its bare label. A name that
// is not a valid RFC 1123 subdomain once lowercased is left out rather than put
// in a certificate, and so is a name in the cluster's own namespace
// (clusterReservedName): a host called "kubernetes" must not put the
// apiserver's name into a certificate the registry serves.
func NodePortServingSANs(node *corev1.Node, hostname string) NodePortSANs {
	var out NodePortSANs
	addName := func(n string) {
		n = strings.ToLower(strings.TrimRight(strings.TrimSpace(n), "."))
		if n == "" || len(validation.IsDNS1123Subdomain(n)) != 0 || clusterReservedName(n) || slices.Contains(out.DNS, n) {
			return
		}
		out.DNS = append(out.DNS, n)
	}
	addLocal := func(n string) {
		n = strings.ToLower(strings.TrimRight(strings.TrimSpace(n), "."))
		if clusterReservedName(n) {
			return // nor its bare label: "box.cluster.local" must not become "box.cluster"
		}
		if bare, ok := strings.CutSuffix(n, ".local"); ok && bare != "" {
			addName(bare)
			addName(n)
		}
	}
	if hostname != "" {
		addName(hostname)
		addLocal(hostname)
	}
	if node == nil {
		return out
	}
	for _, a := range node.Status.Addresses {
		switch a.Type {
		case corev1.NodeInternalIP:
			ip, err := netip.ParseAddr(a.Address)
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsUnspecified() || ip.Zone() != "" || slices.Contains(out.IPs, ip) {
				continue
			}
			out.IPs = append(out.IPs, ip)
		case corev1.NodeHostName:
			addLocal(a.Address)
		}
	}
	return out
}

// clusterReservedName reports whether a lowercased host-derived name falls in
// the names the cluster itself answers to: the apiserver's "kubernetes" and its
// "kubernetes.*" spellings, and anything under a ".svc" or ".cluster.local"
// suffix, which in-cluster DNS resolves to a Service. The NodePort SANs come
// from the host's name and the Node object, neither of which the cluster
// vouches for, so a name a pod would resolve to a different Service is never
// put in the registry's certificate.
func clusterReservedName(n string) bool {
	return n == "kubernetes" || strings.HasPrefix(n, "kubernetes.") ||
		strings.HasSuffix(n, ".svc") || strings.HasSuffix(n, ".cluster.local")
}

// RelayServingSANs is the one composition of the relay's serving certificate
// SANs: the flat Service's names (FlatServiceDNSNames) and addresses
// (FlatServingIPs), then the NodePort SANs ext, each once. With a zero ext it is
// exactly the in-cluster set.
func RelayServingSANs(clusterDomain, clusterIP, meshIP, vmNetSubnet string, ext NodePortSANs) ([]string, []net.IP) {
	dnsNames := FlatServiceDNSNames(clusterDomain)
	for _, n := range ext.DNS {
		if !slices.Contains(dnsNames, n) {
			dnsNames = append(dnsNames, n)
		}
	}
	ips := FlatServingIPs(clusterIP, meshIP, vmNetSubnet)
	for _, a := range ext.IPs {
		ip := net.IP(a.AsSlice())
		if !slices.ContainsFunc(ips, ip.Equal) {
			ips = append(ips, ip)
		}
	}
	return dnsNames, ips
}
