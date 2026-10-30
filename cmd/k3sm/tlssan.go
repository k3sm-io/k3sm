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

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/install"
)

// maxTLSSANs is the most --tls-san names one server takes. Each rides the
// server arguments record as one argument, and that record holds at most
// dataroot.MaxServerArgs, so the cap leaves room for every other flag.
const maxTLSSANs = 32

// tlsSANUsage is the --tls-san help text, shared by `k3sm server` and
// `k3sm install` so the two cannot describe the flag differently.
const tlsSANUsage = "an extra hostname or IP address the apiserver's serving certificate is valid for (repeat the flag, one name each). " +
	"An IP must be an address this Mac holds (an interface, its mesh IP, or loopback); a hostname is checked for syntax only and is never resolved, " +
	"because a load balancer or public DNS name legitimately points elsewhere. On install, passing it replaces the recorded list and omitting it keeps the list"

// ErrTLSSANInvalid is wrapped by every --tls-san syntax or collision refusal.
// Compare with errors.Is.
var ErrTLSSANInvalid = errors.New("invalid --tls-san")

// ErrTLSSANNotLocal is the install-time refusal of an IP --tls-san that no
// interface of this Mac holds. Compare with errors.Is.
var ErrTLSSANNotLocal = errors.New("--tls-san IP address is not held by this Mac")

// tlsSANList is the repeatable --tls-san flag: each occurrence appends one
// name, verbatim. Validation is validateTLSSANs, not Set, so the install and
// the server judge one list the same way.
type tlsSANList []string

// String implements flag.Value.
func (l *tlsSANList) String() string { return strings.Join(*l, ",") }

// Set implements flag.Value.
func (l *tlsSANList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// tlsSANs is a validated --tls-san list: canonical hostnames and IPs, each
// once, in the order given.
type tlsSANs struct {
	dns []string
	ips []net.IP
}

// strings renders the list in its canonical spelling, hostnames first, for
// recording and logging.
func (s tlsSANs) strings() []string {
	out := slices.Clone(s.dns)
	for _, ip := range s.ips {
		out = append(out, ip.String())
	}
	return out
}

// apiServerFixedDNS are the in-cluster names every apiserver serving
// certificate carries. It is the one owner of that set: apiServerServingSANs
// issues it and validateTLSSANs refuses it as a --tls-san.
var apiServerFixedDNS = []string{
	"kubernetes", "kubernetes.default", "kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local", "localhost",
}

// apiServerLoopbackIP is the loopback address every apiserver serving
// certificate carries.
const apiServerLoopbackIP = "127.0.0.1"

// reservedTLSSANNames are the in-cluster names a --tls-san may not claim: the
// fixed set itself. Any name beginning kubernetes.default is refused beside
// them, as policy.
var reservedTLSSANNames = apiServerFixedDNS

// reservedTLSSANIPs are the fixed apiserver addresses a --tls-san may not
// claim, other than the mesh IP: loopback and the kubernetes Service IP of
// serviceCIDR. The Service and pod ranges are refused whole in
// validateTLSSANIP.
func reservedTLSSANIPs(serviceCIDR netip.Prefix) []net.IP {
	return []net.IP{net.ParseIP(apiServerLoopbackIP).To4(), kubernetesServiceIP(serviceCIDR)}
}

// kubernetesServiceIP is the kubernetes Service's cluster IP: the first host
// address of the Service range (10.43.0.1 for the default 10.43.0.0/16).
func kubernetesServiceIP(serviceCIDR netip.Prefix) net.IP {
	ip := net.IP(serviceCIDR.Masked().Addr().Next().AsSlice())
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

// parseServiceCIDR parses the configured --service-cidr for validateTLSSANs.
func parseServiceCIDR(serviceCIDR string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(serviceCIDR)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("the Service CIDR %q is not a CIDR: %w", serviceCIDR, err)
	}
	return p.Masked(), nil
}

// validateTLSSANs is the one validation of a --tls-san list, run by `k3sm
// install` and at every `k3sm server` start. Every entry is lowercased and is
// either an IP literal (an IPv4-in-IPv6 form canonicalised to IPv4) or an RFC
// 1123 hostname. It refuses empty names, wildcards, trailing dots, IPv6 zones,
// port suffixes, URLs, and anything colliding with the fixed in-cluster
// identities, the pod range, and serviceCIDR (the configured --service-cidr)
// with its kubernetes Service IP. meshIP, the server's own mesh address, is
// the one pod-range address allowed. Duplicates are dropped. It checks syntax
// only: whether an IP is held here is nonLocalTLSSANIPs' question.
func validateTLSSANs(raw []string, meshIP, serviceCIDR string) (tlsSANs, error) {
	var out tlsSANs
	if len(raw) > maxTLSSANs {
		return out, fmt.Errorf("%w: %d names, the limit is %d", ErrTLSSANInvalid, len(raw), maxTLSSANs)
	}
	svc, err := parseServiceCIDR(serviceCIDR)
	if err != nil {
		return out, err
	}
	mesh := net.ParseIP(meshIP)
	for _, r := range raw {
		v := strings.ToLower(r)
		if ip := net.ParseIP(v); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			if err := validateTLSSANIP(ip, mesh, svc); err != nil {
				return tlsSANs{}, fmt.Errorf("%w %q: %s", ErrTLSSANInvalid, r, err)
			}
			if !slices.ContainsFunc(out.ips, ip.Equal) {
				out.ips = append(out.ips, ip)
			}
			continue
		}
		if err := validateTLSSANName(v); err != nil {
			return tlsSANs{}, fmt.Errorf("%w %q: %s", ErrTLSSANInvalid, r, err)
		}
		if !slices.Contains(out.dns, v) {
			out.dns = append(out.dns, v)
		}
	}
	return out, nil
}

// validateTLSSANIP is validateTLSSANs for one parsed IP.
func validateTLSSANIP(ip, mesh net.IP, serviceCIDR netip.Prefix) error {
	addr, _ := netip.AddrFromSlice(ip)
	addr = addr.Unmap()
	switch {
	case ip.IsUnspecified():
		return errors.New("the unspecified address names no host")
	case ip.IsMulticast():
		return errors.New("a multicast address names no host")
	case slices.ContainsFunc(reservedTLSSANIPs(serviceCIDR), ip.Equal):
		return errors.New("already one of the apiserver's fixed addresses")
	case mesh != nil && ip.Equal(mesh):
		return nil
	case serviceCIDR.Contains(addr):
		return fmt.Errorf("inside the cluster Service range %s, which the cluster assigns", serviceCIDR)
	case podnet.ClusterPodCIDR.Contains(addr):
		return fmt.Errorf("inside the cluster pod range %s, which the cluster assigns (only this server's own --mesh-ip may be named)", podnet.ClusterPodCIDR)
	}
	return nil
}

// validateTLSSANName is validateTLSSANs for one lowercased non-IP entry.
func validateTLSSANName(v string) error {
	switch {
	case v == "":
		return errors.New("an empty name")
	case strings.Contains(v, "://") || strings.Contains(v, "/"):
		return errors.New("a URL or path; give the bare hostname")
	case strings.Contains(v, "*"):
		return errors.New("a wildcard; name each host")
	case strings.Contains(v, "%"):
		return errors.New("an IPv6 zone; a certificate names an address, not an interface")
	case strings.HasSuffix(v, "."):
		return errors.New("a trailing dot; give the name without it")
	case strings.Contains(v, ":"):
		return errors.New("a port suffix or a malformed IPv6 address; give the bare hostname or IP")
	case slices.Contains(reservedTLSSANNames, v) || strings.HasPrefix(v, "kubernetes.default"):
		return errors.New("already one of the apiserver's fixed in-cluster names")
	case len(v) > 253:
		return errors.New("longer than 253 characters")
	}
	labels := strings.Split(v, ".")
	for _, label := range labels {
		if err := validateTLSSANLabel(label); err != nil {
			return err
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("its last label is all digits, which some resolvers read as a legacy IPv4 form, so clients would disagree on what it names")
	}
	return nil
}

// validateTLSSANLabel is one RFC 1123 hostname label: 1 to 63 of a-z, 0-9 and
// '-', not starting or ending with '-'.
func validateTLSSANLabel(label string) error {
	if label == "" || len(label) > 63 {
		return errors.New("not an RFC 1123 hostname (each dot-separated label must be 1 to 63 characters)")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return errors.New("not an RFC 1123 hostname (a label may not start or end with '-')")
	}
	for _, c := range label {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("not an RFC 1123 hostname (%q is not allowed; use a-z, 0-9, '-' and '.')", c)
		}
	}
	return nil
}

// nonLocalTLSSANIPs returns the IPs of sans that this Mac does not hold: not
// loopback, not meshIP, and on no interface (localInterfaceAddrs).
func nonLocalTLSSANIPs(sans tlsSANs, meshIP string) ([]net.IP, error) {
	var foreign []net.IP
	mesh := net.ParseIP(meshIP)
	for _, ip := range sans.ips {
		if ip.IsLoopback() || (mesh != nil && ip.Equal(mesh)) {
			continue
		}
		addr, _ := netip.AddrFromSlice(ip)
		present, err := localAddressPresent(addr.Unmap())
		if err != nil {
			return nil, fmt.Errorf("list this Mac's addresses to check --tls-san %s: %w", ip, err)
		}
		if !present {
			foreign = append(foreign, ip)
		}
	}
	return foreign, nil
}

// checkInstallTLSSANs is `k3sm install --tls-san`'s refusal, made before
// anything is written. meshIP is the server's effective --mesh-ip ("" on a
// single-node server, which issues the same cluster-CA leaf) and serviceCIDR the
// install's --service-cidr. It refuses any invalid name and an IP this Mac does
// not hold, and returns the list in canonical spelling for the arguments record.
func checkInstallTLSSANs(raw []string, meshIP, serviceCIDR string) ([]string, error) {
	sans, err := validateTLSSANs(raw, meshIP, serviceCIDR)
	if err != nil {
		return nil, err
	}
	foreign, err := nonLocalTLSSANIPs(sans, meshIP)
	if err != nil {
		return nil, err
	}
	if len(foreign) > 0 {
		return nil, fmt.Errorf("%w: %s is on no interface of this Mac and is not its mesh IP; an IP name must be an address clients reach this server at (a load balancer in front of it is named by hostname)", ErrTLSSANNotLocal, foreign[0])
	}
	return sans.strings(), nil
}

// checkServerTLSSANs is the server-start judgement of --tls-san, against the
// server's Service range serviceCIDR, on every topology (meshIP is "" on a
// single-node server; nodeIP is the server's --node-ip). An invalid name is refused. An IP this Mac no longer holds
// (DHCP moved it) is a Warn and still issued: a recorded operator choice must
// never crash-loop the control plane. The final set, with nodeName, is logged
// once at Info.
func checkServerTLSSANs(raw []string, meshIP, nodeIP, nodeName, serviceCIDR string, logger *slog.Logger) error {
	if len(raw) == 0 {
		return nil
	}
	sans, err := validateTLSSANs(raw, meshIP, serviceCIDR)
	if err != nil {
		return err
	}
	foreign, err := nonLocalTLSSANIPs(sans, meshIP)
	if err != nil {
		logger.Warn("could not check that the --tls-san addresses are held by this Mac; issuing them anyway", "err", err)
	}
	for _, ip := range foreign {
		logger.Warn("--tls-san names an address this Mac does not hold now; issuing it anyway, so clients dialling it reach nothing until it returns", "tls-san", ip.String())
	}
	dns, ips, err := apiServerServingSANs(meshIP, nodeIP, nodeName, raw)
	if err != nil {
		return err
	}
	ipText := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipText = append(ipText, ip.String())
	}
	logger.Info("apiserver serving certificate names", "dns", strings.Join(dns, ","), "ips", strings.Join(ipText, ","), "extra", strings.Join(sans.strings(), ","))
	return nil
}

// nodeNameSAN is the DNS name the serving certificate carries for the server's
// canonical node name: the name lowercased, when it passes validateTLSSANName.
// A name that fails syntax or collides with a reserved in-cluster name is an
// error, which the issuer logs at Warn and skips: a node name never crash-loops
// the control plane.
func nodeNameSAN(nodeName string) (string, error) {
	v := strings.ToLower(nodeName)
	if err := validateTLSSANName(v); err != nil {
		return "", fmt.Errorf("node name %q is not issued as a serving-certificate name: %s", nodeName, err)
	}
	return v, nil
}

// nodeIPSAN is the IP the serving certificate carries for the server's node
// address: nodeIP canonicalised to IPv4 where it is one, or nil when it does
// not parse or names no single remote-reachable host (loopback, which the fixed
// set already carries, unspecified, multicast or link-local).
func nodeIPSAN(nodeIP string) net.IP {
	ip := net.ParseIP(nodeIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

// apiServerServingSANs is the one assembly of the apiserver serving
// certificate's names, on every topology. DNS: the fixed in-cluster set
// (apiServerFixedDNS) and the canonical node name (nodeNameSAN; a name it
// refuses is left out). IPs: the mesh IP only when meshIP parses (a single-node
// server has none, and a nil IP is never appended), the node IP when it is a
// host address (nodeIPSAN), loopback, and the kubernetes Service IP of the
// server's Service range, install.DefaultServiceCIDR, which `k3sm server` always
// runs with. Unioned with the --tls-san extras, validated by validateTLSSANs
// unchanged.
//
// The node IP is named because a server without --mesh-ip binds the apiserver
// to it, and the in-process kubeconfigs dial that bind address.
func apiServerServingSANs(meshIP, nodeIP, nodeName string, extra []string) (dns []string, ips []net.IP, err error) {
	svc, err := parseServiceCIDR(install.DefaultServiceCIDR)
	if err != nil {
		return nil, nil, err
	}
	dns = slices.Clone(apiServerFixedDNS)
	if name, nerr := nodeNameSAN(nodeName); nerr == nil && !slices.Contains(dns, name) {
		dns = append(dns, name)
	}
	if mesh := net.ParseIP(meshIP); mesh != nil {
		if mesh4 := mesh.To4(); mesh4 != nil {
			mesh = mesh4
		}
		ips = append(ips, mesh)
	}
	if node := nodeIPSAN(nodeIP); node != nil && !slices.ContainsFunc(ips, node.Equal) {
		ips = append(ips, node)
	}
	for _, ip := range reservedTLSSANIPs(svc) {
		if ip != nil && !slices.ContainsFunc(ips, ip.Equal) {
			ips = append(ips, ip)
		}
	}
	if len(extra) == 0 {
		return dns, ips, nil
	}
	sans, err := validateTLSSANs(extra, meshIP, install.DefaultServiceCIDR)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range sans.dns {
		if !slices.Contains(dns, d) {
			dns = append(dns, d)
		}
	}
	for _, ip := range sans.ips {
		if !slices.ContainsFunc(ips, ip.Equal) {
			ips = append(ips, ip)
		}
	}
	return dns, ips, nil
}
