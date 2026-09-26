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

package netdsvc

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"k3sm.io/darwin-net/pkg/dns"
)

// NodeResolverKey is the SystemConfiguration dynamic-store key netd publishes
// the node resolver entry under. It is FIXED: netd writes exactly this one key
// and removes exactly this one key, so a crash leaves nothing a restart does not
// overwrite and an uninstall does not find. The key names a supplemental DNS
// "service" that no network interface owns; mDNSResponder merges it into the
// host's resolver configuration (`scutil --dns` lists it).
const NodeResolverKey = "State:/Network/Service/io.k3sm.dns/DNS"

// nodeResolverMatchOrder is the entry's SupplementalMatchOrder. It only orders
// supplemental resolvers that share a match domain; nothing else on a Mac
// registers svc or the cluster domain, so the value is a stable tie-breaker,
// not a precedence claim.
const nodeResolverMatchOrder = 1000

// svcMatchDomain is the cluster-reserved "svc" label, registered so a shim-less
// process's partial name.ns.svc reaches the node resolver, which completes it
// server-side (netserve, dns.CompletePartialName).
const svcMatchDomain = "svc"

// ResolverEntry is the supplemental DNS configuration netd publishes: the
// SystemConfiguration DNS dictionary keys, one field each.
type ResolverEntry struct {
	// ServerAddresses is the node DNS VIP, the only server of the entry.
	ServerAddresses []string
	// SupplementalMatchDomains are the suffixes mDNSResponder routes to
	// ServerAddresses: svc and the cluster domain. Static by design: no
	// namespace name is registered, so no real suffix (a TLD, local, corp,
	// internal, ...) is ever captured for the host.
	SupplementalMatchDomains []string
	// SupplementalMatchDomainsNoSearch keeps the match domains out of the
	// host's search list: resolver #1 and /etc/resolv.conf stay untouched, so
	// host processes gain no search domains and single-label names are never
	// completed for a shim-less process.
	SupplementalMatchDomainsNoSearch bool
	// SupplementalMatchOrder orders supplemental resolvers sharing a domain.
	SupplementalMatchOrder int
}

// NodeResolverEntry builds the node resolver entry for the DNS VIP and cluster
// domain. It refuses an invalid VIP, an invalid cluster domain, and a
// single-label cluster domain that is a real or special-use suffix (a cluster
// domain "local" would route every mDNS name on the host to the node DNS).
func NodeResolverEntry(vip netip.Addr, clusterDomain string) (ResolverEntry, error) {
	if !vip.IsValid() || !vip.Is4() {
		return ResolverEntry{}, fmt.Errorf("node resolver: DNS VIP %q is not an IPv4 address", vip)
	}
	domain := strings.ToLower(strings.TrimSuffix(clusterDomain, "."))
	if !validDomain(domain) {
		return ResolverEntry{}, fmt.Errorf("node resolver: cluster domain %q is not a DNS name", clusterDomain)
	}
	if !strings.Contains(domain, ".") && dns.IsReservedSuffix(domain) {
		return ResolverEntry{}, fmt.Errorf("node resolver: cluster domain %q is a real or special-use suffix; routing it to the node DNS would capture it for every process on this Mac", clusterDomain)
	}
	match := []string{svcMatchDomain}
	if domain != svcMatchDomain {
		match = append(match, domain)
	}
	return ResolverEntry{
		ServerAddresses:                  []string{vip.String()},
		SupplementalMatchDomains:         match,
		SupplementalMatchDomainsNoSearch: true,
		SupplementalMatchOrder:           nodeResolverMatchOrder,
	}, nil
}

// validDomain reports whether d is a lower-case dotted sequence of RFC 1123
// labels.
func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// resolverPublisher writes and removes a dynamic-store DNS entry. The darwin
// implementation is SystemStore (SystemConfiguration via cgo); tests inject a
// fake that records calls.
type resolverPublisher interface {
	Publish(key string, entry ResolverEntry) error
	Remove(key string) error
}

// ErrNodeResolverUnsupported is returned by the system store on a build that
// cannot reach SystemConfiguration (a CGO_ENABLED=0 or non-darwin build).
var ErrNodeResolverUnsupported = errors.New("node resolver entry unsupported: SystemConfiguration needs a darwin cgo build")

// NodeResolver owns netd's node resolver entry for the daemon's life: Start
// writes the FULL entry (on every start, a post-crash respawn included, so a
// stale or partial entry is always overwritten), Stop removes it.
//
// It is the resolv.conf translation of B243: on Linux the kubelet writes each
// container's resolv.conf and every descendant inherits it; on macOS the
// equivalent reach is the host resolver configuration mDNSResponder enforces
// for every process, platform binaries included, so a pod whose shell lost the
// DYLD shim still resolves FQDNs and name.ns.svc through it.
type NodeResolver struct {
	pub   resolverPublisher
	entry ResolverEntry
	log   *slog.Logger
}

// NewNodeResolver builds the NodeResolver for the DNS VIP and cluster domain
// over pub. A nil log discards.
func NewNodeResolver(pub resolverPublisher, vip netip.Addr, clusterDomain string, log *slog.Logger) (*NodeResolver, error) {
	if pub == nil {
		return nil, errors.New("node resolver: nil publisher")
	}
	entry, err := NodeResolverEntry(vip, clusterDomain)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &NodeResolver{pub: pub, entry: entry, log: log}, nil
}

// Entry returns a copy of the entry Start publishes.
func (n *NodeResolver) Entry() ResolverEntry {
	e := n.entry
	e.ServerAddresses = slices.Clone(e.ServerAddresses)
	e.SupplementalMatchDomains = slices.Clone(e.SupplementalMatchDomains)
	return e
}

// Start publishes the full entry at NodeResolverKey.
func (n *NodeResolver) Start() error {
	if err := n.pub.Publish(NodeResolverKey, n.Entry()); err != nil {
		return fmt.Errorf("publish node resolver entry %s: %w", NodeResolverKey, err)
	}
	n.log.Info("published the node resolver entry", "key", NodeResolverKey,
		"servers", n.entry.ServerAddresses, "match-domains", n.entry.SupplementalMatchDomains)
	return nil
}

// Stop removes the entry. Removing an absent entry is not an error.
func (n *NodeResolver) Stop() error {
	if err := n.pub.Remove(NodeResolverKey); err != nil {
		return fmt.Errorf("remove node resolver entry %s: %w", NodeResolverKey, err)
	}
	n.log.Info("removed the node resolver entry", "key", NodeResolverKey)
	return nil
}
