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

package status

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/install"
)

// An unprivileged report reads the cluster through the invoking account's own
// kubeconfig, and a kubeconfig can point anywhere. Before a row vouches for
// THIS cluster from what that endpoint answered, the endpoint has to be shown
// to be this cluster's: an Anchor is that test, over the apiserver URL.

// Anchor reports whether an apiserver URL is the endpoint the report is about.
type Anchor func(server string) bool

// ServerAnchor is the anchor of a control-plane Mac: the URL's host is a
// loopback address or one of this Mac's own interface addresses (local), and
// its port is the apiserver port. An endpoint that passes is a listener on this
// Mac at the apiserver's port, which is this server's control plane.
func ServerAnchor(port int, local []netip.Addr) Anchor {
	want := strconv.Itoa(port)
	return func(server string) bool {
		host, p := serverHostPort(server)
		if p != want {
			return false
		}
		if host == "localhost" {
			return true
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		if addr.IsLoopback() {
			return true
		}
		for _, l := range local {
			if l.Unmap() == addr {
				return true
			}
		}
		return false
	}
}

// JoinAnchor is the anchor of a worker: the URL's host is the host this Mac
// joined (joinServer, the agent's --server: a host, host:port or URL). The port
// is not compared, because the join port is the bootstrap listener, not the
// apiserver's. An empty join server anchors nothing.
func JoinAnchor(joinServer string) Anchor {
	join, _ := serverHostPort(joinServer)
	return func(server string) bool {
		host, _ := serverHostPort(server)
		return join != "" && host == join
	}
}

// UserKubeContext picks the context of the invoking account's kubeconfig that
// a report reads the cluster with: the context named name (the installed admin
// context, k3sm unless install was told otherwise), else the current context,
// each only when anchor accepts its cluster's server. A context
// is never trusted by its name alone: a k3sm context pointing at another host
// yields none, because reading some other cluster and calling it this one would
// be worse than reading nothing.
func UserKubeContext(cfg *clientcmdapi.Config, name string, anchor Anchor) (string, bool) {
	if cfg == nil || anchor == nil {
		return "", false
	}
	for _, candidate := range []string{name, cfg.CurrentContext} {
		if candidate == "" {
			continue
		}
		kctx, ok := cfg.Contexts[candidate]
		if !ok || kctx == nil {
			continue
		}
		if cluster, ok := cfg.Clusters[kctx.Cluster]; ok && cluster != nil && anchor(cluster.Server) {
			return candidate, true
		}
	}
	return "", false
}

// serverHostPort is the lowercased host and the port of a server named as a
// URL, host:port or bare host. A URL without a port gets its scheme's default.
func serverHostPort(s string) (host, port string) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", ""
		}
		port = u.Port()
		if port == "" && u.Scheme == "https" {
			port = "443"
		}
		return strings.ToLower(u.Hostname()), port
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.ToLower(h), p
	}
	return strings.ToLower(strings.Trim(s, "[]")), ""
}

// EndpointsRecord is what a node publishes, 0644 in the status directory, about
// the apiserver it belongs to: the port, and every host that names this
// cluster's apiserver. A server lists its serving certificate's SANs, loopback
// and its interface addresses; an agent lists the host it joined and the SANs
// of the serving certificate it read over a handshake verified against its
// node credential's pinned cluster CA. It holds names and addresses, never a
// credential.
type EndpointsRecord struct {
	UpdatedAt time.Time `json:"updatedAt"`
	Port      int       `json:"port"`
	Hosts     []string  `json:"hosts"`
}

// EndpointsPath is the record's path in a status directory.
func EndpointsPath(statusDir string) string {
	return filepath.Join(statusDir, install.EndpointsRecordName)
}

// ReadEndpointsRecord reads the record at path. A missing, unreadable or
// unparsable record, or one with no port or no hosts, is nil: the node is older
// than the record or the record cannot be trusted to name anything, and the
// caller falls back to the anchor it had without one.
func ReadEndpointsRecord(read func(string) ([]byte, error), path string) *EndpointsRecord {
	raw, err := read(path)
	if err != nil {
		return nil
	}
	var rec EndpointsRecord
	if json.Unmarshal(raw, &rec) != nil || rec.Port <= 0 || len(rec.Hosts) == 0 {
		return nil
	}
	return &rec
}

// RecordAnchor accepts a server URL whose host is one of the record's hosts and
// whose port is the record's port.
func RecordAnchor(rec EndpointsRecord) Anchor {
	want := strconv.Itoa(rec.Port)
	hosts := make([]string, 0, len(rec.Hosts))
	for _, h := range rec.Hosts {
		hosts = append(hosts, canonicalHost(h))
	}
	return func(server string) bool {
		host, port := serverHostPort(server)
		if port != want || host == "" {
			return false
		}
		host = canonicalHost(host)
		for _, h := range hosts {
			if h == host {
				return true
			}
		}
		return false
	}
}

// NodeAnchor is the anchor an unprivileged report uses: the published record
// when this node has one, else fallback (the interface-address anchor on a
// server, the join-host anchor on an agent), which is what a node older than
// the record leaves.
func NodeAnchor(rec *EndpointsRecord, fallback Anchor) Anchor {
	if rec == nil {
		return fallback
	}
	return RecordAnchor(*rec)
}

// canonicalHost lowercases a host and writes an IP in its canonical form, so
// "::1" and "0:0::1" or a mapped IPv4 compare equal.
func canonicalHost(h string) string {
	h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]"))
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}
