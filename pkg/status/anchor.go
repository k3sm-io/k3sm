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
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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
