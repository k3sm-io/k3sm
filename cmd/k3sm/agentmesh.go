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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// localAddrDialer is a net.Dialer that remembers the LOCAL address of the most
// recent connection it opened.
//
// It exists so the join can answer a question only the kernel can: which of this
// Mac's addresses reaches the control plane. The route lookup for the join's own
// destination picks it, so it is by construction an address on the interface that
// reaches the server — precisely the address a peer must dial back on.
//
// Locking discipline: mu guards local only. http.Transport dials from arbitrary
// goroutines and the reader is the join path, so the two must not race.
type localAddrDialer struct {
	dialer net.Dialer

	mu    sync.Mutex
	local net.IP
}

// DialContext dials through the embedded net.Dialer and records the connection's
// local address.
func (d *localAddrDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if a, ok := conn.LocalAddr().(*net.TCPAddr); ok && a.IP != nil {
		d.mu.Lock()
		d.local = a.IP
		d.mu.Unlock()
	}
	return conn, nil
}

// localIP returns the recorded local address, or nil if nothing has been dialed.
func (d *localAddrDialer) localIP() net.IP {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.local
}

// probe opens and immediately closes a connection to address so localIP reports
// the source address a connection to THAT destination uses.
//
// It is deliberately best-effort and returns nothing: the endpoint derivation has
// a host-scan fallback, and the join that follows on the same dialer and the same
// destination produces the better error if the server is genuinely unreachable.
// A separate connection is needed because the endpoint travels IN the join request
// body, which is marshalled before any socket exists — the route lookup, however,
// is per-destination and deterministic, so the two connections agree.
func (d *localAddrDialer) probe(ctx context.Context, address string) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return
	}
	_ = conn.Close()
}

// pinnedJoinClient returns the join's CA-hash-pinned HTTP client with a
// local-address-capturing dialer installed, plus that dialer.
//
// It layers ONLY the dialer onto bootstrap.PinnedClient; the TLS config — the
// disabled default verification plus the VerifyConnection that re-imposes real
// pinned-CA verification — is left exactly as PinnedClient built it. Rebuilding
// the transport here instead would silently drop the pin, which is the join's only
// trust anchor before the node possesses any CA.
func pinnedJoinClient(caHash string) (*http.Client, *localAddrDialer, error) {
	client := bootstrap.PinnedClient(caHash)
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, nil, fmt.Errorf("join client transport is %T, want *http.Transport", client.Transport)
	}
	d := &localAddrDialer{dialer: net.Dialer{Timeout: 10 * time.Second}}
	tr.DialContext = d.DialContext
	return client, d, nil
}

// underlayMeshEndpoint returns the host:port this node advertises as its wireguard
// endpoint: the address peers dial to open a handshake with it.
//
// The address MUST be on the underlay. A peer that has not yet completed the
// handshake has no route into the mesh, so an endpoint inside the mesh is
// unreachable at exactly the moment it is needed — the server ends up initiating
// handshakes into its own tunnel. This is the mirror of the server-side rule
// serverMeshEndpoint states for the same reason.
//
// local is the source address the join connection to the control plane used; it is
// preferred because the kernel's route lookup already proved that interface reaches
// the server, which makes it the interface a peer should dial back on. When the
// capture failed or produced an unusable address, the fall-back is the first
// globally-unicast address of an up, non-loopback, non-tunnel interface.
//
// It returns an ERROR rather than falling back to meshIP. A published endpoint that
// can never complete a handshake is indistinguishable, from a peer's side, from a
// working one, so failing the join is the honest outcome.
func underlayMeshEndpoint(local net.IP, meshIP string, port int) (string, error) {
	if host := usableUnderlayIP(local, meshIP); host != "" {
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	scanned := underlayInterfaceIPs()
	candidates := make([]net.IP, 0, len(scanned))
	for _, ip := range scanned {
		if usableUnderlayIP(ip, meshIP) != "" {
			candidates = append(candidates, ip)
		}
	}
	// firstProxyableIP prefers IPv4 (what a dual-stack Mac's peers dial) and keeps
	// the choice stable across restarts by following net.Interfaces' index order.
	if host := firstProxyableIP(candidates); host != "" {
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	return "", fmt.Errorf("no underlay address to advertise as this node's wireguard endpoint: "+
		"the join source address was %v and no up, non-loopback, non-tunnel interface has a globally-unicast address "+
		"outside the mesh CIDR %s (the node's mesh IP %s is not a valid endpoint — no un-joined peer can dial it)",
		local, podnet.ClusterPodCIDR, meshIP)
}

// usableUnderlayIP returns ip's textual form if it is a legitimate wireguard
// endpoint host for a node whose mesh address is meshIP, and "" otherwise.
//
// Three rejections, in order of how they were reached: a non-globally-unicast
// address (loopback, unspecified, link-local, multicast) is not dialable by a
// peer; this node's own mesh IP is the observed defect; and ANY address inside the
// cluster mesh CIDR is rejected for the same reason one step more generally — a
// second utun, or a stale alias, is inside the tunnel a joining peer cannot yet
// reach.
func usableUnderlayIP(ip net.IP, meshIP string) string {
	if ip == nil || !ip.IsGlobalUnicast() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if meshIP != "" && ip.Equal(net.ParseIP(meshIP)) {
		return ""
	}
	if a, ok := netip.AddrFromSlice(ip); ok && podnet.ClusterPodCIDR.Contains(a.Unmap()) {
		return ""
	}
	return ip.String()
}

// underlayInterfaceIPs reports this host's UNDERLAY addresses: those of its up,
// non-loopback, non-tunnel interfaces.
//
// It is deliberately distinct from node.go's hostInterfaceIPs, which does not
// exclude tunnels. For advertising a node address a utun address is merely
// unhelpful; for advertising a wireguard endpoint it is the exact defect this file
// prevents, because the mesh's own utun carries the address no un-joined peer can
// route to. Package var so the selection is unit-testable on a host whose
// interfaces a test cannot change.
var underlayInterfaceIPs = func() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isTunnelInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			// One unreadable interface must not hide the rest.
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ips = append(ips, n.IP)
			}
		}
	}
	return ips
}

// isTunnelInterface reports whether name is a Darwin tunnel device. The mesh's own
// wireguard device is a utun; the rest are listed because they share the property
// that matters — their addresses live inside a tunnel a peer must already be
// through to reach.
func isTunnelInterface(name string) bool {
	for _, prefix := range []string{"utun", "ipsec", "gif", "stf"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
