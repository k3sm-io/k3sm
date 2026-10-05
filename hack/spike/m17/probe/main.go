//go:build darwin

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

// Command probe is the M17.0 spike's measuring instrument: the questions a shell
// cannot observe on its own, answered through the same libraries the product
// uses, so a spike finding is a finding about that code and not about a
// re-implementation of it.
//
//	probe enum                                   linkenum.Exec{}.Ports as JSON
//	probe linkip -node-cidr C -port P            the derived link and mesh-egress addresses
//	probe watch -iface X -for D                  link events from the PF_ROUTE reader, the
//	                                             poll and a raw routing socket, one JSON line each
//	probe zone-serve -iface X -port P -for D     a TLS listener on fe80::%X; prints the zones
//	                                             net/http reports for the first request
//	probe zone-dial -addr A -port P -pin H       a TLS dial to A (a zoned fe80 literal)
//	probe mcast-listen -iface X -port P -for D   the first ff02::1 datagram heard on X
//	probe mcast-send -iface X -port P -count N   N datagrams to ff02::1%X
//
// Every subcommand writes JSON to stdout and exits 0 when it observed what it was
// asked to observe, 3 when it timed out without observing it, and 1 on an error.
// The driver reads the JSON; the exit status is only a summary of it.
//
// It is built by the spike driver for darwin/arm64 and shipped to each Mac; it is
// not part of any k3sm binary.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/linkwatch"
	"k3sm.io/darwin-net/pkg/podnet"
)

// Exit statuses shared by every subcommand.
const (
	exitObserved = 0
	exitError    = 1
	exitTimeout  = 3
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe enum|linkip|watch|zone-serve|zone-dial|mcast-listen|mcast-send [flags]")
		os.Exit(exitError)
	}
	cmds := map[string]func([]string) (int, error){
		"enum":         enum,
		"linkip":       linkIP,
		"watch":        watch,
		"zone-serve":   zoneServe,
		"zone-dial":    zoneDial,
		"mcast-listen": mcastListen,
		"mcast-send":   mcastSend,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "probe: unknown subcommand %q\n", os.Args[1])
		os.Exit(exitError)
	}
	code, err := run(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe %s: %v\n", os.Args[1], err)
		if code == exitObserved {
			code = exitError
		}
	}
	os.Exit(code)
}

// emit writes one JSON object as one line.
func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: encode %T: %v\n", v, err)
		return
	}
	fmt.Println(string(b))
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// enum runs the production enumeration once and prints its result, timing
// included, so S1 records both what the library sees and what it costs.
func enum(args []string) (int, error) {
	fs := flag.NewFlagSet("enum", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 30*time.Second, "enumeration timeout")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	start := time.Now()
	ports, err := linkenum.Exec{}.Ports(ctx)
	out := map[string]any{"ports": ports, "elapsedMs": time.Since(start).Milliseconds()}
	if err != nil {
		out["error"] = err.Error()
		out["noThunderboltService"] = errors.Is(err, linkenum.ErrNoThunderboltService)
	}
	emit(out)
	if err != nil {
		return exitError, err
	}
	return exitObserved, nil
}

// linkIP prints the addresses the product derives for a node's port: the link
// address (netv1alpha1.LinkIP over podnet.NodeIndex) and the mesh-egress source
// the direct /25s carry as RTAX_IFA, plus the two /25 halves of the pod /24.
func linkIP(args []string) (int, error) {
	fs := flag.NewFlagSet("linkip", flag.ContinueOnError)
	nodeCIDR := fs.String("node-cidr", "", "the node's pod /24")
	cluster := fs.String("cluster-cidr", podnet.ClusterPodCIDR.String(), "the cluster pod CIDR")
	port := fs.Int("port", -1, "the port ordinal (receptacle - 1)")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	node, err := netip.ParsePrefix(*nodeCIDR)
	if err != nil {
		return exitError, fmt.Errorf("node cidr: %w", err)
	}
	clusterCIDR, err := netip.ParsePrefix(*cluster)
	if err != nil {
		return exitError, fmt.Errorf("cluster cidr: %w", err)
	}
	idx, err := podnet.NodeIndex(clusterCIDR, node)
	if err != nil {
		return exitError, err
	}
	link, err := netv1alpha1.LinkIP(idx, *port)
	if err != nil {
		return exitError, err
	}
	egress, err := podnet.MeshEgressIP(node)
	if err != nil {
		return exitError, err
	}
	node = node.Masked()
	hi := node.Addr().As4()
	hi[3] = 128
	emit(map[string]any{
		"index":      idx,
		"linkIP":     link.String(),
		"meshEgress": egress.String(),
		"halves":     []string{netip.PrefixFrom(node.Addr(), 25).String(), netip.PrefixFrom(netip.AddrFrom4(hi), 25).String()},
	})
	return exitObserved, nil
}

// watchEvent is one line of the watch subcommand.
type watchEvent struct {
	Time   string `json:"t"`
	Source string `json:"source"` // route (linkwatch.RouteReader), poll (linkwatch.Poller), raw
	Iface  string `json:"iface"`
	Up     bool   `json:"up"`
	Gone   bool   `json:"gone"`
	// Exists is whether net.InterfaceByName still finds the interface when the
	// event is printed: false on an unplug means the kernel destroyed it.
	Exists bool `json:"exists"`
	// RTM is the raw message type (raw source only).
	RTM string `json:"rtm,omitempty"`
}

// watch runs the two production sources separately (never merged or debounced,
// so each one's delivery is visible on its own) plus a raw routing-socket reader
// that names the message type. It exits 0 after the full duration when the route
// reader delivered at least one event for the interface, else 3.
func watch(args []string) (int, error) {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	iface := fs.String("iface", "", "the interface to report (empty = all)")
	dur := fs.Duration("for", 60*time.Second, "how long to watch")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()
	emit(map[string]any{"t": now(), "start": true, "iface": *iface, "uid": os.Getuid()})

	out := make(chan watchEvent, 256)
	exists := func(name string) bool { _, err := net.InterfaceByName(name); return err == nil }
	forward := func(source string, ch <-chan linkwatch.Event) {
		for ev := range ch {
			out <- watchEvent{Time: now(), Source: source, Iface: ev.Iface, Up: ev.Up, Gone: ev.Gone, Exists: exists(ev.Iface)}
		}
	}
	rr, err := linkwatch.OpenRouteReader()
	if err != nil {
		emit(map[string]any{"t": now(), "source": "route", "error": err.Error()})
	} else {
		go forward("route", rr.Events(ctx))
	}
	go forward("poll", linkwatch.Poller{}.Events(ctx))
	if err := rawRoute(ctx, out, exists); err != nil {
		emit(map[string]any{"t": now(), "source": "raw", "error": err.Error()})
	}

	routeSeen := false
	for {
		select {
		case <-ctx.Done():
			emit(map[string]any{"t": now(), "end": true, "routeSeen": routeSeen})
			if routeSeen {
				return exitObserved, nil
			}
			return exitTimeout, nil
		case ev := <-out:
			if *iface != "" && ev.Iface != *iface {
				continue
			}
			if ev.Source == "route" {
				routeSeen = true
			}
			emit(ev)
		}
	}
}

// selfSigned returns a throwaway ECDSA certificate and the hex SHA-256 of its
// DER, which the dialing side pins.
func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "k3sm-m17-spike"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// linkLocal returns iface's link-local IPv6 address.
func linkLocal(iface string) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Is6() && ip.IsLinkLocalUnicast() {
			return ip.WithZone(iface), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no link-local IPv6 address", iface)
}

// zoneOf splits a host:port and returns the address's zone.
func zoneOf(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return a.Zone()
}

// zoneServe listens with TLS on iface's fe80 address and reports, for the first
// request, the local and remote addresses net/http hands the handler and the
// zone each carries. This is the value the pairing trust decision reads.
func zoneServe(args []string) (int, error) {
	fs := flag.NewFlagSet("zone-serve", flag.ContinueOnError)
	iface := fs.String("iface", "", "the interface to listen on")
	port := fs.Int("port", 19346, "the TCP port")
	dur := fs.Duration("for", 120*time.Second, "how long to wait for a request")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	addr, err := linkLocal(*iface)
	if err != nil {
		return exitError, err
	}
	cert, pin, err := selfSigned()
	if err != nil {
		return exitError, err
	}
	ln, err := net.Listen("tcp6", net.JoinHostPort(addr.String(), fmt.Sprint(*port)))
	if err != nil {
		return exitError, err
	}
	seen := make(chan map[string]any, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			local := ""
			if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
				local = la.String()
			}
			select {
			case seen <- map[string]any{"t": now(), "local": local, "localZone": zoneOf(local), "remote": r.RemoteAddr, "remoteZone": zoneOf(r.RemoteAddr), "tls": r.TLS != nil}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer func() { _ = srv.Close() }()
	emit(map[string]any{"t": now(), "listen": ln.Addr().String(), "pin": pin})
	select {
	case got := <-seen:
		emit(got)
		return exitObserved, nil
	case <-time.After(*dur):
		emit(map[string]any{"t": now(), "timeout": true})
		return exitTimeout, nil
	}
}

// zoneDial dials a zoned fe80 literal with TLS 1.3, verifying the server by the
// pin zone-serve printed (the spike has no CA; the pin is what makes the TLS
// leg real rather than a skipped verification).
func zoneDial(args []string) (int, error) {
	fs := flag.NewFlagSet("zone-dial", flag.ContinueOnError)
	addr := fs.String("addr", "", "the zoned link-local address (fe80::...%enX)")
	port := fs.Int("port", 19346, "the TCP port")
	pin := fs.String("pin", "", "hex SHA-256 of the server certificate")
	timeout := fs.Duration("timeout", 10*time.Second, "dial and request timeout")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	target := net.JoinHostPort(*addr, fmt.Sprint(*port))
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The chain is verified by pin below, not by a CA the spike does not have.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			if !strings.EqualFold(hex.EncodeToString(sum[:]), *pin) {
				return errors.New("server certificate does not match the pin")
			}
			return nil
		},
	}
	var local string
	client := &http.Client{Timeout: *timeout, Transport: &http.Transport{
		TLSClientConfig: cfg,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp6", target)
			if err == nil {
				local = c.LocalAddr().String()
			}
			return c, err
		},
	}}
	start := time.Now()
	resp, err := client.Get("https://link-local/")
	if err != nil {
		emit(map[string]any{"t": now(), "ok": false, "error": err.Error()})
		return exitTimeout, nil
	}
	_ = resp.Body.Close()
	emit(map[string]any{"t": now(), "ok": true, "status": resp.StatusCode, "local": local, "localZone": zoneOf(local), "elapsedMs": time.Since(start).Milliseconds()})
	return exitObserved, nil
}

// allNodes is ff02::1, the group the pairing beacon is sent to.
var allNodes = net.ParseIP("ff02::1")

func mcastListen(args []string) (int, error) {
	fs := flag.NewFlagSet("mcast-listen", flag.ContinueOnError)
	iface := fs.String("iface", "", "the interface")
	port := fs.Int("port", 19347, "the UDP port")
	dur := fs.Duration("for", 60*time.Second, "how long to listen")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		return exitError, err
	}
	c, err := net.ListenMulticastUDP("udp6", ifi, &net.UDPAddr{IP: allNodes, Port: *port})
	if err != nil {
		return exitError, err
	}
	defer func() { _ = c.Close() }()
	if err := c.SetReadDeadline(time.Now().Add(*dur)); err != nil {
		return exitError, err
	}
	emit(map[string]any{"t": now(), "listening": *iface, "port": *port})
	buf := make([]byte, 1500)
	n, from, err := c.ReadFromUDP(buf)
	if err != nil {
		emit(map[string]any{"t": now(), "timeout": true, "error": err.Error()})
		return exitTimeout, nil
	}
	emit(map[string]any{"t": now(), "from": from.String(), "zone": from.Zone, "payload": string(buf[:n])})
	return exitObserved, nil
}

func mcastSend(args []string) (int, error) {
	fs := flag.NewFlagSet("mcast-send", flag.ContinueOnError)
	iface := fs.String("iface", "", "the interface")
	port := fs.Int("port", 19347, "the UDP port")
	count := fs.Int("count", 30, "datagrams to send, one per second")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	c, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		return exitError, err
	}
	defer func() { _ = c.Close() }()
	sent := 0
	for i := 0; i < *count; i++ {
		msg := fmt.Sprintf("k3sm-m17-spike %d", i)
		if _, err := c.WriteTo([]byte(msg), &net.UDPAddr{IP: allNodes, Port: *port, Zone: *iface}); err != nil {
			emit(map[string]any{"t": now(), "seq": i, "error": err.Error()})
		} else {
			sent++
		}
		time.Sleep(time.Second)
	}
	emit(map[string]any{"t": now(), "sent": sent})
	if sent == 0 {
		return exitError, errors.New("no datagram was sent")
	}
	return exitObserved, nil
}
