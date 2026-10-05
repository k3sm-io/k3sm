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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/darwin-net/pkg/tcpseg"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/bootstrap/pairing"
	"k3sm.io/k3sm/pkg/linkgraph"
)

// ifaceLinkUp reports an interface's link state from its flags: up and running.
func ifaceLinkUp(name string) bool {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	return ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0
}

// recordFacts is the runtime's onFacts in production: the node's label facts.
func recordFacts(f directLinkFacts) { nodeDirectLinkFacts.Store(&f) }

// newWorkerDirectLinks builds a joined worker's direct-link loop. It publishes
// through the node-certificate verb and reads its own resolved status the same
// way, because the node identity has no read verb on DirectLink. serverHost is
// the bootstrap host:port the post-join verbs go to.
func newWorkerDirectLinks(opts agentOptions, res *bootstrap.JoinResult, serverHost string, logger *slog.Logger) (*directLinkRuntime, error) {
	podCIDR, err := netip.ParsePrefix(res.PodCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse assigned podCIDR %q: %w", res.PodCIDR, err)
	}
	client, err := bootstrap.NodeIdentityClient(res.ClusterCAPEM, res.NodeClientCertPEM, res.NodeClientKeyPEM)
	if err != nil {
		return nil, err
	}
	serverURL := bootstrap.HTTPSURL(serverHost)
	var first netip.Addr
	if res.ServerLinkIP != "" {
		if a, err := netip.ParseAddr(res.ServerLinkIP); err == nil && netv1alpha1.IsLinkAddress(a) {
			first = a
		}
	}
	return newDirectLinkRuntime(directLinkConfig{
		node:      opts.nodeName,
		podCIDR:   podCIDR,
		meshPort:  opts.meshPort,
		enumerate: linkenum.Exec{}.Ports,
		ifaceUp:   ifaceLinkUp,
		publish: func(ctx context.Context, spec netv1alpha1.DirectLinkSpec) error {
			return bootstrap.PublishDirectLink(ctx, client, serverURL, spec)
		},
		fetch: func(ctx context.Context) (*netv1alpha1.DirectLink, bool, error) {
			return bootstrap.FetchDirectLink(ctx, client, serverURL)
		},
		tunnelOnly: func() (tunnelOnlyOverrides, error) {
			return readTunnelOnly(filepath.Join(opts.workDir, tunnelOnlyFile))
		},
		firstContact: first,
		rdmaEnabled:  probeRDMAEnabled,
		onFacts:      recordFacts,
		statusDir:    opts.workDir,
		log:          logger,
	}), nil
}

// newServerDirectLinks builds the control-plane node's direct-link loop. It
// writes through the enroller in-process and watches its own DirectLink with an
// informer over the admin client.
func newServerDirectLinks(e *meshEnroller, opts serverOptions, podCIDR, kubeconfig string, logger *slog.Logger) (*directLinkRuntime, error) {
	prefix, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse the control-plane podCIDR %q: %w", podCIDR, err)
	}
	return newDirectLinkRuntime(directLinkConfig{
		node:      opts.nodeName,
		podCIDR:   prefix,
		meshPort:  serverMeshListenPort,
		enumerate: linkenum.Exec{}.Ports,
		ifaceUp:   ifaceLinkUp,
		publish:   e.ApplyDirectLink,
		watch: func(ctx context.Context, sink func(*netv1alpha1.DirectLink)) error {
			return watchOwnDirectLink(ctx, kubeconfig, opts.nodeName, sink)
		},
		tunnelOnly: func() (tunnelOnlyOverrides, error) {
			return readTunnelOnly(filepath.Join(opts.workDir, tunnelOnlyFile))
		},
		rdmaEnabled: probeRDMAEnabled,
		onFacts:     recordFacts,
		statusDir:   opts.workDir,
		log:         logger,
	}), nil
}

// watchOwnDirectLink runs an informer over the one DirectLink named node and
// hands every add or update to sink, until ctx ends.
func watchOwnDirectLink(ctx context.Context, kubeconfig, node string, sink func(*netv1alpha1.DirectLink)) error {
	cfg, err := restConfigFromKubeconfig(kubeconfig)
	if err != nil {
		return err
	}
	client, err := linkgraph.RESTClient(cfg)
	if err != nil {
		return err
	}
	lw := cache.NewListWatchFromClient(client, linkgraph.Resource, metav1.NamespaceAll, fields.OneTermEqualSelector("metadata.name", node))
	inf := cache.NewSharedIndexInformer(lw, &netv1alpha1.DirectLink{}, 0, cache.Indexers{})
	deliver := func(obj any) {
		if dl, ok := obj.(*netv1alpha1.DirectLink); ok {
			sink(dl)
		}
	}
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    deliver,
		UpdateFunc: func(_, obj any) { deliver(obj) },
	}); err != nil {
		return err
	}
	inf.Run(ctx.Done())
	return nil
}

// restConfigFromKubeconfig loads a kubeconfig for the informer above.
func restConfigFromKubeconfig(path string) (*rest.Config, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig for the DirectLink watch: %w", err)
	}
	return cfg, nil
}

// cabledPort returns this Mac's lowest-ordinal Thunderbolt port with something
// cabled to it: the port a cable-only joiner names for its derived endpoint and
// routes its first contact over.
func cabledPort(ctx context.Context, enum linkenum.Enumerator) (linkenum.Port, error) {
	ports, err := enum.Ports(ctx)
	if err != nil {
		return linkenum.Port{}, err
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].PortOrdinal < ports[j].PortOrdinal })
	for _, p := range ports {
		if p.PeerDomainUUID != "" {
			return p, nil
		}
	}
	return linkenum.Port{}, errors.New("no Thunderbolt port has a Mac cabled to it")
}

// serverLinkIPFor is this server's direct-link address on the cable port named by
// a connection's local zone, or "" when the zone is not a Thunderbolt port. It
// is what fills the join response's ServerLinkIP.
func serverLinkIPFor(ctx context.Context, hw func(context.Context) (map[string]int, error), podCIDR netip.Prefix, iface string) string {
	if iface == "" {
		return ""
	}
	ports, err := hw(ctx)
	if err != nil {
		return ""
	}
	receptacle, ok := ports[iface]
	if !ok {
		return ""
	}
	idx, err := podnet.NodeIndex(podnet.ClusterPodCIDR, podCIDR)
	if err != nil {
		return ""
	}
	a, err := netv1alpha1.LinkIP(idx, receptacle-1)
	if err != nil {
		return ""
	}
	return a.String()
}

// zoneOf is the zone of an address's IP (the interface of a link-local TCP
// connection), or "".
func zoneOf(addr net.Addr) string {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return a.Zone()
}

// isZonedHost reports whether host is a zoned IPv6 literal (fe80::1%en2).
func isZonedHost(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.Zone() != ""
}

// linkHost is the server's per-cable presence: on every configured cable port
// with a link-local address it serves the join listener's LinkHandler (the join
// and the pairing verb) bound to that address, and sends the pairing beacon.
// Ports come and go with cables, so it re-evaluates on a short period.
//
// Locking: mu guards running only.
type linkHost struct {
	ports   func() []linkenum.Port
	handler http.Handler
	tlsCfg  *tls.Config
	beacon  func() netv1alpha1.Beacon
	log     *slog.Logger

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// linkHostPeriod is how often the server re-evaluates its cable ports.
const linkHostPeriod = 5 * time.Second

// run keeps one listener and one beacon per configured cable port until ctx ends.
func (h *linkHost) run(ctx context.Context) {
	h.running = map[string]context.CancelFunc{}
	t := time.NewTicker(linkHostPeriod)
	defer t.Stop()
	for {
		h.reconcile(ctx)
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for _, stop := range h.running {
				stop()
			}
			h.mu.Unlock()
			return
		case <-t.C:
		}
	}
}

func (h *linkHost) reconcile(ctx context.Context) {
	want := map[string]bool{}
	for _, p := range h.ports() {
		want[p.Iface] = true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for iface, stop := range h.running {
		if !want[iface] {
			stop()
			delete(h.running, iface)
		}
	}
	for iface := range want {
		if _, ok := h.running[iface]; ok {
			continue
		}
		addr, ok := linkLocalOf(iface)
		if !ok {
			continue // DAD may not have completed since the port left the bridge
		}
		lctx, cancel := context.WithCancel(ctx)
		if err := h.serve(lctx, iface, addr); err != nil {
			cancel()
			h.log.Debug("link-local join listener not opened yet", "iface", iface, "err", err)
			continue
		}
		h.running[iface] = cancel
		go pairing.Sender{Iface: iface, Beacon: h.beacon, Logger: h.log}.Run(lctx)
		h.log.Info("serving the join listener and the pairing beacon on a cable port", "iface", iface, "addr", addr.String())
	}
}

// serve binds the join listener to iface's link-local address (a per-interface
// bind, never the wildcard) and serves the link handler on it until ctx ends.
func (h *linkHost) serve(ctx context.Context, iface string, addr netip.Addr) error {
	ln, err := net.Listen("tcp6", net.JoinHostPort(addr.WithZone(iface).String(), strconv.Itoa(bootstrapPort)))
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h.handler, TLSConfig: h.tlsCfg, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	// The segment clamp every cross-node listener carries: this one accepts over
	// the cable, which is a cross-node path like any other (R15).
	clamped := tcpseg.WrapListener(ln)
	go func() {
		if err := srv.ServeTLS(clamped, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.log.Warn("link-local join listener stopped", "iface", iface, "err", err)
		}
	}()
	return nil
}

// linkLocalOf returns iface's fe80 address.
func linkLocalOf(iface string) (netip.Addr, bool) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Is6() && ip.IsLinkLocalUnicast() {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

// pairingListenIfaces is where a joiner listens for beacons: bridge0 (an unjoined
// Mac's cable ports are still bridge members, and their frames are forwarded
// there) and every Thunderbolt interface.
func pairingListenIfaces(ctx context.Context) []string {
	out := []string{"bridge0"}
	if hw, err := linkenum.HardwarePorts(ctx); err == nil {
		var names []string
		for name := range hw {
			names = append(names, name)
		}
		sort.Strings(names)
		out = append(out, names...)
	}
	return out
}

// autoJoinPairing runs the joiner: inert (pairing.ErrNotArmed) unless this Mac is
// armed, else it listens for beacons until it obtains a token or the arming ends.
func autoJoinPairing(ctx context.Context, opts agentOptions, logger *slog.Logger) (pairing.Result, error) {
	arm, ok, err := pairing.LoadArm(pairing.ArmPath(opts.workDir))
	if err != nil {
		return pairing.Result{}, err
	}
	if !ok || !arm.Armed(time.Now()) {
		return pairing.Result{}, pairing.ErrNotArmed
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ifaces := pairingListenIfaces(rctx)
	beacons, err := pairing.Receive(rctx, ifaces, logger)
	if err != nil {
		return pairing.Result{}, err
	}
	if arm.Cluster == "" {
		logger.Warn("auto-join is armed WITHOUT --cluster: this Mac will trust the first open-pairing server it hears on a Thunderbolt port while armed (see docs/user/direct-links.md)", "until", arm.Until.Format(time.RFC3339))
	}
	logger.Info("auto-join armed: listening for a pairing beacon", "interfaces", strings.Join(ifaces, ","), "until", arm.Until.Format(time.RFC3339))
	j := pairing.Joiner{Arm: arm, NodeName: opts.nodeName, Pair: pairing.RequestPair, Logger: logger}
	return j.Run(rctx, beacons)
}

// nodeEventRecorder records Events against one Node through the server's admin
// client (pairing.Recorder). It is best effort: an Event that cannot be written is
// logged by nobody, because the Warn line beside it already says the same thing.
type nodeEventRecorder struct {
	cs        kubernetes.Interface
	node      string
	component string
}

// Record writes one Event.
func (r nodeEventRecorder) Record(eventType, reason, message string) {
	if r.cs == nil {
		return
	}
	now := metav1.Now()
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: fmt.Sprintf("%s.%x", r.node, now.UnixNano()), Namespace: metav1.NamespaceDefault},
		InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: r.node, APIVersion: "v1"},
		Reason:         reason,
		Message:        message,
		Type:           eventType,
		Source:         corev1.EventSource{Component: r.component},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = r.cs.CoreV1().Events(metav1.NamespaceDefault).Create(ctx, ev, metav1.CreateOptions{})
}
