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

package svclb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"k3sm.io/darwin-net/pkg/netbind"
)

// IgnoreLabel marks a LoadBalancer Service this controller must SKIP entirely
// (no listeners, no status). The canonical kube-system/k3sm-ingress Service
// carries it: the in-process ingress Server owns those listeners, and splicing
// its selector-less ClusterIP would forward into a void.
const IgnoreLabel = "svclb.k3sm.io/ignore"

// warnInterval throttles repeated per-key warnings (bind conflicts, UDP
// deferral) so a persistent conflict does not flood the log on every event.
const warnInterval = 30 * time.Second

// Config configures the svclb Controller.
type Config struct {
	// Client is the cluster client the Service informer and status writes use.
	Client kubernetes.Interface
	// NodeIP is the SPECIFIC node InternalIP the listeners bind and the address
	// advertised in status.loadBalancer once they are bound.
	NodeIP netip.Addr
	// PrivilegedBinder opens <1024 listeners: netbind.Netd in the unprivileged
	// helper posture (the daemon authorizes the bind because the LoadBalancer
	// Service itself declares the port — the netdsvc node-address rule). Nil
	// means netbind.Direct (run-as-root).
	PrivilegedBinder netbind.Binder
	// Binder opens >=1024 listeners directly in-process (no privilege needed).
	// Nil means netbind.Direct; injectable for tests.
	Binder netbind.Binder
	// Logger is the structured log sink; nil means slog.Default.
	Logger *slog.Logger
}

// Controller reconciles LoadBalancer Services into nodeIP listeners spliced to
// their ClusterIP VIPs, and writes each Service's LB status ONLY once its
// listeners are actually bound (see the package doc's honesty contract).
type Controller struct {
	cfg  Config
	log  *slog.Logger
	priv netbind.Binder
	dir  netbind.Binder

	// forwarders is keyed service "ns/name" -> port -> forwarder. It is owned
	// EXCLUSIVELY by the single reconcile-loop goroutine (Run), so it needs no
	// lock — do not touch it from any other goroutine.
	forwarders map[string]map[int32]*forwarder
	// lastWarn backs the per-key warning throttle; same single-goroutine
	// ownership as forwarders.
	lastWarn map[string]time.Time
	// now is the clock seam for the throttle (tests).
	now func() time.Time
}

// New validates cfg and builds the Controller. It starts nothing; call Run.
func New(cfg Config) (*Controller, error) {
	if cfg.Client == nil {
		return nil, errors.New("svclb: config requires a client")
	}
	if !cfg.NodeIP.IsValid() || cfg.NodeIP.IsUnspecified() {
		return nil, fmt.Errorf("svclb: config requires a specific node address, got %q", cfg.NodeIP)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	priv := cfg.PrivilegedBinder
	if priv == nil {
		priv = netbind.Direct{}
	}
	dir := cfg.Binder
	if dir == nil {
		dir = netbind.Direct{}
	}
	return &Controller{
		cfg:        cfg,
		log:        log,
		priv:       priv,
		dir:        dir,
		forwarders: make(map[string]map[int32]*forwarder),
		lastWarn:   make(map[string]time.Time),
		now:        time.Now,
	}, nil
}

// Run watches Services and reconciles listeners + statuses until ctx is
// cancelled, then drains every forwarder. Reconciles are event-driven and
// coalesced; the loop goroutine is the sole owner of the listener state.
func (c *Controller) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(c.cfg.Client, 30*time.Second)
	inf := factory.Core().V1().Services().Informer()
	trigger := make(chan struct{}, 1)
	kick := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { kick() },
		UpdateFunc: func(_, _ any) { kick() },
		DeleteFunc: func(any) { kick() },
	}); err != nil {
		return fmt.Errorf("svclb: add service handler: %w", err)
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return errors.New("svclb: service informer cache sync failed")
	}
	kick()
	for {
		select {
		case <-ctx.Done():
			c.closeAll()
			return nil
		case <-trigger:
			c.reconcile(ctx, servicesFromStore(inf.GetStore()))
		}
	}
}

// servicesFromStore snapshots the informer cache's Services.
func servicesFromStore(store cache.Store) []*corev1.Service {
	items := store.List()
	svcs := make([]*corev1.Service, 0, len(items))
	for _, item := range items {
		if s, ok := item.(*corev1.Service); ok {
			svcs = append(svcs, s)
		}
	}
	return svcs
}

// reconcile drives the listener set + statuses to match svcs: forwarders for
// removed/retyped Services (or changed VIPs/ports) are torn down, missing
// listeners are bound, and each Service's status is written or cleared per the
// bind-then-advertise honesty rule.
func (c *Controller) reconcile(ctx context.Context, svcs []*corev1.Service) {
	desired := make(map[string]*corev1.Service)
	for _, s := range svcs {
		if s.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if s.Labels[IgnoreLabel] == "true" {
			continue
		}
		desired[s.Namespace+"/"+s.Name] = s
	}

	// Tear down forwarders that no longer match a desired (service, port, VIP).
	for key, ports := range c.forwarders {
		want := make(map[int32]netip.AddrPort)
		if svc := desired[key]; svc != nil {
			if vip, err := netip.ParseAddr(svc.Spec.ClusterIP); err == nil {
				for _, p := range svc.Spec.Ports {
					if isTCP(p) {
						want[p.Port] = netip.AddrPortFrom(vip, uint16(p.Port))
					}
				}
			}
		}
		for port, f := range ports {
			if dst, ok := want[port]; !ok || dst != f.dst {
				f.stop()
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(c.forwarders, key)
		}
	}

	for key, svc := range desired {
		c.reconcileService(ctx, key, svc)
	}
}

// reconcileService binds the missing TCP listeners for one LoadBalancer
// Service and settles its status: advertised ONLY when every TCP port is
// bound; cleared otherwise (a conflict keeps the status empty with a
// throttled Warn — never a dead address).
func (c *Controller) reconcileService(ctx context.Context, key string, svc *corev1.Service) {
	vip, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		c.throttledWarn(key+"\x00vip", "svclb: loadbalancer service has no dialable clusterIP; no listeners bound",
			"service", key, "clusterIP", svc.Spec.ClusterIP)
		c.clearStatus(ctx, svc)
		return
	}
	tcpPorts, bound := 0, 0
	for _, p := range svc.Spec.Ports {
		if !isTCP(p) {
			// UDP (or SCTP) LoadBalancer is DEFERRED: the userspace splice is
			// TCP-only today. Skipped loudly; does not gate the TCP ports' status.
			c.throttledWarn(fmt.Sprintf("%s\x00proto:%d", key, p.Port),
				"svclb: non-TCP loadbalancer port skipped (UDP LB deferred)",
				"service", key, "port", p.Port, "protocol", string(p.Protocol))
			continue
		}
		tcpPorts++
		if c.forwarders[key][p.Port] != nil {
			bound++
			continue
		}
		f, err := c.bind(ctx, p.Port, netip.AddrPortFrom(vip, uint16(p.Port)))
		if err != nil {
			c.throttledWarn(fmt.Sprintf("%s\x00bind:%d", key, p.Port),
				"svclb: listener bind failed (port conflict?); status stays empty",
				"service", key, "addr", netip.AddrPortFrom(c.cfg.NodeIP, uint16(p.Port)).String(), "err", err)
			continue
		}
		if c.forwarders[key] == nil {
			c.forwarders[key] = make(map[int32]*forwarder)
		}
		c.forwarders[key][p.Port] = f
		c.log.Info("svclb: loadbalancer listener bound",
			"service", key, "addr", netip.AddrPortFrom(c.cfg.NodeIP, uint16(p.Port)).String(), "vip", f.dst.String())
		bound++
	}
	if tcpPorts > 0 && bound == tcpPorts {
		c.ensureStatus(ctx, svc)
	} else {
		c.clearStatus(ctx, svc)
	}
}

// bind opens one nodeIP:port listener — through the privileged binder (the
// netd helper, authorized because the LoadBalancer Service declares the port)
// for <1024, directly otherwise — and starts its forwarder.
func (c *Controller) bind(ctx context.Context, port int32, dst netip.AddrPort) (*forwarder, error) {
	binder := c.dir
	if port < 1024 {
		binder = c.priv
	}
	ln, err := binder.Listen(ctx, "tcp", netip.AddrPortFrom(c.cfg.NodeIP, uint16(port)))
	if err != nil {
		return nil, err
	}
	fctx, cancel := context.WithCancel(ctx)
	f := &forwarder{ln: ln, dst: dst, cancel: cancel, done: make(chan struct{}), log: c.log}
	go f.run(fctx)
	return f, nil
}

// closeAll drains every forwarder (shutdown).
func (c *Controller) closeAll() {
	for key, ports := range c.forwarders {
		for _, f := range ports {
			f.stop()
		}
		delete(c.forwarders, key)
	}
}

// throttledWarn logs msg at Warn at most once per warnInterval per key.
func (c *Controller) throttledWarn(key, msg string, args ...any) {
	now := c.now()
	if last, ok := c.lastWarn[key]; ok && now.Sub(last) < warnInterval {
		return
	}
	c.lastWarn[key] = now
	c.log.Warn(msg, args...)
}

// ensureStatus advertises this node's IP on svc's LB status (idempotent). The
// status is EXACTLY this node's IP: the server process is the single frontend
// (multi-node svclb is the named follow-up alongside multi-node ingress).
func (c *Controller) ensureStatus(ctx context.Context, svc *corev1.Service) {
	ip := c.cfg.NodeIP.String()
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		if lbi.IP == ip {
			return
		}
	}
	upd := svc.DeepCopy()
	upd.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ip}}
	if _, err := c.cfg.Client.CoreV1().Services(svc.Namespace).UpdateStatus(ctx, upd, metav1.UpdateOptions{}); err != nil {
		c.log.Warn("svclb: update loadbalancer status", "service", svc.Namespace+"/"+svc.Name, "err", err)
	}
}

// clearStatus removes this node's IP from svc's LB status if present (the
// listeners are not (all) bound — never advertise a dead address).
func (c *Controller) clearStatus(ctx context.Context, svc *corev1.Service) {
	ip := c.cfg.NodeIP.String()
	keep := make([]corev1.LoadBalancerIngress, 0, len(svc.Status.LoadBalancer.Ingress))
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		if lbi.IP != ip {
			keep = append(keep, lbi)
		}
	}
	if len(keep) == len(svc.Status.LoadBalancer.Ingress) {
		return
	}
	upd := svc.DeepCopy()
	upd.Status.LoadBalancer.Ingress = keep
	if _, err := c.cfg.Client.CoreV1().Services(svc.Namespace).UpdateStatus(ctx, upd, metav1.UpdateOptions{}); err != nil {
		c.log.Warn("svclb: clear loadbalancer status", "service", svc.Namespace+"/"+svc.Name, "err", err)
	}
}

// isTCP reports whether p is a TCP port (an empty protocol defaults to TCP).
func isTCP(p corev1.ServicePort) bool {
	return p.Protocol == "" || p.Protocol == corev1.ProtocolTCP
}

// forwarder owns one bound listener and splices every accepted connection to
// its Service's ClusterIP VIP. Its lifetime is bounded by the context bind
// derived it from; stop cancels and waits for the accept loop to exit.
type forwarder struct {
	ln     net.Listener
	dst    netip.AddrPort
	cancel context.CancelFunc
	done   chan struct{}
	log    *slog.Logger
}

// stop cancels the forwarder and waits for its accept loop to drain.
func (f *forwarder) stop() {
	f.cancel()
	<-f.done
}

// run accepts until the listener closes (context cancel) and splices each
// connection concurrently.
func (f *forwarder) run(ctx context.Context) {
	defer close(f.done)
	go func() {
		<-ctx.Done()
		_ = f.ln.Close()
	}()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				f.log.Warn("svclb: accept failed; listener stopped", "addr", f.ln.Addr().String(), "err", err)
			}
			return
		}
		go f.splice(ctx, conn)
	}
}

// splice forwards src <-> the ClusterIP VIP: a plain two-way io.Copy with TCP
// half-close propagation, torn down when either side finishes or ctx cancels.
func (f *forwarder) splice(ctx context.Context, src net.Conn) {
	defer src.Close()
	var d net.Dialer
	dst, err := d.DialContext(ctx, "tcp", f.dst.String())
	if err != nil {
		f.log.Warn("svclb: dial service VIP failed", "vip", f.dst.String(), "err", err)
		return
	}
	defer dst.Close()

	// Close both conns on ctx cancel so shutdown drains in-flight splices; the
	// deferred cancel reaps the watcher goroutine when the splice ends first.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		_ = src.Close()
		_ = dst.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(src, dst)
		closeWrite(src)
	}()
	wg.Wait()
}

// closeWrite propagates a half-close where the conn supports it (TCP).
func closeWrite(c net.Conn) {
	if hc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
	}
}
