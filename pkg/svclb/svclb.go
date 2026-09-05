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
//
// BindAddr and AdvertiseAddr are DIFFERENT addresses. The listeners bind
// the wildcard (every interface answers, matching Docker Desktop's vpnkit and
// k3s' klipper-lb), while the status advertises the node's derived
// globally-unicast InternalIP. A wildcard bind cannot witness the advertised
// address, so the assembler — not this package — owns the choice of both.
type Config struct {
	// Client is the cluster client the Service informer and status writes use.
	Client kubernetes.Interface
	// BindAddr is the address every LoadBalancer listener binds. It must be
	// VALID; the WILDCARD (0.0.0.0) is the production choice and is accepted.
	BindAddr netip.Addr
	// AdvertiseAddr is the address published in status.loadBalancer.ingress once
	// every TCP port of a Service is bound. The ZERO Addr is legal and means the
	// node's advertisable address could not be derived: listeners STILL bind, but
	// no status is ever written (the Service stays <pending> — never a loopback
	// or an "invalid IP" EXTERNAL-IP).
	AdvertiseAddr netip.Addr
	// PodCIDR is the pod address space whose addresses this controller OWNS in
	// status and therefore retracts (see Retractable). Pass the CLUSTER pod CIDR,
	// not this node's /24: a node that re-enrolls moves from e.g. 100.64.0.0/24 to
	// 100.64.2.0/24, and the entry stranded in status is the PREVIOUS /24's .1 —
	// which the current /24 does not contain. svclb is the single server-process
	// frontend (multi-node svclb is a named follow-up), so every pod-CIDR address
	// in an LB status was written by this controller or a previous life of it.
	// The zero Prefix disables that arm of the predicate.
	PodCIDR netip.Prefix
	// ReservedPorts is the set of ports k3sm's OWN wildcard listeners occupy (the
	// NodePort range and the kubelet API port — pkg/ports.ReservedSet). bind
	// REFUSES them outright rather than racing a k3sm listener for the same
	// wildcard socket. Admission rejects such a Service first (pkg/policy) — this
	// is the second, datapath-side enforcement point, because the VAP is
	// failurePolicy: Ignore and may be absent.
	//
	// REQUIRED, and New rejects nil. This is a guard whose other two layers (the
	// VAP's Ignore failure policy, its log-and-continue provisioning) already fail
	// OPEN, so letting the ZERO VALUE of this field disable the last one would
	// point all three the same way. A caller that genuinely wants no reservations
	// — only a test — passes an explicit empty map, which is a visible opt-out
	// rather than an omission.
	ReservedPorts map[int32]bool
	// Binder opens every listener in-process (no privilege needed: on Darwin a
	// WILDCARD bind below 1024 does not require root — it is the SPECIFIC-address
	// bind that returns EACCES, inverted from Linux). Nil means netbind.Direct;
	// injectable for tests. There is deliberately no second, privileged binder:
	// routing a wildcard bind through the root netd helper would fail, since netd
	// refuses the wildcard by design.
	Binder netbind.Binder
	// Logger is the structured log sink; nil means slog.Default.
	Logger *slog.Logger
}

// errReservedPort is the sentinel bind returns for a port k3sm's own wildcard
// listeners own. It is distinguished from an ordinary bind failure so the
// operator-facing warning names the real cause.
var errReservedPort = errors.New("port is reserved by a k3sm listener")

// Controller reconciles LoadBalancer Services into BindAddr listeners spliced to
// their ClusterIP VIPs, and writes each Service's LB status ONLY once its
// listeners are actually bound (see the package doc's honesty contract).
type Controller struct {
	cfg Config
	log *slog.Logger
	dir netbind.Binder

	// forwarders is keyed service "ns/name" -> port -> forwarder. It is owned
	// EXCLUSIVELY by the single reconcile-loop goroutine (Run), so it needs no
	// lock — do not touch it from any other goroutine.
	forwarders map[string]map[int32]*forwarder
	// lastWarn backs the per-key warning throttle; same single-goroutine
	// ownership as forwarders.
	lastWarn map[string]time.Time
	// disclaimed records Services this process has already retracted its own
	// advertisement from (a foreign loadBalancerClass). One-shot per process, so
	// declining a Service never becomes a per-reconcile status rewrite that would
	// fight the implementation that DOES own it. Same single-goroutine ownership.
	disclaimed map[string]bool
	// now is the clock seam for the throttle (tests).
	now func() time.Time
}

// New validates cfg and builds the Controller. It starts nothing; call Run.
func New(cfg Config) (*Controller, error) {
	if cfg.Client == nil {
		return nil, errors.New("svclb: config requires a client")
	}
	// Only VALIDITY is required: the wildcard is the production bind address, so
	// an IsUnspecified rejection here would refuse the shipped configuration. A
	// zero Addr stays rejected — it would reach net.Listen as "invalid AddrPort".
	// AdvertiseAddr is deliberately NOT validated: the zero value is the honest
	// "derivation failed" signal (bind, never advertise).
	if !cfg.BindAddr.IsValid() {
		return nil, fmt.Errorf("svclb: config requires a valid bind address, got %q", cfg.BindAddr)
	}
	// Fail CLOSED on the zero value of a guard: a nil set would silently disable
	// the reserved-port refusal, joining the VAP's Ignore failure policy and its
	// log-and-continue provisioning in failing open. An empty (non-nil) map is the
	// explicit opt-out.
	if cfg.ReservedPorts == nil {
		return nil, errors.New("svclb: config requires a ReservedPorts set (pass ports.ReservedSet(), or an explicit empty map to reserve nothing)")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	dir := cfg.Binder
	if dir == nil {
		dir = netbind.Direct{}
	}
	return &Controller{
		cfg:        cfg,
		log:        log,
		dir:        dir,
		forwarders: make(map[string]map[int32]*forwarder),
		lastWarn:   make(map[string]time.Time),
		disclaimed: make(map[string]bool),
		now:        time.Now,
	}, nil
}

// Run watches Services and reconciles listeners + statuses until ctx is
// cancelled, then drains every forwarder. Reconciles are event-driven and
// coalesced; the loop goroutine is the sole owner of the listener state.
func (c *Controller) Run(ctx context.Context) error {
	// ONE line carrying BOTH addresses: they differ, and every other
	// log line in this package renders the BIND address (what a listener actually
	// occupies). Without this line an operator reading "addr=0.0.0.0:8080" has no
	// way to connect it to the EXTERNAL-IP kubectl shows.
	c.log.Info("svclb: loadbalancer controller starting",
		"bind", c.cfg.BindAddr.String(), "advertise", c.advertiseString())
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

// Claims reports whether this controller owns svc — the ONE ownership rule, so
// the register row, the reconcile filter, the retraction and any dependent item
// cite one predicate instead of re-deriving it.
//
// Three conditions, and the middle one is the API's multi-implementation
// contract: spec.loadBalancerClass nil means "the default implementation", and
// an implementation MUST ignore a Service whose class it does not own. k3sm
// claims NIL ONLY and publishes no class of its own — the same posture upstream's
// cloud-provider controller, k3s and MetalLB take by default. Publishing a class
// would mint a permanent, per-Service IMMUTABLE, user-visible API value (the
// field cannot be changed once set), so it stays an operator decision rather
// than a default.
//
// "Ignore" is literal upstream: a classed Service is never enqueued, so it is
// never bound AND never status-patched. Declining to serve a Service while still
// rewriting its status would not defer to the other implementation at all — it
// would move the collision from the datapath to the status subresource, where it
// is harder to diagnose.
func Claims(svc *corev1.Service) bool {
	if svc == nil || svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	if svc.Spec.LoadBalancerClass != nil {
		return false
	}
	// The k3sm-internal marker on the Service k3sm itself provisions for the
	// ingress host, whose :80/:443 listeners that component owns directly. It
	// stays a label rather than a class because loadBalancerClass is immutable
	// and that Service is created-if-absent, so an upgraded cluster could never
	// acquire one.
	return svc.Labels[IgnoreLabel] != "true"
}

// reconcile drives the listener set + statuses to match svcs: forwarders for
// removed/retyped Services (or changed VIPs/ports) are torn down, missing
// listeners are bound, and each Service's status is written or cleared per the
// bind-then-advertise honesty rule.
func (c *Controller) reconcile(ctx context.Context, svcs []*corev1.Service) {
	desired := make(map[string]*corev1.Service)
	for _, s := range svcs {
		if !Claims(s) {
			// A Service with a foreign class was possibly claimed by an earlier
			// k3sm build; retract that stale advertisement exactly once rather
			// than leaving an EXTERNAL-IP with no listener behind it.
			c.retractDisclaimed(ctx, s)
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
			if errors.Is(err, errReservedPort) {
				c.throttledWarn(fmt.Sprintf("%s\x00reserved:%d", key, p.Port),
					"svclb: loadbalancer port is RESERVED by a k3sm wildcard listener (the NodePort range or the kubelet API port); no listener bound, status stays empty — pick a different spec.ports[].port",
					"service", key, "port", p.Port, "bind", c.bindAddrPort(p.Port).String())
				continue
			}
			c.throttledWarn(fmt.Sprintf("%s\x00bind:%d", key, p.Port),
				"svclb: listener bind failed; status stays empty. Likely causes: another local process OR POD already listening on this wildcard port (darwin has no network namespaces, so pods share the node's port space); a second LoadBalancer Service declaring the same port; or a k3sm-reserved port",
				"service", key, "addr", c.bindAddrPort(p.Port).String(),
				"diagnose", fmt.Sprintf("lsof -nP -iTCP:%d -sTCP:LISTEN", p.Port), "err", err)
			continue
		}
		if c.forwarders[key] == nil {
			c.forwarders[key] = make(map[int32]*forwarder)
		}
		c.forwarders[key][p.Port] = f
		c.log.Info("svclb: loadbalancer listener bound",
			"service", key, "addr", c.bindAddrPort(p.Port).String(), "advertise", c.advertiseString(), "vip", f.dst.String())
		bound++
	}
	// A derivable advertise address is part of the "can this Service be
	// advertised" predicate, not merely an input to it. With no derivable
	// address there is nothing honest to publish, so the Service settles into
	// the SAME state as an unbound one — status RETRACTED, not merely left
	// alone. Routing to ensureStatus here and returning early inside it would
	// mean clearStatus (and therefore Retractable) never runs, stranding a
	// pre-existing loopback or previous-/24 entry forever. ingresshost.syncStatus
	// makes the identical decision; Retractable is the one rule both then apply.
	if tcpPorts > 0 && bound == tcpPorts && c.cfg.AdvertiseAddr.IsValid() {
		c.ensureStatus(ctx, svc)
	} else {
		c.clearStatus(ctx, svc)
	}
}

// bind opens one BindAddr:port listener through the single in-process binder and
// starts its forwarder. There is no port-keyed binder selection any more: on
// Darwin a wildcard bind needs no privilege at ANY port, so the netd helper is
// off the LoadBalancer datapath entirely (and would refuse the wildcard anyway).
//
// It REFUSES a reserved port before touching the binder: racing k3sm's own
// NodePort-range or kubelet-API listener for the same wildcard socket would let
// the winner be decided by start order, and losing :10250 kills logs/exec/
// `kubectl top` on this node.
func (c *Controller) bind(ctx context.Context, port int32, dst netip.AddrPort) (*forwarder, error) {
	if c.cfg.ReservedPorts[port] {
		return nil, fmt.Errorf("svclb: refusing port %d: %w", port, errReservedPort)
	}
	ln, err := c.dir.Listen(ctx, "tcp", c.bindAddrPort(port))
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

// bindAddrPort is the AddrPort a listener for port occupies — always rendered
// from the BIND address, never the advertised one, so a log line names the
// socket that actually exists.
func (c *Controller) bindAddrPort(port int32) netip.AddrPort {
	return netip.AddrPortFrom(c.cfg.BindAddr, uint16(port))
}

// advertiseString renders the advertised address for logs, naming the derivation
// failure explicitly rather than letting the zero Addr print as "invalid IP".
func (c *Controller) advertiseString() string {
	if !c.cfg.AdvertiseAddr.IsValid() {
		return "<none: node address not derived; loadbalancer status stays empty>"
	}
	return c.cfg.AdvertiseAddr.String()
}

// ensureStatus advertises this node's derived address on svc's LB status
// (idempotent). The status is EXACTLY this node's advertised address: the server
// process is the single frontend (multi-node svclb is the named follow-up
// alongside multi-node ingress).
//
// PRECONDITION, owned by the caller (reconcileService): AdvertiseAddr is valid.
// The "is there anything honest to advertise" decision lives at exactly ONE
// place, so a Service that cannot be advertised is routed to clearStatus rather
// than silently short-circuiting here.
func (c *Controller) ensureStatus(ctx context.Context, svc *corev1.Service) {
	ip := c.cfg.AdvertiseAddr.String()
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

// Retractable reports whether an existing status.loadBalancer.ingress entry ip
// must be dropped when this node cannot honestly advertise it. It is the ONE
// retraction rule, exported so the ingress host applies exactly the same
// predicate to Ingress and canonical LB Service statuses instead of growing a
// second, drifting copy.
//
// An entry is retractable when it is:
//
//   - the CURRENT advertise address (the ordinary case), or
//   - ANY loopback address — an older default that an upgraded cluster may
//     still carry; nothing outside this Mac can ever reach it, so an LB status
//     advertising loopback is never legitimate, or
//   - ANY address inside podCIDR. Assemblers pass the CLUSTER pod aggregate
//     (100.64.0.0/10), not this node's /24, because the entry that most needs
//     retracting is a PREVIOUS derived address from before the node's /24 moved
//     (a re-enrolled agent goes 100.64.0.0/24 → 100.64.2.0/24) — which the
//     current /24 does not contain, and which filtering on the advertise value
//     alone strands forever, since ensureStatus REPLACES the slice (self-healing)
//     but clearStatus only filters.
//
// # What this does NOT guarantee
//
// It is NOT "only k3sm's own entries are touched". The third arm is a whole-range
// test over 100.64.0.0/10, which is public RFC-6598 CGNAT space that other tools
// allocate from — Tailscale most commonly, and k3sm's own mesh IPs live there
// too. Any address in that range appearing in an LB status this controller owns
// WILL be dropped, whoever wrote it. Only addresses OUTSIDE the range and outside
// loopback (a LAN address, a public address, a hostname) are left alone.
//
// That widening is deliberate and is sound ONLY under one invariant: svclb is the
// SINGLE server-process frontend for the whole cluster (see the package doc), so
// every pod-space address in an LB status it manages was written by this
// controller or by a previous life of it. There is no second writer to collide
// with.
//
// REVISIT THIS ARM when that invariant ends. Multi-node svclb — the named
// follow-up alongside multi-node ingress — introduces per-node writers whose
// advertised addresses all live in 100.64.0.0/10, and each would then retract the
// others' entries on every reconcile. The fix at that point is to scope this arm
// to the writing node's own /24 plus an explicit record of the /24s it previously
// held, NOT to keep widening it.
func Retractable(podCIDR netip.Prefix, advertise netip.Addr, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false // not an address we could have written
	}
	addr = addr.Unmap()
	switch {
	case advertise.IsValid() && addr == advertise:
		return true
	case addr.IsLoopback():
		return true
	case podCIDR.IsValid() && podCIDR.Contains(addr):
		return true
	}
	return false
}

// clearStatus removes this node's advertised address from svc's LB status if
// present (the listeners are not (all) bound — never advertise a dead address).
// It applies the shared Retractable predicate, NOT a single-value comparison.
func (c *Controller) clearStatus(ctx context.Context, svc *corev1.Service) {
	keep := make([]corev1.LoadBalancerIngress, 0, len(svc.Status.LoadBalancer.Ingress))
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		if !Retractable(c.cfg.PodCIDR, c.cfg.AdvertiseAddr, lbi.IP) {
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

// retractDisclaimed removes THIS controller's own advertisement from a Service
// it no longer claims, exactly once per Service per process.
//
// It exists for one reachable state: a Service carrying a foreign
// loadBalancerClass that an OLDER k3sm build claimed and advertised. The
// apiserver cannot clean that up — it wipes LB status only on a type change, and
// it forbids changing the class in place — so without this the filter would
// unbind the listeners and leave the address published, turning a wrong claim
// ("k3sm owns this") into a worse one ("k3sm serves this", with nothing
// listening). Every generic client reads status, not the daemon log.
//
// It is deliberately NARROWER than Retractable, which treats the whole pod CIDR
// as retractable. That breadth is sound only while svclb is the single LB
// frontend — the exact invariant honouring loadBalancerClass gives up. Here the
// Service belongs to another implementation, so only an entry equal to THIS
// node's AdvertiseAddr may be touched; anything else is the other
// implementation's to manage.
func (c *Controller) retractDisclaimed(ctx context.Context, svc *corev1.Service) {
	if svc == nil || !c.cfg.AdvertiseAddr.IsValid() {
		return
	}
	key := svc.Namespace + "/" + svc.Name
	if c.disclaimed[key] {
		return // one-shot per process; never a per-reconcile status rewrite
	}
	mine := c.cfg.AdvertiseAddr.String()
	keep := make([]corev1.LoadBalancerIngress, 0, len(svc.Status.LoadBalancer.Ingress))
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		if lbi.IP != mine {
			keep = append(keep, lbi)
		}
	}
	c.disclaimed[key] = true
	if len(keep) == len(svc.Status.LoadBalancer.Ingress) {
		return // nothing of ours to retract
	}
	upd := svc.DeepCopy()
	upd.Status.LoadBalancer.Ingress = keep
	if _, err := c.cfg.Client.CoreV1().Services(svc.Namespace).UpdateStatus(ctx, upd, metav1.UpdateOptions{}); err != nil {
		c.log.Warn("svclb: retract advertisement for disclaimed service", "service", key, "err", err)
		delete(c.disclaimed, key) // allow a retry on the next reconcile
		return
	}
	c.log.Info("svclb: retracted stale advertisement for a service this build does not claim",
		"service", key, "class", classOf(svc), "address", mine)
}

// classOf renders a Service's loadBalancerClass for logs ("<none>" when unset).
func classOf(svc *corev1.Service) string {
	if svc.Spec.LoadBalancerClass == nil {
		return "<none>"
	}
	return *svc.Spec.LoadBalancerClass
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
