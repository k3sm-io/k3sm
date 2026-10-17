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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"k3sm.io/darwin-net/pkg/netbind"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// IgnoreLabel marks a LoadBalancer Service this package must SKIP entirely (no
// stamp, no listeners, no status). The canonical kube-system/k3sm-ingress
// Service carries it: the in-process ingress Server owns those listeners, and
// splicing its selector-less ClusterIP would forward into a void.
const IgnoreLabel = "svclb.k3sm.io/ignore"

// FieldManager is the field manager of every write this package makes.
const FieldManager = "k3sm-svclb"

// warnInterval throttles repeated per-key warnings (bind conflicts, UDP
// deferral) so a persistent conflict does not flood the log on every event.
const warnInterval = 30 * time.Second

// hosterResync is how often the hoster re-runs its reconcile without an event,
// which is what retries a report write or a start-of-life reset that failed.
const hosterResync = 30 * time.Second

// withdrawTimeout bounds the best-effort write of the empty report on shutdown.
const withdrawTimeout = 5 * time.Second

// HosterConfig configures a Hoster, the per-node half of svclb.
type HosterConfig struct {
	// Client is THIS node's client (system:node:<name> on a joined worker and on
	// the server's in-process node). It watches Services, watches its own Node,
	// and merge-patches BoundAnnotation on its own Node. It never writes a
	// Service.
	Client kubernetes.Interface
	// NodeName is this node's Node name: the name the decider stamps into
	// HostsAnnotation, and the Node the report is written on.
	NodeName string
	// BindAddr is the address every LoadBalancer listener binds. It must be
	// VALID; the WILDCARD (0.0.0.0) is the production choice and is accepted.
	// BindAddrs, when set, takes its place.
	BindAddr netip.Addr
	// BindAddrs is the address SET every LoadBalancer listener binds, each
	// port on every address of it (EffectiveBindAddrs). Empty means BindAddr
	// alone. It is the initial set: PrepareBindAddrs swaps it while the hoster
	// runs. Every address must be valid.
	BindAddrs []netip.Addr
	// ReservedPorts is the set of ports k3sm's OWN listeners occupy (the
	// NodePort range and the kubelet API port — pkg/ports.ReservedSet). bind
	// REFUSES them outright rather than racing a k3sm listener for the port (a
	// wildcard NodePort fails the bind by start order; a NodePort or kubelet API
	// listener on a specific address coexists with the wildcard LB listener and
	// splits the port's addresses between two owners). Admission rejects such a Service first (pkg/policy) — this
	// is the second, datapath-side enforcement point, because the VAP is
	// failurePolicy: Ignore and may be absent.
	//
	// REQUIRED, and NewHoster rejects nil. This is a guard whose other two layers
	// (the VAP's Ignore failure policy, its log-and-continue provisioning) already
	// fail OPEN, so letting the ZERO VALUE of this field disable the last one
	// would point all three the same way. A caller that genuinely wants no
	// reservations — only a test — passes an explicit empty map, which is a
	// visible opt-out rather than an omission.
	ReservedPorts map[int32]bool
	// Binder opens every listener. Nil means netbind.Direct (in-process);
	// injectable for tests. On Darwin a WILDCARD bind below 1024 does not
	// require root; it is the SPECIFIC-address bind that returns EACCES,
	// inverted from Linux. On a node with the root netd helper the node daemon
	// passes a binder that sends every bind of a port the operator listed
	// (--lb-privileged-ports), the wildcard included, to the helper, and binds
	// every other port in-process. One owner for both the wildcard and the
	// specific-address listener of a port is what lets a LAN access swap bind
	// the new set before it closes the old one: Darwin refuses an unprivileged
	// wildcard bind while a socket of another user holds a specific address on
	// the same port.
	Binder netbind.Binder
	// PrivilegedPorts are the ports below 1024 Binder brokers through the
	// root helper, which can bind 127.0.0.1 there. For those ports the hoster
	// keeps loopback in a specific address set instead of leaving it out
	// (EffectiveBindAddrs); a refused bind still leaves its Service unserved.
	PrivilegedPorts []uint16
	// IngressService names the canonical ingress LoadBalancer Service
	// (namespace, name; pass pkg/ingresshost's ServiceNamespace/ServiceName).
	// Every port it declares is reserved from tenant LoadBalancer Services on
	// THIS node, whether or not the ingress host runs here: the root network
	// helper refuses a tenant a node-address socket on such a port with LAN
	// access off, so serving it with LAN access on would make the node's
	// answer flip with the switch. It is matched by namespace and name, never
	// by a label a tenant could set. The zero value reserves nothing.
	IngressService types.NamespacedName
	// Logger is the structured log sink; nil means slog.Default.
	Logger *slog.Logger
}

// dialFunc is the backend-dial seam a forwarder splices through.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// errReservedPort is the sentinel bind returns for a port k3sm's own wildcard
// listeners own. It is distinguished from an ordinary bind failure so the
// operator-facing warning names the real cause.
var errReservedPort = errors.New("port is reserved by a k3sm listener")

// ErrPrivilegedPortNotWildcard is the sentinel for a LoadBalancer port below
// 1024 under a specific address set that could not be bound: macOS lets only
// root bind a specific address there, and the root netd helper refused it (a
// port not in the operator's --lb-privileged-ports list, or a helper too old
// to know the class) or there is no helper (EACCES). Such a Service is not
// served on this node while the set is specific; it is a refusal, not a
// failure of the set.
var ErrPrivilegedPortNotWildcard = errors.New("a LoadBalancer port below 1024 binds only on every interface")

// Hoster binds the LoadBalancer Services the decider stamped onto THIS node,
// splices them to their ClusterIP VIPs through the node's own L4 proxy, and
// reports the Services whose every TCP port it holds on its own Node
// (BoundAnnotation). It writes no Service and no status: the decider advertises
// a node only when the node is in the stamp AND reports the Service.
type Hoster struct {
	cfg HosterConfig
	log *slog.Logger
	dir netbind.Binder

	// Every field below is owned EXCLUSIVELY by the goroutine running Run (or,
	// before Run starts, the caller of Reset), so none needs a lock.

	// forwarders is keyed service "ns/name" -> port -> forwarder.
	forwarders map[string]map[int32]*forwarder
	// lastWarn backs the per-key warning throttle.
	lastWarn map[string]time.Time
	// lastRanges is each bound Service's last VALID source-range set, keyed
	// "ns/name". An edit whose ranges do not parse keeps enforcing this set (the
	// upstream controller keeps the LB serving while it retries).
	lastRanges map[string]Ranges
	// incarnation names this hoster's current report period: fresh at start and
	// again whenever this node is seen turning Ready, so the decider can tell a
	// report written by this process after a Ready transition from a stale one.
	incarnation string
	// reset is true once the start-of-life empty report has landed. Nothing is
	// bound before it: a report left by a previous process must never be read
	// as vouching for listeners this process has not opened.
	reset bool
	// reported is the last BoundAnnotation value written ("" before the first).
	reported string
	// ownReady is the last observed Ready state of this node's own Node (nil
	// before the first observation).
	ownReady *bool
	// newIncarnation mints an incarnation (tests replace it).
	newIncarnation func() string
	// dial is the backend-dial seam handed to every forwarder; nil means a
	// segment-clamped tcpseg.Dialer (tests inject a recording fake).
	dial dialFunc
	// now is the clock seam for the throttle (tests).
	now func() time.Time
	// addrs is the address set every listener binds (HosterConfig.BindAddrs,
	// swapped by PrepareBindAddrs).
	addrs []netip.Addr
	// entries is each fully bound Service's report entry, keyed "ns/name", as
	// the last reconcile computed it; a rebind withdraws from it.
	entries map[string]string
	// ingressPorts are the ports the canonical ingress Service
	// (HosterConfig.IngressService) declared at the last reconcile.
	ingressPorts map[int32]bool
	// draining holds the forwarders a rebind took off the air: their listeners
	// are closed and their accepted connections run to completion. closeAll
	// cancels them; reconcile reaps the ones with nothing left in flight.
	draining []*forwarder

	// rebind carries PrepareBindAddrs requests to the Run goroutine, which
	// alone touches the listener state; stopped is closed when Run returns.
	rebind  chan rebindRequest
	stopped chan struct{}
}

// NewHoster validates cfg and builds the Hoster. It starts nothing; call Reset
// (optional) and then Run.
func NewHoster(cfg HosterConfig) (*Hoster, error) {
	if cfg.Client == nil {
		return nil, errors.New("svclb: hoster config requires a client")
	}
	if cfg.NodeName == "" {
		return nil, errors.New("svclb: hoster config requires the node name")
	}
	// Only VALIDITY is required: the wildcard is the production bind address, so
	// an IsUnspecified rejection here would refuse the shipped configuration. A
	// zero Addr stays rejected — it would reach net.Listen as "invalid AddrPort".
	addrs := cfg.BindAddrs
	if len(addrs) == 0 {
		addrs = []netip.Addr{cfg.BindAddr}
	}
	for _, a := range addrs {
		if !a.IsValid() {
			return nil, fmt.Errorf("svclb: hoster config requires a valid bind address, got %q", a)
		}
	}
	// Fail CLOSED on the zero value of a guard: a nil set would silently disable
	// the reserved-port refusal, joining the VAP's Ignore failure policy and its
	// log-and-continue provisioning in failing open. An empty (non-nil) map is the
	// explicit opt-out.
	if cfg.ReservedPorts == nil {
		return nil, errors.New("svclb: hoster config requires a ReservedPorts set (pass ports.ReservedSet(), or an explicit empty map to reserve nothing)")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	dir := cfg.Binder
	if dir == nil {
		dir = netbind.Direct{}
	}
	h := &Hoster{
		cfg:            cfg,
		log:            log,
		dir:            dir,
		forwarders:     make(map[string]map[int32]*forwarder),
		lastWarn:       make(map[string]time.Time),
		lastRanges:     make(map[string]Ranges),
		newIncarnation: randomIncarnation,
		now:            time.Now,
		addrs:          slices.Clone(addrs),
		entries:        make(map[string]string),
		rebind:         make(chan rebindRequest),
		stopped:        make(chan struct{}),
	}
	h.incarnation = h.newIncarnation()
	return h, nil
}

// randomIncarnation is a fresh 64-bit hex nonce.
func randomIncarnation() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return hex.EncodeToString(b[:])
}

// Reset writes this hoster's start-of-life report: a fresh incarnation and NO
// Services. It must land before anything is bound, so a report a previous
// process left on the Node never vouches for this process's listeners. Run
// retries it until it lands; calling it first, before the node starts
// publishing status, puts the reset ahead of the node's Ready on a restart.
// It must not be called concurrently with Run.
func (h *Hoster) Reset(ctx context.Context) error {
	value, _ := formatBound(h.incarnation, nil)
	if err := PatchBoundReport(ctx, h.cfg.Client, h.cfg.NodeName, value); err != nil {
		return err
	}
	h.reset = true
	h.reported = value
	h.log.Info("svclb: hoster reset its bound report", "node", h.cfg.NodeName, "incarnation", h.incarnation)
	return nil
}

// PatchBoundReport merge-patches BoundAnnotation on the named Node to value. It
// is the hoster's only write, made with the node's own identity on its own
// Node: no Service write grant is needed or used.
func PatchBoundReport(ctx context.Context, client kubernetes.Interface, node, value string) error {
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{BoundAnnotation: value}}})
	if err != nil {
		return fmt.Errorf("encode the bound report patch: %w", err)
	}
	if _, err := client.CoreV1().Nodes().Patch(ctx, node, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("patch %s on node %s: %w", BoundAnnotation, node, err)
	}
	return nil
}

// Run watches Services and this node's own Node and reconciles listeners and
// the bound report until ctx is cancelled, then drains every forwarder and
// withdraws the report (withdraw).
// Reconciles are event-driven and coalesced; the loop goroutine is the sole
// owner of the listener state.
func (h *Hoster) Run(ctx context.Context) error {
	defer close(h.stopped)
	h.log.Info("svclb: loadbalancer hoster starting", "node", h.cfg.NodeName, "bind", addrsString(h.addrs))
	svcFactory := informers.NewSharedInformerFactory(h.cfg.Client, hosterResync)
	svcInf := svcFactory.Core().V1().Services().Informer()
	// A single-object informer on this node's own Node (a field selector on its
	// name, which the Node authorizer lets a node watch).
	nodeFactory := informers.NewSharedInformerFactoryWithOptions(h.cfg.Client, hosterResync,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("metadata.name", h.cfg.NodeName).String()
		}))
	nodeInf := nodeFactory.Core().V1().Nodes().Informer()
	trigger := make(chan struct{}, 1)
	kick := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { kick() },
		UpdateFunc: func(_, _ any) { kick() },
		DeleteFunc: func(any) { kick() },
	}
	if _, err := svcInf.AddEventHandler(handler); err != nil {
		return fmt.Errorf("svclb: add service handler: %w", err)
	}
	if _, err := nodeInf.AddEventHandler(handler); err != nil {
		return fmt.Errorf("svclb: add node handler: %w", err)
	}
	svcFactory.Start(ctx.Done())
	nodeFactory.Start(ctx.Done())
	// The sync is waited for beside the rebind requests: a swap of the address
	// set that arrives before anything is bound only changes the set.
	synced := make(chan bool, 1)
	go func() { synced <- cache.WaitForCacheSync(ctx.Done(), svcInf.HasSynced, nodeInf.HasSynced) }()
	for waiting := true; waiting; {
		select {
		case ok := <-synced:
			if !ok {
				h.closeAll()
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("svclb: hoster informer cache sync failed")
			}
			waiting = false
		case req := <-h.rebind:
			h.handleRebind(ctx, req)
		}
	}
	ticker := time.NewTicker(hosterResync)
	defer ticker.Stop()
	kick()
	for {
		select {
		case <-ctx.Done():
			h.closeAll()
			h.withdraw(ctx)
			return nil
		case <-trigger:
		case <-ticker.C:
		case req := <-h.rebind:
			h.handleRebind(ctx, req)
		}
		h.step(ctx, servicesFromStore(svcInf.GetStore()), ownNodeFromStore(nodeInf.GetStore(), h.cfg.NodeName))
	}
}

// ownNodeFromStore returns this node's Node from a single-object store, or nil.
func ownNodeFromStore(store cache.Store, name string) *corev1.Node {
	obj, ok, err := store.GetByKey(name)
	if err != nil || !ok {
		return nil
	}
	n, _ := obj.(*corev1.Node)
	return n
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

// step is one hoster pass: rotate the incarnation if this node just turned
// Ready, land the start-of-life reset if it has not landed yet, then reconcile.
func (h *Hoster) step(ctx context.Context, svcs []*corev1.Service, own *corev1.Node) {
	h.observeOwnReady(own)
	if !h.reset {
		if err := h.Reset(ctx); err != nil {
			// The Node may not be registered yet on a first boot: that is the
			// expected NotFound, retried on the next pass, and nothing is bound
			// until it lands.
			if apierrors.IsNotFound(err) {
				h.log.Debug("svclb: own node not registered yet; bound report reset deferred", "node", h.cfg.NodeName)
			} else {
				h.throttledWarn("\x00reset", "svclb: could not reset this node's bound report; binding nothing until it lands", "node", h.cfg.NodeName, "err", err)
			}
			return
		}
	}
	h.reconcile(ctx, svcs)
}

// observeOwnReady rotates the incarnation when this node's Ready condition goes
// from not-True to True. The decider distrusts the incarnation a node held
// before such a transition, so a live hoster re-vouches for its listeners with
// a new one; a stale report left by a dead process cannot.
func (h *Hoster) observeOwnReady(own *corev1.Node) {
	if own == nil {
		return
	}
	ready := nodeReady(own)
	if h.ownReady != nil && !*h.ownReady && ready {
		h.incarnation = h.newIncarnation()
		h.reported = "" // force the next report write under the new incarnation
		h.log.Info("svclb: node turned Ready; bound report re-issued under a new incarnation", "node", h.cfg.NodeName, "incarnation", h.incarnation)
	}
	h.ownReady = &ready
}

// Claims reports whether svclb owns svc — the ONE ownership rule, so the
// register row, the reconcile filter, the retraction and any dependent item
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

// reconcile drives the listener set to match the Services stamped onto this
// node: forwarders for removed, retyped, unstamped Services (or changed VIPs or
// ports) are torn down, missing listeners are bound, and the bound report is
// rewritten if the set of fully bound Services changed.
func (h *Hoster) reconcile(ctx context.Context, svcs []*corev1.Service) {
	h.ingressPorts = h.ingressServicePorts(svcs)
	desired := make(map[string]*corev1.Service)
	for _, s := range svcs {
		if !Claims(s) {
			continue
		}
		// An absent stamp (an older server, or a decider that has not decided
		// yet) binds nothing; only a stamp naming this node binds.
		if hosts, present := parseHosts(s); !present || !hosts[h.cfg.NodeName] {
			continue
		}
		desired[s.Namespace+"/"+s.Name] = s
	}

	// Tear down forwarders that no longer match a desired (service, port, VIP).
	for key, ports := range h.forwarders {
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
			if dst, ok := want[port]; !ok || dst != f.dst || h.ingressPorts[port] {
				f.stop()
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(h.forwarders, key)
		}
	}
	for key := range h.lastRanges {
		if len(h.forwarders[key]) == 0 {
			delete(h.lastRanges, key)
		}
	}

	h.reapDraining()
	clear(h.entries)
	var entries []string
	for key, svc := range desired {
		if h.reconcileService(ctx, key, svc) {
			e := reportEntry(svc)
			h.entries[key] = e
			entries = append(entries, e)
		}
	}
	h.report(ctx, entries)
}

// ingressServicePorts returns the ports the canonical ingress Service in svcs
// declares, or nil when it is absent or not configured.
func (h *Hoster) ingressServicePorts(svcs []*corev1.Service) map[int32]bool {
	id := h.cfg.IngressService
	if id.Namespace == "" || id.Name == "" {
		return nil
	}
	for _, s := range svcs {
		if s == nil || s.Namespace != id.Namespace || s.Name != id.Name {
			continue
		}
		out := make(map[int32]bool, len(s.Spec.Ports))
		for _, p := range s.Spec.Ports {
			out[p.Port] = true
		}
		return out
	}
	return nil
}

// reconcileService binds the missing TCP listeners for one stamped
// LoadBalancer Service and reports whether EVERY TCP port is bound — the only
// state in which this node may be advertised for it. A conflict leaves it
// unreported with a throttled Warn; the decider then keeps this node out of the
// status and records an Event naming it.
func (h *Hoster) reconcileService(ctx context.Context, key string, svc *corev1.Service) bool {
	vip, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		h.throttledWarn(key+"\x00vip", "svclb: loadbalancer service has no dialable clusterIP; no listeners bound",
			"service", key, "clusterIP", svc.Spec.ClusterIP)
		return false
	}
	// Source ranges are resolved on EVERY reconcile and pushed into every bound
	// forwarder, so a live edit applies to the next accept without reopening a
	// listener. A set that does not parse FAILS CLOSED on first provisioning (no
	// listener, not reported); on an edit to an already-bound Service the last
	// valid set stays in force and the listeners keep serving.
	ranges, rerr := SourceRanges(svc)
	if rerr != nil {
		h.logRangesInvalid(svc, key, rerr)
		if len(h.forwarders[key]) == 0 {
			return false
		}
		ranges = h.lastRanges[key]
	} else {
		h.lastRanges[key] = ranges
	}
	tcpPorts, bound := 0, 0
	for _, p := range svc.Spec.Ports {
		if !isTCP(p) {
			// UDP (or SCTP) LoadBalancer is DEFERRED: the userspace splice is
			// TCP-only today. Skipped loudly; does not gate the TCP ports' report.
			h.throttledWarn(fmt.Sprintf("%s\x00proto:%d", key, p.Port),
				"svclb: non-TCP loadbalancer port skipped (UDP LB deferred)",
				"service", key, "port", p.Port, "protocol", string(p.Protocol))
			continue
		}
		tcpPorts++
		if f := h.forwarders[key][p.Port]; f != nil {
			f.setRanges(ranges)
			bound++
			continue
		}
		f, err := h.bind(ctx, p.Port, netip.AddrPortFrom(vip, uint16(p.Port)), ranges)
		if err != nil {
			if errors.Is(err, ErrPrivilegedPortNotWildcard) {
				h.throttledWarn(fmt.Sprintf("%s\x00privileged:%d", key, p.Port),
					"svclb: loadbalancer port below 1024 is not served on this node: with LAN access off macOS lets only root bind this node's address below 1024, and the root network helper serves only a port listed in --lb-privileged-ports (80 and 443 by default) that the ingress host does not own, once a LoadBalancer Service declaring it is in the helper's view (retried on every reconcile). List the port, use a port of 1024 or above, or turn LAN access on",
					"service", key, "port", p.Port, "bind", addrsString(h.addrs))
				continue
			}
			if errors.Is(err, errReservedPort) {
				h.throttledWarn(fmt.Sprintf("%s\x00reserved:%d", key, p.Port),
					"svclb: loadbalancer port is RESERVED by a k3sm listener (the NodePort range, the kubelet API port, or a port the ingress host's kube-system/k3sm-ingress Service declares); no listener bound, this node is not advertised — pick a different spec.ports[].port",
					"service", key, "port", p.Port, "bind", addrsString(h.addrs))
				continue
			}
			h.throttledWarn(fmt.Sprintf("%s\x00bind:%d", key, p.Port),
				"svclb: listener bind failed; this node is not advertised for the service. Likely causes: another local process OR POD already listening on this wildcard port (darwin has no network namespaces, so pods share the node's port space); a second LoadBalancer Service declaring the same port; or a k3sm-reserved port",
				"service", key, "addr", addrsString(h.addrs), "port", p.Port,
				"diagnose", fmt.Sprintf("lsof -nP -iTCP:%d -sTCP:LISTEN", p.Port), "err", err)
			continue
		}
		if h.forwarders[key] == nil {
			h.forwarders[key] = make(map[int32]*forwarder)
		}
		h.forwarders[key][p.Port] = f
		h.log.Info("svclb: loadbalancer listener bound",
			"service", key, "addr", addrsString(f.set.Addrs()), "port", p.Port, "vip", f.dst.String())
		bound++
	}
	return tcpPorts > 0 && bound == tcpPorts
}

// report rewrites this node's bound report when the set changed. A failed write
// is retried on the next pass (the hoster resyncs on a timer).
func (h *Hoster) report(ctx context.Context, entries []string) {
	value, truncated := formatBound(h.incarnation, entries)
	if truncated {
		h.throttledWarn("\x00truncated", "svclb: bound report exceeds the annotation cap; the services past the cap are not advertised on this node",
			"node", h.cfg.NodeName, "services", len(entries), "cap_bytes", maxBoundBytes)
	}
	if value == h.reported {
		return
	}
	if err := PatchBoundReport(ctx, h.cfg.Client, h.cfg.NodeName, value); err != nil {
		h.throttledWarn("\x00report", "svclb: could not write this node's bound report; retrying", "node", h.cfg.NodeName, "err", err)
		return
	}
	h.reported = value
	h.log.Info("svclb: bound report updated", "node", h.cfg.NodeName, "incarnation", h.incarnation, "services", len(entries))
}

// bind opens one listener on every address of the set through the configured
// binder and starts its forwarder. Which process makes a bind is the binder's
// concern (HosterConfig.Binder): with the netd helper present, every bind of a
// listed port goes to it; every other bind is in-process.
//
// It REFUSES a reserved port before touching the binder: against a wildcard
// NodePort listener the winner would be decided by start order, and against
// the kubelet API (bound on the node address) or a NodePort bound on a
// configured address set the wildcard LB listener would coexist and answer
// every other address on the same port. A port keeps one owner on a node.
func (h *Hoster) bind(ctx context.Context, port int32, dst netip.AddrPort, ranges Ranges) (*forwarder, error) {
	if h.cfg.ReservedPorts[port] || h.ingressPorts[port] {
		return nil, fmt.Errorf("svclb: refusing port %d: %w", port, errReservedPort)
	}
	set, err := listenAddrSet(ctx, h.dir.Listen, h.addrs, uint16(port), slices.Contains(h.cfg.PrivilegedPorts, uint16(port)))
	if err != nil {
		return nil, h.classifyBindErr(port, err)
	}
	// Clamp every accepted connection's TCP segment size: a local pod reaches a
	// LoadBalancer address over lo0, and that connection must not carry
	// lo0-sized segments onto the mesh if its route moves.
	ln := tcpseg.WrapListener(set)
	fctx, cancel := context.WithCancel(ctx)
	f := &forwarder{ln: ln, set: set, dst: dst, cancel: cancel, done: make(chan struct{}), log: h.log, dial: h.dial}
	f.setRanges(ranges)
	go f.run(fctx)
	return f, nil
}

// logRangesInvalid reports a source-range parse failure with a throttled Warn.
// The Warning Event is the decider's (it holds the server's client; a node
// identity records no Service Events).
func (h *Hoster) logRangesInvalid(svc *corev1.Service, key string, err error) {
	action := "no listener opened; this node is not advertised"
	if len(h.forwarders[key]) > 0 {
		action = "listeners keep serving with the last valid source ranges"
	}
	h.throttledWarn(key+"\x00ranges", "svclb: loadbalancer source ranges invalid; "+action,
		"service", key, "err", err)
	h.log.Debug("svclb: invalid source ranges, raw values", append([]any{"service", key}, SourceRangesLogArgs(svc)...)...)
}

// closeAll drains every forwarder, the draining ones included (shutdown).
func (h *Hoster) closeAll() {
	for key, ports := range h.forwarders {
		for _, f := range ports {
			f.stop()
		}
		delete(h.forwarders, key)
	}
	for _, f := range h.draining {
		f.stop()
	}
	h.draining = nil
}

// withdraw is the clean-shutdown half of the report: once every listener is
// closed it writes an empty report under the current incarnation, so a stopped
// or restarting node is not advertised for the node-monitor grace period that
// would otherwise pass before it turns NotReady. It is best effort on a fresh
// context bounded by withdrawTimeout (ctx is already cancelled); a write that
// fails leaves the old report, which the decider then drops when the node turns
// NotReady, and a restarted hoster resets it anyway.
func (h *Hoster) withdraw(ctx context.Context) {
	value, _ := formatBound(h.incarnation, nil)
	if value == h.reported {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), withdrawTimeout)
	defer cancel()
	if err := PatchBoundReport(wctx, h.cfg.Client, h.cfg.NodeName, value); err != nil {
		h.log.Warn("svclb: could not withdraw this node's bound report on shutdown; it is dropped when the node turns NotReady", "node", h.cfg.NodeName, "err", err)
		return
	}
	h.reported = value
	h.log.Info("svclb: hoster withdrew its bound report on shutdown", "node", h.cfg.NodeName)
}

// throttledWarn logs msg at Warn at most once per warnInterval per key.
func (h *Hoster) throttledWarn(key, msg string, args ...any) {
	now := h.now()
	if last, ok := h.lastWarn[key]; ok && now.Sub(last) < warnInterval {
		return
	}
	h.lastWarn[key] = now
	h.log.Warn(msg, args...)
}

// Retractable reports whether an existing status.loadBalancer.ingress entry ip
// must be dropped when the INGRESS HOST cannot honestly advertise it. svclb no
// longer calls it: its decider replaces the whole slice on every write, so a
// previous life's address cannot be stranded there. The ingress host, still a
// single server-process frontend, keeps this rule.
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
//     (a re-enrolled node goes 100.64.0.0/24 → 100.64.2.0/24) — which the
//     current /24 does not contain, and which filtering on the advertise value
//     alone strands forever.
//
// # What this does NOT guarantee
//
// It is NOT "only k3sm's own entries are touched". The third arm is a whole-range
// test over 100.64.0.0/10, which is public RFC-6598 CGNAT space that other tools
// allocate from — Tailscale most commonly, and k3sm's own mesh IPs live there
// too. Any address in that range appearing in a status the ingress host owns
// WILL be dropped, whoever wrote it.
//
// That widening is sound ONLY while the ingress host is the single
// server-process frontend for the Services it owns. When multi-node ingress
// arrives, scope this arm to the writing node's own /24 plus an explicit record
// of the /24s it previously held, or move it to a replace-the-slice writer as
// svclb's decider did.
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
	ln net.Listener
	// set is the address-set listener under ln, which a rebind swaps.
	set    *AddrSetListener
	dst    netip.AddrPort
	cancel context.CancelFunc
	done   chan struct{}
	log    *slog.Logger
	// dial is the backend-dial seam; nil means a segment-clamped tcpseg.Dialer.
	dial dialFunc
	// ranges is the client source-range set enforced at accept. It is WRITTEN by
	// the controller's reconcile goroutine (bind, then every reconcile) and READ
	// by this forwarder's accept goroutine, so it is an atomic pointer: an edit
	// swaps the whole set and the next accept sees it, with no lock on the
	// accept path. A nil pointer or empty set allows every peer.
	ranges atomic.Pointer[Ranges]
	// retired is set before a rebind closes the listener under a live
	// forwarder, so the accept loop ends quietly; active counts its splices in
	// flight, so a drained forwarder can be reaped.
	retired atomic.Bool
	active  atomic.Int64
}

// setRanges installs r as the enforced source-range set.
func (f *forwarder) setRanges(r Ranges) {
	f.ranges.Store(&r)
}

// allows applies the current source-range set to conn's peer.
func (f *forwarder) allows(conn net.Conn) bool {
	r := f.ranges.Load()
	return r == nil || r.AllowsConn(conn)
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
			if ctx.Err() == nil && !f.retired.Load() {
				f.log.Warn("svclb: accept failed; listener stopped", "addr", f.ln.Addr().String(), "err", err)
			}
			return
		}
		// Source ranges are checked BEFORE splice, because splice dials the
		// backend first: a denied peer is closed and the backend never sees a
		// connection. This is an accept-time close, not a firewall; the
		// handshake has already completed.
		if !f.allows(conn) {
			f.log.Debug("svclb: connection denied by loadBalancerSourceRanges",
				"addr", f.ln.Addr().String(), "peer", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		f.active.Add(1)
		go func() {
			defer f.active.Add(-1)
			f.splice(ctx, conn)
		}()
	}
}

// splice forwards src <-> the ClusterIP VIP: a plain two-way io.Copy with TCP
// half-close propagation, torn down when either side finishes or ctx cancels.
func (f *forwarder) splice(ctx context.Context, src net.Conn) {
	defer src.Close()
	dial := f.dial
	if dial == nil {
		// The VIP is an lo0 alias: the clamp keeps this connection's segment
		// size safe for the mesh should the alias's route move.
		var d tcpseg.Dialer
		dial = d.DialContext
	}
	dst, err := dial(ctx, "tcp", f.dst.String())
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
		_, _ = copyPooled(dst, src)
		closeWrite(dst)
	}()
	go func() {
		defer wg.Done()
		_, _ = copyPooled(src, dst)
		closeWrite(src)
	}()
	wg.Wait()
}

// spliceBufSize is the per-direction copy buffer, matching the 32 KiB io.Copy
// would have allocated. Sized to be a straight substitute, not a tuning knob.
const spliceBufSize = 32 * 1024

// spliceBufPool holds the splice copy buffers. A pool is the right shape here
// and not a reflex: the buffer is fixed-size, its lifetime is exactly one
// copyPooled call with no aliasing or escape afterwards, and the live count
// equals the number of concurrently spliced connections — which is what is
// already resident today. A per-forwarder buffer is NOT an option, since one
// forwarder's connections are concurrent with each other.
//
// One behaviour this does change: peak footprint is unchanged (both designs
// need 2 x concurrency x spliceBufSize live at peak), but RELEASE is one GC
// cycle slower — sync.Pool's victim cache holds the high-water mark through
// the first GC and frees it on the second. Measured at 2,000 concurrent
// buffers: 58.7 MiB still resident after one GC, 4.1 MiB after two. The
// window is also stretched in wall-clock terms because lowering the
// allocation rate lengthens GC cycles. Bounded and modest, but real: after a
// connection storm the memory comes back one cycle later than it used to.
var spliceBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, spliceBufSize)
		return &b
	},
}

// onlyReader and onlyWriter deliberately expose ONLY Read and ONLY Write,
// hiding whatever else the underlying conn implements.
//
// This is load-bearing, and subtle enough to be worth stating: io.copyBuffer
// tests src.(io.WriterTo) and then dst.(io.ReaderFrom) BEFORE it ever looks at
// the buffer it was handed. A *net.TCPConn satisfies both, so a plain
// io.CopyBuffer(dst, src, buf) between two TCP conns silently DISCARDS buf and
// allocates internally anyway — the naive form of this optimisation is a no-op.
// Shadowing both interfaces is what forces copyBuffer down to the branch that
// uses the supplied buffer.
//
// Nothing is lost by hiding them on this platform: both stdlib zero-copy paths
// are unavailable on darwin. net/splice_stub.go is //go:build !linux and
// reports handled=false, and the sendfile path never engages because
// net.sendFile bails at its `r.(syscall.Conn)` assertion — the stdlib's OWN
// struct{io.Reader} wrapper (inside genericReadFrom) has already hidden that
// interface by the time it is consulted, so poll.SendFile is never reached.
//
// On Linux, hiding these WOULD forfeit splice(2). That costs nothing today
// only because the k3sm binary cannot target Linux: darwin-net's mesh package
// pulls golang.org/x/net/route, which is BSD-only. Note the limit of that
// guarantee — `GOOS=linux go build ./pkg/svclb/` succeeds, so THIS package is
// Linux-portable and the protection is a transitive dependency in another
// repository, not a constraint on this file. A future Linux path in
// darwin-net/pkg/mesh would silently forfeit splice(2) here with no build
// error and no test failure. If k3sm ever targets Linux, gate copyPooled on
// GOOS rather than deleting this comment.
type onlyReader struct{ io.Reader }
type onlyWriter struct{ io.Writer }

// copyPooled is io.Copy with a pooled buffer that is actually used.
//
// Each io.Copy between two *net.TCPConn allocated a fresh 32 KiB buffer, so a
// spliced connection cost ~64 KiB of heap in copy scratch alone regardless of
// how few bytes it carried — a per-connection constant, paid on every accept.
func copyPooled(dst io.Writer, src io.Reader) (int64, error) {
	bp := spliceBufPool.Get().(*[]byte)
	defer spliceBufPool.Put(bp)
	return io.CopyBuffer(onlyWriter{dst}, onlyReader{src}, *bp)
}

// closeWrite propagates a half-close where the conn supports it (TCP).
func closeWrite(c net.Conn) {
	if hc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
	}
}
