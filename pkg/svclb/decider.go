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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// The Warning Event reasons the decider records on Services.
const (
	// EventReasonNoEligibleNodes: the Service is claimed but no Node is eligible
	// to host it (an unknown pool, allow-list mode with no enabled node, or no
	// node with a server-held address). It stays pending.
	EventReasonNoEligibleNodes = "NoEligibleNodes"
	// EventReasonHostNotBound: a Ready node in the Service's stamp has not
	// reported every TCP port bound (a port conflict with a pod or another
	// Service, a reserved port, or invalid source ranges). The message names
	// the node; that node is left out of the status.
	EventReasonHostNotBound = "HostNotBound"
)

// Decider defaults.
const (
	// DefaultHoldDown is how long a newly started decider defers status changes
	// for a Service until every stamped host reports it, so a server restart
	// does not retract every LoadBalancer in the cluster while the hosters
	// (its own included) re-bind. It also bounds how long a report distrusted
	// across a node's Ready transition stays distrusted.
	DefaultHoldDown = 30 * time.Second
	// DefaultResync is the decider's periodic reconcile: every pass recomputes
	// every claimed Service's status and writes it when it differs, so a write
	// lost between the stamp and the status is repaired on the next pass.
	DefaultResync = 30 * time.Second
)

// DeciderConfig configures the Decider, the server-side half of svclb.
type DeciderConfig struct {
	// Client is the server's admin client: it watches Nodes and Services and is
	// the only writer of HostsAnnotation and of LoadBalancer status.
	Client kubernetes.Interface
	// SelfNode and SelfAddr are the server's own node and the address the
	// server derived for it (server-held data: the server process IS that
	// node). SelfAddr may be the zero Addr, and then the server's node is
	// advertised only through its MeshPeer address, if any.
	SelfNode string
	SelfAddr netip.Addr
	// PeerAddresses returns each node's mesh address from its MeshPeer record
	// (written only through the server's guarded enroll path, never by the
	// node). Nil means no MeshPeers exist (a single-node server without a
	// mesh). A failing call keeps the last good set.
	PeerAddresses func(ctx context.Context) (map[string]netip.Addr, error)
	// HoldDown is DefaultHoldDown when zero.
	HoldDown time.Duration
	// Resync is DefaultResync when zero.
	Resync time.Duration
	// Recorder records Warning Events on Services. Nil means Run builds one on
	// Client (NewEventRecorder).
	Recorder record.EventRecorder
	// Logger is the structured log sink; nil means slog.Default.
	Logger *slog.Logger
}

// nodeObs is what the decider last observed of a node.
type nodeObs struct {
	ready bool
	// lastReadyInc is the report incarnation the node held the last time it
	// was observed Ready.
	lastReadyInc string
}

// distrust marks a node's report incarnation as not to be trusted after the
// node turned Ready while still carrying it.
type distrust struct {
	inc   string
	since time.Time
}

// Decider computes, for every claimed LoadBalancer Service, which nodes host it
// (selectHosts), stamps that set on the Service (HostsAnnotation), and writes
// the Service's whole status from the nodes that are in the stamp, Ready, and
// report the Service bound on their own Node (computeIngress). It runs in the
// server process; the nodes never write a Service.
type Decider struct {
	cfg      DeciderConfig
	log      *slog.Logger
	recorder record.EventRecorder
	now      func() time.Time

	// Every field below is owned EXCLUSIVELY by the goroutine running Run.

	startedAt time.Time
	// peers is the last good PeerAddresses result.
	peers map[string]netip.Addr
	// nodes and distrusted are the per-node report trust state.
	nodes      map[string]nodeObs
	distrusted map[string]distrust
	// disclaimed records foreign-class Services already retracted, one-shot per
	// process, so declining a Service never becomes a per-reconcile write that
	// fights the implementation that owns it.
	disclaimed map[string]bool
	// events dedupes Warning Events: key -> last message recorded.
	events map[string]string
	// unbound is when a Ready stamped host was first seen not reporting a
	// Service, keyed "ns/name\x00node".
	unbound map[string]time.Time
	// lastWarn backs the per-key warning throttle.
	lastWarn map[string]time.Time
}

// NewDecider validates cfg and builds the Decider. It starts nothing; call Run.
func NewDecider(cfg DeciderConfig) (*Decider, error) {
	if cfg.Client == nil {
		return nil, errors.New("svclb: decider config requires a client")
	}
	if cfg.HoldDown <= 0 {
		cfg.HoldDown = DefaultHoldDown
	}
	if cfg.Resync <= 0 {
		cfg.Resync = DefaultResync
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Decider{
		cfg:        cfg,
		log:        log,
		recorder:   cfg.Recorder,
		now:        time.Now,
		peers:      map[string]netip.Addr{},
		nodes:      map[string]nodeObs{},
		distrusted: map[string]distrust{},
		disclaimed: map[string]bool{},
		events:     map[string]string{},
		unbound:    map[string]time.Time{},
		lastWarn:   map[string]time.Time{},
	}, nil
}

// Run watches Nodes and Services and reconciles stamps and statuses until ctx
// is cancelled.
func (d *Decider) Run(ctx context.Context) error {
	d.startedAt = d.now()
	d.log.Info("svclb: loadbalancer decider starting", "self", d.cfg.SelfNode, "self_addr", addrString(d.cfg.SelfAddr),
		"hold_down", d.cfg.HoldDown.String(), "mesh_peers", d.cfg.PeerAddresses != nil)
	if d.recorder == nil {
		rec, stop := NewEventRecorder(d.cfg.Client, "k3sm-svclb")
		defer stop()
		d.recorder = rec
	}
	factory := informers.NewSharedInformerFactory(d.cfg.Client, d.cfg.Resync)
	svcInf := factory.Core().V1().Services().Informer()
	nodeInf := factory.Core().V1().Nodes().Informer()
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
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), svcInf.HasSynced, nodeInf.HasSynced) {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("svclb: decider informer cache sync failed")
	}
	// The hold-down ends with a pass of its own, so a deferred write does not
	// wait for the next resync.
	holdEnd := time.AfterFunc(d.cfg.HoldDown, kick)
	defer holdEnd.Stop()
	ticker := time.NewTicker(d.cfg.Resync)
	defer ticker.Stop()
	kick()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
		case <-ticker.C:
		}
		d.reconcile(ctx, nodesFromStore(nodeInf.GetStore()), servicesFromStore(svcInf.GetStore()))
	}
}

// nodesFromStore snapshots the informer cache's Nodes.
func nodesFromStore(store cache.Store) []*corev1.Node {
	items := store.List()
	nodes := make([]*corev1.Node, 0, len(items))
	for _, item := range items {
		if n, ok := item.(*corev1.Node); ok {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// addresses is the server-held address of every node: the MeshPeer set, with
// the server's own derived address for its own node.
func (d *Decider) addresses(ctx context.Context) map[string]netip.Addr {
	if d.cfg.PeerAddresses != nil {
		got, err := d.cfg.PeerAddresses(ctx)
		if err != nil {
			d.throttledWarn("\x00peers", "svclb: could not list MeshPeer addresses; keeping the last good set", "err", err)
		} else {
			d.peers = got
		}
	}
	out := maps.Clone(d.peers)
	if out == nil {
		out = map[string]netip.Addr{}
	}
	if d.cfg.SelfNode != "" && advertisable(d.cfg.SelfAddr) {
		out[d.cfg.SelfNode] = d.cfg.SelfAddr
	}
	return out
}

// trustedReports decodes every node's bound report and returns the ones the
// decider trusts. A report is distrusted when its node turned Ready while still
// carrying the incarnation it held in its previous Ready period: that report
// may predate a restart of the node's process. Trust returns as soon as the
// node writes a new incarnation (a restarted hoster resets at start; a live one
// re-issues on its own Ready transition), or after the hold-down bound.
func (d *Decider) trustedReports(nodes []*corev1.Node) map[string]boundReport {
	now := d.now()
	out := make(map[string]boundReport, len(nodes))
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		seen[n.Name] = true
		ready := nodeReady(n)
		raw, has := n.Annotations[BoundAnnotation]
		rep, ok := parseBound(raw)
		if has && !ok {
			// Only the length is logged: the value is node-written and unbounded.
			d.throttledWarn("\x00badreport\x00"+n.Name, "svclb: ignoring a malformed or oversized bound report; the node is treated as reporting nothing",
				"node", n.Name, "bytes", len(raw))
		}
		prev, had := d.nodes[n.Name]
		obs := nodeObs{ready: ready, lastReadyInc: prev.lastReadyInc}
		if had && !prev.ready && ready {
			d.distrusted[n.Name] = distrust{inc: prev.lastReadyInc, since: now}
			d.log.Info("svclb: node turned Ready; its bound report is ignored until it re-issues one",
				"node", n.Name, "incarnation", prev.lastReadyInc)
		}
		if ready {
			obs.lastReadyInc = rep.incarnation
		}
		d.nodes[n.Name] = obs
		if dt, has := d.distrusted[n.Name]; has {
			if rep.incarnation == dt.inc && now.Sub(dt.since) < d.cfg.HoldDown {
				continue
			}
			delete(d.distrusted, n.Name)
		}
		if ok {
			out[n.Name] = rep
		}
	}
	for name := range d.nodes {
		if !seen[name] {
			delete(d.nodes, name)
			delete(d.distrusted, name)
		}
	}
	return out
}

// holding reports whether the start-up hold-down is still in force.
func (d *Decider) holding() bool { return d.now().Sub(d.startedAt) < d.cfg.HoldDown }

// reconcile is one decider pass over the cache snapshot.
func (d *Decider) reconcile(ctx context.Context, nodes []*corev1.Node, svcs []*corev1.Service) {
	addrs := d.addresses(ctx)
	reports := d.trustedReports(nodes)
	live := make(map[string]bool, len(svcs))
	for _, svc := range svcs {
		key := svc.Namespace + "/" + svc.Name
		if !Claims(svc) {
			d.unclaim(ctx, key, svc, addrs)
			continue
		}
		live[key] = true
		d.decide(ctx, key, svc, nodes, addrs, reports)
	}
	for k := range d.events {
		if svcKey, _, _ := strings.Cut(k, "\x00"); !live[svcKey] {
			delete(d.events, k)
		}
	}
	for k := range d.unbound {
		if svcKey, _, _ := strings.Cut(k, "\x00"); !live[svcKey] {
			delete(d.unbound, k)
		}
	}
}

// decide stamps and settles one claimed Service.
func (d *Decider) decide(ctx context.Context, key string, svc *corev1.Service, nodes []*corev1.Node, addrs map[string]netip.Addr, reports map[string]boundReport) {
	hosts := selectHosts(nodes, svc, addrs)
	stamp := formatHosts(hosts)
	if cur, present := svc.Annotations[HostsAnnotation]; !present || cur != stamp {
		if err := d.patchStamp(ctx, svc, &stamp); err != nil {
			d.throttledWarn(key+"\x00stamp", "svclb: could not stamp the loadbalancer hosts; retrying", "service", key, "err", err)
			return
		}
		d.log.Info("svclb: loadbalancer hosts stamped", "service", key, "hosts", stamp, "previous", cur)
	}

	if len(hosts) == 0 {
		d.event(svc, key+"\x00noeligible", EventReasonNoEligibleNodes,
			"no node is eligible to host this LoadBalancer Service (check the svclb.k3sm.io/lbpool label against the node pools, and svclb.k3sm.io/enablelb=true allow-list mode); it stays pending")
	} else {
		delete(d.events, key+"\x00noeligible")
	}
	d.checkSourceRanges(svc, key)

	entry := reportEntry(svc)
	allReport := true
	var reporting []string
	for _, h := range hosts {
		if reports[h].entries[entry] {
			reporting = append(reporting, h)
			delete(d.unbound, key+"\x00"+h)
			delete(d.events, key+"\x00unbound\x00"+h)
			continue
		}
		allReport = false
		d.noteUnbound(svc, key, h, nodes)
	}

	want := computeIngress(nodes, svc, hosts, addrs, reports)
	if ingressEqual(svc.Status.LoadBalancer.Ingress, want) {
		return
	}
	if d.holding() && !allReport {
		d.log.Debug("svclb: status change deferred by the start-up hold-down", "service", key, "hosts", stamp, "reporting", strings.Join(reporting, ","))
		return
	}
	if err := d.patchStatus(ctx, svc, want); err != nil {
		d.throttledWarn(key+"\x00status", "svclb: could not write the loadbalancer status; retrying on the next pass", "service", key, "err", err)
		return
	}
	d.log.Info("svclb: loadbalancer status written", "service", key, "hosts", stamp,
		"reporting", strings.Join(reporting, ","), "ingress", ingressString(want), "previous", ingressString(svc.Status.LoadBalancer.Ingress))
}

// noteUnbound records an Event once a Ready stamped host has gone a hold-down
// without reporting the Service. A host that is not Ready is already out of the
// status for that reason and is not evented.
func (d *Decider) noteUnbound(svc *corev1.Service, key, host string, nodes []*corev1.Node) {
	uk := key + "\x00" + host
	var n *corev1.Node
	for _, c := range nodes {
		if c != nil && c.Name == host {
			n = c
			break
		}
	}
	if n == nil || !nodeReady(n) {
		delete(d.unbound, uk)
		return
	}
	first, ok := d.unbound[uk]
	if !ok {
		d.unbound[uk] = d.now()
		return
	}
	if d.now().Sub(first) < d.cfg.HoldDown {
		return
	}
	d.event(svc, key+"\x00unbound\x00"+host, EventReasonHostNotBound,
		fmt.Sprintf("node %s is selected to host this Service but has not bound every TCP port (a pod or another Service on the port, a reserved port, or invalid source ranges); it is left out of the status. Check the node's log and `lsof -nP -iTCP:<port> -sTCP:LISTEN` on it.", host))
}

// checkSourceRanges records EventReasonSourceRangesInvalid once per distinct
// parse error. The hosters enforce the rule (fail closed on first provisioning,
// keep the last valid set on an edit); the Event lives here because the decider
// holds the server's client.
func (d *Decider) checkSourceRanges(svc *corev1.Service, key string) {
	ek := key + "\x00ranges"
	if _, err := SourceRanges(svc); err != nil {
		d.event(svc, ek, EventReasonSourceRangesInvalid,
			fmt.Sprintf("loadBalancerSourceRanges invalid (hosts with no listener open none and stay out of the status; hosts already serving keep the last valid ranges): %v", err))
		return
	}
	delete(d.events, ek)
}

// unclaim cleans up after a Service svclb does not (or no longer) claims: the
// stamp is removed; a Service that left type LoadBalancer has its status
// cleared, as the apiserver itself does on a type change; and a foreign-class
// Service has svclb's own addresses retracted from its status, once per
// process. A Service carrying IgnoreLabel keeps its status: the ingress host
// owns it.
func (d *Decider) unclaim(ctx context.Context, key string, svc *corev1.Service, addrs map[string]netip.Addr) {
	_, stamped := svc.Annotations[HostsAnnotation]
	if stamped {
		if err := d.patchStamp(ctx, svc, nil); err != nil {
			d.throttledWarn(key+"\x00stamp", "svclb: could not remove the loadbalancer hosts stamp; retrying", "service", key, "err", err)
		} else {
			d.log.Info("svclb: loadbalancer hosts stamp removed from a service svclb no longer claims", "service", key)
		}
	}
	switch {
	case svc.Spec.Type != corev1.ServiceTypeLoadBalancer:
		if stamped && len(svc.Status.LoadBalancer.Ingress) > 0 {
			if err := d.patchStatus(ctx, svc, nil); err != nil {
				d.throttledWarn(key+"\x00status", "svclb: could not clear the loadbalancer status", "service", key, "err", err)
			}
		}
	case svc.Spec.LoadBalancerClass != nil:
		d.retractDisclaimed(ctx, key, svc, addrs)
	}
}

// retractDisclaimed removes svclb's own node addresses from a Service carrying a
// foreign loadBalancerClass, exactly once per Service per process. It exists for
// one reachable state: a Service an OLDER k3sm build claimed and advertised
// before it acquired a class. The apiserver cannot clean that up (it forbids
// changing the class in place), so without this the address would stay
// published with nothing listening. Only addresses svclb itself would write are
// touched; anything else is the other implementation's to manage.
func (d *Decider) retractDisclaimed(ctx context.Context, key string, svc *corev1.Service, addrs map[string]netip.Addr) {
	if d.disclaimed[key] {
		return
	}
	ours := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		ours[a.String()] = true
	}
	keep := make([]corev1.LoadBalancerIngress, 0, len(svc.Status.LoadBalancer.Ingress))
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		if !ours[lbi.IP] {
			keep = append(keep, lbi)
		}
	}
	d.disclaimed[key] = true
	if len(keep) == len(svc.Status.LoadBalancer.Ingress) {
		return
	}
	if err := d.patchStatus(ctx, svc, keep); err != nil {
		d.log.Warn("svclb: retract advertisement for disclaimed service", "service", key, "err", err)
		delete(d.disclaimed, key) // allow a retry on the next pass
		return
	}
	d.log.Info("svclb: retracted stale advertisement for a service this build does not claim",
		"service", key, "class", classOf(svc))
}

// patchStamp merge-patches HostsAnnotation to *value, or removes it when value
// is nil.
func (d *Decider) patchStamp(ctx context.Context, svc *corev1.Service, value *string) error {
	var v any
	if value != nil {
		v = *value
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{HostsAnnotation: v}}})
	if err != nil {
		return fmt.Errorf("encode the hosts patch: %w", err)
	}
	_, err = d.cfg.Client.CoreV1().Services(svc.Namespace).Patch(ctx, svc.Name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager})
	return err
}

// patchStatus REPLACES status.loadBalancer.ingress with ingress (a JSON merge
// patch replaces a list whole). An empty slice clears it: the pending state.
func (d *Decider) patchStatus(ctx context.Context, svc *corev1.Service, ingress []corev1.LoadBalancerIngress) error {
	var v any
	if len(ingress) > 0 {
		v = ingress
	}
	patch, err := json.Marshal(map[string]any{"status": map[string]any{"loadBalancer": map[string]any{"ingress": v}}})
	if err != nil {
		return fmt.Errorf("encode the status patch: %w", err)
	}
	_, err = d.cfg.Client.CoreV1().Services(svc.Namespace).Patch(ctx, svc.Name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}, "status")
	return err
}

// event records a Warning Event once per distinct message per key.
func (d *Decider) event(svc *corev1.Service, key, reason, msg string) {
	if d.events[key] == msg {
		return
	}
	d.events[key] = msg
	d.log.Warn("svclb: "+msg, "service", svc.Namespace+"/"+svc.Name, "reason", reason)
	if d.recorder != nil {
		d.recorder.Event(svc, corev1.EventTypeWarning, reason, msg)
	}
}

// throttledWarn logs msg at Warn at most once per warnInterval per key.
func (d *Decider) throttledWarn(key, msg string, args ...any) {
	now := d.now()
	if last, ok := d.lastWarn[key]; ok && now.Sub(last) < warnInterval {
		return
	}
	d.lastWarn[key] = now
	d.log.Warn(msg, args...)
}

// ingressString renders an ingress slice for logs.
func ingressString(in []corev1.LoadBalancerIngress) string {
	ips := make([]string, 0, len(in))
	for _, i := range in {
		ips = append(ips, i.IP)
	}
	return strings.Join(ips, ",")
}

// addrString renders an address for logs, naming the zero Addr.
func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return "<none>"
	}
	return a.String()
}
