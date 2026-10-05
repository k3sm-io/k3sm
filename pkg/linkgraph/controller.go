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

package linkgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

const (
	// leaseNamespace holds the node heartbeat Leases.
	leaseNamespace = "kube-node-lease"
	// LeaseGrace is how long past its last renewal a node Lease still counts as
	// fresh when it names no duration of its own: the kube-controller-manager's
	// default node-monitor grace period.
	LeaseGrace = 40 * time.Second
	// resyncPeriod re-runs the resolver with no event, because a Lease going stale
	// is the passage of time, not a write anyone observes.
	resyncPeriod = 10 * time.Second
)

// Transition is one port whose resolved state changed in a pass.
type Transition struct {
	Node  string
	Iface string
	Peer  string
	From  netv1alpha1.DirectLinkState
	To    netv1alpha1.DirectLinkState
}

// Pass is what one resolver pass must write: the objects whose status changed
// (with the new status in place), the display label value per node whose up count
// changed from labels, and the state transitions to record.
type Pass struct {
	Status      []netv1alpha1.DirectLink
	Labels      map[string]string
	Transitions []Transition
}

// Plan computes one pass from the cached objects, Lease freshness and the nodes'
// current direct-links label values (labels[node]; absent = no label). It is
// pure, so the controller's decisions are table-tested over fake objects.
func Plan(links []netv1alpha1.DirectLink, fresh func(string) bool, labels map[string]string, now metav1.Time) Pass {
	resolved := Resolve(links, fresh, now)
	p := Pass{Labels: map[string]string{}}
	for _, l := range links {
		node := nodeOf(l)
		st := resolved[node]
		prev := map[string]netv1alpha1.DirectLinkState{}
		for _, ps := range l.Status.Ports {
			prev[ps.Iface] = ps.State
		}
		for _, ps := range st.Ports {
			if was, ok := prev[ps.Iface]; !ok || was != ps.State {
				p.Transitions = append(p.Transitions, Transition{Node: node, Iface: ps.Iface, Peer: ps.PeerNodeName, From: prev[ps.Iface], To: ps.State})
			}
		}
		if !StatusEqual(l.Status, st) {
			obj := *l.DeepCopy()
			obj.Status = st
			p.Status = append(p.Status, obj)
		}
		want := strconv.Itoa(UpCount(st))
		if cur, ok := labels[node]; !ok || cur != want {
			p.Labels[node] = want
		}
	}
	return p
}

// LeaseFresh reports whether a Lease was renewed recently enough at now: within
// its own duration when it names one (and at least LeaseGrace), else LeaseGrace.
func LeaseFresh(l *coordinationv1.Lease, now time.Time) bool {
	if l == nil || l.Spec.RenewTime == nil {
		return false
	}
	grace := LeaseGrace
	if l.Spec.LeaseDurationSeconds != nil {
		if d := time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second; d > grace {
			grace = d
		}
	}
	return now.Sub(l.Spec.RenewTime.Time) <= grace
}

// Controller runs the resolver on the server: an informer over DirectLinks and
// one over node Leases, a pass on every change and every resyncPeriod, status
// written through the status subresource, the advisory label set on each Node, and
// one Node Event plus one Warn line per port transition.
type Controller struct {
	Store  Store
	Kube   kubernetes.Interface
	Now    func() time.Time
	Logger *slog.Logger
}

// NewController builds the controller over a REST config.
func NewController(cfg *rest.Config, kube kubernetes.Interface, log *slog.Logger) (*Controller, error) {
	client, err := RESTClient(cfg)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Controller{Store: Store{Client: client}, Kube: kube, Now: time.Now, Logger: log}, nil
}

// Run blocks until ctx ends. It starts after the apiserver serves (the caller's
// ordering) and its informers stop with ctx.
func (c *Controller) Run(ctx context.Context) error {
	kick := make(chan struct{}, 1)
	trigger := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { trigger() },
		UpdateFunc: func(any, any) { trigger() },
		DeleteFunc: func(any) { trigger() },
	}
	lw := cache.NewListWatchFromClient(c.Store.Client, Resource, metav1.NamespaceAll, fields.Everything())
	links := cache.NewSharedIndexInformer(lw, &netv1alpha1.DirectLink{}, 0, cache.Indexers{})
	if _, err := links.AddEventHandler(handler); err != nil {
		return fmt.Errorf("direct link handler: %w", err)
	}
	factory := informers.NewSharedInformerFactoryWithOptions(c.Kube, 0, informers.WithNamespace(leaseNamespace))
	leases := factory.Coordination().V1().Leases()
	if _, err := leases.Informer().AddEventHandler(handler); err != nil {
		return fmt.Errorf("lease handler: %w", err)
	}
	go links.Run(ctx.Done())
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), links.HasSynced, leases.Informer().HasSynced) {
		return fmt.Errorf("direct link resolver: informer cache sync failed")
	}
	c.Logger.Info("direct link resolver started")
	t := time.NewTicker(resyncPeriod)
	defer t.Stop()
	trigger()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			trigger()
		case <-kick:
			c.pass(ctx, links.GetStore(), leases.Lister().Leases(leaseNamespace))
		}
	}
}

type leaseGetter interface {
	Get(name string) (*coordinationv1.Lease, error)
}

func (c *Controller) pass(ctx context.Context, store cache.Store, leases leaseGetter) {
	var links []netv1alpha1.DirectLink
	for _, obj := range store.List() {
		if dl, ok := obj.(*netv1alpha1.DirectLink); ok {
			links = append(links, *dl)
		}
	}
	now := c.Now()
	fresh := func(node string) bool {
		l, err := leases.Get(node)
		return err == nil && LeaseFresh(l, now)
	}
	labels := map[string]string{}
	for _, l := range links {
		node := nodeOf(l)
		if n, err := c.Kube.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{}); err == nil {
			if v, ok := n.Labels[netv1alpha1.LabelDirectLinks]; ok {
				labels[node] = v
			}
		}
	}
	p := Plan(links, fresh, labels, metav1.NewTime(now))
	for i := range p.Status {
		if err := c.Store.UpdateStatus(ctx, &p.Status[i]); err != nil {
			c.Logger.Warn("direct link resolver: status not written; retrying on the next pass", "node", p.Status[i].Name, "err", err)
		}
	}
	for _, node := range sortedNodes(p.Labels) {
		c.setLabel(ctx, node, p.Labels[node])
	}
	for _, tr := range p.Transitions {
		c.record(ctx, tr)
	}
}

// setLabel merge-patches the advisory up-count label onto a Node.
func (c *Controller) setLabel(ctx context.Context, node, value string) {
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]string{netv1alpha1.LabelDirectLinks: value}}})
	if _, err := c.Kube.CoreV1().Nodes().Patch(ctx, node, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		c.Logger.Debug("direct link resolver: node label not set", "node", node, "err", err)
	}
}

// record writes one transition as a Warn line and a Node Event. The cable is
// plaintext when up, and the Event says so: that state must be visible wherever
// the link is.
func (c *Controller) record(ctx context.Context, tr Transition) {
	reason, kind := "DirectLinkDown", corev1.EventTypeWarning
	msg := fmt.Sprintf("direct link on %s to %s is %s (was %s); pod traffic to that peer rides the wireguard tunnel", tr.Iface, peerName(tr.Peer), tr.To, stateName(tr.From))
	switch tr.To {
	case netv1alpha1.DirectLinkStateUp:
		reason, kind = "DirectLinkUp", corev1.EventTypeNormal
		msg = fmt.Sprintf("direct link on %s to %s is up (was %s); pod traffic to that peer now crosses the cable in PLAINTEXT", tr.Iface, peerName(tr.Peer), stateName(tr.From))
	case netv1alpha1.DirectLinkStatePeerUnknown:
		reason, kind = "DirectLinkPeerUnknown", corev1.EventTypeNormal
		msg = fmt.Sprintf("a Mac that is not in this cluster is cabled to %s (`sudo k3sm pair --for 10m` admits it)", tr.Iface)
	}
	c.Logger.Warn("direct link transition", "node", tr.Node, "iface", tr.Iface, "peer", tr.Peer, "from", stateName(tr.From), "to", string(tr.To))
	if c.Kube == nil {
		return
	}
	now := metav1.NewTime(c.Now())
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: fmt.Sprintf("%s.%x", tr.Node, now.UnixNano()), Namespace: metav1.NamespaceDefault},
		InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: tr.Node, APIVersion: "v1"},
		Reason:         reason,
		Message:        msg,
		Type:           kind,
		Source:         corev1.EventSource{Component: "k3sm-direct-link-resolver"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	if _, err := c.Kube.CoreV1().Events(metav1.NamespaceDefault).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		c.Logger.Debug("direct link resolver: event not recorded", "node", tr.Node, "err", err)
	}
}

func stateName(s netv1alpha1.DirectLinkState) string {
	if s == "" {
		return "new"
	}
	return string(s)
}

func peerName(p string) string {
	if p == "" {
		return "an unknown peer"
	}
	return p
}
