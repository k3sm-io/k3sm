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

package vkadapter

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// The node controller's timing, set explicitly rather than inherited from
// Virtual Kubelet's zero-value defaults so the numbers the heartbeat depends on
// are written down in one place.
const (
	// nodePingInterval is how often the node controller pings the provider. It
	// is VK's default, kept.
	nodePingInterval = 10 * time.Second
	// nodePingTimeout bounds one ping. Without it VK waits for the provider's
	// Ping forever, and the very first ping gates node registration: a Ping
	// that never returned would leave the node unregistered with nothing logged.
	nodePingTimeout = 5 * time.Second
	// nodePingBudget is how long pingGuard waits for the provider's Ping before
	// answering for it. It is shorter than nodePingTimeout so the guard, not
	// VK's own deadline, decides the outcome of a slow ping.
	nodePingBudget = 2 * time.Second
	// nodeStatusUpdateInterval is how often the node controller re-posts the
	// node status while the Lease carries liveness. It is VK's default, kept, and
	// the cadence NodeStatusProvider publishes on.
	nodeStatusUpdateInterval = time.Minute
	// nodeStatusResyncInterval is how often the node checks whether its status
	// must be posted before the next nodeStatusUpdateInterval: after a failed
	// post, or when the apiserver's Ready condition is not the one the provider
	// reports. It is the kubelet's node-status update frequency, so a node whose
	// path comes back is posted within one check, as a kubelet is.
	nodeStatusResyncInterval = 10 * time.Second
)

// nodeTimings are the node controller intervals NewNode wires. Tests shorten
// them; production uses defaultNodeTimings.
type nodeTimings struct {
	statusInterval time.Duration
	resyncInterval time.Duration
}

var defaultNodeTimings = nodeTimings{
	statusInterval: nodeStatusUpdateInterval,
	resyncInterval: nodeStatusResyncInterval,
}

// Heartbeat is when this node's two liveness writes last landed at the
// apiserver. A zero time means that write has not succeeded since the node
// started.
type Heartbeat struct {
	// StatusPosted is the last successful node-status write (registration or a
	// status PATCH).
	StatusPosted time.Time
	// LeaseRenewed is the last successful Lease create or update.
	LeaseRenewed time.Time
}

// heartbeatRecorder holds the Heartbeat. mu guards hb and statusFailed.
type heartbeatRecorder struct {
	now func() time.Time

	mu sync.Mutex
	hb Heartbeat
	// statusFailed is set when a node-status post fails and cleared when one
	// lands: while it is set, the next post is due at the next resync check.
	statusFailed bool
}

func (r *heartbeatRecorder) statusPosted() {
	t := r.now()
	r.mu.Lock()
	r.hb.StatusPosted = t
	r.statusFailed = false
	r.mu.Unlock()
}

// statusPostFailed records that the node controller's last status post failed.
func (r *heartbeatRecorder) statusPostFailed() {
	r.mu.Lock()
	r.statusFailed = true
	r.mu.Unlock()
}

// statusRetryDue reports whether the last status post failed and none has
// landed since.
func (r *heartbeatRecorder) statusRetryDue() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusFailed
}

func (r *heartbeatRecorder) leaseRenewed() {
	t := r.now()
	r.mu.Lock()
	r.hb.LeaseRenewed = t
	r.mu.Unlock()
}

func (r *heartbeatRecorder) snapshot() Heartbeat {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hb
}

// recordingNodes is the NodeInterface the node controller writes through. It
// records every node-status write that succeeds; everything else passes through.
type recordingNodes struct {
	corev1client.NodeInterface
	rec *heartbeatRecorder
}

// Create records the registration, which carries the first status.
func (n recordingNodes) Create(ctx context.Context, node *corev1.Node, opts metav1.CreateOptions) (*corev1.Node, error) {
	out, err := n.NodeInterface.Create(ctx, node, opts)
	if err == nil {
		n.rec.statusPosted()
	}
	return out, err
}

// Patch records a successful PATCH of the status subresource, the write VK's
// status update makes.
func (n recordingNodes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*corev1.Node, error) {
	out, err := n.NodeInterface.Patch(ctx, name, pt, data, opts, subresources...)
	if err == nil && strings.Join(subresources, "/") == "status" {
		n.rec.statusPosted()
	}
	return out, err
}

// UpdateStatus records a successful status update.
func (n recordingNodes) UpdateStatus(ctx context.Context, node *corev1.Node, opts metav1.UpdateOptions) (*corev1.Node, error) {
	out, err := n.NodeInterface.UpdateStatus(ctx, node, opts)
	if err == nil {
		n.rec.statusPosted()
	}
	return out, err
}

// recordingLeases is the LeaseInterface the lease controller writes through.
type recordingLeases struct {
	coordinationv1client.LeaseInterface
	rec *heartbeatRecorder
}

// Create records the first Lease.
func (l recordingLeases) Create(ctx context.Context, lease *coordinationv1.Lease, opts metav1.CreateOptions) (*coordinationv1.Lease, error) {
	out, err := l.LeaseInterface.Create(ctx, lease, opts)
	if err == nil {
		l.rec.leaseRenewed()
	}
	return out, err
}

// Update records a renewal.
func (l recordingLeases) Update(ctx context.Context, lease *coordinationv1.Lease, opts metav1.UpdateOptions) (*coordinationv1.Lease, error) {
	out, err := l.LeaseInterface.Update(ctx, lease, opts)
	if err == nil {
		l.rec.leaseRenewed()
	}
	return out, err
}

// pingGuard answers the node controller's Ping for a NodeProvider so that a slow
// provider Ping cannot stop the heartbeat.
//
// In Virtual Kubelet a failed ping suppresses BOTH the node-status update and the
// Lease renewal, so a Ping that stalls (or merely outlasts nodePingTimeout)
// takes the node NotReady while everything else on it works. A kubelet has no
// such gate: it posts status and renews its Lease whatever the runtime is doing,
// and reports runtime health as the Ready condition. k3sm's providers do the
// same (NodeStatusProvider publishes runtime health as Ready, and its Ping only
// reports a cancelled context), so the guard keeps that contract true even for
// a provider whose Ping blocks:
//
//   - the provider's Ping runs with VK's context, at most one call at a time;
//   - an answer within nodePingBudget is returned as is, so a provider error
//     still suppresses the heartbeat exactly as VK intends;
//   - no answer within the budget is reported as success with a Warn line, so
//     the status post and the Lease renewal go ahead. A later ping joins the
//     call still in flight rather than stacking another one on it.
type pingGuard struct {
	NodeProvider
	budget time.Duration
	log    *vkLogger

	// mu guards inflight, the provider Ping currently running (nil when none).
	mu       sync.Mutex
	inflight *pingCall
}

type pingCall struct {
	done    chan struct{}
	err     error
	started time.Time
}

// Ping implements NodeProvider.
func (g *pingGuard) Ping(ctx context.Context) error {
	g.mu.Lock()
	c := g.inflight
	if c == nil {
		c = &pingCall{done: make(chan struct{}), started: time.Now()}
		g.inflight = c
		go func() {
			c.err = g.NodeProvider.Ping(ctx)
			g.mu.Lock()
			g.inflight = nil
			g.mu.Unlock()
			close(c.done)
		}()
	}
	g.mu.Unlock()

	t := time.NewTimer(g.budget)
	defer t.Stop()
	select {
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		g.log.with("waited", time.Since(c.started).Round(time.Second).String()).
			Warn("node provider ping has not answered; posting node status and renewing the lease anyway (runtime health is reported as the Ready condition, not through the ping)")
		return nil
	}
}

// statusResync makes the node controller post the node status soon after it
// has gone wrong, instead of at the next nodeStatusUpdateInterval.
//
// Virtual Kubelet posts the status on a fixed interval (a minute, with the
// Lease carrying liveness) and on every status the provider pushes. A failed
// post is not retried until that interval comes round again, and a Ready
// condition the node lifecycle controller rewrote to Unknown while the node was
// unreachable stays Unknown until then, even though the Lease is renewing
// again. A kubelet checks every 10 seconds and posts as soon as its status
// differs from the apiserver's, so it recovers within one check. statusResync
// gives the node the same check: every interval it re-pushes the provider's
// latest node through the controller's own update path when
//
//   - the last status post failed and none has landed since, or
//   - the apiserver's Ready condition (read from its watch cache, as the
//     kubelet's first read is) is not the one the provider last reported.
//
// When neither holds it pushes nothing, so the steady-state cadence stays one
// post per status interval. It never changes what the provider reports: it
// re-sends the provider's own latest node.
type statusResync struct {
	NodeProvider
	interval time.Duration
	rec      *heartbeatRecorder
	// server reads this node from the apiserver.
	server func(ctx context.Context) (*corev1.Node, error)
	log    *slog.Logger

	// mu guards last, a copy of the node the provider last pushed (nil until
	// it pushes one).
	mu   sync.Mutex
	last *corev1.Node
}

// NotifyNodeStatus implements NodeProvider. It records every node the provider
// pushes on its way to the node controller, and starts the resync check, which
// runs until ctx ends.
//
// The check pushes through the controller's callback, which blocks until the
// controller's loop takes the node. That loop runs until ctx ends, and the
// check does not push once ctx has ended; a push already blocked when the loop
// exits stays blocked, exactly as a provider's own push would.
func (s *statusResync) NotifyNodeStatus(ctx context.Context, cb func(*corev1.Node)) {
	s.NodeProvider.NotifyNodeStatus(ctx, func(n *corev1.Node) {
		s.remember(n)
		cb(n)
	})
	go s.run(ctx, cb)
}

func (s *statusResync) remember(n *corev1.Node) {
	c := n.DeepCopy()
	s.mu.Lock()
	s.last = c
	s.mu.Unlock()
}

func (s *statusResync) run(ctx context.Context, cb func(*corev1.Node)) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n := s.due(ctx); n != nil && ctx.Err() == nil {
			cb(n)
		}
	}
}

// due returns the node to push now, or nil when no post is due.
func (s *statusResync) due(ctx context.Context) *corev1.Node {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last == nil {
		return nil
	}
	if s.rec.statusRetryDue() {
		return last.DeepCopy()
	}
	want := readyStatus(last)
	if want == "" {
		return nil
	}
	server, err := s.server(ctx)
	if err != nil {
		// The read fails when the path is down. The node controller's next post
		// then fails too, and that failure makes the post due.
		return nil
	}
	if got := readyStatus(server); got != want {
		s.log.Info("posting node status now: the apiserver's Ready condition differs from this node's",
			"apiserver_ready", string(got), "node_ready", string(want))
		return last.DeepCopy()
	}
	return nil
}

// readyStatus returns the status of n's Ready condition, or "" when it has none.
func readyStatus(n *corev1.Node) corev1.ConditionStatus {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status
		}
	}
	return ""
}
