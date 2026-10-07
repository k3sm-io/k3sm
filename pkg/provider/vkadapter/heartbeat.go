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
)

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

// heartbeatRecorder holds the Heartbeat. mu guards hb.
type heartbeatRecorder struct {
	now func() time.Time

	mu sync.Mutex
	hb Heartbeat
}

func (r *heartbeatRecorder) statusPosted() {
	t := r.now()
	r.mu.Lock()
	r.hb.StatusPosted = t
	r.mu.Unlock()
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
