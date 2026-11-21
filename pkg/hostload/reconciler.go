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

package hostload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// DefaultInterval is how often the Reconciler lists the nodes. The node
// recomputes its condition about once a minute, so a quarter of that keeps the
// taint within one status interval of the condition, and listing a few Nodes
// that often costs the apiserver nothing measurable.
const DefaultInterval = 15 * time.Second

// FieldManager names the Reconciler's Node writes.
const FieldManager = "k3sm-hostload"

// AbsentGrace is how long a tainted node may publish no HostCPUBusy condition
// before the Reconciler removes the taint. A node daemon that restarts on a busy
// Mac publishes no condition until it has measured one rate (about a minute),
// and pods displaced by that restart are exactly the ones the taint should
// steer, so a short silence keeps the taint. A longer one (a node rolled back to
// a release without the condition) clears it.
const AbsentGrace = 3 * time.Minute

// Reconciler keeps the TaintKey taint on exactly the nodes that publish
// HostCPUBusy=True. It runs on the server's admin client. With several servers
// (HA) every server runs one: each computes the same answer from the same
// Nodes, and each write is guarded by the Node's resourceVersion, so two
// servers never undo each other and a write raced by any other writer (an
// operator's kubectl taint included) fails and is recomputed on the next pass
// rather than overwriting it.
//
// It polls rather than watches: the signal it follows changes on a two-minute
// average published once a minute, so a 15 s list adds nothing a watch would
// remove, and it keeps no cache to go stale.
type Reconciler struct {
	client   kubernetes.Interface
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time

	// absentSince records, per tainted node with no condition, when the
	// silence was first seen. Used by Reconcile only, which Run calls serially.
	absentSince map[string]time.Time
	// lastErr is the last pass's error text, so a failure that repeats
	// unchanged is logged once at Warn and then at Debug.
	lastErr string
}

// Config is the input to New.
type Config struct {
	// Client reads and patches Nodes. Required.
	Client kubernetes.Interface
	// Interval overrides DefaultInterval when positive.
	Interval time.Duration
	// Log is the logger; nil uses slog.Default().
	Log *slog.Logger
}

// New returns a Reconciler, or an error when cfg has no client.
func New(cfg Config) (*Reconciler, error) {
	if cfg.Client == nil {
		return nil, errors.New("hostload: Config.Client is required")
	}
	r := &Reconciler{client: cfg.Client, interval: cfg.Interval, log: cfg.Log, now: time.Now, absentSince: map[string]time.Time{}}
	if r.interval <= 0 {
		r.interval = DefaultInterval
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	return r, nil
}

// Run reconciles every interval until ctx is done, and returns ctx's error. A
// failed pass is logged and retried on the next one.
func (r *Reconciler) Run(ctx context.Context) error {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		err := r.Reconcile(ctx)
		switch {
		case ctx.Err() != nil:
		case err == nil:
			r.lastErr = ""
		case err.Error() == r.lastErr:
			r.log.Debug("host cpu taint: reconcile still failing", "err", err)
		default:
			r.lastErr = err.Error()
			r.log.Warn("host cpu taint: reconcile failed; retrying on the next pass", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Reconcile makes one pass over every Node: it adds or removes the TaintKey
// taint where the node's HostCPUBusy condition says it should change, and
// touches no Node that is already right. It returns the joined errors of the
// Nodes it could not write; the others are still written.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	nodes, err := r.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	var errs []error
	now := r.now()
	seen := make(map[string]bool, len(nodes.Items))
	for i := range nodes.Items {
		n := &nodes.Items[i]
		seen[n.Name] = true
		busy := r.wantTaint(n, now)
		taints, changed := DesiredTaints(n, busy)
		if !changed {
			continue
		}
		if err := r.patchTaints(ctx, n, taints); err != nil {
			errs = append(errs, fmt.Errorf("node %s: %w", n.Name, err))
			continue
		}
		verb := "removed"
		if busy {
			verb = "added"
		}
		r.log.Info("host cpu taint "+verb, "node", n.Name, "taint", TaintKey+":"+string(corev1.TaintEffectPreferNoSchedule))
	}
	for name := range r.absentSince {
		if !seen[name] {
			delete(r.absentSince, name)
		}
	}
	return errors.Join(errs...)
}

// wantTaint is the taint decision for n at now: True condition, taint; False
// condition, no taint; no condition, keep a taint already there for
// AbsentGrace from when the silence was first seen, then drop it.
func (r *Reconciler) wantTaint(n *corev1.Node, now time.Time) bool {
	if Reported(n) {
		delete(r.absentSince, n.Name)
		return Busy(n)
	}
	if _, tainted := DesiredTaints(n, false); !tainted {
		delete(r.absentSince, n.Name)
		return false
	}
	since, ok := r.absentSince[n.Name]
	if !ok {
		r.absentSince[n.Name] = now
		return true
	}
	if now.Sub(since) < AbsentGrace {
		return true
	}
	delete(r.absentSince, n.Name)
	return false
}

// patchTaints writes taints to n with a JSON patch whose first operation tests
// the resourceVersion the taints were computed from, so the write lands only on
// the object that was read. A Node changed in between fails the test (the
// apiserver answers 409 or 422) and the next pass recomputes from the new one.
func (r *Reconciler) patchTaints(ctx context.Context, n *corev1.Node, taints []corev1.Taint) error {
	ops := []map[string]any{
		{"op": "test", "path": "/metadata/resourceVersion", "value": n.ResourceVersion},
		{"op": "add", "path": "/spec/taints", "value": taints},
	}
	body, err := json.Marshal(ops)
	if err != nil {
		return fmt.Errorf("encode taint patch: %w", err)
	}
	if _, err := r.client.CoreV1().Nodes().Patch(ctx, n.Name, types.JSONPatchType, body, metav1.PatchOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("patch taints: %w", err)
	}
	return nil
}
