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

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/clock"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/mount"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// projectedRefreshInterval is the cadence of the projected-volume refresh: the
// kubelet re-syncs configMap / secret / downwardAPI / projected volumes about
// once a minute (its pod sync period), and so does this provider. It is its own
// constant, deliberately not resyncInterval: that one paces a cheap in-process
// status poll, this one paces apiserver reads.
const projectedRefreshInterval = 60 * time.Second

// projectedRefreshPodTimeout bounds one pod's refresh, so an apiserver read that
// hangs stalls one pod for one tick rather than every pod behind it forever.
const projectedRefreshPodTimeout = 30 * time.Second

// maxRefreshWarnings bounds a pod's refresh-failure Event bookkeeping
// (podTrack.refreshWarned). A pod has a handful of volumes and a failure has a
// handful of classes; the cap only matters for a pathological pod, which then
// stops receiving new refresh Events rather than growing the map.
const maxRefreshWarnings = 64

// projectedRefresher is the capability the refresh loop needs from the runtime:
// re-render one running pod's projected volumes from current data. It is
// declared here, at the consumer, and satisfied by the concrete in-process
// *runtime.Runtime. It is deliberately NOT a runtime/v1 RPC: the refresh is an
// in-process call between the provider and the runtime it embeds, and the
// resolver it drives is this provider's own kubeResolver.
type projectedRefresher interface {
	RefreshProjectedVolumes(ctx context.Context, podID string) (mount.RefreshResult, error)
}

// Compile-time check that the in-process runtime satisfies the capability.
var _ projectedRefresher = (*runtimed.Runtime)(nil)

// refresherOf returns rt's projected-refresh capability, or nil when rt has
// none (a test double, or an out-of-process backend): the loop then does nothing.
func refresherOf(rt runtimev1.RuntimeServer) projectedRefresher {
	if pr, ok := rt.(projectedRefresher); ok {
		return pr
	}
	return nil
}

// runProjectedRefresh refreshes the projected volumes of every running non-vm
// pod once per projectedRefreshInterval until ctx ends. It does nothing when the
// runtime has no refresh capability.
func (r *runtimedRuntime) runProjectedRefresh(ctx context.Context) {
	if r.refresher == nil {
		return
	}
	var tk clock.Ticker
	if wt, ok := r.clk.(clock.WithTicker); ok {
		tk = wt.NewTicker(projectedRefreshInterval)
	} else {
		tk = clock.RealClock{}.NewTicker(projectedRefreshInterval)
	}
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C():
			r.refreshProjectedOnce(ctx)
		}
	}
}

// refreshCandidate is a tracked pod as snapshotted under r.mu at tick start.
type refreshCandidate struct {
	t   *podTrack
	pod *corev1.Pod
}

// refreshProjectedOnce is one refresh tick. It is the unit the tests drive
// directly. Pods are refreshed one after another under one tick cache, so pods
// sharing a ConfigMap or Secret cost one apiserver read between them.
func (r *runtimedRuntime) refreshProjectedOnce(ctx context.Context) {
	if r.refresher == nil {
		return
	}
	r.mu.Lock()
	cands := make([]refreshCandidate, 0, len(r.track))
	for _, t := range r.track {
		cands = append(cands, refreshCandidate{t: t, pod: t.pod.DeepCopy()})
	}
	r.mu.Unlock()

	// The tick's cost is the trigger for a Watch-strategy follow-up (a tick
	// over 30 s, or D above 300), so it is observable at Debug.
	start := r.clk.Now()
	defer func() {
		r.log.Debug("projected refresh tick", "duration", r.clk.Since(start), "pods", len(cands), "distinct_refs", r.refs.distinct())
	}()
	cache := newRefreshCache()
	for _, c := range cands {
		if ctx.Err() != nil {
			return
		}
		if !c.t.refreshable() {
			continue
		}
		// A vm pod's volumes are guest shares, not atomic-writer generations; the
		// runtime refuses them, and the provider does not ask.
		if backend, err := podSandboxBackend(c.pod); err != nil || backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
			continue
		}
		r.refreshPod(ctx, cache, c)
	}
}

// refreshPod refreshes one pod and reports its per-volume outcomes.
func (r *runtimedRuntime) refreshPod(ctx context.Context, cache *refreshCache, c refreshCandidate) {
	podCtx, cancel := context.WithTimeout(withPodIdentity(withRefreshCache(ctx, cache), c.pod), projectedRefreshPodTimeout)
	defer cancel()
	res, err := r.refresher.RefreshProjectedVolumes(podCtx, string(c.pod.UID))
	switch {
	case errors.Is(err, runtimed.ErrPodNotFound), errors.Is(err, runtimed.ErrProjectedRefreshUnsupported):
		// Not (or no longer) held by the runtime, or a vm pod: nothing to refresh.
		return
	case ctx.Err() != nil:
		return
	}
	reported := false
	for _, v := range res.Volumes {
		switch v.Outcome {
		case mount.RefreshUpdated:
			r.log.Debug("projected volume refreshed", "namespace", c.pod.Namespace, "name", c.pod.Name, "volume", v.Name)
			c.t.clearRefreshWarnings(v.Name, warnKindFailed, warnKindHousekeeping)
		case mount.RefreshUnchanged:
			c.t.clearRefreshWarnings(v.Name, warnKindFailed, warnKindHousekeeping)
		case mount.RefreshUpdatedWithWarnings:
			// The new generation is live, so the volume recovered from any
			// earlier failure; only the housekeeping after the flip went wrong.
			reported = true
			c.t.clearRefreshWarnings(v.Name, warnKindFailed)
			r.reportRefreshWarning(c, v)
		case mount.RefreshSkipped:
			r.log.Debug("projected volume refresh skipped", "namespace", c.pod.Namespace, "name", c.pod.Name, "volume", v.Name, "reason", v.Reason)
		case mount.RefreshFailed:
			reported = true
			r.reportRefreshFailure(c, v)
		}
	}
	if err != nil && !reported {
		// A whole-pod failure no volume carries (the pod is being deleted, its
		// data volume is gone): logged, never an Event, since it names no volume.
		r.log.Warn("projected volume refresh failed", "namespace", c.pod.Namespace, "name", c.pod.Name, "err", err)
	}
}

// reportRefreshFailure logs a failed volume refresh and records one Warning
// Event per volume per failure class. The volume keeps its previous contents.
func (r *runtimedRuntime) reportRefreshFailure(c refreshCandidate, v mount.VolumeRefresh) {
	class := refreshFailureClass(v.Err)
	r.log.Warn("projected volume refresh failed; the volume keeps its previous contents",
		"namespace", c.pod.Namespace, "name", c.pod.Name, "volume", v.Name, "class", class, "err", v.Err)
	if !c.t.markRefreshWarned(v.Name, warnKindFailed, class) {
		return
	}
	msg := fmt.Sprintf("refresh of volume %q failed (%s); it keeps its previous contents: %v", v.Name, class, v.Err)
	r.recorder.Event(c.pod, corev1.EventTypeWarning, reasonProjectedVolumeRefreshFailed, stripControl(msg))
}

// reportRefreshWarning logs a volume whose new contents went live but whose
// post-flip housekeeping failed (linking a new key, removing the previous
// generation, pruning a dropped key), and records one Warning Event per volume
// per failure class. It is never a failure: the pod reads the new data.
func (r *runtimedRuntime) reportRefreshWarning(c refreshCandidate, v mount.VolumeRefresh) {
	class := refreshFailureClass(v.Err)
	r.log.Warn("projected volume refreshed, but its housekeeping failed",
		"namespace", c.pod.Namespace, "name", c.pod.Name, "volume", v.Name, "class", class, "err", v.Err)
	if !c.t.markRefreshWarned(v.Name, warnKindHousekeeping, class) {
		return
	}
	msg := fmt.Sprintf("volume %q was refreshed, but cleanup after the swap failed (%s): %v", v.Name, class, v.Err)
	r.recorder.Event(c.pod, corev1.EventTypeWarning, reasonProjectedVolumeRefreshWarning, stripControl(msg))
}

// The kinds of refresh warning bookkept per volume: a failed refresh, and a
// refresh whose post-flip housekeeping failed. They clear independently.
const (
	warnKindFailed       = "failed"
	warnKindHousekeeping = "housekeeping"
)

// refreshFailureClass buckets a volume refresh error for Event deduplication:
// the reason a repeat of the same failure is not a new Event.
func refreshFailureClass(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "NotFound"
	case apierrors.IsForbidden(err):
		return "Forbidden"
	case apierrors.IsUnauthorized(err):
		return "Unauthorized"
	case errors.Is(err, context.DeadlineExceeded), apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return "Timeout"
	default:
		return "Error"
	}
}

// refreshable reports whether t is a pod the runtime is running: not being
// deleted, and not a parked create the runtime holds nothing for.
func (t *podTrack) refreshable() bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return !t.deleting && t.parked == nil
}

// markRefreshWarned records that volume's refresh reported kind with class,
// reporting true the first time (the caller then records the Event). Bounded by
// maxRefreshWarnings; the bookkeeping dies with the track on delete.
func (t *podTrack) markRefreshWarned(volume, kind, class string) bool {
	key := volume + "\x00" + kind + "\x00" + class
	t.refreshWarnMu.Lock()
	defer t.refreshWarnMu.Unlock()
	if t.refreshWarned[key] || len(t.refreshWarned) >= maxRefreshWarnings {
		return false
	}
	if t.refreshWarned == nil {
		t.refreshWarned = map[string]bool{}
	}
	t.refreshWarned[key] = true
	return true
}

// clearRefreshWarnings forgets volume's recorded warnings of the given kinds
// once the volume refreshes again, so a later one is announced anew.
func (t *podTrack) clearRefreshWarnings(volume string, kinds ...string) {
	t.refreshWarnMu.Lock()
	defer t.refreshWarnMu.Unlock()
	for _, kind := range kinds {
		prefix := volume + "\x00" + kind + "\x00"
		for k := range t.refreshWarned {
			if strings.HasPrefix(k, prefix) {
				delete(t.refreshWarned, k)
			}
		}
	}
}
