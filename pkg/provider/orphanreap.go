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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

// The orphan reaper: a slow, provider-side reconcile that tears down a pod this
// node still runs after the apiserver has stopped holding it.
//
// The symptom it closes: a pod force-deleted while its Mac is partitioned from
// the apiserver keeps running after the partition heals, until the daemon
// restarts. The plausible cause is that the vendored virtual-kubelet pod
// controller drops deletions it learns about through a relist (the informer
// sees the object vanish, not a delete event it acts on) and sweeps for
// dangling pods only at startup — but that mechanism did not confirm on a code
// read. So the design here is deliberately mechanism-agnostic: it does not
// patch or rely on any particular informer path, it asks the apiserver
// directly, and it never consults an informer cache, because the cache is the
// component the bug implicates.
//
// Per tick (orphanReapInterval):
//  1. ONE node-scoped List (fieldSelector spec.nodeName=<node>) — never a Get
//     per tracked pod, so the steady-state cost is one request a minute. A List
//     error means "unknown" and the tick does nothing.
//  2. A tracked pod whose UID the List lacks is confirmed with a LIVE Get. Only
//     apierrors.IsNotFound (or the name now holding a different UID, see
//     liveVerdict) counts as gone; any other error is unknown and moves nothing.
//  3. A pod must be seen gone orphanReapThreshold ticks in a row before it is
//     reaped — the consecutive-threshold counting of probeGauge, reused as is.
//     Seen present resets the count; unknown neither advances nor resets it.
//  4. Reaping re-verifies, under r.mu, that the SAME track (by pointer, keyed by
//     UID) is still installed — the identity re-check untrackRejectedCreate
//     makes — and then runs the full DeletePod teardown (runtime RPC, /32
//     release, log tree, transport override, apiserver delete) minus preStop.

const (
	// orphanReapInterval is the reaper's cadence. It is deliberately SLOWER than
	// the 10s status backstop (resyncInterval): the reaper's work is a List
	// against the apiserver rather than a local RPC, and what it recovers is a
	// rare partition-heal leftover, not a dropped status event. Sixty seconds
	// keeps it at one List a minute per node, and with orphanReapThreshold it
	// bounds a dangling pod's post-heal lifetime to roughly three minutes.
	orphanReapInterval = 60 * time.Second
	// orphanReapThreshold is how many consecutive "gone" verdicts a pod needs
	// before it is reaped. One verdict is never enough: a single List can race a
	// create, and a single Get can race an apiserver restart.
	orphanReapThreshold int32 = 3
	// orphanAPITimeout bounds each apiserver call of a tick, so a partitioned
	// apiserver stalls one tick rather than the loop.
	orphanAPITimeout = 10 * time.Second
)

// apiPodSource is the live apiserver read the reaper needs, defined at the
// consumer. Production wraps a clientset (clientPodSource); tests inject a fake.
type apiPodSource interface {
	// listNodePods lists every pod bound to nodeName.
	listNodePods(ctx context.Context, nodeName string) ([]corev1.Pod, error)
	// getPod reads one pod by name, straight from the apiserver.
	getPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
}

// clientPodSource is the production apiPodSource: direct clientset calls, no
// informer, no cache.
type clientPodSource struct {
	client kubernetes.Interface
}

// newClientPodSource returns the live source over client, or nil when there is
// no client (the reaper is then disabled).
func newClientPodSource(client kubernetes.Interface) apiPodSource {
	if client == nil {
		return nil
	}
	return clientPodSource{client: client}
}

func (s clientPodSource) listNodePods(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	list, err := s.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (s clientPodSource) getPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return s.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

// orphanVerdict is one tick's reading of whether a tracked pod still exists.
type orphanVerdict int

const (
	verdictUnknown orphanVerdict = iota // no reliable answer: move nothing
	verdictPresent                      // the apiserver holds this pod (this UID)
	verdictGone                         // the apiserver definitively does not
)

// runOrphanReaper runs reapOrphans every orphanReapInterval until ctx ends.
func (r *runtimedRuntime) runOrphanReaper(ctx context.Context) {
	if r.podSource == nil {
		return
	}
	t := time.NewTicker(orphanReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.reapOrphans(ctx)
		}
	}
}

// orphanCandidate is a tracked pod as snapshotted under r.mu at the start of a
// tick: the track (whose pointer identity the reap re-checks) and its pod.
type orphanCandidate struct {
	t   *podTrack
	pod *corev1.Pod
}

// reapOrphans is one reaper tick. It is the unit the tests drive directly.
func (r *runtimedRuntime) reapOrphans(ctx context.Context) {
	if r.podSource == nil {
		return
	}
	listCtx, cancel := context.WithTimeout(ctx, orphanAPITimeout)
	listed, err := r.podSource.listNodePods(listCtx, r.nodeName)
	cancel()
	if err != nil {
		// Unknown: a partitioned or restarting apiserver says nothing about any
		// pod. No counter moves.
		r.log.Debug("orphan reaper: node pod list failed; skipping tick", "err", err)
		return
	}
	present := make(map[string]bool, len(listed))
	for i := range listed {
		present[string(listed[i].UID)] = true
	}

	r.mu.Lock()
	tracked := make(map[string]orphanCandidate, len(r.track))
	for id, t := range r.track {
		tracked[id] = orphanCandidate{t: t, pod: t.pod} // the pointer only; see GetPods
	}
	r.mu.Unlock()

	r.pruneOrphanGauges(tracked)
	for id, c := range tracked {
		if present[id] {
			r.recordOrphanVerdict(id, verdictPresent)
			continue
		}
		getCtx, cancel := context.WithTimeout(ctx, orphanAPITimeout)
		v := r.liveVerdict(getCtx, c.pod)
		cancel()
		if !r.recordOrphanVerdict(id, v) {
			continue
		}
		r.reapOrphan(ctx, c.pod, c.t)
	}
}

// liveVerdict confirms, with a direct apiserver Get, whether a pod the List did
// not return is gone. apierrors.IsNotFound is gone; every other error is
// unknown. A successful Get is present when it returns this pod's UID; when the
// name now holds a DIFFERENT UID the apiserver has, live, answered that no
// object with this UID exists under the name (UIDs are never reused), which is
// the same fact a NotFound states — a same-name successor must not keep its
// force-deleted predecessor running forever.
func (r *runtimedRuntime) liveVerdict(ctx context.Context, pod *corev1.Pod) orphanVerdict {
	got, err := r.podSource.getPod(ctx, pod.Namespace, pod.Name)
	switch {
	case apierrors.IsNotFound(err):
		return verdictGone
	case err != nil:
		return verdictUnknown
	case got.UID == pod.UID:
		return verdictPresent
	default:
		return verdictGone
	}
}

// recordOrphanVerdict feeds one verdict into pod id's gauge and reports whether
// the gauge has committed "gone" (the reap threshold is met). Unknown feeds
// nothing: it neither advances nor resets the run.
func (r *runtimedRuntime) recordOrphanVerdict(id string, v orphanVerdict) bool {
	var raw probeOutcome
	switch v {
	case verdictPresent:
		raw = outcomeSuccess
	case verdictGone:
		raw = outcomeFailure
	default:
		return false
	}
	r.orphanMu.Lock()
	defer r.orphanMu.Unlock()
	g := r.orphanGauges[id]
	if g == nil {
		if raw == outcomeSuccess {
			return false // a present pod with no run to reset needs no gauge
		}
		g = newProbeGauge(1, orphanReapThreshold, outcomeSuccess)
		r.orphanGauges[id] = g
	}
	return g.record(raw) == outcomeFailure
}

// pruneOrphanGauges drops the gauge of every pod id no longer tracked, so a
// pod forgotten by any path leaves no counter behind.
func (r *runtimedRuntime) pruneOrphanGauges(tracked map[string]orphanCandidate) {
	r.orphanMu.Lock()
	defer r.orphanMu.Unlock()
	for id := range r.orphanGauges {
		if _, ok := tracked[id]; !ok {
			delete(r.orphanGauges, id)
		}
	}
}

// reapOrphan tears down a pod the apiserver has been seen not to hold
// orphanReapThreshold ticks in a row.
//
// The track is re-verified under r.mu first — identity, not presence, the
// check untrackRejectedCreate makes: the verdict was reached against the track
// snapshotted at the start of the tick, and if an idempotent re-create has
// installed a different track for the id since, that verdict is stale and this
// reap is not the replacement's. A same-name successor is a different UID and
// therefore a different id, so it is never addressed here at all.
//
// The teardown is DeletePod's own (quiesce, then teardownPod) minus preStop: the
// pod no longer exists in the cluster, so there is no graceful-termination
// contract left to honour beyond the SIGTERM grace, which is passed through.
// A failed runtime RPC leaves the track installed, and the still-committed gauge
// retries the reap on the next tick.
func (r *runtimedRuntime) reapOrphan(ctx context.Context, pod *corev1.Pod, t *podTrack) {
	id := string(pod.UID)
	r.mu.Lock()
	if r.track[id] != t {
		r.mu.Unlock()
		return
	}
	pod = t.pod // the latest spec for this same track, still under r.mu
	r.mu.Unlock()

	r.log.Info("orphan reaper: the apiserver no longer holds a pod this node runs; tearing it down",
		"namespace", pod.Namespace, "name", pod.Name, "uid", id,
		"consecutiveNotFound", orphanReapThreshold)
	t.quiesce()
	if err := r.teardownPod(ctx, pod, graceSeconds(pod), t); err != nil {
		r.log.Warn("orphan reaper: teardown failed; retrying next tick",
			"namespace", pod.Namespace, "name", pod.Name, "err", err)
		return
	}
	r.orphanMu.Lock()
	delete(r.orphanGauges, id)
	r.orphanMu.Unlock()
}
