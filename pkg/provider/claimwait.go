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
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/provisioner"
)

// A pod that mounts a PersistentVolumeClaim starts only once every such claim is
// Bound and its PersistentVolume resolves to the directory this node mounts.
//
// Upstream, the kubelet's SyncPod blocks in volumeManager.WaitForAttachAndMount
// (pkg/kubelet/volumemanager/volume_manager.go): the desired-state-of-world
// populator dereferences each claim to its bound PV (getPVCExtractPV, getPVSpec
// in populator/desired_state_of_world_populator.go), and a claim that is not
// Bound fails that step, so no sandbox is created, the pod stays Pending with
// its containers Waiting ContainerCreating, a Warning FailedMount Event is
// recorded, and the pod worker retries. The claim name is never turned into a
// path on its own.
//
// The provider mirrors that at CreatePod. A pod whose claims do not resolve is
// held on the provider side: it is tracked (so virtual-kubelet does not create it
// again), it holds no address and no runtime state, its status is the
// synthesized ContainerCreating one, and a single worker re-checks its claims on
// a capped back-off and runs the create once they resolve. Nothing is started,
// and nothing is written, until then.
//
// The PV check is the half the wire contract cannot carry. runtime/v1 sends only
// the claim reference, and runtimed mounts the per-claim directory of its
// storage class. So the provider refuses to start a pod unless the bound PV's own
// path IS that directory: a PV with no local or hostPath source, or one that
// points anywhere else, waits rather than handing the pod a directory its PV
// does not name.

const (
	// reasonFailedMount is the kubelet's events.FailedMountVolume reason.
	reasonFailedMount = "FailedMount"

	// claimWaitInitialDelay and claimWaitMaxDelay bound the re-check schedule of
	// a held pod: exponential from the first, capped at the second, so a claim
	// that binds is noticed within seconds and a claim that never binds costs two
	// apiserver reads every claimWaitMaxDelay, never a busy loop.
	claimWaitInitialDelay = time.Second
	claimWaitMaxDelay     = 10 * time.Second
	// claimWaitEventInterval re-records an unchanged FailedMount Event at
	// upstream's own cadence: podAttachAndMountTimeout (2m3s) is how long one
	// WaitForAttachAndMount call waits before the kubelet records it again. A
	// changed message is recorded at once.
	claimWaitEventInterval = 2*time.Minute + 3*time.Second

	// pvcProtectionFinalizer is upstream's util.PVCProtectionFinalizer: a claim
	// being deleted that still carries it is kept for the pods that use it.
	pvcProtectionFinalizer = "kubernetes.io/pvc-protection"

	// reasonProviderCreateFailed and statusReasonProviderFailed are the Event
	// reason and pod status reason virtual-kubelet records for a CreatePod that
	// returned an error (node/pod.go: podEventCreateFailed,
	// podStatusReasonProviderFailed). A held pod's create runs after
	// virtual-kubelet's own call has returned, so the provider records them.
	reasonProviderCreateFailed = "ProviderCreateFailed"
	statusReasonProviderFailed = "ProviderFailed"
)

// claimWait is a held pod's wait for its claims. cancel and done belong to the
// one re-check worker; message and lastEvent pace the FailedMount Event.
// Guarded by podTrack.restartMu, except done, which is closed by the worker and
// only read.
type claimWait struct {
	cancel    context.CancelFunc
	done      chan struct{}
	message   string
	lastEvent time.Time
}

// claimWaiting reports whether the track is a pod held for its claims.
func (t *podTrack) claimWaiting() bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.claims != nil
}

// stopClaimWait cancels a held pod's re-check worker and waits for it to
// return, so a create the worker had already begun has finished (and installed
// whatever track it installs) before the caller tears the pod down. It must not
// be called from the worker itself.
func (t *podTrack) stopClaimWait() {
	t.restartMu.Lock()
	cw := t.claims
	t.restartMu.Unlock()
	if cw == nil {
		return
	}
	cw.cancel()
	<-cw.done
}

// unresolvedClaims returns the FailedMount message for a pod one of whose
// claims does not resolve, or "" when every claim does (or the pod mounts none).
func (r *runtimedRuntime) unresolvedClaims(ctx context.Context, pod *corev1.Pod) string {
	var failed, errs []string
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.PersistentVolumeClaim == nil {
			continue
		}
		if err := r.resolveClaim(ctx, pod.Namespace, v.PersistentVolumeClaim.ClaimName); err != nil {
			failed = append(failed, v.Name)
			errs = append(errs, fmt.Sprintf("error processing PVC %s/%s: %v", pod.Namespace, v.PersistentVolumeClaim.ClaimName, err))
		}
	}
	if len(failed) == 0 {
		return ""
	}
	slices.Sort(failed)
	// Upstream's shape: kubelet.go records "Unable to attach or mount volumes:
	// %v" over WaitForAttachAndMount's "unmounted volumes=%v, unattached
	// volumes=%v, failed to process volumes=%v: %w", where the wrapped error is
	// the populator's per-volume errors joined with "; ". No volume of a held pod
	// is mounted, and this node attaches nothing, so unattached is always empty.
	return fmt.Sprintf("Unable to attach or mount volumes: unmounted volumes=%v, unattached volumes=%v, failed to process volumes=%v: %s",
		podMountedVolumeNames(pod), []string{}, failed, strings.Join(errs, "; "))
}

// podMountedVolumeNames is upstream's expected-volume set for the message: the
// sorted names of the pod volumes any container mounts or uses as a device.
func podMountedVolumeNames(pod *corev1.Pod) []string {
	seen := map[string]bool{}
	add := func(mounts []corev1.VolumeMount, devices []corev1.VolumeDevice) {
		for _, m := range mounts {
			seen[m.Name] = true
		}
		for _, d := range devices {
			seen[d.Name] = true
		}
	}
	for i := range pod.Spec.InitContainers {
		add(pod.Spec.InitContainers[i].VolumeMounts, pod.Spec.InitContainers[i].VolumeDevices)
	}
	for i := range pod.Spec.Containers {
		add(pod.Spec.Containers[i].VolumeMounts, pod.Spec.Containers[i].VolumeDevices)
	}
	for i := range pod.Spec.EphemeralContainers {
		add(pod.Spec.EphemeralContainers[i].VolumeMounts, pod.Spec.EphemeralContainers[i].VolumeDevices)
	}
	out := make([]string, 0, len(seen))
	for i := range pod.Spec.Volumes {
		if seen[pod.Spec.Volumes[i].Name] {
			out = append(out, pod.Spec.Volumes[i].Name)
		}
	}
	slices.Sort(out)
	return out
}

// resolveClaim checks one claim the way upstream's getPVCExtractPV and getPVSpec
// do, with upstream's error texts, and then that the bound PV's path is the
// directory runtimed mounts for the claim.
func (r *runtimedRuntime) resolveClaim(ctx context.Context, namespace, claimName string) error {
	if r.client == nil {
		return errors.New("failed to fetch PVC from API server: no apiserver client")
	}
	pvc, err := r.client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, claimName, metav1.GetOptions{})
	if err != nil || pvc == nil {
		return fmt.Errorf("failed to fetch PVC from API server: %v", err)
	}
	if pvc.DeletionTimestamp != nil && !slices.Contains(pvc.Finalizers, pvcProtectionFinalizer) {
		return errors.New("PVC is being deleted")
	}
	if pvc.Status.Phase != corev1.ClaimBound {
		return errors.New("PVC is not bound")
	}
	if pvc.Spec.VolumeName == "" {
		return errors.New("PVC has empty pvc.Spec.VolumeName")
	}
	name := pvc.Spec.VolumeName
	pv, err := r.client.CoreV1().PersistentVolumes().Get(ctx, name, metav1.GetOptions{})
	if err != nil || pv == nil {
		return fmt.Errorf("failed to fetch PV %s from API server: %v", name, err)
	}
	if pv.Spec.ClaimRef == nil {
		return fmt.Errorf("found PV object %s but it has a nil pv.Spec.ClaimRef indicating it is not yet bound to the claim", name)
	}
	if pv.Spec.ClaimRef.UID != pvc.UID {
		return fmt.Errorf("found PV object %s but its pv.Spec.ClaimRef.UID %s does not point to claim.UID %s", name, pv.Spec.ClaimRef.UID, pvc.UID)
	}
	// From here on the checks are k3sm's: upstream hands the PV to a volume
	// plugin, and here the plugin is runtimed's per-claim directory.
	var pvPath string
	switch {
	case pv.Spec.Local != nil:
		pvPath = pv.Spec.Local.Path
	case pv.Spec.HostPath != nil:
		pvPath = pv.Spec.HostPath.Path
	}
	if pvPath == "" {
		return fmt.Errorf("PV %s has no local or hostPath source with a path this node can mount", name)
	}
	want, err := provisioner.ClassForRoot(runtimeRoot(r.rootfs)).DataDir(namespace, claimName)
	if err != nil {
		return fmt.Errorf("PV %s: %v", name, err)
	}
	if pvPath != want {
		return fmt.Errorf("PV %s path %s is not the directory this node mounts for the claim (%s)", name, pvPath, want)
	}
	return nil
}

// holdForClaims keeps a pod whose claims do not resolve from starting. A pod
// not yet tracked gets a held track and a re-check worker; a pod already held
// (the worker's own create found a claim unbound again) only has its spec and
// message refreshed. Either way the FailedMount Event is recorded when the
// message is new, or when the last one is older than claimWaitEventInterval.
func (r *runtimedRuntime) holdForClaims(pod *corev1.Pod, message string) {
	id := string(pod.UID)
	now := r.clk.Now()
	r.mu.Lock()
	t := r.track[id]
	if t != nil {
		t.pod = pod.DeepCopy()
		r.mu.Unlock()
	} else {
		t = &podTrack{pod: pod.DeepCopy(), startTime: metav1.NewTime(now)}
		ctx, cancel := context.WithCancel(context.Background())
		cw := &claimWait{cancel: cancel, done: make(chan struct{})}
		// Installed before the track is published, so no reader sees a held
		// pod's track without its wait.
		t.claims = cw
		r.track[id] = t
		r.mu.Unlock()
		go r.runClaimWait(ctx, t, cw)
	}
	t.restartMu.Lock()
	cw := t.claims
	record := cw != nil && (cw.message != message || !now.Before(cw.lastEvent.Add(claimWaitEventInterval)))
	if record {
		cw.message, cw.lastEvent = message, now
	}
	t.restartMu.Unlock()
	if record {
		r.log.Warn("CreatePod: a claim the pod mounts does not resolve to a bound volume; the pod is held",
			"namespace", pod.Namespace, "name", pod.Name, "message", message)
		r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedMount, message)
	}
}

// runClaimWait is a held pod's single re-check worker. It sleeps the back-off on
// the injected clock, re-reads the claims of the current spec, and runs the
// create once they resolve. It returns when its context is cancelled (the pod
// is being deleted), or once the track is no longer the live, held one for the
// pod: the create installed the pod's real track, or a successor took it over.
//
// A create that fails is reported as virtual-kubelet reports its own failed
// create (handleProviderError): a ProviderCreateFailed Warning Event and a
// ProviderFailed status. A held track the failed create left behind is dropped,
// so the pod is no longer tracked, exactly as after a refused first create.
func (r *runtimedRuntime) runClaimWait(ctx context.Context, t *podTrack, cw *claimWait) {
	defer close(cw.done)
	delay := claimWaitInitialDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.clk.After(delay):
		}
		delay = min(2*delay, claimWaitMaxDelay)
		if !r.heldTrack(t) {
			return
		}
		pod := r.trackPod(t)
		if msg := r.unresolvedClaims(ctx, pod); msg != "" {
			if ctx.Err() != nil {
				return
			}
			r.holdForClaims(pod, msg)
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if err := r.CreatePod(ctx, pod); err != nil {
			r.reportHeldCreateFailure(pod, t, err)
			return
		}
		if !r.heldTrack(t) {
			return
		}
	}
}

// heldTrack reports whether t is still the live track of its pod and still held
// for claims.
func (r *runtimedRuntime) heldTrack(t *podTrack) bool {
	r.mu.Lock()
	live := r.track[string(t.pod.UID)] == t // t.pod is guarded by r.mu
	r.mu.Unlock()
	return live && t.claimWaiting()
}

// reportHeldCreateFailure surfaces a create the claim worker ran and that
// failed, in the shape virtual-kubelet gives a failed CreatePod.
func (r *runtimedRuntime) reportHeldCreateFailure(pod *corev1.Pod, t *podTrack, err error) {
	r.log.Error("CreatePod: the create of a pod whose claims bound failed",
		"namespace", pod.Namespace, "name", pod.Name, "err", err)
	r.mu.Lock()
	held := r.track[string(pod.UID)] == t
	r.mu.Unlock()
	if held {
		r.untrackRejectedCreate(pod, t)
	}
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonProviderCreateFailed, err.Error())
	failed := pod.DeepCopy()
	failed.Status.Phase = corev1.PodPending
	if pod.Spec.RestartPolicy == corev1.RestartPolicyNever {
		failed.Status.Phase = corev1.PodFailed
	}
	failed.Status.Reason = statusReasonProviderFailed
	failed.Status.Message = err.Error()
	if cb := r.callback(); cb != nil {
		cb(failed)
	}
}
