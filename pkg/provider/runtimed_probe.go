package provider

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// runtimedRuntime probe integration: the Virtual Kubelet provider replaces the
// kubelet, so it must serve container probes itself. CreatePod starts a podProber
// for any probed pod; the prober's verdicts are overlaid onto every published
// PodStatus (so readiness drives the Ready condition and thus Service
// EndpointSlice membership), and DeletePod stops it.

// buildCheck resolves one container probe into the concrete check the runner
// executes: it resolves the target port (a named port via the container's port
// table) and defaults the dial host to the bound pod IP. It returns nil for an
// unsupported handler (e.g. a gRPC probe — not modeled by apis in M2) so the
// runner simply does not serve that probe rather than failing the container
// forever.
func (r *runtimedRuntime) buildCheck(podID, podIP string, c *corev1.Container, p *corev1.Probe) checkFunc {
	switch {
	case p.HTTPGet != nil:
		h := p.HTTPGet
		host := podIP
		if h.Host != "" {
			host = h.Host
		}
		port, ok := resolvePort(h.Port, c.Ports)
		if !ok {
			return unresolvedCheck("httpGet", c.Name)
		}
		scheme := string(h.Scheme)
		if scheme == "" {
			scheme = "HTTP"
		}
		return httpProbe(r.probeTransport, scheme, host, port, h.Path, h.HTTPHeaders)
	case p.TCPSocket != nil:
		t := p.TCPSocket
		host := podIP
		if t.Host != "" {
			host = t.Host
		}
		port, ok := resolvePort(t.Port, c.Ports)
		if !ok {
			return unresolvedCheck("tcpSocket", c.Name)
		}
		return tcpProbe(r.dial, host, port)
	case p.Exec != nil:
		return execCheck(r.rt, podID, c.Name, p.Exec.Command)
	default:
		return nil // unsupported handler (e.g. gRPC) — not served in M2
	}
}

// unresolvedCheck is a check that always fails: used when a supported handler's
// port cannot be resolved (a named port with no matching ContainerPort). The
// container reports NotReady, surfacing the misconfiguration rather than masking
// it as healthy.
func unresolvedCheck(handler, container string) checkFunc {
	return func(context.Context, time.Duration) error {
		return fmt.Errorf("%s probe for container %q: unresolved port", handler, container)
	}
}

// startProber builds and starts the provider-served probe runner for pod, keyed
// by pod id. It is idempotent (a second CreatePod for a live pod does not start a
// second prober) and a no-op for a pod with no probes. podIP is the bound pod IP
// (the dial target); it falls back to the node IP when the runtime has not
// assigned one.
func (r *runtimedRuntime) startProber(pod *corev1.Pod, podIP string) {
	id := string(pod.UID)
	if podIP == "" {
		podIP = r.nodeIP
	}
	pr := newPodProber(pod, r.clk, func(c *corev1.Container, p *corev1.Probe) checkFunc {
		return r.buildCheck(id, podIP, c, p)
	}, r.log)
	if pr == nil {
		return // no probes on any container
	}
	// A probe loop is a long-lived worker whose lifetime is the pod's, not any
	// single RPC's, so it roots a fresh cancelable context (cancelled by stop on
	// DeletePod) rather than a request context.
	ctx, cancel := context.WithCancel(context.Background())
	pr.cancel = cancel
	pr.onTransition = func() { r.publishProbeUpdate(ctx, id) }
	// restartFunc is intentionally nil in M2: the provider owns the restart
	// DECISION, count, and gate reset (the observable contract the acceptance gate
	// checks); the literal per-container process re-exec needs a runtime
	// RestartContainer RPC (an apis addition), wired here when it lands.

	r.mu.Lock()
	if _, exists := r.probers[id]; exists {
		r.mu.Unlock()
		cancel() // idempotent CreatePod: a prober already runs for this pod
		return
	}
	r.probers[id] = pr
	r.mu.Unlock()
	pr.start(ctx)
}

// stopProber detaches and stops the pod's prober. It removes the entry under the
// lock but waits for the goroutines OUTSIDE it, so a re-publish in flight (which
// also takes the lock) cannot deadlock the wait.
func (r *runtimedRuntime) stopProber(id string) {
	r.mu.Lock()
	pr := r.probers[id]
	delete(r.probers, id)
	r.mu.Unlock()
	if pr != nil {
		pr.stop()
	}
}

// proberFor returns the pod's prober as a probeState for the status overlay, or a
// nil interface (not a typed nil) when the pod has none — so toPodStatus's nil
// check is correct.
func (r *runtimedRuntime) proberFor(id string) probeState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pr, ok := r.probers[id]; ok {
		return pr
	}
	return nil
}

// publishProbeUpdate re-renders the pod's status (with the prober overlay) and
// runs the VK callback, after a probe-driven change. It reads the callback under
// the lock but invokes it OUTSIDE the lock (the VK NotifyPods re-entrancy rule),
// and no-ops if the pod was deleted concurrently.
func (r *runtimedRuntime) publishProbeUpdate(ctx context.Context, id string) {
	r.mu.Lock()
	t, tracked := r.track[id]
	cb := r.notify
	pr := r.probers[id]
	var pod *corev1.Pod
	var start metav1.Time
	if tracked {
		pod = t.pod.DeepCopy()
		start = t.startTime
	}
	r.mu.Unlock()
	if !tracked || cb == nil {
		return
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return
	}
	var ps probeState
	if pr != nil {
		ps = pr
	}
	pod.Status = *toPodStatus(resp.GetStatus(), r.nodeIP, start, ps)
	cb(pod)
}
