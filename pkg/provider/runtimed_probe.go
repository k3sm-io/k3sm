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
	"net"
	"net/http"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// runtimedRuntime probe integration: the Virtual Kubelet provider replaces the
// kubelet, so it must serve container probes itself. CreatePod starts a podProber
// for any probed pod; the prober's verdicts are overlaid onto every published
// PodStatus (so readiness drives the Ready condition and thus Service
// EndpointSlice membership), and DeletePod stops it.

// probeSeams are the I/O seams ONE pod's probe checks are built against: the dial
// every tcp/grpc check uses and the http transport every httpGet check uses. They
// are per-pod because for a vm pod they RESOLVE — the dial translates the pod's
// published /32 to its guest's live lease per attempt (probeDialFor), and the
// transport is layered on that same dial so an httpGet probe resolves identically
// to a tcpSocket one instead of taking http.Transport's default dialer straight
// to an address nothing answers at.
//
// The runtime-level r.probeTransport is NOT replaced: it keeps the default dialer
// and stays the transport of everything that is not a pod's own probe — today the
// httpGet lifecycle hooks (lifecycle.go), which are dispatched per call rather
// than per prober, and which fail OPEN where a probe fails closed.
type probeSeams struct {
	dial      dialFunc
	transport http.RoundTripper
	// pending, when non-nil, reports the NOT-EVALUATED window ahead of a check
	// whose transport would swallow the dial's sentinel. nil for a native pod.
	pending func() error
}

// probeSeamsFor builds the seams for one pod's prober. vmBacked selects the
// resolving dial; for a native pod probeDialFor hands back r.dial itself, so its
// probes are dialed exactly where they always were.
//
// The transport is built PER PROBER for every pod, not only a vm one, because the
// property worth having is that every probe dial — tcpSocket, gRPC and httpGet
// alike — converges on the ONE dial seam. An httpGet probe left on the shared
// transport would keep http.Transport's own default dialer and silently bypass
// whatever the pod's dial resolves to, which is how the vm bug reached httpGet
// probes in the first place.
func (r *runtimedRuntime) probeSeamsFor(podID string, vmBacked bool) probeSeams {
	dial := r.probeDialFor(podID, vmBacked)
	// A private transport, because its dialer is private. DisableKeepAlives is
	// what makes one per pod cheap (newProbeTransport pools nothing), and it dies
	// with the prober that holds it.
	tr := newProbeTransport()
	tr.DialContext = dial
	seams := probeSeams{dial: dial, transport: tr}
	if !vmBacked || r.transport == nil {
		return seams
	}
	seams.pending = func() error {
		if _, ok := r.transport.live(podID); !ok {
			return fmt.Errorf("pod %s: the guest has not reported its transport address yet: %w",
				podID, errProbeTargetPending)
		}
		return nil
	}
	return seams
}

// notEvaluatedAware builds a check whose NOT-EVALUATED answer survives a client
// that does not preserve the dial's error chain. gRPC is the one such client:
// it converts a dialer error into a status error, so errProbeTargetPending would
// reach the runner as an ordinary failure and count against failureThreshold —
// restarting a container for a window the runtime owns, which is the whole bug.
// The tcp and httpGet paths need none of this (a net.Dialer error and a
// *url.Error both unwrap), and exec makes no dial at all.
//
// It is a CARRIER, not a pre-check, and that distinction is the point: a
// pre-check alone reads the lease once and the dial reads it again, so a lease
// lost between the two reads produces exactly the mis-counted failure the
// pre-check was meant to prevent. So the per-attempt dial RECORDS its own
// refusal, and the recorded refusal — not the status error gRPC returned —
// is what the runner is told. The pending test is kept only as a fast path:
// it saves building a ClientConn for a window that is usually seconds long,
// and it is never the authority.
//
// build is called per attempt because the recorder is per attempt; the handler
// builders are pure closure constructors, so this costs nothing. For a native
// pod (no pending test) the check is built once against the plain dial.
func (s probeSeams) notEvaluatedAware(build func(dial dialFunc) checkFunc) checkFunc {
	if s.pending == nil {
		return build(s.dial)
	}
	return func(ctx context.Context, timeout time.Duration) error {
		if err := s.pending(); err != nil {
			return err // fast path: no lease when the attempt began
		}
		// mu guards refusal: gRPC runs the context dialer on its own transport
		// goroutine, so the write and this read are genuinely concurrent.
		var mu sync.Mutex
		var refusal error
		recording := func(c context.Context, network, address string) (net.Conn, error) {
			conn, err := s.dial(c, network, address)
			if err != nil && errors.Is(err, errProbeTargetPending) {
				mu.Lock()
				refusal = err
				mu.Unlock()
			}
			return conn, err
		}
		err := build(recording)(ctx, timeout)
		if err == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if refusal != nil {
			// The attempt was never made. Whatever the client wrapped it in, THIS
			// is what happened.
			return refusal
		}
		return err
	}
}

// buildCheck resolves one container probe into the concrete check the runner
// executes: it resolves the target port (a named port via the container's port
// table) and defaults the dial host to the bound pod IP. Every branch returns a
// NON-nil check, INCLUDING the default: an unrecognized or handler-less probe
// yields a fail-CLOSED check that always errors, so an unverifiable container is
// reported NotReady (and any liveness/startup gate stays shut) rather than being
// silently treated as healthy. Returning nil here would be a latent node-DoS: the
// runner still builds a probeSpec for the non-nil Probe and would invoke a nil
// check, panicking the single k3sm process (control plane + every pod) — so this
// function MUST never return nil.
func (r *runtimedRuntime) buildCheck(podID, podIP string, seams probeSeams, c *corev1.Container, p *corev1.Probe) checkFunc {
	switch {
	case p.HTTPGet != nil:
		return r.httpGetCheck(seams.transport, podIP, c.Name, c.Ports, p.HTTPGet)
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
		return tcpProbe(seams.dial, host, port)
	case p.GRPC != nil:
		// gRPC health probe (the standard grpc.health.v1 Health/Check RPC).
		// GRPCAction.Port is a plain int32 — gRPC has no named-port form — so it
		// is validated directly (a non-positive port is unresolvable → fail
		// closed) instead of via resolvePort, and the dial host is always the
		// bound pod IP (GRPCAction carries no Host). It dials over the SAME dial
		// seam the tcp/http checks use: a provider-side client dial, so no
		// runtimed/apis change is needed.
		if p.GRPC.Port <= 0 {
			return unresolvedCheck("grpc", c.Name)
		}
		var service string
		if p.GRPC.Service != nil {
			service = *p.GRPC.Service
		}
		return seams.notEvaluatedAware(func(dial dialFunc) checkFunc {
			return grpcProbe(dial, podIP, p.GRPC.Port, service)
		})
	case p.Exec != nil:
		return execCheck(r.rt, podID, c.Name, p.Exec.Command)
	default:
		// No recognized handler (a zero/empty Probe, or a future handler this
		// provider does not yet serve). Fail CLOSED — never nil, never a silent
		// pass — so an unverifiable container is reported NotReady rather than
		// falsely healthy, and the runner never invokes a nil check.
		return unhandledProbeCheck(c.Name)
	}
}

// httpGetCheck resolves an httpGet target — default host = the bound pod IP, default
// scheme = HTTP, the port resolved (a named port via the container's port table) —
// into the check the probe runner and the lifecycle-hook dispatcher (lifecycle.go)
// both execute, so a probe and a hook httpGet resolve IDENTICALLY. rt is the
// caller's transport: a prober passes its own (probeSeams, which resolves a vm
// pod's address), a lifecycle hook passes the shared r.probeTransport. An unresolvable
// named port yields an always-failing check (the misconfiguration surfaces rather
// than masking as success); a hook caller treats that failure as best-effort.
func (r *runtimedRuntime) httpGetCheck(rt http.RoundTripper, podIP, container string, ports []corev1.ContainerPort, h *corev1.HTTPGetAction) checkFunc {
	host := podIP
	if h.Host != "" {
		host = h.Host
	}
	port, ok := resolvePort(h.Port, ports)
	if !ok {
		return unresolvedCheck("httpGet", container)
	}
	scheme := string(h.Scheme)
	if scheme == "" {
		scheme = "HTTP"
	}
	return httpProbe(rt, scheme, host, port, h.Path, h.HTTPHeaders)
}

// unresolvedCheck is a check that always fails: used when a supported handler's
// port cannot be resolved (a named port with no matching ContainerPort, or a
// non-positive gRPC port). The container reports NotReady, surfacing the
// misconfiguration rather than masking it as healthy.
func unresolvedCheck(handler, container string) checkFunc {
	return func(context.Context, time.Duration) error {
		return fmt.Errorf("%s probe for container %q: unresolved port", handler, container)
	}
}

// unhandledProbeCheck is the fail-closed check buildCheck returns for a probe
// with no recognized handler (an empty/zero Probe, or a handler this provider
// does not serve). It ALWAYS fails so the container reports NotReady — never nil
// (which would panic the runner's nil-check invocation) and never a silent pass
// (which would make an unverified container Ready and take Service traffic). The
// error names the container so the never-Ready cause is diagnosable.
func unhandledProbeCheck(container string) checkFunc {
	return func(context.Context, time.Duration) error {
		return fmt.Errorf("probe for container %q: no supported handler (httpGet/tcpSocket/grpc/exec)", container)
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
	// The backend decides how the pod's own address is dialed, so it is resolved
	// ONCE here (the pod's spec cannot change under a running prober) while the
	// LEASE it resolves to is looked up per attempt. An unresolvable RuntimeClass
	// is not vm-backed: CreatePod already refused such a pod, so there is no
	// prober to build — the same fail-toward-existing-behaviour branch
	// transportGateFor documents.
	backend, err := podSandboxBackend(pod)
	vmBacked := err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM
	seams := r.probeSeamsFor(id, vmBacked)
	pr := newPodProber(pod, r.clk, func(c *corev1.Container, p *corev1.Probe) checkFunc {
		return r.buildCheck(id, podIP, seams, c, p)
	}, r.log)
	if pr == nil {
		return // no probes on any container
	}
	// A probe loop is a long-lived worker whose lifetime is the pod's, not any
	// single RPC's, so it roots a fresh cancelable context (cancelled by stop on
	// DeletePod) rather than a request context.
	ctx, cancel := context.WithCancel(context.Background())
	pr.cancel = cancel
	pr.onTransition = func() { r.publishStatusUpdate(ctx, id) }
	// restartFunc connects the restart DECISION (the prober owns the gate reset) to
	// the SHARED restart authority: a committed liveness failure routes through the
	// SAME per-container containerRestart bookkeeping and the SAME CrashLoopBackOff
	// schedule the exit-driven path uses, which then drives the runtime's
	// RestartContainer RPC. It deliberately does NOT call the RPC directly — that
	// bypass left the liveness restart invisible to the exit-driven bookkeeping and
	// let two authorities issue competing re-execs for one container.
	pr.restartFunc = r.restartForLiveness

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

// restartContainerReason is the shared RestartContainer RPC call — the ONE call
// site of the runtime re-exec action, reached only from the single restart
// authority's worker (runtimed_restart.go's runRestart), whichever TRIGGER
// scheduled it. runtimed bumps ContainerStatus.restart_count on this RPC: that
// count is the single restart authority the provider surfaces verbatim.
// grace_period_seconds is left 0 so runtimed applies its own default window. A
// typed failure in the response (e.g. the pod is gone) surfaces as an error the
// caller logs without aborting its loop.
func (r *runtimedRuntime) restartContainerReason(ctx context.Context, podID, container, reason string) error {
	resp, err := r.rt.RestartContainer(ctx, &runtimev1.RestartContainerRequest{
		PodId:     podID,
		Container: container,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("runtimed restart container %s/%s: %w", podID, container, err)
	}
	if e := resp.GetError(); e != nil && e.GetCode() != 0 {
		return fmt.Errorf("runtimed restart container %s/%s rejected: %s", podID, container, e.GetMessage())
	}
	return nil
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

// publishStatusUpdate re-renders the pod's status (with the prober overlay) and
// runs the VK callback, after a provider-side change the runtime's own status
// stream cannot report — a probe verdict, or a postStart hook completing. It
// reads the callback under the lock but invokes it OUTSIDE the lock (the VK
// NotifyPods re-entrancy rule), and no-ops if the pod was deleted concurrently. It
// renders via buildStatus — the single status assembly point — so such a publish
// carries the stable PodReady prior and the CrashLoopBackOff overlay (a
// probe tick while a re-exec is pending must not flash the pod Failed).
func (r *runtimedRuntime) publishStatusUpdate(ctx context.Context, id string) {
	r.mu.Lock()
	t, tracked := r.track[id]
	cb := r.notify
	pr := r.probers[id]
	var pod *corev1.Pod
	if tracked {
		pod = t.pod.DeepCopy()
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
	pod.Status = r.buildStatus(pod, t, resp.GetStatus(), ps)
	cb(pod)
}
