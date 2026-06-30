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
)

// Provider-served container lifecycle hooks (postStart / preStop). The Virtual
// Kubelet provider replaces the kubelet, so — exactly as it serves the pod's probes
// (runtimed_probe.go) — it must execute the pod's lifecycle hooks itself: runtimed
// neither receives nor runs them (toPodBox drops corev1 Lifecycle). The provider
// already retains the full Pod at create and delete, so the hooks are read from
// corev1 with NO apis/PodBox/runtimed change.
//
// Handler set: exec (the runtimed Exec RPC the exec-probe uses, runExecProbe),
// httpGet (the SAME host/port/scheme resolution buildCheck uses, over
// r.probeTransport), and sleep (a pure timer on r.clk). tcpSocket is NOT a valid
// lifecycle handler upstream, and an unknown/empty handler is IGNORED — hooks are
// advisory, so they fail OPEN (unlike a probe, whose unresolved handler fails the
// container).
//
// preStop is served in FULL: it runs BEFORE the runtimed DeletePod RPC (which fires
// SIGTERM synchronously inside that RPC), bounded by — and deducted from — the pod's
// termination grace budget, best-effort (a failed hook is logged; termination
// proceeds).
//
// postStart is DISPATCH-ONLY in B10: the hook is fired in a bounded goroutine after
// the container starts and a failure is logged, but the upstream failure-fidelity
// tail — gating container Ready on the hook, terminal-failing a restartPolicy:Never
// pod, restart-on-failure, and re-running postStart on container restart — is
// DEFERRED to its successor B39 (the provider has no per-container terminal-fail verb
// today; that is B8/B26-class runtimed integration work, out of scope for this
// provider-only unit).

// postStartHookTimeout bounds a dispatched postStart hook's goroutine so it cannot
// leak. Upstream does not time-cap postStart (it blocks container readiness), but
// B10 only DISPATCHES the hook — readiness-gating and proper pod-scoped lifetime are
// deferred to B39 — so a finite cap is the stopgap that keeps the fire-and-forget
// goroutine bounded.
const postStartHookTimeout = 2 * time.Minute

// runPostStart fires each container's postStart hook after the pod's containers are
// created, every hook in its own bounded goroutine so neither CreatePod nor the VK
// reconcile loop blocks on it (B10 dispatch-only — see the file comment; the
// readiness/terminal-fail fidelity is deferred to B39). podIP is the freshly bound
// pod IP (an httpGet hook's default host); it falls back to the node IP. The handler
// and port table are copied so the goroutine cannot race a later mutation of the
// caller's Pod.
func (r *runtimedRuntime) runPostStart(pod *corev1.Pod, podIP string) {
	if podIP == "" {
		podIP = r.nodeIP
	}
	id := string(pod.UID)
	ns, name := pod.Namespace, pod.Name
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Lifecycle == nil || c.Lifecycle.PostStart == nil {
			continue
		}
		h := c.Lifecycle.PostStart.DeepCopy()
		ports := append([]corev1.ContainerPort(nil), c.Ports...)
		cname := c.Name
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), postStartHookTimeout)
			defer cancel()
			if err := r.runHook(ctx, id, podIP, cname, ports, h, postStartHookTimeout); err != nil {
				// B39 will gate container Ready / terminal-fail / restart on this; B10
				// dispatches and logs only — a postStart failure is otherwise advisory.
				r.log.Warn("postStart hook failed", "pod", podKey(ns, name), "container", cname, "err", err)
			}
		}()
	}
}

// runPreStop runs each container's preStop hook BEFORE the runtimed DeletePod RPC
// (which sends SIGTERM synchronously) and returns the residual SIGTERM→SIGKILL grace
// (whole seconds) DeletePod must pass to runtimed.
//
// Grace accounting: the pod's termination budget (graceSeconds — the kubectl
// --grace-period override, else spec.terminationGracePeriodSeconds, else the k8s 30s
// default) covers BOTH the preStop hooks and the SIGTERM→SIGKILL window — the
// upstream contract is that the grace countdown starts before preStop. preStop is
// bounded by that budget; the residual returned is grace − ceil(preStopElapsed),
// FLOORED AT 1 so SIGTERM still fires even when preStop drained the budget (runtimed
// treats a resolved 0 as an immediate SIGKILL with NO SIGTERM — see the runtime
// server's graceDuration). A 0 budget (a --grace-period=0 force delete) skips preStop
// and returns 0, preserving the immediate-kill semantics (upstream also skips preStop
// on a force delete).
//
// preStop is best-effort: a failed or non-zero hook is logged and termination
// proceeds — it does NOT abort the delete (unlike a probe failure, which fails the
// container).
func (r *runtimedRuntime) runPreStop(ctx context.Context, pod *corev1.Pod) int64 {
	grace := graceSeconds(pod)
	if grace <= 0 {
		return grace // force/immediate delete: skip preStop, immediate SIGKILL
	}
	podIP := pod.Status.PodIP
	if podIP == "" {
		podIP = r.nodeIP
	}
	start := r.clk.Now()
	deadline := start.Add(time.Duration(grace) * time.Second)
	ran := false
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Lifecycle == nil || c.Lifecycle.PreStop == nil {
			continue
		}
		ran = true
		remaining := deadline.Sub(r.clk.Now())
		if remaining <= 0 {
			r.log.Warn("preStop grace budget exhausted; skipping remaining hooks",
				"pod", podKey(pod.Namespace, pod.Name), "container", c.Name)
			break
		}
		if err := r.runHook(ctx, string(pod.UID), podIP, c.Name, c.Ports, c.Lifecycle.PreStop, remaining); err != nil {
			r.log.Warn("preStop hook failed; proceeding with termination",
				"pod", podKey(pod.Namespace, pod.Name), "container", c.Name, "err", err)
		}
	}
	if !ran {
		return grace // no preStop hooks: pass the full grace through unchanged
	}
	residual := grace - ceilSeconds(r.clk.Since(start))
	if residual < 1 {
		residual = 1 // floor: a resolved 0 would skip SIGTERM (immediate SIGKILL)
	}
	return residual
}

// runHook dispatches one lifecycle handler for (podID, container), bounded by
// timeout, and returns the handler's error (the caller logs it; a hook never aborts
// create or delete). The supported handlers mirror the probe handlers' seams: exec
// over the runtime Exec RPC, httpGet over r.probeTransport with buildCheck's
// resolution, and sleep as a pure r.clk timer. tcpSocket (a no-op upstream) and any
// empty/unknown handler are ignored — hooks fail OPEN (advisory), unlike probes.
func (r *runtimedRuntime) runHook(ctx context.Context, podID, podIP, container string, ports []corev1.ContainerPort, h *corev1.LifecycleHandler, timeout time.Duration) error {
	switch {
	case h.Exec != nil:
		return runExecProbe(ctx, r.rt, podID, container, h.Exec.Command, timeout)
	case h.HTTPGet != nil:
		return r.httpGetCheck(podIP, container, ports, h.HTTPGet)(ctx, timeout)
	case h.Sleep != nil:
		return r.sleepHook(ctx, time.Duration(h.Sleep.Seconds)*time.Second, timeout)
	default:
		return nil // tcpSocket / empty: ignored (fail-open — hooks are advisory)
	}
}

// sleepHook blocks for want (clamped to the remaining budget) on r.clk, returning
// early if ctx is cancelled. A non-positive sleep is a no-op.
func (r *runtimedRuntime) sleepHook(ctx context.Context, want, budget time.Duration) error {
	if want > budget {
		want = budget
	}
	if want <= 0 {
		return nil
	}
	t := r.clk.NewTimer(want)
	defer t.Stop()
	select {
	case <-t.C():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ceilSeconds rounds a non-negative duration UP to whole seconds. preStop wall-time
// is charged against the integer-second grace budget conservatively (round up), so
// the residual SIGTERM→SIGKILL window never exceeds what the remaining budget allows.
func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}
