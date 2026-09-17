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
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// The two ports the gate's pod is probed on. They are different so one recorder
// can tell the tcpSocket dial from the httpGet one: the two travel through
// different seams (a dialFunc vs. an http.Transport's DialContext) and a fix that
// resolved only one of them would look green on the other.
const (
	probeTCPPort  int32 = 9001
	probeHTTPPort int32 = 9002
	probePeriod         = time.Second // the smallest a corev1 Probe can express
)

// probeTarget is the fake network every probe dial lands on. It records the
// address each attempt ASKED for — after the provider's resolution, which is the
// value under assertion — and then answers only for hosts the case declared
// reachable, refusing everything else.
//
// The refusal is the physical fact the gate is about: a vm pod's published /32 is
// live on NO interface, so a probe dialed there does not time out politely, it is
// never answered at all. A recorder that quietly succeeded for every address
// would hide the very bug (readiness stuck false, liveness restarting a healthy
// guest) this test exists to catch.
type probeTarget struct {
	lis *bufconn.Listener

	mu        sync.Mutex
	dials     []string
	reachable map[string]bool
}

// newProbeTarget starts an in-memory HTTP server (no real network) that answers
// 200 on any path, so a resolved httpGet probe passes and a resolved tcpSocket
// probe connects.
func newProbeTarget(t *testing.T) *probeTarget {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &probeTarget{lis: lis, reachable: map[string]bool{}}
}

// serve declares host reachable: dials to it are answered by the in-memory server.
func (p *probeTarget) serve(host string) {
	p.mu.Lock()
	p.reachable[host] = true
	p.mu.Unlock()
}

// dial is the runtime's r.dial seam — the one place every probe dial converges,
// tcp and httpGet alike, once the prober's transport is built on it.
func (p *probeTarget) dial(ctx context.Context, _, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	p.mu.Lock()
	p.dials = append(p.dials, address)
	reachable := err == nil && p.reachable[host]
	p.mu.Unlock()
	if !reachable {
		return nil, fmt.Errorf("dial %s: connection refused (no interface holds that address)", address)
	}
	return p.lis.DialContext(ctx)
}

// dialed is every address asked for so far, in order.
func (p *probeTarget) dialed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.dials)
}

// count is how many dials have been attempted.
func (p *probeTarget) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.dials)
}

// hostsAt is the set of hosts dialed on the given port.
func (p *probeTarget) hostsAt(port int32) []string {
	var out []string
	for _, a := range p.dialed() {
		h, prt, err := net.SplitHostPort(a)
		if err != nil || prt != fmt.Sprint(port) {
			continue
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// assertOnlyDialed fails when any dial went somewhere other than want.
func (p *probeTarget) assertOnlyDialed(t *testing.T, want string) {
	t.Helper()
	for _, a := range p.dialed() {
		if h, _, err := net.SplitHostPort(a); err != nil || h != want {
			t.Errorf("a probe dialed %q; the only address that may be dialed is %s (all dials: %v)", a, want, p.dialed())
		}
	}
}

// withGateProbes gives pod's container the two probes the gate drives: a
// tcpSocket READINESS probe (whose verdict drives the container's Ready flag and
// so its Service membership) and an httpGet LIVENESS probe (whose committed
// failure restarts the container). Both default their host to the pod's own
// address, which is the whole subject: for a vm pod that address answers nowhere.
//
// The thresholds are the smallest that still mean something — two consecutive
// failures commit either verdict — so an unresolved dial shows up within two
// periods rather than being lost in the default's slack. The per-attempt timeout
// is deliberately NOT tightened to match: a refused dial returns at once, so the
// timeout governs only how much CPU contention from the rest of this package a
// SERVED dial may absorb before it is miscounted as a failure.
func withGateProbes(pod *corev1.Pod) *corev1.Pod {
	c := &pod.Spec.Containers[0]
	c.ReadinessProbe = &corev1.Probe{
		ProbeHandler:     corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(probeTCPPort)}},
		PeriodSeconds:    1,
		TimeoutSeconds:   3,
		SuccessThreshold: 1,
		FailureThreshold: 2,
	}
	c.LivenessProbe = &corev1.Probe{
		ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(probeHTTPPort)}},
		PeriodSeconds:    1,
		TimeoutSeconds:   3,
		FailureThreshold: 2,
	}
	return pod
}

// probeNode is the leaseNode assembled for a probe case: the runtimed fake
// ANSWERS CreatePod with a status the way the real one does (so the prober is
// built against the pod's published /32, not a fallback), and every probe dial is
// routed to the recorder.
type probeNode struct {
	*leaseNode
	tgt *probeTarget
}

func newProbeNode(t *testing.T) *probeNode {
	t.Helper()
	n := newLeaseNode(t)
	n.rt.createStatus = true
	tgt := newProbeTarget(t)
	n.r.dial = tgt.dial
	return &probeNode{leaseNode: n, tgt: tgt}
}

// start watches, creates the probed pod, and blocks until the create's own status
// observation has been delivered. That last step is the ordering the cases depend
// on: the create snapshot carries no lease, so letting it land AFTER a pushed one
// would retract the very override the case installed.
func (n *probeNode) start(t *testing.T, pod *corev1.Pod) string {
	t.Helper()
	id := string(pod.UID)
	n.watch(t)
	if err := n.r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	t.Cleanup(func() { _ = n.r.DeletePod(context.Background(), pod) })
	n.awaitStatus(t, id, 1)
	if n.r.proberFor(id) == nil {
		t.Fatalf("no prober for %s; the pod's probes were never started", id)
	}
	return id
}

// verdictOf returns the prober's published verdict for c0. ok is false while the
// pod's probes are not evaluable (the pending-lease window), which is what leaves
// the RUNTIME's container status untouched and the pod-level transport condition
// as the one an operator reads.
func (n *probeNode) verdictOf(podID string) (probeVerdict, bool) {
	ps := n.r.proberFor(podID)
	if ps == nil {
		return probeVerdict{}, false
	}
	return ps.verdict("c0")
}

// hasVerdict reports whether the prober publishes any verdict for c0.
func (n *probeNode) hasVerdict(podID string) bool {
	_, ok := n.verdictOf(podID)
	return ok
}

// probeReady reports whether the READINESS probe itself has committed a success —
// the container is Ready BECAUSE it was probed, not because an unevaluated
// verdict let the runtime's own flag through.
func (n *probeNode) probeReady(podID string) bool {
	v, ok := n.verdictOf(podID)
	return ok && v.ready
}

// awaitReadyReason blocks until the PUBLISHED PodReady is False with the given
// reason, and returns it.
func (n *probeNode) awaitReadyReason(t *testing.T, podID, reason string) corev1.PodCondition {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if c := findPodCondition(n.conditions(podID), corev1.PodReady); c != nil &&
			c.Status == corev1.ConditionFalse && c.Reason == reason {
			return *c
		}
		select {
		case <-n.notify:
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			got := "<absent>"
			if c := findPodCondition(n.conditions(podID), corev1.PodReady); c != nil {
				got = string(c.Status) + "/" + c.Reason
			}
			t.Fatalf("published PodReady for %s = %s, want False/%s (dials=%v restarts=%d verdict-published=%v)",
				podID, got, reason, n.tgt.dialed(), n.rt.restartCount(), n.hasVerdict(podID))
		}
	}
}

// TestVMPodProbesDialTheLiveGuestAddress is the B318 named gate: a vm pod's
// probes must be dialed at the guest's LIVE lease, never at the published /32
// they were resolved against — and while no lease is held they must not be dialed
// at all.
//
// WHY IT IS NOT VACUOUS. It drives the REAL prober the real CreatePod starts,
// through the real check builders, over the pod's own published /32 as drawn by
// the node's allocator (read back from the adapter, not handed in at both ends).
// The recorder REFUSES every address but the one the case declares reachable, so
// each leg's verdict is a physical fact and not a bookkeeping one: dialing the
// published address fails, and the same probes that hang forever in the pending
// window succeed the moment the lease is resolved. The negative legs are what
// give the positive ones meaning — leg 2 proves the probes do dial once a lease
// exists (so leg 1's silence is the gate, not a prober that never ran), and leg 4
// proves a native pod's probes are untouched (so the resolution is vm-scoped
// rather than a blanket redirect).
func TestVMPodProbesDialTheLiveGuestAddress(t *testing.T) {
	t.Parallel()

	t.Run("no lease: the probes are not dialed, not failed, and nothing is restarted", func(t *testing.T) {
		t.Parallel()
		n := newProbeNode(t)
		pod := withGateProbes(vmPod("team-a", "pending"))
		id := n.start(t, pod)
		// The node DID provision a guest for this pod, so the silence below is the
		// missing lease and not a pod that never took the vm path.
		pub := n.published(t, id)

		waitCond(t, "the prober to report its probes as not evaluable", func() bool { return !n.hasVerdict(id) })

		// Several periods of both probes: an unresolved dial would have been made
		// by now, and a liveness probe counting those refusals would have committed
		// its second failure and restarted the container.
		time.Sleep(4 * probePeriod)
		if got := n.tgt.dialed(); len(got) != 0 {
			t.Errorf("a probe dialed %v while the guest held no lease; the published address %s answers nowhere", got, pub)
		}
		if got := n.rt.restartCount(); got != 0 {
			t.Errorf("RestartContainer was called %d times during the pending-lease window, want 0", got)
		}

		// The reason an operator reads names the window's real owner. The container
		// is left exactly as the runtime reported it (Running and Ready): this node
		// has verified nothing about it, so it asserts nothing — and the pod-level
		// gate is what keeps the pod out of its Services meanwhile.
		n.rt.push(t, id, "")
		ready := n.awaitReadyReason(t, id, reasonGuestTransportNotReady)
		if ready.Message == "" {
			t.Error("the withheld PodReady carries no message")
		}
		if got := condStatusOf(n.conditions(id), corev1.ContainersReady); got != string(corev1.ConditionTrue) {
			t.Errorf("ContainersReady = %s, want True — an unevaluated probe must not demote the runtime's verdict", got)
		}
	})

	t.Run("a lease arriving after the prober started redirects both probes", func(t *testing.T) {
		t.Parallel()
		n := newProbeNode(t)
		pod := withGateProbes(vmPod("team-a", "leased"))
		id := n.start(t, pod)
		pub := n.published(t, id)
		n.tgt.serve(leaseFirst) // only the guest's lease answers, as on a real node

		waitCond(t, "the prober to report its probes as not evaluable", func() bool { return !n.hasVerdict(id) })

		// The guest leases. The probes were resolved against pub at CreatePod and
		// are never rebuilt, so only a PER-ATTEMPT resolution can reach the guest.
		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
		waitCond(t, "both the tcpSocket and the httpGet probe to dial the live guest address", func() bool {
			return slices.Contains(n.tgt.hostsAt(probeTCPPort), leaseFirst) &&
				slices.Contains(n.tgt.hostsAt(probeHTTPPort), leaseFirst)
		})
		n.tgt.assertOnlyDialed(t, leaseFirst)

		// End to end: the readiness probe now SUCCEEDS against the guest, so the
		// container is Ready BY VERDICT — the outcome the published address could
		// never produce — and the pod joins its Services.
		waitCond(t, "the readiness probe to commit a success against the guest", func() bool { return n.probeReady(id) })
		n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)
		if got := n.rt.restartCount(); got != 0 {
			t.Errorf("RestartContainer was called %d times for a healthy guest, want 0", got)
		}
	})

	t.Run("a dropped lease stops the dialing again", func(t *testing.T) {
		t.Parallel()
		n := newProbeNode(t)
		pod := withGateProbes(vmPod("team-a", "lost"))
		id := n.start(t, pod)
		pub := n.published(t, id)
		n.tgt.serve(leaseFirst)

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
		// BOTH probes must have run against the guest before the lease is pulled:
		// this leg is about a pod that was being probed and serving, which is the
		// state a lease loss actually interrupts.
		waitCond(t, "both probes to reach the guest and readiness to commit", func() bool {
			return n.probeReady(id) && slices.Contains(n.tgt.hostsAt(probeHTTPPort), leaseFirst)
		})
		n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)

		// The guest rebooted and has not leased again. There is no address to probe
		// at, so the probes stop — they do not fall back to the published /32, and
		// they do not accumulate failures against a window the runtime owns.
		n.rt.push(t, id, "")
		n.awaitOverrides(t, map[string]string{})
		// The last verdict this node actually observed is FROZEN, not reverted: the
		// container was Ready when it was last reachable, and pretending otherwise
		// would blame the container for the node's lost route. The pod-level reason
		// names the guest lease, exactly as it did before the pod ever leased.
		n.awaitReadyReason(t, id, reasonGuestTransportNotReady)
		if !n.probeReady(id) {
			t.Error("the readiness verdict was reverted by the lease loss; a frozen verdict is the last thing this node observed")
		}

		before := n.tgt.count()
		time.Sleep(3 * probePeriod)
		if got := n.tgt.count(); got != before {
			t.Errorf("%d further dials after the lease was dropped: %v", got-before, n.tgt.dialed()[before:])
		}
		n.tgt.assertOnlyDialed(t, leaseFirst)
		if got := n.rt.restartCount(); got != 0 {
			t.Errorf("RestartContainer was called %d times after the lease was lost, want 0", got)
		}
	})

	t.Run("a lease lost after the front check is not evaluated for a grpc probe", func(t *testing.T) {
		t.Parallel()
		// A real grpc.health.v1 server over bufconn (no real network). The SERVING
		// row below runs first so the pending row is a VERDICT about the lease and
		// not a broken wire.
		lis := bufconn.Listen(1 << 20)
		gs := grpc.NewServer()
		hsrv := health.NewServer()
		grpc_health_v1.RegisterHealthServer(gs, hsrv)
		go func() { _ = gs.Serve(lis) }()
		t.Cleanup(gs.Stop)
		hsrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

		r, _ := newRuntimedFake(t)
		var lost atomic.Bool
		// The seams a vm pod's prober holds, with the lease loss placed in exactly
		// the window a pre-check cannot see: pending() answers "still leased" —
		// it ran before the loss — and the dial then refuses. Two reads of one
		// lease can always straddle a drop; the question this leg settles is which
		// of them the runner is told about.
		seams := probeSeams{
			transport: newProbeTransport(),
			pending:   func() error { return nil },
			dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if lost.Load() {
					return nil, fmt.Errorf("pod uid: the guest has not reported its transport address yet: %w",
						errProbeTargetPending)
				}
				return lis.DialContext(ctx)
			},
		}
		check := r.buildCheck("uid", "10.0.0.5", seams,
			&corev1.Container{Name: "c0"},
			&corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 50051}}})
		pp := &podProber{podID: "uid", log: slog.New(slog.DiscardHandler)}
		spec := &probeSpec{sched: probeSchedule{timeout: 5 * time.Second}, check: check}

		if outcome, evaluated := pp.runCheck(context.Background(), "c0", probeLiveness, spec); outcome != outcomeSuccess || !evaluated {
			t.Fatalf("a SERVING guest → (%v, evaluated=%v), want (success, true)", outcome, evaluated)
		}

		lost.Store(true)
		outcome, evaluated := pp.runCheck(context.Background(), "c0", probeLiveness, spec)
		if evaluated || outcome != outcomeUnknown {
			t.Errorf("a lease lost after the front check → (%v, evaluated=%v), want (unknown, false): "+
				"this tick must move no gauge in either direction", outcome, evaluated)
		}

		// WHY THE CARRIER EXISTS, pinned rather than asserted in prose: gRPC turns
		// the dialer's refusal into a status error, so the sentinel does NOT
		// survive the call itself. errors.Is on the returned error alone — the
		// mechanism every other handler relies on — would have counted this tick
		// as a liveness failure.
		raw := grpcProbe(seams.dial, "10.0.0.5", 50051, "")(context.Background(), 5*time.Second)
		if raw == nil {
			t.Fatal("the naked grpc check passed against a refused dial")
		}
		if errors.Is(raw, errProbeTargetPending) {
			t.Error("gRPC now preserves the dial's error chain; the per-attempt carrier may be reducible to errors.Is")
		}
	})

	t.Run("a native pod's probes dial its published address unchanged", func(t *testing.T) {
		t.Parallel()
		n := newProbeNode(t)
		pod := withGateProbes(hostPod("team-a", "native"))
		id := n.start(t, pod)
		// The /32 the node's IPAM carved, as the created box carried it — a native
		// pod's published address IS live (on lo0), so it is the address to probe.
		pub := n.rt.boxPodIP(id)
		if pub == "" || pub == guestNodeIP {
			t.Fatalf("the native pod's box pod_ip = %q; it must be a pod /32, not the node IP", pub)
		}
		if _, ok := n.adapt.GuestNetwork(id); ok {
			t.Fatal("the adapter recorded a guest network for a host-process pod")
		}
		n.tgt.serve(pub)

		waitCond(t, "both probes to dial the pod's published address", func() bool {
			return slices.Contains(n.tgt.hostsAt(probeTCPPort), pub) &&
				slices.Contains(n.tgt.hostsAt(probeHTTPPort), pub)
		})
		n.tgt.assertOnlyDialed(t, pub)
		n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)
		if sets, live := n.sink.snapshot(); sets != 0 {
			t.Errorf("the sink was called %d times (last=%v) for a host-process pod", sets, renderOverrides(live))
		}
	})
}
