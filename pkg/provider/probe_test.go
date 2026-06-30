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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- test helpers -----------------------------------------------------------

// noopCheckFactory builds a check that always succeeds; the FSM/gating tests
// drive outcomes via observe directly, so the check itself is never run.
func noopCheckFactory(*corev1.Container, *corev1.Probe) checkFunc {
	return func(context.Context, time.Duration) error { return nil }
}

func tcpHandler(port int32) corev1.ProbeHandler {
	return corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt(int(port))}}
}

func probePod(name string, containers ...corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{Containers: containers},
	}
}

// runningProto is a runtime PodStatus with one running, runtime-Ready container —
// the baseline the probe overlay then rewrites.
func runningProto(podID, cname string) *runtimev1.PodStatus {
	return &runtimev1.PodStatus{
		PodId: podID,
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "10.0.0.5",
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name:  cname,
			Ready: true,
			State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(time.Unix(1000, 0))}},
		}},
	}
}

// feed pushes one raw outcome through the monitor and applies the same restart
// bookkeeping tick does, so verdict().restarts reflects a real restart.
func feed(m *containerMonitor, kind probeKind, raw probeOutcome) probeReaction {
	react := m.observe(kind, raw)
	if react == reactRestart {
		m.onRestart()
	}
	return react
}

func condStatus(st *corev1.PodStatus, ct corev1.PodConditionType) corev1.ConditionStatus {
	for _, c := range st.Conditions {
		if c.Type == ct {
			return c.Status
		}
	}
	return corev1.ConditionUnknown
}

// waitWaiters blocks until the fake clock has at least n registered timers (the
// probe loops have parked), so a test can Step deterministically without racing
// the goroutines. It uses millisecond polling, never real-second sleeps.
func waitWaiters(t *testing.T, clk *testclock.FakeClock, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if clk.Waiters() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("clock never reached %d waiters (have %d)", n, clk.Waiters())
}

func waitAtLeast(t *testing.T, c *atomic.Int32, n int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter never reached %d (have %d)", n, c.Load())
}

// fakeRoundTripper returns a scripted HTTP status (or error) and records the URL
// the httpGet probe built — proving named-port resolution without a real socket.
type fakeRoundTripper struct {
	status int
	err    error
	gotURL string
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.gotURL = req.URL.String()
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Header:     make(http.Header),
	}, nil
}

// fakeExecServer is a RuntimeServer whose Exec returns a scripted exit code, so
// the exec probe's exit-code mapping is tested without a real process.
type fakeExecServer struct {
	runtimev1.UnimplementedRuntimeServer
	exitCode int32
	err      error
}

func (f *fakeExecServer) Exec(stream grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	if f.err != nil {
		return f.err
	}
	if _, err := stream.Recv(); err != nil {
		return err
	}
	return stream.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: f.exitCode}})
}

// --- TestM2_ProbeThresholds --------------------------------------------------

// TestM2_ProbeThresholds proves success/failureThreshold consecutive-counting and
// that the per-probe timeout is honored (driven by a fake clock; no real sleeps).
func TestM2_ProbeThresholds(t *testing.T) {
	t.Run("failureThreshold commits only after N consecutive failures", func(t *testing.T) {
		g := newProbeGauge(1, 3, outcomeSuccess) // liveness-like
		if got := g.record(outcomeFailure); got != outcomeSuccess {
			t.Fatalf("after 1 failure committed=%v, want still success", got)
		}
		if got := g.record(outcomeFailure); got != outcomeSuccess {
			t.Fatalf("after 2 failures committed=%v, want still success", got)
		}
		if got := g.record(outcomeFailure); got != outcomeFailure {
			t.Fatalf("after 3 failures committed=%v, want failure", got)
		}
	})

	t.Run("successThreshold commits only after N consecutive successes", func(t *testing.T) {
		g := newProbeGauge(2, 1, outcomeFailure) // readiness-like, successThreshold 2
		if got := g.record(outcomeSuccess); got != outcomeFailure {
			t.Fatalf("after 1 success committed=%v, want still failure", got)
		}
		if got := g.record(outcomeSuccess); got != outcomeSuccess {
			t.Fatalf("after 2 successes committed=%v, want success", got)
		}
	})

	t.Run("an interrupting result resets the run", func(t *testing.T) {
		g := newProbeGauge(1, 3, outcomeSuccess)
		g.record(outcomeFailure)
		g.record(outcomeFailure)
		g.record(outcomeSuccess) // resets the failure run
		if got := g.record(outcomeFailure); got != outcomeSuccess {
			t.Fatalf("committed=%v, want success — the failure run must have reset", got)
		}
	})

	t.Run("timeout honored — the configured timeout reaches the check", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		gotTimeout := make(chan time.Duration, 4)
		mk := func(*corev1.Container, *corev1.Probe) checkFunc {
			return func(_ context.Context, to time.Duration) error { gotTimeout <- to; return nil }
		}
		pod := probePod("to", corev1.Container{
			Name: "c0",
			ReadinessProbe: &corev1.Probe{
				ProbeHandler:        tcpHandler(8080),
				InitialDelaySeconds: 5,
				PeriodSeconds:       10,
				TimeoutSeconds:      2,
			},
		})
		pp := newPodProber(pod, clk, mk, nil)
		ctx, cancel := context.WithCancel(context.Background())
		pp.cancel = cancel
		pp.start(ctx)
		defer pp.stop()

		waitWaiters(t, clk, 1) // parked on the 5s initial-delay timer
		clk.Step(5 * time.Second)
		select {
		case to := <-gotTimeout:
			if to != 2*time.Second {
				t.Fatalf("check received timeout %v, want 2s", to)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("probe never ran after the initial delay")
		}
	})
}

// --- TestM2_StartupGatesLiveness ---------------------------------------------

// TestM2_StartupGatesLiveness proves a liveness probe cannot run or fail until the
// startup probe first succeeds.
func TestM2_StartupGatesLiveness(t *testing.T) {
	c := corev1.Container{
		Name:          "c0",
		StartupProbe:  &corev1.Probe{ProbeHandler: tcpHandler(8080), FailureThreshold: 3},
		LivenessProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), FailureThreshold: 3},
	}
	m := newContainerMonitor(&c, noopCheckFactory)

	if m.shouldProbe(probeLiveness) {
		t.Fatal("liveness must not run before startup succeeds")
	}
	// Liveness failures while the startup gate is closed must NOT restart.
	for i := 0; i < 6; i++ {
		if react := feed(m, probeLiveness, outcomeFailure); react != reactNone {
			t.Fatalf("liveness reaction %v before startup; want none", react)
		}
	}
	if got := m.verdict().restarts; got != 0 {
		t.Fatalf("restarts=%d before startup, want 0", got)
	}

	// Open the startup gate (successThreshold forced to 1).
	if react := feed(m, probeStartup, outcomeSuccess); react != reactPublish {
		t.Fatalf("startup success reaction %v, want publish (gate opened)", react)
	}
	if !m.verdict().started {
		t.Fatal("started must be true after the startup probe succeeds")
	}
	if !m.shouldProbe(probeLiveness) {
		t.Fatal("liveness must run once started")
	}

	// Now liveness is live: 3 consecutive failures restart exactly once.
	if feed(m, probeLiveness, outcomeFailure) != reactNone || feed(m, probeLiveness, outcomeFailure) != reactNone {
		t.Fatal("liveness should not restart before failureThreshold")
	}
	if react := feed(m, probeLiveness, outcomeFailure); react != reactRestart {
		t.Fatalf("3rd liveness failure reaction %v, want restart", react)
	}
	if got := m.verdict().restarts; got != 1 {
		t.Fatalf("restarts=%d after startup+liveness fail, want 1", got)
	}
}

// --- TestM2_LivenessRestarts -------------------------------------------------

// TestM2_LivenessRestarts proves failureThreshold consecutive liveness failures
// restart the container (restart_count increments and surfaces in the status),
// while a passing liveness probe never restarts it.
func TestM2_LivenessRestarts(t *testing.T) {
	pod := probePod("liveness", corev1.Container{
		Name:          "c0",
		LivenessProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), FailureThreshold: 3},
	})
	pp := newPodProber(pod, testclock.NewFakeClock(time.Unix(0, 0)), noopCheckFactory, nil)
	m := pp.monitors["c0"]

	// A healthy liveness probe never restarts.
	for i := 0; i < 5; i++ {
		if react := feed(m, probeLiveness, outcomeSuccess); react != reactNone {
			t.Fatalf("passing liveness reaction %v, want none", react)
		}
	}
	if got := m.verdict().restarts; got != 0 {
		t.Fatalf("restarts=%d after passing liveness, want 0", got)
	}

	// failureThreshold (3) consecutive failures restart once.
	feed(m, probeLiveness, outcomeFailure)
	feed(m, probeLiveness, outcomeFailure)
	if react := feed(m, probeLiveness, outcomeFailure); react != reactRestart {
		t.Fatalf("3rd failure reaction %v, want restart", react)
	}
	if got := m.verdict().restarts; got != 1 {
		t.Fatalf("restarts=%d, want 1", got)
	}

	// The restart count surfaces in the published status.
	st := toPodStatus(nil, runningProto("uid-liveness", "c0"), "192.168.1.10", metav1.Now(), pp)
	if st.ContainerStatuses[0].RestartCount != 1 {
		t.Fatalf("status RestartCount=%d, want 1", st.ContainerStatuses[0].RestartCount)
	}

	// After the gauge resets, another 3 failures restart again (no storm per fail).
	feed(m, probeLiveness, outcomeFailure)
	feed(m, probeLiveness, outcomeFailure)
	if react := feed(m, probeLiveness, outcomeFailure); react != reactRestart {
		t.Fatalf("second cycle 3rd failure reaction %v, want restart", react)
	}
	if got := m.verdict().restarts; got != 2 {
		t.Fatalf("restarts=%d after two cycles, want 2", got)
	}
}

// --- TestProbeRestartInvokesRPC ----------------------------------------------

// TestProbeRestartInvokesRPC is the M2.2-swap proof that a committed liveness
// failure does not just bump bookkeeping but invokes the runtime RestartContainer
// RPC (the restartFunc seam, previously nil, now wired by startProber). It drives
// failureThreshold consecutive liveness failures through the real prober the
// runtimed runtime starts at CreatePod and asserts the RPC fired exactly once for
// the right (pod, container) while the probe-driven restart count incremented.
func TestProbeRestartInvokesRPC(t *testing.T) {
	r, f := newRuntimedFake(t)
	r.clk = testclock.NewFakeClock(time.Unix(0, 0))
	// A dialer that always refuses, so the tcpSocket liveness check fails each tick.
	r.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	ctx := context.Background()

	pod := probePod("live", corev1.Container{
		Name:    "c0",
		Command: []string{"/web"},
		LivenessProbe: &corev1.Probe{
			ProbeHandler:        tcpHandler(8080),
			InitialDelaySeconds: 3600, // park the live loop; the test drives ticks itself
			FailureThreshold:    3,
		},
	})
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

	pp, ok := r.proberFor("uid-live").(*podProber)
	if !ok {
		t.Fatal("a probed pod must have a prober after CreatePod")
	}
	m := pp.monitors["c0"]

	// failureThreshold (3) consecutive liveness failures: the 3rd crosses the
	// threshold and must invoke RestartContainer exactly once (not per failure).
	for i := 0; i < 3; i++ {
		pp.tick(ctx, m, probeLiveness, m.liveness)
	}

	if got := m.verdict().restarts; got != 1 {
		t.Fatalf("probe-driven restarts = %d, want 1", got)
	}
	f.mu.Lock()
	calls, last := f.restartCalls, f.lastRestart
	f.mu.Unlock()
	if calls != 1 {
		t.Fatalf("RestartContainer RPC calls = %d, want 1 (action wired to the seam)", calls)
	}
	if last.podID != "uid-live" || last.container != "c0" {
		t.Errorf("RestartContainer called with (%q,%q), want (uid-live,c0)", last.podID, last.container)
	}

	// The probe-driven restart surfaces in the published status (restart_count).
	st := toPodStatus(nil, runningProto("uid-live", "c0"), r.nodeIP, metav1.Now(), pp)
	if st.ContainerStatuses[0].RestartCount != 1 {
		t.Errorf("status RestartCount = %d, want 1", st.ContainerStatuses[0].RestartCount)
	}
}

// --- TestM2_ReadinessGatesEndpoints ------------------------------------------

// TestM2_ReadinessGatesEndpoints proves a readiness probe drives the container
// Ready and thus the pod Ready/ContainersReady conditions — the signal the
// EndpointSlice controller uses to add/remove the pod from a Service's endpoints.
// It asserts the transitions (not-ready→ready→not-ready→ready), not just
// eventual readiness.
func TestM2_ReadinessGatesEndpoints(t *testing.T) {
	pod := probePod("ready", corev1.Container{
		Name:           "c0",
		ReadinessProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), SuccessThreshold: 1, FailureThreshold: 2},
	})
	pp := newPodProber(pod, testclock.NewFakeClock(time.Unix(0, 0)), noopCheckFactory, nil)
	m := pp.monitors["c0"]

	ready := func() corev1.ConditionStatus {
		return condStatus(toPodStatus(nil, runningProto("uid-ready", "c0"), "192.168.1.10", metav1.Now(), pp), corev1.PodReady)
	}
	containersReady := func() corev1.ConditionStatus {
		return condStatus(toPodStatus(nil, runningProto("uid-ready", "c0"), "192.168.1.10", metav1.Now(), pp), corev1.ContainersReady)
	}

	// Until the readiness probe first succeeds, the container is NOT ready (so it
	// is absent from the EndpointSlice).
	if got := ready(); got != corev1.ConditionFalse {
		t.Fatalf("initial PodReady=%v, want False (not ready until first success)", got)
	}

	// First success → Ready (added to endpoints).
	if feed(m, probeReadiness, outcomeSuccess) != reactPublish {
		t.Fatal("first readiness success should publish a transition")
	}
	if got := ready(); got != corev1.ConditionTrue {
		t.Fatalf("PodReady=%v after success, want True", got)
	}
	if got := containersReady(); got != corev1.ConditionTrue {
		t.Fatalf("ContainersReady=%v after success, want True", got)
	}

	// One failure is below the threshold of 2 — still Ready.
	if react := feed(m, probeReadiness, outcomeFailure); react != reactNone {
		t.Fatalf("1st failure reaction %v, want none (below failureThreshold)", react)
	}
	if got := ready(); got != corev1.ConditionTrue {
		t.Fatalf("PodReady=%v after one failure, want still True", got)
	}

	// Second consecutive failure crosses the threshold → NotReady (removed from
	// the EndpointSlice).
	if react := feed(m, probeReadiness, outcomeFailure); react != reactPublish {
		t.Fatalf("2nd failure reaction %v, want publish (flips NotReady)", react)
	}
	if got := ready(); got != corev1.ConditionFalse {
		t.Fatalf("PodReady=%v after failureThreshold, want False (endpoint removed)", got)
	}
	if got := containersReady(); got != corev1.ConditionFalse {
		t.Fatalf("ContainersReady=%v after failureThreshold, want False", got)
	}

	// Recovery: a success flips it back to Ready (re-added to the EndpointSlice).
	if feed(m, probeReadiness, outcomeSuccess) != reactPublish {
		t.Fatal("recovery success should publish a transition")
	}
	if got := ready(); got != corev1.ConditionTrue {
		t.Fatalf("PodReady=%v after recovery, want True", got)
	}
}

// --- TestM2_ProbeHandlers ----------------------------------------------------

// TestM2_ProbeHandlers proves the three handlers' success/failure mapping and that
// a named probe port resolves against the container's port table.
func TestM2_ProbeHandlers(t *testing.T) {
	ctx := context.Background()

	t.Run("httpGet 2xx/3xx success, 5xx failure", func(t *testing.T) {
		for _, tc := range []struct {
			status  int
			wantErr bool
		}{{200, false}, {204, false}, {301, false}, {404, true}, {500, true}} {
			rt := &fakeRoundTripper{status: tc.status}
			err := httpProbe(rt, "HTTP", "10.0.0.5", 8080, "/healthz", nil)(ctx, time.Second)
			if (err != nil) != tc.wantErr {
				t.Errorf("status %d: err=%v, wantErr=%v", tc.status, err, tc.wantErr)
			}
			if !strings.Contains(rt.gotURL, "10.0.0.5:8080/healthz") {
				t.Errorf("status %d: built URL %q missing host:port/path", tc.status, rt.gotURL)
			}
		}
	})

	t.Run("httpGet transport error is failure", func(t *testing.T) {
		rt := &fakeRoundTripper{err: errors.New("dial tcp: refused")}
		if err := httpProbe(rt, "HTTP", "10.0.0.5", 8080, "/", nil)(ctx, time.Second); err == nil {
			t.Error("transport error should be a probe failure")
		}
	})

	t.Run("tcpSocket dial success / refused", func(t *testing.T) {
		var gotAddr string
		dialOK := func(_ context.Context, _, addr string) (net.Conn, error) {
			gotAddr = addr
			c, _ := net.Pipe()
			return c, nil
		}
		if err := tcpProbe(dialOK, "10.0.0.5", 9000)(ctx, time.Second); err != nil {
			t.Errorf("successful dial should pass: %v", err)
		}
		if gotAddr != "10.0.0.5:9000" {
			t.Errorf("dialed %q, want 10.0.0.5:9000", gotAddr)
		}
		dialRefused := func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}
		if err := tcpProbe(dialRefused, "10.0.0.5", 9000)(ctx, time.Second); err == nil {
			t.Error("refused dial should fail")
		}
	})

	t.Run("exec exit 0 success, non-zero failure", func(t *testing.T) {
		if err := runExecProbe(ctx, &fakeExecServer{exitCode: 0}, "uid", "c0", []string{"sh", "-c", "true"}, time.Second); err != nil {
			t.Errorf("exit 0 should succeed: %v", err)
		}
		if err := runExecProbe(ctx, &fakeExecServer{exitCode: 2}, "uid", "c0", []string{"sh", "-c", "false"}, time.Second); err == nil {
			t.Error("non-zero exit should fail")
		}
	})

	t.Run("resolvePort: int, named, and missing", func(t *testing.T) {
		ports := []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}, {Name: "metrics", ContainerPort: 9090}}
		if p, ok := resolvePort(intstr.FromInt(1234), ports); !ok || p != 1234 {
			t.Errorf("int port → (%d,%v), want (1234,true)", p, ok)
		}
		if p, ok := resolvePort(intstr.FromString("metrics"), ports); !ok || p != 9090 {
			t.Errorf("named metrics → (%d,%v), want (9090,true)", p, ok)
		}
		if _, ok := resolvePort(intstr.FromString("nope"), ports); ok {
			t.Error("unknown named port must not resolve")
		}
	})

	t.Run("named port resolves end-to-end through buildCheck", func(t *testing.T) {
		r, _ := newRuntimedFake(t)
		rt := &fakeRoundTripper{status: 200}
		r.probeTransport = rt
		c := &corev1.Container{Name: "c0", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}
		p := &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/h", Port: intstr.FromString("http")}}}
		check := r.buildCheck("uid", "10.0.0.5", c, p)
		if err := check(ctx, time.Second); err != nil {
			t.Fatalf("named-port httpGet check: %v", err)
		}
		if !strings.Contains(rt.gotURL, "10.0.0.5:8080/h") {
			t.Errorf("named port did not resolve: built URL %q", rt.gotURL)
		}
	})
}

// --- integration + lifecycle -------------------------------------------------

// TestRuntimedProbeReadinessOverlaysStatus is the integration proof that CreatePod
// starts a provider-served prober and its verdict overlays the runtime status:
// a container with a readiness probe is reported NotReady (absent from endpoints)
// until the probe first succeeds, even though the runtime reports it Ready. The
// fake clock is never stepped, so no probe I/O runs — the assertion is on the
// initial (pre-first-success) verdict.
func TestRuntimedProbeReadinessOverlaysStatus(t *testing.T) {
	r, _ := newRuntimedFake(t)
	r.clk = testclock.NewFakeClock(time.Unix(0, 0))
	ctx := context.Background()

	pod := probePod("web", corev1.Container{
		Name:    "c0",
		Image:   "registry/web:latest",
		Command: []string{"/web"},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler:        tcpHandler(8080),
			InitialDelaySeconds: 3600, // far future: the parked loop never probes in-test
			FailureThreshold:    1,
		},
	})
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

	st, err := r.GetPodStatus(ctx, "default", "web")
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	if len(st.ContainerStatuses) != 1 || st.ContainerStatuses[0].Ready {
		t.Fatalf("container Ready=%v, want false (readiness probe not yet succeeded)", st.ContainerStatuses[0].Ready)
	}
	if got := condStatus(st, corev1.PodReady); got != corev1.ConditionFalse {
		t.Errorf("PodReady=%v, want False", got)
	}
	if got := condStatus(st, corev1.ContainersReady); got != corev1.ConditionFalse {
		t.Errorf("ContainersReady=%v, want False", got)
	}
}

// TestRuntimedProbeStopsOnDelete proves DeletePod stops the prober (no goroutine
// leak): the prober is gone from the runtime's bookkeeping afterward.
func TestRuntimedProbeStopsOnDelete(t *testing.T) {
	r, _ := newRuntimedFake(t)
	r.clk = testclock.NewFakeClock(time.Unix(0, 0))
	ctx := context.Background()
	pod := probePod("web", corev1.Container{
		Name:           "c0",
		Command:        []string{"/web"},
		ReadinessProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), InitialDelaySeconds: 3600},
	})
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if r.proberFor("uid-web") == nil {
		t.Fatal("a probed pod should have a prober after CreatePod")
	}
	if err := r.DeletePod(ctx, pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if r.proberFor("uid-web") != nil {
		t.Fatal("prober should be gone after DeletePod")
	}
}

// TestProbeRunnerStopsCleanly exercises concurrent probe loops across multiple
// containers and asserts stop() reaps every goroutine promptly (run under -race
// this is the leak/race guard for the probe loops). It also confirms the
// onTransition callback fires on a readiness change.
func TestProbeRunnerStopsCleanly(t *testing.T) {
	clk := testclock.NewFakeClock(time.Unix(0, 0))
	var calls, transitions atomic.Int32
	mk := func(*corev1.Container, *corev1.Probe) checkFunc {
		return func(context.Context, time.Duration) error { calls.Add(1); return nil }
	}
	mkProbe := func() *corev1.Probe {
		return &corev1.Probe{ProbeHandler: tcpHandler(8080), InitialDelaySeconds: 1, PeriodSeconds: 1, SuccessThreshold: 1, FailureThreshold: 1}
	}
	pod := probePod("multi",
		corev1.Container{Name: "a", LivenessProbe: mkProbe(), ReadinessProbe: mkProbe()},
		corev1.Container{Name: "b", ReadinessProbe: mkProbe()},
	)
	pp := newPodProber(pod, clk, mk, nil)
	pp.onTransition = func() { transitions.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	pp.cancel = cancel
	pp.start(ctx)

	waitWaiters(t, clk, 3) // a.liveness + a.readiness + b.readiness parked on initial delay
	clk.Step(1 * time.Second)
	waitAtLeast(t, &calls, 3)       // every worker probed once
	waitAtLeast(t, &transitions, 1) // a readiness flip republished

	done := make(chan struct{})
	go func() { pp.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop() did not return — probe goroutine leak")
	}
}

// --- TestBuildCheckGRPCProbeNoPanic ------------------------------------------

// TestBuildCheckGRPCProbeNoPanic is the B9 regression gate: a gRPC-handler probe
// (a GA-valid manifest) and a handler-less probe must both build a NON-nil check,
// and a panicking check must be recovered rather than crash the single k3sm
// process. Before B9, buildCheck returned nil for the gRPC/default case while the
// runner still built a probeSpec for the non-nil Probe and invoked the nil check
// with no recover() — an unrecovered panic that took down the whole node. It
// proves four things: gRPC health is now SERVED (over the dial seam), the default
// is fail-CLOSED with a surfaced reason, and a panicking check is contained.
func TestBuildCheckGRPCProbeNoPanic(t *testing.T) {
	ctx := context.Background()

	t.Run("grpc health SERVING passes / NOT_SERVING fails over the dial seam", func(t *testing.T) {
		// A real grpc.health.v1 server over an in-memory bufconn (no real network):
		// the dial seam connects the provider's health client to it.
		lis := bufconn.Listen(1 << 20)
		gs := grpc.NewServer()
		hsrv := health.NewServer()
		grpc_health_v1.RegisterHealthServer(gs, hsrv)
		go func() { _ = gs.Serve(lis) }()
		t.Cleanup(gs.Stop)

		r, _ := newRuntimedFake(t)
		r.dial = func(c context.Context, _, _ string) (net.Conn, error) { return lis.DialContext(c) }

		const svc = "grpc.example.Svc"
		c := &corev1.Container{Name: "c0"}
		p := &corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 50051, Service: ptr(svc)}}}
		check := r.buildCheck("uid", "10.0.0.5", c, p)
		if check == nil {
			t.Fatal("gRPC probe must build a NON-nil check (nil → runner invokes nil → node-DoS panic)")
		}

		hsrv.SetServingStatus(svc, grpc_health_v1.HealthCheckResponse_SERVING)
		if err := check(ctx, 2*time.Second); err != nil {
			t.Fatalf("SERVING gRPC health → check should pass: %v", err)
		}
		hsrv.SetServingStatus(svc, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		if err := check(ctx, 2*time.Second); err == nil {
			t.Fatal("NOT_SERVING gRPC health → check must fail (fail closed)")
		}
	})

	t.Run("grpc dial error is a failure", func(t *testing.T) {
		r, _ := newRuntimedFake(t)
		r.dial = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}
		c := &corev1.Container{Name: "c0"}
		p := &corev1.Probe{ProbeHandler: corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 50051}}}
		check := r.buildCheck("uid", "10.0.0.5", c, p)
		if check == nil {
			t.Fatal("gRPC probe must build a NON-nil check")
		}
		if err := check(ctx, 2*time.Second); err == nil {
			t.Fatal("dial error → gRPC check must fail (fail closed)")
		}
	})

	t.Run("handler-less probe builds a fail-closed check with a surfaced reason", func(t *testing.T) {
		r, _ := newRuntimedFake(t)
		c := &corev1.Container{Name: "c0"}
		check := r.buildCheck("uid", "10.0.0.5", c, &corev1.Probe{}) // zero Probe: no handler
		if check == nil {
			t.Fatal("handler-less probe must build a NON-nil check (nil → spec built → nil-check panic)")
		}
		err := check(ctx, time.Second)
		if err == nil {
			t.Fatal("handler-less probe check must FAIL closed, not silently pass")
		}
		if err.Error() == "" {
			t.Fatal("fail-closed check must surface a non-empty reason")
		}
	})

	t.Run("panicking check is recovered and treated as a failed probe", func(t *testing.T) {
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		pod := probePod("panic", corev1.Container{
			Name:          "c0",
			LivenessProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), FailureThreshold: 1},
		})
		mk := func(*corev1.Container, *corev1.Probe) checkFunc {
			return func(context.Context, time.Duration) error { panic("boom in check") }
		}
		pp := newPodProber(pod, testclock.NewFakeClock(time.Unix(0, 0)), mk, log)
		m := pp.monitors["c0"]
		// Direct tick: were the panic NOT recovered, this call would crash the test
		// binary. Reaching the assertions at all proves recovery; restarts==1 proves
		// the panic was committed as a failed liveness probe (not swallowed as pass).
		pp.tick(ctx, m, probeLiveness, m.liveness)
		if got := m.verdict().restarts; got != 1 {
			t.Fatalf("panicking liveness check → restarts=%d, want 1 (panic must be a failed probe)", got)
		}
		if !strings.Contains(buf.String(), "panicked") {
			t.Errorf("recovered panic must be logged (diagnosable cause); log=%q", buf.String())
		}
	})

	t.Run("panicking check does not kill the probe loop goroutine", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		var calls atomic.Int32
		mk := func(*corev1.Container, *corev1.Probe) checkFunc {
			return func(context.Context, time.Duration) error {
				calls.Add(1)
				panic("boom every tick")
			}
		}
		pod := probePod("loop", corev1.Container{
			Name:           "c0",
			ReadinessProbe: &corev1.Probe{ProbeHandler: tcpHandler(8080), PeriodSeconds: 1, FailureThreshold: 5},
		})
		pp := newPodProber(pod, clk, mk, nil)
		pctx, cancel := context.WithCancel(context.Background())
		pp.cancel = cancel
		pp.start(pctx)
		defer pp.stop()

		waitAtLeast(t, &calls, 1) // first tick fired (panicked, recovered)
		waitWaiters(t, clk, 1)    // the loop PARKED on its period timer → it survived the panic
		clk.Step(1 * time.Second)
		waitAtLeast(t, &calls, 2) // second tick fired → the goroutine is still alive
	})
}
