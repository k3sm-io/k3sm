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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

var updateStreamGolden = flag.Bool("update-stream-golden", false, "rewrite testdata/status_stream_first_frame.golden")

// streamGoldenPath is the golden of the stream's first frame.
var streamGoldenPath = filepath.Join("testdata", "status_stream_first_frame.golden")

// streamStart is the fake clock's epoch and the first report's timestamp.
var streamStart = time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)

// fakeStreamClock is a clock the test moves by hand. Every After call is
// announced on waiting before it returns, so a test that has read the
// announcement knows the stream is about to block, and nothing else moves
// until the test sends a watch signal or advances the clock.
type fakeStreamClock struct {
	mu       sync.Mutex
	now      time.Time
	timer    chan time.Time
	deadline time.Time
	waiting  chan time.Duration
}

func newFakeStreamClock() *fakeStreamClock {
	return &fakeStreamClock{now: streamStart, waiting: make(chan time.Duration)}
}

func (c *fakeStreamClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeStreamClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.timer, c.deadline = ch, c.now.Add(d)
	c.mu.Unlock()
	c.waiting <- d
	return ch
}

// advance moves the clock and fires the pending timer when it is due.
func (c *fakeStreamClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	if c.timer != nil && !c.now.Before(c.deadline) {
		c.timer <- c.now
		c.timer = nil
	}
}

// streamOut is a stdout the stream and the test share.
type streamOut struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *streamOut) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *streamOut) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.TrimSuffix(b.b.String(), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// streamHarness drives one stream: what the next collect returns, the watch
// channel, the clock, and the exit status.
type streamHarness struct {
	t        *testing.T
	clock    *fakeStreamClock
	signals  chan watchSignal
	out      *streamOut
	errOut   *streamOut
	done     chan int
	mu       sync.Mutex
	report   status.Report
	err      error
	collects int
}

// startStream runs `k3sm status --watch -o json` on a pipe against the
// harness's seams and returns once the first collect is done and the stream
// is waiting.
func startStream(t *testing.T, first status.Report) *streamHarness {
	t.Helper()
	h := &streamHarness{t: t, clock: newFakeStreamClock(), signals: make(chan watchSignal),
		out: &streamOut{}, errOut: &streamOut{}, done: make(chan int, 1), report: first}
	r := testRunner(h.out, h.errOut, nil)
	r.stdoutTTY = false
	r.stream = &statusStream{
		collect: func(context.Context) (status.Report, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.collects++
			return h.report, h.err
		},
		watch:    func(context.Context) <-chan watchSignal { return h.signals },
		clock:    h.clock,
		lifetime: streamLifetime,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { h.done <- r.run(ctx, statusOptions{format: "json", watch: defaultWatchInterval}) }()
	h.idle()
	return h
}

// idle waits until the stream blocks on its clock, and returns how long it
// asked to wait.
func (h *streamHarness) idle() time.Duration {
	h.t.Helper()
	select {
	case d := <-h.clock.waiting:
		return d
	case code := <-h.done:
		h.t.Fatalf("the stream exited %d while the test expected it to wait\n%s", code, strings.Join(h.errOut.lines(), "\n"))
	case <-time.After(10 * time.Second):
		h.t.Fatal("the stream never waited on its clock")
	}
	return 0
}

// exit waits for the stream's exit status.
func (h *streamHarness) exit() int {
	h.t.Helper()
	select {
	case code := <-h.done:
		return code
	case d := <-h.clock.waiting:
		h.t.Fatalf("the stream waited %s instead of exiting", d)
	case <-time.After(10 * time.Second):
		h.t.Fatal("the stream never exited")
	}
	return 0
}

// next sets what the next collect returns.
func (h *streamHarness) next(rep status.Report, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.report, h.err = rep, err
}

func (h *streamHarness) collected() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.collects
}

// heartbeat advances one heartbeat and waits for the stream to settle.
func (h *streamHarness) heartbeat() {
	h.clock.advance(streamHeartbeat)
	h.idle()
}

// streamReport is a running server's report at an instant: its timestamp and
// the heartbeat row's ages move with the clock, nothing else does.
func streamReport(at time.Time, nodeReady bool) status.Report {
	age := at.Sub(streamStart) % (40 * time.Second)
	node := status.Row{Name: status.RowNode, State: status.StateReady, Severity: status.SeverityOK, Detail: "1/1 nodes ready · mac kubelet v1.36.2"}
	verdict, summary := status.VerdictRunning, "1/1 nodes ready"
	if !nodeReady {
		node = status.Row{Name: status.RowNode, State: status.StateNotReady, Severity: status.SeverityFail, Detail: "0/1 nodes ready · mac NotReady"}
		verdict, summary = status.VerdictDegraded, "0/1 nodes ready"
	}
	return status.Report{
		SchemaVersion: status.SchemaVersion,
		Capabilities:  status.Capabilities(),
		Verdict:       verdict,
		Role:          "server",
		Summary:       summary,
		Rows: []status.Row{
			{Name: status.RowServer, State: status.StateRunning, Severity: status.SeverityOK, Detail: "pid 840"},
			{Name: status.RowAPIServer, State: status.StateReady, Severity: status.SeverityOK, Detail: "https://127.0.0.1:6444 readyz ok"},
			node,
			{Name: status.RowHeartbeat, State: status.StateOK, Severity: status.SeverityOK,
				Detail: "mac: node status posted " + (age + 2*time.Second).String() + " ago · lease renewed " + (age % (10 * time.Second)).String() + " ago"},
			{Name: status.RowRuntimed, State: status.StateNeedsAdmin, Severity: status.SeveritySkip, Detail: "the runtime socket is owner-only", Remedy: "sudo k3sm status"},
		},
		Version:   version.Info{Version: "v0.1.7", Commit: "abc123", GoVersion: "go1.26.1", Platform: "darwin/arm64"},
		Host:      "26.1",
		Timestamp: at,
	}
}

// decodeFrame decodes one stream line strictly.
func decodeFrame(t *testing.T, line string) streamFrame {
	t.Helper()
	var f streamFrame
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("frame %q does not decode: %v", line, err)
	}
	if f.SchemaVersion != status.SchemaVersion {
		t.Errorf("frame schemaVersion = %d, want %d", f.SchemaVersion, status.SchemaVersion)
	}
	return f
}

// TestStatusWatchStreamsOnChange is the gate on `k3sm status --watch -o json`
// on a pipe: an immediate first frame (golden bytes), no frame while nothing
// changes across heartbeats, one frame per change, a needs-admin row that
// never flaps, a refused credential that ends the stream with its own exit
// status, the closing frame at the lifetime, the redirected text --watch still
// refused, and the one-shot report advertising the mode.
func TestStatusWatchStreamsOnChange(t *testing.T) {
	t.Parallel()

	t.Run("first frame, quiet heartbeats, one frame per change", func(t *testing.T) {
		t.Parallel()
		h := startStream(t, streamReport(streamStart, true))
		lines := h.out.lines()
		if len(lines) != 1 {
			t.Fatalf("after the first collect the stream wrote %d lines, want 1:\n%s", len(lines), strings.Join(lines, "\n"))
		}
		if *updateStreamGolden {
			if err := os.WriteFile(streamGoldenPath, []byte(lines[0]+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		golden, err := os.ReadFile(streamGoldenPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := lines[0] + "\n"; got != string(golden) {
			t.Errorf("first frame:\n%s\nwant (%s):\n%s", got, streamGoldenPath, golden)
		}
		if f := decodeFrame(t, lines[0]); f.Kind != frameReport || f.Report == nil || f.Report.Verdict != status.VerdictRunning {
			t.Errorf("first frame = %+v, want a running report", f)
		}

		for i := 1; i <= 3; i++ {
			h.next(streamReport(h.clock.Now().Add(streamHeartbeat), true), nil)
			h.heartbeat()
		}
		if got := h.collected(); got != 4 {
			t.Errorf("collects after three heartbeats = %d, want 4", got)
		}
		if lines := h.out.lines(); len(lines) != 1 {
			t.Fatalf("three unchanged heartbeats wrote %d frames, want none:\n%s", len(lines)-1, strings.Join(lines[1:], "\n"))
		}

		// A node goes not-ready: the watch fires a burst, which is one collect
		// and one frame.
		changeAt := h.clock.Now()
		h.next(streamReport(changeAt, false), nil)
		for range 3 {
			h.signals <- watchSignal{}
			h.idle()
		}
		h.clock.advance(streamMinGap)
		if d := h.idle(); d != streamHeartbeat {
			t.Errorf("after the change the stream waits %s, want the heartbeat %s", d, streamHeartbeat)
		}
		if got := h.collected(); got != 5 {
			t.Errorf("collects after a burst of three node events = %d, want 5", got)
		}
		lines = h.out.lines()
		if len(lines) != 2 {
			t.Fatalf("a node change wrote %d frames, want 1:\n%s", len(lines)-1, strings.Join(lines[1:], "\n"))
		}
		f := decodeFrame(t, lines[1])
		if f.Kind != frameReport || f.Report == nil || f.Report.Verdict != status.VerdictDegraded {
			t.Errorf("change frame = %+v, want the degraded report", f)
		}
		if row, _ := f.Report.Row(status.RowNode); row.State != status.StateNotReady {
			t.Errorf("change frame node row = %+v, want not-ready", row)
		}
	})

	t.Run("a needs-admin row held across collects writes nothing", func(t *testing.T) {
		t.Parallel()
		h := startStream(t, streamReport(streamStart, true))
		for range 4 {
			h.next(streamReport(h.clock.Now().Add(streamHeartbeat), true), nil)
			h.signals <- watchSignal{}
			h.idle()
			h.clock.advance(streamHeartbeat)
			h.idle()
		}
		if got := h.collected(); got < 5 {
			t.Errorf("collects = %d, want at least 5", got)
		}
		if lines := h.out.lines(); len(lines) != 1 {
			t.Errorf("the held needs-admin row wrote %d extra frames:\n%s", len(lines)-1, strings.Join(lines[1:], "\n"))
		}
		f := decodeFrame(t, h.out.lines()[0])
		if row, _ := f.Report.Row(status.RowRuntimed); row.State != status.StateNeedsAdmin {
			t.Errorf("runtimed row = %+v, want needs-admin", row)
		}
	})

	refusedErr := apierrors.NewUnauthorized("the token is not valid")
	wantAuthFrame := `{"kind":"error","schemaVersion":1,"code":"auth-refused","message":"the token is not valid"}`

	t.Run("a refused credential on a collect ends the stream with its own status", func(t *testing.T) {
		t.Parallel()
		h := startStream(t, streamReport(streamStart, true))
		h.next(status.Report{}, refusedErr)
		h.clock.advance(streamHeartbeat)
		if code := h.exit(); code != exitAuthRefused {
			t.Errorf("exit = %d, want %d", code, exitAuthRefused)
		}
		lines := h.out.lines()
		if len(lines) != 2 || lines[1] != wantAuthFrame {
			t.Errorf("frames after the refusal = %q, want the report then %s", lines, wantAuthFrame)
		}
	})

	t.Run("a refused credential on the watch ends the stream with its own status", func(t *testing.T) {
		t.Parallel()
		h := startStream(t, streamReport(streamStart, true))
		h.signals <- watchSignal{err: refusedErr}
		if code := h.exit(); code != exitAuthRefused {
			t.Errorf("exit = %d, want %d", code, exitAuthRefused)
		}
		if lines := h.out.lines(); len(lines) != 2 || lines[1] != wantAuthFrame {
			t.Errorf("frames = %q, want the report then %s", lines, wantAuthFrame)
		}
	})

	t.Run("a watch the identity may not open is reported once and the heartbeat carries on", func(t *testing.T) {
		t.Parallel()
		h := startStream(t, streamReport(streamStart, true))
		forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("no list"))
		h.signals <- watchSignal{err: forbidden}
		h.idle()
		h.signals <- watchSignal{err: forbidden}
		h.idle()
		lines := h.out.lines()
		if len(lines) != 2 {
			t.Fatalf("frames = %q, want the report and one error frame", lines)
		}
		if f := decodeFrame(t, lines[1]); f.Kind != frameError || f.Code != codeWatchForbidden {
			t.Errorf("error frame = %+v, want %s", f, codeWatchForbidden)
		}
		h.clock.advance(streamHeartbeat)
		h.idle()
		if got := h.collected(); got < 2 {
			t.Errorf("collects = %d; the heartbeat stopped after the watch failed", got)
		}
	})

	t.Run("the closing frame at the lifetime, then exit 0", func(t *testing.T) {
		t.Parallel()
		h := startStream(t, streamReport(streamStart, true))
		for h.clock.Now().Add(streamHeartbeat).Before(streamStart.Add(streamLifetime)) {
			h.next(streamReport(h.clock.Now().Add(streamHeartbeat), true), nil)
			h.heartbeat()
		}
		h.clock.advance(streamHeartbeat)
		if code := h.exit(); code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		lines := h.out.lines()
		if len(lines) != 2 {
			t.Fatalf("frames = %q, want the first report and the closing frame", lines)
		}
		want := `{"kind":"closing","schemaVersion":1,"code":"lifetime","message":"the stream ends after 30m0s; start a new one"}`
		if lines[1] != want {
			t.Errorf("closing frame = %s, want %s", lines[1], want)
		}
	})

	t.Run("a report over the line cap is an error frame", func(t *testing.T) {
		t.Parallel()
		big := streamReport(streamStart, true)
		big.Rows[0].Detail = strings.Repeat("x", streamLineCap)
		h := startStream(t, big)
		lines := h.out.lines()
		if len(lines) != 1 {
			t.Fatalf("frames = %d, want 1", len(lines))
		}
		if f := decodeFrame(t, lines[0]); f.Kind != frameError || f.Code != codeFrameTooLarge {
			t.Errorf("frame = %+v, want %s", f, codeFrameTooLarge)
		}
	})

	t.Run("a redirected --watch without -o json is still refused", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
		r.stream = &statusStream{collect: func(context.Context) (status.Report, error) {
			t.Error("the refused mode collected")
			return status.Report{}, nil
		}}
		for _, o := range []statusOptions{
			{format: "text", watch: time.Second},
			{format: "wide", watch: time.Second},
			{format: "json", view: "daemons", watch: time.Second},
		} {
			if got := r.run(context.Background(), o); got != exitUsage {
				t.Errorf("%+v: exit = %d, want %d", o, got, exitUsage)
			}
		}
		if out.Len() != 0 {
			t.Errorf("a refused --watch wrote to stdout: %q", out.String())
		}
	})

	t.Run("the one-shot report carries the capability", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		paths := statusPaths(dir)
		paths.LaunchDaemonDir = filepath.Join(dir, "LaunchDaemons")
		uid := os.Geteuid()
		c := status.Collector{
			Launchd:  runningLaunchd{running: map[string]bool{install.NetdLabel: true}},
			FS:       osStatusFS{},
			KubeErr:  errors.New("no kubeconfig"),
			Procs:    aliveProcs{},
			DataRoot: plainDataRoot{dir: dir},
			Paths:    paths, EUID: uid, ServiceUID: uid,
			Now: func() time.Time { return streamStart },
		}
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, c.Collect)
		r.run(context.Background(), statusOptions{format: "json"})
		var rep struct {
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("one-shot output is not JSON: %v\n%s", err, out.String())
		}
		if len(rep.Capabilities) != 1 || rep.Capabilities[0] != status.CapabilityWatchJSON {
			t.Errorf("capabilities = %v, want [%s]", rep.Capabilities, status.CapabilityWatchJSON)
		}
	})
}
