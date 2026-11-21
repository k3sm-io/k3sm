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

package registrysvc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/api"
)

// stallingUpstream is a loopback registry in memory: each dial is a net.Pipe
// whose far end reads every request and never answers. Inside a synctest
// bubble its connections block durably, so the transports' response-header
// bounds fire on the bubble's clock.
func stallingUpstream(t *testing.T) func(ctx context.Context, network, addr string) (net.Conn, error) {
	t.Helper()
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return func(context.Context, string, string) (net.Conn, error) {
		c, s := net.Pipe()
		mu.Lock()
		conns = append(conns, s)
		mu.Unlock()
		go func() { _, _ = io.Copy(io.Discard, s) }()
		return c, nil
	}
}

// upstreamGate is the fixture's gate over the default loopback transports and
// their production response-header bounds, pointed at upstream and dialling
// with dial (nil means a real dialer).
func upstreamGate(t *testing.T, upstream string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *memListener {
	t.Helper()
	f := newGateFixture(t)
	g := newGate(gateConfig{
		Upstream:   upstream,
		Auth:       GateAuth{Tokens: f.tokens, Access: f.access, Namespaces: f.namespaces},
		Credential: gateCred,
		Logger:     quietLogger(),
		Now:        f.clock.now,
		dial:       dial,
	})
	return serveMem(t, g)
}

// rawResult is a response read off a connection, or the error reading it.
type rawResult struct {
	resp rawResponse
	err  error
}

// sendRaw writes req on c and reads the response in the background, with no
// deadline of its own; the result arrives on the returned channel.
func sendRaw(c net.Conn, method, req string) <-chan rawResult {
	out := make(chan rawResult, 1)
	go func() {
		if _, err := io.WriteString(c, req); err != nil {
			out <- rawResult{err: fmt.Errorf("write: %w", err)}
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
		if err != nil {
			out <- rawResult{err: fmt.Errorf("read response: %w", err)}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		out <- rawResult{resp: rawResponse{status: resp.StatusCode, header: resp.Header, body: string(b)}, err: err}
	}()
	return out
}

// assertUnavailable502 checks an authorized write answered 502 UNAVAILABLE.
func assertUnavailable502(t *testing.T, r rawResponse) {
	t.Helper()
	if r.status != 502 {
		t.Fatalf("status = %d, want 502; body %q", r.status, r.body)
	}
	if !strings.Contains(r.body, `"code":"`+codeUnavailable+`"`) {
		t.Errorf("body = %q, want code %s", r.body, codeUnavailable)
	}
}

// TestGateAnswers502WhenTheUpstreamStalls: a loopback registry that reads a
// manifest PUT and never answers costs the client a 502 UNAVAILABLE at the
// manifest response-header bound, not a wait until the client gives up. The
// bound is the production one, timed on a synctest clock.
func TestGateAnswers502WhenTheUpstreamStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bound = gateManifestHeaderTimeout
		front := upstreamGate(t, "registry.loopback:5000", stallingUpstream(t))
		c, err := front.dial()
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		req := "PUT /v2/team/app/manifests/V1.0 HTTP/1.1\r\nHost: registry.test\r\n" +
			"Authorization: " + basic(tokTeam) + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
		start := time.Now()
		done := sendRaw(c, "PUT", req)

		time.Sleep(bound - time.Nanosecond)
		synctest.Wait()
		select {
		case r := <-done:
			t.Fatalf("answered after %v, before the %v bound: %+v", time.Since(start), bound, r)
		default:
		}

		r := <-done
		if took := time.Since(start); took < bound || took > bound+time.Second {
			t.Errorf("the 502 came after %v, want at the %v bound", took, bound)
		}
		if r.err != nil {
			t.Fatalf("%v", r.err)
		}
		assertUnavailable502(t, r.resp)
	})
}

// TestGateHeaderBoundByOperation: each class of request is forwarded over the
// transport with its own response-header bound: 30s for a read and an upload
// status, the collect bound for a manifest PUT, the registry's upload bound
// for a blob upload request.
func TestGateHeaderBoundByOperation(t *testing.T) {
	g := newGate(gateConfig{Upstream: "127.0.0.1:1", Logger: quietLogger()})
	for _, tc := range []struct {
		op   gateOp
		want time.Duration
	}{
		{opRead, gateUpstreamHeaderTimeout},
		{opUploadStatus, gateUpstreamHeaderTimeout},
		{opManifestPut, gateManifestHeaderTimeout},
		{opUploadStart, api.DefaultUploadTimeout},
		{opUploadChunk, api.DefaultUploadTimeout},
		{opUploadFinish, api.DefaultUploadTimeout},
	} {
		t.Run(tc.op.String(), func(t *testing.T) {
			tr, ok := g.proxyFor(tc.op).Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport = %T, want *http.Transport", g.proxyFor(tc.op).Transport)
			}
			if got := tr.ResponseHeaderTimeout; got != tc.want {
				t.Errorf("response-header bound = %v, want %v", got, tc.want)
			}
		})
	}
	if gateUpstreamHeaderTimeout != 30*time.Second {
		t.Errorf("gateUpstreamHeaderTimeout = %v, want 30s", gateUpstreamHeaderTimeout)
	}
}

// TestGateManifestBoundCoversCollect: a manifest PUT queued behind a
// collection sweep of its repository waits up to CollectTimeout for the lock
// and then links and re-hashes its blobs, so the manifest bound must exceed
// CollectTimeout by a positive margin or a healthy push is cut.
func TestGateManifestBoundCoversCollect(t *testing.T) {
	if gateManifestCollectMargin <= 0 {
		t.Errorf("gateManifestCollectMargin = %v, want > 0", gateManifestCollectMargin)
	}
	if gateManifestHeaderTimeout < CollectTimeout+gateManifestCollectMargin {
		t.Errorf("gateManifestHeaderTimeout = %v, want at least CollectTimeout (%v) + margin (%v)",
			gateManifestHeaderTimeout, CollectTimeout, gateManifestCollectMargin)
	}
}

// TestGateProxyForEveryOperation walks every operation, gateOp 0 to
// opCount-1, and asserts the proxy, and so the transport class, proxyFor
// picks for it. Every value in that range must have a String name (or be
// opInvalid) and an entry here, so an operation added without either fails,
// which makes whoever adds it name it and decide its bound.
func TestGateProxyForEveryOperation(t *testing.T) {
	g := newGate(gateConfig{Upstream: "127.0.0.1:1", Logger: quietLogger()})
	classes := map[*httputil.ReverseProxy]string{
		g.read:     "read",
		g.write:    "write",
		g.manifest: "manifest",
		g.upload:   "upload",
	}
	if len(classes) != 4 {
		t.Fatalf("the gate's four proxies are not distinct")
	}
	want := map[gateOp]string{
		opInvalid:      "write", // never forwarded; the default
		opRefused:      "write", // never forwarded; the default
		opRead:         "read",
		opUploadStart:  "upload",
		opUploadChunk:  "upload",
		opUploadFinish: "upload",
		opUploadStatus: "write",
		opManifestPut:  "manifest",
	}
	if len(want) != int(opCount) {
		t.Errorf("table has %d operations, gateOp has %d: keep them equal", len(want), opCount)
	}
	if opCount.String() != opInvalid.String() {
		t.Errorf("opCount.String() = %q, want the default name %q: the sentinel is not a named operation", opCount.String(), opInvalid.String())
	}
	if opInvalid != 0 {
		t.Errorf("opInvalid = %d, want 0", opInvalid)
	}
	for op := gateOp(0); op < opCount; op++ {
		if op != opInvalid && op.String() == opInvalid.String() {
			t.Errorf("operation %d has no String name: add a case in gateOp.String", op)
		}
		w, ok := want[op]
		if !ok {
			t.Errorf("operation %d (%s) has no expected proxy class: add it here and a case in proxyFor", op, op)
			continue
		}
		if got := classes[g.proxyFor(op)]; got != w {
			t.Errorf("proxyFor(%s) = %q proxy, want %q", op, got, w)
		}
	}
	for op := range want {
		if op >= opCount {
			t.Errorf("expected operation %d is not below opCount", op)
		}
	}
}

// TestGateWriteErrorIs502WhenUpstreamIsDown: a loopback registry that is not
// listening costs an authorized write a 502 UNAVAILABLE, not a hung request.
func TestGateWriteErrorIs502WhenUpstreamIsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	front := upstreamGate(t, closed, nil)
	r := rawDo(t, front, "PUT", "/v2/team/app/manifests/V1.0",
		map[string]string{"Authorization": basic(tokTeam)}, "{}")
	assertUnavailable502(t, r)
}

// TestGateLeavesBlobUploadsOutOfTheHeaderBound: the registry commits a blob
// upload before it writes a header, so a final blob PUT is held to the upload
// bound, not the shorter ones; just past the longest of those, the manifest
// bound, it is still waiting on the registry, timed on a synctest clock.
func TestGateLeavesBlobUploadsOutOfTheHeaderBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		short := max(gateUpstreamHeaderTimeout, gateManifestHeaderTimeout)
		if short+time.Second >= gateUploadHeaderTimeout {
			t.Fatalf("upload bound %v is not past the short bounds %v", gateUploadHeaderTimeout, short)
		}
		front := upstreamGate(t, "registry.loopback:5000", stallingUpstream(t))
		c, err := front.dial()
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		req := fmt.Sprintf("PUT /v2/team/app/blobs/uploads/abc-123?digest=%s HTTP/1.1\r\nHost: registry.test\r\n"+
			"Authorization: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", digestA, basic(tokTeam))
		done := sendRaw(c, "PUT", req)

		time.Sleep(short + time.Second)
		synctest.Wait()
		select {
		case r := <-done:
			t.Fatalf("answered after %v: %+v; want the upload still waiting on the registry", short+time.Second, r)
		default:
		}
	})
}

// TestGateReadErrorLogsCancellationAtDebug: a read that cannot reach the
// registry is a Warn naming its cause and not the request, unless the client
// cancelled it, which is a Debug naming the method and path.
func TestGateReadErrorLogsCancellationAtDebug(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		level string
	}{
		{"an unreachable registry is a warning", errors.New("connection refused"), "WARN"},
		{"a client's cancellation is debug", fmt.Errorf("proxy: %w", context.Canceled), "DEBUG"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			g := newGate(gateConfig{Upstream: "127.0.0.1:1", Logger: log})
			r := httptest.NewRequest(http.MethodGet, "/v2/team/app/blobs/"+digestA, nil)
			g.readError(httptest.NewRecorder(), r, tc.err)
			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("log line %q: %v", buf.String(), err)
			}
			if line["level"] != tc.level {
				t.Errorf("level = %v, want %s", line["level"], tc.level)
			}
			if tc.level == "WARN" {
				if _, ok := line["method"]; ok {
					t.Errorf("warning names the method %v; want no request", line["method"])
				}
				if _, ok := line["path"]; ok {
					t.Errorf("warning names the path %v; want no request", line["path"])
				}
				if line["cause"] != "other" {
					t.Errorf("cause = %v, want other", line["cause"])
				}
				return
			}
			if line["method"] != "GET" || line["path"] != "/v2/team/app/blobs/"+digestA {
				t.Errorf("method, path = %v, %v; want the request's", line["method"], line["path"])
			}
		})
	}
}

// TestGateReadErrorWarnsOncePerIntervalPerCause: a read that cannot reach the
// registry is a Warn at most once per interval for each cause; the failures in
// between are Debug, and the next Warn counts them. A client's cancellation is
// a Debug outside the count.
func TestGateReadErrorWarnsOncePerIntervalPerCause(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	timeout := fmt.Errorf("proxy: %w", context.DeadlineExceeded)
	canceled := fmt.Errorf("proxy: %w", context.Canceled)
	interval := gateReadWarnInterval

	// event is one failed read, made after advancing the clock by after.
	type event struct {
		after time.Duration
		err   error
	}
	// line is one expected log line: cause "" means no cause key, suppressed
	// 0 means no suppressed key.
	type line struct {
		level      string
		cause      string
		suppressed int
	}
	events := func(n int, e event) []event {
		out := make([]event, n)
		for i := range out {
			out[i] = e
		}
		return out
	}
	lines := func(n int, l line) []line {
		out := make([]line, n)
		for i := range out {
			out[i] = l
		}
		return out
	}
	warn := func(cause string, suppressed int) line { return line{"WARN", cause, suppressed} }
	debug := func(cause string) line { return line{"DEBUG", cause, 0} }
	distinct := make([]event, 10)
	for i := range distinct {
		distinct[i] = event{err: fmt.Errorf("upstream fault %d", i)}
	}

	for _, tc := range []struct {
		name   string
		events []event
		// parallel, when set, makes each event that many concurrent failures
		// at one clock reading; only how often each line occurs is compared.
		parallel int
		want     []line
	}{
		{
			name:   "the first failure warns with its cause and no count",
			events: []event{{err: refused}},
			want:   []line{warn("refused", 0)},
		},
		{
			name:   "failures inside the interval are debug",
			events: events(6, event{err: refused}),
			want:   append([]line{warn("refused", 0)}, lines(5, debug("refused"))...),
		},
		{
			name:   "the first failure after the interval warns with the count",
			events: append(events(6, event{err: refused}), event{after: interval, err: refused}),
			want:   append(append([]line{warn("refused", 0)}, lines(5, debug("refused"))...), warn("refused", 5)),
		},
		{
			name:   "the count resets after each warning",
			events: []event{{err: refused}, {err: refused}, {after: interval, err: refused}, {after: interval, err: refused}},
			want:   []line{warn("refused", 0), debug("refused"), warn("refused", 1), warn("refused", 0)},
		},
		{
			name:   "a cancellation is debug and not counted",
			events: []event{{err: refused}, {err: refused}, {err: canceled}, {after: interval, err: refused}},
			want:   []line{warn("refused", 0), debug("refused"), debug(""), warn("refused", 1)},
		},
		{
			name:   "each cause is limited on its own",
			events: []event{{err: refused}, {err: timeout}, {err: refused}, {err: timeout}},
			want:   []line{warn("refused", 0), warn("timeout", 0), debug("refused"), debug("timeout")},
		},
		{
			name:   "distinct unknown errors share one cause",
			events: distinct,
			want:   append([]line{warn("other", 0)}, lines(9, debug("other"))...),
		},
		{
			name:     "concurrent failures warn once",
			events:   []event{{err: refused}},
			parallel: 64,
			want:     append([]line{warn("refused", 0)}, lines(63, debug("refused"))...),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syncBuffer{}
			log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
			clk := &fakeClock{t: time.Date(2026, 11, 13, 7, 0, 0, 0, time.UTC)}
			g := newGate(gateConfig{Upstream: "127.0.0.1:1", Logger: log, Now: clk.now})
			path := "/v2/team/app/blobs/" + digestA
			fail := func(err error) {
				g.readError(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil), err)
			}
			for _, e := range tc.events {
				clk.advance(e.after)
				if tc.parallel == 0 {
					fail(e.err)
					continue
				}
				var wg sync.WaitGroup
				for range tc.parallel {
					wg.Go(func() { fail(e.err) })
				}
				wg.Wait()
			}

			var got []line
			for _, raw := range strings.Split(strings.TrimSpace(sink.String()), "\n") {
				var m map[string]any
				if err := json.Unmarshal([]byte(raw), &m); err != nil {
					t.Fatalf("log line %q: %v", raw, err)
				}
				l := line{level: fmt.Sprint(m["level"])}
				if c, ok := m["cause"]; ok {
					l.cause = fmt.Sprint(c)
				}
				if n, ok := m["suppressed"]; ok {
					if f, _ := n.(float64); f <= 0 {
						t.Errorf("line %q: want suppressed only when positive", raw)
					} else {
						l.suppressed = int(f)
					}
				}
				_, hasMethod := m["method"]
				_, hasPath := m["path"]
				if l.level == "WARN" && (hasMethod || hasPath) {
					t.Errorf("warning %q names a request; want only the target, cause and error", raw)
				}
				if l.level == "DEBUG" && (m["method"] != "GET" || m["path"] != path) {
					t.Errorf("debug line %q: want the request's method and path", raw)
				}
				if m["target"] != "127.0.0.1:1" || m["err"] == nil {
					t.Errorf("line %q: want the target and the error", raw)
				}
				got = append(got, l)
			}
			if tc.parallel > 0 {
				count := func(ls []line) map[line]int {
					c := map[line]int{}
					for _, l := range ls {
						c[l]++
					}
					return c
				}
				if gc, wc := count(got), count(tc.want); fmt.Sprint(gc) != fmt.Sprint(wc) {
					t.Errorf("lines = %v, want %v", gc, wc)
				}
				return
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("lines =\n%v\nwant\n%v", got, tc.want)
			}
		})
	}
}

// TestGateWriteErrorLogsCancellationAtDebug: an authorized write the registry
// did not take is a Warn naming its cause and not the request, unless the
// client cancelled it, which is a Debug naming the method and path. Either way
// the client is answered 502.
func TestGateWriteErrorLogsCancellationAtDebug(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		level string
	}{
		{"an unreachable registry is a warning", errors.New("connection refused"), "WARN"},
		{"a client's cancellation is debug", fmt.Errorf("proxy: %w", context.Canceled), "DEBUG"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			g := newGate(gateConfig{Upstream: "127.0.0.1:1", Logger: log})
			path := "/v2/team/app/manifests/v1"
			r := httptest.NewRequest(http.MethodPut, path, nil)
			rec := httptest.NewRecorder()
			g.writeError(rec, r, tc.err)
			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("log line %q: %v", buf.String(), err)
			}
			if line["level"] != tc.level {
				t.Errorf("level = %v, want %s", line["level"], tc.level)
			}
			if tc.level == "WARN" {
				if _, ok := line["method"]; ok {
					t.Errorf("warning names the method %v; want no request", line["method"])
				}
				if _, ok := line["path"]; ok {
					t.Errorf("warning names the path %v; want no request", line["path"])
				}
				if line["cause"] != "other" {
					t.Errorf("cause = %v, want other", line["cause"])
				}
			} else if line["method"] != "PUT" || line["path"] != path {
				t.Errorf("method, path = %v, %v; want the request's", line["method"], line["path"])
			}
			if rec.Code != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", rec.Code)
			}
		})
	}
}

// TestGateWriteErrorWarnsOncePerInterval: an authorized write that cannot
// reach the registry is a Warn at most once per interval for each cause, with
// a limit of its own apart from the reads'; the failures in between are Debug,
// and the next Warn counts them. A client's cancellation is a Debug outside the
// count. Every write failure is answered 502.
func TestGateWriteErrorWarnsOncePerInterval(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	canceled := fmt.Errorf("proxy: %w", context.Canceled)
	interval := gateReadWarnInterval
	const (
		readPath  = "/v2/team/app/blobs/" + digestA
		writePath = "/v2/team/app/manifests/v1"
	)

	// event is one failed request, a read or a write, made after advancing
	// the clock by after.
	type event struct {
		after time.Duration
		read  bool
		err   error
	}
	// line is one expected log line: cause "" means no cause key, suppressed
	// 0 means no suppressed key.
	type line struct {
		level      string
		msg        string
		cause      string
		suppressed int
	}
	const (
		readMsg  = "ingest registry gate could not reach the local registry"
		writeMsg = "ingest registry gate could not forward an authorized write"
	)
	write := func(err error) event { return event{err: err} }
	warnW := func(suppressed int) line { return line{"WARN", writeMsg, "refused", suppressed} }
	debugW := func(cause string) line { return line{"DEBUG", writeMsg, cause, 0} }

	for _, tc := range []struct {
		name   string
		events []event
		want   []line
	}{
		{
			name:   "the first write failure warns with its cause and no count",
			events: []event{write(refused)},
			want:   []line{warnW(0)},
		},
		{
			name:   "write failures inside the interval are debug",
			events: []event{write(refused), write(refused), write(refused)},
			want:   []line{warnW(0), debugW("refused"), debugW("refused")},
		},
		{
			name:   "the first write failure after the interval warns with the count",
			events: []event{write(refused), write(refused), write(refused), {after: interval, err: refused}},
			want:   []line{warnW(0), debugW("refused"), debugW("refused"), warnW(2)},
		},
		{
			name:   "a read and a write failing at one instant both warn",
			events: []event{{read: true, err: refused}, write(refused)},
			want:   []line{{"WARN", readMsg, "refused", 0}, warnW(0)},
		},
		{
			name:   "a write cancellation is debug and not counted",
			events: []event{write(refused), write(canceled), write(refused), {after: interval, err: refused}},
			want:   []line{warnW(0), debugW(""), debugW("refused"), warnW(1)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syncBuffer{}
			log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
			clk := &fakeClock{t: time.Date(2026, 11, 13, 7, 0, 0, 0, time.UTC)}
			g := newGate(gateConfig{Upstream: "127.0.0.1:1", Logger: log, Now: clk.now})
			for _, e := range tc.events {
				clk.advance(e.after)
				if e.read {
					g.readError(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, readPath, nil), e.err)
					continue
				}
				rec := httptest.NewRecorder()
				g.writeError(rec, httptest.NewRequest(http.MethodPut, writePath, nil), e.err)
				if rec.Code != http.StatusBadGateway {
					t.Errorf("write status = %d, want 502", rec.Code)
				}
			}

			var got []line
			for _, raw := range strings.Split(strings.TrimSpace(sink.String()), "\n") {
				var m map[string]any
				if err := json.Unmarshal([]byte(raw), &m); err != nil {
					t.Fatalf("log line %q: %v", raw, err)
				}
				l := line{level: fmt.Sprint(m["level"]), msg: fmt.Sprint(m["msg"])}
				if c, ok := m["cause"]; ok {
					l.cause = fmt.Sprint(c)
				}
				if n, ok := m["suppressed"]; ok {
					if f, _ := n.(float64); f <= 0 {
						t.Errorf("line %q: want suppressed only when positive", raw)
					} else {
						l.suppressed = int(f)
					}
				}
				_, hasMethod := m["method"]
				_, hasPath := m["path"]
				if l.level == "WARN" && (hasMethod || hasPath) {
					t.Errorf("warning %q names a request; want only the target, cause and error", raw)
				}
				if l.level == "DEBUG" && l.msg == writeMsg && (m["method"] != "PUT" || m["path"] != writePath) {
					t.Errorf("debug line %q: want the write's method and path", raw)
				}
				if m["target"] != "127.0.0.1:1" || m["err"] == nil {
					t.Errorf("line %q: want the target and the error", raw)
				}
				got = append(got, l)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("lines =\n%v\nwant\n%v", got, tc.want)
			}
		})
	}
}
