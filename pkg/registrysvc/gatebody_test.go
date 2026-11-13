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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGateCutsUpstreamStalledAfterHeaders: a loopback registry that sends a
// blob's headers and part of its body and then goes silent loses the
// connection one progress window later, through the gate's real loopback
// transport: the client's read ends early with a truncated body and the
// registry's request is cancelled, and the cut is logged once. A registry
// that sends slowly but keeps sending, for longer than the window in total,
// is not cut.
func TestGateCutsUpstreamStalledAfterHeaders(t *testing.T) {
	const (
		window = time.Second
		// cadence is a tenth of the window, so a loaded host has room.
		cadence = window / 10
		// bound is generous: the cut is due one window after the last byte.
		bound = 5 * time.Second
		size  = 24
	)
	const cutMsg = "ingest registry gate cut a local registry response that stopped sending"
	blob := "/v2/team/app/blobs/sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name string
		// serve writes the body after the headers; it returns early when
		// the request's context ends.
		serve   func(w http.ResponseWriter, r *http.Request, f http.Flusher)
		wantCut bool
	}{
		{
			name: "stalled after headers",
			serve: func(w http.ResponseWriter, r *http.Request, f http.Flusher) {
				_, _ = io.WriteString(w, "part")
				f.Flush()
				<-r.Context().Done()
			},
			wantCut: true,
		},
		{
			name: "slow but moving",
			serve: func(w http.ResponseWriter, r *http.Request, f http.Flusher) {
				// size bytes, one per cadence: over 2 windows in all.
				for range size {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(cadence):
					}
					_, _ = io.WriteString(w, "x")
					f.Flush()
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cancelled := make(chan struct{})
			release := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				go func() {
					select {
					case <-r.Context().Done():
						close(cancelled)
					case <-release:
					}
				}()
				w.Header().Set("Content-Length", strconv.Itoa(size))
				w.WriteHeader(http.StatusOK)
				tc.serve(w, r, w.(http.Flusher))
			}))
			t.Cleanup(up.Close)
			t.Cleanup(func() { close(release) })

			logs := &syncBuffer{}
			f := newGateFixture(t)
			g := newGate(gateConfig{
				Upstream:             strings.TrimPrefix(up.URL, "http://"),
				Auth:                 GateAuth{Tokens: f.tokens, Access: f.access, Namespaces: f.namespaces},
				Credential:           gateCred,
				Logger:               slog.New(slog.NewJSONHandler(logs, nil)),
				Now:                  f.clock.now,
				UpstreamBodyProgress: window,
			})
			front := serveMem(t, g)

			c, err := front.dial()
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			start := time.Now()
			_ = c.SetDeadline(start.Add(bound))
			if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n\r\n", blob); err != nil {
				t.Fatalf("write: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			took := time.Since(start)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the registry's headers)", resp.StatusCode)
			}

			if !tc.wantCut {
				if readErr != nil || len(body) != size {
					t.Fatalf("a moving transfer was cut after %v: read %d of %d bytes, err %v", took, len(body), size, readErr)
				}
				if n := strings.Count(logs.String(), cutMsg); n != 0 {
					t.Errorf("logged %d cuts of a moving transfer:\n%s", n, logs)
				}
				return
			}
			if took >= bound {
				t.Fatalf("the client's read ran to the %v bound (err %v): the stalled registry still holds the connection", bound, readErr)
			}
			if readErr == nil && len(body) == size {
				t.Fatalf("read the whole %d-byte body from a registry that never sent it", size)
			}
			if string(body) != "part" {
				t.Errorf("body = %q, want the %q sent before the stall", body, "part")
			}
			select {
			case <-cancelled:
			case <-time.After(bound):
				t.Fatalf("the registry's request context was not cancelled within %v of the cut", bound)
			}
			if n := strings.Count(logs.String(), cutMsg); n != 1 {
				t.Fatalf("logged %d cuts, want exactly 1:\n%s", n, logs)
			}
			var cut struct {
				Bytes   *int64         `json:"bytes"`
				Elapsed *time.Duration `json:"elapsed"`
			}
			for line := range strings.Lines(logs.String()) {
				if strings.Contains(line, cutMsg) {
					if err := json.Unmarshal([]byte(line), &cut); err != nil {
						t.Fatalf("decode the cut line: %v\n%s", err, line)
					}
				}
			}
			if cut.Bytes == nil || *cut.Bytes != int64(len("part")) {
				t.Errorf("cut line bytes = %v, want %d (the bytes passed before the stall):\n%s", cut.Bytes, len("part"), logs)
			}
			if cut.Elapsed == nil || *cut.Elapsed < window || *cut.Elapsed >= bound {
				t.Errorf("cut line elapsed = %v, want at least the %v window and under %v:\n%s", cut.Elapsed, window, bound, logs)
			}
		})
	}
}

// TestProgressBodyTimesOnlyUpstreamReads: the progress window measures only
// time spent inside a Read on the upstream body. A consumer that waits longer
// than the window between Reads, while every Read returns promptly, gets the
// whole body and is never cut; an upstream that blocks a Read for the window
// is cut once, and that Read and every later one fail with the stall error.
func TestProgressBodyTimesOnlyUpstreamReads(t *testing.T) {
	const window = 200 * time.Millisecond
	t.Run("slow consumer", func(t *testing.T) {
		const body = "abcd"
		var stalls atomic.Int32
		p := newProgressBody(io.NopCloser(strings.NewReader(body)), window, func(int64, time.Duration) { stalls.Add(1) })
		defer p.Close()
		var got []byte
		buf := make([]byte, 1)
		for {
			// The consumer is busy for over two windows before every Read.
			time.Sleep(window * 5 / 2)
			n, err := p.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("read after %q: %v (a slow consumer was cut)", got, err)
			}
		}
		if string(got) != body {
			t.Errorf("body = %q, want %q", got, body)
		}
		if n := stalls.Load(); n != 0 {
			t.Errorf("stall callback ran %d times for an upstream that always answered promptly", n)
		}
	})
	t.Run("stalled upstream", func(t *testing.T) {
		pr, pw := io.Pipe()
		defer pw.Close()
		go func() { _, _ = io.WriteString(pw, "part") }()
		var stalls atomic.Int32
		p := newProgressBody(pr, window, func(int64, time.Duration) { stalls.Add(1) })
		defer p.Close()
		buf := make([]byte, 16)
		n, err := p.Read(buf)
		if err != nil || string(buf[:n]) != "part" {
			t.Fatalf("first read = %q, %v; want %q, nil", buf[:n], err, "part")
		}
		start := time.Now()
		if _, err := p.Read(buf); !errors.Is(err, errUpstreamBodyStalled) {
			t.Fatalf("read of a silent upstream = %v, want %v", err, errUpstreamBodyStalled)
		}
		if took := time.Since(start); took < window {
			t.Errorf("cut after %v, before the %v window", took, window)
		}
		if _, err := p.Read(buf); !errors.Is(err, errUpstreamBodyStalled) {
			t.Errorf("read after the cut = %v, want %v", err, errUpstreamBodyStalled)
		}
		if n := stalls.Load(); n != 1 {
			t.Errorf("stall callback ran %d times, want exactly 1", n)
		}
	})
}

// TestProgressBodyFirstReadBlocks: an upstream that never sends a byte is cut
// after one window on the first Read, once, and that Read returns the stall
// error.
func TestProgressBodyFirstReadBlocks(t *testing.T) {
	const window = 200 * time.Millisecond
	pr, pw := io.Pipe()
	defer pw.Close()
	var stalls atomic.Int32
	var passed atomic.Int64
	p := newProgressBody(pr, window, func(n int64, _ time.Duration) { passed.Store(n); stalls.Add(1) })
	defer p.Close()
	start := time.Now()
	n, err := p.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, errUpstreamBodyStalled) {
		t.Fatalf("first read = %d, %v; want 0, %v", n, err, errUpstreamBodyStalled)
	}
	if took := time.Since(start); took < window {
		t.Errorf("cut after %v, before the %v window", took, window)
	}
	if c := stalls.Load(); c != 1 {
		t.Errorf("stall callback ran %d times, want exactly 1", c)
	}
	if passed.Load() != 0 {
		t.Errorf("stall reported %d bytes passed, want 0", passed.Load())
	}
}

// TestProgressBodyCloseDuringRead: closing the body while a Read is blocked
// ends that Read and the stall callback never runs.
func TestProgressBodyCloseDuringRead(t *testing.T) {
	const window = 200 * time.Millisecond
	pr, pw := io.Pipe()
	defer pw.Close()
	var stalls atomic.Int32
	p := newProgressBody(pr, window, func(int64, time.Duration) { stalls.Add(1) })
	var wg sync.WaitGroup
	wg.Add(1)
	readErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := p.Read(make([]byte, 8))
		readErr <- err
	}()
	time.Sleep(window / 4)
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-readErr:
		if err == nil || errors.Is(err, errUpstreamBodyStalled) {
			t.Errorf("read ended with %v, want the close error and not the stall error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the blocked Read did not end after Close")
	}
	wg.Wait()
	time.Sleep(window * 3 / 2)
	if n := stalls.Load(); n != 0 {
		t.Errorf("stall callback ran %d times after Close, want 0", n)
	}
}

// TestGateDefaultBodyProgress: a gate built with a zero config watches
// response bodies for the relay's progress window.
func TestGateDefaultBodyProgress(t *testing.T) {
	g := newGate(gateConfig{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if g.bodyProgress != relayWriteProgress {
		t.Errorf("default body progress = %v, want relayWriteProgress %v", g.bodyProgress, relayWriteProgress)
	}
}

// TestWatchesBody: only a response with a body, that is not a HEAD answer and
// not a protocol switch, is watched.
func TestWatchesBody(t *testing.T) {
	body := func() io.ReadCloser { return io.NopCloser(strings.NewReader("x")) }
	get := &http.Request{Method: http.MethodGet}
	cases := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{"HEAD request", &http.Response{StatusCode: 200, Body: body(), ContentLength: 1, Request: &http.Request{Method: http.MethodHead}}, false},
		{"Content-Length 0", &http.Response{StatusCode: 200, Body: body(), ContentLength: 0, Request: get}, false},
		{"http.NoBody", &http.Response{StatusCode: 200, Body: http.NoBody, ContentLength: 1, Request: get}, false},
		{"nil body", &http.Response{StatusCode: 200, Body: nil, ContentLength: 1, Request: get}, false},
		{"101 switching protocols", &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: body(), ContentLength: 1, Request: get}, false},
		{"nil request", &http.Response{StatusCode: 200, Body: body(), ContentLength: 1}, true},
		{"plain GET 200", &http.Response{StatusCode: 200, Body: body(), ContentLength: 1, Request: get}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := watchesBody(tc.resp); got != tc.want {
				t.Errorf("watchesBody = %v, want %v", got, tc.want)
			}
		})
	}
}
