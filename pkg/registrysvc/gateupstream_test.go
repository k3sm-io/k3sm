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
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/api"
)

// stallingUpstream accepts connections on loopback and never answers them.
func stallingUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// upstreamGate is the fixture's gate over the default loopback transports,
// pointed at upstream, with headerTimeout as the bound of every request but a
// blob upload's.
func upstreamGate(t *testing.T, upstream string, headerTimeout time.Duration) *memListener {
	t.Helper()
	f := newGateFixture(t)
	g := newGate(gateConfig{
		Upstream:              upstream,
		Auth:                  GateAuth{Tokens: f.tokens, Access: f.access, Namespaces: f.namespaces},
		Credential:            gateCred,
		Logger:                quietLogger(),
		Now:                   f.clock.now,
		UpstreamHeaderTimeout: headerTimeout,
		ManifestHeaderTimeout: headerTimeout,
	})
	return serveMem(t, g)
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

// TestGateAnswers502WhenTheUpstreamStalls: a loopback registry that accepts a
// connection and never answers costs an authorized manifest PUT a 502 within
// its response-header bound, not a wait until the client gives up.
func TestGateAnswers502WhenTheUpstreamStalls(t *testing.T) {
	const bound = 200 * time.Millisecond
	front := upstreamGate(t, stallingUpstream(t), bound)
	start := time.Now()
	r := rawDo(t, front, "PUT", "/v2/team/app/manifests/V1.0",
		map[string]string{"Authorization": basic(tokTeam)}, "{}")
	if took := time.Since(start); took > bound+3*time.Second {
		t.Errorf("the 502 took %v, want about the %v bound", took, bound)
	}
	assertUnavailable502(t, r)
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
		{opManifestPut, CollectTimeout},
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

// TestGateWriteErrorIs502WhenUpstreamIsDown: a loopback registry that is not
// listening costs an authorized write a 502 UNAVAILABLE, not a hung request.
func TestGateWriteErrorIs502WhenUpstreamIsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	front := upstreamGate(t, closed, 0)
	r := rawDo(t, front, "PUT", "/v2/team/app/manifests/V1.0",
		map[string]string{"Authorization": basic(tokTeam)}, "{}")
	assertUnavailable502(t, r)
}

// TestGateLeavesBlobUploadsOutOfTheHeaderBound: the registry commits a blob
// upload before it writes a header, so a final blob PUT is held to the
// upload bound, not the short one; past the short bound it is still waiting.
func TestGateLeavesBlobUploadsOutOfTheHeaderBound(t *testing.T) {
	const bound = 200 * time.Millisecond
	front := upstreamGate(t, stallingUpstream(t), bound)
	c, err := front.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	req := fmt.Sprintf("PUT /v2/team/app/blobs/uploads/abc-123?digest=%s HTTP/1.1\r\nHost: registry.test\r\n"+
		"Authorization: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", digestA, basic(tokTeam))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * bound))
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read after %v = %d bytes, %v; want the upload still waiting on the registry", 5*bound, n, err)
	}
}

// TestGateReadErrorLogsCancellationAtDebug: a read that cannot reach the
// registry is a Warn naming the method and path, unless the client cancelled
// it, which is a Debug.
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
			if line["method"] != "GET" || line["path"] != "/v2/team/app/blobs/"+digestA {
				t.Errorf("method, path = %v, %v; want the request's", line["method"], line["path"])
			}
		})
	}
}
