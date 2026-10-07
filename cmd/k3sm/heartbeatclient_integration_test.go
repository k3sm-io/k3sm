//go:build integration

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
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

// freezingProxy is a TCP relay on loopback that can make every connection it
// is carrying go half-open: freeze stops forwarding bytes on the connections
// open at that moment WITHOUT closing them, which is what a Wi-Fi roam or a
// dropped NAT entry looks like from the client (no RST, no FIN, just silence).
// Connections accepted after the freeze forward normally.
type freezingProxy struct {
	ln      net.Listener
	target  string
	stop    chan struct{}
	accepts atomic.Int32

	mu    sync.Mutex // guards conns
	conns []*relay
}

type relay struct {
	frozen atomic.Bool
}

func newFreezingProxy(t *testing.T, target string) *freezingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &freezingProxy{ln: ln, target: target, stop: make(chan struct{})}
	t.Cleanup(func() { close(p.stop); _ = ln.Close() })
	go p.serve()
	return p
}

func (p *freezingProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepts.Add(1)
		up, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		r := &relay{}
		p.mu.Lock()
		p.conns = append(p.conns, r)
		p.mu.Unlock()
		go p.pipe(r, c, up)
		go p.pipe(r, up, c)
	}
}

// pipe copies src to dst until either side closes. Once r is frozen it keeps
// reading (so the sender's kernel buffer never fills and nothing errors) and
// drops what it reads, and it never closes either side.
func (p *freezingProxy) pipe(r *relay, src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !r.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if !r.frozen.Load() {
				_ = dst.Close()
			} else {
				<-p.stop
			}
			return
		}
	}
}

func (p *freezingProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.conns {
		r.frozen.Store(true)
	}
}

// TestHeartbeatClientRedialsAfterHalfOpenConnection drives the heartbeat
// client's transport through a connection that goes half-open mid-life, on a
// real loopback TLS/HTTP2 listener. The client must (1) speak HTTP/2, (2) fail
// a request on the silent connection within the request bound instead of
// waiting on it, and (3) succeed again on a NEW connection within the bound the
// health check gives (idle + PING), rather than reusing the dead one.
func TestHeartbeatClientRedialsAfterHalfOpenConnection(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	proxy := newFreezingProxy(t, srv.Listener.Addr().String())

	tm := heartbeatTiming{
		request:   time.Second,
		dial:      time.Second,
		handshake: time.Second,
		readIdle:  200 * time.Millisecond,
		ping:      200 * time.Millisecond,
	}
	base := &rest.Config{
		Host: "https://" + proxy.ln.Addr().String(),
		TLSClientConfig: rest.TLSClientConfig{
			CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}),
		},
		Timeout: 90 * time.Second,
	}
	cfg, err := heartbeatRESTConfig(base, tm)
	if err != nil {
		t.Fatalf("heartbeatRESTConfig: %v", err)
	}
	if base.Timeout != 90*time.Second || base.Transport != nil || len(base.TLSClientConfig.CAData) == 0 {
		t.Fatal("heartbeatRESTConfig modified its base config; the general node client would change with it")
	}
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		t.Fatalf("HTTPClientFor: %v", err)
	}
	get := func() (*http.Response, error) {
		resp, err := hc.Get(base.Host + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		return resp, err
	}

	resp, err := get()
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("first request used %s, want HTTP/2 (the health check is an HTTP/2 PING)", resp.Proto)
	}

	proxy.freeze()
	start := time.Now()
	if _, err := get(); err == nil {
		t.Fatal("a request on the frozen connection succeeded; the proxy is not freezing")
	}
	if took := time.Since(start); took > tm.request+time.Second {
		t.Fatalf("the request on a half-open connection failed after %s, want within the %s request bound", took, tm.request)
	}

	bound := tm.request + tm.readIdle + tm.ping + 2*time.Second
	deadline := time.Now().Add(bound)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, lastErr = get(); lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("no request succeeded within %s of the connection going half-open: %v", bound, lastErr)
	}
	if got := proxy.accepts.Load(); got < 2 {
		t.Fatalf("proxy accepted %d connections, want a second one: the recovery did not redial", got)
	}
}
