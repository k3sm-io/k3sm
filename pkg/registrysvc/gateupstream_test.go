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
	"net"
	"strings"
	"sync"
	"testing"
	"time"
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

// upstreamGate is the fixture's gate over the default loopback transport,
// pointed at upstream.
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
// connection and never answers costs an authorized write a 502 within the
// response-header bound, not a wait until the client gives up.
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
