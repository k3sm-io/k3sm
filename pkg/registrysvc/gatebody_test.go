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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestGateCutsUpstreamStalledAfterHeaders: a loopback registry that sends a
// blob's headers and part of its body and then goes silent loses the
// connection one progress window later, through the gate's real loopback
// transport: the client's read ends early with a truncated body and the
// registry's request is cancelled. A registry that sends slowly but keeps
// sending, for longer than the window in total, is not cut.
func TestGateCutsUpstreamStalledAfterHeaders(t *testing.T) {
	const (
		window = 150 * time.Millisecond
		// bound is generous: the cut is due one window after the last byte.
		bound = 5 * time.Second
		size  = 12
	)
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
				// size bytes, one every window/3: about 4 windows in all.
				for range size {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(window / 3):
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

			f := newGateFixture(t)
			g := newGate(gateConfig{
				Upstream:             strings.TrimPrefix(up.URL, "http://"),
				Auth:                 GateAuth{Tokens: f.tokens, Access: f.access, Namespaces: f.namespaces},
				Credential:           gateCred,
				Logger:               quietLogger(),
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
		})
	}
}
