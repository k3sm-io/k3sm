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

package api_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/auth"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// fakeConn is a net.Conn that only names its remote address, which is all the
// ConnState hook reads.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

// newAuthServer is the registry server with the auth package's Access wired as
// it is in production: Authorize and ConnClosed. The clock never moves, so a
// spent bucket never refills during the test.
func newAuthServer(t *testing.T, secret string, maxConns int) *http.Server {
	t.Helper()
	at := time.Unix(1_700_000_000, 0)
	a, err := auth.New(auth.Config{
		Principals: []auth.Principal{
			{User: auth.UserPush, SecretSHA256: auth.HashSecret(secret)},
			{User: auth.UserGate, SecretSHA256: auth.HashSecret("gate-" + secret)},
		},
		Burst: 2,
		Now:   func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Config{
		Store:      st,
		Authorize:  a.Authorize,
		ConnClosed: a.ConnClosed,
		MaxConns:   maxConns,
		FreeSpace:  func() (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv.HTTPServer("127.0.0.1:0")
}

// versionCheck sends GET /v2/ from remote with the k3sm user and secret.
func versionCheck(hs *http.Server, remote, secret string) int {
	r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	r.RemoteAddr = remote
	r.SetBasicAuth(auth.UserPush, secret)
	w := httptest.NewRecorder()
	hs.Handler.ServeHTTP(w, r)
	return w.Code
}

// TestClosedConnectionBucketIsDropped pins that a source's failure bucket ends
// with its connection: a later connection that reuses the host and port starts
// with a full bucket, while the bucket keeps limiting for as long as the
// connection that spent it stays open.
func TestClosedConnectionBucketIsDropped(t *testing.T) {
	const secret = "the-right-secret"
	cases := []struct {
		name  string
		end   []http.ConnState
		after int
	}{
		{name: "closed", end: []http.ConnState{http.StateClosed}, after: http.StatusOK},
		{name: "hijacked", end: []http.ConnState{http.StateHijacked}, after: http.StatusOK},
		{name: "idle between requests still limits", end: []http.ConnState{http.StateIdle}, after: http.StatusTooManyRequests},
		{name: "open still limits", after: http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := newAuthServer(t, secret, 0)
			const remote = "127.0.0.1:49152"
			addr, err := net.ResolveTCPAddr("tcp", remote)
			if err != nil {
				t.Fatal(err)
			}
			c := fakeConn{remote: addr}
			hs.ConnState(c, http.StateNew)
			hs.ConnState(c, http.StateActive)
			for i := range 2 {
				if got := versionCheck(hs, remote, "wrong"); got != http.StatusUnauthorized {
					t.Fatalf("wrong secret %d: %d, want 401", i, got)
				}
			}
			if got := versionCheck(hs, remote, secret); got != http.StatusTooManyRequests {
				t.Fatalf("right secret on the spent connection: %d, want 429", got)
			}
			for _, s := range tc.end {
				hs.ConnState(c, s)
			}
			if len(tc.end) > 0 && tc.end[0] != http.StateIdle {
				// A new connection that the kernel gave the same port.
				hs.ConnState(c, http.StateNew)
				hs.ConnState(c, http.StateActive)
			}
			if got := versionCheck(hs, remote, secret); got != tc.after {
				t.Fatalf("right secret afterwards: %d, want %d", got, tc.after)
			}
		})
	}
}

// TestConnectionCap pins the listener bounds: the header read timeout, and a
// connection past MaxConns is closed before a request is read, until an open
// connection ends.
func TestConnectionCap(t *testing.T) {
	hs := newAuthServer(t, "s", 2)
	if hs.ReadHeaderTimeout != api.ReadHeaderTimeout || hs.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout %v, want %v", hs.ReadHeaderTimeout, api.ReadHeaderTimeout)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	addr := ln.Addr().String()

	get := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(c, "GET /v2/ HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			return err
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New(resp.Status)
		}
		return nil
	}
	dial := func() net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	held := []net.Conn{dial(), dial()}
	for i, c := range held {
		if err := get(c); err != nil {
			t.Fatalf("connection %d under the cap: %v", i, err)
		}
	}
	if err := get(dial()); err == nil {
		t.Fatal("a third connection over a cap of 2 was served")
	}
	_ = held[0].Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := get(dial())
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection served after one of the two ended: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
