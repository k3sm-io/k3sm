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

package registrysvc

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestServiceRunsTheK3smRegistry runs the whole service with this test binary as
// the executable: Start spawns `<exe> registry serve --config ...`, TestMain runs
// the real Serve, and the registry answers on the configured port with the
// credentials the service minted. It binds a real socket and spawns a real child,
// so it is integration-tagged.
func TestServiceRunsTheK3smRegistry(t *testing.T) {
	work := t.TempDir()
	dbs := seedZotDatabases(t, work)
	s, err := New(Config{WorkDir: work, Port: freePort(t), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	b, err := os.ReadFile(StatePath(work))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseState(b)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateServing {
		t.Errorf("record %+v, want serving", st)
	}

	// The child is the exact argv, a child of this process, of this uid.
	procs, err := listOwnProcesses()
	if err != nil {
		t.Fatal(err)
	}
	var found *procEntry
	for i := range procs {
		if procs[i].ppid == os.Getpid() && slices.Equal(procs[i].argv, s.childArgv()) {
			found = &procs[i]
		}
	}
	if found == nil {
		t.Fatalf("no child with argv %q", s.childArgv())
	}
	if found.pgid != found.pid {
		t.Errorf("child pgid %d, want its own group %d", found.pgid, found.pid)
	}
	// A live parent keeps it from being taken for an orphan.
	if s.isOrphanedChild(*found) {
		t.Error("a child with a live parent matched as an orphan")
	}

	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	base := "http://" + s.Addr() + "/v2/"
	if resp := do(t, c, http.MethodGet, base, "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous /v2/: %d, want 200", resp.StatusCode)
	}
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous upload: %d, want 401", resp.StatusCode)
	}
	gate := s.GateCredential()
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", gate.Username, gate.Password); resp.StatusCode != http.StatusAccepted {
		t.Errorf("the gate credential: %d, want 202", resp.StatusCode)
	}
	push, err := ReadCredential(work)
	if err != nil {
		t.Fatal(err)
	}
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", push.Username, push.Password); resp.StatusCode != http.StatusAccepted {
		t.Errorf("the push credential: %d, want 202", resp.StatusCode)
	}

	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", s.Addr(), time.Second); err == nil {
		t.Error("the port still answers after Shutdown")
	}
	log, err := os.ReadFile(LogPath(work))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), `"msg":"registry server serving"`) || !strings.Contains(string(log), `"reason":"anonymous"`) {
		t.Errorf("registry.log:\n%s", log)
	}
	for _, secret := range []string{gate.Password, push.Password} {
		if strings.Contains(string(log), secret) {
			t.Error("registry.log carries a secret")
		}
	}
	dbs.check(t)
}

// TestAwaitNeedsA200: readiness is a 200 on /v2/, not a connect.
func TestAwaitNeedsA200(t *testing.T) {
	status := http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{WorkDir: t.TempDir(), BindAddress: host, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{http.StatusInternalServerError, http.StatusUnauthorized} {
		status = code
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		err := s.await(ctx, make(chan struct{}))
		cancel()
		if err == nil {
			t.Errorf("await accepted a %d", code)
		}
	}
	status = http.StatusOK
	if err := s.await(t.Context(), make(chan struct{})); err != nil {
		t.Errorf("await refused a 200: %v", err)
	}
	exited := make(chan struct{})
	close(exited)
	if err := s.await(t.Context(), exited); err == nil {
		t.Error("await took a 200 from an incumbent after the child exited")
	}
}

// TestRegistryReadyFollowsNoRedirect: the readiness probe stays on the address it
// was given. Whatever holds the port cannot send it elsewhere, or borrow another
// server's 200.
func TestRegistryReadyFollowsNoRedirect(t *testing.T) {
	var followed atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer other.Close()
	holder := httptest.NewServer(http.RedirectHandler(other.URL+"/v2/", http.StatusFound))
	defer holder.Close()
	if err := registryReady(t.Context(), holder.Listener.Addr().String()); err == nil {
		t.Error("a redirect to a 200 counted as the registry answering")
	}
	if followed.Load() {
		t.Error("the probe followed the redirect")
	}
}
