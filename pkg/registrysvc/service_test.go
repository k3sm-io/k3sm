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
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNewBindDiscipline pins the refusal that IS the security posture: the ingest
// registry serves anonymous pulls over plain HTTP, so a bind it can be talked
// into making off-loopback would publish every image in the cluster and carry the
// push credential in the clear. New must reject one — configuration must not be
// able to widen it.
func TestNewBindDiscipline(t *testing.T) {
	cases := []struct {
		name    string
		bind    string
		port    int
		wantErr error
		wantIP  string
	}{
		{name: "empty defaults to loopback", bind: "", port: 6450, wantIP: LoopbackAddress},
		{name: "explicit IPv4 loopback", bind: "127.0.0.1", port: 6450, wantIP: "127.0.0.1"},
		{name: "an alternate IPv4 loopback address", bind: "127.0.0.53", port: 6450, wantIP: "127.0.0.53"},
		{name: "IPv6 loopback", bind: "::1", port: 6450, wantIP: "::1"},
		{name: "wildcard is refused", bind: "0.0.0.0", port: 6450, wantErr: ErrNonLoopbackBind},
		{name: "IPv6 wildcard is refused", bind: "::", port: 6450, wantErr: ErrNonLoopbackBind},
		{name: "a routable LAN address is refused", bind: "192.168.1.5", port: 6450, wantErr: ErrNonLoopbackBind},
		{name: "a mesh address is refused", bind: "100.64.0.1", port: 6450, wantErr: ErrNonLoopbackBind},
		{name: "a name is refused (only IPs are bindable)", bind: "localhost", port: 6450, wantErr: ErrNonLoopbackBind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(Config{WorkDir: t.TempDir(), BindAddress: tc.bind, Port: tc.port})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("New(%q) err = %v, want %v", tc.bind, err, tc.wantErr)
				}
				if s != nil {
					t.Errorf("New(%q) returned a service alongside its refusal", tc.bind)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) = %v, want a service", tc.bind, err)
			}
			if want := net.JoinHostPort(tc.wantIP, strconv.Itoa(tc.port)); s.Addr() != want {
				t.Errorf("Addr() = %q, want %q", s.Addr(), want)
			}
			if s.Port() != tc.port {
				t.Errorf("Port() = %d, want %d", s.Port(), tc.port)
			}
		})
	}
}

// TestNewRejectsUnusableConfig covers the two refusals that are not about the
// address: a port outside the range, and no work dir to put the state in.
func TestNewRejectsUnusableConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{name: "port zero", cfg: Config{WorkDir: t.TempDir(), Port: 0}},
		{name: "negative port", cfg: Config{WorkDir: t.TempDir(), Port: -1}},
		{name: "port above the range", cfg: Config{WorkDir: t.TempDir(), Port: 65536}},
		{name: "no work dir", cfg: Config{Port: 6450}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New(%+v) = nil, want an error", tc.cfg)
			}
		})
	}
}

// TestNewDerivesPaths pins the defaults New fills in, because every one of them
// is a path another part of k3sm joins independently — the bin dir the control
// plane's own binaries live in, and the pinned zot version.
func TestNewDerivesPaths(t *testing.T) {
	work := t.TempDir()
	s, err := New(Config{WorkDir: work, Port: 6450})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if want := filepath.Join(work, "bin"); s.cfg.BinDir != want {
		t.Errorf("BinDir = %q, want %q", s.cfg.BinDir, want)
	}
	if s.cfg.ZotVersion != DefaultZotVersion {
		t.Errorf("ZotVersion = %q, want %q", s.cfg.ZotVersion, DefaultZotVersion)
	}
	if s.cfg.Logger == nil {
		t.Error("Logger is nil; a Service must never log through a nil handler")
	}
}

// TestWorkDirLayout pins the on-disk contract this package publishes to the rest
// of k3sm. CredentialPath in particular is read by `k3sm image push`, so a change
// to it is a change to a cross-package interface, not an implementation detail.
func TestWorkDirLayout(t *testing.T) {
	const work = "/var/lib/k3sm/server"
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"state dir", StateDir(work), "/var/lib/k3sm/server/registry"},
		{"config", ConfigPath(work), "/var/lib/k3sm/server/registry/config.json"},
		{"htpasswd", HTPasswdPath(work), "/var/lib/k3sm/server/registry/htpasswd"},
		{"credential", CredentialPath(work), "/var/lib/k3sm/server/registry/push-credential.json"},
		{"log", LogPath(work), "/var/lib/k3sm/server/registry.log"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("= %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// TestPreflightPortRefusesAHeldPort pins the fail-closed half of the bring-up: a
// port already held must be refused BEFORE the spawn, because the readiness wait
// afterwards would be satisfied by the incumbent's listener and the registry
// would report itself up while every push went somewhere else.
//
// It binds a real loopback port because that is the condition under test; nothing
// leaves the host and no privilege is involved.
func TestPreflightPortRefusesAHeldPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open the foreign holder: %v", err)
	}
	defer func() { _ = ln.Close() }()
	held := ln.Addr().(*net.TCPAddr).Port

	t.Run("held", func(t *testing.T) {
		err := preflightPort("127.0.0.1", held)
		if !errors.Is(err, ErrPortHeld) {
			t.Fatalf("preflightPort(held) = %v, want ErrPortHeld", err)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(held)) {
			t.Errorf("refusal %q does not name the held port %d", err, held)
		}
	})

	t.Run("free", func(t *testing.T) {
		free := freePort(t)
		if err := preflightPort("127.0.0.1", free); err != nil {
			t.Fatalf("preflightPort(free) = %v, want nil", err)
		}
	})
}

// TestShutdownIsSafeBeforeStart pins that teardown of a service that never
// started is a no-op rather than a nil dereference — the path a bring-up takes
// when Start gave up and the caller still runs its deferred shutdown.
func TestShutdownIsSafeBeforeStart(t *testing.T) {
	s, err := New(Config{WorkDir: t.TempDir(), Port: 6450})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown before Start = %v, want nil", err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown is not idempotent: %v", err)
	}
}

// freePort returns a loopback port that is free at the moment it is asked.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe a free port: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release the probed port: %v", err)
	}
	return p
}
