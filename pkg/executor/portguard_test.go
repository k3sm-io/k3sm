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

package executor

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

// TestBootRefusesForeignDatastorePort pins the fail-closed half of datastore
// isolation: bring-up must REFUSE when the kine port is already held, instead of
// spawning a kine that cannot bind and then satisfying its own readiness probe
// from the incumbent's listener — which is how a second control plane came up
// reporting healthy while serving another cluster's database.
//
// It binds a real loopback port because that is the condition under test; nothing
// leaves the host, and no privilege is involved.
func TestBootRefusesForeignDatastorePort(t *testing.T) {
	// The foreign holder: any listener that is not this server's own kine.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open the foreign holder: %v", err)
	}
	defer ln.Close()
	held := ln.Addr().(*net.TCPAddr).Port

	t.Run("held port is refused before the spawn", func(t *testing.T) {
		s := NewSupervised(Config{WorkDir: t.TempDir(), KinePort: held})
		c, err := s.startKine(context.Background())
		if c != nil {
			t.Errorf("startKine returned a component for a held port — it spawned kine anyway")
		}
		if !errors.Is(err, ErrDatastorePortHeld) {
			t.Fatalf("startKine err = %v, want ErrDatastorePortHeld", err)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(held)) {
			t.Errorf("refusal %q does not name the held port %d", err, held)
		}
	})

	t.Run("free port is not refused", func(t *testing.T) {
		s := NewSupervised(Config{WorkDir: t.TempDir(), KinePort: freePort(t)})
		_, err := s.startKine(context.Background())
		// The spawn itself fails (this temp work-dir has no staged kine binary), which
		// is the point: the guard must let a free port through to the spawn rather
		// than refusing everything.
		if errors.Is(err, ErrDatastorePortHeld) {
			t.Fatalf("a free datastore port was refused: %v", err)
		}
	})
}

// TestPreflightDatastorePortSkipsUnsetPort pins that an unset port is left to
// withDefaults rather than probed — preflight must not turn port 0 (bind-anything)
// into a bogus verdict.
func TestPreflightDatastorePortSkipsUnsetPort(t *testing.T) {
	if err := preflightDatastorePort(context.Background(), 0); err != nil {
		t.Fatalf("preflightDatastorePort(0) = %v, want nil", err)
	}
}

// freePort returns a loopback TCP port that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe a free port: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close the probe listener: %v", err)
	}
	return p
}

// TestBringUpRefusesHeldComponentPort pins the same fail-closed guard for the two
// co-located components, and it exists because the readiness wait alone was
// PROVEN insufficient on a live host: with an incumbent control plane holding
// 11562, a second server's scheduler died on the bind, the wait's probe was
// answered by the incumbent's listener, and bring-up went on to report a healthy
// control plane that had no scheduler at all.
//
// So the assertion is specifically that nothing is spawned. A test that only
// checked for an eventual error would pass against the broken behaviour, because
// the error did eventually arrive — several stages later, describing something
// else.
func TestBringUpRefusesHeldComponentPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open the foreign holder: %v", err)
	}
	defer ln.Close()
	held := ln.Addr().(*net.TCPAddr).Port

	for _, tc := range []struct {
		name  string
		start func(*Supervised) func(context.Context) (*component, error)
	}{
		{"scheduler", func(s *Supervised) func(context.Context) (*component, error) { return s.startScheduler }},
		{"controller-manager", func(s *Supervised) func(context.Context) (*component, error) {
			return s.startControllerManager
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			s := NewSupervised(Config{WorkDir: wd})
			spawned := false
			start := func(ctx context.Context) (*component, error) {
				spawned = true
				return tc.start(s)(ctx)
			}
			err := s.startAndAwaitListening(context.Background(), tc.name, start, held)
			if !errors.Is(err, ErrComponentPortHeld) {
				t.Fatalf("startAndAwaitListening on a held port = %v, want ErrComponentPortHeld", err)
			}
			if spawned {
				t.Error("the component was spawned onto a held port — the refusal must come BEFORE the spawn, since after it the readiness probe is answered by the incumbent")
			}
			for _, want := range []string{tc.name, strconv.Itoa(held)} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q must name %q", err, want)
				}
			}
		})
	}

	t.Run("free port is not refused", func(t *testing.T) {
		s := NewSupervised(Config{WorkDir: t.TempDir()})
		err := s.startAndAwaitListening(context.Background(), "scheduler", s.startScheduler, freePort(t))
		// The spawn fails (no staged binary in this temp work-dir), which is the
		// point: a free port must reach the spawn rather than be refused outright.
		if errors.Is(err, ErrComponentPortHeld) {
			t.Fatalf("a free component port was refused: %v", err)
		}
	})
}

// TestPreflightComponentPortSkipsUnsetPort mirrors the datastore case: port 0
// means "the executor will fill the default", not "probe port zero".
func TestPreflightComponentPortSkipsUnsetPort(t *testing.T) {
	if err := preflightComponentPort(context.Background(), "scheduler", 0); err != nil {
		t.Fatalf("preflightComponentPort(0) = %v, want nil", err)
	}
}
