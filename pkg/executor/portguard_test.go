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
