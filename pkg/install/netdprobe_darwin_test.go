//go:build darwin

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

package install

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// listenUnix binds a unix socket under the test's own dir and hands it to fn on
// its own goroutine. The listener is closed when the test ends, which unblocks
// fn whatever it is waiting on.
func listenUnix(t *testing.T, fn func(net.Listener)) string {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("bind %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go fn(ln)
	return path
}

// TestProbeNetdRequiresAnAnswer is the reason the installer's wait is a round
// trip and not a dial.
//
// connect(2) on a unix socket completes as soon as the listen backlog has room:
// the kernel queues it, and the process that bound the socket need not be
// running its accept loop at all. So a netd that has bound and then wedged —
// still starting, deadlocked, stopped — passes a dial-only probe while serving
// nothing, and `k3sm install` would start the node daemon into it.
//
// These cases are the three states told apart with a REAL listener, because the
// distinction is the kernel's and no fake can prove it.
func TestProbeNetdRequiresAnAnswer(t *testing.T) {
	sys := darwinSystem{}
	// Two of these cases wait out the probe's own timeout by design, so it is
	// shrunk: what is being asserted is the verdict, not the patience.
	orig := netdProbeTimeout
	netdProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { netdProbeTimeout = orig })

	t.Run("a listener that never accepts is not serving", func(t *testing.T) {
		// Bound, and nobody ever calls Accept. The connect still succeeds.
		path := listenUnix(t, func(net.Listener) {})
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
		} else {
			t.Fatalf("the premise of this test is that a connect SUCCEEDS here: %v", err)
		}
		err := sys.ProbeNetd(path)
		if err == nil {
			t.Fatal("ProbeNetd accepted a socket whose daemon never answers — the wedged netd a dial-only probe cannot see")
		}
		if !strings.Contains(err.Error(), "did not answer") {
			t.Errorf("error %q must say the socket accepted and did not answer", err)
		}
	})

	t.Run("a listener that accepts and stays silent is not serving", func(t *testing.T) {
		// One step worse than the above: the accept loop runs, so the
		// connection is established, and the handler behind it does nothing.
		path := listenUnix(t, func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				// Held, deliberately: closing would be an answer.
				t.Cleanup(func() { _ = conn.Close() })
			}
		})
		err := sys.ProbeNetd(path)
		if err == nil {
			t.Fatal("ProbeNetd accepted a daemon that reads nothing and replies to nothing")
		}
		if !strings.Contains(err.Error(), "did not answer") {
			t.Errorf("error %q must say the socket accepted and did not answer", err)
		}
	})

	t.Run("a daemon that replies is serving", func(t *testing.T) {
		path := listenUnix(t, func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					if _, err := wire.ReadFrame(conn, netdProbeMaxReply); err != nil {
						return
					}
					// netd's own answer to a verb it does not know.
					payload, _ := json.Marshal(wire.Response{Version: wire.CurrentVersion(), Error: `unknown verb "` + netdProbeVerb + `"`})
					_ = wire.WriteFrame(conn, payload)
				}()
			}
		})
		if err := sys.ProbeNetd(path); err != nil {
			t.Fatalf("ProbeNetd must accept a daemon that answers, even with an error: %v", err)
		}
	})

	t.Run("a daemon that closes the connection has answered", func(t *testing.T) {
		// netd's peer check declines a uid it does not authorize and closes
		// without a reply. `k3sm install` runs as root and the socket
		// authorizes the service user, so this is the ORDINARY production
		// shape — and it is proof the accept loop and the handler ran.
		path := listenUnix(t, func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		})
		if err := sys.ProbeNetd(path); err != nil {
			t.Fatalf("a netd that rejects this client has still answered it: %v", err)
		}
	})

	t.Run("a daemon that closes before the write lands has answered", func(t *testing.T) {
		// The reject can also land on the WRITE side of the round trip: netd's
		// peer check can close the connection before the probe's frame is
		// even delivered, and the write then fails with EPIPE rather than
		// the read ever seeing the close. That race is what reproduced 2/30
		// against the fake daemon above (its close sometimes beats the
		// write) — this row forces the ordering every time so the assertion
		// does not depend on scheduling luck.
		closed := make(chan struct{})
		path := listenUnix(t, func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
				close(closed)
			}
		})
		orig := netdProbeBeforeWrite
		netdProbeBeforeWrite = func() { <-closed }
		t.Cleanup(func() { netdProbeBeforeWrite = orig })

		if err := sys.ProbeNetd(path); err != nil {
			t.Fatalf("a netd that closes before the write is delivered has still answered it: %v", err)
		}
	})

	t.Run("nothing bound is not serving", func(t *testing.T) {
		if err := sys.ProbeNetd(filepath.Join(shortTempDir(t), "absent")); err == nil {
			t.Fatal("ProbeNetd must fail when there is no socket at all")
		}
	})
}

// shortTempDir is t.TempDir() with a path a unix socket can actually live at: a
// sockaddr_un holds about 104 bytes, and the per-subtest directory name Go
// derives from a test name spends most of that before the socket is named.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k3sm-probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
