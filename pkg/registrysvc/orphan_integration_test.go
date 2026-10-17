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
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a fake zot: re-executed from a copy at
// ZotPath(BinDir) with fakeZotEnv set, it does what the real child does to the
// port (its own process group, a listener on fakeZotAddrEnv) and nothing else.
const (
	fakeZotEnv     = "K3SM_REGISTRYSVC_FAKE_ZOT"
	fakeZotAddrEnv = "K3SM_REGISTRYSVC_FAKE_ZOT_ADDR"
)

func TestMain(m *testing.M) {
	switch os.Getenv(fakeZotEnv) {
	case "listen":
		runFakeZot(false)
	case "listen-ignore-term":
		runFakeZot(true)
	}
	os.Exit(m.Run())
}

// runFakeZot never returns: it listens until a signal ends the process.
func runFakeZot(ignoreTerm bool) {
	_ = syscall.Setpgid(0, 0)
	if ignoreTerm {
		signal.Ignore(syscall.SIGTERM)
	}
	ln, err := net.Listen("tcp", os.Getenv(fakeZotAddrEnv))
	if err != nil {
		os.Exit(3)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(4)
		}
		_ = c.Close()
	}
}

// TestRestartRebindsTheIngestPort pins what a server restart must do to the
// registry port: a previous server that was killed before its deferred
// Shutdown leaves its zot child running under launchd and listening, and the
// next server must reclaim that child and bind, not refuse the port forever.
// It is integration-tier because the condition under test is a real held
// loopback port. It also pins what the reclaim must NOT take: a zot whose parent is alive, a
// zot serving some other config, and a foreign listener.
func TestRestartRebindsTheIngestPort(t *testing.T) {
	cases := []struct {
		name string
		// mode is the fake's behavior; orphan whether its parent exits first;
		// otherConfig whether it serves a config that is not this service's.
		mode        string
		orphan      bool
		otherConfig bool
		wantErr     error
		wantGone    bool
	}{
		{name: "an orphaned child is reclaimed and the port rebinds", mode: "listen", orphan: true, wantGone: true},
		{name: "an orphan that ignores SIGTERM is killed and the port rebinds", mode: "listen-ignore-term", orphan: true, wantGone: true},
		{name: "a child whose parent is alive is left alone", mode: "listen", wantErr: ErrPortHeld},
		{name: "an orphan serving another config is left alone", mode: "listen", orphan: true, otherConfig: true, wantErr: ErrPortHeld},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newReclaimService(t)
			cfg := ConfigPath(s.cfg.WorkDir)
			if tc.otherConfig {
				cfg = filepath.Join(t.TempDir(), "config.json")
			}
			pid := startFakeZot(t, s, tc.mode, cfg, tc.orphan)

			err := s.claimPort(t.Context())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("claimPort = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("claimPort = %v, want the port claimed", err)
			}
			if alive := syscall.Kill(pid, 0) == nil; alive == tc.wantGone {
				t.Fatalf("fake zot pid %d alive = %v after claimPort, want %v", pid, alive, !tc.wantGone)
			}
			if tc.wantGone {
				ln, err := net.Listen("tcp", s.Addr())
				if err != nil {
					t.Fatalf("rebind %s after the reclaim: %v", s.Addr(), err)
				}
				_ = ln.Close()
			}
		})
	}

	t.Run("a foreign listener is refused", func(t *testing.T) {
		s := newReclaimService(t)
		ln, err := net.Listen("tcp", s.Addr())
		if err != nil {
			t.Fatalf("open the foreign holder: %v", err)
		}
		defer func() { _ = ln.Close() }()
		if err := s.claimPort(t.Context()); !errors.Is(err, ErrPortHeld) {
			t.Fatalf("claimPort = %v, want ErrPortHeld", err)
		}
	})
}

// newReclaimService returns a service on a free loopback port whose BinDir
// holds a copy of this test binary as its zot.
func newReclaimService(t *testing.T) *Service {
	t.Helper()
	work := t.TempDir()
	s, err := New(Config{
		WorkDir: work,
		BinDir:  filepath.Join(work, "bin"),
		Port:    freePort(t),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.MkdirAll(s.cfg.BinDir, 0o755); err != nil {
		t.Fatalf("create the bin dir: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	if err := os.Link(self, ZotPath(s.cfg.BinDir)); err != nil {
		copyFile(t, self, ZotPath(s.cfg.BinDir))
	}
	return s
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy to %s: %v", dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", dst, err)
	}
}

// startFakeZot starts the fake child with the argv spawn gives the real one
// (serving cfg) and waits until it listens. orphan starts it from a shell that
// exits at once, so it is re-parented to launchd exactly as a killed server's
// child is. The process is SIGKILLed at cleanup whatever the test did.
func startFakeZot(t *testing.T, s *Service, mode, cfg string, orphan bool) int {
	t.Helper()
	env := append(os.Environ(), fakeZotEnv+"="+mode, fakeZotAddrEnv+"="+s.Addr())
	zot := ZotPath(s.cfg.BinDir)
	var pid int
	if orphan {
		sh := exec.Command("/bin/sh", "-c", `"$0" serve "$1" </dev/null >/dev/null 2>&1 & echo $!`, zot, cfg)
		sh.Env = env
		out, err := sh.Output()
		if err != nil {
			t.Fatalf("start the orphaned fake zot: %v", err)
		}
		if pid, err = strconv.Atoi(strings.TrimSpace(string(out))); err != nil {
			t.Fatalf("read the orphan's pid from %q: %v", out, err)
		}
	} else {
		c := exec.Command(zot, "serve", cfg)
		c.Env = env
		if err := c.Start(); err != nil {
			t.Fatalf("start the fake zot: %v", err)
		}
		pid = c.Process.Pid
		t.Cleanup(func() { _ = c.Wait() })
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := false
		if conn, err := net.DialTimeout("tcp", s.Addr(), time.Second); err == nil {
			_ = conn.Close()
			ready = true
		}
		if ready && (!orphan || ppidOf(t, pid) == launchdPID) {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake zot pid %d not listening on %s (orphan=%v) within the bound", pid, s.Addr(), orphan)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func ppidOf(t *testing.T, pid int) int {
	t.Helper()
	procs, err := listOwnProcesses()
	if err != nil {
		t.Fatalf("list processes: %v", err)
	}
	for _, p := range procs {
		if p.pid == pid {
			return p.ppid
		}
	}
	return -1
}
