//go:build integration && darwin

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
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/executor"
)

// reapHelperEnv names the file a helper process reports "<pid> <port>" in. Its
// presence is what turns TestReapOrphanHelperProcess into the helper.
const reapHelperEnv = "K3SM_REAP_HELPER_REPORT"

// TestReapOrphanHelperProcess is not a test: run as a copy of this test binary
// with reapHelperEnv set, it is a stand-in control-plane child that listens on a
// loopback port and runs until it is signalled. The test timeout passed to it
// bounds its life if a run ever leaks one.
func TestReapOrphanHelperProcess(t *testing.T) {
	report := os.Getenv(reapHelperEnv)
	if report == "" {
		t.Skip("helper process only")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(3)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	tmp := report + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d\n", os.Getpid(), port)), 0o600); err != nil {
		os.Exit(4)
	}
	if err := os.Rename(tmp, report); err != nil {
		os.Exit(5)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(6)
		}
		_ = c.Close()
	}
}

// reapHelper is one planted helper process.
type reapHelper struct {
	pid, port int
	start     int64
}

// alive reports whether the helper is still the process it was planted as.
func (h reapHelper) alive() bool {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", h.pid)
	if err != nil || int(kp.Proc.P_pid) != h.pid || kp.Proc.P_stat == 5 /* SZOMB */ {
		return false
	}
	return kp.Proc.P_starttime.Nano() == h.start
}

// plantHelper copies this test binary to exe and starts it there as a helper,
// orphaned (a double fork through sh, so its parent is launchd) unless child is
// set, in which case it is a direct child of the test process. The helper is
// SIGKILLed at cleanup if it is still the same process.
func plantHelper(t *testing.T, exe string, orphan bool) reapHelper {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(exe); os.IsNotExist(err) {
		if err := unix.Clonefile(self, exe, 0); err != nil {
			copyFile(t, self, exe)
		}
	}
	report := filepath.Join(t.TempDir(), "helper.report")
	args := []string{"-test.run=^TestReapOrphanHelperProcess$", "-test.timeout=5m"}
	env := append(os.Environ(), reapHelperEnv+"="+report)
	var cmd *exec.Cmd
	if orphan {
		cmd = exec.Command("/bin/sh", append([]string{"-c", `"$0" "$@" </dev/null >/dev/null 2>&1 &`, exe}, args...)...)
	} else {
		cmd = exec.Command(exe, args...)
	}
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if orphan {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("intermediate shell: %v", err)
		}
	} else {
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	var h reapHelper
	deadline := time.Now().Add(30 * time.Second)
	for {
		b, err := os.ReadFile(report)
		if err == nil {
			f := strings.Fields(string(b))
			if len(f) == 2 {
				h.pid, _ = strconv.Atoi(f[0])
				h.port, _ = strconv.Atoi(f[1])
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper at %s never reported its port", exe)
		}
		time.Sleep(20 * time.Millisecond)
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", h.pid)
	if err != nil {
		t.Fatalf("read helper pid %d: %v", h.pid, err)
	}
	h.start = kp.Proc.P_starttime.Nano()
	if orphan && kp.Eproc.Ppid != 1 {
		t.Fatalf("helper pid %d has ppid %d, want 1 (orphaned)", h.pid, kp.Eproc.Ppid)
	}
	t.Cleanup(func() {
		if h.alive() {
			_ = unix.Kill(h.pid, syscall.SIGKILL)
		}
	})
	return h
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// freeLoopbackPort returns a loopback port nothing listens on right now.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// reapOpts is a server's options over wd with the datastore on kinePort and the
// component ports moved off their defaults, so a cluster on this Mac is never
// probed.
func reapOpts(t *testing.T, wd string, kinePort int) serverOptions {
	return serverOptions{
		workDir:               wd,
		kinePort:              kinePort,
		apiPort:               freeLoopbackPort(t),
		schedulerPort:         freeLoopbackPort(t),
		controllerManagerPort: freeLoopbackPort(t),
	}
}

// TestServerStartReapsItsOwnOrphanedControlPlane is the gate for a killed server's
// restart: the first step of a server start (reapServerOrphans) stops exactly the
// control-plane processes a previous run of the same work dir left orphaned, with
// real processes and real ports, and nothing else.
func TestServerStartReapsItsOwnOrphanedControlPlane(t *testing.T) {
	orig := daemonStartTime
	t.Cleanup(func() { daemonStartTime = orig })
	// Every helper is planted before the reap runs, so "now" at the reap is a
	// daemon start later than all of them, the shape of a launchd respawn.
	daemonStartTime = func() (time.Time, error) { return time.Now(), nil }

	run := func(t *testing.T, opts serverOptions) (executor.OrphanReap, error, *bytes.Buffer) {
		t.Helper()
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		res, err := reapServerOrphans(t.Context(), opts, newCrashBreaker(opts.workDir, logger), logger)
		t.Cleanup(func() { _ = res.Hold.Release() })
		return res, err, &logs
	}

	t.Run("own orphaned kine is reaped, the port freed, the breaker untouched", func(t *testing.T) {
		wd := filepath.Join(t.TempDir(), "server")
		h := plantHelper(t, filepath.Join(wd, "bin", "kine"), true)
		res, err, logs := run(t, reapOpts(t, wd, h.port))
		if err != nil {
			t.Fatalf("start step = %v, want the reap to succeed", err)
		}
		if h.alive() {
			t.Fatalf("the orphaned kine pid %d survived the reap", h.pid)
		}
		if len(res.Reaped) != 1 || res.Reaped[0].Pid != h.pid || res.Reaped[0].Signal != syscall.SIGTERM {
			t.Fatalf("Reaped = %+v, want pid %d by SIGTERM", res.Reaped, h.pid)
		}
		if res.PortsHeld != nil {
			t.Fatalf("PortsHeld after the reap = %v, want the ports free", res.PortsHeld)
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port)))
		if err != nil {
			t.Fatalf("the datastore port is still held after the reap: %v", err)
		}
		_ = ln.Close()
		if res.Hold == nil {
			t.Fatal("no work-dir hold returned for the executor to adopt")
		}
		if _, err := os.Stat(executor.CrashLoopPath(wd)); !os.IsNotExist(err) {
			t.Fatalf("a successful reap touched the crash-loop record (%v)", err)
		}
		if !strings.Contains(logs.String(), "stopped a control-plane process a previous run of this server left running") ||
			!strings.Contains(logs.String(), "pid="+strconv.Itoa(h.pid)) {
			t.Fatalf("no per-process Warn line for pid %d:\n%s", h.pid, logs.String())
		}
	})

	t.Run("a foreign listener outside the work dir's bin keeps the refusal and survives", func(t *testing.T) {
		root := t.TempDir()
		wd := filepath.Join(root, "server")
		if err := os.MkdirAll(filepath.Join(wd, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		h := plantHelper(t, filepath.Join(root, "elsewhere", "kine"), true)
		res, err, _ := run(t, reapOpts(t, wd, h.port))
		if err != nil {
			t.Fatalf("start step = %v, want no reap error", err)
		}
		if len(res.Reaped) != 0 {
			t.Fatalf("Reaped = %+v, want nothing", res.Reaped)
		}
		if !errors.Is(res.PortsHeld, executor.ErrDatastorePortHeld) {
			t.Fatalf("PortsHeld = %v, want ErrDatastorePortHeld", res.PortsHeld)
		}
		if !h.alive() {
			t.Fatalf("the foreign holder pid %d was killed", h.pid)
		}
	})

	t.Run("bin2 and another work dir's bin survive", func(t *testing.T) {
		root := t.TempDir()
		wd := filepath.Join(root, "server")
		if err := os.MkdirAll(filepath.Join(wd, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		bin2 := plantHelper(t, filepath.Join(wd, "bin2", "kine"), true)
		other := plantHelper(t, filepath.Join(root, "other-server", "bin", "kine"), true)
		res, err, _ := run(t, reapOpts(t, wd, bin2.port))
		if err != nil {
			t.Fatalf("start step = %v", err)
		}
		if len(res.Reaped) != 0 || !bin2.alive() || !other.alive() {
			t.Fatalf("Reaped = %+v, bin2 alive %v, other work dir alive %v; want nothing reaped", res.Reaped, bin2.alive(), other.alive())
		}
		if !errors.Is(res.PortsHeld, executor.ErrDatastorePortHeld) {
			t.Fatalf("PortsHeld = %v, want ErrDatastorePortHeld", res.PortsHeld)
		}
	})

	t.Run("a live supervisor's child survives", func(t *testing.T) {
		t.Run("ppid is not launchd", func(t *testing.T) {
			wd := filepath.Join(t.TempDir(), "server")
			h := plantHelper(t, filepath.Join(wd, "bin", "kine"), false)
			res, err, _ := run(t, reapOpts(t, wd, h.port))
			if err != nil {
				t.Fatalf("start step = %v", err)
			}
			if len(res.Reaped) != 0 || !h.alive() {
				t.Fatalf("Reaped = %+v, alive %v; a live parent's child must survive", res.Reaped, h.alive())
			}
			if !errors.Is(res.PortsHeld, executor.ErrDatastorePortHeld) {
				t.Fatalf("PortsHeld = %v, want ErrDatastorePortHeld", res.PortsHeld)
			}
		})
		t.Run("another holder has the work-dir lock", func(t *testing.T) {
			wd := filepath.Join(t.TempDir(), "server")
			h := plantHelper(t, filepath.Join(wd, "bin", "kine"), true)
			lock, err := os.OpenFile(executor.WorkDirLockPath(wd), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			res, err, _ := run(t, reapOpts(t, wd, h.port))
			if !errors.Is(err, executor.ErrWorkDirLocked) {
				t.Fatalf("start step = %v, want ErrWorkDirLocked", err)
			}
			if len(res.Reaped) != 0 || !h.alive() {
				t.Fatalf("Reaped = %+v, alive %v; nothing may be reaped under another holder's lock", res.Reaped, h.alive())
			}
		})
	})

	t.Run("a work dir reached through a symlink is still reaped", func(t *testing.T) {
		real := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		wd := filepath.Join(link, "server")
		h := plantHelper(t, filepath.Join(wd, "bin", "kine"), true)
		res, err, _ := run(t, reapOpts(t, wd, h.port))
		if err != nil {
			t.Fatalf("start step = %v", err)
		}
		if h.alive() || len(res.Reaped) != 1 || res.Reaped[0].Pid != h.pid {
			t.Fatalf("Reaped = %+v, alive %v; want pid %d reaped through the symlinked work dir", res.Reaped, h.alive(), h.pid)
		}
	})

	t.Run("the etcd posture reaps nothing", func(t *testing.T) {
		wd := filepath.Join(t.TempDir(), "server")
		h := plantHelper(t, filepath.Join(wd, "bin", "kine"), true)
		opts := reapOpts(t, wd, h.port)
		opts.clusterInit = true
		res, err, _ := run(t, opts)
		if err != nil {
			t.Fatalf("start step = %v", err)
		}
		if len(res.Reaped) != 0 || !h.alive() || res.Hold != nil {
			t.Fatalf("Reaped = %+v, alive %v, hold %v; the etcd posture must reap nothing and take no lock here", res.Reaped, h.alive(), res.Hold)
		}
		if _, err := os.Stat(executor.WorkDirLockPath(wd)); !os.IsNotExist(err) {
			t.Fatalf("the etcd posture's reap step created the lock file (%v)", err)
		}
	})
}
