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

package dev

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// System is the syscall seam the dev lifecycle isolates so the reclaim/lock/port
// logic is unit-testable without touching the real host: lo0 alias listing +
// flushing (ifconfig), process liveness + termination (kill), a free-port probe,
// and a work-dir file lock (flock). Defined at the consumer (this package) and
// kept small; the production implementation is realSystem, the tests inject a
// fake.
type System interface {
	// Lo0Aliases returns the IPv4 addresses currently aliased on lo0 (the output
	// of `ifconfig lo0` inet lines). The datapath tier binds Service/pod VIPs as
	// /32 lo0 aliases that outlive the process, so teardown + pre-flight sweep
	// them (see Lo0Flush).
	Lo0Aliases() ([]string, error)
	// Lo0RemoveAlias removes a single /32 lo0 alias (`ifconfig lo0 -alias <ip>`).
	// It requires root; unprivileged callers never allocate lo0 aliases (the
	// rootless tier runs network=none), so a flush there is a no-op over an empty
	// set.
	Lo0RemoveAlias(ip string) error
	// ProcessAlive reports whether pid is a live process (kill -0). A stale pid
	// from a crashed prior run reads false, so pre-flight reclaim reaps it.
	ProcessAlive(pid int) bool
	// TerminateProcess sends SIGTERM to pid's process group, waits up to grace for
	// it to exit, then SIGKILLs. The supervised control plane runs each component
	// in its own process group (executor.spawnEnv Setpgid), so signalling the
	// group tears the whole tree down.
	TerminateProcess(pid int, grace time.Duration) error
	// PortFree reports whether TCP 127.0.0.1:port can be bound right now (probe an
	// actual listen so allocation never hands out a squatted port).
	PortFree(port int) bool
	// LockFile takes an exclusive, non-blocking advisory lock on path (flock
	// LOCK_EX|LOCK_NB), returning an unlock func. A second holder gets an error —
	// the --datapath singleton lock. The returned func releases the lock and
	// closes the fd.
	LockFile(path string) (unlock func() error, err error)
}

// realSystem is the production System over ifconfig/kill/net.Listen/flock.
type realSystem struct{}

// NewSystem returns the production System implementation.
func NewSystem() System { return realSystem{} }

// Lo0Aliases shells `ifconfig lo0` and parses its `inet <ip>` lines.
func (realSystem) Lo0Aliases() ([]string, error) {
	out, err := exec.Command("ifconfig", "lo0").Output()
	if err != nil {
		return nil, fmt.Errorf("ifconfig lo0: %w", err)
	}
	return parseLo0Inet(string(out)), nil
}

// parseLo0Inet extracts the IPv4 addresses from `ifconfig lo0` output. It is a
// pure helper so the parsing is unit-tested off a golden fixture.
func parseLo0Inet(out string) []string {
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// inet lines look like: "inet 100.64.0.2 netmask 0xffffffff"
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				ips = append(ips, f[i+1])
				break
			}
		}
	}
	return ips
}

// Lo0RemoveAlias runs `ifconfig lo0 -alias <ip>`.
func (realSystem) Lo0RemoveAlias(ip string) error {
	if out, err := exec.Command("ifconfig", "lo0", "-alias", ip).CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig lo0 -alias %s: %w (%s)", ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ProcessAlive sends signal 0 to pid.
func (realSystem) ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// TerminateProcess SIGTERMs the process group, waits grace, then SIGKILLs.
func (realSystem) TerminateProcess(pid int, grace time.Duration) error {
	if pid <= 0 {
		return nil
	}
	// Signal the whole process group (the child was started Setpgid, so -pid is
	// its group). Best-effort: an already-dead process yields ESRCH.
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	return nil
}

// PortFree probes a bind of 127.0.0.1:port.
func (realSystem) PortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// LockFile takes a non-blocking exclusive flock on path.
func (realSystem) LockFile(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() error {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}, nil
}
