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
	"bytes"
	"context"
	"errors"
	"testing"
)

// newTestManager builds a Manager over a fake System + a temp-rooted registry,
// with kubeconfig chown disabled (not-under-sudo). euid selects the privilege
// posture under test.
func newTestManager(t *testing.T, sys System, euid int) *Manager {
	t.Helper()
	m := NewManager(ManagerConfig{
		Registry: NewRegistry(t.TempDir()),
		System:   sys,
		Self:     "/usr/local/bin/k3sm",
		EUID:     euid,
		Out:      &bytes.Buffer{},
	})
	// Force not-under-sudo chown semantics regardless of the test environment's
	// SUDO_USER, so the merge/chown paths are deterministic.
	m.kubeMg.chownUser, m.kubeMg.chownUID, m.kubeMg.chownGID = "", -1, -1
	return m
}

func TestUpDatapathRequiresRoot(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501) // non-root
	_, err := m.Up(context.Background(), UpOptions{Name: "dev", Datapath: true})
	if !errors.Is(err, ErrDatapathRequiresRoot) {
		t.Fatalf("Up(--datapath) as non-root = %v, want ErrDatapathRequiresRoot", err)
	}
	// The error must carry the actionable sudo line.
	if !bytes.Contains([]byte(err.Error()), []byte("sudo")) {
		t.Errorf("error %q missing the sudo remediation line", err)
	}
}

func TestUpDatapathSingletonLiveAlias(t *testing.T) {
	sys := newFakeSystem()
	// A live datapath instance's pod-CIDR lo0 alias is already present → a second
	// --datapath up must fail fast BEFORE its pre-flight flush tears it down.
	sys.aliases = []string{"100.64.0.1"}
	m := newTestManager(t, sys, 0) // root
	_, err := m.Up(context.Background(), UpOptions{Name: "b", Datapath: true})
	if !errors.Is(err, ErrDatapathSingleton) {
		t.Fatalf("second --datapath up with a live alias = %v, want ErrDatapathSingleton", err)
	}
	// It must NOT have removed the live alias (the whole point of the assert).
	if len(sys.removed) != 0 {
		t.Errorf("singleton violation removed aliases %v, want none (live datapath preserved)", sys.removed)
	}
}

func TestUpDatapathSingletonLockHeld(t *testing.T) {
	sys := newFakeSystem()
	m := newTestManager(t, sys, 0)
	// Simulate a concurrent holder of the datapath lock.
	sys.lockHeld[m.datapathLockPath()] = true
	_, err := m.Up(context.Background(), UpOptions{Name: "c", Datapath: true})
	if !errors.Is(err, ErrDatapathSingleton) {
		t.Fatalf("Up with the datapath lock held = %v, want ErrDatapathSingleton", err)
	}
}

func TestPreflightReclaimNoManifest(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501)
	// A missing manifest is a clean first boot — no error, nothing reaped.
	if err := m.preflightReclaim("fresh"); err != nil {
		t.Fatalf("preflightReclaim on absent manifest = %v, want nil", err)
	}
}

func TestPreflightReclaimReapsStalePidAndAliases(t *testing.T) {
	sys := newFakeSystem()
	sys.alivePIDs[9999] = true                         // the prior server is still alive
	sys.aliases = []string{"10.43.0.10", "100.64.0.7"} // its datapath aliases persist
	m := newTestManager(t, sys, 0)                     // root (so lo0 flush runs)
	prior := sampleInstance("crashed")
	prior.PID = 9999
	prior.Tier = tierRoot
	prior.Datapath = DatapathDirect
	if err := m.reg.Save(prior); err != nil {
		t.Fatalf("seed prior manifest: %v", err)
	}

	if err := m.preflightReclaim("crashed"); err != nil {
		t.Fatalf("preflightReclaim: %v", err)
	}
	// The stale pid was terminated.
	if len(sys.terminated) != 1 || sys.terminated[0] != 9999 {
		t.Errorf("terminated = %v, want [9999] (stale pid reaped)", sys.terminated)
	}
	// Its Service+pod lo0 aliases were flushed.
	wantRemoved := map[string]bool{"10.43.0.10": true, "100.64.0.7": true}
	for _, r := range sys.removed {
		delete(wantRemoved, r)
	}
	if len(wantRemoved) != 0 {
		t.Errorf("reclaim did not flush %v", wantRemoved)
	}
}

func TestPreflightReclaimRootlessSkipsFlush(t *testing.T) {
	sys := newFakeSystem()
	sys.aliases = []string{"10.43.0.10"} // a stray alias, but the prior run was rootless
	m := newTestManager(t, sys, 501)     // non-root
	prior := sampleInstance("rl")
	prior.PID = 0 // rootless: no live server recorded
	prior.Datapath = DatapathNone
	if err := m.reg.Save(prior); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.preflightReclaim("rl"); err != nil {
		t.Fatalf("preflightReclaim: %v", err)
	}
	// Rootless reclaim never removes lo0 aliases (it allocates none; removal needs root).
	if len(sys.removed) != 0 {
		t.Errorf("rootless reclaim removed %v, want none", sys.removed)
	}
}

func TestLoadValidatesPath(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501)
	// A non-existent path is rejected here, not at pod admission.
	if _, err := m.Load("/definitely/not/a/real/binary/xyz"); err == nil {
		t.Error("Load on a missing path = nil, want an error")
	}
	// A real file yields the stamped image line.
	f := t.TempDir() + "/mybin"
	if err := writeExecutable(f); err != nil {
		t.Fatal(err)
	}
	line, err := m.Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Contains([]byte(line), []byte("NON-PORTABLE")) {
		t.Errorf("Load line %q missing the non-portable stamp", line)
	}
}
