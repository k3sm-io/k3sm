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
	"sync"
	"time"
)

// fakeSystem is the in-memory System used by the unit tests — no real ifconfig,
// flock, kill, or net.Listen. It records every mutation so a test asserts what
// the lifecycle DID (aliases removed, pids terminated) rather than reaching for
// the host.
type fakeSystem struct {
	mu sync.Mutex

	aliases      []string        // current lo0 inet addresses
	removed      []string        // addresses passed to Lo0RemoveAlias
	aliasErr     error           // Lo0Aliases error injection
	removeErr    error           // Lo0RemoveAlias error injection
	alivePIDs    map[int]bool    // pids ProcessLiveness reports LivenessRunning for
	unprobeable  map[int]bool    // pids ProcessLiveness reports LivenessUnknown for (kill EPERM)
	terminated   []int           // pids passed to TerminateProcess
	busyPorts    map[int]bool    // ports PortFree reports false for
	lockHeld     map[string]bool // paths currently locked (LOCK_NB semantics)
	lockFailNext bool            // force the next LockFile to fail
	// aliveProbe, when set, answers ProcessLiveness instead of the in-memory pid
	// table. A test that spawns a REAL child (the bring-up gates) needs the
	// liveness seam to tell the truth about it; the map cannot.
	aliveProbe func(int) bool
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		alivePIDs:   map[int]bool{},
		unprobeable: map[int]bool{},
		busyPorts:   map[int]bool{},
		lockHeld:    map[string]bool{},
	}
}

func (f *fakeSystem) Lo0Aliases() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.aliasErr != nil {
		return nil, f.aliasErr
	}
	return append([]string(nil), f.aliases...), nil
}

func (f *fakeSystem) Lo0RemoveAlias(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, ip)
	out := f.aliases[:0]
	for _, a := range f.aliases {
		if a != ip {
			out = append(out, a)
		}
	}
	f.aliases = out
	return nil
}

func (f *fakeSystem) ProcessLiveness(pid int) Liveness {
	f.mu.Lock()
	probe := f.aliveProbe
	alive := f.alivePIDs[pid]
	eperm := f.unprobeable[pid]
	f.mu.Unlock()
	if probe != nil {
		if probe(pid) {
			return LivenessRunning
		}
		return LivenessDead
	}
	// The EPERM seam: the pid exists but this uid cannot signal it. Checked BEFORE
	// alivePIDs so a test can model "root-owned and unprobeable" without also
	// having to claim the fake can see it running.
	if eperm {
		return LivenessUnknown
	}
	if alive {
		return LivenessRunning
	}
	return LivenessDead
}

func (f *fakeSystem) TerminateProcess(pid int, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.terminated = append(f.terminated, pid)
	delete(f.alivePIDs, pid)
	return nil
}

func (f *fakeSystem) PortFree(port int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.busyPorts[port]
}

func (f *fakeSystem) LockFile(path string) (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lockFailNext || f.lockHeld[path] {
		return nil, fmt.Errorf("resource temporarily unavailable")
	}
	f.lockHeld[path] = true
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.lockHeld, path)
		return nil
	}, nil
}
