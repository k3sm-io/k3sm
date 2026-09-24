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

package podlogs

import "sync"

// DirLocks hands out one mutex per pod log directory. The rotator and the
// garbage collector are the two writers in this package and they operate on the
// same trees from different goroutines: the rotator renames and gzips a
// container's files while the GC may be deleting that container's older
// instances or removing the pod's directory outright. Serialising them per POD
// (not globally, and not per file) is the smallest scope that makes each
// operation see a stable directory listing, and it keeps a slow gzip on one pod
// from stalling rotation on another.
//
// The key MUST be the pod directory — <podLogsDir>/<ns>_<pod>_<uid>, i.e.
// BuildPodLogsDirectory's result — never a container directory one level below
// it. Every caller keying on anything but that exact string gets its own private
// mutex and no exclusion at all against the others: found during the 2026-09-23
// A1 audit, where the rotator's two call sites keyed on the container directory
// (filepath.Dir of a container log file) while the GC correctly keyed on the pod
// directory, so GC's os.RemoveAll(podDir) and the rotator's rename/gzip inside
// that same tree ran fully concurrently with no lock ever actually shared.
//
// The map only grows within a node's lifetime, bounded by the number of pod
// directories the node has ever held; an entry is a zero-sized mutex, so
// reclaiming them would cost more synchronisation than it saves.
type DirLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewDirLocks returns an empty DirLocks. The zero value is not usable: Get would
// have to lazily build the map under a lock it also uses, so the constructor is
// required rather than optional.
func NewDirLocks() *DirLocks {
	return &DirLocks{locks: map[string]*sync.Mutex{}}
}

// Get returns the mutex guarding dir, creating it on first use.
func (d *DirLocks) Get(dir string) *sync.Mutex {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, ok := d.locks[dir]
	if !ok {
		m = &sync.Mutex{}
		d.locks[dir] = m
	}
	return m
}

// Do runs fn while holding dir's lock.
func (d *DirLocks) Do(dir string, fn func()) {
	m := d.Get(dir)
	m.Lock()
	defer m.Unlock()
	fn()
}
