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
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
)

// fakePurge is the fake's model of what `uninstall --purge` reads and changes
// beyond the ordinary uninstall. Every zero value describes the quiet case: no
// path exists (so nothing is purged until a test seeds it), no marker, the
// service user exists and is the one k3sm created with the default data root as
// its home, no process runs as it, and every bootout unloads.
type fakePurge struct {
	// stats answers StatNoFollow; an absent key is a missing path.
	stats map[string]PathStat
	// resolved answers ResolvePath; an absent key resolves to itself.
	resolved map[string]string
	// markers answers ReadDataRootMarker; markerErrs overrides it.
	markers    map[string]dataroot.MarkerFacts
	markerErrs map[string]error
	// purgeErrs makes PurgeTree fail for a root (a mount point found inside it).
	purgeErrs map[string]error
	// user, when set, is the service user record; nil is the k3sm-created one.
	user *ServiceUserRecord
	// userDeleted is set by DeleteServiceUser.
	userDeleted bool
	// procs are the pids running as the service user; unkillable survive
	// KillProcess.
	procs      []int
	unkillable map[int]bool
	// bootoutErrs makes LaunchctlBootout fail for a label; stuck labels are
	// accepted for bootout and never leave the loaded list.
	bootoutErrs map[string]error
	stuck       map[string]bool
	// kubeErr is what RemoveAdminKubeconfigContext returns.
	kubeErr error
	// ino numbers the directories seedPurgeable creates.
	ino uint64
}

// seedPurgeable makes each dir exist in the fake as a real directory on device
// 1, under a parent on the same device, carrying a valid k3sm marker: the
// posture of a tree a current install laid down.
func (f *fakeSystem) seedPurgeable(dirs ...string) {
	for _, d := range dirs {
		f.putStat(filepath.Dir(d), EntryDir, 1)
		f.putStat(d, EntryDir, 1)
		f.putMarker(d, dataroot.MarkerFacts{Regular: true, UID: 0, Mode: 0o644, Content: dataroot.MarkerContent(d)})
	}
}

// putStat seeds one StatNoFollow answer.
func (f *fakeSystem) putStat(path string, kind EntryKind, dev uint64) {
	if f.purge.stats == nil {
		f.purge.stats = map[string]PathStat{}
	}
	f.purge.ino++
	f.purge.stats[path] = PathStat{Kind: kind, Dev: dev, Ino: f.purge.ino}
}

// putMarker seeds one marker.
func (f *fakeSystem) putMarker(dir string, facts dataroot.MarkerFacts) {
	if f.purge.markers == nil {
		f.purge.markers = map[string]dataroot.MarkerFacts{}
	}
	f.purge.markers[dir] = facts
}

func (f *fakeSystem) ResolvePath(path string) (string, error) {
	f.calls = append(f.calls, "ResolvePath:"+path)
	if r, ok := f.purge.resolved[path]; ok {
		return r, nil
	}
	return path, nil
}

func (f *fakeSystem) StatNoFollow(path string) (PathStat, error) {
	f.calls = append(f.calls, "StatNoFollow:"+path)
	if st, ok := f.purge.stats[path]; ok {
		return st, nil
	}
	return PathStat{}, fmt.Errorf("lstat %s: %w", path, fs.ErrNotExist)
}

func (f *fakeSystem) ReadDataRootMarker(dir string) (dataroot.MarkerFacts, error) {
	f.calls = append(f.calls, "ReadDataRootMarker:"+dir)
	if err := f.purge.markerErrs[dir]; err != nil {
		return dataroot.MarkerFacts{}, err
	}
	if m, ok := f.purge.markers[dir]; ok {
		return m, nil
	}
	return dataroot.MarkerFacts{}, fmt.Errorf("open %s: %w", dataroot.MarkerPath(dir), fs.ErrNotExist)
}

// WriteDataRootMarker records the write and leaves the marker a real install
// would: root-owned, 0644, naming dir.
func (f *fakeSystem) WriteDataRootMarker(dir string) error {
	f.calls = append(f.calls, "WriteDataRootMarker:"+dir)
	f.putMarker(dir, dataroot.MarkerFacts{Regular: true, UID: 0, Mode: 0o644, Content: dataroot.MarkerContent(dir)})
	return nil
}

// PurgeTree records the purge, refuses a root that is not the (dev, ino) it is
// handed, and removes the root and everything the fake knows under it.
func (f *fakeSystem) PurgeTree(root string, dev, ino uint64) error {
	f.calls = append(f.calls, "PurgeTree:"+root)
	if err := f.purge.purgeErrs[root]; err != nil {
		return err
	}
	st, ok := f.purge.stats[root]
	if !ok || st.Dev != dev || st.Ino != ino {
		return fmt.Errorf("%s is no longer the directory that was checked", root)
	}
	under := func(p string) bool { return p == root || strings.HasPrefix(p, root+"/") }
	for p := range f.purge.stats {
		if under(p) {
			delete(f.purge.stats, p)
		}
	}
	for p := range f.purge.markers {
		if under(p) {
			delete(f.purge.markers, p)
		}
	}
	for p := range f.files {
		if under(p) {
			delete(f.files, p)
		}
	}
	return nil
}

func (f *fakeSystem) LoadedLabels(prefix string) ([]string, error) {
	f.calls = append(f.calls, "LoadedLabels:"+prefix)
	var out []string
	for l := range f.loaded {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (f *fakeSystem) ProcessesOfUID(uid uint32) ([]int, error) {
	f.calls = append(f.calls, "ProcessesOfUID:"+strconv.Itoa(int(uid)))
	return slices.Clone(f.purge.procs), nil
}

// KillProcess records the kill and removes the pid, unless it is unkillable.
func (f *fakeSystem) KillProcess(pid int) error {
	f.calls = append(f.calls, "KillProcess:"+strconv.Itoa(pid))
	if !f.purge.unkillable[pid] {
		f.purge.procs = slices.DeleteFunc(f.purge.procs, func(p int) bool { return p == pid })
	}
	return nil
}

func (f *fakeSystem) ServiceUser(name string) (ServiceUserRecord, error) {
	f.calls = append(f.calls, "ServiceUser:"+name)
	switch {
	case f.purge.userDeleted:
		return ServiceUserRecord{}, nil
	case f.purge.user != nil:
		return *f.purge.user, nil
	}
	return ServiceUserRecord{Exists: true, UID: 271, RealName: serviceUserRealName, Shell: serviceUserShell, Home: DefaultDataRoot}, nil
}

func (f *fakeSystem) DeleteServiceUser(name string) error {
	f.calls = append(f.calls, "DeleteServiceUser:"+name)
	f.purge.userDeleted = true
	return nil
}

func (f *fakeSystem) RemoveAdminKubeconfigContext(targetUser string) error {
	f.calls = append(f.calls, "RemoveAdminKubeconfigContext:"+targetUser)
	return f.purge.kubeErr
}

// shrinkPurgeBudgets makes every purge wait end at its first re-check.
func shrinkPurgeBudgets(t *testing.T) {
	t.Helper()
	settle, grace, kill, poll := purgeSettle, purgeGrace, purgeKillWait, purgePoll
	purgeSettle, purgeGrace, purgeKillWait, purgePoll = 0, 0, 0, 0
	t.Cleanup(func() { purgeSettle, purgeGrace, purgeKillWait, purgePoll = settle, grace, kill, poll })
}
