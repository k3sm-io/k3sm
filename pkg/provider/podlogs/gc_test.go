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

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakePodState is the GC's seam: a set of known pod UIDs, a sync bit, and a set
// of running container ids.
type fakePodState struct {
	uids    map[string]struct{}
	synced  bool
	running map[string]bool
}

func (f fakePodState) KnownPodUIDs(context.Context) (map[string]struct{}, bool) {
	return f.uids, f.synced
}

func (f fakePodState) ContainerRunning(_ context.Context, id string) (bool, error) {
	return f.running[id], nil
}

// touch creates an empty file, making parents as needed.
func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// exists reports whether a path is present.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// TestPodLogDirLifecycle covers the whole life of a pod's log tree: creation by
// the provider (asserted there), instance pruning to exactly one previous
// instance, removal on delete, the orphan sweep, and the dangling-symlink rules.
//
// It is the gate on the one component that DELETES container output. Every case
// below is a way logs could silently go missing, which is why the sweep is
// deliberately conservative: it deletes only files it can prove it wrote, only
// after the pod source has synced, and never a symlink whose container is still
// running.
func TestPodLogDirLifecycle(t *testing.T) {
	t.Run("keeps the current instance and exactly one previous", func(t *testing.T) {
		root := t.TempDir()
		podDir := BuildPodLogsDirectory(root, "default", "web", "uid-1")
		cdir := filepath.Join(podDir, "c0")
		// Four instances, one of them with a rotated and a compressed sibling.
		touch(t, filepath.Join(cdir, "0.log"))
		touch(t, filepath.Join(cdir, "1.log"))
		touch(t, filepath.Join(cdir, "2.log"))
		touch(t, filepath.Join(cdir, "2.log.20260101-000000.gz"))
		touch(t, filepath.Join(cdir, "3.log"))
		touch(t, filepath.Join(cdir, "3.log.20260101-000001"))
		// Not an instance file: never this sweep's to delete.
		touch(t, filepath.Join(cdir, "notes.txt"))

		gc := NewGC(root, "", fakePodState{uids: map[string]struct{}{"uid-1": {}}, synced: true}, nil, nil)
		gc.RunOnce(context.Background())

		// MaxPerPodContainer is 1, so instances 3 (current) and 2 (the one
		// `kubectl logs --previous` reads) survive WITH their rotated siblings,
		// and 0 and 1 go.
		for _, keep := range []string{"3.log", "3.log.20260101-000001", "2.log", "2.log.20260101-000000.gz", "notes.txt"} {
			if !exists(filepath.Join(cdir, keep)) {
				t.Errorf("%s was deleted, want kept", keep)
			}
		}
		for _, gone := range []string{"0.log", "1.log"} {
			if exists(filepath.Join(cdir, gone)) {
				t.Errorf("%s survived, want deleted (MaxPerPodContainer=1 keeps the current instance plus one)", gone)
			}
		}
	})

	t.Run("removes the tree of a pod the node no longer has", func(t *testing.T) {
		root := t.TempDir()
		mine := BuildPodLogsDirectory(root, "default", "web", "uid-1")
		orphan := BuildPodLogsDirectory(root, "default", "gone", "uid-2")
		touch(t, filepath.Join(mine, "c0", "0.log"))
		touch(t, filepath.Join(orphan, "c0", "0.log"))

		gc := NewGC(root, "", fakePodState{uids: map[string]struct{}{"uid-1": {}}, synced: true}, nil, nil)
		gc.RunOnce(context.Background())

		if !exists(mine) {
			t.Error("the tracked pod's log tree was removed")
		}
		if exists(orphan) {
			t.Error("the orphaned pod's log tree survived")
		}
	})

	t.Run("deletes NOTHING before the pod source has synced", func(t *testing.T) {
		root := t.TempDir()
		dir := BuildPodLogsDirectory(root, "default", "web", "uid-1")
		touch(t, filepath.Join(dir, "c0", "0.log"))
		touch(t, filepath.Join(dir, "c0", "1.log"))
		touch(t, filepath.Join(dir, "c0", "2.log"))
		touch(t, filepath.Join(dir, "c0", "3.log"))

		// An empty, UNSYNCED pod set is exactly the state a node is in for the
		// first seconds after a restart. Treating it as "every pod is gone" would
		// wipe the node's logs on every restart, which is the single most
		// destructive thing this package could do.
		gc := NewGC(root, "", fakePodState{synced: false}, nil, nil)
		gc.RunOnce(context.Background())

		if !exists(dir) {
			t.Fatal("an unsynced pod source let the GC delete a pod log tree")
		}
		for _, n := range []string{"0.log", "1.log", "2.log", "3.log"} {
			if !exists(filepath.Join(dir, "c0", n)) {
				t.Errorf("%s was pruned before the pod source synced", n)
			}
		}
	})

	t.Run("RemovePodLogs removes the pod's tree and tolerates a missing one", func(t *testing.T) {
		root := t.TempDir()
		dir := BuildPodLogsDirectory(root, "team-a", "job", "uid-9")
		touch(t, filepath.Join(dir, "c0", "0.log"))

		gc := NewGC(root, "", fakePodState{synced: true}, nil, nil)
		if err := gc.RemovePodLogs("team-a", "job", "uid-9"); err != nil {
			t.Fatalf("RemovePodLogs: %v", err)
		}
		if exists(dir) {
			t.Error("the pod's log tree survived RemovePodLogs")
		}
		// A pod whose containers never started has no directory; removing it must
		// not be an error, or every such delete would log a failure.
		if err := gc.RemovePodLogs("team-a", "never-started", "uid-10"); err != nil {
			t.Errorf("RemovePodLogs on an absent tree = %v, want nil", err)
		}
	})

	t.Run("dangling symlinks go only when their container is not running", func(t *testing.T) {
		root := t.TempDir()
		links := t.TempDir()
		target := filepath.Join(root, "default_web_uid-1", "c0", "0.log")
		touch(t, target)

		// Hex container ids, as runtimed mints them (a sha256 of the pod,
		// container, pgid and start time): the flat symlink name is parsed back
		// on its LAST hyphen-separated field, so an id containing a hyphen would
		// be unparseable — which is why runtimed's is hex and why the pod name,
		// which may contain hyphens, sits to the left of it.
		live := LogSymlink(links, "web", "default", "c0", "aaaa1111bbbb2222")
		dead := LogSymlink(links, "web", "default", "c1", "cccc3333dddd4444")
		good := LogSymlink(links, "web", "default", "c2", "eeee5555ffff6666")
		// live and dead both point at a target that does not exist — the state
		// rotation passes through between renaming the file and the writer
		// reopening it (kubernetes#52172).
		for _, l := range []string{live, dead} {
			if err := os.Symlink(filepath.Join(root, "missing.log"), l); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}
		if err := os.Symlink(target, good); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		gc := NewGC(root, links, fakePodState{
			uids:    map[string]struct{}{"uid-1": {}},
			synced:  true,
			running: map[string]bool{"aaaa1111bbbb2222": true},
		}, nil, nil)
		gc.RunOnce(context.Background())

		if !exists(live) {
			t.Error("a running container's momentarily-dangling symlink was removed (the rotation race, kubernetes#52172)")
		}
		if exists(dead) {
			t.Error("an exited container's dangling symlink survived")
		}
		if !exists(good) {
			t.Error("a healthy symlink was removed")
		}
	})
}

// TestLogSymlinkNaming pins the flat symlink's name and its truncation, because
// the name is a compatibility surface every log shipper globs and parses.
func TestLogSymlinkNaming(t *testing.T) {
	got := LogSymlink(ContainerLogsDir, "web", "default", "c0", "abc123")
	want := filepath.Join(ContainerLogsDir, "web_default_c0-abc123.log")
	if got != want {
		t.Errorf("LogSymlink = %q, want %q", got, want)
	}

	long := LogSymlink(ContainerLogsDir, repeat("p", 200), repeat("n", 200), "c0", "abc123")
	base := filepath.Base(long)
	if len(base) != maxFileNameLen {
		t.Errorf("truncated symlink name is %d bytes, want %d", len(base), maxFileNameLen)
	}
	// The suffix survives the truncation, which is what keeps a "*.log" glob
	// matching an over-long name.
	if filepath.Ext(base) != ".log" {
		t.Errorf("truncated symlink name %q does not end in .log", base)
	}

	id, err := ContainerIDFromLogSymlink(want)
	if err != nil || id != "abc123" {
		t.Errorf("ContainerIDFromLogSymlink(%q) = (%q, %v), want (abc123, nil)", want, id, err)
	}
	// A trailing field too short to be an id is not treated as one: deleting a
	// file on that evidence would be deleting somebody else's.
	if _, err := ContainerIDFromLogSymlink("/var/log/containers/web_default_c0-ab.log"); err == nil {
		t.Error("ContainerIDFromLogSymlink accepted a two-character id")
	}
}

// repeat returns s repeated n times.
func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
