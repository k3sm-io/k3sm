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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	testclock "k8s.io/utils/clock/testing"
)

// fakeRotateRuntime is the rotation seam over a map of container id → log path.
// reopenErr makes ReopenContainerLog fail, which is the case the rollback exists
// for.
type fakeRotateRuntime struct {
	mu        sync.Mutex
	refs      map[string]ContainerLogRef
	running   map[string]bool
	reopenErr error
	reopened  []string
}

func (f *fakeRotateRuntime) RunningContainerLogs(context.Context) ([]ContainerLogRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ContainerLogRef
	for id, ref := range f.refs {
		if f.running[id] {
			out = append(out, ref)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeRotateRuntime) ContainerLog(_ context.Context, id string) (ContainerLogRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ref, ok := f.refs[id]
	if !ok {
		return ContainerLogRef{}, fmt.Errorf("container %q not found", id)
	}
	return ref, nil
}

func (f *fakeRotateRuntime) ReopenContainerLog(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reopenErr != nil {
		return f.reopenErr
	}
	f.reopened = append(f.reopened, id)
	ref := f.refs[id]
	// The real writer creates the file again at the same path; the fake does the
	// same, because rotation's post-condition is that the container has somewhere
	// to write.
	fh, err := os.OpenFile(ref.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	return fh.Close()
}

// newRotator builds a real containerLogManager over f with a frozen clock.
func newRotator(t *testing.T, f *fakeRotateRuntime, maxSize string, maxFiles int, now time.Time) *containerLogManager {
	t.Helper()
	m, err := NewContainerLogManager(f, maxSize, maxFiles, 1, time.Second, NewDirLocks(), nil)
	if err != nil {
		t.Fatalf("NewContainerLogManager: %v", err)
	}
	c, ok := m.(*containerLogManager)
	if !ok {
		t.Fatalf("NewContainerLogManager returned %T, want the real manager", m)
	}
	c.clock = testclock.NewFakeClock(now)
	return c
}

// write creates a file with the given content.
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// names lists a directory's entries, sorted.
func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// TestContainerLogManagerRotates is the port of k8s.io/kubernetes
// pkg/kubelet/logs/container_log_manager_test.go (TestRotateLogs, TestClean,
// TestCleanupUnusedLog, TestRemoveExcessLog, TestCompressLog,
// TestRotateLatestLog).
//
// Rotation is what makes keeping logs on disk safe at all: without it one chatty
// container fills the system volume and the node starts evicting. Each subtest
// below is one of upstream's cases, asserted on the DIRECTORY CONTENTS after the
// operation, because the file set is the entire contract.
func TestContainerLogManagerRotates(t *testing.T) {
	now := time.Date(2026, 9, 13, 10, 15, 0, 0, time.UTC)
	stamp := now.Format(timestampFormat)

	t.Run("rotate, compress, drop the excess, and skip a container that is not running", func(t *testing.T) {
		dir := t.TempDir()
		logs := []string{
			"test-log-1",                 // short: no rotation
			"test-log-2",                 // over the limit: rotates
			"test-log-3",                 // over the limit, with existing rotated siblings
			"test-log-4",                 // over the limit, but the container has exited
			"test-log-3.00000000-000001", // an uncompressed rotated sibling
			"test-log-3.00000000-000000.gz",
		}
		content := []string{
			"short",
			"longer than 10 bytes",
			"longer than 10 bytes",
			"longer than 10 bytes",
			"the length doesn't matter",
			"the length doesn't matter",
		}
		for i := range logs {
			write(t, filepath.Join(dir, logs[i]), content[i])
		}
		f := &fakeRotateRuntime{
			refs: map[string]ContainerLogRef{
				"no-rotate":   {ID: "no-rotate", Path: filepath.Join(dir, logs[0])},
				"rotate":      {ID: "rotate", Path: filepath.Join(dir, logs[1])},
				"excess":      {ID: "excess", Path: filepath.Join(dir, logs[2])},
				"not-running": {ID: "not-running", Path: filepath.Join(dir, logs[3])},
			},
			running: map[string]bool{"no-rotate": true, "rotate": true, "excess": true},
		}
		c := newRotator(t, f, "10", 3, now)

		if err := c.rotateLogs(context.Background()); err != nil {
			t.Fatalf("rotateLogs: %v", err)
		}
		drainQueue(t, c)

		got := names(t, dir)
		want := []string{
			// Under the limit: untouched.
			"test-log-1",
			// Rotated to a timestamped name; the writer reopened the original.
			"test-log-2",
			"test-log-2." + stamp,
			// Same, plus: the pre-existing uncompressed sibling was gzipped, and
			// with MaxFiles=3 only MaxFiles-2 == 1 rotated file may survive
			// alongside, so the oldest .gz went.
			"test-log-3",
			"test-log-3." + stamp,
			"test-log-3.00000000-000001.gz",
			// Not running: never considered, so no empty current file is created
			// and its real output is not pushed one slot closer to deletion.
			"test-log-4",
		}
		assertNames(t, got, want)
	})

	t.Run("a reopen failure rolls the rename back", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "0.log")
		write(t, path, "longer than 10 bytes")
		f := &fakeRotateRuntime{
			refs:      map[string]ContainerLogRef{"c": {ID: "c", Path: path}},
			running:   map[string]bool{"c": true},
			reopenErr: errors.New("runtime says no"),
		}
		c := newRotator(t, f, "10", 3, now)
		if err := c.rotateLogs(context.Background()); err != nil {
			t.Fatalf("rotateLogs: %v", err)
		}
		drainQueue(t, c)

		// The original name is back, and no timestamped file is left behind: the
		// next tick can try again, rather than leaving the container writing into
		// an unlinked descriptor with nothing at the configured path.
		assertNames(t, names(t, dir), []string{"0.log"})
		if body, err := os.ReadFile(path); err != nil || string(body) != "longer than 10 bytes" {
			t.Errorf("0.log = %q/%v, want the original content restored", body, err)
		}
	})

	t.Run("debris from an interrupted rotation is cleaned up", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "0.log")
		write(t, path, "longer than 10 bytes")
		// A .tmp is an interrupted gzip; a plain file whose .gz twin exists has
		// already been superseded. Neither is in use, and both must go.
		write(t, filepath.Join(dir, "0.log.20260101-000000.tmp"), "junk")
		write(t, filepath.Join(dir, "0.log.20260101-000001"), "superseded")
		write(t, filepath.Join(dir, "0.log.20260101-000001.gz"), "the archive")
		f := &fakeRotateRuntime{
			refs:    map[string]ContainerLogRef{"c": {ID: "c", Path: path}},
			running: map[string]bool{"c": true},
		}
		c := newRotator(t, f, "10", 5, now)
		if err := c.rotateLogs(context.Background()); err != nil {
			t.Fatalf("rotateLogs: %v", err)
		}
		drainQueue(t, c)

		assertNames(t, names(t, dir), []string{
			"0.log",
			"0.log." + stamp,
			"0.log.20260101-000001.gz",
		})
	})

	t.Run("at MaxFiles=5 a container settles at five files", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "0.log")
		f := &fakeRotateRuntime{
			refs:    map[string]ContainerLogRef{"c": {ID: "c", Path: path}},
			running: map[string]bool{"c": true},
		}
		c := newRotator(t, f, "10", 5, now)
		// Ten rotations, each with a distinct clock so the timestamped names do
		// not collide. The file COUNT must stop growing at MaxFiles.
		for i := 0; i < 10; i++ {
			write(t, path, "longer than 10 bytes")
			c.clock = testclock.NewFakeClock(now.Add(time.Duration(i) * time.Minute))
			if err := c.rotateLogs(context.Background()); err != nil {
				t.Fatalf("rotateLogs: %v", err)
			}
			drainQueue(t, c)
		}
		got := names(t, dir)
		if len(got) != 5 {
			t.Fatalf("after ten rotations the directory holds %d files (%v), want exactly MaxFiles=5", len(got), got)
		}
		// The newest rotated file is left UNCOMPRESSED so an in-flight reader can
		// finish; everything older is gzipped.
		plain := 0
		for _, n := range got {
			if filepath.Ext(n) != compressSuffix {
				plain++
			}
		}
		if plain != 2 {
			t.Errorf("uncompressed files = %d (%v), want 2 (the current file and the newest rotated one)", plain, got)
		}
	})

	t.Run("a compressed rotated file round-trips", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "0.log")
		write(t, path, "longer than 10 bytes")
		write(t, filepath.Join(dir, "0.log.20260101-000000"), "the older instance's words")
		f := &fakeRotateRuntime{
			refs:    map[string]ContainerLogRef{"c": {ID: "c", Path: path}},
			running: map[string]bool{"c": true},
		}
		c := newRotator(t, f, "10", 5, now)
		if err := c.rotateLogs(context.Background()); err != nil {
			t.Fatalf("rotateLogs: %v", err)
		}
		drainQueue(t, c)

		gz := filepath.Join(dir, "0.log.20260101-000000"+compressSuffix)
		fh, err := os.Open(gz)
		if err != nil {
			t.Fatalf("open %s: %v", gz, err)
		}
		defer func() { _ = fh.Close() }()
		zr, err := gzip.NewReader(fh)
		if err != nil {
			t.Fatalf("gzip reader: %v (a rename before the trailer is written publishes a truncated archive)", err)
		}
		body, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		if string(body) != "the older instance's words" {
			t.Errorf("archive = %q, want the original content", body)
		}
	})

	t.Run("Clean removes the current file and every rotated sibling", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "0.log")
		write(t, path, "current")
		write(t, filepath.Join(dir, "0.log.20260101-000000.gz"), "archived")
		write(t, filepath.Join(dir, "0.log.20260101-000001"), "rotated")
		// A neighbour that is NOT this container's: the glob is <path>*, so it
		// must survive.
		write(t, filepath.Join(dir, "1.log"), "another instance")
		f := &fakeRotateRuntime{refs: map[string]ContainerLogRef{"c": {ID: "c", Path: path}}}
		c := newRotator(t, f, "10", 5, now)
		if err := c.Clean(context.Background(), path); err != nil {
			t.Fatalf("Clean: %v", err)
		}
		assertNames(t, names(t, dir), []string{"1.log"})
	})

	t.Run("MaxFiles <= 1 is refused and a negative size disables rotation", func(t *testing.T) {
		if _, err := NewContainerLogManager(&fakeRotateRuntime{}, "10Mi", 1, 1, time.Second, nil, nil); err == nil {
			t.Error("NewContainerLogManager(maxFiles=1) returned no error; 1 would mean rotating and immediately discarding")
		}
		m, err := NewContainerLogManager(&fakeRotateRuntime{}, "-1", 5, 1, time.Second, nil, nil)
		if err != nil {
			t.Fatalf("NewContainerLogManager(negative size): %v", err)
		}
		if _, ok := m.(stubContainerLogManager); !ok {
			t.Errorf("a negative max size yielded %T, want the stub manager (rotation disabled, as upstream)", m)
		}
	})
}

// assertNames compares two sorted file-name slices.
func assertNames(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("directory = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("directory = %v, want %v", got, want)
		}
	}
}

// drainQueue runs the manager's queue to empty on this goroutine, so a test
// observes the post-rotation directory without racing a worker.
func drainQueue(t *testing.T, c *containerLogManager) {
	t.Helper()
	for c.queue.Len() > 0 {
		if !c.processContainer(context.Background(), 1) {
			return
		}
	}
}
