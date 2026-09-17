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
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestPodLogsDirsAreRootEquivalent pins the container-log tree's ownership
// policy and the fact that install applies it to BOTH directories.
//
// The policy is the point. Upstream's /var/log/pods is root-owned at 0755, which
// on Linux means root-only. On macOS the node runs as _k3sm, whose primary group
// is `staff` — the default group of every ordinary account — so copying
// upstream's numeric mode across would turn "root only" into "every local user
// can read every pod's output". A regression here is silent and permanent: it
// looks exactly like upstream, and nothing fails.
func TestPodLogsDirsAreRootEquivalent(t *testing.T) {
	t.Run("the policy is 0700 owned by the service user, group wheel", func(t *testing.T) {
		if ContainerLogDirMode != 0o700 {
			t.Errorf("ContainerLogDirMode = %#o, want 0700 (pod output is not readable by every local account)", ContainerLogDirMode)
		}
		if ContainerLogDirGID != 0 {
			t.Errorf("ContainerLogDirGID = %d, want 0 (wheel, not staff — staff is every ordinary account's primary group)", ContainerLogDirGID)
		}
		// And it is NOT the daemon LogDir's policy, which is deliberately laxer
		// because that directory holds only the daemons' own stdout, which an
		// administrator of the Mac may read.
		if ContainerLogDirMode == LogDirMode {
			t.Error("the container-log tree must not use the daemon log dir's mode")
		}
	})

	t.Run("a fresh directory is created at the policy mode", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "pods")
		// The test process's own uid/gid: chowning to _k3sm or to wheel needs
		// root, and what is under test is the MODE and the repair, not whether
		// this process may hand a directory to another user.
		if err := ensureContainerLogDir(dir, os.Getuid(), os.Getgid()); err != nil {
			t.Fatalf("ensureContainerLogDir: %v", err)
		}
		assertMode(t, dir, ContainerLogDirMode)
	})

	t.Run("a group-readable directory is REPAIRED on re-install", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "containers")
		// The state a hand-run mkdir, an older build, or a permissive umask
		// leaves behind. MkdirAll skips an existing directory, so without the
		// explicit chmod this would stay world-readable forever.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := ensureContainerLogDir(dir, os.Getuid(), os.Getgid()); err != nil {
			t.Fatalf("ensureContainerLogDir: %v", err)
		}
		assertMode(t, dir, ContainerLogDirMode)
	})

	t.Run("install creates both directories and uninstall removes both", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}); err != nil {
			t.Fatalf("Install: %v", err)
		}
		for _, dir := range []string{PodLogsDir, ContainerLogsDir} {
			if !slices.Contains(f.calls, "EnsureContainerLogDir:"+dir) {
				t.Errorf("install never ensured %s (calls: %v)", dir, f.calls)
			}
		}

		u := &fakeSystem{}
		if err := Uninstall(context.Background(), u, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		// Removed, unlike DataRoot and the daemon LogDir: every file under it
		// belongs to a pod that will not exist once k3sm is gone.
		for _, dir := range []string{PodLogsDir, ContainerLogsDir} {
			if !slices.Contains(u.calls, "RemoveAll:"+dir) {
				t.Errorf("uninstall never removed %s (calls: %v)", dir, u.calls)
			}
		}
	})

	t.Run("the installed paths are the kubelet's", func(t *testing.T) {
		if PodLogsDir != "/var/log/pods" {
			t.Errorf("PodLogsDir = %q, want /var/log/pods", PodLogsDir)
		}
		if ContainerLogsDir != "/var/log/containers" {
			t.Errorf("ContainerLogsDir = %q, want /var/log/containers", ContainerLogsDir)
		}
	})
}

// assertMode checks a directory's permission bits.
func assertMode(t *testing.T, dir string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if got := info.Mode().Perm(); got != want.Perm() {
		t.Errorf("%s mode = %#o, want %#o", dir, got, want.Perm())
	}
}
