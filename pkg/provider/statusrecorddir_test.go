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

package provider

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/runtimed/pkg/sandbox"
)

// statusDirProfile renders the profile a node with work dir workDir gets
// for a status record dir of statusDir.
func statusDirProfile(t *testing.T, workDir, statusDir string) string {
	t.Helper()
	out, err := sandbox.Generate(&runtimev1.SandboxProfile{DataVolumePath: filepath.Join(workDir, "pods", "p1", "rootfs")}, sandbox.GenerateOptions{
		Posture: sandbox.Posture{WorkDir: workDir, StatusRecordDir: statusDir},
	})
	if err != nil {
		t.Fatalf("sandbox.Generate: %v", err)
	}
	return out
}

// TestStatusRecordDirOnADefaultNode pins the no-drift half: on a default node the
// value is <WorkDir>/status as the runtime joins it, in the /var spelling, and the
// rendered profile is byte for byte the one a node without the field gets, so an
// upgrade does not refuse a single re-attach.
func TestStatusRecordDirOnADefaultNode(t *testing.T) {
	t.Parallel()
	dir := install.StateStatus.Path(install.DefaultDataRoot)
	root := runtimeRoot("")
	got, err := statusRecordDirOf(RuntimedConfig{StatusRecordDir: dir})
	if err != nil {
		t.Fatalf("statusRecordDirOf(%q) on the default path: %v", dir, err)
	}
	if want := filepath.Join(root, sandbox.StatusSubdir); got != want {
		t.Errorf("default value = %q, want %q (the runtime's own join)", got, want)
	}
	if strings.HasPrefix(got, "/private/") {
		t.Errorf("default value = %q, which would change the profile digest", got)
	}
	if statusDirProfile(t, root, got) != statusDirProfile(t, root, "") {
		t.Error("a default node's profile changed, which refuses every re-attach as drift")
	}
}

// TestStatusRecordDirUnderACustomPodRoot pins the reason the field exists: with the
// runtime root moved, the data root's status directory is still what gets denied.
func TestStatusRecordDirUnderACustomPodRoot(t *testing.T) {
	t.Parallel()
	dir := install.StateStatus.Path(install.DefaultDataRoot)
	got, err := statusRecordDirOf(RuntimedConfig{Root: "/opt/k3sm-pods", StatusRecordDir: dir})
	if err != nil {
		t.Fatalf("statusRecordDirOf: %v", err)
	}
	if got != dir {
		t.Errorf("value = %q, want the data root's %q", got, dir)
	}
	profile := statusDirProfile(t, "/opt/k3sm-pods", got)
	for _, form := range []string{dir, "/private" + dir} {
		if !strings.Contains(profile, `(subpath "`+form+`")`) {
			t.Errorf("profile under a custom pod root does not deny %q", form)
		}
	}
}

// resolvedTempDir is a temp dir with no symlink in its path but the firmlinks.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func TestCheckStatusRecordDir(t *testing.T) {
	t.Parallel()
	mkdir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		setup   func(t *testing.T, base string) string
		refused bool
	}{
		{"empty is unset", func(*testing.T, string) string { return "" }, false},
		{"missing has nothing to mismatch", func(_ *testing.T, base string) string {
			return filepath.Join(base, "status")
		}, false},
		{"an existing real directory", func(t *testing.T, base string) string {
			dir := filepath.Join(base, "status")
			mkdir(t, dir)
			return dir
		}, false},
		{"a firmlink spelling is not a mismatch", func(t *testing.T, base string) string {
			dir := filepath.Join(base, "status")
			mkdir(t, dir)
			return strings.TrimPrefix(dir, "/private")
		}, false},
		{"the directory itself is a symlink", func(t *testing.T, base string) string {
			target := filepath.Join(base, "target")
			mkdir(t, target)
			dir := filepath.Join(base, "status")
			link(t, target, dir)
			return dir
		}, true},
		{"an ancestor is a symlink", func(t *testing.T, base string) string {
			mkdir(t, filepath.Join(base, "target", "status"))
			link(t, filepath.Join(base, "target"), filepath.Join(base, "data"))
			return filepath.Join(base, "data", "status")
		}, true},
		{"a dangling symlink cannot be checked", func(t *testing.T, base string) string {
			dir := filepath.Join(base, "status")
			link(t, filepath.Join(base, "gone"), dir)
			return dir
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := tc.setup(t, resolvedTempDir(t))
			err := checkStatusRecordDir(dir)
			if got := errors.Is(err, ErrStatusRecordDirNotCanonical); got != tc.refused {
				t.Errorf("checkStatusRecordDir(%q) = %v, refused = %v, want %v", dir, err, got, tc.refused)
			}
		})
	}
}

// TestNewRuntimedRefusesAStatusRecordDirItCannotDeny drives the constructor, so the
// value is proven to reach both refusals, and each is proven to name itself in the
// log as well as in the returned error.
func TestNewRuntimedRefusesAStatusRecordDirItCannotDeny(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, base string) string
		want  error
	}{
		{"a symlinked directory, refused here", func(t *testing.T, base string) string {
			dir := filepath.Join(base, "status")
			if err := os.Symlink(base, dir); err != nil {
				t.Fatal(err)
			}
			return dir
		}, ErrStatusRecordDirNotCanonical},
		{"under the pods root, refused by the runtime", func(_ *testing.T, base string) string {
			return filepath.Join(base, "pods", "status")
		}, sandbox.ErrInvalidStatusRecordDir},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := resolvedTempDir(t)
			var logged bytes.Buffer
			_, err := NewRuntimed(context.Background(), RuntimedConfig{
				NodeName:        "n1",
				Root:            base,
				PodLogsDir:      filepath.Join(base, "podlogs"),
				StatusRecordDir: tc.setup(t, base),
				Logger:          slog.New(slog.NewTextHandler(&logged, nil)),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewRuntimed err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(logged.String(), "level=ERROR") || !strings.Contains(logged.String(), tc.want.Error()) {
				t.Errorf("the refusal is not logged by name:\n%s", logged.String())
			}
		})
	}
}
