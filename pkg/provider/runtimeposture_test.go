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
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/image"
)

// RuntimePosture is the posture NewRuntimed hands runtimed for the same cfg:
// the pod root runtimed defaults, and the data root, state dir, status record
// dir and container-log root runtimedConfigOf carries, firmlink-spelled and
// symlinked inputs included.
func TestRuntimePostureIsTheRuntimesConfig(t *testing.T) {
	t.Parallel()
	base := resolvedTempDir(t)
	data, target := filepath.Join(base, "data"), filepath.Join(base, "elsewhere")
	for _, dir := range []string{data, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(data, "server")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  RuntimedConfig
	}{
		{"the default", RuntimedConfig{}},
		{"a firmlink-spelled data root", RuntimedConfig{Root: "/var/k3sm-posture-absent", DataRoot: "/private/var/k3sm-posture-absent", StateDir: "/private/var/k3sm-posture-absent/server"}},
		{"a symlinked state dir", RuntimedConfig{Root: data, DataRoot: data, StateDir: filepath.Join(data, "server"), PodLogsDir: filepath.Join(base, "logs")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := RuntimePosture(tc.cfg)
			if err != nil {
				t.Fatalf("RuntimePosture: %v", err)
			}
			statusDir, err := statusRecordDirOf(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			dataRoot, stateDir, err := dataRootOf(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			rc := runtimedConfigOf(tc.cfg, slog.New(slog.DiscardHandler), statusDir, dataRoot, stateDir)
			root := rc.Root
			if root == "" {
				root = image.DefaultRoot // runtime.New's own default
			}
			if got.WorkDir != root || got.DataRoot != rc.DataRoot || got.StateDir != rc.StateDir || got.StatusRecordDir != rc.StatusRecordDir || got.PodLogsDir != rc.PodLogsDir {
				t.Errorf("RuntimePosture = %+v; the runtime is given Root %q DataRoot %q StateDir %q StatusRecordDir %q PodLogsDir %q",
					got, root, rc.DataRoot, rc.StateDir, rc.StatusRecordDir, rc.PodLogsDir)
			}
		})
	}
}
