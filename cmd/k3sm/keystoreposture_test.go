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

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore/socket"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The posture the keystore socket's start check renders the Pod profile
// from is the one the server's runtime renders from: for the same options,
// serverPodPosture's WorkDir, DataRoot and StateDir are the ones the
// provider derives from the RuntimedConfig the server's node is given
// (serverRuntimeDirs through runtimedConfig), and the values that
// derivation is known to produce: the runtime root's spelling for a
// firmlink-spelled data root, the resolved target of a symlinked state dir,
// and runtimed's default pod root.
func TestServerPodPostureMatchesRuntime(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, target := filepath.Join(base, "data"), filepath.Join(base, "elsewhere")
	for _, dir := range []string{data, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(data, "server")); err != nil {
		t.Fatal(err)
	}
	const absent = "k3sm-posture-absent"
	for _, tt := range []struct {
		name                        string
		opts                        serverOptions
		workDir, dataRoot, stateDir string
	}{
		{
			name:     "a /private/var data root under a /var pod root",
			opts:     serverOptions{workDir: "/private/var/" + absent + "/server", podRoot: "/var/" + absent},
			workDir:  "/var/" + absent,
			dataRoot: "/var/" + absent,
			stateDir: "/private/var/" + absent + "/server",
		},
		{
			name:     "a /System/Volumes/Data data root under a / pod root",
			opts:     serverOptions{workDir: "/System/Volumes/Data/" + absent + "/server", podRoot: "/" + absent},
			workDir:  "/" + absent,
			dataRoot: "/System/Volumes/Data/" + absent,
			stateDir: "/System/Volumes/Data/" + absent + "/server",
		},
		{
			name:     "a symlinked state dir",
			opts:     serverOptions{workDir: filepath.Join(data, "server"), podRoot: data},
			workDir:  data,
			dataRoot: data,
			stateDir: target,
		},
		{
			name:     "the default",
			opts:     serverOptions{workDir: install.DefaultDataRoot + "/server"},
			workDir:  image.DefaultRoot,
			dataRoot: install.DefaultDataRoot,
			stateDir: install.DefaultDataRoot + "/server",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serverPodPosture(tt.opts)
			if err != nil {
				t.Fatalf("serverPodPosture: %v", err)
			}
			want, err := provider.RuntimePosture(runtimedConfig(serverRuntimeDirs(tt.opts), nil))
			if err != nil {
				t.Fatalf("the runtime's posture: %v", err)
			}
			if got.WorkDir != want.WorkDir || got.DataRoot != want.DataRoot || got.StateDir != want.StateDir {
				t.Errorf("serverPodPosture = WorkDir %q DataRoot %q StateDir %q; the runtime renders from WorkDir %q DataRoot %q StateDir %q",
					got.WorkDir, got.DataRoot, got.StateDir, want.WorkDir, want.DataRoot, want.StateDir)
			}
			if got.WorkDir != tt.workDir || got.DataRoot != tt.dataRoot || got.StateDir != tt.stateDir {
				t.Errorf("serverPodPosture = WorkDir %q DataRoot %q StateDir %q; want %q %q %q",
					got.WorkDir, got.DataRoot, got.StateDir, tt.workDir, tt.dataRoot, tt.stateDir)
			}
		})
	}
}

// A posture the provider cannot derive (here a custom state-dir leaf behind
// a symlink, which the provider refuses the node for) is the node's
// configuration: the user scope goes off with OffPodProfileConfig, naming
// the derivation error, and is retried; nothing in it stops the server.
func TestServerPodPostureFailureIsConfiguration(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, target := filepath.Join(base, "data"), filepath.Join(base, "elsewhere")
	for _, dir := range []string{data, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(data, "cp")); err != nil {
		t.Fatal(err)
	}
	opts := serverOptions{workDir: filepath.Join(data, "cp"), podRoot: data}
	if _, err := serverPodPosture(opts); !errors.Is(err, provider.ErrDataRootNotCanonical) {
		t.Fatalf("serverPodPosture = %v, want the provider's refusal", err)
	}
	f := newWiringFixture(t)
	var derived int
	f.deps.podProfile = postureProfile(func() (sandbox.Posture, error) { derived++; return serverPodPosture(opts) })
	synctest.Test(t, func(t *testing.T) {
		ks, err := newKeystoreSocket(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		stop := runKeystoreSocket(context.Background(), ks)
		synctest.Wait()
		st := ks.sup.State()
		stop()
		if st.Phase != socket.PhaseOff || st.Reason != socket.OffPodProfileConfig || !strings.Contains(st.Detail, "derive the runtime's posture") || st.Until.IsZero() {
			t.Fatalf("state = %+v, want off with %q naming the derivation and a retry", st, socket.OffPodProfileConfig)
		}
		if derived == 0 {
			t.Fatal("the posture was never derived")
		}
	})
}

// Under --runtime hostprocess the start log says the Pod-profile check does
// not apply, and why; under runtimed it says nothing.
func TestPodProfileCheckScopeLoggedForHostProcess(t *testing.T) {
	for _, tt := range []struct {
		runtime string
		logged  bool
	}{
		{runtimeHostProcess, true},
		{runtimeRuntimed, false},
		{"", false},
	} {
		var buf bytes.Buffer
		notePodProfileCheckScope(tt.runtime, slog.New(slog.NewTextHandler(&buf, nil)))
		got := strings.Contains(buf.String(), "does not apply under --runtime hostprocess") && strings.Contains(buf.String(), "refuses them by uid")
		if got != tt.logged || (!tt.logged && buf.Len() != 0) {
			t.Errorf("runtime %q logged %q, want logged %v", tt.runtime, buf.String(), tt.logged)
		}
	}
}
