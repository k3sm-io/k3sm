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
	"strings"
	"testing"
)

// The three reinstall defects observed live across four install cycles on the
// lab rig, each pinned here:
//
//  1. the run dir was left root-owned by whichever daemon created it first
//     (netd), so the _k3sm server could not bind its runtimed control socket;
//  2. a reinstall re-rendered the stock server plist over the operator's
//     --mesh-ip / --registry-port, which then had to be repaired by hand; and
//  3. the admin kubeconfig hardcoded loopback and skipped verification, so on a
//     mesh server it addressed nothing and verified nothing.

// TestInstallEnsuresRunDir proves the installer prepares the run dir for the
// SERVICE USER, at the path derived from the data root, BEFORE anything that
// could create it root-owned: the vm socket dir underneath it, and either daemon
// bootstrapping.
func TestInstallEnsuresRunDir(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dataRoot string
		want     string
	}{
		{name: "default data root", dataRoot: "", want: "/var/lib/k3sm/run"},
		{name: "custom data root", dataRoot: "/opt/k3sm-lab", want: "/opt/k3sm-lab/run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", DataRoot: tc.dataRoot}
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}
			ensure := idx(f.calls, "EnsureRunDir:"+tc.want)
			if ensure < 0 {
				t.Fatalf("no EnsureRunDir for %q; calls = %v", tc.want, f.calls)
			}
			// The leaf must be prepared after its parent, or MkdirAll of the leaf
			// creates the parent under the wrong owner.
			if vm := idx(f.calls, "EnsureVMRunDir:"+VMRunDir); tc.dataRoot == "" && ensure > vm {
				t.Errorf("run dir must be ensured before the vm socket dir under it (%d > %d)", ensure, vm)
			}
			// The whole point: no daemon may reach the run dir first.
			for _, label := range []string{NetdLabel, ServerLabel} {
				if boot := idx(f.calls, "Bootstrap:"+label); ensure > boot {
					t.Errorf("run dir must be ensured before %s bootstraps (%d > %d)", label, ensure, boot)
				}
			}
		})
	}
}

// TestRunDirDerivation pins RunDir against the constants the installer's other
// run-dir paths are composed from. The cross-package half of this invariant —
// that RunDir is the DIRECTORY provider.RuntimedSocketPath binds inside — is
// pinned in rundir_pin_test.go, which can import the provider without the cycle
// this package would take on.
func TestRunDirDerivation(t *testing.T) {
	if got := RunDir(""); got != DefaultRunDir {
		t.Errorf("RunDir(\"\") = %q, want the default run dir %q", got, DefaultRunDir)
	}
	for _, path := range []string{DefaultNetdSocket, MeshKeyDir, VMRunDir} {
		if !strings.HasPrefix(path, DefaultRunDir+"/") {
			t.Errorf("%q must live under the run dir %q", path, DefaultRunDir)
		}
	}
	if got, want := RunDir("/opt/lab"), "/opt/lab/run"; got != want {
		t.Errorf("RunDir(%q) = %q, want %q", "/opt/lab", got, want)
	}
}
