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
	"errors"
	"strings"
	"testing"
)

// servedAdminToken is the admin token the control plane reads when it starts.
func servedAdminToken(t *testing.T, f *fakeSystem, cfg Config) string {
	t.Helper()
	raw, err := f.readRegularFileContent(cfg.withDefaults().serverTokenPath())
	if err != nil {
		t.Fatalf("read the staged admin token: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// TestFailedUncordonKeepsTheInstallAndItsKubeconfig is the gate for the kubeconfig
// across a failed install: a rollback leaves the operator one the control plane
// accepts.
func TestFailedUncordonKeepsTheInstallAndItsKubeconfig(t *testing.T) {
	ctx := context.Background()
	t.Run("a rollback puts back the token the old kubeconfig carries", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		before, _ := adminCredential(t, f)
		f.calls = nil
		logs.Reset()
		f.putBootstrapAlways(NetdLabel, errors.New("Bootstrap failed: 125"))

		err := Install(ctx, f, cfg)

		if err == nil || !strings.Contains(err.Error(), "rolled back to the previous install root") {
			t.Fatalf("Install = %v, want the rollback", err)
		}
		if got, _ := adminCredential(t, f); got != before {
			t.Error("the rollback rewrote the admin kubeconfig although the old token works again")
		}
		if served := servedAdminToken(t, f, cfg); served != before {
			t.Error("the control plane serves a token the operator's kubeconfig does not carry")
		}
	})

	t.Run("the rollback beside a stuck developer-mode marker puts the token back too", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(ctx, f, stageCfg()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		before, _ := adminCredential(t, f)
		putUnclearableMarker(t, f, EntryRegular)
		f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
		f.chownErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
		f.putLoaded(NetdLabel, ServerLabel)
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff

		err := Install(ctx, f, cfg)

		if err == nil || !strings.Contains(err.Error(), "rolled back to the previous install root") {
			t.Fatalf("Install = %v, want the rollback", err)
		}
		if served := servedAdminToken(t, f, cfg); served != before {
			t.Error("the control plane serves a token the operator's kubeconfig does not carry")
		}
	})

	t.Run("a rollback that has no token to put back writes the new kubeconfig", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		before, _ := adminCredential(t, f)
		f.putFile(cfg.withDefaults().serverTokenPath(), []byte("not a k3sm token\n"))
		f.calls = nil
		logs.Reset()
		f.putBootstrapAlways(NetdLabel, errors.New("Bootstrap failed: 125"))

		err := Install(ctx, f, cfg)

		if err == nil || !strings.Contains(err.Error(), "rolled back to the previous install root") {
			t.Fatalf("Install = %v, want the rollback", err)
		}
		got, _ := adminCredential(t, f)
		if got == before {
			t.Error("the admin kubeconfig still holds the old token")
		}
		if served := servedAdminToken(t, f, cfg); served != got {
			t.Error("the control plane serves a token the operator's kubeconfig does not carry")
		}
	})
}
