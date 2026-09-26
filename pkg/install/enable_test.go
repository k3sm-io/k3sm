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

// TestInstallEnablesADisabledService is the regression for a live install that
// failed at `bootstrap io.k3sm.netd` because an operator had disabled the label in
// launchd's system domain. launchd refuses a disabled label with "Bootstrap failed:
// 5: Input/output error", which is ALSO the errno a draining label reports, so the
// transient retry spent its whole budget on a refusal that never clears. Install
// must enable each label immediately before bootstrapping it, once, so the first
// bootstrap is accepted and no retry budget is burned. Uninstall must never touch
// the bit.
func TestInstallEnablesADisabledService(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeSystem)
		check func(t *testing.T, f *fakeSystem, err error)
	}{
		{
			name: "a disabled label is enabled, then bootstrapped in one attempt",
			setup: func(f *fakeSystem) {
				f.disabled = map[string]bool{NetdLabel: true, ServerLabel: true}
			},
			check: func(t *testing.T, f *fakeSystem, err error) {
				if err != nil {
					t.Fatalf("Install over disabled labels: %v", err)
				}
				for _, l := range []string{NetdLabel, ServerLabel} {
					if n := countCalls(f, "Enable:"+l); n != 1 {
						t.Errorf("%s enable calls = %d, want exactly 1", l, n)
					}
					if n := countCalls(f, "Bootstrap:"+l); n != 1 {
						t.Errorf("%s bootstrap attempts = %d, want exactly 1 (no retry budget may be burned on a disabled label)", l, n)
					}
					enable, boot := idx(f.calls, "Enable:"+l), idx(f.calls, "Bootstrap:"+l)
					if enable < 0 || boot < 0 || enable >= boot {
						t.Errorf("%s: enable at %d, bootstrap at %d; want enable strictly before bootstrap (calls: %v)", l, enable, boot, f.calls)
					}
				}
			},
		},
		{
			name: "an enable failure names the label and the remedy",
			setup: func(f *fakeSystem) {
				f.enableErrs = map[string]error{NetdLabel: errors.New("launchctl enable io.k3sm.netd: exit status 1: Not privileged")}
			},
			check: func(t *testing.T, f *fakeSystem, err error) {
				if err == nil {
					t.Fatal("Install must fail when the label cannot be enabled")
				}
				for _, want := range []string{NetdLabel, "sudo launchctl enable system/" + NetdLabel} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not mention %q", err, want)
					}
				}
			},
		},
		{
			name: "an exhausted transient bootstrap carries the print-disabled hint",
			setup: func(f *fakeSystem) {
				f.putBootstrapAlways(NetdLabel, transientBootstrapErr())
			},
			check: func(t *testing.T, f *fakeSystem, err error) {
				if err == nil {
					t.Fatal("Install must fail when launchd never accepts the bootstrap")
				}
				want := "if 'launchctl print-disabled system' lists " + NetdLabel + ", run: sudo launchctl enable system/" + NetdLabel
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not carry the static hint %q", err, want)
				}
			},
		},
		{
			name:  "uninstall never enables or disables a label",
			setup: func(*fakeSystem) {},
			check: func(t *testing.T, f *fakeSystem, err error) {
				if err != nil {
					t.Fatalf("Install: %v", err)
				}
				f.calls = nil
				if err := Uninstall(context.Background(), f, installCfg()); err != nil {
					t.Fatalf("Uninstall: %v", err)
				}
				if len(recorded(f.calls, "Bootout:")) == 0 {
					t.Fatalf("uninstall booted nothing out, so it asserted nothing (calls: %v)", f.calls)
				}
				for _, c := range f.calls {
					if strings.HasPrefix(c, "Enable:") || strings.HasPrefix(c, "Disable:") {
						t.Errorf("uninstall called %s; it must leave the enabled/disabled bit alone", c)
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := reinstallFake()
			tc.setup(f)
			tc.check(t, f, Install(context.Background(), f, installCfg()))
		})
	}
}
