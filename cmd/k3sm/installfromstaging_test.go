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
	"strings"
	"testing"
)

// TestInstallFromStagingFlags pins the flag contract of --from-staging and
// --allow-downgrade, including the exact argv the k3sm.app root step emits.
func TestInstallFromStagingFlags(t *testing.T) {
	t.Parallel()
	const stage = "/Library/k3sm.staging/0.4.0.AbCdEfGh"
	cases := []struct {
		name string
		args []string
		want string // "" = accepted
	}{
		{name: "the app's server and update argv", args: []string{"--user", "admin", "--from-staging", stage}},
		{name: "the app's join argv", args: []string{"--user", "admin", "--from-staging", stage, "--agent", "--server", "192.168.0.50", "--token-file", stage + "/join-token"}},
		{name: "downgrade allowed beside --from-staging", args: []string{"--user", "admin", "--from-staging", stage, "--allow-downgrade"}},
		{name: "--allow-downgrade alone is refused", args: []string{"--user", "admin", "--allow-downgrade"}, want: "--allow-downgrade needs --from-staging"},
		{name: "a relative --from-staging is refused", args: []string{"--user", "admin", "--from-staging", "k3sm.staging/x"}, want: "must be a clean absolute path"},
		{name: "an unclean --from-staging is refused", args: []string{"--user", "admin", "--from-staging", stage + "/../y"}, want: "must be a clean absolute path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o, err := parseInstallFlags(tc.args)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("parseInstallFlags = %v, want it to say %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInstallFlags = %v, want accepted", err)
			}
			cfg := o.installConfig("/Library/k3sm.staging/0.4.0.AbCdEfGh/k3sm.app/Contents/Resources/payload/k3sm", nil, nil)
			if cfg.FromStagingDir != stage {
				t.Errorf("FromStagingDir = %q, want %q", cfg.FromStagingDir, stage)
			}
			if cfg.Executable != cfg.BinarySource || cfg.Executable == "" {
				t.Errorf("Executable = %q, want the running binary %q", cfg.Executable, cfg.BinarySource)
			}
			if cfg.AllowDowngrade != o.set["allow-downgrade"] {
				t.Errorf("AllowDowngrade = %v, want %v", cfg.AllowDowngrade, o.set["allow-downgrade"])
			}
		})
	}
}
