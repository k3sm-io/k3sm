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

	"k3sm.io/k3sm/pkg/install"
)

// TestInstallDeveloperModeFlag pins --developer-mode: exactly on or off, unset
// when not passed, accepted on every install shape, and carried into the
// install Config.
func TestInstallDeveloperModeFlag(t *testing.T) {
	t.Parallel()
	const stage = "/Library/k3sm.staging/0.4.0.AbCdEfGh"
	cases := []struct {
		name    string
		args    []string
		want    install.DeveloperMode
		wantErr string
	}{
		{name: "not passed", args: nil, want: install.DeveloperModeUnset},
		{name: "on", args: []string{"--developer-mode", "on"}, want: install.DeveloperModeOn},
		{name: "off", args: []string{"--developer-mode=off"}, want: install.DeveloperModeOff},
		{name: "on with --from-staging", args: []string{"--developer-mode", "on", "--from-staging", stage}, want: install.DeveloperModeOn},
		{name: "on with --agent", args: []string{"--developer-mode", "on", "--agent", "--server", "192.0.2.10"}, want: install.DeveloperModeOn},
		{name: "empty value", args: []string{"--developer-mode="}, wantErr: "--developer-mode"},
		{name: "capitalised", args: []string{"--developer-mode", "On"}, wantErr: "--developer-mode"},
		{name: "yes", args: []string{"--developer-mode", "yes"}, wantErr: "--developer-mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o, err := parseInstallFlags(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseInstallFlags(%q) = %v, want an error naming %s", tc.args, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInstallFlags(%q): %v", tc.args, err)
			}
			if o.developerMode != tc.want {
				t.Errorf("developerMode = %q, want %q", o.developerMode, tc.want)
			}
			if got := o.installConfig("/tmp/k3sm", nil, nil).DeveloperMode; got != tc.want {
				t.Errorf("Config.DeveloperMode = %q, want %q", got, tc.want)
			}
		})
	}
}
