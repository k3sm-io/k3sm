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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestInstallFromStagingFlags pins the flag contract of --from-staging,
// --allow-downgrade and --require-team-signature, including the exact argv the k3sm.app root step emits.
func TestInstallFromStagingFlags(t *testing.T) {
	t.Parallel()
	const stage = "/Library/k3sm.staging/0.4.0.AbCdEfGh"
	cases := []struct {
		name string
		args []string
		want string // "" = accepted
	}{
		{name: "the app's server and update argv", args: []string{"--user", "admin", "--from-staging", stage}},
		{name: "the app's join argv", args: []string{"--user", "admin", "--from-staging", stage, "--agent", "--server", "192.0.2.10", "--token-file", stage + "/join-token"}},
		{name: "downgrade allowed beside --from-staging", args: []string{"--user", "admin", "--from-staging", stage, "--allow-downgrade"}},
		{name: "both update flags beside --from-staging", args: []string{"--user", "admin", "--from-staging", stage, "--allow-downgrade", "--require-team-signature"}},
		{name: "--require-team-signature alone is refused", args: []string{"--user", "admin", "--require-team-signature"}, want: "--require-team-signature needs --from-staging"},
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
			if cfg.RequireTeamSignature != o.set["require-team-signature"] {
				t.Errorf("RequireTeamSignature = %v, want %v", cfg.RequireTeamSignature, o.set["require-team-signature"])
			}
		})
	}
}

// TestInstallEarlyRefusalDiscardsToken pins the token on every refusal that
// comes before the install runs: under --from-staging with --token-file, a
// flag that fails validation, the root check, the --user check, an
// unresolvable executable and a bad data-volume flag each unlink the staged
// token file. A run that gets past them, and a plain --token-file, leave it.
func TestInstallEarlyRefusalDiscardsToken(t *testing.T) {
	t.Parallel()
	agent := func(extra ...string) []string {
		return append([]string{"--agent", "--server", "192.0.2.10"}, extra...)
	}
	cases := []struct {
		name     string
		args     []string
		euid     int
		exeErr   bool
		staging  bool
		wantErr  string
		wantGone bool
	}{
		{name: "a flag that fails validation", staging: true, euid: 0, args: []string{"--user", "admin", "--agent"}, wantErr: "--agent needs --server", wantGone: true},
		{name: "not root", staging: true, euid: 501, args: agent("--user", "admin"), wantErr: "must run as root", wantGone: true},
		{name: "no human --user", staging: true, euid: 0, args: agent("--user", "root"), wantErr: "non-root human", wantGone: true},
		{name: "the executable cannot be resolved", staging: true, euid: 0, exeErr: true, args: agent("--user", "admin"), wantErr: "no executable", wantGone: true},
		{name: "a bad data-volume flag", staging: true, euid: 0, wantErr: "--data-volume-encrypt needs --data-volume", wantGone: true,
			args: []string{"--user", "admin", "--server-join", "--server", "192.0.2.10", "--node-ip", "192.0.2.11", "--data-volume-encrypt"}},
		{name: "no refusal leaves the token for the install", staging: true, euid: 0, args: agent("--user", "admin")},
		{name: "a plain --token-file is never discarded", euid: 501, args: agent("--user", "admin"), wantErr: "must run as root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(dir, "k3sm.staging")
			stage := filepath.Join(root, "0.4.0.AbCdEfGh")
			if err := os.MkdirAll(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			token := filepath.Join(stage, "join-token")
			if err := os.WriteFile(token, []byte("tok"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"--token-file", token}, tc.args...)
			if tc.staging {
				args = append(args, "--from-staging", stage)
			}
			env := installEnv{
				euid: tc.euid,
				executable: func() (string, error) {
					if tc.exeErr {
						return "", errors.New("no executable")
					}
					return filepath.Join(stage, "k3sm"), nil
				},
				stagingFS:   install.NewDarwinStagingFS(),
				stagingRoot: root,
			}
			_, _, _, err = env.prepare(args)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("prepare = %v, want no refusal", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("prepare = %v, want it to say %q", err, tc.wantErr)
			}
			_, statErr := os.Lstat(token)
			gone := errors.Is(statErr, fs.ErrNotExist)
			if gone != tc.wantGone {
				t.Errorf("token gone = %v, want %v", gone, tc.wantGone)
			}
		})
	}
}

// TestInstallInPlaceShape pins the in-place update at the CLI: the root
// helper's argv (--from-staging alone, with no $SUDO_USER and no --user)
// passes the early refusals, any other install still needs a human --user,
// and a Mac resolved as a worker refuses the control-plane flags.
func TestInstallInPlaceShape(t *testing.T) {
	t.Parallel()
	const stage = "/Library/k3sm.staging/netd-update-AbCd"
	env := installEnv{euid: 0, executable: func() (string, error) { return stage + "/k3sm", nil }}
	for _, tc := range []struct {
		name    string
		args    []string
		inPlace bool
		wantErr string
	}{
		{name: "the root helper's argv", args: []string{"--from-staging", stage, "--allow-downgrade", "--require-team-signature"}, inPlace: true},
		{name: "a worker update from the app is not in place", args: []string{"--user", "admin", "--from-staging", stage, "--agent", "--server", "192.0.2.10"}},
		{name: "--from-staging with a role flag still needs --user", args: []string{"--from-staging", stage, "--agent", "--server", "192.0.2.10"}, wantErr: "non-root human"},
		{name: "a plain install still needs --user", args: []string{}, wantErr: "non-root human"},
		{name: "--user root is refused in place too", args: []string{"--from-staging", stage, "--user", "root"}, inPlace: true, wantErr: "non-root human"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := tc.args
			if !slices.Contains(args, "--user") {
				args = append([]string{"--user", ""}, args...)
			}
			o, _, _, err := env.prepare(args)
			if o.inPlace() != tc.inPlace {
				t.Errorf("inPlace = %v, want %v", o.inPlace(), tc.inPlace)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("prepare = %v, want accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("prepare = %v, want %q", err, tc.wantErr)
			}
		})
	}
	t.Run("a worker resolved from the disk refuses control-plane flags", func(t *testing.T) {
		t.Parallel()
		asAgent := func(c install.Config) (install.Config, error) { c.Role = install.RoleAgent; return c, nil }
		o, err := parseInstallFlags([]string{"--from-staging", stage, "--mesh-ip", "100.64.0.1"})
		if err != nil {
			t.Fatalf("parseInstallFlags = %v", err)
		}
		if _, err := o.resolveInPlace(o.installConfig(stage+"/k3sm", nil, nil), asAgent); err == nil || !strings.Contains(err.Error(), "--mesh-ip") {
			t.Fatalf("resolveInPlace = %v, want --mesh-ip refused on a worker", err)
		}
		o, err = parseInstallFlags([]string{"--from-staging", stage})
		if err != nil {
			t.Fatalf("parseInstallFlags = %v", err)
		}
		cfg, err := o.resolveInPlace(o.installConfig(stage+"/k3sm", nil, nil), asAgent)
		if err != nil || cfg.Role != install.RoleAgent {
			t.Fatalf("resolveInPlace = %v, %v; want the resolved worker", cfg.Role, err)
		}
		called := false
		o, _ = parseInstallFlags([]string{"--user", "admin", "--from-staging", stage, "--agent", "--server", "192.0.2.10"})
		if _, err := o.resolveInPlace(o.installConfig(stage+"/k3sm", nil, nil), func(c install.Config) (install.Config, error) { called = true; return c, nil }); err != nil || called {
			t.Fatalf("an explicit worker update ran the in-place resolver (called=%v, err=%v)", called, err)
		}
	})
}
