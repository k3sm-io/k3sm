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
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// markerOn reads the marker through the production reader, so a verdict never
// rests on the log substring alone.
func markerOn(f *fakeSystem) bool {
	return ReadDeveloperModeState(f, DeveloperModeMarkerPath) == DeveloperModeMarkerOn
}

// TestDeveloperModeOffKeepsMarkerOnDeveloperIDError pins the fail-closed
// direction on the --from-staging path: a Developer ID verification error on
// the installed k3sm, the staged k3sm, or any helper keeps the marker.
func TestDeveloperModeOffKeepsMarkerOnDeveloperIDError(t *testing.T) {
	t.Parallel()
	installed := Config{}.withDefaults().installedBinary()
	_, probe := stagedFixture()
	staged := probe.Executable
	cases := []struct {
		name string
		path string
	}{
		{name: "the installed k3sm", path: installed},
		{name: "the staged k3sm", path: staged},
	}
	for _, h := range []string{ExecShimName, PathShimName, DNSShimName, VMHostName, "bin/kine"} {
		cases = append(cases, struct{ name, path string }{name: "helper " + h, path: filepath.Join(testPayloadDir, h)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signer := fakeSigner{
				ids:       signedTree(map[string]string{installed: testTeamID}),
				devIDErrs: map[string]error{tc.path: errors.New("codesign: a sealed resource is missing or invalid")},
			}
			f, cfg, logs := devModeStagedInstall(t, signer)
			if !markerOn(f) {
				t.Fatal("the marker is not On before the install")
			}
			if err := preflightFromStaging(context.Background(), &cfg); err != nil {
				t.Fatalf("preflightFromStaging = %v, want accepted in developer mode", err)
			}
			removal, err := applyDeveloperMode(context.Background(), f, cfg)
			if err != nil {
				t.Fatalf("applyDeveloperMode = %v", err)
			}
			if err := removal.drop(f, cfg); err != nil {
				t.Fatalf("drop = %v", err)
			}
			if !markerOn(f) {
				t.Errorf("the marker is not On after the install; logs:\n%s", logs.String())
			}
			if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), `"developer mode stays on`) {
				t.Errorf("no stays-on Warn; logs:\n%s", logs.String())
			}
		})
	}
}

// cancelingSigner cancels the install's context while reading the team, then
// reports the context's error, as a real reader does when it is cancelled.
type cancelingSigner struct{ cancel context.CancelFunc }

func (s cancelingSigner) TeamID(ctx context.Context, _ string) (string, error) {
	s.cancel()
	return "", ctx.Err()
}

func (s cancelingSigner) DeveloperID(ctx context.Context, _, _ string) (bool, error) {
	return false, ctx.Err()
}

// TestDeveloperModeKeptOnEveryPlainVerificationError pins that a no-flag plain
// install keeps the marker for every way the signature check can fail, not
// only ErrNoTeamID.
func TestDeveloperModeKeptOnEveryPlainVerificationError(t *testing.T) {
	t.Parallel()
	const src = "/tmp/k3sm"
	cases := []struct {
		name   string
		src    string
		signer func(cancel context.CancelFunc) TeamIDReader
	}{
		{name: "a generic TeamID error (codesign missing)", src: src,
			signer: func(context.CancelFunc) TeamIDReader {
				return fakeSigner{errs: map[string]error{src: errors.New("exec: \"codesign\": executable file not found in $PATH")}}
			}},
		{name: "an unreadable signature", src: src,
			signer: func(context.CancelFunc) TeamIDReader {
				return fakeSigner{errs: map[string]error{src: errSignatureUnreadable}}
			}},
		{name: "a cancelled context", src: src,
			signer: func(cancel context.CancelFunc) TeamIDReader { return cancelingSigner{cancel: cancel} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
			f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
			if !markerOn(f) {
				t.Fatal("the marker is not On before the install")
			}
			var logs strings.Builder
			cfg := Config{BinarySource: tc.src, TargetUser: "alice", Logger: slog.New(slog.NewTextHandler(&logs, nil))}
			cfg.Signer = tc.signer(cancel)
			if err := Install(ctx, f, cfg); err != nil {
				t.Fatalf("Install = %v", err)
			}
			if !markerOn(f) {
				t.Errorf("the marker is not On after the install; logs:\n%s", logs.String())
			}
			if !strings.Contains(logs.String(), "developer mode stays on") {
				t.Errorf("no stays-on Warn; logs:\n%s", logs.String())
			}
		})
	}
}

// TestDeveloperModeKeptOnEmptyExecutablePath pins that a plain install naming
// no k3sm binary keeps the marker. Install itself refuses an empty
// BinarySource, so the decision is read at plainInstallTeam, which returns
// before any signature is read.
func TestDeveloperModeKeptOnEmptyExecutablePath(t *testing.T) {
	t.Parallel()
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	seedMarkerAncestors(f)
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
	if !markerOn(f) {
		t.Fatal("the marker is not On before the install")
	}
	cfg := Config{TargetUser: "alice"}
	cfg.Signer = fakeSigner{ids: map[string]string{"": testTeamID}}
	team, keep := plainInstallTeam(context.Background(), cfg)
	if team != "" || keep == "" {
		t.Errorf("plainInstallTeam = (%q, %q), want no team and a keep reason", team, keep)
	}
	if !markerOn(f) {
		t.Error("the marker is not On after the decision")
	}
}
