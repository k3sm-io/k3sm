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
		want string
	}{
		{name: "the installed k3sm", path: installed, want: "the installed k3sm names no Developer ID team"},
		{name: "the staged k3sm", path: staged, want: "the staged k3sm is not signed by the installed team"},
	}
	for _, h := range []string{ExecShimName, PathShimName, DNSShimName, VMHostName, "bin/kine"} {
		cases = append(cases, struct{ name, path, want string }{name: "helper " + h, path: filepath.Join(testPayloadDir, h), want: "not every binary in the staged tree is signed by team"})
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
			wantStaysOn(t, logs.String(), tc.want)
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
		want   string
		signer func(cancel context.CancelFunc) TeamIDReader
	}{
		{name: "a generic TeamID error (codesign missing)", src: src, want: "executable file not found",
			signer: func(context.CancelFunc) TeamIDReader {
				return fakeSigner{errs: map[string]error{src: errors.New("exec: \"codesign\": executable file not found in $PATH")}}
			}},
		{name: "an unreadable signature", src: src, want: errSignatureUnreadable.Error(),
			signer: func(context.CancelFunc) TeamIDReader {
				return fakeSigner{errs: map[string]error{src: errSignatureUnreadable}}
			}},
		{name: "a cancelled context", src: src, want: "context canceled",
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
			wantStaysOn(t, logs.String(), tc.want)
		})
	}
}

// wantStaysOn asserts the install logged the stays-on Warn and that it names
// the specific cause, so a pass for a different reason is rejected.
func wantStaysOn(t *testing.T, logs, reason string) {
	t.Helper()
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "developer mode stays on: ") {
		t.Errorf("no stays-on Warn; logs:\n%s", logs)
		return
	}
	if !strings.Contains(logs, reason) {
		t.Errorf("the stays-on Warn does not name %q; logs:\n%s", reason, logs)
	}
}

// TestDeveloperModeKeptOnEmptyExecutablePath pins that a plain install naming
// no k3sm binary keeps the marker. Install itself refuses an empty
// BinarySource, so it drives applyDeveloperMode and drop, the caller that
// consumes the keep reason, with a signer that would accept the empty path.
func TestDeveloperModeKeptOnEmptyExecutablePath(t *testing.T) {
	t.Parallel()
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	seedMarkerAncestors(f)
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
	if !markerOn(f) {
		t.Fatal("the marker is not On before the install")
	}
	var logs strings.Builder
	cfg := Config{TargetUser: "alice", Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	cfg.Signer = fakeSigner{ids: map[string]string{"": testTeamID}}
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
	wantStaysOn(t, logs.String(), "names no k3sm binary")
}

// TestDeveloperModeOffKeepsMarkerOnInstalledAndStagedTeamErrors pins the two
// --from-staging keep-on branches the signing table never reached (the
// installed k3sm's signature unreadable; an ad-hoc installed k3sm beside an
// ad-hoc staged one), and is the one gate for every keep-on test of this
// file: a run of it alone covers them all.
func TestDeveloperModeOffKeepsMarkerOnInstalledAndStagedTeamErrors(t *testing.T) {
	t.Parallel()
	installed := Config{}.withDefaults().installedBinary()
	_, probe := stagedFixture()
	staged := probe.Executable
	cases := []struct {
		name   string
		signer fakeSigner
		want   string
	}{
		{name: "the installed signature cannot be read",
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: errors.New("codesign: resource busy")}},
			want:   "the signature of the installed k3sm could not be read (codesign: resource busy)"},
		{name: "an ad-hoc installed k3sm beside an ad-hoc staged k3sm",
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: ErrNoTeamID, staged: ErrNoTeamID}},
			want:   "the staged k3sm carries no Developer ID team signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, cfg, logs := devModeStagedInstall(t, tc.signer)
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
			wantStaysOn(t, logs.String(), tc.want)
		})
	}
	t.Run("TestDeveloperModeOffKeepsMarkerOnDeveloperIDError", TestDeveloperModeOffKeepsMarkerOnDeveloperIDError)
	t.Run("TestDeveloperModeKeptOnEveryPlainVerificationError", TestDeveloperModeKeptOnEveryPlainVerificationError)
	t.Run("TestDeveloperModeKeptOnEmptyExecutablePath", TestDeveloperModeKeptOnEmptyExecutablePath)
}
