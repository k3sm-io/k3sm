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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devModeStagedInstall is a --from-staging install with no --developer-mode
// flag over a valid marker: the fixture tree, the signer given, and a fake
// system holding the marker, read through the production reader.
func devModeStagedInstall(t *testing.T, signer fakeSigner) (*fakeSystem, Config, *strings.Builder) {
	t.Helper()
	_, cfg := stagedFixture()
	cfg.Signer = signer
	var logs strings.Builder
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
	if err := resolveDeveloperMode(f, &cfg); err != nil {
		t.Fatal(err)
	}
	return f, cfg, &logs
}

// TestDeveloperModeOffNeedsTheWholeTree pins when an install without the flag
// turns developer mode off: only when the staged k3sm and every other Mach-O
// of the staged tree carry the Developer ID signature of the team the signing
// continuity check would require (the installed build's team when it is
// team-signed, else the staged k3sm's). Any other tree keeps the marker, and
// the install says why in a Warn.
func TestDeveloperModeOffNeedsTheWholeTree(t *testing.T) {
	t.Parallel()
	installed := Config{}.withDefaults().installedBinary()
	helper := filepath.Join(testPayloadDir, VMHostName)
	kine := filepath.Join(testPayloadDir, "bin/kine")
	cases := []struct {
		name       string
		signer     fakeSigner
		wantRemove bool
	}{
		{name: "the whole tree signed by the installed team turns it off", wantRemove: true,
			signer: fakeSigner{ids: signedTree(map[string]string{installed: testTeamID})}},
		{name: "the whole tree signed by one team over an ad-hoc install turns it off", wantRemove: true,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: ErrNoTeamID}}},
		// W1: the main binary alone is not the tree.
		{name: "a team-signed k3sm beside an ad-hoc helper keeps it",
			signer: fakeSigner{ids: signedTree(map[string]string{installed: testTeamID}), errs: map[string]error{helper: ErrNoTeamID}}},
		{name: "a team-signed k3sm beside an ad-hoc payload binary keeps it",
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: ErrNoTeamID, kine: ErrNoTeamID}}},
		{name: "a helper signed Apple Development keeps it",
			signer: fakeSigner{ids: signedTree(map[string]string{installed: testTeamID}), notDevID: map[string]bool{helper: true}}},
		// W2: a Developer ID of some other team is not the k3sm team.
		{name: "a tree signed by another team than the installed one keeps it",
			signer: fakeSigner{ids: signedTree(map[string]string{installed: "ZZZZZ99999"})}},
		{name: "a helper signed by another team keeps it",
			signer: fakeSigner{ids: signedTree(map[string]string{installed: testTeamID, helper: "ZZZZZ99999"})}},
		{name: "an Apple Development installed build does not name the team",
			signer: fakeSigner{ids: signedTree(map[string]string{installed: "ZZZZZ99999"}), notDevID: map[string]bool{installed: true}}},
		{name: "an ad-hoc tree keeps it", signer: fakeSigner{errs: adHocTree()}},
		{name: "an unreadable installed signature keeps it",
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: errSignatureUnreadable}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, cfg, logs := devModeStagedInstall(t, tc.signer)
			if err := preflightFromStaging(context.Background(), &cfg); err != nil {
				t.Fatalf("preflightFromStaging = %v, want accepted in developer mode", err)
			}
			if err := applyDeveloperMode(context.Background(), f, cfg); err != nil {
				t.Fatalf("applyDeveloperMode = %v", err)
			}
			_, kept := f.files[DeveloperModeMarkerPath]
			if kept == tc.wantRemove {
				t.Fatalf("marker kept = %v, want %v; logs:\n%s", kept, !tc.wantRemove, logs.String())
			}
			if kept && !strings.Contains(logs.String(), "level=WARN") || kept && !strings.Contains(logs.String(), `"developer mode stays on`) {
				t.Errorf("a kept marker is not explained in a Warn; logs:\n%s", logs.String())
			}
		})
	}
}

// TestDeveloperModeMarkerChangedUnderTheLock pins the re-read under the
// install lock: a marker that changed between the read the --from-staging
// predicate acted on and the read under the lock refuses the install, before
// the marker is touched.
func TestDeveloperModeMarkerChangedUnderTheLock(t *testing.T) {
	t.Parallel()
	installed := Config{}.withDefaults().installedBinary()
	cases := []struct {
		name   string
		change func(*fakeSystem)
	}{
		{name: "removed", change: func(f *fakeSystem) {
			delete(f.owners, DeveloperModeMarkerPath)
			delete(f.files, DeveloperModeMarkerPath)
		}},
		{name: "made world-writable", change: func(f *fakeSystem) {
			e := f.owners[DeveloperModeMarkerPath]
			e.Mode = 0o666
			f.owners[DeveloperModeMarkerPath] = e
		}},
		{name: "replaced by a symlink", change: func(f *fakeSystem) {
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntrySymlink, Mode: 0o755}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, cfg, _ := devModeStagedInstall(t, fakeSigner{ids: signedTree(map[string]string{installed: testTeamID})})
			if err := preflightFromStaging(context.Background(), &cfg); err != nil {
				t.Fatal(err)
			}
			tc.change(f)
			f.calls = nil
			err := applyDeveloperMode(context.Background(), f, cfg)
			if !errors.Is(err, ErrDeveloperModeChanged) {
				t.Fatalf("applyDeveloperMode = %v, want %v", err, ErrDeveloperModeChanged)
			}
			for _, c := range f.calls {
				if strings.HasPrefix(c, "RemoveEntry:") || strings.HasPrefix(c, "WriteRootOnlyFile:") {
					t.Errorf("the marker was touched after the change was seen: %s", c)
				}
			}
		})
	}

	t.Run("a marker that appeared refuses too", func(t *testing.T) {
		t.Parallel()
		_, cfg := stagedFixture()
		cfg.Signer = fakeSigner{ids: signedTree(map[string]string{installed: testTeamID})}
		f := &fakeSystem{owners: map[string]OwnedEntry{}}
		if err := resolveDeveloperMode(f, &cfg); err != nil {
			t.Fatal(err)
		}
		if err := preflightFromStaging(context.Background(), &cfg); err != nil {
			t.Fatal(err)
		}
		f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
		if err := applyDeveloperMode(context.Background(), f, cfg); !errors.Is(err, ErrDeveloperModeChanged) {
			t.Fatalf("applyDeveloperMode = %v, want %v", err, ErrDeveloperModeChanged)
		}
	})

	t.Run("an unchanged marker is accepted", func(t *testing.T) {
		t.Parallel()
		f, cfg, _ := devModeStagedInstall(t, fakeSigner{ids: signedTree(map[string]string{installed: testTeamID})})
		if err := preflightFromStaging(context.Background(), &cfg); err != nil {
			t.Fatal(err)
		}
		if err := applyDeveloperMode(context.Background(), f, cfg); err != nil {
			t.Fatalf("applyDeveloperMode = %v, want accepted", err)
		}
	})
}

// pinPlainInstallSignature, run by TestDeveloperModeMarkerOnInstall, pins which signature on a plain install
// (no --from-staging, no flag) turns developer mode off and which leaves it
// on, the log line that names the team, and the sentences of the user docs
// that say so.
func pinPlainInstallSignature(t *testing.T) {
	const exe = "/usr/local/bin/k3sm"
	const sibling = "/usr/local/bin/k3sm-vmhost"
	cases := []struct {
		name       string
		signer     fakeSigner
		wantRemove bool
		wantTeam   string
	}{
		{name: "a Developer ID of the release team turns it off", wantRemove: true, wantTeam: testTeamID,
			signer: fakeSigner{ids: map[string]string{exe: testTeamID}}},
		{name: "a Developer ID of any other team turns it off", wantRemove: true, wantTeam: "ZZZZZ99999",
			signer: fakeSigner{ids: map[string]string{exe: "ZZZZZ99999"}}},
		{name: "an ad-hoc sibling payload is not checked", wantRemove: true, wantTeam: testTeamID,
			signer: fakeSigner{ids: map[string]string{exe: testTeamID}, errs: map[string]error{sibling: ErrNoTeamID}}},
		{name: "an Apple Development signature keeps it",
			signer: fakeSigner{ids: map[string]string{exe: testTeamID}, notDevID: map[string]bool{exe: true}}},
		{name: "an ad-hoc signature keeps it",
			signer: fakeSigner{errs: map[string]error{exe: ErrNoTeamID}}},
		{name: "an unreadable signature keeps it",
			signer: fakeSigner{errs: map[string]error{exe: errSignatureUnreadable}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}}
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
			f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
			var logs strings.Builder
			cfg := Config{
				BinarySource:   exe,
				Logger:         slog.New(slog.NewTextHandler(&logs, nil)),
				StagingOptions: StagingOptions{Executable: exe, Signer: tc.signer},
			}
			if err := resolveDeveloperMode(f, &cfg); err != nil {
				t.Fatal(err)
			}
			if err := applyDeveloperMode(context.Background(), f, cfg); err != nil {
				t.Fatalf("applyDeveloperMode = %v", err)
			}
			_, kept := f.files[DeveloperModeMarkerPath]
			if kept == tc.wantRemove {
				t.Fatalf("marker kept = %v, want %v; logs:\n%s", kept, !tc.wantRemove, logs.String())
			}
			if tc.wantRemove {
				want := "developer mode turned off by a signed install"
				if !strings.Contains(logs.String(), want) || !strings.Contains(logs.String(), "team-id="+tc.wantTeam) {
					t.Errorf("log does not say %q with team-id=%s:\n%s", want, tc.wantTeam, logs.String())
				}
			} else if !strings.Contains(logs.String(), "developer mode stays on") {
				t.Errorf("a kept marker is not explained:\n%s", logs.String())
			}
		})
	}

	t.Run("the user docs say what the code does", func(t *testing.T) {
		t.Parallel()
		doc, err := os.ReadFile("../../docs/user/install.md")
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(doc)), " ")
		for _, want := range []string{
			"a plain `sudo k3sm install` turns it off when the `k3sm` doing the install carries a Developer ID Application signature of any team",
			"The team is not compared with the installed one",
			"the other programs the install lays down are not checked",
			"An ad-hoc signed build from source, or one signed for Apple Development, leaves it on",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("docs/user/install.md lacks %q", want)
			}
		}
	})
}
