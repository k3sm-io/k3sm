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
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// TestPurgeFlagValidation pins the CLI half of the confirmation: --yes alone is
// a mistake, --purge alone refuses (naming what would be destroyed), and only
// the pair, or neither, proceeds.
func TestPurgeFlagValidation(t *testing.T) {
	for _, tc := range []struct {
		purge, yes bool
		wantErr    string
	}{
		{false, false, ""},
		{true, true, ""},
		{false, true, "--yes only confirms --purge"},
		{true, false, "Re-run as 'sudo k3sm uninstall --purge --yes'"},
	} {
		err := checkPurgeFlags(tc.purge, tc.yes)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("purge=%v yes=%v: %v", tc.purge, tc.yes, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("purge=%v yes=%v = %v, want %q", tc.purge, tc.yes, err, tc.wantErr)
		}
	}
	if err := checkPurgeFlags(true, false); !strings.Contains(err.Error(), "/var/lib/k3sm") || !strings.Contains(err.Error(), "_k3sm") {
		t.Errorf("the refusal must say what would be destroyed: %v", err)
	}
	if err := checkPurgeFlags(true, false); !strings.Contains(err.Error(), "_k3sm user (deletion attempted; macOS may need an approval at the screen)") {
		t.Errorf("the refusal must say the account deletion may need an approval at the screen: %v", err)
	}
	if _, _, err := purgeTarget("", "501"); err == nil {
		t.Error("a purge with no invoking user must be refused")
	}
	if _, _, err := purgeTarget("root", "0"); err == nil {
		t.Error("a purge for root's own kubeconfig must be refused")
	}
}

// TestPurgeTargetCrossChecksSudoUID proves SUDO_USER is believed only when the
// account it names carries the uid sudo recorded in SUDO_UID.
func TestPurgeTargetCrossChecksSudoUID(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	if me.Username == "root" {
		t.Skip("run as root: the root refusal answers first")
	}
	name, home, err := purgeTarget(me.Username, me.Uid)
	if err != nil || name != me.Username || home != me.HomeDir {
		t.Fatalf("purgeTarget(%s, %s) = %q, %q, %v", me.Username, me.Uid, name, home, err)
	}
	if _, _, err := purgeTarget(me.Username, me.Uid+"9"); err == nil || !strings.Contains(err.Error(), "SUDO_UID") {
		t.Fatalf("a mismatched SUDO_UID = %v, want a refusal", err)
	}
	if _, _, err := purgeTarget(me.Username, ""); err == nil || !strings.Contains(err.Error(), "SUDO_UID") {
		t.Fatalf("a missing SUDO_UID = %v, want a refusal", err)
	}
}

// TestUninstallPurgeExplicitUser proves --user names the purge's human from
// the account lookup alone, refuses accounts that are not a human's, and
// beats the sudo environment, which still works unchanged without it.
func TestUninstallPurgeExplicitUser(t *testing.T) {
	home := t.TempDir()
	link := filepath.Join(t.TempDir(), "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]*user.User{
		"alice":   {Uid: "501", Username: "alice", HomeDir: link},
		"bob":     {Uid: "502", Username: "bob", HomeDir: home},
		"root":    {Uid: "0", Username: "root", HomeDir: "/var/root"},
		"svc":     {Uid: "300", Username: "svc", HomeDir: home},
		"_k3sm":   {Uid: "700", Username: "_k3sm", HomeDir: home},
		"nobody":  {Uid: "4294967294", Username: "nobody", HomeDir: "/var/empty"},
		"slash":   {Uid: "503", Username: "slash", HomeDir: "/"},
		"nodata":  {Uid: "504", Username: "nodata", HomeDir: "/var"},
		"nohome":  {Uid: "505", Username: "nohome", HomeDir: ""},
		"missing": {Uid: "506", Username: "missing", HomeDir: filepath.Join(home, "absent")},
	}
	old := lookupUser
	t.Cleanup(func() { lookupUser = old })
	lookupUser = func(name string) (*user.User, error) {
		if u, ok := accounts[name]; ok {
			return u, nil
		}
		return nil, user.UnknownUserError(name)
	}

	// The uid comes from the lookup (501), the home is symlink-resolved, and
	// a wrong SUDO_UID is ignored because --user does not consult it.
	name, got, err := resolvePurgeTarget("alice", "", "9999")
	if err != nil || name != "alice" || got != resolvedHome {
		t.Fatalf("--user alice = %q, %q, %v; want alice, %q", name, got, err, resolvedHome)
	}

	refused := []struct{ flag, want string }{
		{"root", "not a human"},
		{"ghost", "look up"},
		{"svc", "below 501"},
		{"_k3sm", "not a human"},
		{"nobody", "not a human"},
		{"slash", "contains the cluster data"},
		{"nodata", "contains the cluster data"},
		{"nohome", "no home"},
		{"missing", "resolve the home"},
	}
	for _, tc := range refused {
		if _, _, err := resolvePurgeTarget(tc.flag, "alice", "501"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("--user %s = %v, want a refusal containing %q", tc.flag, err, tc.want)
		}
	}
	// A refused --user never falls back to SUDO_USER.
	if _, _, err := resolvePurgeTarget("root", "alice", "501"); err == nil {
		t.Error("--user root fell back to SUDO_USER")
	}

	// --user wins over a valid SUDO_USER.
	if name, _, err := resolvePurgeTarget("bob", "alice", "501"); err != nil || name != "bob" {
		t.Errorf("--user bob with SUDO_USER alice = %q, %v; want bob", name, err)
	}

	// Without --user the sudo path is unchanged: home unresolved, uid cross-check kept.
	name, got, err = resolvePurgeTarget("", "alice", "501")
	if err != nil || name != "alice" || got != link {
		t.Errorf("SUDO_USER fallback = %q, %q, %v; want alice, %q", name, got, err, link)
	}
	if _, _, err := resolvePurgeTarget("", "alice", "999"); err == nil || !strings.Contains(err.Error(), "SUDO_UID") {
		t.Errorf("SUDO_USER with a wrong SUDO_UID = %v, want a refusal", err)
	}
	if _, _, err := resolvePurgeTarget("", "", ""); err == nil {
		t.Error("no --user and no sudo environment must be refused")
	}
}
