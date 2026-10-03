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
	"os/user"
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
