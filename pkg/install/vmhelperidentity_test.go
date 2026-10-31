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
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestVerifyVMHelperFollowsVersionedLayout pins the vm helper's peer identity
// check across the install layouts: the helper is this install's k3sm-vmhost
// whether its recorded executable is the flat path of today's layout, the same
// name through current, the name inside the version directory current or
// previous points at (where the runtime's symlink-resolved lookup lands, and
// where a helper started before a flip keeps running), or the flat path with
// its symlinks resolved. A path outside versions/, a version no link retains, a
// version path with no current link at all, a deeper or partial version path,
// or any other basename is refused with an error and never signalled.
func TestVerifyVMHelperFollowsVersionedLayout(t *testing.T) {
	const pgid = 801
	flat := DefaultInstallDir + "/" + VMHostName
	current := DefaultInstallDir + "/current"
	previous := DefaultInstallDir + "/previous"
	// The versioned tree: current is 0.3.0, previous (the rollback, and the
	// version a pod started before the last flip runs from) is 0.2.9.
	retained := map[string]string{current: "versions/0.3.0", previous: "versions/0.2.9"}
	for _, tc := range []struct {
		name     string
		exe      string
		uid      uint32
		resolved map[string]string
		links    map[string]string
		want     bool
	}{
		{name: "flat layout path", exe: flat, uid: fakeServiceUID, want: true},
		{name: "flat path uncleaned", exe: DefaultInstallDir + "//" + VMHostName, uid: fakeServiceUID, want: true},
		{name: "through current", exe: DefaultInstallDir + "/current/" + VMHostName, uid: fakeServiceUID, want: true},
		{name: "flat layout path, no current link", exe: flat, uid: fakeServiceUID, links: map[string]string{}, want: true},
		{name: "under versions, the active version", exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: fakeServiceUID, links: retained, want: true},
		{name: "under versions, the retained previous version", exe: DefaultInstallDir + "/versions/0.2.9/" + VMHostName, uid: fakeServiceUID, links: retained, want: true},
		{
			name:  "under versions, a migrated unknown version that is current",
			exe:   DefaultInstallDir + "/versions/unknown-0123456789ab/" + VMHostName,
			uid:   fakeServiceUID,
			links: map[string]string{current: "versions/unknown-0123456789ab"},
			want:  true,
		},
		{name: "under versions, a validly named version no link retains", exe: DefaultInstallDir + "/versions/0.2.8/" + VMHostName, uid: fakeServiceUID, links: retained},
		{name: "under versions, no current link (the flat layout)", exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: fakeServiceUID},
		{
			name:  "under versions, current points somewhere not a version directory",
			exe:   DefaultInstallDir + "/versions/0.3.0/" + VMHostName,
			uid:   fakeServiceUID,
			links: map[string]string{current: "/Library/k3sm/versions/0.3.0"},
		},
		{
			name:     "the flat path resolved elsewhere",
			exe:      "/private/k3sm-root/" + VMHostName,
			uid:      fakeServiceUID,
			resolved: map[string]string{flat: "/private/k3sm-root/" + VMHostName},
			want:     true,
		},
		{name: "outside versions", exe: "/tmp/" + VMHostName, uid: fakeServiceUID},
		{name: "a sibling of versions", exe: DefaultInstallDir + "/updater-work/" + VMHostName, uid: fakeServiceUID},
		{name: "a staged partial version", exe: DefaultInstallDir + "/versions/0.3.0.partial/" + VMHostName, uid: fakeServiceUID},
		{name: "deeper than a version directory", exe: DefaultInstallDir + "/versions/0.3.0/bin/" + VMHostName, uid: fakeServiceUID},
		{name: "a dot-dot escape", exe: DefaultInstallDir + "/versions/../../tmp/" + VMHostName, uid: fakeServiceUID},
		{name: "wrong name under versions", exe: DefaultInstallDir + "/versions/0.3.0/k3sm", uid: fakeServiceUID},
		{name: "wrong name through current", exe: DefaultInstallDir + "/current/k3sm-execshim", uid: fakeServiceUID},
		{name: "wrong name flat", exe: DefaultInstallDir + "/k3sm", uid: fakeServiceUID},
		{name: "relative path", exe: "versions/0.3.0/" + VMHostName, uid: fakeServiceUID},
		{
			name:     "resolved to a different basename",
			exe:      "/private/k3sm-root/other",
			uid:      fakeServiceUID,
			resolved: map[string]string{flat: "/private/k3sm-root/other"},
		},
		{name: "right path, wrong uid", exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: 0, links: retained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := &fakeSystem{}
			f.podLeaders = map[int]int64{pgid: 7}
			f.life.procs = map[int]fakeProc{pgid: {exe: tc.exe, uid: tc.uid}}
			f.purge.resolved = tc.resolved
			f.purge.links = tc.links
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
			ok, err := verifyVMHelper(f, cfg, VMHostRecord{PodID: "p", Pgid: pgid, StartUnixNano: 7}, fakeServiceUID)
			if ok != tc.want {
				t.Fatalf("verifyVMHelper(%q, uid %d) = %v (%v), want %v", tc.exe, tc.uid, ok, err, tc.want)
			}
			if tc.want && err != nil {
				t.Errorf("an accepted helper reported %v", err)
			}
			if !tc.want && (err == nil || !strings.Contains(err.Error(), "not signalled")) {
				t.Errorf("a refused helper reported %v, want the forged record named", err)
			}
		})
	}
}
