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
	"fmt"
	"io/fs"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// devModeSystem answers the marker's owner and ACL probes from a table: all a
// developer-mode read makes of a System.
type devModeSystem struct {
	install.System
	owners map[string]install.OwnedEntry
}

func (s devModeSystem) Owner(path string) (install.OwnedEntry, error) {
	if e, ok := s.owners[path]; ok {
		return e, nil
	}
	return install.OwnedEntry{}, fmt.Errorf("lstat %s: %w", path, fs.ErrNotExist)
}

func (devModeSystem) HasACL(string) (bool, error) { return false, nil }

// TestStatusCollectorWiresTheDeveloperModeCause pins that the production
// collector reads the marker, and that the snapshot it reads carries what the
// row needs to name a cause: without the directories above the marker, the row
// falls back to a removal command aimed through a directory nobody can trust.
// The reader takes the installer's system, so it runs on a fake here.
func TestStatusCollectorWiresTheDeveloperModeCause(t *testing.T) {
	if newStatusCollector().DeveloperMode == nil {
		t.Fatal("the status collector must be wired with the marker reader")
	}
	dir := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o755}
	file := install.OwnedEntry{Kind: install.EntryRegular, Mode: 0o644}
	badDir := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o775}
	for _, tc := range []struct {
		name          string
		library       install.OwnedEntry
		marker        install.OwnedEntry
		wantAncestor  string
		wantDirMarker bool
	}{
		{name: "a file under a group-writable /Library", library: badDir, marker: file, wantAncestor: "/Library"},
		{name: "a directory under a sound /Library", library: dir, marker: dir, wantDirMarker: true},
		{name: "a directory under a group-writable /Library", library: badDir, marker: dir, wantAncestor: "/Library", wantDirMarker: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := statusDeveloperMode(devModeSystem{owners: map[string]install.OwnedEntry{
				"/":                             dir,
				"/Library":                      tc.library,
				install.DeveloperModeMarkerPath: tc.marker,
			}})
			if got := install.DeveloperModeAncestorCause(f, install.DeveloperModeMarkerPath); got != tc.wantAncestor {
				t.Errorf("ancestor = %q, want %q", got, tc.wantAncestor)
			}
			if got := install.DeveloperModeMarkerIsDir(f); got != tc.wantDirMarker {
				t.Errorf("directory at the marker path = %v, want %v", got, tc.wantDirMarker)
			}
		})
	}
}
