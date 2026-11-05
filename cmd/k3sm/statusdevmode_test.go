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
// collector can name the cause of an invalid marker: without these readers the
// row silently falls back to a `sudo rm` remedy that does not fix a bad
// directory and that rm refuses for a directory at the path. The readers
// themselves take the installer's system, so they run on a fake here.
func TestStatusCollectorWiresTheDeveloperModeCause(t *testing.T) {
	c := newStatusCollector()
	if c.DeveloperMode == nil {
		t.Error("the status collector must be wired with the marker reader")
	}
	if c.DeveloperModeAncestor == nil {
		t.Error("the status collector must be wired with the ancestor cause reader")
	}
	if c.DeveloperModeMarkerIsDir == nil {
		t.Error("the status collector must be wired with the directory reader")
	}

	dir := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o755}
	file := install.OwnedEntry{Kind: install.EntryRegular, Mode: 0o644}
	t.Run("a group-writable /Library is named", func(t *testing.T) {
		sys := devModeSystem{owners: map[string]install.OwnedEntry{
			"/":                             dir,
			"/Library":                      {Kind: install.EntryDir, Mode: 0o775},
			install.DeveloperModeMarkerPath: file,
		}}
		if got := statusDeveloperModeAncestor(sys); got != "/Library" {
			t.Errorf("ancestor = %q, want /Library", got)
		}
		if statusDeveloperModeIsDir(sys) {
			t.Error("a file at the marker path reads as a directory")
		}
	})
	t.Run("a directory at the marker path is seen", func(t *testing.T) {
		sys := devModeSystem{owners: map[string]install.OwnedEntry{
			"/":                             dir,
			"/Library":                      dir,
			install.DeveloperModeMarkerPath: dir,
		}}
		if !statusDeveloperModeIsDir(sys) {
			t.Error("a directory at the marker path does not read as one")
		}
		if got := statusDeveloperModeAncestor(sys); got != "" {
			t.Errorf("ancestor = %q, want none", got)
		}
	})
}
