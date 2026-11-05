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
	"errors"
	"testing"
)

// TestDeveloperModeAncestorCause pins which directory is named: the first bad
// one above a sound marker, and nothing when the marker itself is the cause.
func TestDeveloperModeAncestorCause(t *testing.T) {
	t.Parallel()
	good := OwnedEntry{Kind: EntryDir, Mode: 0o755}
	file := OwnedEntry{Kind: EntryRegular, Mode: 0o644}
	path := DeveloperModeMarkerPath
	bad := OwnedEntry{Kind: EntryDir, Mode: 0o775}
	cases := []struct {
		name string
		f    DeveloperModeFacts
		want string
	}{
		{"all sound", DeveloperModeFacts{Exists: true, Entry: file, Ancestors: []DeveloperModeAncestor{{Entry: good}, {Entry: good}}}, ""},
		{"library writable", DeveloperModeFacts{Exists: true, Entry: file, Ancestors: []DeveloperModeAncestor{{Entry: good}, {Entry: bad}}}, "/Library"},
		{"root acl", DeveloperModeFacts{Exists: true, Entry: file, Ancestors: []DeveloperModeAncestor{{Entry: good, HasACL: true}, {Entry: good}}}, "/"},
		{"symlink root", DeveloperModeFacts{Exists: true, Entry: file, Ancestors: []DeveloperModeAncestor{{Entry: OwnedEntry{Kind: EntrySymlink, Mode: 0o755}}, {Entry: good}}}, "/"},
		{"probe error on library", DeveloperModeFacts{Exists: true, Entry: file, Ancestors: []DeveloperModeAncestor{{Entry: good}, {Err: errors.New("lstat failed")}}}, "/Library"},
		{"a directory marker under a bad directory", DeveloperModeFacts{Exists: true, Entry: good, Ancestors: []DeveloperModeAncestor{{Entry: good}, {Entry: bad}}}, "/Library"},
		{"a directory marker under sound directories", DeveloperModeFacts{Exists: true, Entry: good, Ancestors: []DeveloperModeAncestor{{Entry: good}, {Entry: good}}}, ""},
		{"a symlink marker under a bad root", DeveloperModeFacts{Exists: true, Entry: OwnedEntry{Kind: EntrySymlink, Mode: 0o755}, Ancestors: []DeveloperModeAncestor{{Entry: bad}, {Entry: good}}}, "/"},
		{"marker unread", DeveloperModeFacts{Exists: true, Err: errors.New("lstat failed")}, ""},
		{"marker is the cause", DeveloperModeFacts{Exists: true, Entry: OwnedEntry{Kind: EntryRegular, UID: 501, Mode: 0o644}, Ancestors: []DeveloperModeAncestor{{Entry: bad}, {Entry: bad}}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DeveloperModeAncestorCause(tc.f, path); got != tc.want {
				t.Errorf("cause %q, want %q", got, tc.want)
			}
		})
	}
}
