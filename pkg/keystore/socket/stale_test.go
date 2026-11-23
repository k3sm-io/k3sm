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

package socket

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeNodes is a socket directory: lstat answers from a table, unlink
// records.
type fakeNodes struct {
	typ, uid uint32
	statErr  error
	unlinked []string
}

func (f *fakeNodes) lstat(string) (uint32, uint32, error) { return f.typ, f.uid, f.statErr }

func (f *fakeNodes) unlink(name string) error {
	f.unlinked = append(f.unlinked, name)
	return nil
}

func TestStaleSocketUnlinkChecksOwner(t *testing.T) {
	const other = 501
	for _, tc := range []struct {
		name     string
		node     fakeNodes
		file     string
		unlinked bool
		refused  bool // ErrNotStaleSocket, with a Warn
		fails    bool // another error
	}{
		{"service-user socket", fakeNodes{typ: unix.S_IFSOCK, uid: serviceUID}, "keys.sock", true, false, false},
		{"another user's socket", fakeNodes{typ: unix.S_IFSOCK, uid: other}, "keys.sock", false, true, false},
		{"root's socket", fakeNodes{typ: unix.S_IFSOCK, uid: 0}, "keys.sock", false, true, false},
		{"service-user regular file", fakeNodes{typ: unix.S_IFREG, uid: serviceUID}, "keys.sock", false, true, false},
		{"service-user symlink", fakeNodes{typ: unix.S_IFLNK, uid: serviceUID}, "keys.sock", false, true, false},
		{"service-user directory", fakeNodes{typ: unix.S_IFDIR, uid: serviceUID}, "keys.sock", false, true, false},
		{"absent", fakeNodes{statErr: unix.ENOENT}, "keys.sock", false, false, false},
		{"lstat fails", fakeNodes{statErr: unix.EACCES}, "keys.sock", false, false, true},
		{"a path, not a name", fakeNodes{typ: unix.S_IFSOCK, uid: serviceUID}, "../keys.sock", false, false, true},
		{"dot-dot", fakeNodes{typ: unix.S_IFSOCK, uid: serviceUID}, "..", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &logBuf{}
			n := tc.node
			err := unlinkStale(&n, tc.file, serviceUID, slog.New(slog.NewTextHandler(log, nil)))
			if got := len(n.unlinked) == 1; got != tc.unlinked {
				t.Fatalf("unlinked %v, want %v", n.unlinked, tc.unlinked)
			}
			if errors.Is(err, ErrNotStaleSocket) != tc.refused {
				t.Fatalf("unlinkStale = %v, refused want %v", err, tc.refused)
			}
			if warned := log.count("level=WARN") == 1; warned != tc.refused {
				t.Fatalf("Warn logged %v, want %v", warned, tc.refused)
			}
			if (err != nil && !tc.refused) != tc.fails {
				t.Fatalf("unlinkStale = %v, failure want %v", err, tc.fails)
			}
		})
	}

	// Through a real directory descriptor: what is not a socket stays, and
	// a dangling symlink is judged as itself, not as its absent target.
	dir := t.TempDir()
	me := uint32(os.Getuid())
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	quiet := slog.New(slog.DiscardHandler)
	for _, name := range []string{"file", "link"} {
		if err := UnlinkStaleSocket(d, name, me, quiet); !errors.Is(err, ErrNotStaleSocket) {
			t.Errorf("%s: UnlinkStaleSocket = %v, want ErrNotStaleSocket", name, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: gone after a refusal: %v", name, err)
		}
	}
	if err := UnlinkStaleSocket(d, "absent", me, quiet); err != nil {
		t.Errorf("absent: UnlinkStaleSocket = %v, want nil", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent: %v", err)
	}
}
