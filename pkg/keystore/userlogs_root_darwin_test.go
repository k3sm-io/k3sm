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

package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAppendOnlyFlagHoldsAsRoot sets the real SF_APPEND flag (chflags
// sappnd) on a log the service user owns at 0600, and proves what the
// flag variant of the user-scope floor rests on: an O_APPEND write lands,
// while a truncate, an unlink, a rename over the file and an O_TRUNC open
// all fail and leave every byte in place. The store's own check, through
// the real flag source, admits the flagged file and refuses it once the
// flag is cleared. Only root can set SF_APPEND, so it skips unless root.
func TestAppendOnlyFlagHoldsAsRoot(t *testing.T) {
	if !asRoot() {
		t.Skip("root-only: SF_APPEND can only be set by root")
	}
	s, _ := newTestStore(t)
	p := filepath.Join(s.dataRoot, userFloorLogName)
	if err := os.WriteFile(p, []byte("first\n"), logMode); err != nil {
		t.Fatal(err)
	}
	giveToService(t, p)
	if err := unix.Chflags(p, sfAppend); err != nil {
		t.Fatalf("chflags sappnd: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(p, 0) }) // so TempDir can remove it

	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open O_APPEND on a flagged file: %v", err)
	}
	if _, err := f.Write([]byte("second\n")); err != nil {
		t.Fatalf("append to a flagged file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	want := "first\nsecond\n"

	other := filepath.Join(s.dataRoot, "other")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string]func() error{
		"truncate":    func() error { return os.Truncate(p, 0) },
		"unlink":      func() error { return os.Remove(p) },
		"rename over": func() error { return os.Rename(other, p) },
		"O_TRUNC open": func() error {
			g, err := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0)
			if err == nil {
				_ = g.Close() // the open itself is the failure
			}
			return err
		},
	} {
		if err := attempt(); err == nil {
			t.Errorf("%s of a flagged file succeeded", name)
		}
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			t.Fatalf("after the %s attempt the file holds %q (%v), want %q", name, b, err, want)
		}
	}

	s.logFlags = fileFlags
	l := newFileFloorLog(s).log
	g, _, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatalf("the store refused the flagged log: %v", err)
	}
	_ = g.Close() // read-only
	if err := unix.Chflags(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.open(unix.O_RDONLY); err == nil {
		t.Fatal("the store admitted the log with its flag cleared")
	}
}
