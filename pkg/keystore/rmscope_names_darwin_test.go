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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// hostileName is a name the service user can give a file in its tree: a
// shell separator, a command substitution, a newline and an ESC sequence.
const hostileName = "a; touch pwned $(id)\n\x1b[2J\x1b]0;title\x07b"

// assertInert fails unless msg carries no control byte and holds want,
// the hostile name inside a Go-quoted string.
func assertInert(t *testing.T, msg, want string) {
	t.Helper()
	for _, c := range []byte(msg) {
		if c < 0x20 || c == 0x7f {
			t.Fatalf("the message %q carries the control byte %#x", msg, c)
		}
	}
	if !strings.Contains(msg, want) {
		t.Fatalf("the message %q does not name the file as one quoted string", msg)
	}
}

// Every rm-scope error or hint that prints a name from the service user's
// tree renders it quoted with its control bytes removed, so neither the
// terminal nor a pasted command acts on it; the suggested chflags acts on
// a symlink itself (-h) and asks for the path to be checked first.
func TestRmScopeHostileNameInert(t *testing.T) {
	w := &rmWalk{svc: 501, base: "/data/keystore/.user/1001"}
	st := unix.Stat_t{Mode: unix.S_IFIFO, Uid: 501, Flags: unix.UF_IMMUTABLE}
	msg := w.flagKept(filepath.Join("entries", hostileName), &st, unix.EPERM).Error()
	assertInert(t, msg, `"/data/keystore/.user/1001/entries/a; touch pwned $(id)[2J]0;titleb"`)
	if !strings.Contains(msg, "check that the path is the one meant, then clear it with sudo chflags -h nouchg,nouappnd \"") {
		t.Fatalf("the hint %q is not chflags -h after a check", msg)
	}
	d := t.TempDir()
	if err := os.Symlink("x", filepath.Join(d, hostileName)); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(d, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	_, _, err = openDirAt(fd, hostileName)
	if !errors.Is(err, errPlanted) {
		t.Fatalf("openDirAt over a symlink: %v, want errPlanted", err)
	}
	assertInert(t, err.Error(), `"a; touch pwned $(id)[2J]0;titleb"`)
}
