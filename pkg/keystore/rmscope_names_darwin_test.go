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
	"os/exec"
	"path/filepath"
	"slices"
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

// hostileSpecials are the bytes of hostileName a shell or a terminal acts
// on; a command rm-scope offers holds none of them.
const hostileSpecials = ";$()\n\x1b[]\x07"

// Every rm-scope error that prints a name from the service user's tree
// renders it quoted with its control bytes removed and labelled as not for
// pasting, so the terminal does not act on it, and the one command it
// offers names only the scope directory, never the entry: no byte of the
// hostile name a shell acts on is in it.
func TestRmScopeHostileNameInert(t *testing.T) {
	w := &rmWalk{svc: 501, base: "/data/keystore/.user/1001", scope: "user/1001"}
	st := unix.Stat_t{Mode: unix.S_IFIFO, Uid: 0, Flags: unix.UF_IMMUTABLE}
	msg := w.flagKept(filepath.Join("entries", hostileName), &st, unix.EPERM).Error()
	assertInert(t, msg, `"/data/keystore/.user/1001/entries/a; touch pwned $(id)[2J]0;titleb" (named for reading, not for pasting)`)
	_, hint, ok := strings.Cut(msg, "to clear it, run ")
	if !ok {
		t.Fatalf("the message %q offers no repair", msg)
	}
	if want := "sudo k3sm stop, then sudo chflags -R -P nouchg,nouappnd '/data/keystore/.user/1001', then rerun sudo k3sm keys rm-scope user/1001 --yes"; hint != want {
		t.Fatalf("the repair is %q, want %q", hint, want)
	}
	if i := strings.IndexAny(hint, hostileSpecials); i >= 0 {
		t.Fatalf("the repair %q holds the hostile name's byte %q", hint, hint[i])
	}
	if strings.Contains(hint, "entries") || strings.Contains(hint, "pwned") {
		t.Fatalf("the repair %q names the entry", hint)
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

// Every command rm-scope offers parses (sh -n), and a shell expands
// nothing in it: run through sh -c with printf in place of the command,
// each word comes back as written, and nothing runs, even when the scope
// directory's path itself holds a command substitution, a backtick, a
// variable and a single quote.
func TestRmScopeRepairCommandsDoNotExpand(t *testing.T) {
	for _, base := range []string{
		"/data/keystore/.user/1001",
		"/data/a$(touch pwned)b/keystore/.user/1001",
		"/data/a`touch pwned`b/$HOME/it's/keystore/.user/1001",
	} {
		t.Run(base, func(t *testing.T) {
			cwd := t.TempDir()
			for _, c := range repairCommands(base, "user/1001") {
				if out, err := exec.Command("sh", "-n", "-c", c).CombinedOutput(); err != nil {
					t.Fatalf("sh -n %q: %v: %s", c, err, out)
				}
				cmd := exec.Command("sh", "-c", "printf '%s\\n' "+c)
				cmd.Dir = cwd
				cmd.Env = []string{"HOME=/expanded", "PATH=/usr/bin:/bin"}
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("sh -c printf %q: %v", c, err)
				}
				got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
				want := strings.Fields(c)
				if strings.Contains(c, "chflags") {
					want = append(strings.Fields("sudo chflags -R -P nouchg,nouappnd"), base)
				}
				if !slices.Equal(got, want) {
					t.Fatalf("the shell expanded %q to %q, want %q", c, got, want)
				}
			}
			if names, _ := os.ReadDir(cwd); len(names) != 0 {
				t.Fatalf("a repair command ran something: %v", names)
			}
		})
	}
}
