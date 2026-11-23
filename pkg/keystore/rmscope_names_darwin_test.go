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

// Every rm-scope error that prints a name from the service user's tree
// renders it quoted with its control bytes removed and labelled as not for
// pasting, so the terminal does not act on it.
func TestRmScopeHostileNameInert(t *testing.T) {
	w := &rmWalk{svc: 501, base: "/data/keystore/.user/1001", scope: "user/1001"}
	st := unix.Stat_t{Mode: unix.S_IFIFO, Uid: 0, Nlink: 1, Flags: sfAppend}
	msg := w.flagKept(filepath.Join("entries", hostileName), &st, unix.EPERM).Error()
	assertInert(t, msg, `"/data/keystore/.user/1001/entries/a; touch pwned $(id)[2J]0;titleb" (named for reading, not for pasting)`)
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

// rm-scope prints no command at all: not for a system flag it leaves, not
// for a twice-linked flagged entry another user owns (which it does not
// clear), neither of which offers any action by hand, not for the service
// user's own twice-linked file (which it cleared, and which was flagged
// again: rerun once nothing sets the flag), not for a tree nested past its depth limit (named
// relative to the scope directory; nothing below it removed), and not for
// a run that meets its flag budget (which says to run rm-scope again). No
// message holds sudo, chflags or a stop, and a path appears only inside
// the one quoted name labelled as not for pasting.
func TestRmScopeOffersNoCommand(t *testing.T) {
	base := "/data/a$(touch pwned)b/keystore/.user/1001"
	w := &rmWalk{svc: 501, base: base, scope: "user/1001"}
	label := quoteName(filepath.Join(base, "entries", "x")) + " (named for reading, not for pasting)"
	deep := filepath.Join("entries", "d$(id)", "e")
	for name, tc := range map[string]struct {
		msg    string
		want   []string
		absent []string
		label  string
	}{
		"system flag": {
			w.flagKept(filepath.Join("entries", "x"), &unix.Stat_t{Mode: unix.S_IFREG, Uid: 0, Nlink: 1, Flags: sfAppend | unix.UF_IMMUTABLE}, unix.EPERM).Error(),
			[]string{label, "carries a system flag (flags", "another user (uid 0) owns it", "rm-scope left the flag in place"},
			[]string{"administrator", "Root may", "clear the flag", "Rerun"},
			"",
		},
		"linked user flag": {
			w.flagKept(filepath.Join("entries", "x"), &unix.Stat_t{Mode: unix.S_IFREG, Uid: 0, Nlink: 2, Flags: unix.UF_IMMUTABLE}, unix.EPERM).Error(),
			[]string{label, "has 2 links", "another user (uid 0) owns it", "rm-scope does not clear it", "rm-scope left the flag in place"},
			[]string{"cleared the flag", "Root may", "clear the flag", "its owner may", "Rerun"},
			"",
		},
		"linked user flag, the service user's": {
			w.flagKept(filepath.Join("entries", "x"), &unix.Stat_t{Mode: unix.S_IFREG, Uid: 501, Nlink: 2, Flags: unix.UF_IMMUTABLE}, unix.EPERM).Error(),
			[]string{label, "has 2 links", "the service user (uid 501) owns it", "rm-scope cleared the flag, and it was set again while rm-scope ran", "Rerun once nothing sets the flag"},
			[]string{"does not clear it", "left the flag in place"},
			"",
		},
		"too deep": {
			w.tooDeep(deep).Error(),
			[]string{quoteName(deep) + " below the scope directory (named for reading, not for pasting)", "nested more than 32 directories deep", "rm-scope removed nothing below it"},
			[]string{"remove it", "rerun"},
			quoteName(deep) + " below the scope directory (named for reading, not for pasting)",
		},
		"budget": {errScopeFlagBudget.Error(), []string{"run rm-scope for this scope again", "each run unlocks up to"}, nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			for _, bad := range []string{"sudo", "chflags", "k3sm stop", "'"} {
				if strings.Contains(tc.msg, bad) {
					t.Errorf("the message %q offers a command (%q)", tc.msg, bad)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(tc.msg, want) {
					t.Errorf("the message %q does not say %q", tc.msg, want)
				}
			}
			for _, bad := range tc.absent {
				if strings.Contains(tc.msg, bad) {
					t.Errorf("the message %q says %q", tc.msg, bad)
				}
			}
			lbl := label
			if tc.label != "" {
				lbl = tc.label
			}
			if rest := strings.Replace(tc.msg, lbl, "", 1); strings.Contains(rest, "/data") || strings.Contains(rest, "pwned") || strings.Contains(rest, "$(id)") {
				t.Errorf("the message %q holds a path outside the one name labelled not for pasting", tc.msg)
			}
		})
	}
}
