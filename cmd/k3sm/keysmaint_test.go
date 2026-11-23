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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// keysAttrRecorder is a file-attribute writer that records each call.
type keysAttrRecorder struct{ calls []string }

func (r *keysAttrRecorder) Fchown(int, int, int) error {
	r.calls = append(r.calls, "fchown")
	return nil
}

func (r *keysAttrRecorder) Fchmod(int, uint32) error {
	r.calls = append(r.calls, "fchmod")
	return nil
}

func (r *keysAttrRecorder) Fchflags(int, int) error {
	r.calls = append(r.calls, "fchflags")
	return nil
}

// floor --rebuild and rm-scope: usage and a non-root caller are refused
// before the store opens; floor --rebuild acts through the file-attribute
// writer the verb is given and writes its audit line as floor-rebuild, via
// root; rm-scope refuses an absent scope, audited as refused.
func TestKeysMaintenanceVerbs(t *testing.T) {
	h := newKeysHarness(t)
	var lines []string
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	rec := &keysAttrRecorder{}
	h.attrs = rec
	h.stdin = bytes.NewReader([]byte("tok"))
	h.mustRun(keysOK, "put", "system/api-token", "--in", "-")

	for _, tc := range []struct {
		args []string
		euid int
		code int
	}{
		{[]string{"floor"}, 0, keysBadUsage},
		{[]string{"floor", "--rebuild", "extra"}, 0, keysBadUsage},
		{[]string{"floor", "--rebuild"}, 501, keysRefused},
		{[]string{"rm-scope", "user/1001"}, 0, keysBadUsage},
		{[]string{"rm-scope", "user/01001", "--yes"}, 0, keysBadUsage},
		{[]string{"rm-scope", "system/x", "--yes"}, 0, keysBadUsage},
		{[]string{"rm-scope", "user/1001", "--yes"}, 501, keysRefused},
	} {
		lines = nil
		h.euid = tc.euid
		h.mustRun(tc.code, tc.args...)
		if len(lines) != 0 {
			t.Errorf("keys %v asked for audit lines %q before opening the store", tc.args, lines)
		}
	}

	h.euid = 0
	h.logFlags = keysFlagged
	if err := os.MkdirAll(filepath.Join(h.cfg.DataRoot, keystore.LogsDirName, keystore.FloorDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	floor := filepath.Join(h.cfg.DataRoot, keystore.LogsDirName, keystore.FloorDirName, "keystore-user-floor.log")
	if err := os.WriteFile(floor, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lines = nil
	h.mustRun(keysOK, "floor", "--rebuild")
	if !strings.Contains(h.stdout.String(), "rebuilt the user-scope floor: 0 scopes, 0 keys") {
		t.Errorf("floor --rebuild printed %q", h.stdout.String())
	}
	if !slices.Equal(lines, []string{"floor-rebuild  ok"}) {
		t.Errorf("floor --rebuild audit lines %q", lines)
	}
	if !slices.Contains(rec.calls, "fchflags") {
		t.Errorf("floor --rebuild did not act through the writer it was given: %q", rec.calls)
	}
	// A rebuild that dropped anything is done, exits 4 and lists the
	// counts by class; its audit line's result is committed.
	f, err := os.OpenFile(floor, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("not a floor line\n" + strings.Repeat("z", 4096) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	lines = nil
	h.stdout.Reset()
	h.mustRun(keysCommitted, "floor", "--rebuild")
	for _, want := range []string{"dropped 1 lines of the old floor that did not parse", "dropped 1 lines of the old floor over the per-line bound", "(exit 4)"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("floor --rebuild after drops printed %q, want %q", h.stdout.String(), want)
		}
	}
	if !slices.Equal(lines, []string{"floor-rebuild  committed"}) {
		t.Errorf("floor --rebuild after drops audit lines %q", lines)
	}
	lines = nil
	h.mustRun(keysRefused, "rm-scope", "user/1001", "--yes")
	if !slices.Equal(lines, []string{"rm-scope  refused"}) {
		t.Errorf("rm-scope audit lines %q", lines)
	}
}

// keysInoRecorder is a file-attribute writer that records each call with
// the inode of the descriptor it acts on, so a test can tell which file
// each call reached.
type keysInoRecorder struct {
	t     *testing.T
	calls map[uint64][]string
}

func (r *keysInoRecorder) note(fd int, call string) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		r.t.Errorf("fstat the descriptor of %s: %v", call, err)
		return
	}
	r.calls[st.Ino] = append(r.calls[st.Ino], call)
}

func (r *keysInoRecorder) Fchown(fd, _, _ int) error {
	r.note(fd, "fchown")
	return nil
}

func (r *keysInoRecorder) Fchmod(fd int, mode uint32) error {
	r.note(fd, fmt.Sprintf("fchmod %o", mode))
	return nil
}

func (r *keysInoRecorder) Fchflags(fd, flags int) error {
	r.note(fd, fmt.Sprintf("fchflags %#x", flags))
	return nil
}

// keysFlagged is a flag source that reports SF_APPEND on every log, as the
// maintenance verbs leave each one: a non-root test cannot set it.
func keysFlagged(*os.File) (uint32, error) { return 0x00040000, nil }

// keysIno is the inode at path.
func keysIno(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// U91: audit --rotate keeps four archives, .1 the newest; with .4 present
// it refuses, changing nothing, unless --discard-oldest, which deletes .4
// first; the swapped-in directory holds a fresh .1 with the old log's
// bytes, the older archives carried by hard link as .2 to .4, root's 0600
// and unflagged, and an empty new log, so every uid's share of it starts
// at 0. Usage and a non-root caller are refused before the store
// opens; the verb's audit line is audit-rotate, via root (AuditRoot).
func TestAuditRotateKeepsFourArchives(t *testing.T) {
	h := newKeysHarness(t)
	var lines []string
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	h.put("system/api-token", []byte("tok"))

	for _, tc := range []struct {
		args []string
		euid int
		code int
	}{
		{[]string{"audit"}, 0, keysBadUsage},
		{[]string{"audit", "--discard-oldest"}, 0, keysBadUsage},
		{[]string{"audit", "--rotate", "extra"}, 0, keysBadUsage},
		{[]string{"audit", "--rotate"}, 501, keysRefused},
	} {
		lines = nil
		h.euid = tc.euid
		h.mustRun(tc.code, tc.args...)
		if len(lines) != 0 {
			t.Errorf("keys %v asked for audit lines %q before opening the store", tc.args, lines)
		}
	}
	h.euid = 0

	h.logFlags = keysFlagged
	root := h.cfg.DataRoot
	logs := filepath.Join(root, keystore.LogsDirName)
	adir := filepath.Join(logs, keystore.AuditDirName)
	if err := os.MkdirAll(adir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := func(n int) string {
		if n == 0 {
			return filepath.Join(adir, keystore.AuditLogName)
		}
		return filepath.Join(adir, fmt.Sprintf("%s.%d", keystore.AuditLogName, n))
	}
	write := func(n int, s string) {
		t.Helper()
		if err := os.WriteFile(name(n), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// read drops the verb's own audit-rotate line, which AuditRoot appends
	// to the new log once the verb is done (step 7), and the newline each
	// append leads with.
	read := func(n int) string {
		t.Helper()
		b, err := os.ReadFile(name(n))
		if errors.Is(err, os.ErrNotExist) {
			return "<absent>"
		}
		if err != nil {
			t.Fatal(err)
		}
		var out strings.Builder
		for _, l := range strings.SplitAfter(string(b), "\n") {
			if l == "\n" || strings.Contains(l, `"op":"audit-rotate"`) {
				continue
			}
			out.WriteString(l)
		}
		return out.String()
	}
	want := func(step string, contents ...string) {
		t.Helper()
		for n, c := range contents {
			if got := read(n + 1); got != c {
				t.Errorf("%s: archive .%d holds %q, want %q", step, n+1, got, c)
			}
		}
	}
	write(0, "live\n")
	write(1, "a1\n")
	write(2, "a2\n")

	// Two archives: both are linked one number up, the old log's bytes
	// become .1, and the new log is empty.
	rec := &keysInoRecorder{t: t, calls: map[uint64][]string{}}
	h.attrs = rec
	lines = nil
	h.mustRun(keysOK, "audit", "--rotate")
	want("rotate with two archives", "live\n", "a1\n", "a2\n", "<absent>")
	if !strings.Contains(h.stdout.String(), "3 archives kept") {
		t.Errorf("audit --rotate printed %q", h.stdout.String())
	}
	if !slices.Equal(lines, []string{"audit-rotate  ok"}) {
		t.Errorf("audit --rotate audit lines %q, want [audit-rotate  ok]", lines)
	}
	if got := read(0); got != "" {
		t.Errorf("the new audit log holds %q, want it empty: every share restarts at 0", got)
	}
	flagged := fmt.Sprintf("fchflags %#x", 0x00040000)
	for n := 2; n <= 3; n++ {
		if got := rec.calls[keysIno(t, name(n))]; len(got) != 0 {
			t.Errorf("the archive shifted to .%d saw %q on its descriptor, want none: archives are root's and unflagged", n, got)
		}
	}
	if got := rec.calls[keysIno(t, name(1))]; len(got) != 0 {
		t.Errorf("the new archive .1 saw %q through the attribute writer, want none: it is root's 0600", got)
	}
	if got := rec.calls[keysIno(t, name(0))]; !slices.Equal(got, []string{"fchown", "fchmod 600", flagged}) {
		t.Errorf("the new log saw %q, want the service user, 0600, then the flag", got)
	}
	for _, d := range []string{logs, adir} {
		if got := rec.calls[keysIno(t, d)]; len(got) != 0 {
			t.Errorf("%s saw %q, want no attribute call: there is no gate", d, got)
		}
	}
	for _, n := range []string{"keystore-maintenance", "keystore-staging"} {
		if _, err := os.Lstat(filepath.Join(root, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind: %v", n, err)
		}
	}

	// Three archives: the fourth is filled.
	write(0, "live2\n")
	h.attrs = &keysAttrRecorder{}
	h.mustRun(keysOK, "audit", "--rotate")
	want("rotate with three archives", "live2\n", "live\n", "a1\n", "a2\n")

	// Four archives: refused, every file as it was, and the refusal is
	// audited.
	write(0, "live3\n")
	rec4 := &keysAttrRecorder{}
	h.attrs = rec4
	lines = nil
	h.mustRun(keysRefused, "audit", "--rotate")
	want("refused rotate", "live2\n", "live\n", "a1\n", "a2\n")
	if got := read(0); got != "live3\n" {
		t.Errorf("a refused rotate left the audit log %q, want it unchanged", got)
	}
	if !strings.Contains(h.stderr.String(), "--discard-oldest") || !strings.Contains(h.stderr.String(), "export the archives first") {
		t.Errorf("the refusal %q names neither --discard-oldest nor the export", h.stderr.String())
	}
	if len(rec4.calls) != 0 {
		t.Errorf("a refused rotate changed attributes: %q", rec4.calls)
	}
	if !slices.Equal(lines, []string{"audit-rotate  refused"}) {
		t.Errorf("refused audit --rotate audit lines %q", lines)
	}
	for _, n := range []string{"keystore-maintenance", "keystore-staging"} {
		if _, err := os.Lstat(filepath.Join(root, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a refused rotate left %s: %v", n, err)
		}
	}

	// --discard-oldest deletes .4 and shifts the rest: still four.
	h.mustRun(keysOK, "audit", "--rotate", "--discard-oldest")
	want("rotate --discard-oldest", "live3\n", "live2\n", "live\n", "a1\n")
	if !strings.Contains(h.stdout.String(), "discarded the oldest") || !strings.Contains(h.stdout.String(), "4 archives kept") {
		t.Errorf("audit --rotate --discard-oldest printed %q", h.stdout.String())
	}

	// doctor's hint past the soft cap says to export the archives first,
	// then rotate.
	env := healthyDoctorEnv()
	env.keystoreLogs = func(context.Context) error { return nil }
	env.keystoreLogSizes = func(context.Context) (keystore.LogSizes, error) {
		return keystore.LogSizes{Audit: 65, SoftCap: 64, HardCap: 256}, nil
	}
	r := checkKeystoreLogs(env)
	if r.status != statusWarn || !strings.Contains(r.remedy, "export the audit archives first") || !strings.Contains(r.remedy, "sudo k3sm keys audit --rotate") ||
		strings.Index(r.remedy, "export") > strings.Index(r.remedy, "audit --rotate") {
		t.Errorf("doctor past the audit log's soft cap: %v %q / %q, want a WARN saying to export first, then rotate", r.status, r.detail, r.remedy)
	}
}
