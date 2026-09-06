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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

const (
	testServiceUID = 250
	testServiceGID = 20
)

// fakeStat is one directory as the fake ownership seam reports it.
type fakeStat struct {
	uid  uint32
	mode fs.FileMode
}

func (f fakeStat) Name() string       { return "" }
func (f fakeStat) Size() int64        { return 0 }
func (f fakeStat) Mode() fs.FileMode  { return f.mode | fs.ModeDir }
func (f fakeStat) ModTime() time.Time { return time.Time{} }
func (f fakeStat) IsDir() bool        { return true }
func (f fakeStat) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// fakeOwn is the ownership seam: it FAKES everything privileged (ownership,
// mount state, the user database) and performs for real only what the listen
// step needs — creating and removing the socket directory in a temp dir.
type fakeOwn struct {
	fstab     string
	stat      map[string]fakeStat
	mounts    map[string]string // path -> the mount point statfs(2) reports
	lookupErr error
	calls     []string
}

func (f *fakeOwn) Stat(path string) (fs.FileInfo, error) {
	if st, ok := f.stat[path]; ok {
		return st, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
}

func (f *fakeOwn) Statfs(path string, st *unix.Statfs_t) error {
	on, ok := f.mounts[path]
	if !ok {
		on = "/"
	}
	copy(st.Mntonname[:], on)
	st.Mntonname[len(on)] = 0
	copy(st.Fstypename[:], "apfs")
	st.Fstypename[4] = 0
	copy(st.Mntfromname[:], "/dev/disk3s7")
	st.Mntfromname[12] = 0
	return nil
}

func (f *fakeOwn) ReadFile(path string) ([]byte, error) {
	if path != dataroot.FstabPath || f.fstab == "" {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return []byte(f.fstab), nil
}

func (f *fakeOwn) ReadDir(path string) ([]fs.DirEntry, error) {
	return nil, &fs.PathError{Op: "readdir", Path: path, Err: fs.ErrNotExist}
}

func (f *fakeOwn) Lookup(string) (int, int, error) {
	if f.lookupErr != nil {
		return 0, 0, f.lookupErr
	}
	return testServiceUID, testServiceGID, nil
}

func (f *fakeOwn) MkdirAll(path string, perm fs.FileMode) error {
	f.calls = append(f.calls, "mkdirall "+path)
	// Really create it: the listen step below binds a socket inside.
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	for p := path; len(p) > 1; p = filepath.Dir(p) {
		if _, ok := f.stat[p]; !ok {
			f.stat[p] = fakeStat{uid: 0, mode: perm}
		}
	}
	return nil
}

func (f *fakeOwn) Chown(path string, uid, gid int) error {
	f.calls = append(f.calls, fmt.Sprintf("chown %s %d:%d", path, uid, gid))
	if st, ok := f.stat[path]; ok {
		st.uid = uint32(uid)
		f.stat[path] = st
	}
	return nil
}

func (f *fakeOwn) Chmod(path string, mode fs.FileMode) error {
	f.calls = append(f.calls, fmt.Sprintf("chmod %s %04o", path, mode.Perm()))
	if st, ok := f.stat[path]; ok {
		st.mode = mode
		f.stat[path] = st
	}
	return nil
}

func (f *fakeOwn) Remove(path string) error {
	f.calls = append(f.calls, "remove "+path)
	return os.Remove(path)
}

func (f *fakeOwn) has(want string) bool {
	for _, c := range f.calls {
		if c == want {
			return true
		}
	}
	return false
}

// touching returns the OWNERSHIP calls (chown/chmod) made against path. An
// idempotent MkdirAll over an existing directory is not a change of ownership
// and is deliberately not counted.
func (f *fakeOwn) touching(path string) []string {
	var out []string
	for _, c := range f.calls {
		fields := strings.Fields(c)
		if len(fields) > 1 && fields[1] == path && (fields[0] == "chown" || fields[0] == "chmod") {
			out = append(out, c)
		}
	}
	return out
}

// tempRoot returns a short-lived directory to hang a data root off. It is
// os.MkdirTemp rather than t.TempDir because a unix socket path is capped near
// 104 bytes and t.TempDir embeds the (long) subtest name.
func tempRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k3sm")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// captureLogs redirects the default slog logger into a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestListenNetdGuardsDataRoot pins both halves of the 2026-09-05 fix: netd
// REFUSES a declared-but-unmounted data root without creating or chowning
// anything, and otherwise ALIGNS what it finds (or creates) to the install
// ownership policy.
func TestListenNetdGuardsDataRoot(t *testing.T) {
	t.Run("fresh missing plain root is created and aligned", func(t *testing.T) {
		base := tempRoot(t)
		root := filepath.Join(base, "k3sm")
		socket := filepath.Join(root, "run", "netd.sock")
		own := &fakeOwn{stat: map[string]fakeStat{}}

		l, err := listenNetd(socket, root, testServiceGID, own)
		if err != nil {
			t.Fatalf("listenNetd: %v", err)
		}
		defer l.Close()

		for _, want := range []string{
			"mkdirall " + filepath.Join(root, "run"),
			fmt.Sprintf("chown %s %d:%d", root, testServiceUID, install.DataRootGID),
			fmt.Sprintf("chmod %s %04o", root, install.DataRootMode.Perm()),
			fmt.Sprintf("chown %s %d:%d", filepath.Join(root, "run"), testServiceUID, testServiceGID),
			fmt.Sprintf("chmod %s 0700", filepath.Join(root, "run")),
		} {
			if !own.has(want) {
				t.Fatalf("missing call %q in %v", want, own.calls)
			}
		}
	})

	t.Run("an existing wrong-owned root is realigned and warned about", func(t *testing.T) {
		base := tempRoot(t)
		root := filepath.Join(base, "k3sm")
		runDir := filepath.Join(root, "run")
		if err := os.MkdirAll(runDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		socket := filepath.Join(runDir, "netd.sock")
		own := &fakeOwn{stat: map[string]fakeStat{
			root:   {uid: 0, mode: 0o755},
			runDir: {uid: 0, mode: 0o755},
		}}
		logs := captureLogs(t)

		l, err := listenNetd(socket, root, testServiceGID, own)
		if err != nil {
			t.Fatalf("listenNetd: %v", err)
		}
		defer l.Close()

		for _, want := range []string{
			fmt.Sprintf("chown %s %d:%d", root, testServiceUID, install.DataRootGID),
			fmt.Sprintf("chmod %s %04o", root, install.DataRootMode.Perm()),
			fmt.Sprintf("chown %s %d:%d", runDir, testServiceUID, testServiceGID),
			fmt.Sprintf("chmod %s 0700", runDir),
		} {
			if !own.has(want) {
				t.Fatalf("missing call %q in %v", want, own.calls)
			}
		}
		if !strings.Contains(logs.String(), "aligned data-root ownership") {
			t.Fatalf("no realignment warning logged: %s", logs.String())
		}
	})

	t.Run("an already-correct root is left alone", func(t *testing.T) {
		base := tempRoot(t)
		root := filepath.Join(base, "k3sm")
		runDir := filepath.Join(root, "run")
		if err := os.MkdirAll(runDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		socket := filepath.Join(runDir, "netd.sock")
		own := &fakeOwn{stat: map[string]fakeStat{
			root:   {uid: testServiceUID, mode: install.DataRootMode},
			runDir: {uid: testServiceUID, mode: 0o700},
		}}
		logs := captureLogs(t)

		l, err := listenNetd(socket, root, testServiceGID, own)
		if err != nil {
			t.Fatalf("listenNetd: %v", err)
		}
		defer l.Close()

		if got := own.touching(root); len(got) != 0 {
			t.Fatalf("data root touched when it was already correct: %v", got)
		}
		if got := own.touching(runDir); len(got) != 0 {
			t.Fatalf("run dir touched when it was already correct: %v", got)
		}
		if strings.Contains(logs.String(), "aligned data-root ownership") {
			t.Fatalf("warned about a root that did not change: %s", logs.String())
		}
	})

	t.Run("a missing service user is logged and ownership left as-is", func(t *testing.T) {
		base := tempRoot(t)
		root := filepath.Join(base, "k3sm")
		socket := filepath.Join(root, "run", "netd.sock")
		own := &fakeOwn{stat: map[string]fakeStat{}, lookupErr: errors.New("unknown user _k3sm")}
		logs := captureLogs(t)

		l, err := listenNetd(socket, root, testServiceGID, own)
		if err != nil {
			t.Fatalf("listenNetd: %v", err)
		}
		defer l.Close()

		if got := own.touching(root); len(got) != 0 {
			t.Fatalf("ownership changed without a service user: %v", got)
		}
		if got := own.touching(filepath.Join(root, "run")); len(got) != 0 {
			t.Fatalf("ownership changed without a service user: %v", got)
		}
		if !strings.Contains(logs.String(), "service user not found") {
			t.Fatalf("no service-user error logged: %s", logs.String())
		}
	})

	t.Run("every level created below the root is aligned", func(t *testing.T) {
		base := tempRoot(t)
		root := filepath.Join(base, "k3sm")
		socket := filepath.Join(root, "a", "b", "netd.sock")
		own := &fakeOwn{stat: map[string]fakeStat{}}

		l, err := listenNetd(socket, root, testServiceGID, own)
		if err != nil {
			t.Fatalf("listenNetd: %v", err)
		}
		defer l.Close()

		for _, level := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
			if !own.has(fmt.Sprintf("chown %s %d:%d", level, testServiceUID, testServiceGID)) ||
				!own.has(fmt.Sprintf("chmod %s 0700", level)) {
				t.Fatalf("level %s not aligned: %v", level, own.calls)
			}
		}
	})

	t.Run("a shadowed root is refused without creating anything", func(t *testing.T) {
		base := tempRoot(t)
		root := filepath.Join(base, "k3sm")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		socket := filepath.Join(root, "run", "netd.sock")
		own := &fakeOwn{
			fstab:  "UUID=DEADBEEF " + root + " apfs rw\n",
			stat:   map[string]fakeStat{root: {uid: 0, mode: 0o755}},
			mounts: map[string]string{root: "/"}, // mounted on /, i.e. NOT a mount point
		}

		l, err := listenNetd(socket, root, testServiceGID, own)
		if err == nil {
			_ = l.Close()
			t.Fatal("listenNetd accepted a shadowed data root")
		}
		if !errors.Is(err, dataroot.ErrNotMounted) {
			t.Fatalf("error does not wrap ErrNotMounted: %v", err)
		}
		if len(own.calls) != 0 {
			t.Fatalf("netd wrote to a shadowed data root: %v", own.calls)
		}
		if _, serr := os.Stat(filepath.Join(root, "run")); serr == nil {
			t.Fatal("netd created the run dir inside a shadowed mountpoint")
		}
	})
}
