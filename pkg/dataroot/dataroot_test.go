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

package dataroot

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeInfo is a fs.FileInfo whose Sys() carries a uid, like os.Stat's.
type fakeInfo struct {
	name string
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode | fs.ModeDir }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return true }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// fakeEntry is a fs.DirEntry carrying only a name.
type fakeEntry struct{ name string }

func (e fakeEntry) Name() string               { return e.name }
func (e fakeEntry) IsDir() bool                { return false }
func (e fakeEntry) Type() fs.FileMode          { return 0 }
func (e fakeEntry) Info() (fs.FileInfo, error) { return fakeInfo{name: e.name}, nil }

// fakeMount is one mounted filesystem as statfs(2) would report it.
type fakeMount struct{ on, fstype, from string }

// fakeFS describes a filesystem posture no unprivileged unit test could create
// for real (a declared-but-unmounted APFS volume, a root-owned data root).
type fakeFS struct {
	fstab   string // "" means /etc/fstab is absent
	stat    map[string]fakeInfo
	statfs  map[string]fakeMount
	entries map[string][]string
}

func (f fakeFS) Stat(path string) (fs.FileInfo, error) {
	if fi, ok := f.stat[path]; ok {
		return fi, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
}

func (f fakeFS) Statfs(path string, st *unix.Statfs_t) error {
	m, ok := f.statfs[path]
	if !ok {
		return unix.ENOENT
	}
	copyC(st.Mntonname[:], m.on)
	copyC(st.Fstypename[:], m.fstype)
	copyC(st.Mntfromname[:], m.from)
	return nil
}

func (f fakeFS) ReadFile(path string) ([]byte, error) {
	if path != FstabPath || f.fstab == "" {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return []byte(f.fstab), nil
}

func (f fakeFS) ReadDir(path string) ([]fs.DirEntry, error) {
	names, ok := f.entries[path]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: path, Err: fs.ErrNotExist}
	}
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, fakeEntry{name: n})
	}
	return out, nil
}

func copyC(dst []byte, s string) {
	n := copy(dst, s)
	if n < len(dst) {
		dst[n] = 0
	}
}

const testRoot = "/var/lib/k3sm"

func TestRead(t *testing.T) {
	declared := "UUID=DEADBEEF-0000-1111-2222-333344445555 " + testRoot + " apfs rw\n"

	tests := []struct {
		name string
		fsys fakeFS
		dir  string
		want State
	}{
		{
			name: "declared volume mounted",
			fsys: fakeFS{
				fstab:  declared,
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o750, uid: 250}},
				statfs: map[string]fakeMount{testRoot: {on: testRoot, fstype: "apfs", from: "/dev/disk3s7"}},
			},
			dir: testRoot,
			want: State{
				Exists: true, DeclaredMount: true, Mounted: true,
				FSType: "apfs", VolumeName: "disk3s7",
				OwnerUID: 250, OwnerWritable: true,
			},
		},
		{
			name: "declared but not mounted shadows the mountpoint",
			fsys: fakeFS{
				fstab:   declared,
				stat:    map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o755, uid: 0}},
				statfs:  map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
				entries: map[string][]string{testRoot: {"run", "server"}},
			},
			dir: testRoot,
			want: State{
				Exists: true, DeclaredMount: true, Mounted: false,
				OwnerUID: 0, OwnerWritable: true,
				ShadowEntries: []string{"run", "server"},
			},
		},
		{
			name: "plain directory owned by the service user",
			fsys: fakeFS{
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o750, uid: 250}},
				statfs: map[string]fakeMount{testRoot: {on: "/", fstype: "apfs", from: "/dev/disk3s5"}},
			},
			dir:  testRoot,
			want: State{Exists: true, OwnerUID: 250, OwnerWritable: true},
		},
		{
			name: "plain directory owned by root and not owner-writable",
			fsys: fakeFS{
				stat: map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o500, uid: 0}},
			},
			dir:  testRoot,
			want: State{Exists: true, OwnerUID: 0, OwnerWritable: false},
		},
		{
			name: "absent directory is not an error",
			fsys: fakeFS{fstab: declared},
			dir:  testRoot,
			want: State{Exists: false, DeclaredMount: true},
		},
		{
			name: "no fstab means nothing was declared",
			fsys: fakeFS{
				stat: map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o750, uid: 250}},
			},
			dir:  testRoot,
			want: State{Exists: true, OwnerUID: 250, OwnerWritable: true},
		},
		{
			name: "fstab with comments, blank lines and other mounts",
			fsys: fakeFS{
				fstab: "#\n# Warning - this file should only be modified with vifs(8)\n#\n\n" +
					"LABEL=Backup\t/Volumes/Backup\thfs\trw\n" +
					"UUID=DEADBEEF-0000-1111-2222-333344445555   " + testRoot + "   apfs   rw\n",
				stat:   map[string]fakeInfo{testRoot: {name: "k3sm", mode: 0o750, uid: 250}},
				statfs: map[string]fakeMount{testRoot: {on: testRoot, fstype: "apfs", from: "/dev/disk3s7"}},
			},
			dir: testRoot,
			want: State{
				Exists: true, DeclaredMount: true, Mounted: true,
				FSType: "apfs", VolumeName: "disk3s7",
				OwnerUID: 250, OwnerWritable: true,
			},
		},
		{
			name: "a subdirectory of a declared root is not itself declared",
			fsys: fakeFS{
				fstab:  declared,
				stat:   map[string]fakeInfo{testRoot + "/run": {name: "run", mode: 0o700, uid: 250}},
				statfs: map[string]fakeMount{testRoot + "/run": {on: testRoot, fstype: "apfs", from: "/dev/disk3s7"}},
			},
			dir:  testRoot + "/run",
			want: State{Exists: true, OwnerUID: 250, OwnerWritable: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(tc.fsys, tc.dir)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Read(%s)\n got %+v\nwant %+v", tc.dir, got, tc.want)
			}
			if want := tc.want.DeclaredMount && !tc.want.Mounted; got.Shadowed() != want {
				t.Fatalf("Shadowed() = %v, want %v", got.Shadowed(), want)
			}
		})
	}
}

// TestRefusalWrapsErrNotMounted pins the sentinel every caller matches on, and
// that the operator action stays in the message.
func TestRefusalWrapsErrNotMounted(t *testing.T) {
	err := Refusal(testRoot)
	if !errors.Is(err, ErrNotMounted) {
		t.Fatalf("Refusal does not wrap ErrNotMounted: %v", err)
	}
	for _, want := range []string{testRoot, "diskutil mount", "io.k3sm.server"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Refusal message lost %q: %v", want, err)
		}
	}
}
