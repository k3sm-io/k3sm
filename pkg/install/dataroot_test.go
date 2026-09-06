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
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/dataroot"
)

// fakeDirInfo is a directory fs.FileInfo; the uid is irrelevant to the refusal,
// only the mount posture is.
type fakeDirInfo struct{ mode fs.FileMode }

func (f fakeDirInfo) Name() string       { return "" }
func (f fakeDirInfo) Size() int64        { return 0 }
func (f fakeDirInfo) Mode() fs.FileMode  { return f.mode | fs.ModeDir }
func (f fakeDirInfo) ModTime() time.Time { return time.Time{} }
func (f fakeDirInfo) IsDir() bool        { return true }
func (f fakeDirInfo) Sys() any           { return nil }

// fakeRootFS describes a data-root mount posture the unit tier cannot create.
type fakeRootFS struct {
	fstab   string
	exists  bool
	mountOn string // what statfs(2) reports as the mount point
}

func (f fakeRootFS) Stat(path string) (fs.FileInfo, error) {
	if !f.exists {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return fakeDirInfo{mode: 0o750}, nil
}

func (f fakeRootFS) Statfs(_ string, st *unix.Statfs_t) error {
	on := f.mountOn
	if on == "" {
		on = "/"
	}
	copy(st.Mntonname[:], on)
	st.Mntonname[len(on)] = 0
	return nil
}

func (f fakeRootFS) ReadFile(path string) ([]byte, error) {
	if path != dataroot.FstabPath || f.fstab == "" {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return []byte(f.fstab), nil
}

func (f fakeRootFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, nil }

// TestInstallRefusesShadowedDataRoot pins the installer's half of the
// 2026-09-05 fix: `k3sm install` must not chown a declared-but-unmounted
// mountpoint to the service user, because a writable shadow is worse than a
// crash — the control plane would build an empty datastore over the real one.
func TestInstallRefusesShadowedDataRoot(t *testing.T) {
	declared := "UUID=DEADBEEF " + DefaultDataRoot + " apfs rw\n"

	tests := []struct {
		name   string
		fsys   fakeRootFS
		refuse bool
	}{
		{
			name:   "declared but not mounted",
			fsys:   fakeRootFS{fstab: declared, exists: true, mountOn: "/"},
			refuse: true,
		},
		{
			name:   "declared and not even created yet",
			fsys:   fakeRootFS{fstab: declared},
			refuse: true,
		},
		{
			name: "declared and mounted",
			fsys: fakeRootFS{fstab: declared, exists: true, mountOn: DefaultDataRoot},
		},
		{
			name: "a plain undeclared directory",
			fsys: fakeRootFS{exists: true, mountOn: "/"},
		},
		{
			name: "an unrelated fstab entry",
			fsys: fakeRootFS{fstab: "LABEL=Backup /Volumes/Backup hfs rw\n", exists: true, mountOn: "/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseShadowedDataRoot(tc.fsys, DefaultDataRoot)
			if tc.refuse {
				if !errors.Is(err, dataroot.ErrNotMounted) {
					t.Fatalf("refuseShadowedDataRoot = %v, want ErrNotMounted", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refuseShadowedDataRoot = %v, want nil", err)
			}
		})
	}
}

// TestNetdLogPath pins the netd log path AND that the plist launchd opens the
// file with is rendered from it — the drift ServerLogPath already prevents on
// the server side.
func TestNetdLogPath(t *testing.T) {
	if got, want := NetdLogPath(), filepath.Join(LogDir, "netd.log"); got != want {
		t.Fatalf("NetdLogPath() = %q, want %q", got, want)
	}
	plist := string(NetdPlist(Config{}))
	if !strings.Contains(plist, "<string>"+NetdLogPath()+"</string>") {
		t.Fatalf("the netd plist does not use NetdLogPath():\n%s", plist)
	}
}
