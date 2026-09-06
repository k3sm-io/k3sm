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
	"errors"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
)

// strictFS wraps the netd fake with one extra assertion: reading /etc/fstab at
// all is a failure. It backs the "work-dir outside the data root" case, where
// the containment test must short-circuit before any inspection happens.
type strictFS struct {
	*fakeOwn
	t *testing.T
}

func (s strictFS) ReadFile(path string) ([]byte, error) {
	s.t.Fatalf("refuseShadowedWorkDir read %s for a work-dir outside the data root", path)
	return nil, nil
}

// TestServerRefusesShadowedDataRoot pins the control plane's half of the
// 2026-09-05 fix: it will not create its work-dir inside a data root that is
// declared as a mount point but is not mounted.
func TestServerRefusesShadowedDataRoot(t *testing.T) {
	const root = "/var/lib/k3sm"

	t.Run("a shadowed data root is refused", func(t *testing.T) {
		fsys := &fakeOwn{
			fstab:  "UUID=DEADBEEF " + root + " apfs rw\n",
			stat:   map[string]fakeStat{root: {uid: 0, mode: 0o755}},
			mounts: map[string]string{root: "/"},
		}
		err := refuseShadowedWorkDir(fsys, root+"/server", root)
		if !errors.Is(err, dataroot.ErrNotMounted) {
			t.Fatalf("refuseShadowedWorkDir = %v, want ErrNotMounted", err)
		}
	})

	t.Run("a mounted data root is accepted", func(t *testing.T) {
		fsys := &fakeOwn{
			fstab:  "UUID=DEADBEEF " + root + " apfs rw\n",
			stat:   map[string]fakeStat{root: {uid: testServiceUID, mode: 0o750}},
			mounts: map[string]string{root: root},
		}
		if err := refuseShadowedWorkDir(fsys, root+"/server", root); err != nil {
			t.Fatalf("refuseShadowedWorkDir = %v, want nil", err)
		}
	})

	t.Run("a plain undeclared data root is accepted", func(t *testing.T) {
		fsys := &fakeOwn{stat: map[string]fakeStat{root: {uid: testServiceUID, mode: 0o750}}}
		if err := refuseShadowedWorkDir(fsys, root+"/server", root); err != nil {
			t.Fatalf("refuseShadowedWorkDir = %v, want nil", err)
		}
	})

	t.Run("a work-dir outside the data root is not inspected", func(t *testing.T) {
		fsys := strictFS{fakeOwn: &fakeOwn{stat: map[string]fakeStat{}}, t: t}
		for _, workDir := range []string{"/Users/dev/.k3sm/server", root + "/nested/server", root} {
			if err := refuseShadowedWorkDir(fsys, workDir, root); err != nil {
				t.Fatalf("refuseShadowedWorkDir(%s) = %v, want nil", workDir, err)
			}
		}
	})
}
