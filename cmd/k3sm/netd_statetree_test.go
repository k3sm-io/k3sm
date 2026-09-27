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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestNetdAlignmentUsesTheOwnershipTable is netd's half of the B397 gate.
//
// Before the root-owned layout, netd found the data root and chowned IT to the
// service user, so moving the mesh keys up a level would have been undone at the
// next netd start: whoever owns the root can rename or unlink the keys dir.
// netd now applies install.OwnershipOf, the same table the installer uses: the
// root is root:wheel 0755 (and a service-user-owned root an older build left is
// healed here), each service-user tree is handed to the service user, the key
// directory is never touched, and a key still at the legacy run-dir location is
// warned about with the remedy rather than moved.
func TestNetdAlignmentUsesTheOwnershipTable(t *testing.T) {
	base := tempRoot(t)
	root := filepath.Join(base, "k3sm")
	runDir := filepath.Join(root, "run")
	keysDir := install.StateKeys.Path(root)
	legacyKey := install.LegacyMeshKeyFiles(root)[1]
	socket := filepath.Join(runDir, "netd.sock")
	own := &fakeOwn{stat: map[string]fakeStat{
		// The layout every build before this one left behind: the root is the
		// service user's, and a key sits in the run dir.
		root:                    {uid: testServiceUID, gid: testServiceGID, mode: 0o750},
		runDir:                  {uid: testServiceUID, gid: testServiceGID, mode: 0o700},
		filepath.Dir(legacyKey): {uid: 0, gid: 0, mode: 0o700},
		legacyKey:               {uid: 0, gid: 0, mode: 0o600, kind: fakeFile},
		keysDir:                 {uid: 0, gid: 0, mode: 0o700},
		filepath.Join(keysDir, install.MeshKeyRefAgent): {uid: 0, gid: 0, mode: 0o600, kind: fakeFile},
		// A service-user tree someone replaced with a symlink: never chowned.
		install.StateLevel("pods").Path(root): {uid: testServiceUID, mode: 0o777, kind: fakeLink},
		// A manifest directory the service user owns: every pod could write
		// into it, so it is healed back to root.
		install.StateManifests.Path(root): {uid: testServiceUID, gid: testServiceGID, mode: 0o775},
	}}
	logs := captureLogs(t)

	l, err := listenNetd(socket, root, testServiceGID, own)
	if err != nil {
		t.Fatalf("listenNetd: %v", err)
	}
	defer l.Close()

	// The root is healed to the table's row, and FIRST.
	rootChown := fmt.Sprintf("chown %s 0:%d", root, install.StateRootGID)
	rootChmod := fmt.Sprintf("chmod %s %04o", root, install.StateRootMode.Perm())
	if !own.has(rootChown) || !own.has(rootChmod) {
		t.Fatalf("the service-user-owned root was not healed to root:wheel %04o: %v", install.StateRootMode, own.calls)
	}
	rootAt := -1
	for i, c := range own.calls {
		if c == rootChown {
			rootAt = i
			break
		}
	}
	for i, c := range own.calls {
		if strings.HasPrefix(c, "chown ") && i < rootAt {
			t.Errorf("%q ran before the root was root's", c)
		}
		if strings.HasPrefix(c, fmt.Sprintf("chown %s %d:", root, testServiceUID)) {
			t.Errorf("the root was handed to the service user: %s", c)
		}
	}
	if !strings.Contains(logs.String(), "aligned data-root ownership") {
		t.Errorf("the root heal was not warned about: %s", logs.String())
	}

	// Every service-user tree is the service user's, at the table's mode.
	for _, level := range install.ServiceLevels() {
		path := level.Path(root)
		want, _ := install.OwnershipOf(level)
		if level == "pods" {
			if got := own.touching(path); len(got) != 0 {
				t.Errorf("netd chowned through a symlinked tree: %v", got)
			}
			continue
		}
		st, ok := own.stat[path]
		if !ok {
			t.Errorf("%s was not created", path)
			continue
		}
		if int(st.uid) != want.UID(testServiceUID) || int(st.gid) != want.GID || st.mode.Perm() != want.Mode {
			t.Errorf("%s = %d:%d %04o, want %d:%d %04o", path, st.uid, st.gid, st.mode.Perm(),
				want.UID(testServiceUID), want.GID, want.Mode)
		}
	}

	// The root-owned trees below the root are root's, at the table's mode.
	for _, level := range install.RootTreeLevels() {
		path := level.Path(root)
		want, _ := install.OwnershipOf(level)
		st := own.stat[path]
		if int(st.uid) != want.UID(testServiceUID) || int(st.gid) != want.GID || st.mode.Perm() != want.Mode {
			t.Errorf("%s = %d:%d %04o, want %d:%d %04o", path, st.uid, st.gid, st.mode.Perm(),
				want.UID(testServiceUID), want.GID, want.Mode)
		}
	}
	if got := install.RootTreeLevels(); len(got) != 1 || got[0] != install.StateManifests {
		t.Errorf("RootTreeLevels() = %v, want exactly [%s] (never the root, never the keys)", got, install.StateManifests)
	}

	// The key dir and everything in it are untouched.
	for _, c := range own.calls {
		fields := strings.Fields(c)
		if len(fields) > 1 && (fields[1] == keysDir || strings.HasPrefix(fields[1], keysDir+"/")) {
			t.Errorf("netd touched the key dir: %s", c)
		}
		if len(fields) > 1 && strings.HasPrefix(fields[1], filepath.Dir(legacyKey)) {
			t.Errorf("netd touched the legacy key location (moving it is the installer's): %s", c)
		}
	}

	// The legacy key is warned about, naming the remedy.
	out := logs.String()
	if !strings.Contains(out, "sudo k3sm install") || !strings.Contains(out, legacyKey) {
		t.Errorf("no WARN naming `sudo k3sm install` for the legacy key %s: %s", legacyKey, out)
	}
}

// TestNetdWarnsOnlyOnKnownLegacyLeaves is the netd half of (n): a legacy key
// dir holding nothing k3sm knows (a hand-left file) is not warned about, while
// any of the three known leaves — the two keys and the node identity — is.
func TestNetdWarnsOnlyOnKnownLegacyLeaves(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf string
		warn bool
	}{
		{"only an unknown file", "node-pod-cidr.sep24-stale", false},
		{"the node identity", "node-pod-cidr", true},
		{"a key", install.MeshKeyRefAgent, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tempRoot(t)
			root := filepath.Join(base, "k3sm")
			runDir := filepath.Join(root, "run")
			legacyDir := filepath.Join(runDir, "keys")
			own := &fakeOwn{stat: map[string]fakeStat{
				root:                              {uid: 0, gid: 0, mode: 0o755},
				runDir:                            {uid: testServiceUID, gid: testServiceGID, mode: 0o700},
				legacyDir:                         {uid: 0, gid: 0, mode: 0o700},
				filepath.Join(legacyDir, tc.leaf): {uid: 0, gid: 0, mode: 0o600, kind: fakeFile},
			}}
			logs := captureLogs(t)
			l, err := listenNetd(filepath.Join(runDir, "netd.sock"), root, testServiceGID, own)
			if err != nil {
				t.Fatalf("listenNetd: %v", err)
			}
			defer l.Close()
			if got := strings.Contains(logs.String(), "legacy run-dir location"); got != tc.warn {
				t.Errorf("warned = %v, want %v:\n%s", got, tc.warn, logs.String())
			}
		})
	}
}
