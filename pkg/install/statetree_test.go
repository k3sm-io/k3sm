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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/netdsvc"
)

// indexFrom returns the index of the first call equal to want at or after
// from, or -1.
func indexFrom(calls []string, from int, want string) int {
	for i := max(from, 0); i < len(calls); i++ {
		if calls[i] == want {
			return i
		}
	}
	return -1
}

// mintKey returns a fresh wireguard private key for a fixture.
func mintKey(t *testing.T) string {
	t.Helper()
	priv, _, err := bootstrap.GenerateWireguardKey()
	if err != nil {
		t.Fatalf("mint a key for the fixture: %v", err)
	}
	return priv
}

// seedLegacyKeyTree describes the run dir and its keys dir as an older build
// left them: two real directories owned by the service user.
func seedLegacyKeyTree(f *fakeSystem) {
	f.putOwned(DefaultRunDir, 271, ServiceTreeGID, 0o700, EntryDir)
	f.putOwned(LegacyMeshKeyDir, 0, 0, 0o700, EntryDir)
}

// TestMeshKeyDirLivesOutsideTheServiceUserRunDir is the B397 gate.
//
// The defect: the mesh keys lived in <run dir>/keys, and the run dir is the
// service user's. On macOS the right to unlink or rename an entry is the
// PARENT's write bit, so the unprivileged service user could rename or unlink
// root's 0700 key directory whatever its own mode, and a netd restart mid-join
// did exactly that to the agent's key. The data root itself was chowned to the
// service user too, by the installer and by netd, so moving the keys up one
// level would have fixed nothing.
//
// The fix follows k3s's data-dir layout, translated to k3sm's split privilege:
// the data root is root:wheel 0755, the keys live directly under it root:wheel
// 0700, and only the trees the unprivileged daemons write are the service
// user's — all of it stated once, in the ownership table (OwnershipOf).
func TestMeshKeyDirLivesOutsideTheServiceUserRunDir(t *testing.T) {
	serverHelper := filepath.Join(MeshKeyDir, MeshKeyRefServer)
	serverWork := filepath.Join(DefaultDataRoot, "server", MeshKeyRefServer)
	legacyServer := filepath.Join(LegacyMeshKeyDir, MeshKeyRefServer)
	legacyIdentity := filepath.Join(LegacyMeshKeyDir, netdsvc.NodeIdentityFileName)
	newIdentity := netdsvc.NodeIdentityPath(MeshKeyDir)

	t.Run("a: every component from the state root to the keys is root:wheel", func(t *testing.T) {
		if strings.HasPrefix(MeshKeyDir+"/", DefaultRunDir+"/") {
			t.Fatalf("MeshKeyDir %q is under the service user's run dir %q", MeshKeyDir, DefaultRunDir)
		}
		if got := StateKeys.Path(DefaultDataRoot); got != MeshKeyDir {
			t.Fatalf("the table's key level resolves to %q, want MeshKeyDir %q", got, MeshKeyDir)
		}
		if got := filepath.Dir(netdsvc.NodeIdentityPath(MeshKeyDir)); got != MeshKeyDir {
			t.Errorf("the node identity lives in %q, want it beside the keys in %q", got, MeshKeyDir)
		}
		want := map[string]StateOwnership{
			DefaultDataRoot: {Principal: PrincipalRoot, GID: 0, Mode: 0o755},
			MeshKeyDir:      {Principal: PrincipalRoot, GID: 0, Mode: 0o700},
		}
		// Walk every component from the state root down to MeshKeyDir: each
		// must be a table level, root-owned, at the named mode. A component the
		// table does not name, or names for the service user, fails.
		rel, err := filepath.Rel(DefaultDataRoot, MeshKeyDir)
		if err != nil {
			t.Fatalf("rel: %v", err)
		}
		levels := []StateLevel{StateRoot}
		cur := ""
		for _, part := range strings.Split(rel, "/") {
			cur = filepath.Join(cur, part)
			levels = append(levels, StateLevel(cur))
		}
		for _, level := range levels {
			path := level.Path(DefaultDataRoot)
			own, ok := OwnershipOf(level)
			if !ok {
				t.Fatalf("%s is on the path to the keys but the ownership table does not name it", path)
			}
			if own.Principal != PrincipalRoot || own.UID(271) != 0 {
				t.Errorf("%s is owned by the service user; nothing on the path to the keys may be", path)
			}
			if w := want[path]; own != w {
				t.Errorf("%s ownership = %+v, want %+v", path, own, w)
			}
		}
		// And the live install applies exactly those two rows.
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		wantCall(t, f, fmt.Sprintf("EnsureOwnedDir:%s:0:0:%#o", DefaultDataRoot, StateRootMode))
		wantCall(t, f, fmt.Sprintf("EnsureMeshKeyDir:%s:%#o", MeshKeyDir, MeshKeyDirMode))
		wantCall(t, f, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", serverHelper, MeshKeyFileMode))
	})

	t.Run("b: a fresh install hands the subtrees over explicitly and never the root", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		rootCall := fmt.Sprintf("EnsureOwnedDir:%s:0:0:%#o", DefaultDataRoot, StateRootMode)
		rootAt := idx(f.calls, rootCall)
		if rootAt < 0 {
			t.Fatalf("the data root was never ensured root:wheel %#o: %v", StateRootMode, f.calls)
		}
		for _, level := range ServiceLevels() {
			if level == StateLevel("server") || level == StateLevel(agentWorkSubdir) {
				continue // handed over by the steps that write into them
			}
			own, _ := OwnershipOf(level)
			call := fmt.Sprintf("EnsureOwnedDir:%s:271:%d:%#o", level.Path(DefaultDataRoot), own.GID, own.Mode)
			at := idx(f.calls, call)
			if at < 0 {
				t.Errorf("the service-user tree %s was not handed over explicitly (%s)", level.Path(DefaultDataRoot), call)
				continue
			}
			if at < rootAt {
				t.Errorf("%s was handed over before the root was root's", level.Path(DefaultDataRoot))
			}
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "EnsureOwnedDir:"+DefaultDataRoot+":271:") ||
				strings.HasPrefix(c, "Chown:"+DefaultDataRoot+":271:") ||
				strings.HasPrefix(c, "WriteServiceUserFile:"+MeshKeyDir+"/") {
				t.Errorf("the install handed the data root or the key dir to the service user: %s", c)
			}
		}
	})

	t.Run("c: an upgrade copies, verifies, THEN removes the legacy keys", func(t *testing.T) {
		shrinkRestartBudgets(t)
		key := mintKey(t)
		f := &fakeSystem{}
		seedLegacyKeyTree(f)
		f.putFile(serverWork, []byte(key))
		f.putFile(legacyServer, []byte(key))
		f.putFile(legacyIdentity, []byte("10.42.3.0/24\n"))
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := string(f.files[serverHelper]); got != key {
			t.Errorf("new key = %q, want the legacy bytes %q", got, key)
		}
		if got := string(f.files[newIdentity]); got != "10.42.3.0/24\n" {
			t.Errorf("node identity was not moved: %q", got)
		}
		for _, leaf := range []string{MeshKeyRefServer, netdsvc.NodeIdentityFileName} {
			dest := filepath.Join(MeshKeyDir, leaf)
			write := idx(f.calls, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", dest, MeshKeyFileMode))
			verify := indexFrom(f.calls, write+1, "ReadRegularFile:"+dest)
			remove := idx(f.calls, "RemoveEntry:h1:"+leaf)
			if write < 0 || verify < 0 || remove < 0 || !(write < verify && verify < remove) {
				t.Errorf("%s: want copy (%d) < verify (%d) < legacy removal (%d): %v", leaf, write, verify, remove, f.calls)
			}
			if _, ok := f.files[filepath.Join(LegacyMeshKeyDir, leaf)]; ok {
				t.Errorf("the legacy %s is still there", leaf)
			}
		}
		dirRemove := idx(f.calls, "RemoveEntry:"+DefaultRunDir+":keys")
		if dirRemove < idx(f.calls, "RemoveEntry:h1:"+MeshKeyRefServer) {
			t.Errorf("the legacy dir must be removed after its leaves: %v", f.calls)
		}
		// The move happens before the key is read for provisioning, so the
		// node keeps its identity rather than minting a new one.
		if !bytes.Equal(f.files[serverWork], []byte(key)) {
			t.Errorf("the work-dir key changed across the upgrade")
		}
	})

	t.Run("d: an existing new key wins; an identical legacy leaf is removed and nothing copied", func(t *testing.T) {
		// A legacy copy that DIFFERS from the new one is refused instead: d2.
		shrinkRestartBudgets(t)
		current := mintKey(t)
		f := &fakeSystem{}
		seedLegacyKeyTree(f)
		f.putFile(serverWork, []byte(current))
		f.putFile(serverHelper, []byte(current))
		f.putFile(legacyServer, []byte(current))
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := string(f.files[serverHelper]); got != current {
			t.Errorf("the new key was overwritten by the legacy copy: %q", got)
		}
		if calls := meshKeyCalls(f, "WriteRootOnlyFile:"+MeshKeyDir+"/"); len(calls) != 0 {
			t.Errorf("nothing should have been copied: %v", calls)
		}
		wantCall(t, f, "RemoveEntry:h1:"+MeshKeyRefServer)
		if _, ok := f.files[legacyServer]; ok {
			t.Error("the identical legacy key is still there")
		}
	})

	t.Run("e: a symlink at the legacy path is refused", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			seed func(f *fakeSystem)
		}{
			{"the legacy keys dir", func(f *fakeSystem) {
				f.putOwned(DefaultRunDir, 271, ServiceTreeGID, 0o700, EntryDir)
				f.putOwned(LegacyMeshKeyDir, 271, ServiceTreeGID, 0o777, EntrySymlink)
			}},
			{"its parent, the run dir", func(f *fakeSystem) {
				f.putOwned(DefaultRunDir, 271, ServiceTreeGID, 0o777, EntrySymlink)
			}},
			{"a legacy key file", func(f *fakeSystem) {
				seedLegacyKeyTree(f)
				f.putSymlink(legacyServer)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				shrinkRestartBudgets(t)
				f := &fakeSystem{}
				tc.seed(f)
				f.putFile(legacyServer, []byte(mintKey(t)))
				err := Install(context.Background(), f, serverCfg())
				if err == nil {
					t.Fatal("Install moved keys through a symlink the service user could have planted")
				}
				if !strings.Contains(err.Error(), "legacy") && !strings.Contains(err.Error(), "symlink") {
					t.Errorf("the refusal names neither the legacy path nor the symlink: %v", err)
				}
				for _, c := range f.calls {
					if strings.HasPrefix(c, "RemoveEntry:") || strings.HasPrefix(c, "WriteRootOnlyFile:") {
						t.Errorf("the refusal still touched a key: %s", c)
					}
				}
			})
		}
	})

	t.Run("f: the netd plist renders the new --mesh-key-dir", func(t *testing.T) {
		plist := string(NetdPlist(serverCfg()))
		want := "<string>--mesh-key-dir</string>\n    <string>" + MeshKeyDir + "</string>"
		if !strings.Contains(plist, want) {
			t.Errorf("netd plist does not pass --mesh-key-dir %s:\n%s", MeshKeyDir, plist)
		}
		if strings.Contains(plist, LegacyMeshKeyDir) {
			t.Errorf("netd plist still names the legacy key dir %s", LegacyMeshKeyDir)
		}
	})

	t.Run("g: uninstall preserves the key dir and its keys", func(t *testing.T) {
		m := artifactManifest(serverCfg())
		var sawDir bool
		for _, a := range m {
			if a.path == MeshKeyDir {
				sawDir = true
				if a.disp != dispPreserve {
					t.Errorf("MeshKeyDir disposition = %v, want dispPreserve", a.disp)
				}
			}
		}
		if !sawDir {
			t.Error("the manifest does not record MeshKeyDir at all")
		}
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		for _, c := range f.calls {
			if c == "RemoveAll:"+MeshKeyDir || c == "RemoveAll:"+serverHelper ||
				c == "RemoveAll:"+filepath.Join(MeshKeyDir, MeshKeyRefAgent) || c == "RemoveAll:"+DefaultDataRoot {
				t.Errorf("uninstall removed preserved key state: %s", c)
			}
		}
		// The node identity is role state and still goes (B396).
		wantCall(t, f, "RemoveAll:"+newIdentity)
	})

	t.Run("h: the service user's home-Library and Go caches do not need a writable root", func(t *testing.T) {
		// The data root is _k3sm's home. macOS seeds <home>/Library for it, and
		// the boot-time kine build would otherwise derive its caches from HOME
		// (<home>/go/pkg/mod, <home>/Library/Caches/go-build) — top-level
		// directories the service user cannot create under a root-owned root.
		own, ok := OwnershipOf(StateLevel("Library"))
		if !ok {
			t.Fatal("the ownership table has no Library row")
		}
		if own.Principal != PrincipalServiceUser || own.GID != ServiceTreeGID || own.Mode != 0o700 {
			t.Errorf("Library row = %+v, want the service user, group staff, 0700", own)
		}
		for _, tc := range []struct {
			name    string
			plist   []byte
			workDir string
		}{
			{"server", ServerPlist(serverCfg()), filepath.Join(DefaultDataRoot, "server")},
			{"agent", AgentPlist(Config{Role: RoleAgent, JoinServer: "cp.example", BinarySource: "/tmp/k3sm", TargetUser: "alice"}), filepath.Join(DefaultDataRoot, agentWorkSubdir)},
		} {
			for key, want := range map[string]string{
				"GOMODCACHE": filepath.Join(tc.workDir, "go", "mod"),
				"GOCACHE":    filepath.Join(tc.workDir, "go", "build"),
			} {
				entry := "<key>" + key + "</key>\n  <string>" + want + "</string>"
				if !strings.Contains(string(tc.plist), entry) {
					t.Errorf("%s plist does not pin %s=%s:\n%s", tc.name, key, want, tc.plist)
				}
			}
		}
	})

	t.Run("i: the move reads and removes through ONE held descriptor", func(t *testing.T) {
		t.Run("the path swapped after the open is not followed", func(t *testing.T) {
			shrinkRestartBudgets(t)
			key := mintKey(t)
			f := &fakeSystem{}
			seedLegacyKeyTree(f)
			f.putFile(serverWork, []byte(key))
			f.putFile(legacyServer, []byte(key))
			f.putFile(legacyIdentity, []byte("10.42.3.0/24\n"))
			// The service user renames the dir away and plants a symlink at the
			// path the moment after the install opened it.
			f.afterOpenDir = func(dir string) {
				if dir == LegacyMeshKeyDir {
					f.putOwned(LegacyMeshKeyDir, 271, ServiceTreeGID, 0o777, EntrySymlink)
				}
			}
			if err := Install(context.Background(), f, serverCfg()); err != nil {
				t.Fatalf("Install: %v", err)
			}
			if n := len(meshKeyCalls(f, "OpenDirNoFollow:"+LegacyMeshKeyDir)); n != 1 {
				t.Errorf("the legacy dir was opened %d times, want once", n)
			}
			for _, leaf := range []string{MeshKeyRefServer, netdsvc.NodeIdentityFileName} {
				wantCall(t, f, "ReadEntry:h1:"+leaf)
				wantCall(t, f, "RemoveEntry:h1:"+leaf)
			}
			for _, c := range f.calls {
				if strings.HasPrefix(c, "ReadRegularFile:"+LegacyMeshKeyDir+"/") || strings.HasPrefix(c, "RemoveEntry:"+LegacyMeshKeyDir+":") {
					t.Errorf("a legacy leaf was reached by PATH, which the swap could redirect: %s", c)
				}
			}
			if got := string(f.files[serverHelper]); got != key {
				t.Errorf("the key read through the held descriptor was not moved: %q", got)
			}
		})
		for _, tc := range []struct {
			name string
			race func(f *fakeSystem)
			// kept is the legacy leaf the refusal must leave in place.
			kept string
		}{
			{"a leaf swapped for a symlink after the open is refused", func(f *fakeSystem) {
				f.afterOpenDir = func(string) { f.putSymlink(legacyServer) }
			}, MeshKeyRefServer},
			{"a node identity that is not a CIDR is refused", func(f *fakeSystem) {
				f.putFile(legacyIdentity, []byte("not-a-cidr\n"))
			}, netdsvc.NodeIdentityFileName},
		} {
			t.Run(tc.name, func(t *testing.T) {
				shrinkRestartBudgets(t)
				f := &fakeSystem{}
				seedLegacyKeyTree(f)
				f.putFile(legacyServer, []byte(mintKey(t)))
				tc.race(f)
				if err := Install(context.Background(), f, serverCfg()); err == nil {
					t.Fatal("Install promoted a legacy file it should have refused")
				}
				for _, c := range f.calls {
					if c == "RemoveEntry:h1:"+tc.kept || c == "RemoveEntry:"+DefaultRunDir+":keys" {
						t.Errorf("the refusal still removed the legacy copy: %s", c)
					}
					if c == fmt.Sprintf("WriteRootOnlyFile:%s:%#o", newIdentity, MeshKeyFileMode) {
						t.Errorf("an unvalidated node identity was promoted: %s", c)
					}
				}
			})
		}
	})

	t.Run("j: an upgrade stops the running daemons before the first ownership apply", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		firstApply := idx(f.calls, fmt.Sprintf("EnsureOwnedDir:%s:0:0:%#o", DefaultDataRoot, StateRootMode))
		for _, c := range f.calls[:firstApply] {
			if strings.HasPrefix(c, "Bootout:") {
				t.Errorf("a first install booted a daemon out before re-owning the tree: %s", c)
			}
		}
		// The daemons the first install bootstrapped are loaded now: this is the
		// upgrade the stop exists for.
		f.calls = nil
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("upgrade Install: %v", err)
		}
		server, netd := idx(f.calls, "Bootout:"+ServerLabel), idx(f.calls, "Bootout:"+NetdLabel)
		user := idx(f.calls, "EnsureServiceUser:_k3sm:"+DefaultDataRoot)
		apply := idx(f.calls, fmt.Sprintf("EnsureOwnedDir:%s:0:0:%#o", DefaultDataRoot, StateRootMode))
		if server < 0 || netd < 0 || !(server < netd && netd < user && user < apply) {
			t.Errorf("want Bootout server (%d) < Bootout netd (%d) < EnsureServiceUser (%d) < the root apply (%d): %v", server, netd, user, apply, f.calls)
		}
		// And step 4 still brings them back.
		if idx(f.calls, "Bootstrap:"+NetdLabel) < apply || idx(f.calls, "Bootstrap:"+ServerLabel) < apply {
			t.Errorf("the upgrade did not bootstrap both daemons after the re-own: %v", f.calls)
		}
	})

	t.Run("k: the run dir's owner and mode come only from the table", func(t *testing.T) {
		row, _ := OwnershipOf(StateRun)
		if row.Principal != PrincipalServiceUser || row.GID != ServiceTreeGID || row.Mode != 0o700 {
			t.Errorf("run row = %+v, want the service user, group staff, 0700", row)
		}
		src, err := os.ReadFile("install_darwin.go")
		if err != nil {
			t.Fatalf("read install_darwin.go: %v", err)
		}
		body := string(src)
		start := strings.Index(body, "func ensureServiceOwnedDir(")
		if start < 0 {
			t.Fatal("ensureServiceOwnedDir is gone; EnsureRunDir's applied ownership is unpinned")
		}
		end := strings.Index(body[start:], "\n}\n")
		fn := body[start : start+end]
		if !strings.Contains(fn, "OwnershipOf(StateRun)") {
			t.Errorf("ensureServiceOwnedDir does not read OwnershipOf(StateRun):\n%s", fn)
		}
		for _, literal := range []string{"0o700", "RunDirMode", "ServiceTreeGID", ", 20)"} {
			if strings.Contains(fn, literal) {
				t.Errorf("ensureServiceOwnedDir restates the run dir's ownership (%q) instead of reading the table:\n%s", literal, fn)
			}
		}
	})

	t.Run("l: an unknown file in the legacy dir is warned about, kept, and never fails the install", func(t *testing.T) {
		shrinkRestartBudgets(t)
		server, node := mintKey(t), mintKey(t)
		unknown := filepath.Join(LegacyMeshKeyDir, "node-pod-cidr.sep24-stale")
		f := &fakeSystem{}
		seedLegacyKeyTree(f)
		f.putFile(serverWork, []byte(server))
		f.putFile(legacyServer, []byte(server))
		f.putFile(filepath.Join(LegacyMeshKeyDir, MeshKeyRefAgent), []byte(node))
		f.putFile(legacyIdentity, []byte("10.42.3.0/24\n"))
		f.putFile(unknown, []byte("10.42.9.0/24\n"))
		var logs bytes.Buffer
		cfg := serverCfg()
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install failed over an unknown file in the legacy dir: %v", err)
		}
		for leaf, want := range map[string]string{MeshKeyRefServer: server, MeshKeyRefAgent: node, netdsvc.NodeIdentityFileName: "10.42.3.0/24\n"} {
			if got := string(f.files[filepath.Join(MeshKeyDir, leaf)]); got != want {
				t.Errorf("%s was not moved: %q", leaf, got)
			}
			if _, ok := f.files[filepath.Join(LegacyMeshKeyDir, leaf)]; ok {
				t.Errorf("the legacy %s is still there", leaf)
			}
		}
		if _, ok := f.files[unknown]; !ok {
			t.Error("the unknown file was removed; it is not k3sm's to delete")
		}
		var warned bool
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "node-pod-cidr.sep24-stale") && strings.Contains(line, LegacyMeshKeyDir) {
				warned = true
			}
		}
		if !warned {
			t.Errorf("no WARN names the unknown file and the legacy dir:\n%s", logs.String())
		}
	})

	t.Run("m: a run with the keys already moved and only an unknown file left is silent and succeeds", func(t *testing.T) {
		// The state (l) leaves behind, and the lab's second run: every known
		// leaf is at MeshKeyDir, the legacy dir holds a hand-left file only.
		shrinkRestartBudgets(t)
		key := mintKey(t)
		f := &fakeSystem{}
		seedLegacyKeyTree(f)
		f.putFile(serverWork, []byte(key))
		f.putFile(serverHelper, []byte(key))
		f.putFile(newIdentity, []byte("10.42.3.0/24\n"))
		f.putFile(filepath.Join(LegacyMeshKeyDir, "node-pod-cidr.sep24-stale"), []byte("10.42.9.0/24\n"))
		var logs bytes.Buffer
		cfg := serverCfg()
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install failed with nothing left to migrate: %v", err)
		}
		if strings.Contains(logs.String(), LegacyMeshKeyDir) {
			t.Errorf("a run with nothing to migrate logged about the legacy dir at INFO or above:\n%s", logs.String())
		}
	})

	t.Run("d2: a leaf in BOTH places is dropped when identical and refused when not", func(t *testing.T) {
		shrinkRestartBudgets(t)
		current, other := mintKey(t), mintKey(t)
		same := &fakeSystem{}
		seedLegacyKeyTree(same)
		same.putFile(serverWork, []byte(current))
		same.putFile(serverHelper, []byte(current))
		same.putFile(legacyServer, []byte(current))
		if err := Install(context.Background(), same, serverCfg()); err != nil {
			t.Fatalf("an identical legacy copy failed the install: %v", err)
		}
		if _, ok := same.files[legacyServer]; ok {
			t.Error("the identical legacy copy was kept")
		}
		differ := &fakeSystem{}
		seedLegacyKeyTree(differ)
		differ.putFile(serverWork, []byte(current))
		differ.putFile(serverHelper, []byte(current))
		differ.putFile(legacyServer, []byte(other))
		err := Install(context.Background(), differ, serverCfg())
		if err == nil || !strings.Contains(err.Error(), legacyServer) || !strings.Contains(err.Error(), serverHelper) {
			t.Fatalf("a differing legacy copy must be refused naming both paths, got %v", err)
		}
		if got := string(differ.files[serverHelper]); got != current {
			t.Errorf("the root-owned copy was overwritten: %q", got)
		}
		if _, ok := differ.files[legacyServer]; !ok {
			t.Error("the differing legacy copy was deleted; the operator must decide")
		}
	})

}
