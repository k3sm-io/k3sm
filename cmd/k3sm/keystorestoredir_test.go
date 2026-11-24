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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/socket"
)

// passingChecks is the supervisor's start checks over cfg, with the
// sandbox self-check and the server count faked to pass, as on a
// single-server node whose sandbox check works, and the uid pair the
// evaluator compares faked below the login range, which the test user is
// in; the store underneath judges by the test user's uid.
func passingChecks(cfg socket.SupervisorConfig) socket.Preconditions {
	return socket.Preconditions{
		EUID: func() int { return 277 }, ServiceUID: 277,
		IgnoresOwnership: cfg.IgnoresOwnership, EndPass: cfg.EndPass,
		CheckInstall: cfg.CheckInstall, MaintenanceMarked: cfg.MaintenanceMarked,
		StoreDir: cfg.StoreDir, OpenLogs: cfg.OpenLogs,
		SandboxCheck: func() error { return nil },
		ServerCount:  func(context.Context) (int, error) { return 1, nil },
		StartScopes:  cfg.StartScopes,
	}
}

// TestKeystoreServerCreatesStoreDir: on a fresh install, with no store
// directory and no root put, the server's start checks create the store
// directory as a first put would, every check then passes, and the user
// scope serves a login user's list.
func TestKeystoreServerCreatesStoreDir(t *testing.T) {
	f, peer := installedWiringFixture(t, false)
	dir := f.deps.layout(f.deps.workDir).Dir
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the fresh install has a store directory: %v", err)
	}
	cfg, closeAll, err := keystoreSocketConfig(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	if cfg.StoreDir == nil {
		t.Fatal("the server's config runs no store-directory step")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the build created the store directory before the start checks ran: %v", err)
	}
	if reason, detail := passingChecks(cfg).Check(t.Context()); reason != "" {
		t.Fatalf("the start checks on a fresh install: %q %q, want every check to pass", reason, detail)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("the start checks created no store directory: %v", err)
	}
	if st := fi.Sys().(*syscall.Stat_t); !fi.IsDir() || fi.Mode().Perm() != 0o700 || st.Uid != uint32(os.Getuid()) {
		t.Fatalf("the store directory: dir %v mode %04o uid %d; want the service user's 0700 directory", fi.IsDir(), fi.Mode().Perm(), st.Uid)
	}
	// The scope serves: a login user's list is answered, empty. (Its first
	// put needs the master, which only a root put mints.)
	c := dialHandler(t, cfg.Handler, peer)
	var l socket.ListReply
	c.reply(t, c.call(t, map[string]any{"op": socket.OpList}, nil), &l)
	if len(l.Entries) != 0 {
		t.Fatalf("list on a fresh install: %+v, want none", l.Entries)
	}
}

// TestKeystoreStoreDirRefusedNotRepaired: an existing store directory the
// store's open refuses (a wider mode, another owner) keeps the user scope
// off with OffStoreDir and the open's text, naming the repair, on every
// pass, and the directory is left as it was.
func TestKeystoreStoreDirRefusedNotRepaired(t *testing.T) {
	for _, tt := range []struct {
		name string
		mode os.FileMode
		uid  func(me uint32) uint32 // the service uid the store judges by
		want string
	}{
		{"a wider mode", 0o755, func(me uint32) uint32 { return me }, "grants more than 0700"},
		{"another owner", 0o700, func(me uint32) uint32 { return me + 1 }, "owned by uid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := installedWiringFixture(t, false)
			me := uint32(os.Getuid())
			svc := tt.uid(me)
			f.deps.serviceIDs = func() (uint32, uint32, error) { return svc, uint32(os.Getgid()), nil }
			dir := f.deps.layout(f.deps.workDir).Dir
			if err := os.Mkdir(dir, tt.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tt.mode); err != nil {
				t.Fatal(err)
			}
			cfg, closeAll, err := keystoreSocketConfig(f.deps)
			if err != nil {
				t.Fatal(err)
			}
			defer closeAll()
			p := passingChecks(cfg)
			p.CheckInstall = func(context.Context) error { return nil } // another service uid owns no installed log here
			for pass := range 2 {
				reason, detail := p.Check(t.Context())
				if reason != socket.OffStoreDir || !strings.Contains(detail, tt.want) || !strings.Contains(detail, storeDirRepair) {
					t.Fatalf("pass %d: %q %q, want OffStoreDir with the open's %q and the repair", pass, reason, detail, tt.want)
				}
			}
			fi, err := os.Lstat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != tt.mode || fi.Sys().(*syscall.Stat_t).Uid != me {
				t.Fatalf("the refused directory is now mode %04o uid %d; want it left at %04o uid %d", fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Uid, tt.mode, me)
			}
			// Doctor judges it the same, read-only.
			store := keystore.New(func() keystore.Config {
				c := f.deps.layout(f.deps.workDir)
				c.UID, c.GID = svc, uint32(os.Getgid())
				return c
			}())
			if err := doctorStoreDir(store)(t.Context()); err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), storeDirRepair) {
				t.Fatalf("doctor's step = %v, want the same refusal and repair", err)
			}
		})
	}
}

// TestKeystoreWorkerCreatesNoStoreDir: an installed agent builds no
// listener and creates no store directory, even with the work dir there.
func TestKeystoreWorkerCreatesNoStoreDir(t *testing.T) {
	f, _ := installedWiringFixture(t, false)
	f.deps.nodeRole = func() (install.Role, bool) { return install.RoleAgent, true }
	ks, err := newKeystoreSocket(f.deps)
	if ks != nil || err != nil {
		t.Fatalf("an agent built %v, %v; want nothing", ks, err)
	}
	runKeystoreSocket(t.Context(), ks)()
	if _, err := os.Lstat(f.deps.layout(f.deps.workDir).Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a worker created the store directory: %v", err)
	}
}

// TestDoctorStoreDirRow: doctor's user-scope row on a fresh install, before
// the server has started, is off for the store directory and says the
// server creates it at start; once the server's step has created it the
// same checks pass. Doctor's own step creates nothing.
func TestDoctorStoreDirRow(t *testing.T) {
	f, _ := installedWiringFixture(t, false)
	me, myGID := uint32(os.Getuid()), uint32(os.Getgid())
	storeCfg := f.deps.layout(f.deps.workDir)
	storeCfg.UID, storeCfg.GID = me, myGID
	store := keystore.New(storeCfg)
	row := func() checkResult {
		e := healthyDoctorEnv()
		e.keystoreUserScope = userScopeChecks(func(p *socket.Preconditions) { p.StoreDir = doctorStoreDir(store) })
		return checkKeystoreUserScope(e)
	}
	r := row()
	if r.status != statusWarn || !strings.HasPrefix(r.detail, "keystore user scope: off ("+string(socket.OffStoreDir)+")") ||
		!strings.Contains(r.detail, "the server creates the store directory at start") {
		t.Fatalf("before the server's start: %+v, want WARN off for the store directory, saying the server creates it at start", r)
	}
	if r.remedy != "" || strings.Contains(r.detail, "sudo k3sm install") {
		t.Fatalf("before the server's start the row names %q / %q; install does not create the store directory", r.remedy, r.detail)
	}
	if _, err := os.Lstat(storeCfg.Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("doctor's step created the store directory: %v", err)
	}
	if err := serverStoreDir(store)(t.Context()); err != nil {
		t.Fatalf("the server's step: %v", err)
	}
	if r := row(); r.status != statusPass {
		t.Fatalf("after the server's start: %+v, want PASS", r)
	}
	if _, err := os.Lstat(filepath.Join(storeCfg.Dir, ".lock")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("doctor's step took the store lock: %v", err)
	}
}

// TestStoreDirRaceTextIsTransient: the server's store-directory step names
// the "as root, make it ... or remove it" repair only for a persistent
// refusal of an existing directory; a directory it cannot open, as one a
// root put has made and not yet handed over, is worded as the one-pass race
// it is, retried, with no repair.
func TestStoreDirRaceTextIsTransient(t *testing.T) {
	f, _ := installedWiringFixture(t, false)
	storeCfg := f.deps.layout(f.deps.workDir)
	storeCfg.UID, storeCfg.GID = uint32(os.Getuid()), uint32(os.Getgid())
	store := keystore.New(storeCfg)
	if err := os.Mkdir(storeCfg.Dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(storeCfg.Dir, 0o700) })
	err := serverStoreDir(store)(t.Context())
	if err == nil || !strings.Contains(err.Error(), storeDirRaceText) || strings.Contains(err.Error(), storeDirRepair) {
		t.Fatalf("a directory the server cannot open: %v, want %q and no repair", err, storeDirRaceText)
	}
	if !strings.Contains(storeDirRaceText, "a root keys put may be creating it; retried") {
		t.Fatalf("the race text %q does not say it is transient", storeDirRaceText)
	}
	if err := os.Chmod(storeCfg.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	err = serverStoreDir(store)(t.Context())
	if err == nil || !strings.Contains(err.Error(), storeDirRepair) || strings.Contains(err.Error(), storeDirRaceText) {
		t.Fatalf("a wider mode: %v, want the repair and not the race text", err)
	}
}

// TestKeystoreListenerOffWhileMergePending: with a restore staged (the
// floor moved aside as keystore-floor.json.pre-restore in the data root)
// the server's start checks keep the user scope off, naming keys floor
// merge, and create no store directory; once the merge has renamed the
// file every check passes.
func TestKeystoreListenerOffWhileMergePending(t *testing.T) {
	f, _ := installedWiringFixture(t, false)
	aside := filepath.Join(f.dataRoot, "keystore-floor.json.pre-restore")
	if err := os.WriteFile(aside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, closeAll, err := keystoreSocketConfig(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	if reason, detail := passingChecks(cfg).Check(t.Context()); reason == "" || !strings.Contains(detail, "keys floor merge") {
		t.Fatalf("the start checks with a restore staged: %q %q, want off naming keys floor merge", reason, detail)
	}
	if _, err := os.Lstat(f.deps.layout(f.deps.workDir).Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the server made a store directory with a restore staged: %v", err)
	}
	if err := os.Rename(aside, aside+".merged"); err != nil {
		t.Fatal(err)
	}
	if reason, detail := passingChecks(cfg).Check(t.Context()); reason != "" {
		t.Fatalf("the start checks after the merge: %q %q, want every check to pass", reason, detail)
	}
}
