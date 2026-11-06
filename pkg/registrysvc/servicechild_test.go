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

package registrysvc

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// childTestService is a service whose executable is fixed.
func childTestService(t *testing.T, exe string) *Service {
	t.Helper()
	s, err := New(Config{
		WorkDir:    t.TempDir(),
		Port:       6450,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Executable: func() (string, error) { return exe, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestChildCommand pins the spawn's shape: the exact argv, an empty environment
// rather than an inherited one (nil is inherit), its own process group, and no
// descriptor beyond stdio.
func TestChildCommand(t *testing.T) {
	s := childTestService(t, "/Library/k3sm/k3sm")
	cmd, err := s.childCommand()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/Library/k3sm/k3sm", "registry", "serve", "--config", filepath.Join(s.cfg.WorkDir, "registry-state", "serve.json")}
	if cmd.Path != want[0] || !slices.Equal(cmd.Args, want) {
		t.Errorf("command %s %q, want %q", cmd.Path, cmd.Args, want)
	}
	if cmd.Env == nil || len(cmd.Env) != 0 {
		t.Errorf("Env = %#v, want empty and not nil", cmd.Env)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Error("the child is not its own process group")
	}
	if len(cmd.ExtraFiles) != 0 {
		t.Errorf("ExtraFiles = %v, want none", cmd.ExtraFiles)
	}
	if cmd.Stdin != nil {
		t.Errorf("Stdin = %v, want /dev/null", cmd.Stdin)
	}
}

// TestSpawnRefusesAMovedExecutable: the spawn refuses a binary that no longer
// resolves to the path recorded at start, before it creates anything.
func TestSpawnRefusesAMovedExecutable(t *testing.T) {
	t.Run("moved", func(t *testing.T) {
		s := childTestService(t, "/Library/k3sm/k3sm")
		s.cfg.Executable = func() (string, error) { return "/tmp/elsewhere/k3sm", nil }
		if _, err := s.spawn(); !errors.Is(err, ErrExecutableMoved) {
			t.Fatalf("spawn = %v, want ErrExecutableMoved", err)
		}
		if _, err := os.Stat(LogPath(s.cfg.WorkDir)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the refused spawn created the log: %v", err)
		}
	})
	t.Run("unresolved at start", func(t *testing.T) {
		boom := errors.New("no path")
		s, err := New(Config{WorkDir: t.TempDir(), Port: 6450, Executable: func() (string, error) { return "", boom }})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.spawn(); !errors.Is(err, boom) {
			t.Fatalf("spawn = %v, want the resolve error", err)
		}
	})
}

// TestStartRefusesARootDaemon: a server running as root has no registry, says so
// in the record, and writes no credential.
func TestStartRefusesARootDaemon(t *testing.T) {
	s := childTestService(t, "/Library/k3sm/k3sm")
	s.geteuid = func() int { return 0 }
	begin := time.Now()
	if err := s.Start(t.Context()); !errors.Is(err, ErrServeAsRoot) {
		t.Fatalf("Start = %v, want ErrServeAsRoot", err)
	}
	if d := time.Since(begin); d > retryDelay {
		t.Errorf("Start took %s: a root daemon is not retried", d)
	}
	b, err := os.ReadFile(StatePath(s.cfg.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseState(b)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateDisabled || !strings.Contains(st.Reason, "root") {
		t.Errorf("record %+v, want disabled with the reason", st)
	}
	if _, err := os.Stat(ServeConfigPath(s.cfg.WorkDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused start provisioned: %v", err)
	}
}

// TestProvisionWritesTheChildsConfig: the serve config carries the listener, the
// data volume and this process's credential, and the child accepts it. No zot
// config is rendered.
func TestProvisionWritesTheChildsConfig(t *testing.T) {
	s, err := New(Config{WorkDir: t.TempDir(), Port: 6450, DataVolume: "/var/lib/k3sm"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.provision(); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadServeConfig(ServeConfigPath(s.cfg.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.validateForServing(); err != nil {
		t.Errorf("the child would refuse it: %v", err)
	}
	if cfg.Listen != s.Addr() || cfg.DataVolume != "/var/lib/k3sm" || cfg.UID != os.Geteuid() || cfg.GID != os.Getegid() {
		t.Errorf("config %+v", cfg)
	}
	if err := applyServeCredential(cfg, osIdentity()); err != nil {
		t.Errorf("the child would refuse the credential: %v", err)
	}
	if _, err := os.Stat(ConfigPath(s.cfg.WorkDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a zot config was rendered: %v", err)
	}
}

// TestRecordKeepsTheServersFields: the daemon's transitions keep what the server
// process reported.
func TestRecordKeepsTheServersFields(t *testing.T) {
	s := childTestService(t, "/Library/k3sm/k3sm")
	swept := time.Date(2026, 11, 5, 1, 2, 3, 0, time.UTC)
	if err := WriteState(s.cfg.WorkDir, State{State: StateServing, GC: &GCStatus{LastSweep: swept, Blobs: 3}, UploadSessions: 2}); err != nil {
		t.Fatal(err)
	}
	s.record(StateStopped, "", 0)
	b, err := os.ReadFile(StatePath(s.cfg.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseState(b)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateStopped || st.GC == nil || st.GC.Blobs != 3 || !st.GC.LastSweep.Equal(swept) || st.UploadSessions != 2 {
		t.Errorf("record %+v", st)
	}
}

// TestIsOrphanedChild pins the reclaim's match, row by row: this argv and the
// legacy zot argv of this work dir, this uid, ppid 1, and nothing else.
func TestIsOrphanedChild(t *testing.T) {
	s := childTestService(t, "/Library/k3sm/k3sm")
	uid := os.Geteuid()
	child := s.childArgv()
	legacy := []string{ZotPath(s.cfg.BinDir), "serve", ConfigPath(s.cfg.WorkDir)}
	otherConfig := slices.Clone(child)
	otherConfig[4] = "/elsewhere/registry-state/serve.json"
	otherExe := slices.Clone(child)
	otherExe[0] = "/tmp/k3sm"
	cases := []struct {
		name string
		p    procEntry
		want bool
	}{
		{"this child orphaned", procEntry{ppid: 1, uid: uid, argv: child}, true},
		{"the legacy zot orphaned", procEntry{ppid: 1, uid: uid, argv: legacy}, true},
		{"this child with a live parent", procEntry{ppid: 77, uid: uid, argv: child}, false},
		{"another uid", procEntry{ppid: 1, uid: uid + 1, argv: child}, false},
		{"another work dir's config", procEntry{ppid: 1, uid: uid, argv: otherConfig}, false},
		{"another binary", procEntry{ppid: 1, uid: uid, argv: otherExe}, false},
		{"an extra argument", procEntry{ppid: 1, uid: uid, argv: append(slices.Clone(child), "x")}, false},
		{"another k3sm verb", procEntry{ppid: 1, uid: uid, argv: []string{child[0], "server"}}, false},
		{"the legacy zot with another config", procEntry{ppid: 1, uid: uid, argv: []string{legacy[0], "serve", "/x/config.json"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.isOrphanedChild(tc.p); got != tc.want {
				t.Errorf("isOrphanedChild = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReclaimRechecksBeforeEachSignal: a process that stops matching is not
// signalled, before the SIGTERM or before the SIGKILL.
func TestReclaimRechecksBeforeEachSignal(t *testing.T) {
	start := func(t *testing.T) *exec.Cmd {
		t.Helper()
		// A shell that ignores SIGTERM, so only a SIGKILL would end it.
		cmd := exec.Command("/bin/sh", "-c", `trap "" TERM; while :; do sleep 1; done`)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		// Give the shell time to install the trap.
		time.Sleep(200 * time.Millisecond)
		return cmd
	}
	alive := func(cmd *exec.Cmd) bool { return lookupAlive(cmd.Process.Pid) }

	t.Run("reused before the SIGTERM", func(t *testing.T) {
		s := childTestService(t, "/Library/k3sm/k3sm")
		cmd := start(t)
		var reads int
		s.lookupProc = func(pid int) (procEntry, bool) {
			reads++
			return procEntry{pid: pid, ppid: 1, pgid: pid, uid: os.Geteuid(), argv: []string{"/bin/other"}}, true
		}
		if err := s.reclaim(t.Context(), procEntry{pid: cmd.Process.Pid}); err != nil {
			t.Fatal(err)
		}
		if reads != 1 || !alive(cmd) {
			t.Errorf("reads %d, alive %v; want one read and the process untouched", reads, alive(cmd))
		}
	})
	t.Run("reused before the SIGKILL", func(t *testing.T) {
		s := childTestService(t, "/Library/k3sm/k3sm")
		cmd := start(t)
		var reads int
		s.lookupProc = func(pid int) (procEntry, bool) {
			reads++
			argv := s.childArgv()
			if reads > 1 {
				argv = []string{"/bin/other"}
			}
			return procEntry{pid: pid, ppid: 1, pgid: 0, uid: os.Geteuid(), argv: argv}, true
		}
		if err := s.reclaim(t.Context(), procEntry{pid: cmd.Process.Pid}); err != nil {
			t.Fatal(err)
		}
		if reads != 2 || !alive(cmd) {
			t.Errorf("reads %d, alive %v; want two reads and no SIGKILL", reads, alive(cmd))
		}
	})
	t.Run("gone before the SIGTERM", func(t *testing.T) {
		s := childTestService(t, "/Library/k3sm/k3sm")
		s.lookupProc = func(int) (procEntry, bool) { return procEntry{}, false }
		if err := s.reclaim(t.Context(), procEntry{pid: 1}); err != nil {
			t.Fatal(err)
		}
	})
}

// lookupAlive reports whether pid is a live process, not a zombie.
func lookupAlive(pid int) bool {
	_, ok := lookupOwnProcess(pid)
	return ok
}

// TestStoreLeavesZotsDatabasesAlone: a store with zot's databases in it serves,
// and neither file is deleted or written. They are ignored.
func TestStoreLeavesZotsDatabasesAlone(t *testing.T) {
	work := writeTestServeConfig(t, nil)
	dbs := seedZotDatabases(t, work)
	l := newMemListener()
	result, cancel := runTestServe(t, work, testServeDeps(l))
	if resp := do(t, memClient(t, l), "POST", "http://registry.test/v2/demo/blobs/uploads/", "k3sm-gate", testGateSecret); resp.StatusCode != 202 {
		t.Errorf("upload: %d", resp.StatusCode)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	dbs.check(t)
}

// zotDatabases remembers the bytes and mtimes of zot's two databases.
type zotDatabases map[string]struct {
	body  string
	mtime time.Time
}

// seedZotDatabases writes cache.db and meta.db into the store root, dated in the
// past so a write would show.
func seedZotDatabases(t *testing.T, work string) zotDatabases {
	t.Helper()
	root := StateDir(work)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	out := zotDatabases{}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	for _, name := range []string{"cache.db", "meta.db"} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("zot database "+name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
		out[p] = struct {
			body  string
			mtime time.Time
		}{"zot database " + name, past}
	}
	return out
}

func (d zotDatabases) check(t *testing.T) {
	t.Helper()
	for p, want := range d {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want.body || !fi.ModTime().Equal(want.mtime) {
			t.Errorf("%s was written: %q at %s", p, b, fi.ModTime())
		}
	}
}
