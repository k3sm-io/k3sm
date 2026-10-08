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

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"k3sm.io/k3sm/pkg/certs"
)

// writeBolt writes a bbolt database holding the named buckets (one key each).
func writeBolt(t *testing.T, path string, buckets ...string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range buckets {
			b, err := tx.CreateBucketIfNotExists([]byte(name))
			if err != nil {
				return err
			}
			if err := b.Put([]byte("k"), []byte("v")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// appendTrailer appends the SHA-256 of the file's bytes, as etcd's snapshot does.
func appendTrailer(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if err := os.WriteFile(path, append(b, sum[:]...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// restoreFixture is a work dir with this server's PKI and a live etcd data dir, and
// a set of snapshot files of every shape a restore must tell apart.
type restoreFixture struct {
	wd, dir                                          string
	clientPort, apiPort                              int
	good, sqlite, noTrailer, corrupt, truncated, bad string
	garbage                                          string
}

func newRestoreFixture(t *testing.T, withMember bool) *restoreFixture {
	t.Helper()
	f := &restoreFixture{wd: t.TempDir(), dir: t.TempDir(), clientPort: 2379, apiPort: 6444}
	if _, err := certs.EnsureHierarchy(f.wd, certs.RoleMintAuthority, certs.PostureKine); err != nil {
		t.Fatal(err)
	}
	if _, _, err := certs.EnsureEtcdCAs(f.wd); err != nil {
		t.Fatal(err)
	}
	if withMember {
		if err := os.MkdirAll(filepath.Join(etcdMemberDir(f.wd), "snap"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(etcdMemberDir(f.wd), "snap", "db"), []byte("the old member's data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeEtcdStatus(f.wd, EtcdStatus{MemberName: "etcd-a"}); err != nil {
			t.Fatal(err)
		}
	}
	p := func(n string) string { return filepath.Join(f.dir, n) }
	f.good, f.noTrailer, f.corrupt, f.truncated, f.bad = p("good.db"), p("member-snap.db"), p("corrupt.db"), p("truncated.db"), p("buckets.db")
	f.sqlite, f.garbage = p("kine.db"), p("garbage.db")
	writeBolt(t, f.good, "key", "meta")
	writeBolt(t, f.noTrailer, "key", "meta")
	writeBolt(t, f.bad, "nothing-etcd")
	for _, path := range []string{f.good, f.bad} {
		appendTrailer(t, path)
	}
	b, _ := os.ReadFile(f.good)
	flipped := bytes.Clone(b)
	flipped[len(flipped)/2] ^= 0xff
	mustWrite(t, f.corrupt, flipped)
	mustWrite(t, f.truncated, b[:len(b)-100])
	mustWrite(t, f.sqlite, append([]byte("SQLite format 3\x00"), make([]byte, 4080)...))
	mustWrite(t, f.garbage, bytes.Repeat([]byte("x"), 4096))
	return f
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *restoreFixture) opts(snapshot string) EtcdRestoreOptions {
	return EtcdRestoreOptions{WorkDir: f.wd, Snapshot: snapshot, Name: "etcd-a", PeerIP: "192.0.2.10",
		PeerPort: 2380, ClientPort: f.clientPort, APIServerPort: f.apiPort}
}

// fakeRestoreSeams fakes etcdutl: it writes a member/snap/db and a wal dir into the
// --data-dir it is handed, and records the argv.
func fakeRestoreSeams(t *testing.T, args *[]string) etcdRestoreSeams {
	t.Helper()
	return etcdRestoreSeams{
		etcdutl: func(context.Context, string, string) (string, error) { return "/fake/etcdutl", nil },
		run: func(_ context.Context, _ string, a []string) ([]byte, error) {
			if args != nil {
				*args = a
			}
			dd := a[slices.Index(a, "--data-dir")+1]
			if err := os.MkdirAll(filepath.Join(dd, "member", "snap"), 0o700); err != nil {
				return nil, err
			}
			if err := os.MkdirAll(filepath.Join(dd, "member", "wal"), 0o700); err != nil {
				return nil, err
			}
			return nil, os.WriteFile(filepath.Join(dd, "member", "snap", "db"), []byte("restored"), 0o600)
		},
		rename:    os.Rename,
		now:       func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) },
		listening: func(context.Context, string) bool { return false },
		held:      func(context.Context, int) (string, bool) { return "", false },
	}
}

// workDirEntries lists the work dir's top level, to prove a refusal moved nothing.
func workDirEntries(t *testing.T, wd string) []string {
	t.Helper()
	es, err := os.ReadDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		if e.Name() == workDirLockName {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// TestEtcdRestoreRefusals: every refusal named by the restore's contract fires
// before anything in the work dir moves, and each is its own sentinel.
func TestEtcdRestoreRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, s *etcdRestoreSeams)
		want  error
		say   string
	}{
		{name: "no etcd configuration", want: ErrEtcdRestoreNeedsEtcd,
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot, o.PeerIP = f.good, ""
			}},
		{name: "kine posture: a state.db is present", want: ErrEtcdRestoreOverSQLite,
			setup: func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				if err := os.MkdirAll(dbDir(f.wd), 0o755); err != nil {
					t.Fatal(err)
				}
				mustWrite(t, StateDBPath(f.wd), []byte("SQLite format 3\x00"))
			}},
		{name: "a kine snapshot handed to the etcd posture", want: ErrKineSnapshotForEtcd,
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.sqlite
			}},
		{name: "a copy of member/snap/db with no trailer", want: ErrEtcdSnapshotNoTrailer, say: "member/snap/db",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.noTrailer
			}},
		{name: "corrupt (trailer mismatch)", want: ErrEtcdSnapshotVerify, say: "does not match its SHA-256 trailer",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.corrupt
			}},
		{name: "truncated", want: ErrEtcdSnapshotVerify, say: "not a database plus its SHA-256 trailer",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.truncated
			}},
		{name: "wrong buckets", want: ErrEtcdSnapshotVerify, say: "bucket",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) { o.Snapshot = f.bad }},
		{name: "neither etcd nor SQLite", want: ErrEtcdSnapshotVerify,
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.garbage
			}},
		{name: "missing file", want: ErrSnapshotNotFound,
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = filepath.Join(f.dir, "absent.db")
			}},
		{name: "daemon running: the work-dir lock is held", want: ErrWorkDirLocked,
			setup: func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				unlock, err := lockWorkDir(f.wd)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = unlock() })
			}},
		{name: "daemon running: the etcd client port is held", want: ErrControlPlaneRunning, say: "etcd client port",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, s *etcdRestoreSeams) {
				o.Snapshot = f.good
				s.held = func(_ context.Context, port int) (string, bool) { return "etcd (pid 9)", port == f.clientPort }
			}},
		{name: "daemon running: the apiserver port is held", want: ErrControlPlaneRunning, say: "apiserver port",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, s *etcdRestoreSeams) {
				o.Snapshot = f.good
				s.held = func(_ context.Context, port int) (string, bool) { return "kube-apiserver (pid 9)", port == f.apiPort }
			}},
		{name: "daemon running: the peer port accepts", want: ErrControlPlaneRunning, say: "peer port",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, s *etcdRestoreSeams) {
				o.Snapshot = f.good
				s.listening = func(_ context.Context, hp string) bool { return hp == "192.0.2.10:2380" }
			}},
		{name: "daemon running: the recorded etcd pid is alive", want: ErrControlPlaneRunning, say: "SIGKILL",
			setup: func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				writeEtcdStatusPID(t, f.wd, startFakeEtcd(t))
			}},
		{name: "daemon running: the launchd job", want: ErrControlPlaneRunning, say: "launchd job",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				o.Running = func(context.Context) (string, error) { return "the io.k3sm.server launchd job is running (pid 7)", nil }
			}},
		{name: "no PKI in the work dir", want: ErrEtcdRestoreNoPKI,
			setup: func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				if err := os.RemoveAll(certs.PKIDir(f.wd)); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the etcd CAs are missing", want: ErrEtcdCAsMissing,
			setup: func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				if err := os.Remove(certs.EtcdCertPaths(f.wd).PeerCAKey); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "not twice the snapshot's size free", want: ErrSnapshotSpace, say: "the snapshot's size",
			setup: func(t *testing.T, f *restoreFixture, o *EtcdRestoreOptions, _ *etcdRestoreSeams) {
				o.Snapshot = f.good
				orig := freeSpace
				t.Cleanup(func() { freeSpace = orig })
				freeSpace = func(string) (uint64, error) { return 1024, nil }
			}},
		{name: "etcdutl fails", want: ErrEtcdRestoreFailed, say: "boom",
			setup: func(_ *testing.T, f *restoreFixture, o *EtcdRestoreOptions, s *etcdRestoreSeams) {
				o.Snapshot = f.good
				s.run = func(_ context.Context, _ string, a []string) ([]byte, error) {
					dd := a[slices.Index(a, "--data-dir")+1]
					_ = os.MkdirAll(filepath.Join(dd, "member"), 0o700) // a partial rebuild
					return []byte("boom"), errors.New("exit status 1")
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRestoreFixture(t, true)
			o, s := f.opts(""), fakeRestoreSeams(t, nil)
			tc.setup(t, f, &o, &s)
			before := workDirEntries(t, f.wd)
			res, err := restoreEtcdSnapshot(t.Context(), o, s)
			if !errors.Is(err, tc.want) {
				t.Fatalf("restore = (%+v, %v), want %v", res, err, tc.want)
			}
			if tc.say != "" && !strings.Contains(err.Error(), tc.say) {
				t.Errorf("refusal %q does not say %q", err, tc.say)
			}
			if after := workDirEntries(t, f.wd); !slices.Equal(before, after) {
				t.Errorf("the refusal changed the work dir: %v -> %v", before, after)
			}
			if b, err := os.ReadFile(filepath.Join(etcdMemberDir(f.wd), "snap", "db")); err != nil || string(b) != "the old member's data" {
				t.Errorf("the live data dir changed: %q (%v)", b, err)
			}
		})
	}
}

// writeEtcdStatusPID records pid as the etcd member's.
func writeEtcdStatusPID(t *testing.T, wd string, pid int) {
	t.Helper()
	if err := writeEtcdStatus(wd, EtcdStatus{MemberName: "etcd-a", PID: pid}); err != nil {
		t.Fatal(err)
	}
}

// startFakeEtcd builds and starts a stand-in that sleeps under the command name
// etcd (a copied platform binary is killed at exec on arm64, so it is compiled) and
// returns its pid.
func startFakeEtcd(t *testing.T) int {
	t.Helper()
	goBin, err := lookPathGo()
	if err != nil {
		t.Skip("no Go toolchain to build a stand-in etcd")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), []byte("module standin\n\ngo 1.26\n"))
	mustWrite(t, filepath.Join(dir, "main.go"), []byte("package main\n\nimport \"time\"\n\nfunc main() { time.Sleep(time.Minute) }\n"))
	bin := filepath.Join(dir, etcdBinaryName)
	build := exec.Command(goBin, "build", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the stand-in etcd: %v\n%s", err, out)
	}
	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the stand-in etcd: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for !processIsEtcd(cmd.Process.Pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d (a binary named etcd) is not reported as etcd", cmd.Process.Pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cmd.Process.Pid
}

// TestEtcdRestoreStalePIDIsNotARefusal: a recorded pid that a different program now
// holds (the pid was recycled) does not block a restore forever.
func TestEtcdRestoreStalePIDIsNotARefusal(t *testing.T) {
	f := newRestoreFixture(t, true)
	writeEtcdStatusPID(t, f.wd, os.Getpid())
	if _, err := restoreEtcdSnapshot(t.Context(), f.opts(f.good), fakeRestoreSeams(t, nil)); err != nil {
		t.Fatalf("restore with a recycled pid in the status record = %v, want success", err)
	}
}

// TestEtcdRestoreSwap: the destructive window. A rebuild replaces the live data dir,
// which is preserved byte-identical as the .bak with the status record beside it; a
// work dir with no data dir (a rebuilt server) restores too; and a failure on any
// rename puts back everything already moved.
func TestEtcdRestoreSwap(t *testing.T) {
	const stamp = "20261007T120000Z"
	t.Run("replaces and preserves the live data dir", func(t *testing.T) {
		f := newRestoreFixture(t, true)
		var args []string
		res, err := restoreEtcdSnapshot(t.Context(), f.opts(f.good), fakeRestoreSeams(t, &args))
		if err != nil {
			t.Fatal(err)
		}
		bak := filepath.Join(f.wd, "etcd.restore-"+stamp+".bak")
		if res.PreviousDataDir != bak {
			t.Errorf("PreviousDataDir = %q, want %q", res.PreviousDataDir, bak)
		}
		if b, _ := os.ReadFile(filepath.Join(bak, "member", "snap", "db")); string(b) != "the old member's data" {
			t.Errorf(".bak holds %q, want the old member's data", b)
		}
		if b, _ := os.ReadFile(filepath.Join(EtcdDataDir(f.wd), "member", "snap", "db")); string(b) != "restored" {
			t.Errorf("live data dir holds %q, want the rebuild", b)
		}
		if fi, err := os.Stat(EtcdDataDir(f.wd)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("live data dir mode = %v (%v), want 0700", fi.Mode().Perm(), err)
		}
		if _, err := os.Stat(EtcdStatusPath(f.wd)); !os.IsNotExist(err) {
			t.Error("the old status record stayed beside the restored data dir")
		}
		if want := filepath.Join(f.wd, etcdStatusName+".restore-"+stamp+".bak"); !slices.Equal(res.MovedAside, []string{want}) {
			t.Errorf("MovedAside = %v, want [%s]", res.MovedAside, want)
		}
		if _, err := os.Stat(filepath.Join(f.wd, "etcd.restore-"+stamp+".tmp")); !os.IsNotExist(err) {
			t.Error("the .tmp rebuild dir is left behind")
		}
		for _, want := range []string{"--bump-revision", strconv.FormatUint(EtcdRestoreRevisionBump, 10), "--mark-compacted",
			"--initial-cluster", "etcd-a=https://192.0.2.10:2380", "--initial-advertise-peer-urls"} {
			if !slices.Contains(args, want) {
				t.Errorf("etcdutl argv %q lacks %q", args, want)
			}
		}
		if slices.Contains(args, "--skip-hash-check") {
			t.Error("etcdutl argv skips the hash check")
		}
		token := args[slices.Index(args, "--initial-cluster-token")+1]
		pin, _ := clusterCAPin(f.wd)
		if !strings.HasPrefix(token, etcdClusterToken(pin)+"-r") || token == etcdClusterToken(pin) {
			t.Errorf("token %q is not a fresh token under the cluster's pin", token)
		}
	})

	t.Run("a work dir with no data dir restores", func(t *testing.T) {
		f := newRestoreFixture(t, false)
		res, err := restoreEtcdSnapshot(t.Context(), f.opts(f.good), fakeRestoreSeams(t, nil))
		if err != nil {
			t.Fatal(err)
		}
		if res.PreviousDataDir != "" || !EtcdMemberExists(f.wd) {
			t.Errorf("result %+v, member exists %v; want a member and nothing preserved", res, EtcdMemberExists(f.wd))
		}
	})

	for _, failAt := range []int{1, 2, 3} {
		t.Run("rename "+strconv.Itoa(failAt)+" fails and the original comes back", func(t *testing.T) {
			f := newRestoreFixture(t, true)
			s := fakeRestoreSeams(t, nil)
			calls := 0
			s.rename = func(oldpath, newpath string) error {
				calls++
				if calls == failAt {
					return errors.New("injected rename failure")
				}
				return os.Rename(oldpath, newpath)
			}
			res, err := restoreEtcdSnapshot(t.Context(), f.opts(f.good), s)
			if !errors.Is(err, ErrEtcdRestoreSwap) {
				t.Fatalf("restore = %v, want ErrEtcdRestoreSwap", err)
			}
			if b, _ := os.ReadFile(filepath.Join(EtcdDataDir(f.wd), "member", "snap", "db")); string(b) != "the old member's data" {
				t.Errorf("after the failed swap the live data dir holds %q, want the original", b)
			}
			if _, err := os.Stat(EtcdStatusPath(f.wd)); err != nil {
				t.Errorf("the status record was not put back: %v", err)
			}
			if got := workDirEntries(t, f.wd); slices.ContainsFunc(got, func(n string) bool { return strings.Contains(n, ".restore-") }) {
				t.Errorf("a failed swap left %v behind", got)
			}
			if res != nil && res.PreviousDataDir != "" {
				t.Errorf("a failed swap reports a preserved dir %q", res.PreviousDataDir)
			}
		})
	}
}

// TestEtcdRestoreWarnsOnReadableSnapshot: a snapshot others can read is restored
// with a warning, and its mode is left alone.
func TestEtcdRestoreWarnsOnReadableSnapshot(t *testing.T) {
	f := newRestoreFixture(t, true)
	if err := os.Chmod(f.good, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := restoreEtcdSnapshot(t.Context(), f.opts(f.good), fakeRestoreSeams(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "plaintext") {
		t.Errorf("warnings = %q, want one plaintext warning", res.Warnings)
	}
	if fi, _ := os.Stat(f.good); fi.Mode().Perm() != 0o644 {
		t.Errorf("the restore changed the snapshot's mode to %v", fi.Mode().Perm())
	}
}

// TestKineRestoreRefusesEtcdSnapshot: the kine restore shares the posture
// preflight, so an etcd snapshot never reaches SQLite.
func TestKineRestoreRefusesEtcdSnapshot(t *testing.T) {
	f := newRestoreFixture(t, false)
	for _, snap := range []string{f.good, f.noTrailer} {
		_, err := RestoreSnapshot(t.Context(), SnapshotRestoreOptions{WorkDir: t.TempDir(), Snapshot: snap,
			Running: func(context.Context) (string, error) { return "", nil }})
		if !errors.Is(err, ErrEtcdSnapshotForKine) {
			t.Errorf("kine restore of %s = %v, want ErrEtcdSnapshotForKine", filepath.Base(snap), err)
		}
	}
}

// TestRestoreEtcdSnapshotRefusesLoopbackPeer: the exported entry point validates the
// peer address a real server advertises.
func TestRestoreEtcdSnapshotRefusesLoopbackPeer(t *testing.T) {
	_, err := RestoreEtcdSnapshot(t.Context(), EtcdRestoreOptions{WorkDir: t.TempDir(), Snapshot: "x", Name: "a", PeerIP: "127.0.0.1"})
	if !errors.Is(err, ErrEtcdNeedsNodeIP) {
		t.Fatalf("RestoreEtcdSnapshot(loopback peer) = %v, want ErrEtcdNeedsNodeIP", err)
	}
}

// TestRefuseInterruptedEtcdRestore: a work dir a restore stopped in (no data dir, its
// .bak or .tmp beside it) refuses every etcd start path, the executor's provision and
// --cluster-reset included; finishing the restore by re-running it clears it.
func TestRefuseInterruptedEtcdRestore(t *testing.T) {
	const stamp = "20261007T120000Z"
	for _, tc := range []struct {
		name      string
		live, bak bool
		tmp       bool
		want      bool
		say       []string
	}{
		{name: "a completed restore (data dir and .bak)", live: true, bak: true},
		{name: "a fresh work dir", want: false},
		{name: "crashed after the aside rename", bak: true, tmp: true, want: true,
			say: []string{"k3sm snapshot restore", "sudo mv", "etcd.restore-" + stamp + ".bak", "remove the unfinished rebuild"}},
		{name: "a rebuilt server that crashed mid-rebuild", tmp: true, want: true, say: []string{"k3sm snapshot restore", "remove the unfinished rebuild"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			mk := func(cond bool, name string) {
				if cond {
					if err := os.MkdirAll(filepath.Join(wd, name, "member"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			mk(tc.live, "etcd")
			mk(tc.bak, "etcd.restore-"+stamp+".bak")
			mk(tc.tmp, "etcd.restore-"+stamp+".tmp")
			err := RefuseInterruptedEtcdRestore(wd)
			if got := errors.Is(err, ErrEtcdRestoreInterrupted); got != tc.want {
				t.Fatalf("RefuseInterruptedEtcdRestore = %v, want refusal %v", err, tc.want)
			}
			for _, want := range tc.say {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not say %q", err, want)
				}
			}
			if !tc.want {
				return
			}
			cfg := Config{WorkDir: wd, Etcd: &EtcdConfig{Role: EtcdInit, Name: "etcd-a", PeerIP: "192.0.2.10"}}
			if err := NewSupervised(cfg).provision(t.Context()); !errors.Is(err, ErrEtcdRestoreInterrupted) {
				t.Errorf("executor provision = %v, want ErrEtcdRestoreInterrupted", err)
			}
			if err := clusterReset(t.Context(), cfg, defaultEtcdSeams()); !errors.Is(err, ErrEtcdRestoreInterrupted) {
				t.Errorf("cluster reset = %v, want ErrEtcdRestoreInterrupted", err)
			}
			if _, err := os.Stat(EtcdDataDir(wd)); !os.IsNotExist(err) {
				t.Error("a refusal created an etcd data dir")
			}
		})
	}

	t.Run("re-running the restore finishes it", func(t *testing.T) {
		f := newRestoreFixture(t, true)
		s := fakeRestoreSeams(t, nil)
		calls := 0
		s.rename = func(oldpath, newpath string) error {
			calls++
			if calls == 3 { // the rebuilt dir into place: the process dies here
				panic(errCrashBetweenRenames)
			}
			return os.Rename(oldpath, newpath)
		}
		func() {
			defer func() {
				if r := recover(); r != errCrashBetweenRenames {
					t.Fatalf("restore did not reach the third rename (recovered %v)", r)
				}
			}()
			_, _ = restoreEtcdSnapshot(t.Context(), f.opts(f.good), s)
		}()
		if err := RefuseInterruptedEtcdRestore(f.wd); !errors.Is(err, ErrEtcdRestoreInterrupted) {
			t.Fatalf("after the crash, start check = %v, want ErrEtcdRestoreInterrupted", err)
		}
		s2 := fakeRestoreSeams(t, nil)
		s2.now = func() time.Time { return time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC) }
		if _, err := restoreEtcdSnapshot(t.Context(), f.opts(f.good), s2); err != nil {
			t.Fatalf("re-run restore = %v", err)
		}
		if err := RefuseInterruptedEtcdRestore(f.wd); err != nil {
			t.Errorf("after finishing the restore, start check = %v, want nil", err)
		}
	})
}

// errCrashBetweenRenames stands in for the process dying mid-swap: a panic skips the
// swap's own rollback exactly as a crash would.
var errCrashBetweenRenames = errors.New("crashed between the renames")
