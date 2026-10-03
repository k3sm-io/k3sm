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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"k3sm.io/k3sm/pkg/certs"
)

// resetTestConfig is an init member's Config over wd.
func resetTestConfig(t *testing.T, wd string) Config {
	t.Helper()
	return Config{WorkDir: wd, KinePort: freePort(t), Logger: slog.New(slog.DiscardHandler),
		Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP}}
}

// resetSeams are fakes for a reset: the member answers from fake, the clock is fake,
// and the client port "accepts" once the fake child has recorded its argv (so the
// reset cannot stop the child before it has run).
func resetSeams(fake *fakeEtcd, wd string) etcdSeams {
	return etcdSeams{
		clock: newFakeClock(0),
		dial:  func(context.Context, string, string) (etcdAdmin, error) { return fake, nil },
		ready: func(int) func(context.Context) bool {
			return func(context.Context) bool {
				_, err := os.Stat(filepath.Join(binDir(wd), "etcd.argv"))
				return err == nil
			}
		},
		dialPeer: func(context.Context, string) bool { return false },
	}
}

// existingMember lays down what a member that has booted before leaves behind: the
// hierarchy, the etcd CAs and the member dir.
func existingMember(t *testing.T, wd string) {
	t.Helper()
	if _, err := certs.EnsureHierarchy(wd); err != nil {
		t.Fatal(err)
	}
	if _, _, err := certs.EnsureEtcdCAs(wd); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(etcdMemberDir(wd), 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestClusterResetArgsAndPostcondition: --force-new-cluster only on the reset path; a
// nil return only when the member list is exactly this server; refused without a
// member, while the work-dir lock is held, and outside the etcd posture.
func TestClusterResetArgsAndPostcondition(t *testing.T) {
	t.Run("refused outside the etcd posture", func(t *testing.T) {
		wd := t.TempDir()
		if err := clusterReset(t.Context(), Config{WorkDir: wd}, resetSeams(healthyFake(), wd)); !errors.Is(err, ErrClusterResetNeedsEtcd) {
			t.Errorf("kine posture reset = %v, want ErrClusterResetNeedsEtcd", err)
		}
	})

	t.Run("the exported entry point refuses a loopback peer IP", func(t *testing.T) {
		wd := t.TempDir()
		existingMember(t, wd)
		cfg := resetTestConfig(t, wd)
		cfg.Etcd.PeerIP = "127.0.0.1"
		if err := ClusterReset(t.Context(), cfg); !errors.Is(err, ErrEtcdNeedsNodeIP) {
			t.Fatalf("ClusterReset with a loopback peer IP = %v, want ErrEtcdNeedsNodeIP", err)
		}
		if err := ClusterReset(t.Context(), Config{WorkDir: wd}); !errors.Is(err, ErrClusterResetNeedsEtcd) {
			t.Errorf("ClusterReset outside the etcd posture = %v, want ErrClusterResetNeedsEtcd", err)
		}
	})

	t.Run("refused without an existing member", func(t *testing.T) {
		wd := t.TempDir()
		writeEtcdChild(t, wd, argvChild)
		err := clusterReset(t.Context(), resetTestConfig(t, wd), resetSeams(healthyFake(), wd))
		if !errors.Is(err, ErrNoEtcdMember) {
			t.Fatalf("reset = %v, want ErrNoEtcdMember", err)
		}
		if _, err := os.Stat(filepath.Join(binDir(wd), "etcd.argv")); !os.IsNotExist(err) {
			t.Error("a refused reset started the member")
		}
	})

	t.Run("refused while the work-dir lock is held", func(t *testing.T) {
		wd := t.TempDir()
		existingMember(t, wd)
		writeEtcdChild(t, wd, argvChild)
		unlock, err := lockWorkDir(wd) // the running server's hold
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unlock() }()
		if err := clusterReset(t.Context(), resetTestConfig(t, wd), resetSeams(healthyFake(), wd)); !errors.Is(err, ErrWorkDirLocked) {
			t.Fatalf("reset under a held lock = %v, want ErrWorkDirLocked", err)
		}
		if _, err := os.Stat(filepath.Join(binDir(wd), "etcd.argv")); !os.IsNotExist(err) {
			t.Error("a refused reset started the member")
		}
	})

	t.Run("succeeds only when the member list is exactly self", func(t *testing.T) {
		wd := t.TempDir()
		existingMember(t, wd)
		writeEtcdChild(t, wd, argvChild)
		if err := clusterReset(t.Context(), resetTestConfig(t, wd), resetSeams(healthyFake(), wd)); err != nil {
			t.Fatalf("reset = %v", err)
		}
		args := strings.Split(strings.TrimSpace(string(waitFile(t, filepath.Join(binDir(wd), "etcd.argv")))), "\n")
		if !slices.Contains(args, "--force-new-cluster") {
			t.Errorf("reset argv lacks --force-new-cluster: %v", args)
		}
		for _, f := range []string{"--initial-cluster", "--initial-cluster-state", "--initial-cluster-token"} {
			if slices.Contains(args, f) {
				t.Errorf("reset argv carries the first-boot flag %s", f)
			}
		}
		unlock, err := lockWorkDir(wd)
		if err != nil {
			t.Fatalf("the reset kept the work-dir lock: %v", err)
		}
		_ = unlock()

		// The ordinary boot of the same member never forces a new cluster.
		cfg := resetTestConfig(t, wd).withDefaults()
		if slices.Contains(etcdArgs(etcdArgsInputFor(cfg, "pin", true)), "--force-new-cluster") {
			t.Error("a normal restart renders --force-new-cluster")
		}
	})

	for _, tc := range []struct {
		name    string
		members []etcdMember
		leader  uint64
	}{
		{"a second member survived", []etcdMember{
			{ID: testOwnID, Name: "server-a", PeerURLs: []string{testOwnPeer}},
			{ID: 0xdef, Name: "server-b", PeerURLs: []string{"https://192.168.0.11:2380"}},
		}, testOwnID},
		{"own peer URL is wrong", []etcdMember{{ID: testOwnID, Name: "server-a", PeerURLs: []string{"https://192.168.0.99:2380"}}}, testOwnID},
		{"no leader", []etcdMember{{ID: testOwnID, Name: "server-a", PeerURLs: []string{testOwnPeer}}}, 0},
	} {
		t.Run("fails when "+tc.name, func(t *testing.T) {
			wd := t.TempDir()
			existingMember(t, wd)
			writeEtcdChild(t, wd, argvChild)
			fake := healthyFake()
			fake.members, fake.status.Leader = tc.members, tc.leader
			err := clusterReset(t.Context(), resetTestConfig(t, wd), resetSeams(fake, wd))
			if !errors.Is(err, ErrClusterResetFailed) || !strings.Contains(err.Error(), "snapshot") {
				t.Fatalf("reset = %v, want ErrClusterResetFailed naming the snapshot restore", err)
			}
			if fake.listCalls < 2 {
				t.Errorf("the postcondition was checked %d times; it must be polled until its bound", fake.listCalls)
			}
		})
	}
}

// etcdBackendBytes builds a bbolt file with the given buckets and returns its bytes.
func etcdBackendBytes(t *testing.T, buckets ...string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			bk, err := tx.CreateBucket([]byte(b))
			if err != nil {
				return err
			}
			if err := bk.Put([]byte("k"), []byte("v")); err != nil {
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
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withTrailer appends etcd's SHA-256 trailer.
func withTrailer(db []byte) []byte {
	sum := sha256.Sum256(db)
	return append(slices.Clone(db), sum[:]...)
}

// TestEtcdSnapshotSaveVerifies: the save writes 0600, verifies the trailer and the
// bbolt backend before the file takes its name, and leaves nothing behind otherwise.
func TestEtcdSnapshotSaveVerifies(t *testing.T) {
	good := etcdBackendBytes(t, "key", "meta")
	corrupt := withTrailer(good)
	corrupt[100] ^= 0xff
	for _, tc := range []struct {
		name   string
		stream []byte
		ok     bool
	}{
		{"a complete etcd backend with its trailer", withTrailer(good), true},
		{"a byte flipped in transit", corrupt, false},
		{"no trailer", good, false},
		{"a bbolt file that is not an etcd backend", withTrailer(etcdBackendBytes(t, "other")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			if err := writeEtcdStatus(wd, EtcdStatus{ClientURL: "https://127.0.0.1:2379"}); err != nil {
				t.Fatal(err)
			}
			fake := &fakeEtcd{snapshot: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(tc.stream)), nil
			}}
			var dialed string
			dial := func(_ context.Context, _, endpoint string) (etcdAdmin, error) { dialed = endpoint; return fake, nil }
			dst := filepath.Join(t.TempDir(), "snaps", "etcd.snap")
			err := snapshotEtcd(t.Context(), wd, dst, dial)
			if dialed != "https://127.0.0.1:2379" {
				t.Errorf("dialed %q, want the recorded loopback client URL", dialed)
			}
			if _, terr := os.Stat(dst + ".tmp"); !os.IsNotExist(terr) {
				t.Error("a partial .tmp was left behind")
			}
			if !tc.ok {
				if !errors.Is(err, ErrEtcdSnapshotVerify) {
					t.Errorf("save = %v, want ErrEtcdSnapshotVerify", err)
				}
				if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
					t.Error("an unverified snapshot took the destination name")
				}
				return
			}
			if err != nil {
				t.Fatalf("save = %v", err)
			}
			fi, err := os.Stat(dst)
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("snapshot mode = %v (%v), want 0600", fi.Mode(), err)
			}
			if !fake.closed {
				t.Error("the admin client was not closed")
			}
		})
	}

	t.Run("refused without a recorded loopback member", func(t *testing.T) {
		dial := func(context.Context, string, string) (etcdAdmin, error) {
			t.Error("dialed with no recorded member")
			return nil, errors.New("unreachable")
		}
		if err := snapshotEtcd(t.Context(), t.TempDir(), filepath.Join(t.TempDir(), "s"), dial); !errors.Is(err, ErrNoEtcdClient) {
			t.Errorf("no status record: save = %v, want ErrNoEtcdClient", err)
		}
		wd := t.TempDir()
		if err := writeEtcdStatus(wd, EtcdStatus{ClientURL: "https://192.0.2.10:2379"}); err != nil {
			t.Fatal(err)
		}
		if err := snapshotEtcd(t.Context(), wd, filepath.Join(t.TempDir(), "s"), dial); !errors.Is(err, ErrNoEtcdClient) {
			t.Errorf("non-loopback client URL: save = %v, want ErrNoEtcdClient", err)
		}
	})
}

// TestRestoreRefusesEtcdMember: snapshot restore is refused on an etcd member before
// anything is read or moved.
func TestRestoreRefusesEtcdMember(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(etcdMemberDir(wd), 0o700); err != nil {
		t.Fatal(err)
	}
	probe := func(context.Context) (string, error) {
		t.Error("the live-control-plane probe ran before the etcd refusal")
		return "", nil
	}
	_, err := RestoreSnapshot(t.Context(), SnapshotRestoreOptions{WorkDir: wd, Snapshot: filepath.Join(wd, "absent.db"), Running: probe})
	if !errors.Is(err, ErrEtcdRestoreUnsupported) {
		t.Fatalf("restore on an etcd member = %v, want ErrEtcdRestoreUnsupported", err)
	}
	if _, err := os.Stat(dbDir(wd)); !os.IsNotExist(err) {
		t.Error("the refusal touched the datastore dir")
	}
}
