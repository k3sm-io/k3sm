//go:build integration

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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	// walTestPuts is enough write traffic to cross SQLite's 1000-page autocheckpoint
	// threshold dozens of times: each put of walTestValue lands about a dozen pages.
	walTestPuts = 4000
	// walTestValue is a lease-object-sized value, the apiserver's steadiest writer.
	walTestValue = 2048
	// walTestBound is the WAL size a checkpointing kine stays under. A WAL that is
	// checkpointed is reset and reused from its start, so it settles near the
	// autocheckpoint threshold (1000 pages of 4 KiB, about 4 MiB); 16 MiB is four times
	// that. A pinned WAL under this load is well over 150 MiB.
	walTestBound = 16 << 20
)

// TestKineWALCheckpoints proves the pinned kine, staged through the production
// stagedChild protocol and started from kineArgs, lets SQLite checkpoint its WAL
// while a watch is open and writes keep coming (the apiserver's steady state).
//
// A kine that holds a read transaction open for its whole life pins the oldest WAL
// snapshot: no checkpoint can copy a frame past it, the WAL is never reset, and
// state.db-wal grows without bound until the data volume fills. The probe is the
// same one an operator runs: PRAGMA wal_checkpoint(PASSIVE) from a second
// connection, which reports busy|log|checkpointed and checkpoints 0 frames while a
// reader pins the snapshot.
func TestKineWALCheckpoints(t *testing.T) {
	bin := itKineBinary(t)
	if !fileExists(sqlite3Bin) {
		t.Fatalf("%s not found: the checkpoint probe needs the bundled SQLite CLI", sqlite3Bin)
	}

	work := t.TempDir()
	if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
		t.Fatal(err)
	}
	var ports itPorts
	cfg := Config{WorkDir: work, KinePort: ports.next(t)}
	args, err := kineArgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startITKine(t, bin, args, cfg.KinePort)
	db := StateDBPath(work)

	// At start, before any client: kine has opened the datastore and created its
	// schema, so the WAL holds frames, and every one must be checkpointable.
	if busy, log, ckpt := passiveCheckpoint(t, db); busy != 0 || log == 0 || ckpt != log {
		t.Errorf("checkpoint right after start = busy %d, log %d, checkpointed %d; want every frame checkpointed (a reader opened at start pins the WAL)", busy, log, ckpt)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"127.0.0.1:" + strconv.Itoa(cfg.KinePort)},
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// The open watch is the apiserver's shape: kine's poll loop serves it for the
	// whole run. Events are drained so the watch never backs up.
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	events := make(chan int, 1)
	go func() {
		n := 0
		for resp := range cli.Watch(watchCtx, "/registry/", clientv3.WithPrefix()) {
			n += len(resp.Events)
		}
		events <- n
	}()

	val := strings.Repeat("x", walTestValue)
	maxWAL := int64(0)
	for i := range walTestPuts {
		key := fmt.Sprintf("/registry/leases/kube-node-lease/node-%d", i%50)
		if _, err := cli.Put(ctx, key, val); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		if i%250 == 0 {
			if fi, err := os.Stat(db + "-wal"); err == nil && fi.Size() > maxWAL {
				maxWAL = fi.Size()
			}
		}
	}
	stopWatch()
	if n := <-events; n == 0 {
		t.Error("the watch saw no events — the load did not exercise kine's poll loop")
	}

	busy, log, ckpt := passiveCheckpoint(t, db)
	t.Logf("after %d puts: PASSIVE checkpoint busy=%d log=%d checkpointed=%d; peak WAL %d bytes", walTestPuts, busy, log, ckpt, maxWAL)
	if ckpt == 0 {
		t.Errorf("PASSIVE checkpoint after the load checkpointed 0 of %d frames: a reader pins the WAL", log)
	}
	if maxWAL > walTestBound {
		t.Errorf("WAL peaked at %d bytes under the load, want <= %d: it is not being checkpointed and reset", maxWAL, walTestBound)
	}
	fi, err := os.Stat(db + "-wal")
	if err != nil {
		t.Fatalf("stat WAL: %v", err)
	}
	if fi.Size() > walTestBound {
		t.Errorf("WAL is %d bytes after the load, want <= %d", fi.Size(), walTestBound)
	}
}

// TestKineRecoversLeftoverWAL is the upgrade's first boot: a kine built WITHOUT the
// carried patches (the build every node ran before them) grows a large WAL and is
// killed, then the patched kine starts over it. prepareKineWAL must size the
// recovery (an Info line, a proportional wait, and a free-space need that matches the
// growth state.db actually takes), and the patched kine must checkpoint and truncate
// the whole WAL and listen well inside that wait.
func TestKineRecoversLeftoverWAL(t *testing.T) {
	patched := itKineBinary(t)
	unpatched := itUnpatchedKineBinary(t)
	if !fileExists(sqlite3Bin) {
		t.Fatalf("%s not found", sqlite3Bin)
	}
	work := t.TempDir()
	if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
		t.Fatal(err)
	}
	var ports itPorts
	cfg := Config{WorkDir: work, KinePort: ports.next(t)}
	args, err := kineArgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := StateDBPath(work)

	// Grow a WAL past largeWALBytes with the unpatched build, then kill -9 it.
	stop := startITKine(t, unpatched, args, cfg.KinePort)
	putLoad(t, cfg.KinePort, 2000)
	stop()
	fi, err := os.Stat(db + "-wal")
	if err != nil || fi.Size() < largeWALBytes {
		t.Fatalf("the unpatched kine left a WAL of %v bytes (%v), want >= %d", fi.Size(), err, largeWALBytes)
	}
	walBytes := fi.Size()
	dbBefore, err := os.Stat(db)
	if err != nil {
		t.Fatal(err)
	}
	growth, err := walCheckpointGrowth(db)
	if err != nil {
		t.Fatalf("walCheckpointGrowth on a real WAL: %v", err)
	}
	var logs strings.Builder
	wait, err := prepareKineWAL(slog.New(slog.NewTextHandler(&logs, nil)), work)
	if err != nil {
		t.Fatalf("prepareKineWAL: %v", err)
	}
	if wait <= componentReadyTimeout || !strings.Contains(logs.String(), "recovering a large datastore WAL") {
		t.Errorf("prepareKineWAL = %v with log %q; want a longer wait and an Info line", wait, logs.String())
	}

	start := time.Now()
	startITKine(t, patched, args, cfg.KinePort)
	took := time.Since(start)
	dbAfter, err := os.Stat(db)
	if err != nil {
		t.Fatal(err)
	}
	actual := dbAfter.Size() - dbBefore.Size()
	t.Logf("leftover WAL %d bytes: patched kine listening after %v (wait %v); state.db grew %d bytes, estimated %d", walBytes, took, wait, actual, growth)
	if took > wait/4 {
		t.Errorf("recovery took %v, more than a quarter of the %v wait", took, wait)
	}
	if actual > growth {
		t.Errorf("state.db grew %d bytes, more than the %d the free-space check reserved", actual, growth)
	}
	if growth > actual+(8<<20) {
		t.Errorf("the free-space check reserved %d bytes for a growth of %d: the estimate is not the WAL's commit size", growth, actual)
	}
	if fi, err := os.Stat(db + "-wal"); err == nil && fi.Size() > walTestBound {
		t.Errorf("WAL is %d bytes after the patched start, want it truncated", fi.Size())
	}
}

// putLoad writes n lease-sized values through kine's etcd API, with a watch open.
func putLoad(t *testing.T, port, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{"127.0.0.1:" + strconv.Itoa(port)}, DialTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	defer func() { _ = cli.Close() }()
	watch := cli.Watch(ctx, "/registry/", clientv3.WithPrefix())
	go func() {
		for range watch {
		}
	}()
	val := strings.Repeat("x", walTestValue)
	for i := range n {
		if _, err := cli.Put(ctx, fmt.Sprintf("/registry/leases/kube-node-lease/node-%d", i%50), val); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
}

// itUnpatchedKineBinary builds the pinned kine through the production build with the
// carried patches removed: the binary every node ran before them.
func itUnpatchedKineBinary(t *testing.T) string {
	t.Helper()
	saved := kinePatches
	kinePatches = nil
	t.Cleanup(func() { kinePatches = saved })
	scratch := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	bin, err := buildKine(ctx, DefaultKineVersion, scratch)
	if err != nil {
		t.Fatalf("build unpatched kine: %v", err)
	}
	kinePatches = saved
	return bin
}

// passiveCheckpoint runs PRAGMA wal_checkpoint(PASSIVE) from a second connection and
// returns its busy, log-frame and checkpointed-frame counts.
func passiveCheckpoint(t *testing.T, db string) (busy, log, ckpt int) {
	t.Helper()
	out, err := sqlite3(t.Context(), db, "PRAGMA wal_checkpoint(PASSIVE);")
	if err != nil {
		t.Fatalf("checkpoint probe: %v", err)
	}
	f := strings.Split(strings.TrimSpace(out), "|")
	if len(f) != 3 {
		t.Fatalf("checkpoint probe output %q, want busy|log|checkpointed", out)
	}
	n := make([]int, 3)
	for i, s := range f {
		if n[i], err = strconv.Atoi(s); err != nil {
			t.Fatalf("checkpoint probe output %q: %v", out, err)
		}
	}
	return n[0], n[1], n[2]
}

// itKineBinary stages the pinned kine through ensureKineInto (the production
// build) and returns its path. It skips only without a Go toolchain or when the
// module cache and proxy are unreachable; any other build failure fails the test.
func itKineBinary(t *testing.T) string {
	t.Helper()
	if _, err := lookPathGo(); err != nil {
		t.Skip("no Go toolchain on PATH to build kine: " + err.Error())
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	if err := ensureKineInto(ctx, dir, DefaultKineVersion); err != nil {
		switch {
		case errors.Is(err, ErrNoGoToolchain):
			t.Skip("no Go toolchain to build kine: " + err.Error())
		case moduleFetchFailed(err):
			t.Skip("the module cache/proxy is unreachable for the kine build: " + err.Error())
		}
		t.Fatalf("stage kine %s: %v", DefaultKineVersion, err)
	}
	bin := filepath.Join(dir, kineBinaryName)
	// The build stamps the pin into kine's version package; the soak's built-binary
	// witness reads it back from here.
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("staged kine --version: %v: %s", err, out)
	}
	if want := "kine version " + kineStampedVersion(DefaultKineVersion) + " "; !strings.HasPrefix(string(out), want) {
		t.Errorf("staged kine --version = %q, want it to start %q", out, want)
	}
	return bin
}

// startITKine starts kine with args and waits for its listener. The returned stop
// kills it with SIGKILL (as a crash or a power cut would) and waits for it; it also
// runs when the test ends, and is safe to call twice.
func startITKine(t *testing.T, bin string, args []string, port int) (stop func()) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdout = itLogWriter{t: t, name: "kine"}
	cmd.Stderr = itLogWriter{t: t, name: "kine"}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kine: %v", err)
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
	}
	t.Cleanup(stop)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(time.Minute)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return stop
		}
		if time.Now().After(deadline) {
			t.Fatalf("kine did not listen on %s within a minute: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
