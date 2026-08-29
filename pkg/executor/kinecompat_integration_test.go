//go:build kinecompat

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

// The kine cross-pin datastore-compatibility tests.
//
// Build-tagged `kinecompat` because they need two REAL kine binaries — the pin k3sm is
// leaving and the pin it is moving to — which the caller builds and names in
// K3SM_KINE_OLD / K3SM_KINE_NEW. hack/acceptance/B69.sh is that caller.
//
// What they prove is narrow and deliberate: an existing single-node datastore written
// by the old pin is still fully readable by the new one (FORWARD), and a datastore the
// new pin has written and migrated is still readable by the old one (DOWNGRADE — the
// rollback half, which no forward test can imply). They do NOT prove the new pin is
// correct in general; kine's own test suite owns that.
//
// The fixture is production-SHAPED on purpose. A three-key toy dataset would pass
// against a schema change that only affects large values, secrets, leases, or the
// list/range path the apiserver actually depends on, so the dataset carries real
// /registry key shapes across kinds (including Secrets, Leases, and Events), realistic
// value sizes, and a churn pass of updates and deletes that leaves superseded rows and
// tombstones in the table — the rows a migration is most likely to mishandle.

package executor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// oldPinDSNParams is the DSN shape the SUPERSEDED pin shipped with — no vacuum opt-out,
// because that pin had no startup VACUUM to opt out of. The old-pin phases use it so the
// fixture is written exactly as a real pre-migration node's was.
const oldPinDSNParams = "?_journal=WAL&_busy_timeout=30000"

// kineBinaries resolves the two binaries under test. Absent env is a FAILURE, not a
// skip: under the kinecompat tag the caller has promised to supply them, and a silent
// skip is how a compat gate goes falsely green.
func kineBinaries(t *testing.T) (old, new string) {
	t.Helper()
	old, new = os.Getenv("K3SM_KINE_OLD"), os.Getenv("K3SM_KINE_NEW")
	for name, p := range map[string]string{"K3SM_KINE_OLD": old, "K3SM_KINE_NEW": new} {
		if p == "" {
			t.Fatalf("%s is unset — the kinecompat tests need both kine binaries; run them via hack/acceptance/B69.sh", name)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s=%s: %v", name, p, err)
		}
	}
	return old, new
}

// freePort reserves and releases a loopback port, returning its number.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// serve starts a kine binary against dbPath and returns a connected etcd client plus a
// stop func. The stop func kills kine and waits, so the NEXT phase opens a database with
// no live writer — which is the state the real migration runs in (the control plane is
// stopped when the executor snapshots and re-opens).
func serve(t *testing.T, bin, dbPath, dsnParams string) (*clientv3.Client, func()) {
	t.Helper()
	port := freePort(t)
	logPath := filepath.Join(t.TempDir(), "kine.log")
	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin,
		"--listen-address", "127.0.0.1:"+strconv.Itoa(port),
		"--metrics-bind-address", "0",
		"--endpoint", "sqlite://"+dbPath+dsnParams)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = lf.Close()
	}

	deadline := time.Now().Add(45 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			out, _ := os.ReadFile(logPath)
			stop()
			t.Fatalf("%s never listened on :%d\n%s", bin, port, out)
		}
		time.Sleep(200 * time.Millisecond)
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"127.0.0.1:" + strconv.Itoa(port)},
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		stop()
		t.Fatalf("etcd client for %s: %v", bin, err)
	}
	return cli, func() { _ = cli.Close(); stop() }
}

// kine implements only the etcd Txn SHAPES the apiserver emits — a bare Put is
// "Unimplemented" — so create/update/delete below reproduce those exact shapes
// (kine pkg/server/{create,update,delete}.go: isCreate/isUpdate/isDelete). Using the
// apiserver's own shapes is also what makes this test a datastore test rather than a
// test of a private API.

// create writes a key that must not already exist (isCreate: one MOD==0 compare, one
// Put, NO failure op).
func create(ctx context.Context, cli *clientv3.Client, key string, val []byte) error {
	r, err := cli.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, string(val))).
		Commit()
	if err != nil {
		return err
	}
	if !r.Succeeded {
		return fmt.Errorf("create %s: key already exists", key)
	}
	return nil
}

// update replaces a key at its current revision (isUpdate: one MOD==rev compare, one
// Put, one Range failure op).
func update(ctx context.Context, cli *clientv3.Client, key string, val []byte) error {
	cur, err := cli.Get(ctx, key)
	if err != nil {
		return err
	}
	if len(cur.Kvs) != 1 {
		return fmt.Errorf("update %s: not present", key)
	}
	r, err := cli.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", cur.Kvs[0].ModRevision)).
		Then(clientv3.OpPut(key, string(val))).
		Else(clientv3.OpGet(key)).
		Commit()
	if err != nil {
		return err
	}
	if !r.Succeeded {
		return fmt.Errorf("update %s: revision moved under us", key)
	}
	return nil
}

// remove deletes a key at its current revision (isDelete: one MOD==rev compare, one
// DeleteRange, one Range failure op). It leaves a TOMBSTONE row, which is exactly the
// kind of row a schema migration can mishandle.
func remove(ctx context.Context, cli *clientv3.Client, key string) error {
	cur, err := cli.Get(ctx, key)
	if err != nil {
		return err
	}
	if len(cur.Kvs) != 1 {
		return fmt.Errorf("delete %s: not present", key)
	}
	r, err := cli.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", cur.Kvs[0].ModRevision)).
		Then(clientv3.OpDelete(key)).
		Else(clientv3.OpGet(key)).
		Commit()
	if err != nil {
		return err
	}
	if !r.Succeeded {
		return fmt.Errorf("delete %s: revision moved under us", key)
	}
	return nil
}

// blob renders a deterministic value of n bytes for a key, prefixed the way the
// apiserver's protobuf storage serializer prefixes every object it writes ("k8s\0").
// Deterministic so the verifying phase recomputes the expectation rather than trusting
// whatever it read back.
func blob(key string, n int) []byte {
	out := append([]byte{'k', '8', 's', 0}, []byte(key)...)
	for len(out) < n {
		sum := sha256.Sum256(out[max(0, len(out)-64):])
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// dataset is the production-shaped fixture: real /registry key shapes across the kinds a
// live cluster writes, at realistic sizes. Secrets and ConfigMaps are large-valued (the
// BLOB column's stress case), Events and Leases are numerous and short-lived (the churn
// and tombstone cases), and the pod/replicaset families give the range/list path
// something with a shared prefix to scan.
func dataset() map[string][]byte {
	keys := []struct {
		key  string
		size int
	}{
		// NB: /registry/health is kine's OWN key (it writes it at startup), so it is
		// deliberately absent — creating it would collide, not exercise anything.
		{"/registry/ranges/servicenodeports", 192},
		{"/registry/ranges/serviceips", 192},
		{"/registry/namespaces/default", 512},
		{"/registry/namespaces/kube-system", 512},
		{"/registry/serviceaccounts/default/default", 640},
		{"/registry/configmaps/kube-system/kube-root-ca.crt", 2048},
		{"/registry/secrets/default/web-tls", 8192},
		{"/registry/secrets/kube-system/k3sm-serving", 4096},
		{"/registry/services/specs/default/web", 1024},
		{"/registry/services/endpoints/default/web", 1024},
		{"/registry/endpointslices/default/web-x7f2k", 1536},
		{"/registry/deployments/default/web", 3072},
		{"/registry/replicasets/default/web-6d4bb9c8f7", 2560},
		{"/registry/persistentvolumeclaims/default/data-web-0", 1280},
		{"/registry/persistentvolumes/pvc-9a1c2f60-11e3-4a5b-9c3d-0f2b7a4e6d18", 1536},
		{"/registry/leases/kube-system/kube-scheduler", 320},
		{"/registry/leases/kube-system/kube-controller-manager", 320},
		{"/registry/masterleases/127.0.0.1", 128},
		{"/registry/apiregistration.k8s.io/apiservices/v1.", 768},
	}
	out := map[string][]byte{}
	for _, k := range keys {
		out[k.key] = blob(k.key, k.size)
	}
	// A pod + node-lease + event family per node, the churn-heavy shapes.
	for i := range 12 {
		n := strconv.Itoa(i)
		out["/registry/pods/default/web-"+n] = blob("/registry/pods/default/web-"+n, 4096)
		out["/registry/leases/kube-node-lease/node-"+n] = blob("/registry/leases/kube-node-lease/node-"+n, 288)
		out["/registry/events/default/web-"+n+".18a2f3c4d5e6f7a8"] = blob("/registry/events/default/web-"+n, 896)
	}
	return out
}

// seed writes the dataset through cli and then CHURNS it the way a running cluster
// does: several update rounds over the hot keys (superseded rows), then deletions of the
// short-lived ones (tombstones). It returns the keys expected LIVE and the keys expected
// GONE, with the live keys' final values.
func seed(ctx context.Context, t *testing.T, cli *clientv3.Client) (live map[string][]byte, gone []string) {
	t.Helper()
	live = dataset()
	for k, v := range live {
		if err := create(ctx, cli, k, v); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Churn: three update rounds over the pods and node leases — the objects a real
	// kubelet/VK node rewrites constantly.
	for round := 1; round <= 3; round++ {
		for k := range live {
			if !strings.HasPrefix(k, "/registry/pods/") && !strings.HasPrefix(k, "/registry/leases/kube-node-lease/") {
				continue
			}
			v := blob(k+"-r"+strconv.Itoa(round), len(live[k]))
			if err := update(ctx, cli, k, v); err != nil {
				t.Fatalf("churn update: %v", err)
			}
			live[k] = v
		}
	}
	// Deletions: every event, plus two pods scaled away. Tombstones stay in the table.
	for k := range live {
		if strings.HasPrefix(k, "/registry/events/") {
			gone = append(gone, k)
		}
	}
	gone = append(gone, "/registry/pods/default/web-10", "/registry/pods/default/web-11")
	for _, k := range gone {
		if err := remove(ctx, cli, k); err != nil {
			t.Fatalf("churn delete: %v", err)
		}
		delete(live, k)
	}
	return live, gone
}

// verify round-trips every live key (exact bytes), asserts every deleted key is absent,
// and exercises the prefixed RANGE the apiserver lists with.
func verify(ctx context.Context, t *testing.T, cli *clientv3.Client, live map[string][]byte, gone []string, phase string) {
	t.Helper()
	for k, want := range live {
		r, err := cli.Get(ctx, k)
		if err != nil {
			t.Fatalf("%s: get %s: %v", phase, k, err)
		}
		if len(r.Kvs) != 1 {
			t.Errorf("%s: get %s returned %d kvs, want 1", phase, k, len(r.Kvs))
			continue
		}
		if got := r.Kvs[0].Value; string(got) != string(want) {
			t.Errorf("%s: %s value mismatch (%d bytes vs %d)", phase, k, len(got), len(want))
		}
	}
	for _, k := range gone {
		r, err := cli.Get(ctx, k)
		if err != nil {
			t.Fatalf("%s: get %s: %v", phase, k, err)
		}
		if len(r.Kvs) != 0 {
			t.Errorf("%s: deleted key %s came back", phase, k)
		}
	}
	// The list path: every live pod must be visible under its prefix in ONE range.
	want := 0
	for k := range live {
		if strings.HasPrefix(k, "/registry/pods/") {
			want++
		}
	}
	r, err := cli.Get(ctx, "/registry/pods/", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("%s: range /registry/pods/: %v", phase, err)
	}
	if len(r.Kvs) != want {
		t.Errorf("%s: range /registry/pods/ returned %d keys, want %d", phase, len(r.Kvs), want)
	}
}

// TestKineCompatForward is the migration itself: a production-shaped datastore written
// and churned by the SUPERSEDED pin, then opened and served by the pinned one through
// the SHIPPED DSN (sqliteEndpoint — so the vacuum opt-out and the WAL/busy-timeout
// posture under test are the real ones), with every key round-tripped.
func TestKineCompatForward(t *testing.T) {
	oldBin, newBin := kineBinaries(t)
	ctx := t.Context()
	work := t.TempDir()
	if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
		t.Fatal(err)
	}
	db := StateDBPath(work)

	oldCli, stopOld := serve(t, oldBin, db, oldPinDSNParams)
	live, gone := seed(ctx, t, oldCli)
	verify(ctx, t, oldCli, live, gone, "old pin (same-pin baseline)")
	stopOld()

	newParams := strings.TrimPrefix(sqliteEndpoint(work), "sqlite://"+db)
	newCli, stopNew := serve(t, newBin, db, newParams)
	defer stopNew()
	verify(ctx, t, newCli, live, gone, "FORWARD (new pin over the old pin's datastore)")

	// The new pin must also be able to WRITE the migrated datastore, not merely read it.
	k := "/registry/pods/default/post-migration"
	v := blob(k, 4096)
	if err := create(ctx, newCli, k, v); err != nil {
		t.Fatalf("FORWARD: new pin cannot write the migrated datastore: %v", err)
	}
	if r, err := newCli.Get(ctx, k); err != nil || len(r.Kvs) != 1 || string(r.Kvs[0].Value) != string(v) {
		t.Fatalf("FORWARD: post-migration write did not round-trip: %v", err)
	}
}

// TestKineCompatDowngrade is the rollback half, and it is NOT implied by the forward
// leg: it asks whether the superseded pin can still read a datastore the new pin has
// created, migrated, and written. A red here does not by itself block the migration —
// the pre-migration backup is the supported rollback — but it changes what the upgrade
// docs may promise, so it is measured rather than assumed.
func TestKineCompatDowngrade(t *testing.T) {
	oldBin, newBin := kineBinaries(t)
	ctx := t.Context()
	work := t.TempDir()
	if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
		t.Fatal(err)
	}
	db := StateDBPath(work)

	newParams := strings.TrimPrefix(sqliteEndpoint(work), "sqlite://"+db)
	newCli, stopNew := serve(t, newBin, db, newParams)
	live, gone := seed(ctx, t, newCli)
	verify(ctx, t, newCli, live, gone, "new pin (same-pin baseline)")
	stopNew()

	oldCli, stopOld := serve(t, oldBin, db, oldPinDSNParams)
	defer stopOld()
	verify(ctx, t, oldCli, live, gone, "DOWNGRADE (old pin over the new pin's datastore)")

	k := "/registry/pods/default/post-downgrade"
	v := blob(k, 2048)
	if err := create(ctx, oldCli, k, v); err != nil {
		t.Fatalf("DOWNGRADE: old pin cannot write the datastore: %v", err)
	}
	if r, err := oldCli.Get(ctx, k); err != nil || len(r.Kvs) != 1 || string(r.Kvs[0].Value) != string(v) {
		t.Fatalf("DOWNGRADE: post-downgrade write did not round-trip: %v", err)
	}
}

// TestEnsureKineIntoRestagesStaleMarker exercises the REAL staging path end to end: a
// bin dir holding a kine binary with no marker — the state of every node that booted
// before markers existed — must be re-staged from a fresh build, and must end up with a
// marker vouching for the pinned version and the nocgo variant.
//
// It lives under the kinecompat tag because it performs an actual `go install` of the
// pinned kine (network + module proxy), which is exactly what makes it a proof rather
// than a restatement of the predicate.
func TestEnsureKineIntoRestagesStaleMarker(t *testing.T) {
	bd := t.TempDir()
	if err := os.WriteFile(kinePath(bd), []byte("stale-kine-from-an-older-release"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A marker naming the SUPERSEDED pin, which must not be believed.
	if err := os.WriteFile(kineMarkerPath(bd), []byte("v1.14.2 cgo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	if err := ensureKineInto(ctx, bd, DefaultKineVersion); err != nil {
		t.Fatalf("ensureKineInto over a stale staging: %v", err)
	}

	got, err := os.ReadFile(kinePath(bd))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == "stale-kine-from-an-older-release" {
		t.Fatal("the stale kine was left in place — a pin change would never reach a booted node")
	}
	v, variant := readKineMarker(bd)
	if v != DefaultKineVersion || variant != kineBuildVariant {
		t.Errorf("marker after re-stage = (%q,%q), want (%q,%q)", v, variant, DefaultKineVersion, kineBuildVariant)
	}
	if _, err := os.Stat(kinePath(bd) + ".tmp"); !os.IsNotExist(err) {
		t.Error("the atomic binary stage left its .tmp behind")
	}
	// The re-staged binary is a real, runnable kine.
	out, err := exec.Command(kinePath(bd), "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("re-staged kine is not runnable: %v: %s", err, out)
	}
	// ...and it is the pure-Go build: no mattn/go-sqlite3 in its module list.
	mods, err := exec.Command("go", "version", "-m", kinePath(bd)).CombinedOutput()
	if err != nil {
		t.Fatalf("go version -m: %v: %s", err, mods)
	}
	if strings.Contains(string(mods), "github.com/mattn/go-sqlite3") {
		t.Error("the staged kine links mattn/go-sqlite3 — the build was not CGO_ENABLED=0")
	}
	if !strings.Contains(string(mods), "modernc.org/sqlite") {
		t.Error("the staged kine does not link modernc.org/sqlite — it has no SQLite backend at all")
	}
}
