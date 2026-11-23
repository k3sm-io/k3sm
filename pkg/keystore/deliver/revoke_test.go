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

package deliver

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// deleteUIDs is the UID precondition of every recorded delete of the Secret
// name, "" for a delete without one.
func (h *harness) deleteUIDs(name string) []string {
	var out []string
	for _, a := range h.client.Actions() {
		d, ok := a.(k8stesting.DeleteAction)
		if !ok || d.GetName() != name {
			continue
		}
		uid := ""
		if pre := d.GetDeleteOptions().Preconditions; pre != nil && pre.UID != nil {
			uid = string(*pre.UID)
		}
		out = append(out, uid)
	}
	return out
}

// gone fails unless ns/name is absent.
func (h *harness) gone(t *testing.T, ns, name string) {
	t.Helper()
	_, err := h.client.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("%s/%s is still there after its entry was deleted (err %v); calls %v", ns, name, err, h.verbs())
	}
}

// TestRmDeletesDeliveredSecret: put, deliver, rm, sweep, and the Secret is
// gone, deleted once under a precondition on the UID its create returned,
// and the delete is logged with names only.
func TestRmDeletesDeliveredSecret(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("revoked-value"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	uid := string(h.secret(t, "payments", "api-token").UID)
	h.store.rm("api-token")
	h.client.ClearActions()
	h.r.Sweep(ctx)
	h.gone(t, "payments", "api-token")
	if got := h.deleteUIDs("api-token"); len(got) != 1 || got[0] != uid {
		t.Fatalf("deletes %q, want one under the precondition %q", got, uid)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
	logs := h.logs.String()
	if !strings.Contains(logs, "deleted the Secret; its keystore entry no longer exists") ||
		!strings.Contains(logs, "secret=api-token") || !strings.Contains(logs, "namespace=payments") {
		t.Fatalf("the delete is not logged with its names\n%s", logs)
	}
	if strings.Contains(logs, "revoked-value") {
		t.Fatalf("the log carries the value\n%s", logs)
	}
	// The next sweep finds nothing to delete and creates nothing.
	h.client.ClearActions()
	h.r.Sweep(ctx)
	for _, v := range h.verbs() {
		if v != "get/secrets" {
			t.Fatalf("a sweep after the delete made %s: %v", v, h.verbs())
		}
	}
}

// TestRmKeepsSecretWhenAbsenceUnconfirmed: Current's ErrNotFound alone
// deletes nothing; a store that cannot confirm the entry is gone (a missing
// entries' directory) keeps the Secret, and once it confirms, the next sweep
// deletes it.
func TestRmKeepsSecretWhenAbsenceUnconfirmed(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.store.rm("api-token")
	h.store.absentErr = fs.ErrNotExist
	h.client.ClearActions()
	h.r.Sweep(ctx)
	if got := h.deleteUIDs("api-token"); len(got) != 0 {
		t.Fatalf("an unconfirmed absence drew deletes %q", got)
	}
	h.secret(t, "payments", "api-token")
	if !strings.Contains(h.logs.String(), "absence cannot be confirmed") {
		t.Fatalf("the kept Secret is not logged\n%s", h.logs.String())
	}
	h.store.absentErr = nil
	h.r.Sweep(ctx)
	h.gone(t, "payments", "api-token")
}

// TestRmDeletesUnmarkedSecretWithWarning: the recorded UID decides, not the
// marks. A Secret this server created whose label or version annotation was
// stripped is still deleted when its entry goes, and the missing mark is
// logged at Warn.
func TestRmDeletesUnmarkedSecretWithWarning(t *testing.T) {
	h := newHarness(t, true, false)
	for _, n := range []string{"marked", "no-label", "no-version"} {
		h.store.set(n, 1, []byte("v-"+n))
	}
	h.declare(t,
		Target{Entry: "system/marked", Namespace: "payments"},
		Target{Entry: "system/no-label", Namespace: "payments"},
		Target{Entry: "system/no-version", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	uids := map[string]string{}
	for _, n := range []string{"marked", "no-label", "no-version"} {
		uids[n] = string(h.secret(t, "payments", n).UID)
	}
	s := h.secret(t, "payments", "no-label")
	delete(s.Labels, LabelKey)
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	s = h.secret(t, "payments", "no-version")
	delete(s.Annotations, VersionAnnotation)
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"marked", "no-label", "no-version"} {
		h.store.rm(n)
	}
	h.client.ClearActions()
	h.r.Sweep(ctx)
	for _, n := range []string{"marked", "no-label", "no-version"} {
		h.gone(t, "payments", n)
		if got := h.deleteUIDs(n); len(got) != 1 || got[0] != uids[n] {
			t.Fatalf("%s deletes %q, want one under the precondition %q", n, got, uids[n])
		}
	}
	logs := h.logs.String()
	if n := strings.Count(logs, `level=WARN msg="keystore delivery: the Secret of a deleted entry lacks the marks`); n != 2 {
		t.Fatalf("got %d Warn lines for the two unmarked Secrets, want 2\n%s", n, logs)
	}
}

// TestRmKeepsSecretOfAnotherUID: a Secret recreated by someone else with
// every mark, whose UID is not the recorded one, draws no delete; a delete
// whose UID precondition the apiserver refuses (the Secret was replaced
// after the Get) deletes nothing; a plain one beside them is deleted.
func TestRmKeepsSecretOfAnotherUID(t *testing.T) {
	h := newHarness(t, true, false)
	for _, n := range []string{"plain", "recreated", "raced"} {
		h.store.set(n, 1, []byte("v-"+n))
	}
	h.declare(t,
		Target{Entry: "system/plain", Namespace: "payments"},
		Target{Entry: "system/recreated", Namespace: "payments"},
		Target{Entry: "system/raced", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	old := h.secret(t, "payments", "recreated")
	if err := h.client.CoreV1().Secrets("payments").Delete(ctx, "recreated", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	again := secretObj("payments", "recreated", old.Labels, map[string][]byte{DefaultDataKey: []byte("tenant's")})
	again.Annotations = old.Annotations
	again.UID = "tenant-2"
	if _, err := h.client.CoreV1().Secrets("payments").Create(ctx, again, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	racedUID := string(h.secret(t, "payments", "raced").UID)
	h.client.PrependReactor("delete", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.DeleteAction).GetName() != "raced" {
			return false, nil, nil
		}
		return true, nil, apierrors.NewConflict(corev1.Resource("secrets"), "raced", errors.New("Precondition failed: UID in precondition"))
	})
	for _, n := range []string{"plain", "recreated", "raced"} {
		h.store.rm(n)
	}
	h.client.ClearActions()
	h.r.Sweep(ctx)
	h.gone(t, "payments", "plain")
	if got := h.deleteUIDs("recreated"); len(got) != 0 {
		t.Fatalf("a Secret of another UID drew deletes %q", got)
	}
	if got := h.secret(t, "payments", "recreated"); got.UID != "tenant-2" || string(got.Data[DefaultDataKey]) != "tenant's" {
		t.Fatalf("the recreated Secret changed: uid %q data %q", got.UID, got.Data[DefaultDataKey])
	}
	if got := h.deleteUIDs("raced"); len(got) != 1 || got[0] != racedUID {
		t.Fatalf("raced deletes %q, want one under the precondition %q", got, racedUID)
	}
	h.secret(t, "payments", "raced")
	logs := h.logs.String()
	if !strings.Contains(logs, "not created by this server") || !strings.Contains(logs, "replaced before it could be deleted") {
		t.Fatalf("the kept Secrets are not logged\n%s", logs)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
}

// TestRmLeavesLiveKeySecret: deleting one entry deletes only its Secret; a
// live entry's Secret draws no update and no delete, and keeps its UID and
// value.
func TestRmLeavesLiveKeySecret(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("revoked", 1, []byte("old"))
	h.store.set("live", 1, []byte("live-value"))
	h.declare(t,
		Target{Entry: "system/revoked", Namespace: "payments"},
		Target{Entry: "system/live", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	before := h.secret(t, "payments", "live")
	h.store.rm("revoked")
	h.client.ClearActions()
	h.r.Sweep(ctx)
	h.gone(t, "payments", "revoked")
	if got := h.deleteUIDs("live"); len(got) != 0 {
		t.Fatalf("the live Secret drew deletes %q", got)
	}
	if n := h.updates(); n != 0 {
		t.Fatalf("a sweep after the rm made %d updates: %v", n, h.verbs())
	}
	after := h.secret(t, "payments", "live")
	if after.UID != before.UID || string(after.Data[DefaultDataKey]) != "live-value" {
		t.Fatalf("the live Secret changed: uid %q (was %q) data %q", after.UID, before.UID, after.Data[DefaultDataKey])
	}
}

// TestRmDeletedAfterUndeliver: rm, then undeliver before a sweep, then a
// sweep: the withdrawn target's Secret is deleted and its record dropped. A
// live entry undelivered in the same change keeps its Secret.
func TestRmDeletedAfterUndeliver(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("revoked", 1, []byte("old"))
	h.store.set("live", 1, []byte("live-value"))
	h.declare(t,
		Target{Entry: "system/revoked", Namespace: "payments"},
		Target{Entry: "system/live", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	uid := string(h.secret(t, "payments", "revoked").UID)
	h.store.rm("revoked")
	h.declare(t)
	h.client.ClearActions()
	h.r.Sweep(ctx)
	h.gone(t, "payments", "revoked")
	if got := h.deleteUIDs("revoked"); len(got) != 1 || got[0] != uid {
		t.Fatalf("deletes %q, want one under the precondition %q", got, uid)
	}
	if got := h.deleteUIDs("live"); len(got) != 0 {
		t.Fatalf("an undeliver of a live entry drew deletes %q", got)
	}
	if got := string(h.secret(t, "payments", "live").Data[DefaultDataKey]); got != "live-value" {
		t.Fatalf("the live Secret now holds %q", got)
	}
	st := h.state(t)
	if st.UID("payments", "revoked") != "" || st.UID("payments", "live") != "" {
		t.Fatalf("the withdrawn records were not dropped: %+v", st)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
}

// TestRevokeWhileEncryptionOff: with plaintext delivery refused, a Secret
// delivered under the override is still revoked once its entry is deleted,
// after the restarted server's first sweep has seen the keystore; nothing is
// created or updated.
func TestRevokeWhileEncryptionOff(t *testing.T) {
	h := newHarness(t, false, true)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	uid := string(h.secret(t, "payments", "api-token").UID)
	h.store.rm("api-token")
	h.client.ClearActions()
	h.store.reads = 0
	restarted := h.reconciler(false, false)
	restarted.Sweep(ctx)
	h.secret(t, "payments", "api-token") // the first sweep since start holds
	restarted.Sweep(ctx)
	h.gone(t, "payments", "api-token")
	if got := h.deleteUIDs("api-token"); len(got) != 1 || got[0] != uid {
		t.Fatalf("deletes %q, want one under the precondition %q", got, uid)
	}
	for _, v := range h.verbs() {
		if v == "create/secrets" || v == "update/secrets" {
			t.Fatalf("encryption off drew %s: %v", v, h.verbs())
		}
	}
	if h.store.reads != 0 {
		t.Fatalf("encryption off: a value was read %d times", h.store.reads)
	}
}

// TestRevokedTargetIsQuiet: once its Secret was revoked, a target whose entry
// is still gone logs nothing on later sweeps.
func TestRevokedTargetIsQuiet(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.store.rm("api-token")
	h.r.Sweep(ctx)
	h.gone(t, "payments", "api-token")
	before := h.logs.String()
	h.r.Sweep(ctx)
	h.r.Sweep(ctx)
	if after := h.logs.String(); after != before {
		t.Fatalf("a revoked target logged again:\n%s", strings.TrimPrefix(after, before))
	}
	if strings.Contains(h.logs.String(), "cannot read the entry") {
		t.Fatalf("a revoked target warned that it cannot read the entry\n%s", h.logs.String())
	}
}

// TestRevokeBreaker: when more than max(3, 25%) of the recorded Secrets'
// entries go at once, none is deleted and one Error carries the count; once
// the absent set is back to the limit, they are.
func TestRevokeBreaker(t *testing.T) {
	h := newHarness(t, true, false)
	names := []string{"a", "b", "c", "d", "e"}
	var targets []Target
	for _, n := range names {
		h.store.set(n, 1, []byte("v-"+n))
		targets = append(targets, Target{Entry: "system/" + n, Namespace: "payments"})
	}
	h.declare(t, targets...)
	ctx := context.Background()
	h.r.Sweep(ctx)
	for _, n := range names[:4] {
		h.store.rm(n)
	}
	h.client.ClearActions()
	h.r.Sweep(ctx)
	h.r.Sweep(ctx)
	for _, v := range h.verbs() {
		if v == "delete/secrets" {
			t.Fatalf("4 of 5 entries gone drew a delete: %v", h.verbs())
		}
	}
	logs := h.logs.String()
	if n := strings.Count(logs, "level=ERROR msg=\"keystore delivery: 4 of 5 delivered Secrets' entries are gone at once"); n != 1 {
		t.Fatalf("got %d breaker Errors over two sweeps, want 1\n%s", n, logs)
	}
	h.store.set("a", 1, []byte("v-a"))
	h.r.Sweep(ctx)
	for _, n := range names[1:4] {
		h.gone(t, "payments", n)
	}
	h.secret(t, "payments", "a")
	h.secret(t, "payments", "e")
}

// TestRevokeHeldAcrossKeystoreRestore: a real store; three entries
// delivered, then an older keystore/ holding only one of them is swapped in,
// as the restore steps do. The sweep that first sees it deletes nothing and
// logs one Error naming the change.
func TestRevokeHeldAcrossKeystoreRestore(t *testing.T) {
	h, s, dir := newRealStoreHarness(t)
	ctx := context.Background()
	mustStorePut(t, s, "a")
	older := dir + ".older"
	copyTree(t, dir, older)
	mustStorePut(t, s, "b")
	mustStorePut(t, s, "c")
	h.declare(t,
		Target{Entry: "system/a", Namespace: "payments"},
		Target{Entry: "system/b", Namespace: "payments"},
		Target{Entry: "system/c", Namespace: "payments"})
	h.r.Sweep(ctx)
	for _, n := range []string{"a", "b", "c"} {
		h.secret(t, "payments", n)
	}
	if err := os.Rename(dir, dir+".pre-restore"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(older, dir); err != nil {
		t.Fatal(err)
	}
	h.client.ClearActions()
	h.r.Sweep(ctx)
	if got := h.deleteUIDs("b"); len(got) != 0 {
		t.Fatalf("the restore's first sweep deleted b: %v", h.verbs())
	}
	if got := h.deleteUIDs("c"); len(got) != 0 {
		t.Fatalf("the restore's first sweep deleted c: %v", h.verbs())
	}
	for _, n := range []string{"a", "b", "c"} {
		h.secret(t, "payments", n)
	}
	logs := h.logs.String()
	if n := strings.Count(logs, "level=ERROR msg=\"keystore delivery: the keystore directory changed"); n != 1 {
		t.Fatalf("got %d Errors naming the keystore change, want 1\n%s", n, logs)
	}
}

// TestRmDeletesWithRealStore: a real store whose keystore/ stays the same;
// a plain rm of one entry deletes its Secret on the next sweep and leaves the
// other's.
func TestRmDeletesWithRealStore(t *testing.T) {
	h, s, _ := newRealStoreHarness(t)
	ctx := context.Background()
	mustStorePut(t, s, "a")
	mustStorePut(t, s, "b")
	h.declare(t,
		Target{Entry: "system/a", Namespace: "payments"},
		Target{Entry: "system/b", Namespace: "payments"})
	h.r.Sweep(ctx)
	h.secret(t, "payments", "a")
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	h.r.Sweep(ctx)
	h.gone(t, "payments", "a")
	h.secret(t, "payments", "b")
}

// state reads the harness's state file.
func (h *harness) state(t *testing.T) State {
	t.Helper()
	euid := uint32(os.Geteuid())
	st, err := ReadState(filepath.Join(h.dir, StateFileName), OpenNoFollow, StateDirCheck(euid), StateFileCheck(euid))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// newRealStoreHarness is newHarness over a keystore.FileStore in a temp
// tree, owned by the running user, who stands in for both the service user
// and root (the keystore package's own tests do the same non-root). It
// returns the store and its entries' directory. A root run skips: the store
// would need a separate service user.
func newRealStoreHarness(t *testing.T) (*harness, *keystore.FileStore, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a real store as root needs a service user; covered by the fake store")
	}
	h := newHarness(t, true, false)
	data := t.TempDir()
	server := filepath.Join(data, "server")
	if err := os.Mkdir(server, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(server, "keystore")
	s := keystore.New(keystore.Config{
		Dir:       dir,
		MasterDir: filepath.Join(server, "cred", "keystore-master"),
		UID:       uint32(os.Getuid()),
		GID:       uint32(os.Getgid()),
		DataRoot:  data,
		FloorUID:  os.Getuid(),
		FloorGID:  os.Getgid(),
	})
	h.r.store = s
	return h, s, dir
}

func mustStorePut(t *testing.T, s *keystore.FileStore, name string) {
	t.Helper()
	if _, err := s.Put(context.Background(), name, keystore.KindOpaque, []byte("v-"+name)); err != nil {
		t.Fatalf("Put %s: %v", name, err)
	}
}

// copyTree copies the directory src to dst, keeping each file's and
// directory's permission bits, as a backup taken with ditto would.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := os.Mkdir(to, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(to, fi.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(to, b, fi.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(to, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}
