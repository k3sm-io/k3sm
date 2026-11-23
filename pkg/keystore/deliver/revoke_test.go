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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
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

// TestRmKeepsUnmarkedSecret: a Secret this server created whose label or
// annotations were stripped is not deleted when its entry goes, and the
// reason is logged; a marked one beside it is.
func TestRmKeepsUnmarkedSecret(t *testing.T) {
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
	h.gone(t, "payments", "marked")
	for _, n := range []string{"no-label", "no-version"} {
		if got := h.deleteUIDs(n); len(got) != 0 {
			t.Fatalf("the unmarked %s drew deletes %q", n, got)
		}
		if got := string(h.secret(t, "payments", n).Data[DefaultDataKey]); got != "v-"+n {
			t.Fatalf("the unmarked %s now holds %q", n, got)
		}
	}
	logs := h.logs.String()
	if strings.Count(logs, "lacks the marks a delivery sets") != 2 {
		t.Fatalf("each unmarked Secret is not logged once\n%s", logs)
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
