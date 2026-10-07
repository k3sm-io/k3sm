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

package vkadapter

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestHeartbeatRecordsOnlySuccessfulWrites pins what Node.Heartbeat means: the
// time of the last write that LANDED. A failed status PATCH or Lease update
// leaves the recorded time where it was, and a PATCH of the node object itself
// (not its status) is not a status post.
func TestHeartbeatRecordsOnlySuccessfulWrites(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n"}},
		&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: corev1.NamespaceNodeLease}},
	)
	fail := true
	cs.PrependReactor("*", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if fail && (a.GetVerb() == "patch" || a.GetVerb() == "update") {
			return true, nil, errors.New("injected")
		}
		return false, nil, nil
	})
	now := time.Unix(1000, 0)
	rec := &heartbeatRecorder{now: func() time.Time { return now }}
	nodes := recordingNodes{NodeInterface: cs.CoreV1().Nodes(), rec: rec}
	leases := recordingLeases{LeaseInterface: cs.CoordinationV1().Leases(corev1.NamespaceNodeLease), rec: rec}
	patch := []byte(`{"status":{"phase":"Running"}}`)

	if _, err := nodes.Patch(ctx, "n", types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status"); err == nil {
		t.Fatal("injected PATCH failure did not fail")
	}
	if _, err := leases.Update(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: corev1.NamespaceNodeLease}}, metav1.UpdateOptions{}); err == nil {
		t.Fatal("injected Lease update failure did not fail")
	}
	if hb := rec.snapshot(); !hb.StatusPosted.IsZero() || !hb.LeaseRenewed.IsZero() {
		t.Fatalf("after failed writes Heartbeat = %+v, want zero", hb)
	}

	fail = false
	if _, err := nodes.Patch(ctx, "n", types.StrategicMergePatchType, []byte(`{"metadata":{"labels":{"a":"b"}}}`), metav1.PatchOptions{}); err != nil {
		t.Fatalf("object PATCH: %v", err)
	}
	if hb := rec.snapshot(); !hb.StatusPosted.IsZero() {
		t.Fatalf("a PATCH of the node object (no status subresource) was recorded as a status post: %+v", hb)
	}
	if _, err := nodes.Patch(ctx, "n", types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status"); err != nil {
		t.Fatalf("status PATCH: %v", err)
	}
	if _, err := leases.Update(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: corev1.NamespaceNodeLease}}, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Lease update: %v", err)
	}
	if hb := rec.snapshot(); !hb.StatusPosted.Equal(now) || !hb.LeaseRenewed.Equal(now) {
		t.Fatalf("after successful writes Heartbeat = %+v, want both at %v", hb, now)
	}
}

// blockingPing is a NodeProvider whose Ping blocks until released, counting
// how many calls are in flight.
type blockingPing struct {
	NaiveNodeProvider
	release chan struct{}
	started chan struct{}
	err     error
}

func (b *blockingPing) Ping(context.Context) error {
	b.started <- struct{}{}
	<-b.release
	return b.err
}

// TestPingGuard pins the guard's three outcomes: a Ping that has not answered
// within the budget is reported as success (so the heartbeat goes ahead), a
// later ping joins the call still in flight instead of starting another, and a
// Ping that answers within the budget has its own answer returned, error
// included.
func TestPingGuard(t *testing.T) {
	inner := &blockingPing{release: make(chan struct{}), started: make(chan struct{}, 4)}
	g := &pingGuard{NodeProvider: inner, budget: 50 * time.Millisecond, log: newVKLogger(discardLogger())}

	if err := g.Ping(context.Background()); err != nil {
		t.Fatalf("hung Ping through the guard = %v, want nil after the budget", err)
	}
	if err := g.Ping(context.Background()); err != nil {
		t.Fatalf("second hung Ping = %v, want nil", err)
	}
	if got := len(inner.started); got != 1 {
		t.Fatalf("provider Ping started %d times while the first was in flight, want 1", got)
	}
	<-inner.started
	inner.err = errors.New("provider says no")
	close(inner.release)
	// The first call drains; a new one answers at once with the provider's error.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := g.Ping(context.Background())
		if err != nil {
			if err.Error() != "provider says no" {
				t.Fatalf("Ping = %v, want the provider's error", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the guard never returned the provider's own answer")
		}
		select {
		case <-inner.started:
		default:
		}
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
