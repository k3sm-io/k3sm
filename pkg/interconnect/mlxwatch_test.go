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

package interconnect

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// mlxModelObject is a sharded MLXModel over path at generation gen.
func mlxModelObject(path string, gen int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "mlx.k3sm.io/v1alpha1",
		"kind":       "MLXModel",
		"metadata":   map[string]any{"name": "ring", "namespace": "ml", "uid": "u-ring", "generation": gen},
		"spec":       map[string]any{"model": "m", "distributed": map[string]any{"ranks": int64(2), "interconnect": path}},
	}}
}

func fakeMLXModels() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		mlxModelGVR: "MLXModelList",
		GVR:         "InterconnectList",
	})
}

// waitNudge waits for one signal on ch, failing after within.
func waitNudge(t *testing.T, ch <-chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("no reconcile within %s of %s", within, what)
	}
}

// drain discards signals until none arrives for quiet.
func drain(ch <-chan struct{}, quiet time.Duration) {
	for {
		select {
		case <-ch:
		case <-time.After(quiet):
			return
		}
	}
}

// TestMLXModelChangeNudgesTheResolver pins that the leading resolver
// reconciles on an MLXModel add, spec change and delete, well inside
// ResyncInterval, so a model flipped onto the interconnect is published in the
// nodes' desired annotation before its gang is placed.
func TestMLXModelChangeNudgesTheResolver(t *testing.T) {
	dyn := fakeMLXModels()
	cs := kubefake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "mac-a"}})
	reconciled := make(chan struct{}, 64)
	r := NewResolver(ResolverConfig{
		Client: cs,
		Store:  Store{Client: dyn},
		Indices: func(context.Context) (Indices, error) {
			reconciled <- struct{}{}
			return Indices{Index: map[string]int{"mac-a": 0}}, nil
		},
		MLXModels:     MLXModelLister(dyn),
		MLXModelWatch: dyn,
		Recorder:      record.NewFakeRecorder(64),
		Log:           slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.lead(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	// Well inside ResyncInterval: only a nudge reconciles this soon.
	const within = ResyncInterval / 3
	waitNudge(t, reconciled, within, "the lead starting")
	drain(reconciled, 500*time.Millisecond)

	res := dyn.Resource(mlxModelGVR).Namespace("ml")
	if _, err := res.Create(ctx, mlxModelObject("network", 1), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitNudge(t, reconciled, within, "an MLXModel add")
	drain(reconciled, 500*time.Millisecond)

	if _, err := res.Update(ctx, mlxModelObject("thunderbolt", 2), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitNudge(t, reconciled, within, "an MLXModel spec change")
	drain(reconciled, 500*time.Millisecond)

	if err := res.Delete(ctx, "ring", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitNudge(t, reconciled, within, "an MLXModel delete")
}

// TestWatchMLXModelsNudgesOnSpecChangesOnly pins the handler's filter: an add,
// a generation change and a delete nudge; a status-only update does not.
func TestWatchMLXModelsNudgesOnSpecChangesOnly(t *testing.T) {
	dyn := fakeMLXModels()
	nudges := make(chan struct{}, 16)
	stop := make(chan struct{})
	shutdown, synced := watchMLXModels(dyn, func() { nudges <- struct{}{} }, stop)
	defer func() {
		close(stop)
		shutdown()
	}()
	if !cache.WaitForCacheSync(stop, synced) {
		t.Fatal("the MLXModel informer did not sync")
	}
	ctx := context.Background()
	res := dyn.Resource(mlxModelGVR).Namespace("ml")
	step := func(what string, do func() error) {
		t.Helper()
		if err := do(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	step("create", func() error {
		_, err := res.Create(ctx, mlxModelObject("network", 1), metav1.CreateOptions{})
		return err
	})
	step("status-only update", func() error {
		u := mlxModelObject("network", 1)
		u.Object["status"] = map[string]any{"phase": "Pending"}
		_, err := res.Update(ctx, u, metav1.UpdateOptions{})
		return err
	})
	step("spec change", func() error {
		_, err := res.Update(ctx, mlxModelObject("thunderbolt", 2), metav1.UpdateOptions{})
		return err
	})
	step("delete", func() error { return res.Delete(ctx, "ring", metav1.DeleteOptions{}) })

	// The handler sees events in order, so once the delete's nudge is in, every
	// earlier event has been handled: exactly three nudges, none for the status.
	for i := range 3 {
		waitNudge(t, nudges, 5*time.Second, fmt.Sprintf("event %d", i+1))
	}
	select {
	case <-nudges:
		t.Error("a status-only update nudged the resolver")
	case <-time.After(200 * time.Millisecond):
	}
}
