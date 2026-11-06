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

package provider

import (
	"context"
	"slices"
	"testing"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// TestReplacedPodStopsBeforeItsSuccessorStarts drives the replacement of a same-name pod
// (vkadapter.ReplaceRecreatedPods, whose order under a real Virtual Kubelet controller
// TestRecreateCoalescedWithDeleteRemovesOldPod pins) over this provider: the runtime is
// told to stop the old UID with its own grace, and hears no create of the new UID until
// that stop has returned. Fails when the old pod is left to the orphan reaper, or the
// stop takes the successor's grace or none.
func TestReplacedPodStopsBeforeItsSuccessorStarts(t *testing.T) {
	ctx := context.Background()
	r, f := newRuntimedFake(t)
	grace := int64(45)
	old := runtimedPod("default", "web")
	old.UID = "old"
	old.Spec.TerminationGracePeriodSeconds = &grace
	if err := r.CreatePod(ctx, old); err != nil {
		t.Fatalf("CreatePod of the old pod: %v", err)
	}

	successor := runtimedPod("default", "web")
	successor.UID = "new"
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := indexer.Add(successor); err != nil {
		t.Fatalf("seed the lister: %v", err)
	}
	h := vkadapter.ReplaceRecreatedPods(NewVKProvider(r, "n"), corev1listers.NewPodLister(indexer))

	if got, err := h.GetPod(ctx, "default", "web"); !vkadapter.IsNotFound(err) {
		t.Fatalf("GetPod with the name re-created = %v, %v, want NotFound: Virtual Kubelet would not create the successor", got, err)
	}

	release := f.holdDelete()
	defer release()
	created := make(chan error, 1)
	go func() { created <- h.CreatePod(ctx, successor.DeepCopy()) }()
	waitRestart(t, "the old pod's stop to be entered", func() bool { return f.deleteCount() == 1 })
	if f.hasCreated("new") || len(created) != 0 {
		t.Fatal("the successor started inside the old pod's stop")
	}
	if got := f.deleteRecords(); !slices.Equal(got, []string{"old"}) {
		t.Errorf("runtime deletes = %v, want the old UID alone", got)
	}
	release()
	if err := awaitErr(t, created, "the successor's create"); err != nil {
		t.Fatalf("the successor's create: %v", err)
	}

	f.mu.Lock()
	graces := slices.Clone(f.graces)
	f.mu.Unlock()
	if !slices.Equal(graces, []int64{grace}) {
		t.Errorf("runtime delete graces = %v, want the old pod's own [%d]", graces, grace)
	}
	if !f.hasCreated("new") {
		t.Error("the runtime holds no guest for the successor")
	}
	if r.trackByID("old") != nil {
		t.Error("the old pod still has a track")
	}
	if r.trackByID("new") == nil {
		t.Error("the successor has no track")
	}
	got, err := h.GetPod(ctx, "default", "web")
	if err != nil || got.UID != successor.UID {
		t.Errorf("GetPod after the replacement = %v, %v, want the successor", got, err)
	}
}
