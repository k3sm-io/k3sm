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

package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	crdconfig "k3sm.io/apis/config/crd"
	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
)

// fakeCRDServer builds a fake apiextensions API server that performs real
// server-side apply and, like the real one, marks a CRD Established shortly after
// it appears.
//
// The stock fakes cannot do the apply: NewClientset's generated type converter
// carries an empty schema for the apiextensions types, and NewSimpleClientset
// degrades an apply to a strategic merge patch. A field-managed tracker with a
// deduced type converter gives real apply semantics on a schema this client-go
// has no typed model for.
func fakeCRDServer(t *testing.T) *apiextensionsfake.Clientset {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiextensions types: %v", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	tracker := k8stesting.NewFieldManagedObjectTracker(scheme, codecs.UniversalDecoder(), managedfields.NewDeducedTypeConverter())

	cs := apiextensionsfake.NewSimpleClientset()
	cs.PrependReactor("*", "*", k8stesting.ObjectReaction(tracker))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			client := cs.ApiextensionsV1().CustomResourceDefinitions()
			list, err := client.List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for i := range list.Items {
				item := list.Items[i]
				if hasEstablished(&item) {
					continue
				}
				item.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{
					{Type: apiextensionsv1.NamesAccepted, Status: apiextensionsv1.ConditionTrue, Reason: "NoConflicts"},
					{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue, Reason: "InitialNamesAccepted"},
				}
				_, _ = client.UpdateStatus(ctx, &item, metav1.UpdateOptions{})
			}
		}
	}()
	return cs
}

func hasEstablished(c *apiextensionsv1.CustomResourceDefinition) bool {
	for _, cond := range c.Status.Conditions {
		if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
			return true
		}
	}
	return false
}

// TestRunEnsuresTheMLXModelCRDAndNothingElse is the Res. 10 guard seen from the
// operator's side: starting the controller creates EXACTLY ONE
// CustomResourceDefinition, the MLXModel one.
//
// The MeshPeer CRD ships in the same apis directory as the MLXModel manifest and
// is applied out-of-band by the existing bootstrap path. If this ensure ever
// widened — an embed glob, a "the CRDs k3sm applies" list — MeshPeer would be
// adopted as a side effect, giving that bootstrap path a second, competing
// writer with a forced field manager and no diff anywhere to review it. This test
// is what makes that widening loud.
func TestRunEnsuresTheMLXModelCRDAndNothingElse(t *testing.T) {
	crdClient := fakeCRDServer(t)
	h := newHarness(t, model(), func(c *Config) { c.CRD = crdClient })

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- h.ctrl.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		list, err := crdClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
		return err == nil && len(list.Items) > 0
	}, "the mlxmodels CRD was never applied")

	list, err := crdClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list crds: %v", err)
	}
	if len(list.Items) != 1 {
		var names []string
		for _, item := range list.Items {
			names = append(names, item.Name)
		}
		t.Fatalf("the operator applied %d CRDs (%v), want exactly the mlxmodels one", len(list.Items), names)
	}
	if got := list.Items[0].Name; got != crdconfig.MLXModelCRDName {
		t.Errorf("applied CRD %q, want %q", got, crdconfig.MLXModelCRDName)
	}
	if list.Items[0].Spec.Group == "net.k3sm.io" {
		t.Error("the operator applied the MeshPeer CRD; adopting it owes a mesh-regression check and must not be a side effect")
	}

	// The drain contract: Run returns only after the worker has stopped, so the
	// control plane can be torn down knowing no write is in flight.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned %v after a clean cancel, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled; the drain would hang shutdown")
	}
}

// TestRunReconcilesEveryExistingModelOnStart pins the recovery path: the
// informer's initial sync re-delivers every existing MLXModel as an Add, so a
// control-plane restart re-reconciles each one and strands none.
func TestRunReconcilesEveryExistingModelOnStart(t *testing.T) {
	h := newHarness(t, model(), nil) // no CRD client: something else established it

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- h.ctrl.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		sts, err := h.kube.AppsV1().StatefulSets(testNamespace).Get(ctx, testModelName, metav1.GetOptions{})
		return err == nil && sts != nil
	}, "the pre-existing MLXModel was never reconciled after start")

	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestStatefulSetRevisionBumpTriggersReconcile closes the revision-resync
// ceiling: a roll that moves the owned StatefulSet's status.updateRevision while
// no pod changes yet must reconcile the owning MLXModel now, not at the next
// resync. Without the StatefulSet watch the old-revision replica keeps the model
// reading Serving for up to a full resync period after the template changed.
func TestStatefulSetRevisionBumpTriggersReconcile(t *testing.T) {
	t.Run("revision_bump_without_pod_churn_reconciles_the_owner", func(t *testing.T) {
		h := newHarness(t, model(), nil)

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- h.ctrl.Run(ctx) }()
		defer func() {
			cancel()
			select {
			case <-runDone:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after ctx was cancelled")
			}
		}()

		// The initial sync reconciles the model, which applies the StatefulSet
		// carrying the controller ownerReference.
		waitFor(t, 5*time.Second, func() bool { return h.statefulSetOrNil(ctx) != nil },
			"the model was never reconciled into a StatefulSet")

		// Stand in for the upstream StatefulSet controller: publish the current
		// revision, then let one replica on it come up Ready. The pod event
		// reconciles the model to Serving.
		h.setUpdateRevision(t, testPodRevision)
		if _, err := h.kube.CoreV1().Pods(testNamespace).Create(ctx,
			servingPod(testModelName+"-0", corev1.PodRunning, true), metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed pod: %v", err)
		}
		waitFor(t, 5*time.Second, func() bool { return h.readyReason(ctx) == mlx.ReasonServing },
			"the model never reached Serving on a current-revision ready replica")

		// Let the self-triggered reconciles (each status write is a watch event
		// that re-enqueues the model) die out, so nothing already queued can
		// observe the bump below and pass this test by accident.
		h.waitQuiescent(t, 300*time.Millisecond)

		// The roll: the template revision moves and NO pod changes. Only the
		// StatefulSet event can tell the operator its Ready replica is now stale.
		h.setUpdateRevision(t, "qwen-new0000000")
		waitFor(t, 5*time.Second, func() bool { return h.readyReason(ctx) == mlx.ReasonPending },
			"the updateRevision bump never reconciled the owning model (no StatefulSet watch)")
	})

	// The enqueue decision itself, checked on an idle controller so the queue
	// length is exact. Every StatefulSet below is named after the model: the
	// name convention alone must never be enough to enqueue it.
	modelOwner := metav1.OwnerReference{
		APIVersion: mlxv1alpha1.SchemeGroupVersion.String(),
		Kind:       mlxModelKind,
		Name:       testModelName,
		UID:        types.UID("11111111-2222-3333-4444-555555555555"),
		Controller: ptr.To(true),
	}
	withOwner := func(mutate func(*metav1.OwnerReference)) []metav1.OwnerReference {
		ref := modelOwner
		if mutate != nil {
			mutate(&ref)
		}
		return []metav1.OwnerReference{ref}
	}
	tests := []struct {
		name     string
		owners   []metav1.OwnerReference
		oldRev   string
		newRev   string
		oldGen   int64
		newGen   int64
		wantKeys []string
	}{
		{name: "owned_revision_bump_enqueues_the_owner", owners: withOwner(nil),
			oldRev: "r1", newRev: "r2", wantKeys: []string{key()}},
		{name: "owned_generation_bump_enqueues_the_owner", owners: withOwner(nil),
			oldRev: "r1", newRev: "r1", oldGen: 1, newGen: 2, wantKeys: []string{key()}},
		{name: "owner_named_differently_enqueues_the_owner_not_the_name", owners: withOwner(func(r *metav1.OwnerReference) { r.Name = "other" }),
			oldRev: "r1", newRev: "r2", wantKeys: []string{testNamespace + "/other"}},
		{name: "unchanged_revision_and_generation_does_not_enqueue", owners: withOwner(nil),
			oldRev: "r1", newRev: "r1"},
		{name: "forged_name_without_an_owner_ref_does_not_enqueue",
			oldRev: "r1", newRev: "r2"},
		{name: "non_controller_owner_ref_does_not_enqueue", owners: withOwner(func(r *metav1.OwnerReference) { r.Controller = ptr.To(false) }),
			oldRev: "r1", newRev: "r2"},
		{name: "controller_of_another_kind_does_not_enqueue", owners: withOwner(func(r *metav1.OwnerReference) { r.Kind = "Deployment"; r.APIVersion = "apps/v1" }),
			oldRev: "r1", newRev: "r2"},
		{name: "mlxmodel_kind_in_another_group_does_not_enqueue", owners: withOwner(func(r *metav1.OwnerReference) { r.APIVersion = "example.com/v1" }),
			oldRev: "r1", newRev: "r2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, model(), nil)
			sts := func(rev string, gen int64) *appsv1.StatefulSet {
				return &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:            mlx.StatefulSetName(testModelName),
						Namespace:       testNamespace,
						Labels:          mlx.Labels(testModelName),
						Generation:      gen,
						OwnerReferences: tt.owners,
					},
					Status: appsv1.StatefulSetStatus{UpdateRevision: rev},
				}
			}
			h.ctrl.enqueueStatefulSetOwner(sts(tt.oldRev, tt.oldGen), sts(tt.newRev, tt.newGen))

			var got []string
			for h.ctrl.queue.Len() > 0 {
				k, _ := h.ctrl.queue.Get()
				got = append(got, k)
				h.ctrl.queue.Done(k)
			}
			if len(got) != len(tt.wantKeys) {
				t.Fatalf("enqueued %v, want %v", got, tt.wantKeys)
			}
			for i := range got {
				if got[i] != tt.wantKeys[i] {
					t.Errorf("enqueued %q, want %q", got[i], tt.wantKeys[i])
				}
			}
		})
	}
}

// waitQuiescent waits until neither fake API server has seen a request for the
// window: the operator's queue has drained and no reconcile is in flight.
func (h *harness) waitQuiescent(t *testing.T, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := len(h.dyn.Actions()) + len(h.kube.Actions())
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		n := len(h.dyn.Actions()) + len(h.kube.Actions())
		if n != last {
			last, stableSince = n, time.Now()
			continue
		}
		if time.Since(stableSince) >= window {
			return
		}
	}
	t.Fatal("the operator never went quiet")
}

// statefulSetOrNil reads the owned StatefulSet, nil on any error.
func (h *harness) statefulSetOrNil(ctx context.Context) *appsv1.StatefulSet {
	sts, err := h.kube.AppsV1().StatefulSets(testNamespace).Get(ctx, mlx.StatefulSetName(testModelName), metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return sts
}

// setUpdateRevision writes status.updateRevision on the owned StatefulSet, as
// the upstream StatefulSet controller (which the fake does not run) would.
func (h *harness) setUpdateRevision(t *testing.T, revision string) {
	t.Helper()
	sts := h.statefulSetOrNil(context.Background())
	if sts == nil {
		t.Fatal("no StatefulSet to bump")
	}
	sts.Status.UpdateRevision = revision
	if _, err := h.kube.AppsV1().StatefulSets(testNamespace).UpdateStatus(context.Background(), sts, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("bump updateRevision to %q: %v", revision, err)
	}
}

// readyReason reads the model's Ready condition reason, "" when absent.
func (h *harness) readyReason(ctx context.Context) string {
	got, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Get(ctx, testModelName, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	m, err := toModel(got)
	if err != nil {
		return ""
	}
	c := meta.FindStatusCondition(m.Status.Conditions, mlxv1alpha1.MLXModelConditionReady)
	if c == nil {
		return ""
	}
	return c.Reason
}
