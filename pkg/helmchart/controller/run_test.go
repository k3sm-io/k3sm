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

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/managedfields"
	k8stesting "k8s.io/client-go/testing"

	crdconfig "k3sm.io/apis/config/crd"
)

// fakeCRDServer is a fake apiextensions API server that performs real
// server-side apply and marks every CRD Established shortly after it appears
// (pkg/mlx/operator's run_test.go explains why the stock fakes cannot).
func fakeCRDServer(t *testing.T) *apiextensionsfake.Clientset {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
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
				if len(item.Status.Conditions) > 0 {
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

func waitFor(t *testing.T, budget time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestRunCRDEnsureFailureReturnsNil: a CRD the apiserver will not take disables
// the controller with a log line, and Run returns nil (an optional surface's
// failure is not the control plane's), without ever campaigning for the Lease.
func TestRunCRDEnsureFailureReturnsNil(t *testing.T) {
	h := newHarness(t, newChart())
	crd := apiextensionsfake.NewSimpleClientset()
	crd.PrependReactor("patch", "customresourcedefinitions", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver says no")
	})
	h.ctrl.crd = crd

	done := make(chan error, 1)
	go func() { done <- h.ctrl.Run(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the CRD ensure failed")
	}
	if _, err := h.kube.CoordinationV1().Leases(LeaseNamespace).Get(context.Background(), LeaseName, metav1.GetOptions{}); err == nil {
		t.Error("Run campaigned for the Lease after the CRD ensure failed")
	}
}

// TestRunLeadsAndReconciles runs the whole controller against fake clients: it
// ensures exactly the two helm CRDs, takes the Lease through the real
// leaderelection code (the fake clientset serves Lease objects), reconciles the
// existing chart into its install Job, and on cancel drains and releases.
func TestRunLeadsAndReconciles(t *testing.T) {
	h := newHarness(t, newChart())
	crd := fakeCRDServer(t)
	h.ctrl.crd = crd

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.ctrl.Run(ctx) }()

	waitFor(t, 10*time.Second, func() bool { return h.job(t, "helm-install-podinfo") != nil },
		"the leader never created the install Job")
	lease, err := h.kube.CoordinationV1().Leases(LeaseNamespace).Get(ctx, LeaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "k3sm-test" {
		t.Errorf("lease holder = %v, want k3sm-test", lease.Spec.HolderIdentity)
	}
	list, err := crd.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, item := range list.Items {
		names[item.Name] = true
	}
	if len(names) != 2 || !names[crdconfig.HelmChartCRDName] || !names[crdconfig.HelmChartConfigCRDName] {
		t.Errorf("ensured CRDs = %v, want exactly the HelmChart and HelmChartConfig CRDs", names)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not drain after cancel")
	}
}
