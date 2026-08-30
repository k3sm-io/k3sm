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
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
)

const (
	testNamespace = "ml"
	testModelName = "qwen"
	testImage     = "ghcr.io/k3sm-io/mlx-serve@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	testPort      = int32(8080)
)

// fixedNow pins condition timestamps so a status comparison is about content.
var fixedNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// model builds a minimal, valid MLXModel, applying each mutation in turn.
func model(mutate ...func(*mlxv1alpha1.MLXModel)) *mlxv1alpha1.MLXModel {
	m := &mlxv1alpha1.MLXModel{
		TypeMeta: metav1.TypeMeta{APIVersion: mlxv1alpha1.SchemeGroupVersion.String(), Kind: "MLXModel"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       testModelName,
			Namespace:  testNamespace,
			UID:        "11111111-2222-3333-4444-555555555555",
			Generation: 3,
		},
		Spec: mlxv1alpha1.MLXModelSpec{
			Model:  "mlx-community/Qwen3-0.6B-4bit",
			Memory: resource.MustParse("24Gi"),
		},
	}
	for _, fn := range mutate {
		fn(m)
	}
	return m
}

// mlxScheme returns what the fake dynamic client needs to serve a list-backed
// informer over MLXModels: an EMPTY scheme plus the list kind for the MLXModel
// resource.
//
// The scheme is empty deliberately (the same choice pkg/addons' fake makes). A
// scheme with the MLXModel types registered makes the fake try to build a TYPED
// MLXModelList out of the unstructured objects its tracker holds, and the list —
// hence the informer's initial sync — fails with a conversion error that surfaces
// only as a watch that never syncs.
func mlxScheme(t *testing.T) (*runtime.Scheme, map[schema.GroupVersionResource]string) {
	t.Helper()
	return runtime.NewScheme(), map[schema.GroupVersionResource]string{mlxModelResource: "MLXModelList"}
}

// harness is one wired controller plus the two fake API servers behind it.
type harness struct {
	ctrl *Controller
	kube *kubefake.Clientset
	dyn  *dynamicfake.FakeDynamicClient
}

// newHarness wires a Controller over fake clients seeded with m.
//
// The typed fake is built with a field-managed tracker so that server-side apply
// really applies. kubefake.NewClientset gives that for core and apps types, whose
// apply schemas ARE generated — unlike the apiextensions ones.
func newHarness(t *testing.T, m *mlxv1alpha1.MLXModel, cfg func(*Config)) *harness {
	t.Helper()
	scheme, listKinds := mlxScheme(t)

	var seed []runtime.Object
	if m != nil {
		u, err := toUnstructured(m)
		if err != nil {
			t.Fatalf("seed mlxmodel: %v", err)
		}
		seed = append(seed, u)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, seed...)
	kube := kubefake.NewClientset()

	c := Config{
		Client:  kube,
		Dynamic: dyn,
		Options: mlx.Options{DefaultImage: testImage, DefaultPort: testPort},
		// A transport that refuses every probe: the default verdict is then
		// Unreachable, which is the honest reading of a replica that has not
		// started serving. A test that wants a different verdict overrides it.
		ProbeTransport: refusingTransport{},
	}
	if cfg != nil {
		cfg(&c)
	}
	ctrl, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctrl.now = func() time.Time { return fixedNow }
	return &harness{ctrl: ctrl, kube: kube, dyn: dyn}
}

// key is the workqueue key for the seeded model.
func key() string { return testNamespace + "/" + testModelName }

// reconcile runs one reconcile and fails the test on a transient error.
func (h *harness) reconcile(t *testing.T) {
	t.Helper()
	if err := h.ctrl.Reconcile(context.Background(), key()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

// status reads back the MLXModel status the reconcile wrote.
func (h *harness) status(t *testing.T) mlxv1alpha1.MLXModelStatus {
	t.Helper()
	got, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).
		Get(context.Background(), testModelName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read back mlxmodel: %v", err)
	}
	m, err := toModel(got)
	if err != nil {
		t.Fatalf("decode mlxmodel: %v", err)
	}
	return m.Status
}

// statefulSet reads back the applied StatefulSet, or nil when none exists.
func (h *harness) statefulSet(t *testing.T) *appsv1.StatefulSet {
	t.Helper()
	sts, err := h.kube.AppsV1().StatefulSets(testNamespace).
		Get(context.Background(), mlx.StatefulSetName(testModelName), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read back statefulset: %v", err)
	}
	return sts
}

// refusingTransport fails every probe request, standing in for a serving surface
// that is not listening yet.
type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net0Error{}
}

type net0Error struct{}

func (*net0Error) Error() string   { return "connection refused" }
func (*net0Error) Timeout() bool   { return false }
func (*net0Error) Temporary() bool { return false }

// servingPod builds a pod carrying the render's own labels, so the reconcile's
// selector-based observation finds it.
func servingPod(name string, phase corev1.PodPhase, ready bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    mlx.Labels(testModelName),
		},
		Status: corev1.PodStatus{Phase: phase, PodIP: "10.42.0.9"},
	}
	condStatus := corev1.ConditionFalse
	if ready {
		condStatus = corev1.ConditionTrue
	}
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: condStatus}}
	return pod
}

// TestReconcileAppliesTheServingObjects is the core M8.5-a1 reconcile slice: an
// MLXModel becomes a StatefulSet plus both Services, every one of them applied by
// server-side apply under this operator's field manager and carrying a controller
// ownerReference back to the model.
//
// The ownerReference assertion is the one that must not be dropped. Without it,
// `kubectl delete mlxmodel` cascades NOTHING — the StatefulSet, both Services,
// and (through the StatefulSet's own whenDeleted retention policy) every
// per-replica cache volume outlive the object that asked for them, and the leak
// is invisible until a node fills up.
func TestReconcileAppliesTheServingObjects(t *testing.T) {
	h := newHarness(t, model(), nil)
	h.reconcile(t)

	sts := h.statefulSet(t)
	if sts == nil {
		t.Fatal("no StatefulSet was applied")
	}
	assertOwnedByModel(t, "statefulset", sts.OwnerReferences)

	for _, name := range []string{mlx.ServiceName(testModelName), mlx.HeadlessServiceName(testModelName)} {
		svc, err := h.kube.CoreV1().Services(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("service %s was not applied: %v", name, err)
		}
		assertOwnedByModel(t, "service "+name, svc.OwnerReferences)
	}

	var applies int
	for _, action := range h.kube.Actions() {
		pa, ok := action.(k8stesting.PatchActionImpl)
		if !ok {
			continue
		}
		applies++
		if pa.GetPatchType() != types.ApplyPatchType {
			t.Errorf("%s %s used patch type %q, want %q", pa.GetResource().Resource, pa.GetName(), pa.GetPatchType(), types.ApplyPatchType)
		}
		if pa.PatchOptions.FieldManager != FieldManager {
			t.Errorf("%s %s field manager %q, want %q", pa.GetResource().Resource, pa.GetName(), pa.PatchOptions.FieldManager, FieldManager)
		}
		if pa.PatchOptions.Force == nil || !*pa.PatchOptions.Force {
			t.Errorf("%s %s apply was not forced; drift a foreign manager owns would wedge convergence", pa.GetResource().Resource, pa.GetName())
		}
	}
	if applies != 3 {
		t.Errorf("recorded %d applies, want 3 (StatefulSet + headless Service + ClusterIP Service)", applies)
	}
}

// assertOwnedByModel checks one object's ownerReferences name the MLXModel as
// its CONTROLLER.
func assertOwnedByModel(t *testing.T, what string, refs []metav1.OwnerReference) {
	t.Helper()
	if len(refs) == 0 {
		t.Fatalf("%s carries no ownerReferences; deleting the MLXModel would cascade nothing", what)
	}
	for _, ref := range refs {
		if ref.Kind != "MLXModel" || ref.Name != testModelName {
			continue
		}
		if ref.Controller == nil || !*ref.Controller {
			t.Errorf("%s ownerReference to the MLXModel is not a controller reference", what)
		}
		if ref.UID == "" {
			t.Errorf("%s ownerReference carries no UID; the apiserver rejects it", what)
		}
		return
	}
	t.Fatalf("%s has no ownerReference naming the MLXModel: %+v", what, refs)
}

// TestReconcileWritesStatusConditionsFirst pins the status contract: a Ready
// condition carrying the observed generation, with Phase as a projection of it.
//
// Phase is a printer column, never a source of truth — a consumer branches on the
// condition. Asserting the condition first, and the phase only as its projection,
// is what keeps a future change from making the two disagree with the phase
// winning.
func TestReconcileWritesStatusConditionsFirst(t *testing.T) {
	h := newHarness(t, model(), nil)
	h.reconcile(t)

	status := h.status(t)
	ready := meta.FindStatusCondition(status.Conditions, mlxv1alpha1.MLXModelConditionReady)
	if ready == nil {
		t.Fatal("no Ready condition was written; the status contract is conditions-first")
	}
	if ready.Status != metav1.ConditionFalse {
		t.Errorf("Ready = %s with no pods running, want False", ready.Status)
	}
	if ready.Reason != mlx.ReasonPending {
		t.Errorf("Ready reason = %q, want %q", ready.Reason, mlx.ReasonPending)
	}
	if ready.ObservedGeneration != 3 || status.ObservedGeneration != 3 {
		t.Errorf("observedGeneration = %d/%d, want 3 on both; without it a consumer reads a status describing the previous spec",
			ready.ObservedGeneration, status.ObservedGeneration)
	}
	if got, want := status.Phase, mlx.PhaseFromConditions(status.Conditions); got != want {
		t.Errorf("phase %q is not the projection of the conditions (%q)", got, want)
	}
	if status.Endpoint != "" {
		t.Errorf("endpoint %q published for a model with no ready replica; a client would connect and hang", status.Endpoint)
	}
}

// TestReconcilePublishesTheEndpointOnlyWhenServing covers the other half of the
// status contract, with a ready replica present.
func TestReconcilePublishesTheEndpointOnlyWhenServing(t *testing.T) {
	h := newHarness(t, model(), nil)
	if _, err := h.kube.CoreV1().Pods(testNamespace).
		Create(context.Background(), servingPod(testModelName+"-0", corev1.PodRunning, true), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed pod: %v", err)
	}
	h.reconcile(t)

	status := h.status(t)
	if status.Phase != mlxv1alpha1.MLXModelPhaseReady {
		t.Fatalf("phase = %q with one ready replica, want Ready", status.Phase)
	}
	want := mlx.ServiceName(testModelName) + "." + testNamespace + ".svc."
	if !strings.HasPrefix(status.Endpoint, want) {
		t.Errorf("endpoint = %q, want it to name the ClusterIP Service (%s...)", status.Endpoint, want)
	}
	if !strings.HasSuffix(status.Endpoint, ":8080") {
		t.Errorf("endpoint = %q, want the rendered serving port", status.Endpoint)
	}
}

// TestReconcileSplitsDownloadingFromLoadingWithTheProbe pins that the operator's
// own serving-surface probe is what refines a not-ready replica.
//
// The rendered pod carries a readiness probe and NOTHING else, so readiness alone
// cannot tell "fetching gigabytes" from "fetched, loading into memory". Without
// the probe verdict both look like Downloading, and an operator watching a model
// that has finished a forty-minute download sees no change at all.
func TestReconcileSplitsDownloadingFromLoadingWithTheProbe(t *testing.T) {
	cases := []struct {
		name       string
		transport  http.RoundTripper
		wantReason string
	}{
		{"an unreachable serving surface reads as downloading", refusingTransport{}, mlx.ReasonDownloading},
		{"an answering serving surface reads as loading", healthyButModelless{}, mlx.ReasonLoading},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, model(), func(c *Config) { c.ProbeTransport = tc.transport })
			if _, err := h.kube.CoreV1().Pods(testNamespace).
				Create(context.Background(), servingPod(testModelName+"-0", corev1.PodRunning, false), metav1.CreateOptions{}); err != nil {
				t.Fatalf("seed pod: %v", err)
			}
			h.reconcile(t)

			ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
			if ready == nil {
				t.Fatal("no Ready condition")
			}
			if ready.Reason != tc.wantReason {
				t.Errorf("Ready reason = %q, want %q", ready.Reason, tc.wantReason)
			}
		})
	}
}

// healthyButModelless answers /health but lists no models, which is exactly the
// state of an engine that has the weights and is loading them.
type healthyButModelless struct{}

func (healthyButModelless) RoundTrip(req *http.Request) (*http.Response, error) {
	body := `{}`
	if strings.Contains(req.URL.Path, "/v1/models") {
		body = `{"data":[]}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       readCloser(body),
		Request:    req,
	}, nil
}

func readCloser(s string) *stringReadCloser { return &stringReadCloser{Reader: strings.NewReader(s)} }

type stringReadCloser struct{ *strings.Reader }

func (*stringReadCloser) Close() error { return nil }

// TestReconcileRefusesAnUnfittableSpecWithoutCreatingPods is the validation half
// of M8.5-a1 seen end to end: a spec.memory the node's GPU facts cannot fund
// produces a Failed status and NO objects at all.
//
// "No objects" is the assertion that matters. A reconcile that applied first and
// let the pod die at load time would restart it into a download from zero, and
// the model would simply never become ready — with the real reason nowhere in the
// MLXModel's own status.
func TestReconcileRefusesAnUnfittableSpecWithoutCreatingPods(t *testing.T) {
	tooBig := model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("512Gi") })
	h := newHarness(t, tooBig, func(c *Config) { c.GPU = StaticGPU(facts()) })
	h.reconcile(t)

	if sts := h.statefulSet(t); sts != nil {
		t.Error("a StatefulSet was applied for a spec that cannot fit; its pods would die at load time and re-download from zero")
	}
	for _, action := range h.kube.Actions() {
		if action.GetVerb() == "patch" {
			t.Errorf("an object (%s) was applied for a spec that cannot fit", action.GetResource().Resource)
		}
	}

	status := h.status(t)
	if status.Phase != mlxv1alpha1.MLXModelPhaseFailed {
		t.Errorf("phase = %q, want Failed", status.Phase)
	}
	ready := meta.FindStatusCondition(status.Conditions, mlxv1alpha1.MLXModelConditionReady)
	if ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %+v, want False", ready)
	}
	if ready.Reason != ReasonMemoryExceedsHostMemory {
		t.Errorf("Ready reason = %q, want %q", ready.Reason, ReasonMemoryExceedsHostMemory)
	}
	degraded := meta.FindStatusCondition(status.Conditions, ConditionDegraded)
	if degraded == nil || degraded.Status != metav1.ConditionTrue {
		t.Errorf("Degraded condition = %+v, want True", degraded)
	}
	if !strings.Contains(ready.Message, "512Gi") {
		t.Errorf("message %q does not name the memory that was asked for", ready.Message)
	}
}

// TestReconcileReportsAnUnrenderableSpecWithoutRequeueing covers the other
// terminal path: a spec that renders to nothing.
//
// It must NOT come back as an error, because an error is requeued with backoff
// and a bad spec cannot improve on retry — the loop would spin forever producing
// log volume and no progress.
func TestReconcileReportsAnUnrenderableSpecWithoutRequeueing(t *testing.T) {
	broken := model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" })
	h := newHarness(t, broken, nil)

	if err := h.ctrl.Reconcile(context.Background(), key()); err != nil {
		t.Fatalf("Reconcile returned a transient error for a permanently bad spec: %v", err)
	}
	if sts := h.statefulSet(t); sts != nil {
		t.Error("a StatefulSet was applied for a spec that does not render")
	}
	ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
	if ready == nil || ready.Reason != ReasonInvalidSpec {
		t.Fatalf("Ready condition = %+v, want reason %q", ready, ReasonInvalidSpec)
	}
}

// TestReconcileStampsThePullSecretOnlyWhenItExists pins the private-registry
// contract in both directions.
//
// Stamping unconditionally would name a Secret that does not exist, which is
// itself a pull failure — so it would break every public-image deployment in
// order to serve the private one. Not stamping at all leaves the private image to
// pull anonymously and fail at materialize.
func TestReconcileStampsThePullSecretOnlyWhenItExists(t *testing.T) {
	t.Run("absent secret is not named", func(t *testing.T) {
		h := newHarness(t, model(), nil)
		h.reconcile(t)
		if refs := h.statefulSet(t).Spec.Template.Spec.ImagePullSecrets; len(refs) != 0 {
			t.Errorf("imagePullSecrets = %v with no Secret present; naming a missing Secret is itself a pull failure", refs)
		}
	})

	t.Run("present secret is stamped", func(t *testing.T) {
		h := newHarness(t, model(), nil)
		mustCreateSecret(t, h, DefaultPullSecretName)
		h.reconcile(t)

		refs := h.statefulSet(t).Spec.Template.Spec.ImagePullSecrets
		if len(refs) != 1 || refs[0].Name != DefaultPullSecretName {
			t.Fatalf("imagePullSecrets = %v, want exactly [{%s}]", refs, DefaultPullSecretName)
		}
	})

	t.Run("a configured name overrides the convention", func(t *testing.T) {
		h := newHarness(t, model(), func(c *Config) { c.PullSecretName = "house-creds" })
		mustCreateSecret(t, h, "house-creds")
		h.reconcile(t)

		refs := h.statefulSet(t).Spec.Template.Spec.ImagePullSecrets
		if len(refs) != 1 || refs[0].Name != "house-creds" {
			t.Fatalf("imagePullSecrets = %v, want exactly [{house-creds}]", refs)
		}
	})

	t.Run("re-reconciling does not accumulate duplicates", func(t *testing.T) {
		h := newHarness(t, model(), nil)
		mustCreateSecret(t, h, DefaultPullSecretName)
		h.reconcile(t)
		h.reconcile(t)

		if refs := h.statefulSet(t).Spec.Template.Spec.ImagePullSecrets; len(refs) != 1 {
			t.Errorf("imagePullSecrets = %v after two reconciles, want exactly one", refs)
		}
	})
}

func mustCreateSecret(t *testing.T, h *harness, name string) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)},
	}
	if _, err := h.kube.CoreV1().Secrets(testNamespace).Create(context.Background(), secret, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed secret %s: %v", name, err)
	}
}

// TestReconcileSkipsAnUnchangedStatusWrite pins the write suppression.
//
// Every resync re-derives the status of every model. Writing unconditionally
// would produce one apiserver write per model per resync forever — and each write
// is a watch event that re-enqueues the model that produced it, so the loop feeds
// itself.
func TestReconcileSkipsAnUnchangedStatusWrite(t *testing.T) {
	h := newHarness(t, model(), nil)
	h.reconcile(t)
	first := countStatusWrites(h.dyn.Actions())
	if first == 0 {
		t.Fatal("the first reconcile wrote no status; the suppression assertion below would be vacuous")
	}
	h.reconcile(t)
	if second := countStatusWrites(h.dyn.Actions()); second != first {
		t.Errorf("a second reconcile over unchanged state wrote status again (%d writes, was %d)", second, first)
	}
}

func countStatusWrites(actions []k8stesting.Action) int {
	n := 0
	for _, a := range actions {
		if a.GetVerb() == "update" && a.GetSubresource() == "status" {
			n++
		}
	}
	return n
}

// TestReconcileIgnoresAGoneOrTerminatingModel covers the two states in which
// applying would be wrong.
//
// A deleted MLXModel's objects are the garbage collector's, reached through the
// ownerReferences; re-applying to a terminating object would recreate exactly
// what the collector is removing, and the operator would race itself.
func TestReconcileIgnoresAGoneOrTerminatingModel(t *testing.T) {
	t.Run("gone", func(t *testing.T) {
		h := newHarness(t, nil, nil)
		if err := h.ctrl.Reconcile(context.Background(), key()); err != nil {
			t.Fatalf("Reconcile of an absent model: %v", err)
		}
		if sts := h.statefulSet(t); sts != nil {
			t.Error("objects were applied for a model that does not exist")
		}
	})

	t.Run("terminating", func(t *testing.T) {
		terminating := model(func(m *mlxv1alpha1.MLXModel) {
			m.DeletionTimestamp = ptr.To(metav1.NewTime(fixedNow))
			m.Finalizers = []string{"example.io/hold"}
		})
		h := newHarness(t, terminating, nil)
		h.reconcile(t)
		if sts := h.statefulSet(t); sts != nil {
			t.Error("objects were re-applied for a terminating model, racing the garbage collector")
		}
	})
}

// TestReconcileConvergesDriftInTheAppliedObjects pins that a hand-edited serving
// object is brought back, not merged with.
//
// This is the property forced server-side apply exists for. Without Force, a
// field a foreign manager has claimed wedges convergence permanently and the only
// symptom is a StatefulSet that quietly stops tracking its MLXModel.
func TestReconcileConvergesDriftInTheAppliedObjects(t *testing.T) {
	h := newHarness(t, model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Replicas = ptr.To(int32(2)) }), nil)
	h.reconcile(t)
	if got := ptr.Deref(h.statefulSet(t).Spec.Replicas, -1); got != 2 {
		t.Fatalf("replicas = %d after the first apply, want 2", got)
	}

	// Someone scales it by hand, under their own field manager.
	drifted := h.statefulSet(t).DeepCopy()
	drifted.Spec.Replicas = ptr.To(int32(7))
	if _, err := h.kube.AppsV1().StatefulSets(testNamespace).
		Update(context.Background(), drifted, metav1.UpdateOptions{FieldManager: "kubectl"}); err != nil {
		t.Fatalf("hand-scale the statefulset: %v", err)
	}
	if got := ptr.Deref(h.statefulSet(t).Spec.Replicas, -1); got != 7 {
		t.Fatal("the drift seed did not take; the convergence assertion below would be vacuous")
	}

	h.reconcile(t)
	if got := ptr.Deref(h.statefulSet(t).Spec.Replicas, -1); got != 2 {
		t.Errorf("replicas = %d after re-reconcile, want the spec's 2; the apply did not converge the drift", got)
	}
}

// TestObserveProbesOnlyNotReadyReplicas pins the probe scope.
//
// Readiness is what gates a replica's address into the ClusterIP Service, so a
// probe can only refine WHY a replica is not ready and must never promote one.
// Probing ready replicas would spend a round trip per replica per reconcile to
// learn nothing.
func TestObserveProbesOnlyNotReadyReplicas(t *testing.T) {
	counter := &countingTransport{inner: healthyButModelless{}}
	h := newHarness(t, model(func(m *mlxv1alpha1.MLXModel) { m.Spec.Replicas = ptr.To(int32(2)) }),
		func(c *Config) { c.ProbeTransport = counter })
	for _, pod := range []*corev1.Pod{
		servingPod(testModelName+"-0", corev1.PodRunning, true),
		servingPod(testModelName+"-1", corev1.PodRunning, false),
	} {
		if _, err := h.kube.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed pod: %v", err)
		}
	}

	obs, err := h.ctrl.observe(context.Background(), model())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(obs.Pods) != 2 {
		t.Fatalf("observed %d pods, want 2", len(obs.Pods))
	}
	for _, p := range obs.Pods {
		if p.Ready && p.Probe != mlx.ProbeUnknown {
			t.Errorf("ready replica %s carries probe verdict %q; a ready replica is not probed", p.Name, p.Probe)
		}
		if !p.Ready && p.Probe == mlx.ProbeUnknown {
			t.Errorf("not-ready replica %s was not probed; the status cannot then tell downloading from loading", p.Name)
		}
	}
	if counter.hosts() == 0 {
		t.Error("no probe request was made at all")
	}
}

type countingTransport struct {
	inner http.RoundTripper
	seen  []string
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.seen = append(c.seen, req.URL.Host)
	return c.inner.RoundTrip(req)
}

func (c *countingTransport) hosts() int { return len(c.seen) }

// TestNewRejectsAnIncompleteConfig covers the two clients with no sane default.
func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	scheme, listKinds := mlxScheme(t)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)

	if _, err := New(Config{Dynamic: dyn}); err == nil {
		t.Error("New accepted a Config with no kubernetes client")
	}
	if _, err := New(Config{Client: kubefake.NewClientset()}); err == nil {
		t.Error("New accepted a Config with no dynamic client")
	}
}

// TestFieldManagersAreDistinct pins the field-manager separation.
//
// Two independent appliers sharing one manager name each take ownership of the
// other's fields and fight over them on every pass — a boot-loop of writes with
// no diff to show for it. The CRD applier, the add-on reconciler, and this
// controller must therefore stay three names.
func TestFieldManagersAreDistinct(t *testing.T) {
	names := map[string]string{
		"operator": FieldManager,
		"crd":      "k3sm",
		"addons":   "k3sm-addons",
	}
	seen := map[string]string{}
	for who, name := range names {
		if other, dup := seen[name]; dup {
			t.Errorf("%s and %s share the field manager %q", who, other, name)
		}
		seen[name] = who
	}
}
