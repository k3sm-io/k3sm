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
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// B233: UpdatePodDoesNotRematerializeVolumes pins TODAY's contract — runtimed's
// UpdatePod applies labels/annotations only (its updatableOnly check rejects
// every other field change as NOT_UPDATABLE), and volumes are materialized
// exactly once, at create: nothing on any path re-resolves ConfigMap, Secret, or
// projected ServiceAccount-token DATA after creation. This is a
// CHARACTERIZATION test of that TODAY, not a design requirement — a
// projected-volume refresh feature (B234) must invert it DELIBERATELY, not by
// accident, and this test is exactly what would need to change to do that.

// updateRecordingRuntime is a PLAIN (non-minting) fake runtime — unlike
// tokenMintingRuntime (tokenbinding_test.go), it mints no token and calls back
// into no resolver from either RPC. CreatePod behaves exactly like
// fakeRuntimeServer's default (records the box; the embedded fake never touches
// the apiserver). UpdatePod SUCCEEDS — unlike fakeRuntimeServer's default
// refusal — and records the PodBox it received. Because this fake never drives
// the resolver itself, ANY clientset action this test observes after CreatePod
// can only have come from the PROVIDER's own in-process code (buildBox →
// resolvePodBoxEnv) — which is the discriminator the test needs.
type updateRecordingRuntime struct {
	*fakeRuntimeServer

	mu      sync.Mutex
	updates []*runtimev1.PodBox
}

// UpdatePod records the box it received and answers success, the shape a real
// in-place labels/annotations update takes.
func (f *updateRecordingRuntime) UpdatePod(_ context.Context, req *runtimev1.UpdatePodRequest) (*runtimev1.UpdatePodResponse, error) {
	f.mu.Lock()
	f.updates = append(f.updates, req.GetPod())
	f.mu.Unlock()
	return &runtimev1.UpdatePodResponse{Status: &runtimev1.PodStatus{PodId: req.GetPod().GetPodId()}}, nil
}

// updateBoxes returns every PodBox UpdatePod has received, in order.
func (f *updateRecordingRuntime) updateBoxes() []*runtimev1.PodBox {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*runtimev1.PodBox(nil), f.updates...)
}

// rematerializePod returns a pod carrying a projected ServiceAccount-token
// volume AND a ConfigMap-backed volume — the two payload kinds runtimed's
// mount.Materialize resolves through the provider's Resolver — but
// DELIBERATELY no envFrom/configMapKeyRef/secretKeyRef env source. Env-source
// resolution (resolvePodBoxEnv) is a SEPARATE path that legitimately re-runs on
// every buildBox call, CreatePod and UpdatePod alike (env.go), so it is
// excluded here on purpose: this test pins the VOLUME path, not the env path.
func rematerializePod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			UID:       types.UID("uid-" + name),
			Labels:    map[string]string{"app": "orig"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "app-sa",
			Containers: []corev1.Container{{
				Name:  "c0",
				Image: "registry/app:latest",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "kube-api-access", MountPath: caMountRoot, ReadOnly: true},
					{Name: "cfg", MountPath: "/etc/app-config", ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				{
					Name: "kube-api-access",
					VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{
							{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr(int64(3607))}},
						},
					}},
				},
				{
					Name:         "cfg",
					VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}},
				},
			},
		},
	}
}

// TestUpdatePodDoesNotRematerializeVolumes pins the PROVIDER half of B233's
// contract: an UpdatePod that changes only labels/annotations must reach the
// runtime with a PodBox that is byte-identical to the one CreatePod sent, save
// for those two fields, must issue no further CreatePod, and must not mint a
// token or read a ConfigMap/Secret through the apiserver on the way. The other
// half — that runtimed itself never re-materializes on update — is pinned where
// the materializer lives, by TestUpdatePodNeverMaterializes in runtimed's
// pkg/runtime, whose spy records the create-time resolution and asserts it does
// not move; this test's apiserver assertions are the provider-side fence for a
// future buildBox change, not that proof.
func TestUpdatePodDoesNotRematerializeVolumes(t *testing.T) {
	cs := fake.NewSimpleClientset()
	// A minimal TokenRequest reactor. It exists ONLY so that the B233 brief's
	// fails-before mutation proof (a direct call to resolver.ServiceAccountToken
	// added temporarily inside UpdatePod) can mint successfully instead of
	// erroring on an unregistered subresource; it changes nothing about what
	// THIS committed test exercises, because the committed production code never
	// reaches it.
	cs.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		ca, ok := action.(ktesting.CreateActionImpl)
		if !ok || ca.GetSubresource() != "token" {
			return false, nil, nil // not a TokenRequest; fall through
		}
		return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: "opaque-test-token"}}, nil
	})

	res := newKubeResolver(cs)
	f := &updateRecordingRuntime{fakeRuntimeServer: newFakeRuntimeServer()}
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir()}, res, nil)

	pod := rematerializePod("team", "snap")

	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	createdBox := f.createdBox(string(pod.UID))
	if createdBox == nil {
		t.Fatalf("fake runtime holds no box for pod %s after CreatePod", pod.UID)
	}
	createdBox = proto.Clone(createdBox).(*runtimev1.PodBox)
	createCallsAfterCreate := f.createCount()

	// Snapshot AFTER the create — resolvePodBoxEnv already ran once for it (with
	// zero env sources, so it touched nothing) — so every action counted below is
	// scoped to "between the create and the end of the update", as B233 specifies.
	cs.ClearActions()

	updated := pod.DeepCopy()
	updated.Labels = map[string]string{"app": "orig", "app.kubernetes.io/revision": "2"}
	updated.Annotations = map[string]string{"k3sm.io/note": "updated"}

	if err := r.UpdatePod(context.Background(), updated); err != nil {
		t.Fatalf("UpdatePod: %v", err)
	}

	// (1) zero token-mint / ConfigMap / Secret reads reached the fake apiserver
	// while serving the update.
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "serviceaccounts" {
			if ca, ok := a.(ktesting.CreateActionImpl); ok && ca.GetSubresource() == "token" {
				t.Errorf("UpdatePod minted a ServiceAccount token (%s/%s) — volumes must materialize ONLY at create (B233)", a.GetNamespace(), ca.Name)
			}
			continue
		}
		if (a.GetResource().Resource == "configmaps" || a.GetResource().Resource == "secrets") &&
			(a.GetVerb() == "get" || a.GetVerb() == "list") {
			t.Errorf("UpdatePod issued a %s on %s in namespace %s — volumes must materialize ONLY at create (B233)", a.GetVerb(), a.GetResource().Resource, a.GetNamespace())
		}
	}

	// (2) exactly one UpdatePodRequest reached the runtime, and no additional
	// CreatePodRequest rode along with it.
	updates := f.updateBoxes()
	if len(updates) != 1 {
		t.Fatalf("runtime received %d UpdatePodRequest(s), want 1", len(updates))
	}
	if got := f.createCount(); got != createCallsAfterCreate {
		t.Errorf("runtime received %d additional CreatePodRequest(s) while serving the update, want 0", got-createCallsAfterCreate)
	}

	// (3) the update's PodBox differs from the create's ONLY in labels/
	// annotations: volumes, mounts, env, and every identity field are
	// byte-identical — the proof that buildBox neither re-resolved nor
	// re-materialized anything for the update.
	updateBox := proto.Clone(updates[0]).(*runtimev1.PodBox)
	compareBox := proto.Clone(createdBox).(*runtimev1.PodBox)
	compareBox.Labels = updateBox.GetLabels()
	compareBox.Annotations = updateBox.GetAnnotations()
	if !proto.Equal(compareBox, updateBox) {
		t.Errorf("UpdatePod's PodBox differs from CreatePod's beyond labels/annotations:\ncreate=%v\nupdate=%v", createdBox, updateBox)
	}

	// (4) the update DID carry the NEW labels/annotations, not the old ones —
	// (3) alone would also pass on a box that dropped the change entirely.
	if got := updateBox.GetLabels()["app.kubernetes.io/revision"]; got != "2" {
		t.Errorf("UpdatePod's PodBox.Labels[app.kubernetes.io/revision] = %q, want %q", got, "2")
	}
	if got := updateBox.GetAnnotations()["k3sm.io/note"]; got != "updated" {
		t.Errorf("UpdatePod's PodBox.Annotations[k3sm.io/note] = %q, want %q", got, "updated")
	}
}
