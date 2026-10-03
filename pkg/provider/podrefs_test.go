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
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// refPod is a pod in ns whose first container takes env from the named
// Secrets (secretKeyRef, key "k").
func refPod(ns, name string, secrets ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			NodeName:   "n",
			Containers: []corev1.Container{{Name: "c0", Image: "registry/web:latest", Command: []string{"/web"}}},
		},
	}
	for i, s := range secrets {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name: fmt.Sprintf("S%d", i),
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: s}, Key: "k",
			}},
		})
	}
	return pod
}

// secretObj is a Secret with one key "k".
func secretObj(ns, name string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: map[string][]byte{"k": []byte("v")}}
}

// configMapObj is a ConfigMap with one key "k".
func configMapObj(ns, name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: map[string]string{"k": "v"}}
}

// secretKey and configMapKey name one registry key.
func secretKey(ns, name string) sourceKey {
	return sourceKey{kind: kindSecret, namespace: ns, name: name}
}
func configMapKey(ns, name string) sourceKey {
	return sourceKey{kind: kindConfigMap, namespace: ns, name: name}
}

// scmActions returns the recorded actions on secrets and configmaps.
func scmActions(cs *fake.Clientset) []ktesting.Action {
	var out []ktesting.Action
	for _, a := range cs.Actions() {
		switch a.GetResource().Resource {
		case "secrets", "configmaps":
			out = append(out, a)
		}
	}
	return out
}

// newGatedRuntime is a runtimedRuntime over rt whose resolver reads through a
// podRefManager on clk, the production wiring.
func newGatedRuntime(t *testing.T, rt runtimev1.RuntimeServer, cfg RuntimedConfig, cs *fake.Clientset, clk clock.Clock) (*runtimedRuntime, *podRefManager) {
	t.Helper()
	m := newPodRefManager(cs, clk, nil)
	if cfg.NodeName == "" {
		cfg.NodeName, cfg.NodeIP = "n", "192.168.1.10"
	}
	cfg.Root, cfg.PodLogsDir = t.TempDir(), t.TempDir()
	r := newRuntimedWith(rt, cfg, newKubeResolver(cs, m), nil)
	if r.refs != m {
		t.Fatal("the runtime does not register pods with the manager its resolver reads through")
	}
	if got := r.Objects(); got != m {
		t.Fatalf("Objects() = %v, want the runtime's manager", got)
	}
	return r, m
}

// TestPodRefManagerRegisterUnregister pins the refcounting: references are
// counted per pod, a re-register replaces rather than adds, and an object
// stops being referenced only when its last pod goes.
func TestPodRefManagerRegisterUnregister(t *testing.T) {
	m := newPodRefManager(fake.NewSimpleClientset(), clock.RealClock{}, nil)
	a := refPod("ns", "a", "shared", "a-only")
	b := refPod("ns", "b", "shared")

	steps := []struct {
		name string
		do   func()
		want map[sourceKey]int
	}{
		{"register a", func() { m.RegisterPod(a) }, map[sourceKey]int{secretKey("ns", "shared"): 1, secretKey("ns", "a-only"): 1}},
		{"register b", func() { m.RegisterPod(b) }, map[sourceKey]int{secretKey("ns", "shared"): 2, secretKey("ns", "a-only"): 1}},
		{"re-register a is idempotent", func() { m.RegisterPod(a) }, map[sourceKey]int{secretKey("ns", "shared"): 2, secretKey("ns", "a-only"): 1}},
		{"unregister a keeps the shared one", func() { m.UnregisterPod(a.UID) }, map[sourceKey]int{secretKey("ns", "shared"): 1}},
		{"unregister a again is a no-op", func() { m.UnregisterPod(a.UID) }, map[sourceKey]int{secretKey("ns", "shared"): 1}},
		{"unregister b drops it", func() { m.UnregisterPod(b.UID) }, map[sourceKey]int{}},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			s.do()
			m.mu.Lock()
			got := map[sourceKey]int{}
			for k, v := range m.refs {
				got[k] = v
			}
			m.mu.Unlock()
			if fmt.Sprint(got) != fmt.Sprint(s.want) {
				t.Errorf("refs = %v, want %v", got, s.want)
			}
			if d := m.distinct(); d != len(s.want) {
				t.Errorf("distinct() = %d, want %d", d, len(s.want))
			}
		})
	}

	t.Run("a nil manager registers nothing and does not panic", func(t *testing.T) {
		var nilM *podRefManager
		nilM.RegisterPod(a)
		nilM.UnregisterPod(a.UID)
		if nilM.distinct() != 0 {
			t.Error("a nil manager reports references")
		}
	})
}

// TestPodRefManagerGetsReferencedSecretByName pins the request shape: a
// referenced object costs exactly one GET by name, through the manager and
// through the resolver that reads via it, and never a LIST or WATCH.
func TestPodRefManagerGetsReferencedSecretByName(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		resource string
		read     func(ctx context.Context, m *podRefManager, r *kubeResolver) error
	}{
		{"secret through the manager", kindSecret, "secrets", func(ctx context.Context, m *podRefManager, _ *kubeResolver) error {
			_, err := m.Secret(ctx, "ns", "obj")
			return err
		}},
		{"secret through the resolver", kindSecret, "secrets", func(ctx context.Context, _ *podRefManager, r *kubeResolver) error {
			_, err := r.Secret(ctx, "ns", "obj")
			return err
		}},
		{"configmap through the manager", kindConfigMap, "configmaps", func(ctx context.Context, m *podRefManager, _ *kubeResolver) error {
			_, err := m.ConfigMap(ctx, "ns", "obj")
			return err
		}},
		{"configmap through the resolver", kindConfigMap, "configmaps", func(ctx context.Context, _ *podRefManager, r *kubeResolver) error {
			_, err := r.ConfigMap(ctx, "ns", "obj")
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(secretObj("ns", "obj"), configMapObj("ns", "obj"))
			m := newPodRefManager(cs, clock.RealClock{}, nil)
			pod := refPod("ns", "p")
			if tt.kind == kindSecret {
				pod = refPod("ns", "p", "obj")
			} else {
				pod.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "obj"}}}}}
			}
			m.RegisterPod(pod)
			if err := tt.read(context.Background(), m, newKubeResolver(cs, m)); err != nil {
				t.Fatalf("read: %v", err)
			}
			acts := scmActions(cs)
			if len(acts) != 1 {
				t.Fatalf("recorded %d secret/configmap actions, want exactly one get: %v", len(acts), acts)
			}
			g, ok := acts[0].(ktesting.GetAction)
			if !ok || g.GetVerb() != "get" || g.GetResource().Resource != tt.resource || g.GetNamespace() != "ns" || g.GetName() != "obj" {
				t.Errorf("action = %#v, want get %s ns/obj", acts[0], tt.resource)
			}
		})
	}
}

// TestPodRefManagerNeverFetchesUnreferenced pins the refusal: an object no
// registered pod references is errNotReferenced with no apiserver call, never
// an "absent" answer an optional source would swallow, and a hard error for a
// pull secret.
func TestPodRefManagerNeverFetchesUnreferenced(t *testing.T) {
	cs := fake.NewSimpleClientset(
		secretObj("a", "db"), secretObj("a", "other"), secretObj("b", "db"),
		configMapObj("a", "db"), configMapObj("a", "cfg"),
	)
	m := newPodRefManager(cs, clock.RealClock{}, nil)
	m.RegisterPod(refPod("a", "p", "db"))
	res := newKubeResolver(cs, m)
	ctx := context.Background()

	tests := []struct {
		name string
		read func() error
	}{
		{"another secret in the same namespace", func() error { _, err := m.Secret(ctx, "a", "other"); return err }},
		{"the same secret name in another namespace", func() error { _, err := m.Secret(ctx, "b", "db"); return err }},
		{"a configmap sharing the referenced secret's name", func() error { _, err := m.ConfigMap(ctx, "a", "db"); return err }},
		{"an unreferenced configmap", func() error { _, err := m.ConfigMap(ctx, "a", "cfg"); return err }},
		{"through the resolver", func() error { _, err := res.Secret(ctx, "a", "other"); return err }},
		{"inside a refresh tick", func() error {
			_, err := res.ConfigMap(withRefreshCache(ctx, newRefreshCache()), "a", "cfg")
			return err
		}},
		{"an optional env source is not skipped", func() error {
			_, skip, err := fetchData(ctx, res, kindSecret, "a", "other", true)
			if skip {
				return errors.New("an unreferenced optional source was skipped as absent")
			}
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs.ClearActions()
			err := tt.read()
			if !errors.Is(err, errNotReferenced) {
				t.Fatalf("err = %v, want errNotReferenced", err)
			}
			if errors.Is(err, os.ErrNotExist) || apierrors.IsNotFound(err) {
				t.Errorf("errNotReferenced reads as not-found: %v", err)
			}
			if acts := scmActions(cs); len(acts) != 0 {
				t.Errorf("an unreferenced read reached the apiserver: %v", acts)
			}
		})
	}

	t.Run("a pull secret is a hard error, not skipped", func(t *testing.T) {
		cs.ClearActions()
		refs := []*runtimev1.LocalObjectReference{{Name: "other"}, {Name: "db"}}
		_, ok, err := newKubeCredentials(m).PullCredential(ctx, "a", refs, "registry.example.com/app:1")
		if ok || !errors.Is(err, errNotReferenced) || !errors.Is(err, ErrPullSecretNotReadable) {
			t.Fatalf("PullCredential = ok %v, err %v; want a hard errNotReferenced", ok, err)
		}
		if acts := scmActions(cs); len(acts) != 0 {
			t.Errorf("an unreferenced pull secret reached the apiserver: %v", acts)
		}
	})
}

// TestPodRefVisitorCoversEveryReferenceSite is the table over every site the
// upstream VisitPodSecretNames / VisitPodConfigmapNames visit, plus the
// projections that are not references.
func TestPodRefVisitorCoversEveryReferenceSite(t *testing.T) {
	ref := func(name string) corev1.LocalObjectReference { return corev1.LocalObjectReference{Name: name} }
	secretEnv := []corev1.EnvVar{{Name: "E", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: ref("env-secret"), Key: "k"}}}}
	cmEnv := []corev1.EnvVar{{Name: "E", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: ref("env-cm"), Key: "k"}}}}
	vol := func(src corev1.VolumeSource) func(*corev1.PodSpec) {
		return func(s *corev1.PodSpec) { s.Volumes = append(s.Volumes, corev1.Volume{Name: "v", VolumeSource: src}) }
	}

	tests := []struct {
		name  string
		apply func(*corev1.PodSpec)
		want  []sourceKey
	}{
		{"imagePullSecrets", func(s *corev1.PodSpec) { s.ImagePullSecrets = []corev1.LocalObjectReference{ref("pull")} }, []sourceKey{secretKey("ns", "pull")}},
		{"container env secretKeyRef", func(s *corev1.PodSpec) { s.Containers[0].Env = secretEnv }, []sourceKey{secretKey("ns", "env-secret")}},
		{"container env configMapKeyRef", func(s *corev1.PodSpec) { s.Containers[0].Env = cmEnv }, []sourceKey{configMapKey("ns", "env-cm")}},
		{"init container env", func(s *corev1.PodSpec) {
			s.InitContainers = []corev1.Container{{Name: "i", Env: secretEnv}}
		}, []sourceKey{secretKey("ns", "env-secret")}},
		{"ephemeral container env", func(s *corev1.PodSpec) {
			s.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg", Env: cmEnv}}}
		}, []sourceKey{configMapKey("ns", "env-cm")}},
		{"envFrom secretRef and configMapRef", func(s *corev1.PodSpec) {
			s.Containers[0].EnvFrom = []corev1.EnvFromSource{
				{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: ref("from-secret")}},
				{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: ref("from-cm")}},
			}
		}, []sourceKey{configMapKey("ns", "from-cm"), secretKey("ns", "from-secret")}},
		{"secret volume", vol(corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "vol-secret"}}), []sourceKey{secretKey("ns", "vol-secret")}},
		{"configMap volume", vol(corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: ref("vol-cm")}}), []sourceKey{configMapKey("ns", "vol-cm")}},
		{"projected secret and configMap", vol(corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
			{Secret: &corev1.SecretProjection{LocalObjectReference: ref("proj-secret")}},
			{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: ref("kube-root-ca.crt")}},
			{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}},
			{DownwardAPI: &corev1.DownwardAPIProjection{}},
			{ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{Name: ptr("bundle"), Path: "b"}},
		}}}), []sourceKey{configMapKey("ns", "kube-root-ca.crt"), secretKey("ns", "proj-secret")}},
		{"CSI nodePublishSecretRef", vol(corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "d", NodePublishSecretRef: &corev1.LocalObjectReference{Name: "csi"}}}), []sourceKey{secretKey("ns", "csi")}},
		{"azureFile", vol(corev1.VolumeSource{AzureFile: &corev1.AzureFileVolumeSource{SecretName: "azure"}}), []sourceKey{secretKey("ns", "azure")}},
		{"cephfs", vol(corev1.VolumeSource{CephFS: &corev1.CephFSVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "ceph"}}}), []sourceKey{secretKey("ns", "ceph")}},
		{"cinder", vol(corev1.VolumeSource{Cinder: &corev1.CinderVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "cinder"}}}), []sourceKey{secretKey("ns", "cinder")}},
		{"flexVolume", vol(corev1.VolumeSource{FlexVolume: &corev1.FlexVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "flex"}}}), []sourceKey{secretKey("ns", "flex")}},
		{"rbd", vol(corev1.VolumeSource{RBD: &corev1.RBDVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "rbd"}}}), []sourceKey{secretKey("ns", "rbd")}},
		{"scaleIO", vol(corev1.VolumeSource{ScaleIO: &corev1.ScaleIOVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "scaleio"}}}), []sourceKey{secretKey("ns", "scaleio")}},
		{"iscsi", vol(corev1.VolumeSource{ISCSI: &corev1.ISCSIVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "iscsi"}}}), []sourceKey{secretKey("ns", "iscsi")}},
		{"storageOS", vol(corev1.VolumeSource{StorageOS: &corev1.StorageOSVolumeSource{SecretRef: &corev1.LocalObjectReference{Name: "storageos"}}}), []sourceKey{secretKey("ns", "storageos")}},
		{"downwardAPI volume is not a reference", vol(corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{}}), nil},
		{"an empty name is skipped", func(s *corev1.PodSpec) { s.ImagePullSecrets = []corev1.LocalObjectReference{ref("")} }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := refPod("ns", "p")
			tt.apply(&pod.Spec)
			var got []sourceKey
			for k := range podReferences(pod) {
				got = append(got, k)
			}
			sortKeys(got)
			want := append([]sourceKey(nil), tt.want...)
			sortKeys(want)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("references = %v, want %v", got, want)
			}
		})
	}
}

func sortKeys(ks []sourceKey) {
	sort.Slice(ks, func(i, j int) bool { return fmt.Sprint(ks[i]) < fmt.Sprint(ks[j]) })
}

// TestAdoptedPodsRegisterRefs proves a pod re-attached at startup is
// registered before its first read: its env resolves during the attach, and a
// later refresh tick reads its Secret instead of being refused.
func TestAdoptedPodsRegisterRefs(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	pod := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
	pod.Spec.Containers[0].Env = refPod("default", "x", "db").Spec.Containers[0].Env

	rt := newAttachRuntime()
	rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
		PodId: "uid-web", Phase: runtimev1.PodPhase_POD_PHASE_RUNNING, PodIp: "100.64.0.7",
		ContainerStatuses: []*runtimev1.ContainerStatus{
			{Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", Ready: true, State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{}}},
			{Name: "c1", Image: "registry/web:latest", ContainerId: "cid1", Ready: true, State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{}}},
		},
	}}
	cs := fake.NewSimpleClientset(secretObj("default", "db"))
	r, m := newGatedRuntime(t, rt, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10",
		Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), "192.168.1.10", nil),
		Recorder: record.NewFakeRecorder(64),
	}, cs, clock.RealClock{})
	r.podSource = &fakePodSource{listed: []corev1.Pod{pod}}

	r.adoptNodePods(context.Background(), rt)

	if r.trackByID("uid-web") == nil {
		t.Fatal("the pod was not re-attached (its env read was refused before registration?)")
	}
	if !m.referenced(secretKey("default", "db")) {
		t.Fatal("the re-attached pod's Secret is not registered")
	}
	cs.ClearActions()
	if _, err := r.resolver.Secret(withRefreshCache(context.Background(), newRefreshCache()), "default", "db"); err != nil {
		t.Fatalf("refresh read of the adopted pod's Secret: %v", err)
	}
	acts := scmActions(cs)
	if len(acts) != 1 {
		t.Fatalf("refresh read made %d actions, want one get", len(acts))
	}
	if rv := acts[0].(ktesting.GetActionImpl).GetOptions.ResourceVersion; rv != "0" {
		t.Errorf("refresh read resourceVersion = %q, want \"0\" (the watch-cache read)", rv)
	}
}

// TestPodRefManagerRegistersOnUpdate proves UpdatePod re-registers the pod:
// a reference added by the update (an ephemeral container's secretKeyRef)
// becomes fetchable, and one the update removed stops being fetchable.
func TestPodRefManagerRegistersOnUpdate(t *testing.T) {
	cs := fake.NewSimpleClientset(secretObj("default", "old"), secretObj("default", "debug-token"))
	r, m := newGatedRuntime(t, &updateRecordingRuntime{fakeRuntimeServer: newFakeRuntimeServer()}, RuntimedConfig{}, cs, clock.RealClock{})
	ctx := context.Background()

	pod := refPod("default", "web", "old")
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if _, err := m.Secret(ctx, "default", "debug-token"); !errors.Is(err, errNotReferenced) {
		t.Fatalf("before the update, debug-token read = %v, want errNotReferenced", err)
	}

	updated := pod.DeepCopy()
	updated.Spec.Containers[0].Env = nil
	updated.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
		Name: "dbg", Image: "registry/debug:1", Env: refPod("default", "x", "debug-token").Spec.Containers[0].Env,
	}}}
	if err := r.UpdatePod(ctx, updated); err != nil {
		t.Fatalf("UpdatePod: %v", err)
	}
	if _, err := m.Secret(ctx, "default", "debug-token"); err != nil {
		t.Errorf("after the update, the ephemeral container's Secret read = %v, want it fetched", err)
	}
	if _, err := m.Secret(ctx, "default", "old"); !errors.Is(err, errNotReferenced) {
		t.Errorf("after the update removed it, old read = %v, want errNotReferenced", err)
	}

	if err := r.DeletePod(ctx, updated); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if d := m.distinct(); d != 0 {
		t.Errorf("after DeletePod the manager still holds %d references", d)
	}
}

// forbiddenThen answers a get on resource with 403 for the first n calls and
// lets the tracker answer after; n < 0 is forbidden forever. It returns the
// get counter.
func forbiddenThen(cs *fake.Clientset, resource string, n int64) *atomic.Int64 {
	var calls atomic.Int64
	cs.PrependReactor("get", resource, func(a ktesting.Action) (bool, runtime.Object, error) {
		c := calls.Add(1)
		if n < 0 || c <= n {
			gr := schema.GroupResource{Resource: resource}
			return true, nil, apierrors.NewForbidden(gr, a.(ktesting.GetAction).GetName(), errors.New("no path to object"))
		}
		return false, nil, nil
	})
	return &calls
}

// driveClock steps clk by forbiddenBackoffStart whenever something waits on
// it, until done closes. Every backoff and the budget are multiples of that
// step, so fake time advances exactly as far as the retries wait.
func driveClock(t *testing.T, clk *testclock.FakeClock, done <-chan struct{}) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case <-done:
			return
		case <-deadline:
			t.Fatal("the retrying read did not finish")
		default:
		}
		if clk.HasWaiters() {
			clk.Step(forbiddenBackoffStart)
			continue
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPodRefManagerRetriesTransientForbidden pins the create-path retry of a
// Forbidden read (the Node authorizer's graph can lag a just-bound pod): a
// restartPolicy Never pod's create survives it, the retry is bounded by one
// budget for the whole create, and nothing else retries.
func TestPodRefManagerRetriesTransientForbidden(t *testing.T) {
	t.Run("a Never pod's create survives two 403s", func(t *testing.T) {
		cs := fake.NewSimpleClientset(secretObj("default", "db"))
		calls := forbiddenThen(cs, "secrets", 2)
		clk := testclock.NewFakeClock(time.Unix(10000, 0))
		r, _ := newGatedRuntime(t, newFakeRuntimeServer(), RuntimedConfig{}, cs, clk)
		pod := refPod("default", "job", "db")
		pod.Spec.RestartPolicy = corev1.RestartPolicyNever

		done := make(chan struct{})
		var err error
		go func() { defer close(done); err = r.CreatePod(context.Background(), pod) }()
		driveClock(t, clk, done)
		if err != nil {
			t.Fatalf("CreatePod after two transient 403s: %v", err)
		}
		if got := calls.Load(); got != 3 {
			t.Errorf("secret gets = %d, want 3 (two 403s, then the answer)", got)
		}
	})

	t.Run("a persistent 403 fails at the create budget", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		calls := forbiddenThen(cs, "secrets", -1)
		clk := testclock.NewFakeClock(time.Unix(10000, 0))
		m := newPodRefManager(cs, clk, nil)
		m.RegisterPod(refPod("default", "p", "db"))
		start := clk.Now()
		ctx := m.withCreateFetchBudget(context.Background())

		done := make(chan struct{})
		var err error
		go func() { defer close(done); _, err = m.Secret(ctx, "default", "db") }()
		driveClock(t, clk, done)
		if !apierrors.IsForbidden(err) {
			t.Fatalf("err = %v, want the Forbidden", err)
		}
		if got := clk.Since(start); got != createFetchBudget {
			t.Errorf("gave up after %s of fake time, want exactly the %s budget", got, createFetchBudget)
		}
		// 250ms, 500ms, 1s, 2s, 4s, 4s, then the 3.25s left: eight reads.
		if got := calls.Load(); got != 8 {
			t.Errorf("secret gets = %d, want 8", got)
		}
	})

	t.Run("the budget is one deadline for the whole create, not per read", func(t *testing.T) {
		cs := fake.NewSimpleClientset(secretObj("default", "first"), secretObj("default", "second"))
		var firstCalls atomic.Int64
		cs.PrependReactor("get", "secrets", func(a ktesting.Action) (bool, runtime.Object, error) {
			name := a.(ktesting.GetAction).GetName()
			// "first" is forbidden four times (3.75 s of backoff), "second" always.
			if name == "first" && firstCalls.Add(1) > 4 {
				return false, nil, nil
			}
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, name, errors.New("no path to object"))
		})
		clk := testclock.NewFakeClock(time.Unix(10000, 0))
		m := newPodRefManager(cs, clk, nil)
		m.RegisterPod(refPod("default", "p", "first", "second"))
		start := clk.Now()
		ctx := m.withCreateFetchBudget(context.Background())

		done := make(chan struct{})
		var err1, err2 error
		var firstDoneAt time.Duration
		go func() {
			defer close(done)
			_, err1 = m.Secret(ctx, "default", "first")
			firstDoneAt = clk.Since(start)
			_, err2 = m.Secret(ctx, "default", "second")
		}()
		driveClock(t, clk, done)
		if err1 != nil {
			t.Fatalf("first read: %v", err1)
		}
		if firstDoneAt != 3750*time.Millisecond {
			t.Fatalf("first read finished at %s, want 3.75s", firstDoneAt)
		}
		if !apierrors.IsForbidden(err2) {
			t.Fatalf("second read: err = %v, want the Forbidden", err2)
		}
		if got := clk.Since(start); got != createFetchBudget {
			t.Errorf("the create's reads gave up at %s, want the one %s budget (a per-read budget would run to %s)", got, createFetchBudget, firstDoneAt+createFetchBudget)
		}
	})

	t.Run("NotFound is not retried", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		clk := testclock.NewFakeClock(time.Unix(10000, 0))
		m := newPodRefManager(cs, clk, nil)
		m.RegisterPod(refPod("default", "p", "missing"))
		_, err := m.Secret(m.withCreateFetchBudget(context.Background()), "default", "missing")
		if !apierrors.IsNotFound(err) {
			t.Fatalf("err = %v, want NotFound", err)
		}
		if n := len(scmActions(cs)); n != 1 {
			t.Errorf("secret gets = %d, want 1", n)
		}
	})

	nonCreate := []struct {
		name string
		ctx  func(m *podRefManager) context.Context
		rv   string
	}{
		{"the refresh tick does not retry", func(m *podRefManager) context.Context {
			return withRefreshCache(m.withCreateFetchBudget(context.Background()), newRefreshCache())
		}, "0"},
		{"a read outside a create does not retry", func(*podRefManager) context.Context { return context.Background() }, ""},
	}
	for _, tt := range nonCreate {
		t.Run(tt.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			calls := forbiddenThen(cs, "secrets", -1)
			clk := testclock.NewFakeClock(time.Unix(10000, 0))
			m := newPodRefManager(cs, clk, nil)
			m.RegisterPod(refPod("default", "p", "db"))
			_, err := m.Secret(tt.ctx(m), "default", "db")
			if !apierrors.IsForbidden(err) {
				t.Fatalf("err = %v, want the Forbidden at once", err)
			}
			if calls.Load() != 1 {
				t.Errorf("secret gets = %d, want 1", calls.Load())
			}
			if rv := scmActions(cs)[0].(ktesting.GetActionImpl).GetOptions.ResourceVersion; rv != tt.rv {
				t.Errorf("resourceVersion = %q, want %q", rv, tt.rv)
			}
		})
	}
}

// TestPodRefManagerConcurrent runs Register/Unregister/Get from many
// goroutines under -race, and proves the lock is not held across I/O: while
// one Get is blocked inside a slow apiserver read, registration still
// completes.
func TestPodRefManagerConcurrent(t *testing.T) {
	cs := fake.NewSimpleClientset(secretObj("ns", "slow"), secretObj("ns", "s0"), secretObj("ns", "s1"))
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	cs.PrependReactor("get", "secrets", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.(ktesting.GetAction).GetName() == "slow" {
			once.Do(func() { close(entered) })
			<-release
		}
		return false, nil, nil
	})
	m := newPodRefManager(cs, clock.RealClock{}, nil)
	m.RegisterPod(refPod("ns", "slow-pod", "slow"))

	slowDone := make(chan error, 1)
	go func() { _, err := m.Secret(context.Background(), "ns", "slow"); slowDone <- err }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the slow read never reached the apiserver")
	}

	registered := make(chan struct{})
	go func() {
		m.RegisterPod(refPod("ns", "other", "s0"))
		m.UnregisterPod("uid-other")
		_ = m.distinct()
		close(registered)
	}()
	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("RegisterPod blocked behind an in-flight apiserver read: the lock is held across I/O")
	}
	close(release)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow read: %v", err)
	}

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("p%d", i)
			for j := range 50 {
				pod := refPod("ns", name, fmt.Sprintf("s%d", j%2))
				m.RegisterPod(pod)
				_, _ = m.Secret(context.Background(), "ns", fmt.Sprintf("s%d", (j+1)%2))
				_, _ = m.ConfigMap(context.Background(), "ns", "none")
				m.UnregisterPod(pod.UID)
			}
		}()
	}
	wg.Wait()
	if d := m.distinct(); d != 1 {
		t.Errorf("distinct() = %d after every goroutine unregistered, want 1 (the slow pod's)", d)
	}
}
