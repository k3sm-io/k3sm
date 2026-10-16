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

package updatectl

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/update"
)

const (
	oldKubelet = "v1.34.1+k3sm.0.1.0"
	target     = "v0.2.0"
	newKubelet = "v1.34.1+k3sm.0.2.0"
	targetSum  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	serverName = "srv"
)

// fakeResolver resolves every tag to one archive and counts the calls.
type fakeResolver struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (r *fakeResolver) Resolve(_ context.Context, tag string) (Release, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return Release{}, r.err
	}
	url, _ := r.AssetURL(tag)
	return Release{Version: tag, URL: url, SHA256: targetSum}, nil
}

func (r *fakeResolver) AssetURL(tag string) (string, error) {
	return HTTPResolver{Base: "https://example.test/releases"}.AssetURL(tag)
}

// rig is a fake cluster: the typed and dynamic fakes, a clock, the node-side
// and a log of what the controller did to each node.
type rig struct {
	t        *testing.T
	cs       *fake.Clientset
	dyn      *dynamicfake.FakeDynamicClient
	resolver *fakeResolver
	now      time.Time

	mu     sync.Mutex
	events []string // "cordon w1", "handover w1", "uncordon w1"

	// failNodes report Failed with this message instead of Done.
	failNodes map[string]string
	// notReady nodes come back NotReady after they report Done.
	notReady map[string]bool
	// step is how far the clock moves between passes.
	step     time.Duration
	recorder *record.FakeRecorder
}

func node(name, kubelet string, server bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if server {
		n.Labels[controlPlaneLabel] = "true"
	}
	n.Status.NodeInfo.KubeletVersion = kubelet
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	return n
}

func newRig(t *testing.T, nodes ...*corev1.Node) *rig {
	t.Helper()
	objs := make([]runtime.Object, 0, len(nodes))
	for _, n := range nodes {
		objs = append(objs, n)
	}
	r := &rig{
		t:         t,
		cs:        fake.NewSimpleClientset(objs...),
		resolver:  &fakeResolver{},
		now:       time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC),
		failNodes: map[string]string{},
		notReady:  map[string]bool{},
		step:      10 * time.Second,
		recorder:  record.NewFakeRecorder(10000),
	}
	// An empty scheme: the fake then stores the Updates as unstructured, as
	// the apiserver serves them to a dynamic client.
	r.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{updateResource: "UpdateList"})
	r.cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.PatchAction)
		var body struct {
			Metadata struct {
				Annotations map[string]any `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Unschedulable *bool `json:"unschedulable"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(p.GetPatch(), &body); err != nil {
			t.Errorf("node patch: %v", err)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case body.Spec.Unschedulable != nil && *body.Spec.Unschedulable:
			r.events = append(r.events, "cordon "+p.GetName())
		case body.Spec.Unschedulable != nil:
			r.events = append(r.events, "uncordon "+p.GetName())
		case body.Metadata.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != nil:
			r.events = append(r.events, "handover "+p.GetName())
		}
		return false, nil, nil // fall through to the tracker
	})
	r.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "eviction" {
			return false, nil, nil
		}
		ev := a.(k8stesting.CreateAction).GetObject().(metav1.Object)
		err := r.cs.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), ev.GetNamespace(), ev.GetName())
		return true, nil, err
	})
	return r
}

// testSigning is one cluster CA and the update signer it issued, shared by
// every controller the tests build.
var testSigning = sync.OnceValue(func() struct {
	ca     *certs.CA
	signer *certs.UpdateSigner
} {
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		panic(err)
	}
	s, err := ca.IssueUpdateSigner()
	if err != nil {
		panic(err)
	}
	return struct {
		ca     *certs.CA
		signer *certs.UpdateSigner
	}{ca, s}
})

func (r *rig) controller() *Controller {
	r.t.Helper()
	c, err := New(Config{
		Client: r.cs, Dynamic: r.dyn, Resolver: r.resolver, ServerNode: serverName, IssueSigner: func() (*certs.UpdateSigner, error) { return testSigning().signer, nil },
		Now: func() time.Time { return r.now }, Recorder: r.recorder,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *rig) createUpdate(name string, spec updatesv1alpha1.UpdateSpec) {
	r.t.Helper()
	u := &updatesv1alpha1.Update{
		TypeMeta:   metav1.TypeMeta{APIVersion: updatesv1alpha1.SchemeGroupVersion.String(), Kind: "Update"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1},
		Spec:       spec,
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(u)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.dyn.Resource(updateResource).Create(context.Background(), &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) update(name string) *updatesv1alpha1.Update {
	r.t.Helper()
	obj, err := r.dyn.Resource(updateResource).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	u, err := decodeUpdate(obj)
	if err != nil {
		r.t.Fatal(err)
	}
	return u
}

func (r *rig) setCancel() {
	r.t.Helper()
	u := r.update(updatesv1alpha1.UpdateName)
	u.Spec.Cancel = true
	u.Generation++
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(u)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.dyn.Resource(updateResource).Update(context.Background(), &unstructured.Unstructured{Object: obj}, metav1.UpdateOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) node(name string) *corev1.Node {
	r.t.Helper()
	n, err := r.cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	return n
}

// nodeSide is the fake node-side agent: a node handed the target with no
// phase report starts Installing; one Installing reports Done and restarts on
// the target (its kubeletVersion moves), or reports Failed when it is in
// failNodes.
func (r *rig) nodeSide() {
	r.t.Helper()
	list, err := r.cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		r.t.Fatal(err)
	}
	for i := range list.Items {
		n := list.Items[i].DeepCopy()
		if n.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != target {
			continue
		}
		switch n.Annotations[updatesv1alpha1.AnnotationUpdatePhase] {
		case "":
			n.Annotations[updatesv1alpha1.AnnotationUpdatePhase] = string(updatesv1alpha1.UpdateNodePhaseInstalling)
		case string(updatesv1alpha1.UpdateNodePhaseInstalling):
			if msg, bad := r.failNodes[n.Name]; bad {
				n.Annotations[updatesv1alpha1.AnnotationUpdatePhase] = "Failed: " + msg
			} else {
				n.Annotations[updatesv1alpha1.AnnotationUpdatePhase] = string(updatesv1alpha1.UpdateNodePhaseDone)
				n.Status.NodeInfo.KubeletVersion = newKubelet
				if r.notReady[n.Name] {
					n.Status.Conditions[0].Status = corev1.ConditionFalse
				}
			}
		default:
			continue
		}
		if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
			r.t.Fatal(err)
		}
	}
}

// drive reconciles, lets the node-side act and moves the clock, until the
// singleton finishes or stop says so.
func (r *rig) drive(c *Controller, stop func() bool) {
	r.t.Helper()
	for range 1000 {
		if _, err := c.reconcile(context.Background()); err != nil {
			r.t.Fatalf("reconcile: %v", err)
		}
		if finished(r.update(updatesv1alpha1.UpdateName)) || (stop != nil && stop()) {
			return
		}
		r.nodeSide()
		r.now = r.now.Add(r.step)
	}
	r.t.Fatal("the roll did not finish in 1000 passes")
}

func (r *rig) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func phases(u *updatesv1alpha1.Update) map[string]updatesv1alpha1.UpdateNodePhase {
	out := map[string]updatesv1alpha1.UpdateNodePhase{}
	for _, e := range u.Status.Nodes {
		out[e.Name] = e.Phase
	}
	return out
}

func threeNodes() []*corev1.Node {
	// Created out of order: the plan sorts the workers and puts the server last.
	return []*corev1.Node{node(serverName, oldKubelet, true), node("w2", oldKubelet, false), node("w1", oldKubelet, false)}
}

func TestRollingOrderWorkersThenServer(t *testing.T) {
	t.Run("workers by name then the server, each cordoned and uncordoned", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(r.controller(), nil)

		want := []string{
			"cordon w1", "handover w1", "uncordon w1",
			"cordon w2", "handover w2", "uncordon w2",
			"cordon srv", "handover srv", "uncordon srv",
		}
		if got := r.log(); !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions:\n got %v\nwant %v", got, want)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q, want Succeeded", u.Status.Phase)
		}
		if !meta.IsStatusConditionTrue(u.Status.Conditions, ConditionSucceeded) ||
			!meta.IsStatusConditionTrue(u.Status.Conditions, updatesv1alpha1.UpdateConditionReconciled) {
			t.Fatalf("conditions %+v", u.Status.Conditions)
		}
		if u.Status.ObservedGeneration != 1 {
			t.Fatalf("observedGeneration %d, want 1", u.Status.ObservedGeneration)
		}
		var names []string
		for _, e := range u.Status.Nodes {
			names = append(names, e.Name)
			if e.Phase != updatesv1alpha1.UpdateNodePhaseDone || e.From != "v0.1.0" || e.To != target ||
				e.StartedAt == nil || e.FinishedAt == nil {
				t.Errorf("node entry %+v", e)
			}
		}
		if !reflect.DeepEqual(names, []string{"w1", "w2", serverName}) {
			t.Fatalf("status order %v", names)
		}
		if u.Status.Resolved == nil || u.Status.Resolved.Digest != "sha256:"+targetSum || u.Status.Resolved.Version != target {
			t.Fatalf("resolved %+v", u.Status.Resolved)
		}
		if r.resolver.calls != 1 {
			t.Fatalf("resolved %d times, want once", r.resolver.calls)
		}
		var p Payload
		if err := json.Unmarshal([]byte(r.node("w1").Annotations[updatesv1alpha1.AnnotationUpdatePayload]), &p); err != nil {
			t.Fatal(err)
		}
		wantP := Payload{Version: target, URL: "https://example.test/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz",
			SHA256: targetSum, Signature: updatesv1alpha1.UpdateSignatureIfSigned}
		if p != wantP {
			t.Fatalf("payload %+v, want %+v", p, wantP)
		}
		// The handover is signed: the node verifies it against the cluster CA.
		ann := r.node("w1").Annotations
		signed, err := update.VerifySignedPayload(update.CAPool(testSigning().ca.CertPEM), []byte(ann[update.AnnotationUpdatePayload]),
			ann[update.AnnotationUpdatePayloadSig], ann[update.AnnotationUpdateSigner], r.now)
		if err != nil || signed.Payload != wantP {
			t.Fatalf("the handed-over payload does not verify: %v (%+v)", err, signed.Payload)
		}
		for _, n := range []string{"w1", "w2", serverName} {
			if nd := r.node(n); nd.Spec.Unschedulable || nd.Annotations[CordonedAnnotation] != "" {
				t.Errorf("node %s left cordoned", n)
			}
		}
	})

	t.Run("a node already on the target is skipped", func(t *testing.T) {
		nodes := threeNodes()
		nodes[1].Status.NodeInfo.KubeletVersion = newKubelet // w2
		r := newRig(t, nodes...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(r.controller(), nil)
		want := []string{"cordon w1", "handover w1", "uncordon w1", "cordon srv", "handover srv", "uncordon srv"}
		if got := r.log(); !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions:\n got %v\nwant %v", got, want)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		if got := phases(u)["w2"]; got != updatesv1alpha1.UpdateNodePhaseSkipped {
			t.Fatalf("w2 phase %q, want Skipped", got)
		}
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q", u.Status.Phase)
		}
	})

	t.Run("a failed node stops the roll and stays cordoned", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.failNodes["w2"] = "disk full"
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(r.controller(), nil)
		want := []string{"cordon w1", "handover w1", "uncordon w1", "cordon w2", "handover w2"}
		if got := r.log(); !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions:\n got %v\nwant %v", got, want)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		got := phases(u)
		if got["w1"] != updatesv1alpha1.UpdateNodePhaseDone || got["w2"] != updatesv1alpha1.UpdateNodePhaseFailed ||
			got[serverName] != updatesv1alpha1.UpdateNodePhasePending {
			t.Fatalf("node phases %v", got)
		}
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || !meta.IsStatusConditionTrue(u.Status.Conditions, ConditionFailed) {
			t.Fatalf("phase %q conditions %+v", u.Status.Phase, u.Status.Conditions)
		}
		if msg := u.Status.Nodes[1].Message; !strings.HasPrefix(msg, "disk full"+progressMark) {
			t.Fatalf("w2 message %q", msg)
		}
		if c := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed); !strings.Contains(c.Message, "w2: disk full") {
			t.Fatalf("Failed message %q", c.Message)
		}
		if !r.node("w2").Spec.Unschedulable {
			t.Fatal("the failed node was uncordoned")
		}
		// A finished Update is not resumed.
		before := len(r.log())
		r.drive(r.controller(), nil)
		if len(r.log()) != before {
			t.Fatal("a failed Update touched a node again")
		}
	})

	t.Run("cancel lets the current node finish and starts no other", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		c := r.controller()
		r.drive(c, func() bool { return len(r.log()) == 2 }) // w1 cordoned and handed over
		r.setCancel()
		r.drive(c, nil)
		want := []string{"cordon w1", "handover w1", "uncordon w1"}
		if got := r.log(); !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions:\n got %v\nwant %v", got, want)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		got := phases(u)
		if got["w1"] != updatesv1alpha1.UpdateNodePhaseDone || got["w2"] != updatesv1alpha1.UpdateNodePhaseCancelled ||
			got[serverName] != updatesv1alpha1.UpdateNodePhaseCancelled {
			t.Fatalf("node phases %v", got)
		}
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseCancelled || u.Status.ObservedGeneration != 2 {
			t.Fatalf("phase %q observedGeneration %d", u.Status.Phase, u.Status.ObservedGeneration)
		}
	})

	t.Run("cancel before the handover lifts the cordon", func(t *testing.T) {
		r := newRig(t, append(threeNodes(), podNode())...)
		if err := r.cs.Tracker().Add(pod("held", "w0", owned)); err != nil {
			t.Fatal(err)
		}
		r.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, tooManyRequests()
		})
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true}})
		c := r.controller()
		r.drive(c, func() bool { return len(r.log()) == 1 })
		r.setCancel()
		r.drive(c, nil)
		if got, want := r.log(), []string{"cordon w0", "uncordon w0"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions %v, want %v", got, want)
		}
		if got := phases(r.update(updatesv1alpha1.UpdateName)); got["w0"] != updatesv1alpha1.UpdateNodePhaseCancelled {
			t.Fatalf("node phases %v", got)
		}
	})

	t.Run("a restarted controller resumes from the persisted status", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		// The first controller hands w2 over, then stops.
		r.drive(r.controller(), func() bool { return len(r.log()) == 5 })
		// The second stops right after it hands the server (its own node) over:
		// the server restarts on the new release mid-roll.
		r.drive(r.controller(), func() bool { return len(r.log()) == 8 })
		// The third is the server's controller on the new release.
		r.drive(r.controller(), nil)
		want := []string{
			"cordon w1", "handover w1", "uncordon w1",
			"cordon w2", "handover w2", "uncordon w2",
			"cordon srv", "handover srv", "uncordon srv",
		}
		if got := r.log(); !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions:\n got %v\nwant %v", got, want)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q", u.Status.Phase)
		}
		if r.resolver.calls != 1 {
			t.Fatalf("resolved %d times across restarts, want once", r.resolver.calls)
		}
	})

	t.Run("an Update under another name is not reconciled", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.createUpdate("other", updatesv1alpha1.UpdateSpec{Version: target})
		if _, err := r.controller().reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		u := r.update("other")
		c := meta.FindStatusCondition(u.Status.Conditions, updatesv1alpha1.UpdateConditionReconciled)
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason != updatesv1alpha1.UpdateReasonNotTheSingleton {
			t.Fatalf("Reconciled %+v", c)
		}
		if len(r.log()) != 0 || len(u.Status.Nodes) != 0 {
			t.Fatalf("a non-singleton touched nodes: %v", r.log())
		}
	})
}

// podNode is a worker that sorts first, for the drain cases.
func podNode() *corev1.Node { return node("w0", oldKubelet, false) }

func tooManyRequests() error {
	return apierrors.NewTooManyRequests("Cannot evict pod as it would violate the pod's disruption budget.", 0)
}

// TestNewRequiresAnUpdateSigner: a controller that could not sign would hand
// nodes payloads their root helper refuses, so it is not built at all.
func TestNewRequiresAnUpdateSigner(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := New(Config{Client: r.cs, Dynamic: r.dyn, ServerNode: serverName}); err == nil || !strings.Contains(err.Error(), "signer") {
		t.Fatalf("New without a signer = %v, want refused", err)
	}
}

// TestUpdateSignerIsShortLived pins the signer's renewal on a fake clock: a
// signer is reused while it has at least certs.UpdateSignerRenewBefore left,
// and replaced by a fresh one-day signer once it has less, so no payload the
// controller signs authorises anything for more than a day.
func TestUpdateSignerIsShortLived(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	issued := 0
	r := newRig(t)
	c, err := New(Config{
		Client: r.cs, Dynamic: r.dyn, ServerNode: serverName,
		Now: func() time.Time { return now },
		IssueSigner: func() (*certs.UpdateSigner, error) {
			issued++
			s := *testSigning().signer
			cert := *s.Cert
			cert.NotAfter = now.Add(certs.UpdateSignerValidity)
			s.Cert = &cert
			return &s, nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	step := func(d time.Duration, wantIssued int) {
		t.Helper()
		now = now.Add(d)
		s, err := c.currentSigner()
		if err != nil {
			t.Fatalf("currentSigner = %v", err)
		}
		if issued != wantIssued {
			t.Fatalf("after +%v: %d signers issued, want %d", d, issued, wantIssued)
		}
		if left := s.Cert.NotAfter.Sub(now); left < certs.UpdateSignerRenewBefore || left > certs.UpdateSignerValidity {
			t.Fatalf("after +%v: the signer used has %v left", d, left)
		}
	}
	step(0, 1)            // the first handover mints one
	step(11*time.Hour, 1) // 13 h left: reused
	step(2*time.Hour, 2)  // 11 h left: replaced
	step(time.Minute, 2)  // the fresh one is reused
	step(48*time.Hour, 3) // long expired: replaced
	if certs.UpdateSignerValidity != 24*time.Hour {
		t.Errorf("UpdateSignerValidity = %v, want a day", certs.UpdateSignerValidity)
	}
}
