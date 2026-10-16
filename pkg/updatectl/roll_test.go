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
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/version"
)

func pod(name, nodeName string, mutate func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: corev1.PodSpec{NodeName: nodeName}}
	if mutate != nil {
		mutate(p)
	}
	return p
}

// owned gives a pod a ReplicaSet controller, so a drain moves it.
func owned(p *corev1.Pod) {
	p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs", Controller: ptr.To(true)}}
}

func TestDrainHonoursBudgetsAndSkipsDaemonSetAndMirrorPods(t *testing.T) {
	r := newRig(t, append(threeNodes(), podNode())...)
	pods := []*corev1.Pod{
		pod("plain", "w0", owned),
		pod("budgeted", "w0", owned),
		pod("ds", "w0", func(p *corev1.Pod) {
			p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "d", UID: "u", Controller: ptr.To(true)}}
		}),
		pod("mirror", "w0", func(p *corev1.Pod) { p.Annotations = map[string]string{mirrorPodAnnotation: "x"} }),
		pod("done", "w0", func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }),
		pod("elsewhere", "not-in-the-roll", nil), // another node's bare pod
	}
	for _, p := range pods {
		if err := r.cs.Tracker().Add(p); err != nil {
			t.Fatal(err)
		}
	}
	var evicted []string
	refusals := 2 // the budget refuses the first two evictions of "budgeted"
	r.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "eviction" {
			return false, nil, nil
		}
		name := a.(k8stesting.CreateAction).GetObject().(metav1.Object).GetName()
		evicted = append(evicted, name)
		if name == "budgeted" && refusals > 0 {
			refusals--
			return true, nil, tooManyRequests()
		}
		return false, nil, nil // the rig's reactor deletes it
	})
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{
		Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true},
	})
	r.drive(r.controller(), nil)

	if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
		t.Fatalf("phase %q", got)
	}
	want := []string{"budgeted", "plain", "budgeted", "budgeted"} // listed by name
	if !reflect.DeepEqual(evicted, want) {
		t.Fatalf("evictions %v, want %v", evicted, want)
	}
	for _, name := range []string{"ds", "mirror", "done", "elsewhere"} {
		if _, err := r.cs.CoreV1().Pods("default").Get(context.Background(), name, metav1.GetOptions{}); err != nil {
			t.Errorf("pod %s was removed: %v", name, err)
		}
	}
	log := r.log()
	if log[0] != "cordon w0" || log[1] != "handover w0" {
		t.Fatalf("the handover did not wait for the drain: %v", log)
	}
}

func TestDrainTimeoutFailsTheNode(t *testing.T) {
	r := newRig(t, append(threeNodes(), podNode())...)
	if err := r.cs.Tracker().Add(pod("stuck", "w0", owned)); err != nil {
		t.Fatal(err)
	}
	r.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "eviction" {
			return false, nil, nil
		}
		return true, nil, tooManyRequests()
	})
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{
		Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true},
	})
	c := r.controller()
	c.cfg.DrainTimeout = 5 * time.Second
	r.drive(c, nil)
	u := r.update(updatesv1alpha1.UpdateName)
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed {
		t.Fatalf("phase %q", u.Status.Phase)
	}
	e := u.Status.Nodes[0]
	if e.Name != "w0" || e.Phase != updatesv1alpha1.UpdateNodePhaseFailed || !strings.Contains(e.Message, "default/stuck") {
		t.Fatalf("w0 entry %+v", e)
	}
	if got, want := r.log(), []string{"cordon w0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node actions %v, want %v", got, want)
	}
}

func TestNodeTimeoutFailsTheNode(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	c.cfg.NodeTimeout = 3 * time.Second
	for range 10 { // no node-side: nothing ever reports
		if _, err := c.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.now = r.now.Add(time.Second)
	}
	u := r.update(updatesv1alpha1.UpdateName)
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || u.Status.Nodes[0].Phase != updatesv1alpha1.UpdateNodePhaseFailed {
		t.Fatalf("phase %q nodes %+v", u.Status.Phase, u.Status.Nodes)
	}
}

func TestRefusalsBeforeAnyNodeIsTouched(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    updatesv1alpha1.UpdateSpec
		resolve error
		want    string
	}{
		{name: "downgrade", spec: updatesv1alpha1.UpdateSpec{Version: "v0.0.9"}, want: "spec.allowDowngrade"},
		{name: "unpublished release", spec: updatesv1alpha1.UpdateSpec{Version: target}, resolve: ErrRelease, want: "cannot be resolved"},
		{name: "bad tag", spec: updatesv1alpha1.UpdateSpec{Version: "v0.2.0;rm"}, want: "not a usable release tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, threeNodes()...)
			r.resolver.err = tc.resolve
			r.createUpdate(updatesv1alpha1.UpdateName, tc.spec)
			r.drive(r.controller(), nil)
			u := r.update(updatesv1alpha1.UpdateName)
			c := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
			if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || c == nil || !strings.Contains(c.Message, tc.want) {
				t.Fatalf("phase %q Failed %+v", u.Status.Phase, c)
			}
			if len(r.log()) != 0 {
				t.Fatalf("a node was touched: %v", r.log())
			}
		})
	}
}

func TestDowngradeAllowed(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: "v0.0.9", AllowDowngrade: true})
	c := r.controller()
	if _, err := c.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.log(); len(got) != 2 || got[0] != "cordon w1" {
		t.Fatalf("node actions %v", got)
	}
	if !strings.Contains(r.node("w1").Annotations[updatesv1alpha1.AnnotationUpdatePayload], `"allowDowngrade":true`) {
		t.Fatalf("payload %s", r.node("w1").Annotations[updatesv1alpha1.AnnotationUpdatePayload])
	}
}

func TestTransientResolveIsRetried(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.resolver.err = errors.New("connection refused")
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	if _, err := c.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	u := r.update(updatesv1alpha1.UpdateName)
	if finished(u) || len(r.log()) != 0 {
		t.Fatalf("a transient resolve error ended the roll or touched a node: %q %v", u.Status.Phase, r.log())
	}
	r.resolver.err = nil
	r.drive(c, nil)
	if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
		t.Fatalf("phase %q", got)
	}
}

func TestOperatorCordonIsKept(t *testing.T) {
	nodes := threeNodes()
	nodes[2].Spec.Unschedulable = true // w1, cordoned by the operator
	r := newRig(t, nodes...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	r.drive(r.controller(), nil)
	if !r.node("w1").Spec.Unschedulable {
		t.Fatal("the operator's cordon was lifted")
	}
	if got := r.log(); got[0] != "handover w1" {
		t.Fatalf("node actions %v", got)
	}
}

// handlerTransport serves requests from an in-process handler through
// httptest.NewRecorder: no socket is opened.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func TestHTTPResolver(t *testing.T) {
	const base = "https://releases.example.test/releases"
	const sums = "aaaa  other.tar.gz\n" + targetSum + "  k3sm_0.2.0_darwin_arm64.tar.gz\n"
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/releases/download/v0.2.0/k3sm_0.2.0_checksums.txt":
			_, _ = w.Write([]byte(sums))
		case "/releases/download/v0.3.0/k3sm_0.3.0_checksums.txt":
			_, _ = w.Write([]byte("aaaa  other.tar.gz\n"))
		case "/releases/download/v0.4.0/k3sm_0.4.0_checksums.txt":
			http.Error(w, "boom", http.StatusBadGateway)
		case "/releases/download/v0.5.0/k3sm_0.5.0_checksums.txt":
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/releases/download/v0.6.0/k3sm_0.6.0_checksums.txt":
			http.Error(w, "gone", http.StatusGone)
		default:
			http.NotFound(w, req)
		}
	})
	res := HTTPResolver{Base: base, Client: &http.Client{Transport: handlerTransport{h}}}

	got, err := res.Resolve(context.Background(), "0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	want := Release{Version: "0.2.0", URL: base + "/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz", SHA256: targetSum}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, tc := range []struct {
		tag        string
		definitive bool
	}{
		{"v0.3.0", true},  // no entry for the archive
		{"v9.9.9", true},  // not published
		{"v0.4.0", false}, // a 5xx is retried
		{"v0.5.0", true},  // 403
		{"v0.6.0", true},  // 410
		{"-v1", true},     // refused tag
		{"v1/../x", true}, // refused tag
		{"v", true},       // empty version
	} {
		_, err := res.Resolve(context.Background(), tc.tag)
		if err == nil || errors.Is(err, ErrRelease) != tc.definitive {
			t.Errorf("%s: err %v, definitive want %v", tc.tag, err, tc.definitive)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	const a = "k3sm_0.2.0_darwin_arm64.tar.gz"
	other := strings.Repeat("b", 64)
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"exact":       {targetSum + "  " + a + "\n", true},
		"suffix only": {targetSum + "  x" + a + "\n", false},
		"malformed":   {"XYZ  " + a + "\n", false},
		"conflict":    {targetSum + "  " + a + "\n" + other + "  " + a + "\n", false},
		"empty":       {"", false},
	} {
		got, err := checksumFor([]byte(tc.body), a)
		if tc.ok != (err == nil) || (tc.ok && got != targetSum) {
			t.Errorf("%s: got %q err %v", name, got, err)
		}
	}
}

func TestVersionHelpers(t *testing.T) {
	n := node("n", "v1.34.1+k3sm.0.2.0-rc.1", false)
	if !onTarget(n, "v0.2.0-rc.1") || onTarget(n, "v0.2.0") {
		t.Fatal("onTarget")
	}
	if got := fromRelease(n); got != "v0.2.0-rc.1" {
		t.Fatalf("fromRelease %q", got)
	}
	if got := fromRelease(node("n", "v1.34.1", false)); got != "v1.34.1" {
		t.Fatalf("fromRelease without a k3sm part %q", got)
	}
	for _, tc := range []struct {
		from, to string
		down     bool
	}{
		{"v0.2.0", "v0.1.9", true},
		{"v0.2.0", "v0.2.0-rc.1", true},
		{"v0.2.0-rc.2", "v0.2.0-rc.10", false},
		{"v0.2.0-rc.1", "v0.2.0", false},
		{"v0.2.0", "v0.10.0", false},
		{"v0.0.0-20261001-abcdef.dirty", "v0.1.0", false}, // a dev build is never a downgrade
		{"(devel)", "v0.1.0", false},
	} {
		if got := isDowngrade(tc.from, tc.to); got != tc.down {
			t.Errorf("isDowngrade(%s, %s) = %v", tc.from, tc.to, got)
		}
	}
}

func TestBarePodsFailTheNodeWithoutEviction(t *testing.T) {
	r := newRig(t, append(threeNodes(), podNode())...)
	for _, p := range []*corev1.Pod{pod("bare", "w0", nil), pod("rs", "w0", owned)} {
		if err := r.cs.Tracker().Add(p); err != nil {
			t.Fatal(err)
		}
	}
	evictions := 0
	r.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "eviction" {
			evictions++
		}
		return false, nil, nil
	})
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true}})
	r.drive(r.controller(), nil)
	u := r.update(updatesv1alpha1.UpdateName)
	e := u.Status.Nodes[0]
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || e.Phase != updatesv1alpha1.UpdateNodePhaseFailed ||
		!strings.Contains(e.Message, "default/bare") || strings.Contains(e.Message, "default/rs") {
		t.Fatalf("phase %q entry %+v", u.Status.Phase, e)
	}
	if evictions != 0 {
		t.Fatalf("%d evictions with a bare pod on the node", evictions)
	}
}

func TestServerIsNeverDrained(t *testing.T) {
	r := newRig(t, threeNodes()...)
	if err := r.cs.Tracker().Add(pod("native", serverName, owned)); err != nil {
		t.Fatal(err)
	}
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true}})
	r.drive(r.controller(), nil)
	if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
		t.Fatalf("phase %q", got)
	}
	if _, err := r.cs.CoreV1().Pods("default").Get(context.Background(), "native", metav1.GetOptions{}); err != nil {
		t.Fatalf("the server's pod was evicted: %v", err)
	}
}

func TestSingleNodeDrainIsRefused(t *testing.T) {
	r := newRig(t, node(serverName, oldKubelet, true))
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true}})
	r.drive(r.controller(), nil)
	u := r.update(updatesv1alpha1.UpdateName)
	c := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || c == nil || !strings.Contains(c.Message, "one node") || len(r.log()) != 0 {
		t.Fatalf("phase %q Failed %+v actions %v", u.Status.Phase, c, r.log())
	}
}

func TestSettleBeforeUncordon(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.step = time.Second
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	var readyAt time.Time
	r.drive(c, func() bool {
		if readyAt.IsZero() {
			if t0, ok := annotationTime(r.node("w1"), ReadyAtAnnotation); ok {
				readyAt = t0
			}
		}
		return len(r.log()) == 3 // w1 uncordoned
	})
	if readyAt.IsZero() {
		t.Fatal("w1 was never marked ready")
	}
	if waited := r.now.Sub(readyAt); waited < SettlePeriod {
		t.Fatalf("w1 uncordoned %s after it was Ready, want at least %s", waited, SettlePeriod)
	}
	n := r.node("w1")
	for _, k := range []string{CordonedAnnotation, HandedOverAnnotation, ReadyAtAnnotation} {
		if _, ok := n.Annotations[k]; ok {
			t.Errorf("annotation %s left on a done node", k)
		}
	}
}

func TestNotReadyNodeIsHeldAndReported(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.notReady["w1"] = true
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	for range 20 {
		if _, err := c.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.nodeSide()
		r.now = r.now.Add(10 * time.Second)
	}
	u := r.update(updatesv1alpha1.UpdateName)
	if e := u.Status.Nodes[0]; e.Phase == updatesv1alpha1.UpdateNodePhaseDone || !strings.Contains(e.Message, "Ready") {
		t.Fatalf("w1 entry %+v", e)
	}
	if !r.node("w1").Spec.Unschedulable {
		t.Fatal("a NotReady node was uncordoned")
	}
	if !strings.Contains(meta.FindStatusCondition(u.Status.Conditions, ConditionProgressing).Message, "last progress ") {
		t.Fatalf("Progressing %+v", meta.FindStatusCondition(u.Status.Conditions, ConditionProgressing))
	}
	// It comes back Ready: the roll finishes.
	n := r.node("w1")
	n.Status.Conditions[0].Status = corev1.ConditionTrue
	if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
		t.Fatal(err)
	}
	r.notReady = map[string]bool{}
	r.drive(c, nil)
	if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
		t.Fatalf("phase %q", got)
	}
}

func TestNodeTimeoutCountsFromTheHandover(t *testing.T) {
	r := newRig(t, append(threeNodes(), podNode())...)
	if err := r.cs.Tracker().Add(pod("slow", "w0", owned)); err != nil {
		t.Fatal(err)
	}
	refusals := 30 // the budget holds the pod for about 300 s
	r.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "eviction" && refusals > 0 {
			refusals--
			return true, nil, tooManyRequests()
		}
		return false, nil, nil
	})
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target, Strategy: updatesv1alpha1.UpdateStrategy{Drain: true}})
	c := r.controller()
	c.cfg.NodeTimeout = 2 * time.Minute // shorter than the drain, longer than the node-side
	r.drive(c, nil)
	if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
		t.Fatalf("phase %q: the drain ate the node timeout", got)
	}
}

func TestResolveRetryIsBounded(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.resolver.err = errors.New("connection refused")
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	for _, step := range []time.Duration{0, 5 * time.Minute, 6 * time.Minute} {
		r.now = r.now.Add(step)
		if _, err := c.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	u := r.update(updatesv1alpha1.UpdateName)
	f := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || f == nil || !strings.Contains(f.Message, "connection refused") {
		t.Fatalf("phase %q Failed %+v", u.Status.Phase, f)
	}
	if len(r.log()) != 0 {
		t.Fatalf("a node was touched: %v", r.log())
	}
}

func TestPhaseTransitionsRecordEvents(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.failNodes["w2"] = "disk full"
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	r.drive(r.controller(), nil)
	close(r.recorder.Events)
	var got []string
	for ev := range r.recorder.Events {
		got = append(got, ev)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"Normal NodeCordoning node w1: Cordoning",
		"Normal NodeCordoning update to v0.2.0: Cordoning",
		"Normal NodeDone node w1: Done",
		"Warning NodeFailed node w2: Failed: disk full",
		"Warning NodeFailed update to v0.2.0: Failed: disk full",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no event %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "node srv") {
		t.Errorf("an event for a node the roll never reached:\n%s", joined)
	}
}

// TestBuildMetadataMatchesNodeVersion pins buildMetadata to the k3sm part
// pkg/version's NodeVersion reports, so onTarget sees a node's release the
// way the node writes it.
func TestBuildMetadataMatchesNodeVersion(t *testing.T) {
	for _, tag := range []string{
		"v0.2.0", "0.2.0", "v0.2.0-rc.1", "v0.2.0+meta", "v0.0.0-20261016120000-abcdef012345", "v1.2.3_x", "(devel)",
	} {
		nv := version.Info{KubeVersion: "v1.34.1", Version: tag}.NodeVersion()
		_, part, ok := strings.Cut(nv, nodeVersionMarker)
		if !ok {
			t.Fatalf("%s: NodeVersion %q carries no %q", tag, nv, nodeVersionMarker)
		}
		if got := buildMetadata(tag); got != part {
			t.Errorf("%s: buildMetadata %q, NodeVersion part %q", tag, got, part)
		}
		if !onTarget(node("n", nv, false), tag) {
			t.Errorf("%s: a node reporting %q is not on it", tag, nv)
		}
	}
}
