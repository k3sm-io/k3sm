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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

// TestNodeStatusCarriesAdminTokenRotated: a control plane whose mark names the
// release its entry moves it to carries AdminTokenRotated, its message names
// the remedy and the Succeeded condition names it. The version decides, not
// the clock: a mark timed before the handover (a lagging control-plane clock)
// still counts. A mark naming another release (an unstamped build) is logged
// with both versions and counts only when it was made at or after the
// handover. A worker's mark is
// ignored. A mark that lands after the node settled is still recorded while
// the roll goes on, and when it ends cancelled. The handover clears a mark a
// node carried in from an earlier roll.
func TestNodeStatusCarriesAdminTokenRotated(t *testing.T) {
	const cp2 = "cp2" // a control plane that is not the controller's own
	type mark struct {
		node    string
		version string
		offset  time.Duration // the mark's time relative to the node's handover
		late    bool          // set once the node's entry is Done, not when it reports Done
	}
	for _, tc := range []struct {
		name    string
		marks   []mark
		cancel  bool
		rotated []string
		warn    string // a Warn line must carry this
	}{
		{name: "a mark for the release, at the handover", marks: []mark{{node: serverName, version: "0.2.0"}}, rotated: []string{serverName}},
		{name: "a mark for the release, timed before the handover", marks: []mark{{node: serverName, version: target, offset: -time.Hour}}, rotated: []string{serverName}},
		{name: "a mark for another release, made after the handover", marks: []mark{{node: serverName, version: "dev", offset: time.Minute}}, rotated: []string{serverName}, warn: "mark_version=dev to=v0.2.0"},
		{name: "a mark for another release, made at the handover", marks: []mark{{node: serverName, version: "0.1.9"}}, rotated: []string{serverName}, warn: "mark_version=0.1.9 to=v0.2.0"},
		{name: "a mark for another release, made before the handover", marks: []mark{{node: serverName, version: "0.1.9", offset: -time.Second}}, warn: "mark_version=0.1.9 to=v0.2.0"},
		{name: "no mark"},
		{name: "a worker's mark", marks: []mark{{node: "w1", version: "0.2.0"}}},
		{name: "a mark that lands after the node settled", marks: []mark{{node: cp2, version: "0.2.0", late: true}}, rotated: []string{cp2}},
		{name: "a mark on a roll that ends cancelled", marks: []mark{{node: cp2, version: "0.2.0"}}, cancel: true, rotated: []string{cp2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := append(threeNodes(), node(cp2, oldKubelet, true))
			// w1 carries a mark from an earlier roll: its handover clears it.
			nodes[2].Annotations = map[string]string{AdminTokenRotatedAnnotation: "0.2.0 " + rigStart.Add(-time.Hour).Format(time.RFC3339)}
			r := newRig(t, nodes...)
			r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
			c := r.controller()
			var logs bytes.Buffer
			c.log = slog.New(slog.NewTextHandler(&logs, nil))
			done := map[string]bool{}
			cancelled := false
			for range 1000 {
				if _, err := c.reconcile(context.Background()); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				u := r.update(updatesv1alpha1.UpdateName)
				if finished(u) {
					break
				}
				entryDone := map[string]bool{}
				for _, e := range u.Status.Nodes {
					entryDone[e.Name] = e.Phase == updatesv1alpha1.UpdateNodePhaseDone
				}
				r.nodeSide()
				for _, m := range tc.marks {
					n := r.node(m.node)
					reported := n.Annotations[updatesv1alpha1.AnnotationUpdatePhase] == string(updatesv1alpha1.UpdateNodePhaseDone)
					if done[m.node] || !reported || (m.late && !entryDone[m.node]) {
						continue
					}
					handedAt, ok := annotationTime(n, HandedOverAnnotation)
					if !ok {
						handedAt = r.now // the release patch has already gone
					}
					n.Annotations[AdminTokenRotatedAnnotation] = m.version + " " + handedAt.Add(m.offset).Format(time.RFC3339)
					if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
						t.Fatal(err)
					}
					done[m.node] = true
				}
				// Cancel while cp2 settles: the roll ends before srv starts.
				if tc.cancel && !cancelled && done[cp2] {
					r.setCancel()
					cancelled = true
				}
				r.now = r.now.Add(r.step)
			}
			u := r.update(updatesv1alpha1.UpdateName)
			want := updatesv1alpha1.UpdatePhaseSucceeded
			if tc.cancel {
				want = updatesv1alpha1.UpdatePhaseCancelled
			}
			if u.Status.Phase != want {
				t.Fatalf("phase %q, want %q", u.Status.Phase, want)
			}
			for _, e := range u.Status.Nodes {
				flagged := slices.Contains(tc.rotated, e.Name)
				if e.AdminTokenRotated != flagged {
					t.Errorf("node %s AdminTokenRotated = %v, want %v", e.Name, e.AdminTokenRotated, flagged)
				}
				if got := strings.Contains(e.Message, AdminTokenRotatedMessage); got != flagged {
					t.Errorf("node %s message %q: remedy present %v, want %v", e.Name, e.Message, got, flagged)
				}
			}
			if !tc.cancel {
				succeeded := meta.FindStatusCondition(u.Status.Conditions, ConditionSucceeded)
				if succeeded == nil {
					t.Fatal("no Succeeded condition")
				}
				for _, name := range []string{serverName, cp2} {
					names := strings.Contains(succeeded.Message, "admin credential re-minted on") && strings.Contains(succeeded.Message, name)
					if flagged := slices.Contains(tc.rotated, name); names != flagged {
						t.Errorf("Succeeded message %q: names %s %v, want %v", succeeded.Message, name, names, flagged)
					}
				}
			}
			if v := r.node("w1").Annotations[AdminTokenRotatedAnnotation]; strings.HasSuffix(v, rigStart.Add(-time.Hour).Format(time.RFC3339)) {
				t.Error("the handover left w1's mark from an earlier roll")
			}
			if tc.warn != "" && (!strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), tc.warn)) {
				t.Errorf("no Warn naming both versions (%q) in:\n%s", tc.warn, logs.String())
			}
			if tc.warn == "" && strings.Contains(logs.String(), "mark_version=") {
				t.Errorf("a version-mismatch Warn on a mark that names the release:\n%s", logs.String())
			}
		})
	}
}

// TestAdminTokenRotationAfterSucceeded: a control plane's mark that lands
// after the newest Update reached Succeeded is still recorded on it, and the
// Succeeded condition names the node; once a newer Update exists the old one
// is left as it is.
func TestAdminTokenRotationAfterSucceeded(t *testing.T) {
	const cp2 = "cp2"
	succeeded := func(t *testing.T) (*rig, *Controller) {
		t.Helper()
		r := newRig(t, append(threeNodes(), node(cp2, oldKubelet, true))...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		c := r.controller()
		r.drive(c, nil)
		if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q, want Succeeded", got)
		}
		return r, c
	}
	markLate := func(t *testing.T, r *rig, c *Controller, name string) *updatesv1alpha1.Update {
		t.Helper()
		n := r.node(name)
		n.Annotations[AdminTokenRotatedAnnotation] = "0.2.0 " + r.now.Format(time.RFC3339)
		if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := c.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		return r.update(updatesv1alpha1.UpdateName)
	}
	entry := func(u *updatesv1alpha1.Update, name string) updatesv1alpha1.UpdateNodeStatus {
		for _, e := range u.Status.Nodes {
			if e.Name == name {
				return e
			}
		}
		return updatesv1alpha1.UpdateNodeStatus{}
	}

	t.Run("the newest Update records a late mark", func(t *testing.T) {
		r, c := succeeded(t)
		u := markLate(t, r, c, serverName)
		if e := entry(u, serverName); !e.AdminTokenRotated || !strings.Contains(e.Message, AdminTokenRotatedMessage) {
			t.Errorf("srv entry %+v: want the flag and the remedy", e)
		}
		if cond := meta.FindStatusCondition(u.Status.Conditions, ConditionSucceeded); cond == nil || cond.Status != metav1.ConditionTrue ||
			!strings.Contains(cond.Message, "admin credential re-minted on "+serverName) {
			t.Errorf("Succeeded %+v", cond)
		}
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Errorf("phase %q", u.Status.Phase)
		}
	})

	t.Run("an Update a newer one followed is left alone", func(t *testing.T) {
		r, c := succeeded(t)
		newer := &updatesv1alpha1.Update{
			TypeMeta:   metav1.TypeMeta{APIVersion: updatesv1alpha1.SchemeGroupVersion.String(), Kind: "Update"},
			ObjectMeta: metav1.ObjectMeta{Name: "later", Generation: 1, CreationTimestamp: metav1.NewTime(r.now)},
			Spec:       updatesv1alpha1.UpdateSpec{Version: "v0.2.1"},
		}
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(newer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.dyn.Resource(updateResource).Create(context.Background(), &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		u := markLate(t, r, c, cp2)
		if e := entry(u, cp2); e.AdminTokenRotated || strings.Contains(e.Message, AdminTokenRotatedMessage) {
			t.Errorf("cp2 entry %+v: an older Update recorded a mark", e)
		}
		if cond := meta.FindStatusCondition(u.Status.Conditions, ConditionSucceeded); cond == nil || strings.Contains(cond.Message, "re-minted") {
			t.Errorf("Succeeded %+v", cond)
		}
	})
}

// TestParseAdminTokenRotatedMark pins the annotation's one shape.
func TestParseAdminTokenRotatedMark(t *testing.T) {
	for _, tc := range []struct {
		in      string
		version string
		ok      bool
	}{
		{"0.2.0 2026-10-17T09:30:00Z", "0.2.0", true},
		{"v0.2.0 2026-10-17T09:30:00Z", "v0.2.0", true},
		{"2026-10-17T09:30:00Z", "", false},
		{"0.2.0 not-a-time", "", false},
		{"0.2.0 2026-10-17T09:30:00Z extra", "", false},
		{" 2026-10-17T09:30:00Z", "", false},
		{"", "", false},
	} {
		v, _, ok := ParseAdminTokenRotatedMark(tc.in)
		if ok != tc.ok || v != tc.version {
			t.Errorf("ParseAdminTokenRotatedMark(%q) = %q, %v; want %q, %v", tc.in, v, ok, tc.version, tc.ok)
		}
	}
}
