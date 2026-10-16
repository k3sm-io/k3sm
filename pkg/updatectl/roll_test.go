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
)

func pod(name, nodeName string, mutate func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: corev1.PodSpec{NodeName: nodeName}}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func TestDrainHonoursBudgetsAndSkipsDaemonSetAndMirrorPods(t *testing.T) {
	r := newRig(t, append(threeNodes(), podNode())...)
	pods := []*corev1.Pod{
		pod("plain", "w0", nil),
		pod("budgeted", "w0", nil),
		pod("ds", "w0", func(p *corev1.Pod) {
			p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "d", UID: "u", Controller: ptr.To(true)}}
		}),
		pod("mirror", "w0", func(p *corev1.Pod) { p.Annotations = map[string]string{mirrorPodAnnotation: "x"} }),
		pod("done", "w0", func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }),
		pod("elsewhere", "not-in-the-roll", nil), // another node's pod
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
	if err := r.cs.Tracker().Add(pod("stuck", "w0", nil)); err != nil {
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

func TestHTTPResolver(t *testing.T) {
	const sums = "aaaa  other.tar.gz\n" + targetSum + "  k3sm_0.2.0_darwin_arm64.tar.gz\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/releases/download/v0.2.0/k3sm_0.2.0_checksums.txt":
			_, _ = w.Write([]byte(sums))
		case "/releases/download/v0.3.0/k3sm_0.3.0_checksums.txt":
			_, _ = w.Write([]byte("aaaa  other.tar.gz\n"))
		case "/releases/download/v0.4.0/k3sm_0.4.0_checksums.txt":
			http.Error(w, "boom", http.StatusBadGateway)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()
	res := HTTPResolver{Base: srv.URL + "/releases", Client: srv.Client()}

	got, err := res.Resolve(context.Background(), "0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	want := Release{Version: "0.2.0", URL: srv.URL + "/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz", SHA256: targetSum}
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
