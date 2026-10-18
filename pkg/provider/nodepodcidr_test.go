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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestNodePublishesItsPodCIDR pins how a node publishes its pod range: a fresh
// registration carries it in spec.podCIDR and spec.podCIDRs, an existing Node
// without one is patched once at start, a Node with the same value is left
// alone, a Node with a different value gets a Warn and no patch (spec.podCIDR is
// immutable once set), a rejected patch is not retried, and a range that fails
// validation writes nothing.
func TestNodePublishesItsPodCIDR(t *testing.T) {
	const (
		name   = "worker"
		cidr   = "100.64.1.0/24"
		meshIP = "100.64.1.1"
	)
	ctx := context.Background()

	type actions struct{ gets, patches int }
	count := func(cs *fake.Clientset) actions {
		var a actions
		for _, act := range cs.Actions() {
			if act.GetResource().Resource != "nodes" {
				continue
			}
			switch act.GetVerb() {
			case "get":
				a.gets++
			case "patch":
				a.patches++
			}
		}
		return a
	}
	podCIDRs := func(t *testing.T, cs *fake.Clientset) (string, []string) {
		t.Helper()
		n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node: %v", err)
		}
		return n.Spec.PodCIDR, n.Spec.PodCIDRs
	}
	node := func(podCIDR string) *corev1.Node {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if podCIDR != "" {
			n.Spec.PodCIDR = podCIDR
			n.Spec.PodCIDRs = []string{podCIDR}
		}
		return n
	}

	t.Run("fresh registration carries the range", func(t *testing.T) {
		r := NewNodePodRange(cidr, meshIP, nil)
		n := node("")
		r.Stamp(n)
		cs := fake.NewClientset()
		if _, err := cs.CoreV1().Nodes().Create(ctx, n, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, gots := podCIDRs(t, cs)
		if got != cidr || len(gots) != 1 || gots[0] != cidr {
			t.Fatalf("registered spec.podCIDR=%q podCIDRs=%v, want %q and [%q]", got, gots, cidr, cidr)
		}
		// The start patch then finds the value in place and writes nothing.
		cs.ClearActions()
		if err := r.Publish(ctx, cs.CoreV1().Nodes(), name); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if a := count(cs); a.patches != 0 {
			t.Fatalf("patches after a fresh registration = %d, want 0", a.patches)
		}
	})

	t.Run("existing node without a range is patched once at start", func(t *testing.T) {
		cs := fake.NewClientset(node(""))
		if err := NewNodePodRange(cidr, meshIP, nil).Publish(ctx, cs.CoreV1().Nodes(), name); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if a := count(cs); a.gets != 1 || a.patches != 1 {
			t.Fatalf("actions = %+v, want one get and one patch", a)
		}
		for _, act := range cs.Actions() {
			if p, ok := act.(k8stesting.PatchAction); ok && p.GetSubresource() != "" {
				t.Fatalf("patched subresource %q, want the Node spec", p.GetSubresource())
			}
		}
		got, gots := podCIDRs(t, cs)
		if got != cidr || len(gots) != 1 || gots[0] != cidr {
			t.Fatalf("patched spec.podCIDR=%q podCIDRs=%v, want %q and [%q]", got, gots, cidr, cidr)
		}
	})

	t.Run("node with the same range is untouched", func(t *testing.T) {
		cs := fake.NewClientset(node(cidr))
		if err := NewNodePodRange(cidr, meshIP, nil).Publish(ctx, cs.CoreV1().Nodes(), name); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if a := count(cs); a.patches != 0 {
			t.Fatalf("patches = %d, want 0", a.patches)
		}
	})

	t.Run("node with a different range gets a warn and no patch", func(t *testing.T) {
		const other = "100.64.7.0/24"
		var logs bytes.Buffer
		cs := fake.NewClientset(node(other))
		r := NewNodePodRange(cidr, meshIP, slog.New(slog.NewTextHandler(&logs, nil)))
		if err := r.Publish(ctx, cs.CoreV1().Nodes(), name); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if a := count(cs); a.gets != 1 || a.patches != 0 {
			t.Fatalf("actions = %+v, want one get and no patch", a)
		}
		out := logs.String()
		if strings.Count(out, "level=WARN") != 1 || !strings.Contains(out, other) || !strings.Contains(out, cidr) {
			t.Fatalf("want one Warn naming %s and %s, got:\n%s", other, cidr, out)
		}
		if got, _ := podCIDRs(t, cs); got != other {
			t.Fatalf("spec.podCIDR = %q, want the existing %q kept", got, other)
		}
	})

	t.Run("rejected patch is not retried", func(t *testing.T) {
		cs := fake.NewClientset(node(""))
		rejected := errors.New("rejected")
		cs.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, rejected
		})
		err := NewNodePodRange(cidr, meshIP, nil).Publish(ctx, cs.CoreV1().Nodes(), name)
		if !errors.Is(err, rejected) {
			t.Fatalf("publish err = %v, want the rejection", err)
		}
		if a := count(cs); a.gets != 1 || a.patches != 1 {
			t.Fatalf("actions = %+v, want one get and one patch", a)
		}
	})

	for _, tc := range []struct{ name, cidr, meshIP string }{
		{"not a /24", "100.64.0.0/23", "100.64.0.1"},
		{"the cluster aggregate", "100.64.0.0/10", "100.64.0.1"},
		{"outside the cluster CIDR", "10.42.1.0/24", "10.42.1.1"},
		{"does not contain the mesh IP", cidr, "100.64.2.1"},
		{"unparseable", "not-a-cidr", meshIP},
		{"IPv6", "fd00::/24", meshIP},
		{"host bits set", "100.64.1.1/24", meshIP},
		{"no mesh IP", cidr, ""},
	} {
		t.Run("invalid range writes nothing: "+tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			r := NewNodePodRange(tc.cidr, tc.meshIP, slog.New(slog.NewTextHandler(&logs, nil)))
			if !strings.Contains(logs.String(), "level=WARN") {
				t.Fatalf("want a Warn for the invalid range, got:\n%s", logs.String())
			}
			n := node("")
			r.Stamp(n)
			if n.Spec.PodCIDR != "" || len(n.Spec.PodCIDRs) != 0 {
				t.Fatalf("stamped %q %v from an invalid range", n.Spec.PodCIDR, n.Spec.PodCIDRs)
			}
			cs := fake.NewClientset(node(""))
			if err := r.Publish(ctx, cs.CoreV1().Nodes(), name); err != nil {
				t.Fatalf("publish: %v", err)
			}
			if a := count(cs); a.gets != 0 || a.patches != 0 {
				t.Fatalf("actions = %+v, want none", a)
			}
		})
	}
}
