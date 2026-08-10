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

package svclb

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/ports"
)

func strptr(s string) *string { return &s }

// TestLoadBalancerClassRespected is B135's named gate.
//
// spec.loadBalancerClass is the API's multi-implementation contract: nil means
// "the default implementation", and an implementation must IGNORE a Service
// whose class it does not own. Upstream's ignore is literal — a classed Service
// is never enqueued, so it is never bound AND never status-patched.
//
// The assertion is therefore over the CLIENT ACTIONS, not over the resulting
// status. "Status is empty" would pass while k3sm wiped a foreign
// implementation's address, which is the precise failure this contract exists to
// prevent; only "we issued no write at all" distinguishes deferring from
// fighting.
func TestLoadBalancerClassRespected(t *testing.T) {
	ctx := context.Background()

	newController := func(t *testing.T, binder *fakeBinder, objs ...*corev1.Service) (*Controller, *fake.Clientset) {
		t.Helper()
		cs := fake.NewClientset()
		for _, o := range objs {
			if _, err := cs.CoreV1().Services(o.Namespace).Create(ctx, o, metav1.CreateOptions{}); err != nil {
				t.Fatalf("seed %s/%s: %v", o.Namespace, o.Name, err)
			}
		}
		c, err := New(Config{
			Client:        cs,
			BindAddr:      testBindAddr,
			AdvertiseAddr: testAdvertiseAddr,
			PodCIDR:       testPodCIDR,
			ReservedPorts: ports.ReservedSet(),
			Binder:        binder,
			Logger:        slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// Drop the seeding Creates so writeActions observes only what the
		// controller itself issues.
		cs.ClearActions()
		return c, cs
	}

	// writeActions returns every mutating action the controller issued against
	// the named Service. Reads are ignored; this is the "never patched" property.
	writeActions := func(cs *fake.Clientset, name string) []string {
		var out []string
		for _, a := range cs.Actions() {
			switch a.GetVerb() {
			case "get", "list", "watch":
				continue
			}
			if a.GetResource().Resource != "services" {
				continue
			}
			if u, ok := a.(k8stesting.UpdateAction); ok {
				if svc, ok := u.GetObject().(*corev1.Service); ok && svc.Name != name {
					continue
				}
			}
			out = append(out, a.GetVerb()+"/"+a.GetSubresource())
		}
		return out
	}

	t.Run("Claims is the one ownership rule", func(t *testing.T) {
		cases := []struct {
			name string
			svc  *corev1.Service
			want bool
		}{
			{"nil class is ours (the default implementation)", lbService("default", "a", "10.43.0.5", 80), true},
			{"foreign class is not ours", func() *corev1.Service {
				s := lbService("default", "b", "10.43.0.6", 80)
				s.Spec.LoadBalancerClass = strptr("metallb.universe.tf/metallb")
				return s
			}(), false},
			{"even a k3sm-shaped class is not claimed — k3sm publishes none", func() *corev1.Service {
				s := lbService("default", "c", "10.43.0.7", 80)
				s.Spec.LoadBalancerClass = strptr("k3sm.io/svclb")
				return s
			}(), false},
			{"empty-string class is still set, so not ours", func() *corev1.Service {
				s := lbService("default", "d", "10.43.0.8", 80)
				s.Spec.LoadBalancerClass = strptr("")
				return s
			}(), false},
			{"ignore-labelled (k3sm's own ingress Service) is not ours", func() *corev1.Service {
				s := lbService("kube-system", "k3sm-ingress", "10.43.0.9", 80)
				s.Labels = map[string]string{IgnoreLabel: "true"}
				return s
			}(), false},
			{"non-LoadBalancer type is not ours", &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "np"},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort},
			}, false},
			{"nil service", nil, false},
		}
		for _, tc := range cases {
			if got := Claims(tc.svc); got != tc.want {
				t.Errorf("Claims(%s) = %v, want %v", tc.name, got, tc.want)
			}
		}
	})

	t.Run("a foreign-class Service is never bound and never written", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "foreign", "10.43.0.20", 8093)
		svc.Spec.LoadBalancerClass = strptr("metallb.universe.tf/metallb")
		// The other implementation has already published ITS address.
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.168.7.7"}}
		c, cs := newController(t, binder, svc)

		c.reconcile(ctx, []*corev1.Service{svc})

		if n := len(binder.bound); n != 0 {
			t.Errorf("bound %d listener(s) for a Service with a foreign class; want 0", n)
		}
		if acts := writeActions(cs, "foreign"); len(acts) != 0 {
			t.Errorf("issued writes %v against a foreign-class Service; upstream never patches one", acts)
		}
		// And the other implementation's address must survive verbatim.
		got, err := cs.CoreV1().Services("default").Get(ctx, "foreign", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != "192.168.7.7" {
			t.Errorf("foreign address = %+v, want it untouched at 192.168.7.7", got.Status.LoadBalancer.Ingress)
		}
	})

	t.Run("a stale k3sm advertisement on a disclaimed Service is retracted once", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "was-ours", "10.43.0.21", 8094)
		svc.Spec.LoadBalancerClass = strptr("metallb.universe.tf/metallb")
		// An older k3sm build claimed it and published THIS node's address,
		// alongside the real owner's. The apiserver cannot clean this up: it wipes
		// LB status only on a type change and forbids changing the class in place.
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{IP: testAdvertiseAddr.String()},
			{IP: "192.168.7.7"},
		}
		c, cs := newController(t, binder, svc)

		c.reconcile(ctx, []*corev1.Service{svc})

		got, err := cs.CoreV1().Services("default").Get(ctx, "was-ours", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != "192.168.7.7" {
			t.Fatalf("after retraction status = %+v, want ONLY the other implementation's 192.168.7.7",
				got.Status.LoadBalancer.Ingress)
		}

		// One-shot: a second reconcile must not write again, or declining a
		// Service becomes a per-reconcile status fight with its real owner.
		before := len(writeActions(cs, "was-ours"))
		c.reconcile(ctx, []*corev1.Service{got})
		if after := len(writeActions(cs, "was-ours")); after != before {
			t.Errorf("retraction repeated: %d writes then %d; it must be one-shot per process", before, after)
		}
	})

	t.Run("an unclassed Service is still claimed and advertised", func(t *testing.T) {
		// POSITIVE CONTROL. Without it the table cannot distinguish "the class is
		// respected" from "every Service is now ignored", which would silently
		// disable the LoadBalancer implementation entirely.
		binder := &fakeBinder{}
		svc := lbService("default", "ours", "10.43.0.22", 8095)
		c, cs := newController(t, binder, svc)

		c.reconcile(ctx, []*corev1.Service{svc})

		got, err := cs.CoreV1().Services("default").Get(ctx, "ours", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != testAdvertiseAddr.String() {
			t.Errorf("unclassed Service status = %+v, want the node address %s",
				got.Status.LoadBalancer.Ingress, testAdvertiseAddr)
		}
	})
}
