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

package svcstatus

import (
	"context"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/status"
)

// service returns a one-port TCP ClusterIP Service created at created.
func service(ns, name, clusterIP string, port int32, created time.Time) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, CreationTimestamp: metav1.NewTime(created)},
		Spec: corev1.ServiceSpec{ClusterIP: clusterIP, Ports: []corev1.ServicePort{
			{Port: port, Protocol: corev1.ProtocolTCP},
		}},
	}
}

// slice returns an IPv4 EndpointSlice for ns/svc on port, last written at
// written, with one endpoint per address and the given readiness.
func slice(ns, svc string, port int32, written time.Time, ready map[string]bool) *discoveryv1.EndpointSlice {
	sl := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: svc + "-abc",
			Labels:            map[string]string{discoveryv1.LabelServiceName: svc},
			CreationTimestamp: metav1.NewTime(written.Add(-time.Hour)),
			ManagedFields:     []metav1.ManagedFieldsEntry{{Manager: "endpointslice-controller.k8s.io", Time: &metav1.Time{Time: written}}},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Port: &port}},
	}
	addrs := make([]string, 0, len(ready))
	for a := range ready {
		addrs = append(addrs, a)
	}
	slices.Sort(addrs)
	for _, a := range addrs {
		r := ready[a]
		sl.Endpoints = append(sl.Endpoints, discoveryv1.Endpoint{Addresses: []string{a}, Conditions: discoveryv1.EndpointConditions{Ready: &r}})
	}
	return sl
}

// TestCompareServicesNamesTheMissingBackend drives the comparer over a fake
// clientset: a Service port whose record lacks a Ready endpoint the LIST has is
// diverging and names it; an unready endpoint is not expected; the cluster DNS
// VIP and a pinned Service are not compared; a Service changed after the record,
// or gone from the API, is settling rather than diverging.
func TestCompareServicesNamesTheMissingBackend(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)
	objs := []runtime.Object{
		service("web", "front", "10.43.0.20", 80, old),
		slice("web", "front", 8080, old, map[string]bool{"100.64.0.7": true, "100.64.0.9": true, "100.64.0.11": false}),
		service("web", "fresh", "10.43.0.21", 80, old),
		slice("web", "fresh", 8080, now.Add(-time.Second), map[string]bool{"100.64.0.8": true}),
		service("kube-system", "kube-dns", "10.43.0.10", 53, old),
		slice("kube-system", "kube-dns", 53, old, map[string]bool{"100.64.0.2": true}),
		service("default", "kubernetes", "10.43.0.1", 443, old),
		service("web", "same", "10.43.0.22", 80, old),
		slice("web", "same", 8080, old, map[string]bool{"100.64.0.12": true}),
	}
	rec := status.ServicesRecord{
		UpdatedAt: now.Add(-20 * time.Second),
		Unproxied: []string{"10.43.0.10"},
		VIPs: []status.VIPEntry{
			{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP", Namespace: "default", Name: "kubernetes", Backends: []string{"127.0.0.1:6443"}, Static: true},
			{ClusterIP: "10.43.0.20", Port: 80, Protocol: "TCP", Namespace: "web", Name: "front", Backends: []string{"100.64.0.7:8080"}},
			{ClusterIP: "10.43.0.21", Port: 80, Protocol: "TCP", Namespace: "web", Name: "fresh", Backends: []string{}},
			{ClusterIP: "10.43.0.22", Port: 80, Protocol: "TCP", Namespace: "web", Name: "same", Backends: []string{"100.64.0.12:8080"}},
			{ClusterIP: "10.43.0.30", Port: 80, Protocol: "TCP", Namespace: "web", Name: "deleted", Backends: []string{"100.64.0.13:8080"}},
		},
	}
	got, err := Comparer{Client: fake.NewClientset(objs...), Timeout: time.Second}.CompareServices(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Diverging) != 1 {
		t.Fatalf("diverging = %+v, want only web/front", got.Diverging)
	}
	d := got.Diverging[0]
	if d.Namespace != "web" || d.Name != "front" || d.Port != "10.43.0.20:80/TCP" ||
		!slices.Equal(d.Missing, []string{"100.64.0.9:8080"}) || len(d.Extra) != 0 {
		t.Errorf("divergence = %+v, want web/front 10.43.0.20:80/TCP missing 100.64.0.9:8080", d)
	}
	var settling []string
	for _, s := range got.Settling {
		settling = append(settling, s.Namespace+"/"+s.Name)
	}
	if !slices.Equal(settling, []string{"web/fresh", "web/deleted"}) {
		t.Errorf("settling = %v, want [web/fresh web/deleted]", settling)
	}
}
