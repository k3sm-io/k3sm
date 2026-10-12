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

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/interconnect"
)

// TestInterconnectIndicesAndPeersUseTheSlotDerivation pins the wiring of the
// node index and the slot-0 addresses: the index is podnet.NodeIndex of the
// node's MeshPeer pod /24 (netd's own derivation), the address is
// InterconnectSlotAddress(idx, 0), and a node beyond the ceiling has none.
func TestInterconnectIndicesAndPeersUseTheSlotDerivation(t *testing.T) {
	list := func(context.Context) ([]netv1.MeshPeerSpec, error) {
		return []netv1.MeshPeerSpec{
			{NodeName: "studio", PodCIDR: "100.64.0.0/24"},
			{NodeName: "book", PodCIDR: "100.64.1.0/24"},
			{NodeName: "far", PodCIDR: "100.64.31.0/24"},
			{NodeName: "garbage", PodCIDR: "not-a-cidr"},
			{NodeName: "outside", PodCIDR: "10.0.0.0/24"},
		}, nil
	}
	idx, err := meshPeerIndices(list)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"studio": 0, "book": 1, "far": 31}; !reflect.DeepEqual(idx, want) {
		t.Errorf("indices = %v, want %v", idx, want)
	}
	set, err := meshPeerIndexSet(list)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Invalid) != 2 || set.Invalid["garbage"] == "" || set.Invalid["outside"] == "" {
		t.Errorf("invalid = %v, want garbage and outside reported, never skipped silently", set.Invalid)
	}
	peers, err := slot0Peers(meshPeerIndices(list))(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for n, a := range peers {
		got[n] = a.String()
	}
	if want := map[string]string{"studio": "169.254.0.1", "book": "169.254.0.9"}; !reflect.DeepEqual(got, want) {
		t.Errorf("slot-0 peers = %v, want %v (index 31 has no address)", got, want)
	}
}

// TestInterconnectMetricsRoute pins that the metrics ride the kubelet endpoint
// at their path and render in the Prometheus text format.
func TestInterconnectMetricsRoute(t *testing.T) {
	m := interconnect.NewMetrics()
	m.SetMembers(map[string]bool{"studio": true})
	routes := interconnectRoutes(m)
	if len(routes) != 1 || routes[0].Pattern != interconnect.MetricsPath {
		t.Fatalf("routes = %+v, want one at %s", routes, interconnect.MetricsPath)
	}
	rec := httptest.NewRecorder()
	routes[0].Handler.ServeHTTP(rec, httptest.NewRequest("GET", interconnect.MetricsPath, nil))
	if body := rec.Body.String(); !strings.Contains(body, `k3sm_interconnect_member_up{node="studio"} 1`) ||
		!strings.Contains(body, "k3sm_interconnect_attached_pods 0") {
		t.Errorf("metrics body = %q", body)
	}
	if interconnectRoutes(nil) != nil {
		t.Error("nil metrics must add no route")
	}
}

// TestInterconnectNodeNeedsTheHelper pins that a node without the root helper
// starts no interconnect loop (the alias verbs exist only there).
func TestInterconnectNodeNeedsTheHelper(t *testing.T) {
	stop := startInterconnectNode(context.Background(), nodeOptions{nodeName: "n", netMode: hostnet.Mode{Backend: hostnet.BackendNone}},
		fake.NewClientset(), nil, nil, nil, slog.New(slog.DiscardHandler))
	stop() // a no-op stop; a started loop would need a rest config and panic above
}

// TestInterconnectCLI pins the verb surface: enable records the authenticated
// identity, disable clears it, and bad usage is refused before any client.
func TestInterconnectCLI(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "selfsubjectreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.SelfSubjectReview{Status: authenticationv1.SelfSubjectReviewStatus{
			UserInfo: authenticationv1.UserInfo{Username: "system:admin"},
		}}, nil
	})
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{interconnect.GVR: "InterconnectList"})
	var asked []string
	clients := func(kc string) (kubernetes.Interface, dynamic.Interface, error) {
		asked = append(asked, kc)
		return cs, dyn, nil
	}
	var out, errb bytes.Buffer
	if err := runInterconnectWith([]string{"enable", "--kubeconfig", "/x/admin.kubeconfig"}, &out, &errb, clients); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !strings.Contains(out.String(), "armed by system:admin") || !reflect.DeepEqual(asked, []string{"/x/admin.kubeconfig"}) {
		t.Errorf("enable output = %q, kubeconfig = %v", out.String(), asked)
	}
	ic, err := interconnect.Store{Client: dyn}.Get(context.Background(), interconnect.Name)
	if err != nil || !ic.Spec.Enabled || ic.Status.ArmedBy != "system:admin" {
		t.Fatalf("after enable: %+v, %v", ic, err)
	}
	out.Reset()
	if err := runInterconnectWith([]string{"disable", "thunderbolt"}, &out, &errb, clients); err != nil {
		t.Fatalf("disable: %v", err)
	}
	ic, _ = interconnect.Store{Client: dyn}.Get(context.Background(), interconnect.Name)
	if ic.Spec.Enabled || ic.Status.ArmedBy != "" {
		t.Errorf("after disable: %+v", ic)
	}
	asked = nil
	for _, bad := range [][]string{nil, {"arm"}, {"enable", "a", "b"}} {
		if err := runInterconnectWith(bad, &out, &errb, clients); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if len(asked) != 0 {
		t.Errorf("bad usage built clients %v", asked)
	}
}
