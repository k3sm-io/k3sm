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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	crdconfig "k3sm.io/apis/config/crd"
	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// This file is B224's MESH-REGRESSION leg: the proof that adopting the MeshPeer CRD
// into bring-up's applied set did not perturb the mesh/enroll path it sits in front
// of. Both tests here are GREEN BEFORE AND AFTER the adoption by design — they are
// regression pins, not red-before evidence.
//
// What they prove, on one machine:
//   - the schema k3sm now applies ACCEPTS exactly the object the enroller writes
//     (every spec key is a declared property, so structural pruning drops nothing,
//     and every required key is populated);
//   - the enroller's own behaviour — index assignment, the create, and the rejoin
//     update — is unchanged, driven end to end through its real REST client.
//
// What they do NOT prove: that a live API server admits the write. A fake REST
// backend has no CRD, no structural pruning and no validation, so "the write lands"
// against a real apiserver is the integration leg of hack/acceptance/B224.sh, and
// the cross-node join remains the two-Mac K3SM_LAB slice.

// TestMeshPeerCRDSchemaAcceptsTheEnrollWrite pins the contract between the manifest
// bring-up now applies and the object the enroller POSTs.
//
// The CRD declares no x-kubernetes-preserve-unknown-fields, so a spec key the schema
// does not list is PRUNED by the API server — silently, with the write still
// succeeding. That failure mode is invisible to every other test in this repo: the
// enroll returns 201 and the peer comes back missing a field the mesh needs.
func TestMeshPeerCRDSchemaAcceptsTheEnrollWrite(t *testing.T) {
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(crdconfig.MeshPeerCRD(), &crd); err != nil {
		t.Fatalf("decode the embedded MeshPeer crd: %v", err)
	}

	if crd.Name != crdconfig.MeshPeerCRDName {
		t.Errorf("crd metadata.name %q, want %q", crd.Name, crdconfig.MeshPeerCRDName)
	}
	if crd.Spec.Group != netv1.SchemeGroupVersion.Group {
		t.Errorf("crd group %q, want %q (the group meshPeerRESTClient addresses)", crd.Spec.Group, netv1.SchemeGroupVersion.Group)
	}
	if crd.Spec.Names.Plural != meshPeerResource {
		t.Errorf("crd plural %q, want %q (the resource the enroller writes)", crd.Spec.Names.Plural, meshPeerResource)
	}
	// Cluster scope is load-bearing: the enroller's REST requests carry no namespace,
	// so a namespaced MeshPeer would 404 every enroll.
	if crd.Spec.Scope != apiextensionsv1.ClusterScoped {
		t.Errorf("crd scope %q, want %q — the enroller issues namespace-less requests", crd.Spec.Scope, apiextensionsv1.ClusterScoped)
	}

	var served *apiextensionsv1.CustomResourceDefinitionVersion
	for i := range crd.Spec.Versions {
		if crd.Spec.Versions[i].Name == netv1.SchemeGroupVersion.Version {
			served = &crd.Spec.Versions[i]
		}
	}
	if served == nil {
		t.Fatalf("crd serves no version %q; the enroller's REST client speaks only that one", netv1.SchemeGroupVersion.Version)
	}
	if !served.Served || !served.Storage {
		t.Errorf("crd version %s served=%v storage=%v, want both true", served.Name, served.Served, served.Storage)
	}
	if served.Schema == nil || served.Schema.OpenAPIV3Schema == nil {
		t.Fatal("crd version carries no openAPIV3Schema")
	}
	specSchema, ok := served.Schema.OpenAPIV3Schema.Properties["spec"]
	if !ok {
		t.Fatal("crd schema declares no spec property")
	}

	// The exact object the enroller hands the API server for a first join: node
	// index 1's /24 and its derived mesh-egress /32, through the same
	// bootstrap.BuildMeshPeer the enroll path calls.
	peer, err := bootstrap.BuildMeshPeer("worker-a", "100.64.1.0/24", "100.64.1.1", netv1.MeshEnrollRequest{
		NodeName:  "worker-a",
		PublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0=",
		Endpoint:  "192.0.2.10:51820",
	})
	if err != nil {
		t.Fatalf("build the enroller's mesh peer: %v", err)
	}
	raw, err := json.Marshal(peer)
	if err != nil {
		t.Fatalf("marshal the mesh peer: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal the mesh peer wire form: %v", err)
	}
	var wireSpec map[string]json.RawMessage
	if err := json.Unmarshal(wire["spec"], &wireSpec); err != nil {
		t.Fatalf("unmarshal the mesh peer spec: %v", err)
	}

	for key := range wireSpec {
		if _, declared := specSchema.Properties[key]; !declared {
			t.Errorf("the enroller writes spec.%s but the applied CRD declares no such property; the api server would PRUNE it and the write would still succeed", key)
		}
	}
	for _, required := range specSchema.Required {
		if _, present := wireSpec[required]; !present {
			t.Errorf("the applied CRD requires spec.%s but the enroller's write omits it; every enroll would be rejected", required)
		}
	}
}

// TestMeshEnrollerCreatesAndRejoinsUnchanged drives the real meshEnroller against a
// stub API server, pinning the behaviour the CRD adoption must not have moved: a
// first join is assigned index 1's /24 and CREATED, and a rejoin reuses the same
// /24 and UPDATES in place instead of failing on AlreadyExists.
//
// The stub speaks the meshpeers REST surface rather than faking the Enroller
// interface, so the enroller's own client construction, resource path, and
// AlreadyExists handling are all exercised.
func TestMeshEnrollerCreatesAndRejoinsUnchanged(t *testing.T) {
	api := newMeshPeerAPIStub()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	enroller, err := newMeshEnroller(&rest.Config{Host: srv.URL}, quietLogger())
	if err != nil {
		t.Fatalf("newMeshEnroller: %v", err)
	}

	req := netv1.MeshEnrollRequest{
		NodeName:  "worker-a",
		PublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0=",
		Endpoint:  "192.0.2.10:51820",
	}

	got, err := enroller.Enroll(context.Background(), "worker-a", req)
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if got.PodCIDR != "100.64.1.0/24" {
		t.Errorf("first enroll podCIDR = %q, want 100.64.1.0/24 (index 0 is the control-plane node)", got.PodCIDR)
	}
	if got.MeshIP != "100.64.1.1" {
		t.Errorf("first enroll meshIP = %q, want 100.64.1.1", got.MeshIP)
	}
	if len(got.Peers) != 1 || got.Peers[0].NodeName != "worker-a" {
		t.Fatalf("first enroll returned peers %+v, want the one just written", got.Peers)
	}
	if api.creates != 1 || api.updates != 0 {
		t.Errorf("first enroll issued %d creates / %d updates, want 1/0", api.creates, api.updates)
	}
	stored := api.peer("worker-a")
	if stored == nil {
		t.Fatal("the api server holds no MeshPeer named worker-a after the enroll")
	}
	if len(stored.Spec.AllowedIPs) != 1 || stored.Spec.AllowedIPs[0] != "100.64.1.0/24" {
		t.Errorf("written allowedIPs = %v, want the symmetric [100.64.1.0/24]", stored.Spec.AllowedIPs)
	}
	if stored.Spec.PublicKey != req.PublicKey {
		t.Errorf("written publicKey = %q, want the joining node's %q", stored.Spec.PublicKey, req.PublicKey)
	}

	// The rejoin: same node, new endpoint. The CIDR must be REUSED (a second /24
	// would strand every route the peers already programmed) and the write must be
	// an update, not a failed create.
	req.Endpoint = "192.0.2.11:51820"
	again, err := enroller.Enroll(context.Background(), "worker-a", req)
	if err != nil {
		t.Fatalf("rejoin Enroll: %v", err)
	}
	if again.PodCIDR != got.PodCIDR {
		t.Errorf("rejoin podCIDR = %q, want the original %q", again.PodCIDR, got.PodCIDR)
	}
	if api.updates != 1 {
		t.Errorf("rejoin issued %d updates, want 1", api.updates)
	}
	if len(again.Peers) != 1 {
		t.Errorf("rejoin returned %d peers, want 1 (the rejoin must not duplicate the node)", len(again.Peers))
	}
	if stored := api.peer("worker-a"); stored == nil || stored.Spec.Endpoint != "192.0.2.11:51820" {
		t.Errorf("rejoin did not update the stored endpoint: %+v", stored)
	}
}

// meshPeerAPIStub is an in-memory stand-in for the apiserver's meshpeers REST
// surface: list, create (409 on a duplicate), get by name, and update.
type meshPeerAPIStub struct {
	mu               sync.Mutex
	peers            map[string]*netv1.MeshPeer
	creates, updates int
}

func newMeshPeerAPIStub() *meshPeerAPIStub {
	return &meshPeerAPIStub{peers: map[string]*netv1.MeshPeer{}}
}

func (s *meshPeerAPIStub) peer(name string) *netv1.MeshPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peers[name]
}

// meshPeerAPIPath is the collection path the enroller's REST client addresses:
// APIPath /apis + the net.k3sm.io/v1 group-version + the meshpeers resource.
var meshPeerAPIPath = "/apis/" + netv1.SchemeGroupVersion.String() + "/" + meshPeerResource

func (s *meshPeerAPIStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, meshPeerAPIPath), "/")
	switch {
	case r.Method == http.MethodGet && name == "":
		list := netv1.MeshPeerList{TypeMeta: metav1.TypeMeta{APIVersion: netv1.SchemeGroupVersion.String(), Kind: "MeshPeerList"}}
		for _, p := range s.peers {
			list.Items = append(list.Items, *p)
		}
		writeJSON(w, http.StatusOK, list)
	case r.Method == http.MethodGet:
		p, ok := s.peers[name]
		if !ok {
			writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)
	case r.Method == http.MethodPost:
		var in netv1.MeshPeer
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest)
			return
		}
		if _, exists := s.peers[in.Name]; exists {
			writeStatus(w, http.StatusConflict, metav1.StatusReasonAlreadyExists)
			return
		}
		in.ResourceVersion = "1"
		s.peers[in.Name] = &in
		s.creates++
		writeJSON(w, http.StatusCreated, &in)
	case r.Method == http.MethodPut:
		var in netv1.MeshPeer
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest)
			return
		}
		in.ResourceVersion = "2"
		s.peers[name] = &in
		s.updates++
		writeJSON(w, http.StatusOK, &in)
	default:
		writeStatus(w, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func writeStatus(w http.ResponseWriter, code int, reason metav1.StatusReason) {
	writeJSON(w, code, metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Reason:   reason,
		Code:     int32(code),
	})
}
