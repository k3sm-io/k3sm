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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// deregisterAPIStub is an in-memory apiserver that serves the two DELETEs a
// deregistration performs and records the ORDER they arrived in.
type deregisterAPIStub struct {
	mu sync.Mutex
	// deletes is the resource of every DELETE, in arrival order.
	deletes []string
	// missing are the resources that answer 404, so the idempotent arm can be
	// driven.
	missing map[string]bool
}

// nodeAPIPath is the collection path the core client addresses for Nodes.
const nodeAPIPath = "/api/v1/nodes"

func (s *deregisterAPIStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var resource string
	switch {
	case strings.HasPrefix(r.URL.Path, meshPeerAPIPath):
		resource = "meshpeer"
	case strings.HasPrefix(r.URL.Path, nodeAPIPath):
		resource = "node"
	default:
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound)
		return
	}
	if r.Method != http.MethodDelete {
		writeStatus(w, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed)
		return
	}
	s.deletes = append(s.deletes, resource)
	if s.missing[resource] {
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound)
		return
	}
	writeJSON(w, http.StatusOK, metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusSuccess,
	})
}

func (s *deregisterAPIStub) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deletes...)
}

// enrollerOverDeregisterStub wires a real meshEnroller to the stub above.
func enrollerOverDeregisterStub(t *testing.T, missing ...string) (*meshEnroller, *deregisterAPIStub) {
	t.Helper()
	api := &deregisterAPIStub{missing: map[string]bool{}}
	for _, m := range missing {
		api.missing[m] = true
	}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	e, err := newMeshEnroller(&rest.Config{Host: srv.URL}, quietLogger())
	if err != nil {
		t.Fatalf("newMeshEnroller: %v", err)
	}
	return e, api
}

// TestDeregisterDeletesTheMeshPeerBeforeTheNode pins the supervisor half of the
// deregistration: which objects go, in which order, and what an already-absent
// object means.
//
// The order is the property. The MeshPeer is what every remaining node's
// wireguard device is programmed from, so removing it first is what makes the
// peers drop their tunnel entry for the departing Mac; removing the Node first
// would leave that entry live for a node the cluster no longer has. And both
// deletes must tolerate NotFound, because an uninstall can be re-run and an
// operator may have deleted one half by hand.
func TestDeregisterDeletesTheMeshPeerBeforeTheNode(t *testing.T) {
	t.Run("the MeshPeer goes first, then the Node", func(t *testing.T) {
		e, api := enrollerOverDeregisterStub(t)
		if err := e.Deregister(context.Background(), "worker-1"); err != nil {
			t.Fatalf("Deregister: %v", err)
		}
		got := api.recorded()
		want := []string{"meshpeer", "node"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("deletes = %v, want %v — the peer entry must go before the node it belongs to", got, want)
		}
	})

	t.Run("an already-absent object is not an error", func(t *testing.T) {
		e, api := enrollerOverDeregisterStub(t, "meshpeer", "node")
		if err := e.Deregister(context.Background(), "worker-1"); err != nil {
			t.Fatalf("a node the cluster has already forgotten is the state we asked for, not an error: %v", err)
		}
		if got := api.recorded(); len(got) != 2 {
			t.Errorf("deletes = %v, want both to be attempted", got)
		}
	})

	t.Run("an empty node name is refused before any delete", func(t *testing.T) {
		e, api := enrollerOverDeregisterStub(t)
		if err := e.Deregister(context.Background(), ""); err == nil {
			t.Error("Deregister accepted an empty node name")
		}
		if got := api.recorded(); len(got) != 0 {
			t.Errorf("deletes = %v for an empty node name, want none", got)
		}
	})
}
