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

package policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// populatedAPIServer is a fake apiserver that behaves like a live datastore: a
// create stores the object, but with the apiserver's defaults filled in
// (failurePolicy, matchPolicy, namespaceSelector, objectSelector, rule scope,
// reinvocationPolicy, and an empty matchResources on a binding); a create of an
// existing name answers 409; a get answers the stored, defaulted form; a put
// replaces it and is counted. The defaulting here is written out independently
// of the package under test.
type populatedAPIServer struct {
	mu      sync.Mutex // guards the fields below
	objects map[string]map[string]any
	updates map[string]int
}

func newPopulatedAPIServer() *populatedAPIServer {
	return &populatedAPIServer{objects: map[string]map[string]any{}, updates: map[string]int{}}
}

func setDefault(m map[string]any, key string, v any) {
	if _, ok := m[key]; !ok {
		m[key] = v
	}
}

func defaultMatch(m map[string]any) {
	setDefault(m, "matchPolicy", "Equivalent")
	setDefault(m, "namespaceSelector", map[string]any{})
	setDefault(m, "objectSelector", map[string]any{})
	for _, key := range []string{"resourceRules", "excludeResourceRules"} {
		rules, _ := m[key].([]any)
		for _, r := range rules {
			if rm, ok := r.(map[string]any); ok {
				setDefault(rm, "scope", "*")
			}
		}
	}
}

// applyAPIServerDefaults fills in the defaults the apiserver stores for resource.
func applyAPIServerDefaults(resource string, obj map[string]any) {
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return
	}
	switch resource {
	case "validatingadmissionpolicies", "mutatingadmissionpolicies":
		setDefault(spec, "failurePolicy", "Fail")
		if resource == "mutatingadmissionpolicies" {
			setDefault(spec, "reinvocationPolicy", "Never")
		}
		mc, ok := spec["matchConstraints"].(map[string]any)
		if !ok {
			mc = map[string]any{}
			spec["matchConstraints"] = mc
		}
		defaultMatch(mc)
	case "validatingadmissionpolicybindings", "mutatingadmissionpolicybindings":
		mr, ok := spec["matchResources"].(map[string]any)
		if !ok {
			mr = map[string]any{}
			spec["matchResources"] = mr
		}
		defaultMatch(mr)
	}
}

func (s *populatedAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	name, resource := segs[len(segs)-1], segs[len(segs)-2]
	if r.Method == http.MethodPost {
		// A create's path ends at the collection.
		name, resource = "", segs[len(segs)-1]
	}
	w.Header().Set("Content-Type", "application/json")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var obj map[string]any
		if err := json.Unmarshal(body, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		meta, _ := obj["metadata"].(map[string]any)
		key := resource + "/"
		if r.Method == http.MethodPut {
			key += name
			s.updates[key]++
		} else {
			key += meta["name"].(string)
			if _, exists := s.objects[key]; exists {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"AlreadyExists","code":409,"message":"already exists"}`)
				return
			}
		}
		meta["resourceVersion"] = "1"
		applyAPIServerDefaults(resource, obj)
		s.objects[key] = obj
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodGet:
		obj, ok := s.objects[resource+"/"+name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404,"message":"not found"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(obj)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

// TestUnchangedPolicyIsNotRewritten is the B702 gate. The apiserver stores every
// policy and binding with its defaults filled in, so the sparse object this
// package builds never DeepEquals the stored one; the comparison used to call
// every unchanged object stale, and every server start rewrote all of them. On a
// datastore already holding the whole set in its defaulted form, a start must
// make zero update calls, and one drifted field must make exactly one.
func TestUnchangedPolicyIsNotRewritten(t *testing.T) {
	ctx := context.Background()
	fakeAPI := newPopulatedAPIServer()
	cfg := fakeConfig(fakeAPI)
	cfg.ContentType = "application/json"
	cs, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// First start: everything is created (and stored defaulted).
	if err := reconcileEverySet(ctx, cs); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if n := len(fakeAPI.objects); n < 23 {
		t.Fatalf("only %d objects stored, want the whole set (at least 23): the gate would pass vacuously", n)
	}
	// The fake really did default: a policy carries failurePolicy it was never sent.
	spec := fakeAPI.objects["validatingadmissionpolicies/"+foreignUserPolicyName]["spec"].(map[string]any)
	if spec["matchConstraints"].(map[string]any)["matchPolicy"] != "Equivalent" {
		t.Fatalf("the fake did not default matchPolicy: %v", spec["matchConstraints"])
	}

	t.Run("a restart on a populated datastore writes nothing", func(t *testing.T) {
		if err := reconcileEverySet(ctx, cs); err != nil {
			t.Fatalf("restart reconcile: %v", err)
		}
		if len(fakeAPI.updates) != 0 {
			t.Errorf("an unchanged set was rewritten: %v", fakeAPI.updates)
		}
	})

	t.Run("one drifted field is rewritten exactly once", func(t *testing.T) {
		key := "validatingadmissionpolicies/" + foreignUserPolicyName
		vals := fakeAPI.objects[key]["spec"].(map[string]any)["validations"].([]any)
		vals[0].(map[string]any)["message"] = "drifted"
		if err := reconcileEverySet(ctx, cs); err != nil {
			t.Fatalf("drift reconcile: %v", err)
		}
		if len(fakeAPI.updates) != 1 || fakeAPI.updates[key] != 1 {
			t.Errorf("updates = %v, want exactly one, on %s", fakeAPI.updates, key)
		}
	})

	t.Run("a drifted binding is rewritten exactly once", func(t *testing.T) {
		clear(fakeAPI.updates)
		key := "validatingadmissionpolicybindings/" + foreignUserBindingName
		fakeAPI.objects[key]["spec"].(map[string]any)["validationActions"] = []any{"Warn"}
		if err := reconcileEverySet(ctx, cs); err != nil {
			t.Fatalf("binding drift reconcile: %v", err)
		}
		if len(fakeAPI.updates) != 1 || fakeAPI.updates[key] != 1 {
			t.Errorf("updates = %v, want exactly one, on %s", fakeAPI.updates, key)
		}
	})
}
