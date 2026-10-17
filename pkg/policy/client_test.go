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
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// staleAPIServer is a fake apiserver, served in-process through the client's
// transport (no socket; see handlerTransport), on which every object this
// package provisions already exists with a drifted spec: a create answers 409
// AlreadyExists, a get answers the object with an empty spec, and an update is
// echoed back in the encoding it arrived in. It records every request's arrival time, and the update count per
// object, so a test sees both the client's pacing and that every object converged.
// failUpdates turns every update into a 500.
type staleAPIServer struct {
	failUpdates bool

	mu       sync.Mutex // guards the fields below
	arrivals []time.Time
	updates  map[string]int
}

// handlerTransport is the seam: an http.RoundTripper that hands each request to
// an http.Handler in-process, so the real client-go REST stack (and its rate
// limiter, which sits above the transport) runs end to end without a listener.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// fakeConfig is a client config whose every request reaches h.
func fakeConfig(h http.Handler) *rest.Config {
	return &rest.Config{Host: "http://apiserver.invalid", Transport: handlerTransport{h}}
}

// kindOf maps a resource path segment to the kind and apiVersion the fake answers with.
var kindOf = map[string][2]string{
	"validatingadmissionpolicies":       {"ValidatingAdmissionPolicy", "admissionregistration.k8s.io/v1"},
	"validatingadmissionpolicybindings": {"ValidatingAdmissionPolicyBinding", "admissionregistration.k8s.io/v1"},
	"mutatingadmissionpolicies":         {"MutatingAdmissionPolicy", "admissionregistration.k8s.io/v1"},
	"mutatingadmissionpolicybindings":   {"MutatingAdmissionPolicyBinding", "admissionregistration.k8s.io/v1"},
	"limitranges":                       {"LimitRange", "v1"},
}

func (s *staleAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.arrivals = append(s.arrivals, time.Now())
	s.mu.Unlock()

	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPost:
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"AlreadyExists","code":409,"message":"already exists"}`)
	case http.MethodGet:
		if len(segs) < 2 {
			http.NotFound(w, r)
			return
		}
		name, resource := segs[len(segs)-1], segs[len(segs)-2]
		kv, ok := kindOf[resource]
		if !ok {
			http.NotFound(w, r)
			return
		}
		meta := map[string]any{"name": name, "resourceVersion": "1", "uid": "uid-" + name}
		if len(segs) >= 4 && segs[len(segs)-4] == "namespaces" {
			meta["namespace"] = segs[len(segs)-3]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": kv[0], "apiVersion": kv[1], "metadata": meta, "spec": map[string]any{}})
	case http.MethodPut:
		if s.failUpdates {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","code":500,"message":"injected update failure"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.updates[segs[len(segs)-2]+"/"+segs[len(segs)-1]]++
		s.mu.Unlock()
		// Echoed in the encoding it arrived in (client-go may send protobuf).
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		_, _ = w.Write(body)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

// reconcileEverySet runs every Ensure* the server runs at start, in its order,
// returning the first error.
func reconcileEverySet(ctx context.Context, cs kubernetes.Interface) error {
	steps := []func() error{
		func() error { return EnsureDarwinAdmission(ctx, cs) },
		func() error { return EnsureExternalTrafficPolicyLocalWarn(ctx, cs) },
		func() error { return EnsureUDPServiceWarn(ctx, cs) },
		func() error { return EnsureRejectReservedLoadBalancerPort(ctx, cs) },
		func() error { return EnsureRejectServiceDeniedLocalPort(ctx, cs, []int{6443}) },
		func() error { return EnsureProviderTolerationWarn(ctx, cs) },
		func() error { return EnsureEgressAnnotationWarn(ctx, cs) },
		func() error { return EnsureXcodeToolchainAnnotationWarn(ctx, cs) },
		func() error { return EnsureDaemonSetTolerationMutation(ctx, cs) },
		func() error { return EnsureNoForeignUserAdmission(ctx, cs, 250) },
		func() error { return EnsureDefaultLimitRange(ctx, cs) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// TestReconcileIsNotRateLimitedPerObject is the B699 gate. On a populated
// datastore whose every k3sm-managed object has drifted, the server's start-up
// reconcile used to pay about a second per object: the admin clientset it ran on
// kept client-go's default 5 QPS / 10 burst limiter, and each drifted object costs
// up to six requests. The provisioning client NewClient builds must carry no
// limiter, so the whole set (some 70 requests here, which the default limiter
// would spread over more than 10 s) reconciles in well under a second, and every
// object still converges.
func TestReconcileIsNotRateLimitedPerObject(t *testing.T) {
	ctx := context.Background()

	t.Run("every stale object converges without a per-object wait", func(t *testing.T) {
		fakeAPI := &staleAPIServer{updates: map[string]int{}}
		cs, err := NewClient(fakeConfig(fakeAPI))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		start := time.Now()
		if err := reconcileEverySet(ctx, cs); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		elapsed := time.Since(start)

		fakeAPI.mu.Lock()
		defer fakeAPI.mu.Unlock()
		t.Logf("reconciled %d objects in %d requests in %v", len(fakeAPI.updates), len(fakeAPI.arrivals), elapsed)
		const bound = time.Second
		if elapsed >= bound {
			t.Errorf("reconciling %d objects in %d requests took %v, want under %v: the provisioning client is still rate limited", len(fakeAPI.updates), len(fakeAPI.arrivals), elapsed, bound)
		}
		// The set: the eleven server-start policies, their eleven bindings, the
		// LimitRange. Every one was stale, so every one must be written exactly once.
		if len(fakeAPI.updates) < 23 {
			t.Errorf("only %d objects were updated, want every stale object (at least 23): %v", len(fakeAPI.updates), fakeAPI.updates)
		}
		for obj, n := range fakeAPI.updates {
			if n != 1 {
				t.Errorf("%s updated %d times, want exactly once", obj, n)
			}
		}
		if len(fakeAPI.arrivals) <= 10 {
			t.Fatalf("only %d requests reached the server: the set no longer exceeds the default limiter's burst of 10, so this gate would pass vacuously", len(fakeAPI.arrivals))
		}
	})

	t.Run("an update failure still surfaces", func(t *testing.T) {
		cs, err := NewClient(fakeConfig(&staleAPIServer{failUpdates: true, updates: map[string]int{}}))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		err = EnsureDarwinAdmission(ctx, cs)
		if err == nil || !strings.Contains(err.Error(), "injected update failure") {
			t.Fatalf("EnsureDarwinAdmission = %v, want the injected update failure", err)
		}
	})

	t.Run("the caller's config keeps its own limiter settings", func(t *testing.T) {
		cfg := &rest.Config{Host: "http://127.0.0.1:1", QPS: 7, Burst: 9}
		cs, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if cfg.QPS != 7 || cfg.Burst != 9 || cfg.RateLimiter != nil {
			t.Errorf("NewClient modified the caller's config: QPS %v, Burst %v, RateLimiter %v", cfg.QPS, cfg.Burst, cfg.RateLimiter)
		}
		for name, rc := range map[string]rest.Interface{
			"admissionregistration/v1": cs.AdmissionregistrationV1().RESTClient(),
			"core/v1":                  cs.CoreV1().RESTClient(),
			"node/v1":                  cs.NodeV1().RESTClient(),
		} {
			if l := rc.GetRateLimiter(); l != nil {
				t.Errorf("%s client carries a rate limiter (%T), want none", name, l)
			}
		}
	})

	t.Run("a nil config is an error", func(t *testing.T) {
		if _, err := NewClient(nil); err == nil {
			t.Fatal("NewClient(nil) succeeded, want an error")
		}
	})
}
