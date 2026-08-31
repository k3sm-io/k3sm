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
	"context"
	"sync"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// B226 (lab defect D5) — a projected ServiceAccount token must be BOUND to the
// Pod object it was minted for, exactly as upstream kubelet binds it. Without
// spec.boundObjectRef the token stays valid after the pod is deleted (until
// expiry) and the apiserver emits no authentication.kubernetes.io/pod-name or
// pod-uid TokenReview extras, so every identity consumer that reads them (Istio
// SDS, OPA external data, workload-identity federators) sees a pod-less token.
//
// The binding under test is the EXACT reference — Kind "Pod", APIVersion "v1",
// the creating pod's Name AND its UID. A Kind "ServiceAccount" ref, or one
// missing the UID, is a different and weaker binding: the UID is what the
// apiserver matches to decide the token died with the pod, and what it echoes
// into the extras.

// tokenRecorder captures every TokenRequest that reaches the (fake) apiserver,
// so a test can assert both what was minted and — for the fail-closed case —
// that NOTHING was minted at all.
type tokenRecorder struct {
	mu       sync.Mutex
	saNames  []string
	requests []*authnv1.TokenRequest
}

// record appends one CreateToken call: the ServiceAccount it named and the
// TokenRequest it carried.
func (r *tokenRecorder) record(sa string, tr *authnv1.TokenRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saNames = append(r.saNames, sa)
	r.requests = append(r.requests, tr)
}

// count returns the number of CreateToken calls seen.
func (r *tokenRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// last returns the ServiceAccount name and TokenRequest of the most recent
// CreateToken call, failing the test when there was none.
func (r *tokenRecorder) last(t *testing.T) (string, *authnv1.TokenRequest) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) == 0 {
		t.Fatalf("no TokenRequest reached the apiserver")
	}
	return r.saNames[len(r.saNames)-1], r.requests[len(r.requests)-1]
}

// newTokenClient returns a fake clientset whose TokenRequest subresource records
// into rec and returns an opaque token.
func newTokenClient(rec *tokenRecorder) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		ca, ok := action.(ktesting.CreateActionImpl)
		if !ok || ca.GetSubresource() != "token" {
			return false, nil, nil // not a TokenRequest; fall through
		}
		tr, _ := ca.GetObject().(*authnv1.TokenRequest)
		rec.record(ca.Name, tr)
		return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: "opaque-test-token"}}, nil
	})
	return cs
}

// tokenMintingRuntime mints a projected SA token from INSIDE the runtime's
// CreatePod/UpdatePod, on the request context, which is exactly where runtimed's
// mount.Materialize calls the provider's Resolver back in-process. It is how
// these tests exercise the whole threading path (provider CreatePod → the
// runtime seam → ServiceAccountToken) without a real runtime.
type tokenMintingRuntime struct {
	*fakeRuntimeServer

	resolver *kubeResolver

	mu      sync.Mutex
	mintErr error
}

// CreatePod mints the pod's token on ctx, then delegates to the recording fake.
func (f *tokenMintingRuntime) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	f.mint(ctx, req.GetPod().GetNamespace())
	return f.fakeRuntimeServer.CreatePod(ctx, req)
}

// UpdatePod mints the pod's token on ctx (the in-place re-materialize case),
// then delegates to the recording fake.
func (f *tokenMintingRuntime) UpdatePod(ctx context.Context, req *runtimev1.UpdatePodRequest) (*runtimev1.UpdatePodResponse, error) {
	f.mint(ctx, req.GetPod().GetNamespace())
	return &runtimev1.UpdatePodResponse{}, nil
}

// mint calls the resolver seam and records any failure for the test to assert.
func (f *tokenMintingRuntime) mint(ctx context.Context, namespace string) {
	_, err := f.resolver.ServiceAccountToken(ctx, namespace, "", 3607)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mintErr = err
}

// err returns the last mint error seen at the runtime seam.
func (f *tokenMintingRuntime) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mintErr
}

// newTokenBindingFake wires a provider whose runtime mints a token on the
// request context, over a fake apiserver recording into rec.
func newTokenBindingFake(t *testing.T, rec *tokenRecorder) (*runtimedRuntime, *tokenMintingRuntime) {
	t.Helper()
	res := newKubeResolver(newTokenClient(rec))
	f := &tokenMintingRuntime{fakeRuntimeServer: newFakeRuntimeServer(), resolver: res}
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir()}, res, nil)
	return r, f
}

// assertBoundToPod asserts the TokenRequest carries the EXACT pod-object
// reference upstream kubelet sets: Kind "Pod", APIVersion "v1", the pod's Name,
// and the pod's UID. Each field is checked separately — a partially-correct ref
// (right kind, absent UID) is the failure mode this test exists to catch.
func assertBoundToPod(t *testing.T, tr *authnv1.TokenRequest, name, uid string) {
	t.Helper()
	ref := tr.Spec.BoundObjectRef
	if ref == nil {
		t.Fatalf("TokenRequest.Spec.BoundObjectRef is nil — the projected token is UNBOUND and outlives pod %s", name)
	}
	if ref.Kind != "Pod" {
		t.Errorf("BoundObjectRef.Kind = %q, want %q", ref.Kind, "Pod")
	}
	if ref.APIVersion != "v1" {
		t.Errorf("BoundObjectRef.APIVersion = %q, want %q", ref.APIVersion, "v1")
	}
	if ref.Name != name {
		t.Errorf("BoundObjectRef.Name = %q, want %q", ref.Name, name)
	}
	if string(ref.UID) != uid {
		t.Errorf("BoundObjectRef.UID = %q, want %q (without it the apiserver cannot invalidate the token with the pod, and emits no pod-uid extra)", ref.UID, uid)
	}
}

// TestB226_ProjectedTokenBoundToPod proves the provider binds every projected
// ServiceAccount token to the Pod object that caused it to be minted, and fails
// closed rather than minting an unbound token.
func TestB226_ProjectedTokenBoundToPod(t *testing.T) {
	const ns = "team"

	t.Run("CreatePod binds the token to the creating pod", func(t *testing.T) {
		rec := &tokenRecorder{}
		r, f := newTokenBindingFake(t, rec)
		pod := saAccessPod(ns, "snap", "snapshot-manager")

		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := f.err(); err != nil {
			t.Fatalf("mint at the runtime seam: %v", err)
		}
		sa, tr := rec.last(t)
		if sa != "snapshot-manager" {
			t.Errorf("token minted for ServiceAccount %q, want snapshot-manager", sa)
		}
		assertBoundToPod(t, tr, "snap", "uid-snap")
	})

	t.Run("UpdatePod binds the token to the same pod", func(t *testing.T) {
		rec := &tokenRecorder{}
		r, f := newTokenBindingFake(t, rec)
		pod := saAccessPod(ns, "snap", "snapshot-manager")

		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := r.UpdatePod(context.Background(), pod); err != nil {
			t.Fatalf("UpdatePod: %v", err)
		}
		if err := f.err(); err != nil {
			t.Fatalf("mint at the runtime seam: %v", err)
		}
		_, tr := rec.last(t)
		assertBoundToPod(t, tr, "snap", "uid-snap")
	})

	t.Run("a pod with no ServiceAccount still binds to the pod object", func(t *testing.T) {
		rec := &tokenRecorder{}
		r, f := newTokenBindingFake(t, rec)
		pod := saAccessPod(ns, "snap2", "")

		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := f.err(); err != nil {
			t.Fatalf("mint at the runtime seam: %v", err)
		}
		sa, tr := rec.last(t)
		if sa != defaultServiceAccount {
			t.Errorf("token minted for ServiceAccount %q, want %q", sa, defaultServiceAccount)
		}
		assertBoundToPod(t, tr, "snap2", "uid-snap2")
	})

	t.Run("no pod identity in context fails closed and mints nothing", func(t *testing.T) {
		rec := &tokenRecorder{}
		res := newKubeResolver(newTokenClient(rec))

		tok, err := res.ServiceAccountToken(context.Background(), ns, "", 3607)
		if err == nil {
			t.Fatalf("ServiceAccountToken minted %q with no pod identity bound — an UNBOUND token", tok)
		}
		if tok != "" {
			t.Errorf("ServiceAccountToken returned token %q alongside its error", tok)
		}
		if n := rec.count(); n != 0 {
			t.Errorf("%d TokenRequest(s) reached the apiserver; a call with no pod identity must never mint", n)
		}
	})
}
