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

package bootstrap_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// scriptedNodePasswords is a NodePasswordStore that answers every Ensure with
// one fixed error and counts the calls, so a test can tell "the store said no"
// from "the store did not answer" and prove when the store was never asked.
//
// Locking discipline: mu guards calls; httptest serves each request on its own
// goroutine.
type scriptedNodePasswords struct {
	err error

	mu    sync.Mutex
	calls int
}

func (s *scriptedNodePasswords) Ensure(context.Context, string, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.err
}

func (s *scriptedNodePasswords) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// newStoreJoinServerRig is the join server over a caller-supplied node-password
// store. The rig's passwords field is left nil: the store under test is the
// caller's.
func newStoreJoinServerRig(t *testing.T, store bootstrap.NodePasswordStore) *joinServerRig {
	t.Helper()
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signingCA, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	tokens := bootstrap.NewTokenStore(nil)
	user, secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        tokens,
		NodePasswords: store,
		Enroller:      newPeerStoreEnroller("100.64.1.0/24", "100.64.1.1"),
		SelfNodeName:  "k3sm-host",
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &joinServerRig{
		ts:        ts,
		token:     bootstrap.FormatToken(clusterCA.PinHash(), user, secret),
		signingCA: signingCA,
		tokens:    tokens,
		caHash:    clusterCA.PinHash(),
	}
}

// TestJoinNodePasswordVerdictsAndFaults pins how handleJoin answers the
// node-password step now that the store is datastore-backed on every server.
//
// A mismatch is a verdict about the caller (403, nothing to retry). Any other
// store error is the datastore not answering: nothing was decided, so the
// caller is told to come back (503 + Retry-After) instead of being refused, and
// no join proceeds either way. And a name the store could never bind (not a
// DNS-1123 subdomain, or too long once the Secret suffix is appended) is a 400
// that never reaches the store at all.
//
// Fails before the fix: every store error was a 403, and an invalid name was
// handed to the store.
func TestJoinNodePasswordVerdictsAndFaults(t *testing.T) {
	t.Parallel()

	join := func(rig *joinServerRig, name string) bootstrap.JoinRequest {
		return bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      name,
			NodePassword:  "worker-node-password",
			Mesh:          netv1.MeshEnrollRequest{NodeName: name}.WithDefaults(),
		}
	}

	t.Run("a store fault is 503 with Retry-After", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: errors.New("get node-password secret: etcdserver: request timed out")}
		rig := newStoreJoinServerRig(t, store)
		status, body, hdr := rig.postWithHeaders(t, join(rig, "worker-1"))
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d (%s), want 503: a store that did not answer decided nothing", status, body)
		}
		if ra := hdr.Get("Retry-After"); ra == "" || ra == "0" {
			t.Errorf("Retry-After = %q, want a positive number of seconds", ra)
		}
		if strings.Contains(body, "etcdserver") {
			t.Errorf("the 503 body leaks the store's internal error: %q", body)
		}
		if store.count() != 1 {
			t.Errorf("store calls = %d, want 1", store.count())
		}
	})

	t.Run("a mismatch is 403", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: bootstrap.ErrNodePasswordMismatch}
		rig := newStoreJoinServerRig(t, store)
		status, body, hdr := rig.postWithHeaders(t, join(rig, "worker-1"))
		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403", status, body)
		}
		if !strings.Contains(body, "node-password rejected") {
			t.Errorf("body = %q, want the node-password refusal", body)
		}
		if ra := hdr.Get("Retry-After"); ra != "" {
			t.Errorf("a mismatch carries Retry-After %q: waiting changes nothing about it", ra)
		}
	})

	t.Run("a wrapped mismatch is still 403", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: errors.Join(errors.New("verify"), bootstrap.ErrNodePasswordMismatch)}
		rig := newStoreJoinServerRig(t, store)
		if status, body, _ := rig.postWithHeaders(t, join(rig, "worker-1")); status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403", status, body)
		}
	})

	for _, tc := range []struct{ caseName, nodeName string }{
		{"upper case", "Worker-1"},
		{"a slash", "a/b"},
		{"an underscore", "worker_1"},
		{"a trailing dot", "worker-1."},
		{"one past the cap", strings.Repeat("a", bootstrap.MaxNodeNameLength+1)},
		{"far too long", strings.Repeat("a", 300)},
	} {
		t.Run("an invalid name is 400 and never reaches the store: "+tc.caseName, func(t *testing.T) {
			t.Parallel()
			store := &scriptedNodePasswords{}
			rig := newStoreJoinServerRig(t, store)
			status, body, _ := rig.postWithHeaders(t, join(rig, tc.nodeName))
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d (%s), want 400", status, body)
			}
			if store.count() != 0 {
				t.Errorf("store calls = %d, want 0: an unbindable name must not touch the store", store.count())
			}
		})
	}

	t.Run("a name exactly at the cap reaches the store", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: bootstrap.ErrNodePasswordMismatch}
		rig := newStoreJoinServerRig(t, store)
		name := strings.Repeat("a", bootstrap.MaxNodeNameLength)
		if status, body, _ := rig.postWithHeaders(t, join(rig, name)); status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want the store's 403: a name at the cap is bindable", status, body)
		}
		if store.count() != 1 {
			t.Errorf("store calls = %d, want 1", store.count())
		}
		if got := len(name + bootstrap.NodePasswordSecretSuffix); got != 253 {
			t.Errorf("the binding's Secret name is %d characters at the cap, want exactly 253", got)
		}
	})

	t.Run("an empty node-password is 400 and never reaches the store", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{}
		rig := newStoreJoinServerRig(t, store)
		req := join(rig, "worker-1")
		req.NodePassword = ""
		if status, body, _ := rig.postWithHeaders(t, req); status != http.StatusBadRequest {
			t.Fatalf("status = %d (%s), want 400", status, body)
		}
		if store.count() != 0 {
			t.Errorf("store calls = %d, want 0", store.count())
		}
	})

	t.Run("an oversized node-password is 400 and never reaches the store", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: errors.New("bcrypt: password length exceeds 72 bytes")}
		rig := newStoreJoinServerRig(t, store)
		req := join(rig, "worker-1")
		req.NodePassword = strings.Repeat("p", bootstrap.MaxNodePasswordLength+1)
		if status, body, _ := rig.postWithHeaders(t, req); status != http.StatusBadRequest {
			t.Fatalf("status = %d (%s), want 400: a caller-input defect is not a store outage", status, body)
		}
		if store.count() != 0 {
			t.Errorf("store calls = %d, want 0", store.count())
		}
	})

	t.Run("a node-password at the limit reaches the store", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: bootstrap.ErrNodePasswordMismatch}
		rig := newStoreJoinServerRig(t, store)
		req := join(rig, "worker-1")
		req.NodePassword = strings.Repeat("p", bootstrap.MaxNodePasswordLength)
		if status, body, _ := rig.postWithHeaders(t, req); status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want the store's 403", status, body)
		}
		if store.count() != 1 {
			t.Errorf("store calls = %d, want 1", store.count())
		}
	})

	t.Run("the join client reads a 503 as retry-later, not a refusal", func(t *testing.T) {
		t.Parallel()
		store := &scriptedNodePasswords{err: errors.New("datastore busy")}
		rig := newStoreJoinServerRig(t, store)
		_, err := bootstrap.Join(context.Background(), bootstrap.JoinOptions{
			Server:       rig.ts.URL,
			Token:        rig.token,
			NodeName:     "worker-1",
			NodePassword: "worker-node-password",
			MeshEndpoint: "192.0.2.50:51820",
			HTTPClient:   rig.ts.Client(),
		})
		if !errors.Is(err, bootstrap.ErrJoinUnavailable) {
			t.Fatalf("join err = %v, want ErrJoinUnavailable", err)
		}
		var unavailable *bootstrap.JoinUnavailableError
		if !errors.As(err, &unavailable) || unavailable.RetryAfter <= 0 {
			t.Errorf("join err = %#v, want a JoinUnavailableError carrying the server's Retry-After", err)
		}
		if errors.Is(err, bootstrap.ErrJoinRateLimited) {
			t.Error("a 503 must not read as the rate limit: the two are answered differently")
		}
	})
}

// TestValidateNodeNameMatchesTheNodePasswordSecret pins the cap to the Secret
// name it protects: the longest accepted node name plus the suffix is exactly
// the 253 characters a Secret name may have.
func TestValidateNodeNameMatchesTheNodePasswordSecret(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"worker-1", true},
		{"k3sm-studio.local", true},
		{strings.Repeat("a", bootstrap.MaxNodeNameLength), true},
		{strings.Repeat("a", bootstrap.MaxNodeNameLength+1), false},
		{"Worker-1", false},
		{"a/b", false},
		{"", false},
	} {
		if err := bootstrap.ValidateNodeName(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidateNodeName(%.20q...) = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
