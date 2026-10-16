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
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/nodecred"
)

// TestEnsureNetserveCredential pins where the worker datapath's identity comes
// from on each start: the join's pair when the join issued one; the stored pair
// when it is this node's, in date and from this cluster's client CA; otherwise a
// fetch with the node credential, which is how a node joined before the identity
// existed obtains it without a rejoin. Whatever the source, the result is a
// 0600 kubeconfig the reader reports Valid for this node.
func TestEnsureNetserveCredential(t *testing.T) {
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signing, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	const node = "worker-a"
	const url = "https://100.64.0.1:6444"
	issue := func(t *testing.T, name string, validFor time.Duration) ([]byte, []byte) {
		t.Helper()
		c, k, err := signing.IssueNetserveClient(name, validFor)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return c, k
	}
	baseRes := func() *bootstrap.JoinResult {
		return &bootstrap.JoinResult{NodeName: node, ClusterCAPEM: clusterCA.CertPEM, ClientCAPEM: signing.CertPEM}
	}
	logger := slog.New(slog.DiscardHandler)

	type fetchCount struct{ n int }
	fetcher := func(fc *fetchCount, certPEM, keyPEM []byte, ferr error) netserveFetcher {
		return func(_ context.Context, _ *bootstrap.JoinResult, name string) ([]byte, []byte, error) {
			fc.n++
			if name != node {
				t.Errorf("fetch asked for %q, want %q", name, node)
			}
			return certPEM, keyPEM, ferr
		}
	}
	assertValid := func(t *testing.T, store nodeCredentialStore, path string) {
		t.Helper()
		if path != store.netserveKubeconfigPath() {
			t.Errorf("path = %q, want %q", path, store.netserveKubeconfigPath())
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600 (the node kubeconfig's mode)", fi.Mode().Perm())
		}
		state, cred, err := store.reader().NetserveStatus(time.Now(), node, signing.CertPEM)
		if state != nodecred.Valid || err != nil {
			t.Fatalf("stored netserve credential = %v (%v), want valid", state, err)
		}
		if cred.APIServerURL != url {
			t.Errorf("apiserver = %q, want %q", cred.APIServerURL, url)
		}
	}

	t.Run("the join's pair is stored and nothing is fetched", func(t *testing.T) {
		store := nodeCredentialStore{dir: t.TempDir()}
		res := baseRes()
		res.NetserveClientCertPEM, res.NetserveClientKeyPEM = issue(t, node, 48*time.Hour)
		var fc fetchCount
		path, err := ensureNetserveCredential(context.Background(), store, node, url, res, fetcher(&fc, nil, nil, errors.New("must not fetch")), time.Now(), logger)
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if fc.n != 0 {
			t.Errorf("fetched %d times after a join that issued a pair", fc.n)
		}
		assertValid(t, store, path)
	})

	t.Run("a join pair for another node is refused", func(t *testing.T) {
		store := nodeCredentialStore{dir: t.TempDir()}
		res := baseRes()
		res.NetserveClientCertPEM, res.NetserveClientKeyPEM = issue(t, "worker-b", 48*time.Hour)
		var fc fetchCount
		if _, err := ensureNetserveCredential(context.Background(), store, node, url, res, fetcher(&fc, nil, nil, nil), time.Now(), logger); err == nil {
			t.Fatal("a join that issued worker-b's identity to worker-a was accepted")
		}
	})

	t.Run("an already-joined node with no netserve identity fetches one", func(t *testing.T) {
		store := nodeCredentialStore{dir: t.TempDir()}
		c, k := issue(t, node, 48*time.Hour)
		var fc fetchCount
		path, err := ensureNetserveCredential(context.Background(), store, node, url, baseRes(), fetcher(&fc, c, k, nil), time.Now(), logger)
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if fc.n != 1 {
			t.Errorf("fetched %d times, want 1", fc.n)
		}
		assertValid(t, store, path)
	})

	t.Run("a valid stored identity is reused without a fetch", func(t *testing.T) {
		store := nodeCredentialStore{dir: t.TempDir()}
		c, k := issue(t, node, 48*time.Hour)
		if err := store.saveNetserve(url, node, clusterCA.CertPEM, c, k); err != nil {
			t.Fatalf("seed: %v", err)
		}
		var fc fetchCount
		path, err := ensureNetserveCredential(context.Background(), store, node, url, baseRes(), fetcher(&fc, nil, nil, errors.New("must not fetch")), time.Now(), logger)
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		if fc.n != 0 {
			t.Errorf("fetched %d times over a valid stored identity", fc.n)
		}
		assertValid(t, store, path)
	})

	for name, seed := range map[string]func(t *testing.T) ([]byte, []byte){
		"an expiring stored identity is rotated":     func(t *testing.T) ([]byte, []byte) { return issue(t, node, time.Hour) },
		"another node's stored identity is replaced": func(t *testing.T) ([]byte, []byte) { return issue(t, "worker-b", 48*time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			store := nodeCredentialStore{dir: t.TempDir()}
			oc, ok := seed(t)
			if err := store.saveNetserve(url, node, clusterCA.CertPEM, oc, ok); err != nil {
				t.Fatalf("seed: %v", err)
			}
			c, k := issue(t, node, 48*time.Hour)
			var fc fetchCount
			path, err := ensureNetserveCredential(context.Background(), store, node, url, baseRes(), fetcher(&fc, c, k, nil), time.Now(), logger)
			if err != nil {
				t.Fatalf("ensure: %v", err)
			}
			if fc.n != 1 {
				t.Errorf("fetched %d times, want 1", fc.n)
			}
			assertValid(t, store, path)
		})
	}

	t.Run("a failed fetch fails the start", func(t *testing.T) {
		store := nodeCredentialStore{dir: t.TempDir()}
		var fc fetchCount
		_, err := ensureNetserveCredential(context.Background(), store, node, url, baseRes(), fetcher(&fc, nil, nil, bootstrap.ErrNetserveCertUnsupported), time.Now(), logger)
		if !errors.Is(err, bootstrap.ErrNetserveCertUnsupported) {
			t.Fatalf("err = %v, want the fetch error wrapped", err)
		}
		if _, err := os.Stat(store.netserveKubeconfigPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a failed fetch left a netserve kubeconfig behind (%v)", err)
		}
	})
}

// TestWorkerNetserveRotation pins the worker's in-process rotation: the
// re-check is NetserveStatus, so a stored pair outside the margin is left alone
// and one inside it is renewed with the node credential, persisted, and swapped
// into the running client, at a fake "now" a day before its expiry.
func TestWorkerNetserveRotation(t *testing.T) {
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signing, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	const node = "worker-a"
	const url = "https://100.64.0.1:6444"
	store := nodeCredentialStore{dir: t.TempDir()}
	oldCert, oldKey, err := signing.IssueNetserveClient(node, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.saveNetserve(url, node, clusterCA.CertPEM, oldCert, oldKey); err != nil {
		t.Fatalf("seed: %v", err)
	}
	newCert, newKey, err := signing.IssueNetserveClient(node, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	fetches := 0
	rot := workerNetserveRotation{
		store: store, nodeName: node, apiserverURL: url,
		res: &bootstrap.JoinResult{NodeName: node, ClusterCAPEM: clusterCA.CertPEM, ClientCAPEM: signing.CertPEM},
		fetch: func(context.Context, *bootstrap.JoinResult, string) ([]byte, []byte, error) {
			fetches++
			return newCert, newKey, nil
		},
	}
	cred, err := netserve.NewRotatingCredential(oldCert, oldKey, nil)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	r := &netserve.Rotator{Credential: cred, Due: rot.due, Renew: rot.renew}

	now := time.Now()
	if r.Tick(context.Background(), now) || fetches != 0 {
		t.Fatalf("renewed a pair 30 days from expiry (fetches %d)", fetches)
	}
	dayBefore := cred.NotAfter().Add(-nodecred.ExpiryMargin + time.Hour)
	if !r.Tick(context.Background(), dayBefore) || fetches != 1 {
		t.Fatalf("did not renew inside the margin (fetches %d)", fetches)
	}
	if got, _, err := store.reader().NetserveStatus(now, node, signing.CertPEM); got != nodecred.Valid || err != nil {
		t.Fatalf("the renewed pair was not persisted: %v %v", got, err)
	}
	_, stored, _ := store.reader().NetserveStatus(now, node, signing.CertPEM)
	if string(stored.CertPEM) != string(newCert) {
		t.Error("the store still holds the old certificate after a renewal")
	}
	if !cred.NotAfter().After(dayBefore.Add(300 * 24 * time.Hour)) {
		t.Error("the running client was not swapped to the renewed pair")
	}
}
