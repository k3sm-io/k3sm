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
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// capturingEnroller records every MeshEnrollRequest the supervisor hands it, so a
// test can assert what the JOINING node advertised rather than what it kept.
//
// Locking discipline: mu guards reqs; httptest serves each join on its own
// goroutine.
type capturingEnroller struct {
	mu   sync.Mutex
	reqs []netv1.MeshEnrollRequest
}

func (c *capturingEnroller) Enroll(_ context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	c.mu.Lock()
	c.reqs = append(c.reqs, req)
	c.mu.Unlock()
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  "100.64.1.0/24",
		MeshIP:   "100.64.1.1",
	}.WithDefaults(), nil
}

func (c *capturingEnroller) captured() []netv1.MeshEnrollRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]netv1.MeshEnrollRequest(nil), c.reqs...)
}

// TestJoinAdvertisesTheSuppliedWireguardKey is the wire half of M14.2 defect B.
//
// Persisting the key on the node is worth nothing unless the join USES it: Join
// minted a keypair unconditionally, so every restart enrolled a new public key and
// every peer's programmed key went stale. Two joins off one persisted private key
// must advertise one public key, and that key must be the derivation of the
// supplied private key rather than anything the server chose.
func TestJoinAdvertisesTheSuppliedWireguardKey(t *testing.T) {
	priv, pub, err := bootstrap.GenerateWireguardKey()
	if err != nil {
		t.Fatalf("mint the node's persisted key: %v", err)
	}

	enroller := &capturingEnroller{}
	ts, opts := newJoinFixture(t, enroller)
	defer ts.Close()
	opts.WGPrivateKeyB64 = priv

	for i := range 2 {
		res, err := bootstrap.Join(context.Background(), opts)
		if err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
		if res.WGPrivateKeyB64 != priv {
			t.Errorf("join %d returned private key %q, want the supplied %q", i, res.WGPrivateKeyB64, priv)
		}
		if res.WGPublicKeyB64 != pub {
			t.Errorf("join %d returned public key %q, want %q", i, res.WGPublicKeyB64, pub)
		}
	}

	got := enroller.captured()
	if len(got) != 2 {
		t.Fatalf("supervisor saw %d enroll requests, want 2", len(got))
	}
	if got[0].PublicKey != pub || got[1].PublicKey != pub {
		t.Fatalf("the two joins advertised %q then %q, want the persisted %q both times — "+
			"a restart would rotate this node's MeshPeer key and strand every peer",
			got[0].PublicKey, got[1].PublicKey, pub)
	}
}

// TestJoinMintsAKeyWhenNoneIsSupplied keeps JoinOptions' zero value usable: a
// caller that persists nothing still gets a valid keypair, and the two joins then
// legitimately differ — which is precisely the behaviour the agent must not have.
func TestJoinMintsAKeyWhenNoneIsSupplied(t *testing.T) {
	enroller := &capturingEnroller{}
	ts, opts := newJoinFixture(t, enroller)
	defer ts.Close()

	res, err := bootstrap.Join(context.Background(), opts)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if res.WGPrivateKeyB64 == "" || res.WGPublicKeyB64 == "" || res.WGPrivateKeyB64 == res.WGPublicKeyB64 {
		t.Fatal("join with no supplied key must mint a distinct private/public pair")
	}
	derived, err := bootstrap.WireguardPublicKey(res.WGPrivateKeyB64)
	if err != nil {
		t.Fatalf("WireguardPublicKey: %v", err)
	}
	if derived != res.WGPublicKeyB64 {
		t.Errorf("minted public key %q is not the derivation of the minted private key (%q)", res.WGPublicKeyB64, derived)
	}
}

// TestJoinRejectsAnUnusableSuppliedKey: a corrupt persisted key must fail the join
// rather than fall through to a fresh mint, which would rotate the identity the
// persistence exists to hold stable.
func TestJoinRejectsAnUnusableSuppliedKey(t *testing.T) {
	enroller := &capturingEnroller{}
	ts, opts := newJoinFixture(t, enroller)
	defer ts.Close()
	opts.WGPrivateKeyB64 = "!!!not-a-key!!!"

	if _, err := bootstrap.Join(context.Background(), opts); err == nil {
		t.Fatal("join accepted an unusable wireguard private key")
	}
	if n := len(enroller.captured()); n != 0 {
		t.Errorf("the supervisor saw %d enroll requests; a bad key must fail before the node enrolls", n)
	}
}

// newJoinFixture stands up an in-process supervisor over httptest and returns it
// with a JoinOptions that succeeds against it (the live CA pin is exercised by
// TestCAHierarchyAndPinnedJoin; here the httptest client's own trust is used so the
// tests isolate the key contract).
func newJoinFixture(t *testing.T, enroller bootstrap.Enroller) (*httptest.Server, bootstrap.JoinOptions) {
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
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      enroller,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	return ts, bootstrap.JoinOptions{
		Server:       ts.URL,
		Token:        bootstrap.FormatToken(clusterCA.PinHash(), user, secret),
		NodeName:     "worker-1",
		NodeIP:       "100.64.1.1",
		NodePassword: "node-secret-1",
		MeshEndpoint: "192.168.1.50:51820",
		HTTPClient:   ts.Client(),
	}
}
