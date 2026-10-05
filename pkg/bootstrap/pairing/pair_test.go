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

package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// testPin is a cluster pin shaped like a real one (64 hex characters).
const testPin = "3b5e1f0c9a7d2e4b6c8a0f1e3d5c7b9a1f2e3d4c5b6a7980f1e2d3c4b5a69788"

// tbPorts is the hardware-port mapping the table injects: two Thunderbolt
// receptacles. bridge0 ("Thunderbolt Bridge"), Wi-Fi, Ethernet, a dock's
// "Ethernet Adapter" and every utun are absent, exactly as linkenum reports them.
var tbPorts = map[string]int{"en2": 1, "en3": 2}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// fixture is one server-side pairing setup over a real file token store.
type fixture struct {
	h      *Handler
	tokens *bootstrap.FileTokenStore
	win    WindowStore
	clock  *fakeClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	clock := &fakeClock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	tokens := bootstrap.NewFileTokenStore(bootstrap.TokensPath(dir), clock.Now)
	win := WindowStore{Path: WindowPath(dir), Lock: tokens.WithLock}
	h := &Handler{
		HardwarePorts: func(context.Context) (map[string]int, error) { return tbPorts, nil },
		Windows:       win,
		Tokens:        tokens,
		ClusterPin:    testPin,
		JoinPort:      9345,
		LinkIP:        func(iface string) string { return map[string]string{"en2": "169.254.0.1", "en3": "169.254.0.2"}[iface] },
		Now:           clock.Now,
	}
	return &fixture{h: h, tokens: tokens, win: win, clock: clock}
}

// pair runs one request with the given local and remote addresses (the zone of a
// TCP connection's addresses is the interface the kernel received it on).
func (f *fixture) pair(t *testing.T, local, remote, node string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(netv1alpha1.PairRequest{Version: netv1alpha1.PairVersion, NodeName: node})
	r := httptest.NewRequest(http.MethodPost, bootstrap.PairPath, strings.NewReader(string(body)))
	la := netip.MustParseAddr(local)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.IP(la.AsSlice()), Port: 9345, Zone: la.Zone()}))
	r.RemoteAddr = net.JoinHostPort(remote, "51234")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *fixture) open(t *testing.T, maxJoins int) {
	t.Helper()
	if _, err := f.win.Open(f.clock.Now(), 10*time.Minute, maxJoins); err != nil {
		t.Fatal(err)
	}
}

func decodeToken(t *testing.T, w *httptest.ResponseRecorder) netv1alpha1.PairResponse {
	t.Helper()
	var resp netv1alpha1.PairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode pair response: %v (%s)", err, w.Body.String())
	}
	return resp
}

// TestPairTrustDecision pins the pairing trust decision, server side and joiner
// side, as the M17 plan §4 lists it, over an injected hardware-port mapping, a
// fake clock and fake connection addresses. The real-socket test
// (zone_integration_test.go) pins the premise this table fakes: that the zone
// net/http reports for an accepted link-local connection is the interface name.
func TestPairTrustDecision(t *testing.T) {
	const tbLocal, tbRemote = "fe80::1%en2", "fe80::2%en2"
	refusals := []struct {
		name     string
		setup    func(f *fixture)
		local    string
		remote   string
		wantCode int
		want     Reason
	}{
		{"bridge0 zone", nil, "fe80::1%bridge0", "fe80::2%bridge0", http.StatusForbidden, ReasonNotThunderbolt},
		{"Wi-Fi en0 zone", nil, "fe80::1%en0", "fe80::2%en0", http.StatusForbidden, ReasonNotThunderbolt},
		{"Ethernet en1 zone", nil, "fe80::1%en1", "fe80::2%en1", http.StatusForbidden, ReasonNotThunderbolt},
		{"utun zone", nil, "fe80::1%utun4", "fe80::2%utun4", http.StatusForbidden, ReasonNotThunderbolt},
		{"dock Ethernet Adapter zone", nil, "fe80::1%en7", "fe80::2%en7", http.StatusForbidden, ReasonNotThunderbolt},
		{"global-unicast local address", nil, "2001:db8::1", "2001:db8::2", http.StatusForbidden, ReasonNotLinkLocal},
		{"IPv4 local address", nil, "192.0.2.10", "192.0.2.11", http.StatusForbidden, ReasonNotLinkLocal},
		{"remote zone differs from the local zone", nil, tbLocal, "fe80::2%en3", http.StatusForbidden, ReasonRemoteNotSameLink},
		{"remote not link-local", nil, tbLocal, "2001:db8::2", http.StatusForbidden, ReasonRemoteNotSameLink},
		{"closed window (none)", func(f *fixture) {}, tbLocal, tbRemote, http.StatusForbidden, ReasonWindowClosed},
		{"closed window (expired)", func(f *fixture) {
			f.open(t, 1)
			f.clock.Advance(11 * time.Minute)
		}, tbLocal, tbRemote, http.StatusForbidden, ReasonWindowClosed},
		{"completed >= maxJoins", func(f *fixture) {
			f.open(t, 1)
			if err := f.win.RecordCompleted(); err != nil {
				t.Fatal(err)
			}
		}, tbLocal, tbRemote, http.StatusForbidden, ReasonWindowFull},
	}
	for _, tc := range refusals {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			} else {
				f.open(t, 1) // the window is open: the refusal is the connection's
			}
			w := f.pair(t, tc.local, tc.remote, "new-mac")
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (%s)", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), string(tc.want)) {
				t.Errorf("body %q does not name the reason %q", w.Body.String(), tc.want)
			}
		})
	}

	t.Run("accept/thunderbolt zone and open window mint a reserved one-shot token bound to the name", func(t *testing.T) {
		f := newFixture(t)
		f.open(t, 1)
		w := f.pair(t, tbLocal, tbRemote, "new-mac")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
		}
		resp := decodeToken(t, w)
		tok, err := bootstrap.ParseToken(resp.Token)
		if err != nil {
			t.Fatalf("minted token does not parse: %v", err)
		}
		if tok.CAHash != testPin {
			t.Errorf("token pins %q, want the cluster pin", tok.CAHash)
		}
		if resp.ServerLinkIP != "169.254.0.1" {
			t.Errorf("ServerLinkIP = %q, want the en2 port's address", resp.ServerLinkIP)
		}
		if resp.ServerURL != "https://[fe80::1]:9345" {
			t.Errorf("ServerURL = %q, want the server's link-local join listener without a zone", resp.ServerURL)
		}
		// The token is the ordinary kind: an ordinary verifier refuses it, the
		// join verifier honours it only for the bound name, and it is one-shot.
		if err := f.tokens.VerifyToken(context.Background(), resp.Token); !errors.Is(err, bootstrap.ErrTokenNodeMismatch) {
			t.Errorf("plain VerifyToken = %v, want ErrTokenNodeMismatch (a bound token is honoured only through the binding)", err)
		}
		claim, err := f.tokens.VerifyJoinToken(context.Background(), resp.Token, "new-mac")
		if err != nil {
			t.Fatalf("VerifyJoinToken for the bound name: %v", err)
		}
		if !claim.OneShot() {
			t.Error("the minted token's claim is not one-shot")
		}
		if _, err := f.tokens.VerifyJoinToken(context.Background(), resp.Token, "new-mac"); !errors.Is(err, bootstrap.ErrTokenInUse) {
			t.Errorf("a second verify while the first join holds the token = %v, want ErrTokenInUse (the atomic reserve)", err)
		}
		claim.Release()
		claim, err = f.tokens.VerifyJoinToken(context.Background(), resp.Token, "new-mac")
		if err != nil {
			t.Fatalf("a failed join released the token, so a retry must verify: %v", err)
		}
		if err := claim.Consume(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("refuse/a second request on the interface within 10s is 429", func(t *testing.T) {
		f := newFixture(t)
		f.open(t, 2)
		if w := f.pair(t, tbLocal, tbRemote, "new-mac"); w.Code != http.StatusOK {
			t.Fatalf("first request status = %d (%s)", w.Code, w.Body.String())
		}
		f.clock.Advance(5 * time.Second)
		w := f.pair(t, tbLocal, tbRemote, "new-mac")
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), string(ReasonRateLimited)) {
			t.Fatalf("second request within 10s: status %d body %q, want 429 rate-limited", w.Code, w.Body.String())
		}
		f.clock.Advance(6 * time.Second)
		if w := f.pair(t, tbLocal, tbRemote, "new-mac"); w.Code != http.StatusOK {
			t.Fatalf("a request after 10s: status %d (%s), want 200", w.Code, w.Body.String())
		}
	})

	t.Run("refuse/the window's mint cap", func(t *testing.T) {
		f := newFixture(t)
		f.open(t, 1)
		for i := 0; i < mintsPerJoin; i++ {
			if w := f.pair(t, tbLocal, tbRemote, "new-mac"); w.Code != http.StatusOK {
				t.Fatalf("mint %d: status %d (%s)", i, w.Code, w.Body.String())
			}
			f.clock.Advance(AcceptInterval)
		}
		w := f.pair(t, tbLocal, tbRemote, "new-mac")
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), string(ReasonMintCap)) {
			t.Fatalf("mint past the cap: status %d body %q, want 403 mint-cap", w.Code, w.Body.String())
		}
	})

	t.Run("refuse/the minted token used with another name", func(t *testing.T) {
		f := newFixture(t)
		f.open(t, 1)
		resp := decodeToken(t, f.pair(t, tbLocal, tbRemote, "new-mac"))
		if _, err := f.tokens.VerifyJoinToken(context.Background(), resp.Token, "someone-else"); !errors.Is(err, bootstrap.ErrTokenNodeMismatch) {
			t.Fatalf("VerifyJoinToken with another name = %v, want ErrTokenNodeMismatch (the join handler answers it 403)", err)
		}
	})

	t.Run("refuse/the minted token used twice", func(t *testing.T) {
		f := newFixture(t)
		f.open(t, 1)
		resp := decodeToken(t, f.pair(t, tbLocal, tbRemote, "new-mac"))
		claim, err := f.tokens.VerifyJoinToken(context.Background(), resp.Token, "new-mac")
		if err != nil {
			t.Fatal(err)
		}
		if err := claim.Consume(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.tokens.VerifyJoinToken(context.Background(), resp.Token, "new-mac"); !errors.Is(err, bootstrap.ErrTokenConsumed) {
			t.Fatalf("a second use = %v, want ErrTokenConsumed", err)
		}
		// A fresh store over the same file agrees: consumption is persisted.
		again := bootstrap.NewFileTokenStore(f.tokens.Path(), f.clock.Now)
		if _, err := again.VerifyJoinToken(context.Background(), resp.Token, "new-mac"); !errors.Is(err, bootstrap.ErrTokenConsumed) {
			t.Fatalf("a second use through a restarted store = %v, want ErrTokenConsumed", err)
		}
	})

	open := netv1alpha1.Beacon{Version: netv1alpha1.BeaconVersion, ClusterPin: testPin, NodeName: "server", JoinPort: 9345, PairingOpen: true}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	joinerRows := []struct {
		name   string
		arm    Arm
		beacon netv1alpha1.Beacon
		want   string
	}{
		{"joiner/a beacon whose pin mismatches --cluster is ignored", Arm{Until: now.Add(time.Minute), Cluster: strings.Repeat("0", 64)}, open, "cluster-pin-mismatch"},
		{"joiner/an unarmed machine ignores every beacon", Arm{}, open, "not-armed"},
		{"joiner/an expired arming ignores every beacon", Arm{Until: now.Add(-time.Second)}, open, "not-armed"},
		{"joiner/a closed window is not asked", Arm{Until: now.Add(time.Minute)}, func() netv1alpha1.Beacon { b := open; b.PairingOpen = false; return b }(), "pairing-closed"},
		{"joiner/a matching pin is asked", Arm{Until: now.Add(time.Minute), Cluster: testPin}, open, ""},
		{"joiner/no --cluster trusts the first open server (the documented limitation)", Arm{Until: now.Add(time.Minute)}, open, ""},
	}
	for _, tc := range joinerRows {
		t.Run(tc.name, func(t *testing.T) {
			j := Joiner{Arm: tc.arm}
			h := Heard{Beacon: tc.beacon, Src: netip.MustParseAddr("fe80::1"), Iface: "bridge0"}
			if got := j.Consider(h, now); got != tc.want {
				t.Fatalf("Consider = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDecideTakesTheZoneFromTheLocalAddressOnly pins that the interface is read
// from the connection's local zone and from nothing a client sends: a remote
// zone naming a Thunderbolt port does not rescue a local zone that names none.
func TestDecideTakesTheZoneFromTheLocalAddressOnly(t *testing.T) {
	d := Decide(netip.MustParseAddr("fe80::1%bridge0"), netip.MustParseAddr("fe80::2%en2"), tbPorts)
	if d.Refused != ReasonNotThunderbolt {
		t.Fatalf("Decide = %+v, want not-thunderbolt", d)
	}
	d = Decide(netip.MustParseAddr("fe80::1%en3"), netip.MustParseAddr("fe80::2%en3"), tbPorts)
	if d.Refused != "" || d.Iface != "en3" {
		t.Fatalf("Decide = %+v, want trusted on en3", d)
	}
	d = Decide(netip.MustParseAddr("fe80::1%en2"), netip.MustParseAddr("fe80::2%en2"), nil)
	if d.Refused != ReasonNotThunderbolt {
		t.Fatalf("Decide with no mapping = %+v, want not-thunderbolt (no mapping is no Thunderbolt port)", d)
	}
}

func TestWindowPathIsUnderTheWorkDir(t *testing.T) {
	if got := WindowPath("/w"); got != filepath.Join("/w", WindowFile) {
		t.Fatalf("WindowPath = %q", got)
	}
}
