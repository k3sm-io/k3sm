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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// fakeMembers is an in-memory etcd membership: MemberAddAsLearner appends an
// unstarted learner (no name, no client URLs, as etcd registers one), and every call
// is recorded in order.
type fakeMembers struct {
	mu      sync.Mutex
	members []bootstrap.EtcdMember
	nextID  uint64
	calls   []string
	listErr error
	promErr error
}

func (f *fakeMembers) record(c string) { f.calls = append(f.calls, c) }

func (f *fakeMembers) MemberList(context.Context) ([]bootstrap.EtcdMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("list")
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.members), nil
}

func (f *fakeMembers) MemberAddAsLearner(_ context.Context, peerURL string) (bootstrap.EtcdMember, []bootstrap.EtcdMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("add " + peerURL)
	f.nextID++
	m := bootstrap.EtcdMember{ID: 0x1000 + f.nextID, PeerURLs: []string{peerURL}, IsLearner: true}
	f.members = append(f.members, m)
	return m, slices.Clone(f.members), nil
}

func (f *fakeMembers) MemberPromote(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fmt.Sprintf("promote %x", id))
	if f.promErr != nil {
		return f.promErr
	}
	for i := range f.members {
		if f.members[i].ID == id {
			f.members[i].IsLearner = false
		}
	}
	return nil
}

func (f *fakeMembers) MemberRemove(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fmt.Sprintf("remove %x", id))
	f.members = slices.DeleteFunc(f.members, func(m bootstrap.EtcdMember) bool { return m.ID == id })
	return nil
}

func (f *fakeMembers) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

const (
	memberTestSecret = "high-entropy-server-bootstrap-secret-abc123"
	serverAPeer      = "https://192.0.2.10:2380"
	joinerPeer       = "https://192.0.2.11:2380"
)

// serverA is the existing server's member as etcd lists it.
var serverA = bootstrap.EtcdMember{ID: 0xa, Name: "server-a", PeerURLs: []string{serverAPeer}, ClientURLs: []string{"https://127.0.0.1:2379"}}

type memberRig struct {
	ts          *httptest.Server
	members     *fakeMembers
	serverToken string
	workerToken string
	logs        *syncBuffer
}

// syncBuffer is a goroutine-safe log sink: the handler logs on the server's
// goroutine, the test reads on its own.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newMemberRig(t *testing.T, members *fakeMembers) memberRig {
	t.Helper()
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	workerTokens := bootstrap.NewTokenStore(nil)
	wUser, wSecret, _, err := workerTokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create worker token: %v", err)
	}
	logs := &syncBuffer{}
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        workerTokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "198.51.100.0/24", meshIP: "198.51.100.11"},
		SelfNodeName:  "server-a",
		ServerAuth:    bootstrap.NewStaticServerSecret(memberTestSecret),
		Members:       members,
		Logger:        slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return memberRig{
		ts:          ts,
		members:     members,
		serverToken: bootstrap.FormatServerToken(clusterCA.PinHash(), memberTestSecret),
		workerToken: bootstrap.FormatToken(clusterCA.PinHash(), wUser, wSecret),
		logs:        logs,
	}
}

func (r memberRig) post(t *testing.T, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, r.ts.URL+path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func countPrefix(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// TestEtcdMemberRouteAddsLearner pins the ordinary join: the name is unused, so the
// route adds exactly one LEARNER at the joiner's peer URL (never a voting add) and
// answers with its ID and an --initial-cluster built from the resulting member list,
// the unstarted joiner named by the request. The client helper speaks the same wire.
func TestEtcdMemberRouteAddsLearner(t *testing.T) {
	rig := newMemberRig(t, &fakeMembers{members: []bootstrap.EtcdMember{serverA}})

	resp, err := bootstrap.RequestEtcdMember(context.Background(), rig.ts.URL, rig.serverToken, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, rig.ts.Client())
	if err != nil {
		t.Fatalf("RequestEtcdMember: %v", err)
	}
	calls := rig.members.callLog()
	if !slices.Equal(calls, []string{"list", "add " + joinerPeer}) {
		t.Fatalf("calls = %v, want one list then one learner add", calls)
	}
	if resp.MemberID != 0x1001 {
		t.Errorf("member ID = %x, want the added learner's 1001", resp.MemberID)
	}
	want := "server-a=" + serverAPeer + ",server-b=" + joinerPeer
	if resp.InitialCluster != want {
		t.Errorf("initial cluster = %q, want %q", resp.InitialCluster, want)
	}
	if got := rig.members.members[1]; !got.IsLearner {
		t.Errorf("the joiner was added as a voting member: %+v", got)
	}

	// The peer URL must be canonical https://<non-loopback ip>:<port>; anything else
	// is refused before the membership is touched.
	before := len(rig.members.callLog())
	for _, bad := range []string{"http://192.0.2.11:2380", "https://127.0.0.1:2380", "https://host.local:2380", "https://192.0.2.11", "https://192.0.2.11:2380/x", "https://u:p@192.0.2.11:2380"} {
		r, _ := rig.post(t, bootstrap.EtcdMemberPath, rig.serverToken, bootstrap.EtcdMemberRequest{Name: "server-c", PeerURL: bad})
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("peer URL %q: status %d, want 400", bad, r.StatusCode)
		}
	}
	// A non-canonical name and this server's own name are refused too: the second
	// would let the stale-member path remove the member serving the request.
	for _, bad := range []string{"Server-C", "server-a"} {
		r, _ := rig.post(t, bootstrap.EtcdMemberPath, rig.serverToken, bootstrap.EtcdMemberRequest{Name: bad, PeerURL: "https://192.0.2.12:2380"})
		if r.StatusCode/100 != 4 {
			t.Errorf("name %q: status %d, want a 4xx refusal", bad, r.StatusCode)
		}
	}
	if after := len(rig.members.callLog()); after != before {
		t.Errorf("a refused request touched the membership: %v", rig.members.callLog()[before:])
	}
}

// TestEtcdMemberRouteReusesUnstartedLearner pins the launchd-restart case: the joiner
// was added, then restarted before its member ever ran, so an UNSTARTED learner (no
// name, no client URLs) already sits at its peer URL. The route reuses it — no second
// add, no remove — and the answer names that learner.
func TestEtcdMemberRouteReusesUnstartedLearner(t *testing.T) {
	pending := bootstrap.EtcdMember{ID: 0xb, PeerURLs: []string{joinerPeer}, IsLearner: true}
	rig := newMemberRig(t, &fakeMembers{members: []bootstrap.EtcdMember{serverA, pending}})

	for range 2 {
		resp, err := bootstrap.RequestEtcdMember(context.Background(), rig.ts.URL, rig.serverToken, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, rig.ts.Client())
		if err != nil {
			t.Fatalf("RequestEtcdMember: %v", err)
		}
		if resp.MemberID != 0xb {
			t.Errorf("member ID = %x, want the existing learner b", resp.MemberID)
		}
		if want := "server-a=" + serverAPeer + ",server-b=" + joinerPeer; resp.InitialCluster != want {
			t.Errorf("initial cluster = %q, want %q", resp.InitialCluster, want)
		}
	}
	calls := rig.members.callLog()
	if countPrefix(calls, "add") != 0 || countPrefix(calls, "remove") != 0 {
		t.Errorf("calls = %v, want lists only (the unstarted learner is reused)", calls)
	}
}

// TestEtcdMemberRouteRemovesStaleMember pins the re-join after a wiped data dir: a
// STARTED member already carries the joiner's name, and its old identity can never
// start again, so it is removed and a fresh learner added. An unstarted entry at a
// DIFFERENT peer URL under no name is untouched (another server mid-join), and a
// member under the joiner's name at a different peer URL is removed the same way.
func TestEtcdMemberRouteRemovesStaleMember(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stale bootstrap.EtcdMember
	}{
		{"started member, wiped data dir", bootstrap.EtcdMember{ID: 0xb, Name: "server-b", PeerURLs: []string{joinerPeer}, ClientURLs: []string{"https://127.0.0.1:2379"}}},
		{"same name, different peer URL", bootstrap.EtcdMember{ID: 0xb, Name: "server-b", PeerURLs: []string{"https://192.0.2.99:2380"}, ClientURLs: []string{"https://127.0.0.1:2379"}}},
		{"unstarted VOTING entry at the peer URL", bootstrap.EtcdMember{ID: 0xb, PeerURLs: []string{joinerPeer}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := bootstrap.EtcdMember{ID: 0xc, PeerURLs: []string{"https://192.0.2.77:2380"}, IsLearner: true}
			rig := newMemberRig(t, &fakeMembers{members: []bootstrap.EtcdMember{serverA, tc.stale, other}})

			resp, err := bootstrap.RequestEtcdMember(context.Background(), rig.ts.URL, rig.serverToken, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, rig.ts.Client())
			if err != nil {
				t.Fatalf("RequestEtcdMember: %v", err)
			}
			calls := rig.members.callLog()
			if !slices.Equal(calls, []string{"list", "remove b", "add " + joinerPeer}) {
				t.Fatalf("calls = %v, want list, remove the stale member, then the learner add", calls)
			}
			want := "server-a=" + serverAPeer + ",unstarted-c=https://192.0.2.77:2380,server-b=" + joinerPeer
			if resp.InitialCluster != want {
				t.Errorf("initial cluster = %q, want %q", resp.InitialCluster, want)
			}
			// Removing a STARTED member changes the cluster's quorum, so it is said at
			// WARN naming what went; an unstarted entry's removal stays at INFO.
			var warn string
			for _, l := range strings.Split(rig.logs.String(), "\n") {
				if strings.Contains(l, "level=WARN") && strings.Contains(l, "removed a started etcd member") {
					warn = l
				}
			}
			if tc.stale.Unstarted() {
				if warn != "" {
					t.Errorf("an unstarted entry's removal was logged at WARN: %s", warn)
				}
				return
			}
			for _, want := range []string{"member-id=b", "removed-name=" + tc.stale.Name, tc.stale.PeerURLs[0]} {
				if !strings.Contains(warn, want) {
					t.Errorf("the started-member removal WARN %q does not carry %q; logs:\n%s", warn, want, rig.logs.String())
				}
			}
		})
	}
}

// TestMemberRoutesRequireSelfNodeName: the etcd member routes refuse to be built
// without SelfNodeName, the guard that stops a request under this server's own name
// from removing the member serving it; the worker join alone still builds without it.
func TestMemberRoutesRequireSelfNodeName(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	cfg := func(self string, members bootstrap.MemberJoiner) bootstrap.ServerConfig {
		return bootstrap.ServerConfig{
			ClusterCA: clusterCA, SigningCA: signingCA, Tokens: bootstrap.NewTokenStore(nil),
			NodePasswords: bootstrap.NewMemoryNodePasswords(), Enroller: &fakeEnroller{},
			ServerAuth: bootstrap.NewStaticServerSecret(memberTestSecret), SelfNodeName: self, Members: members,
		}
	}
	for _, self := range []string{"", "   "} {
		if srv, err := bootstrap.NewServer(cfg(self, &fakeMembers{})); !errors.Is(err, bootstrap.ErrMembersNeedSelfNodeName) || srv != nil {
			t.Errorf("Members with SelfNodeName %q: NewServer = %v, %v; want nil, ErrMembersNeedSelfNodeName", self, srv, err)
		}
	}
	if _, err := bootstrap.NewServer(cfg("", nil)); err != nil {
		t.Errorf("no Members, no SelfNodeName: NewServer = %v, want it built (the worker join keeps its other guards)", err)
	}
	if _, err := bootstrap.NewServer(cfg("server-a", &fakeMembers{})); err != nil {
		t.Errorf("Members with SelfNodeName: NewServer = %v", err)
	}
}

// TestEtcdMemberPromoteRoute pins promotion: the named learner is promoted, an
// already-voting member is a 200 with no promote call (idempotent), a learner etcd
// will not promote yet is a 503 the joiner retries, and a name with no started member
// is a 404.
func TestEtcdMemberPromoteRoute(t *testing.T) {
	learner := bootstrap.EtcdMember{ID: 0xb, Name: "server-b", PeerURLs: []string{joinerPeer}, ClientURLs: []string{"https://127.0.0.1:2379"}, IsLearner: true}
	members := &fakeMembers{members: []bootstrap.EtcdMember{serverA, learner}, promErr: errors.New("can only promote a learner member which is in sync with leader")}
	rig := newMemberRig(t, members)
	ctx := context.Background()

	if err := bootstrap.PromoteEtcdMember(ctx, rig.ts.URL, rig.serverToken, "server-b", rig.ts.Client()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a not-yet-synced learner: err = %v, want a 503", err)
	}
	members.mu.Lock()
	members.promErr = nil
	members.mu.Unlock()
	for range 2 {
		if err := bootstrap.PromoteEtcdMember(ctx, rig.ts.URL, rig.serverToken, "server-b", rig.ts.Client()); err != nil {
			t.Fatalf("PromoteEtcdMember: %v", err)
		}
	}
	if n := countPrefix(members.callLog(), "promote b"); n != 2 {
		t.Errorf("promote calls = %d, want 2 (the refused one and the one that landed; the repeat is a no-op)", n)
	}
	if err := bootstrap.PromoteEtcdMember(ctx, rig.ts.URL, rig.serverToken, "server-z", rig.ts.Client()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("unknown member: err = %v, want a 404", err)
	}
}

// TestServerClassRoutesRejectWorkerToken pins the class split on the new routes: a
// worker token, a missing token and a wrong server secret are all refused before the
// membership is read, while the server token is served. /join keeps refusing a server
// token (TestCABundleEndpointRejectsWorkerIdentity covers the bundle route), and a
// server without Members serves neither route.
func TestServerClassRoutesRejectWorkerToken(t *testing.T) {
	rig := newMemberRig(t, &fakeMembers{members: []bootstrap.EtcdMember{serverA}})
	wrongSecret := bootstrap.FormatServerToken(strings.SplitN(strings.TrimPrefix(rig.serverToken, "K10"), "::", 2)[0], "not-the-secret")

	for _, path := range []string{bootstrap.EtcdMemberPath, bootstrap.EtcdMemberPromotePath} {
		body := bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}
		for _, tc := range []struct {
			name, token string
			want        int
		}{
			{"worker token", rig.workerToken, http.StatusForbidden},
			{"no token", "", http.StatusUnauthorized},
			{"wrong server secret", wrongSecret, http.StatusForbidden},
		} {
			resp, _ := rig.post(t, path, tc.token, body)
			if resp.StatusCode != tc.want {
				t.Errorf("%s with %s: status %d, want %d", path, tc.name, resp.StatusCode, tc.want)
			}
		}
		req, _ := http.NewRequest(http.MethodGet, rig.ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+rig.serverToken)
		if resp, err := rig.ts.Client().Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: %v %v, want 405", path, resp, err)
		}
	}
	if calls := rig.members.callLog(); len(calls) != 0 {
		t.Fatalf("a refused request reached the membership: %v", calls)
	}
	if _, err := bootstrap.RequestEtcdMember(context.Background(), rig.ts.URL, rig.workerToken, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, rig.ts.Client()); !errors.Is(err, bootstrap.ErrNotServerToken) {
		t.Errorf("the client helper accepted a worker token: %v", err)
	}
	if resp, _ := rig.post(t, bootstrap.EtcdMemberPath, rig.serverToken, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}); resp.StatusCode != http.StatusOK {
		t.Errorf("server token: status %d, want 200", resp.StatusCode)
	}

	// /join refuses the server class: the server token is not a worker join token.
	resp, _ := rig.post(t, bootstrap.JoinPath, "", bootstrap.JoinRequest{Token: rig.serverToken, NodeName: "server-b"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/join with a server token: status %d, want 401", resp.StatusCode)
	}

	// No Members: neither route exists, even with ServerAuth set.
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	bare, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA: clusterCA, SigningCA: signingCA, Tokens: bootstrap.NewTokenStore(nil),
		NodePasswords: bootstrap.NewMemoryNodePasswords(), Enroller: &fakeEnroller{},
		ServerAuth: bootstrap.NewStaticServerSecret(memberTestSecret),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(bare.Handler())
	defer ts.Close()
	r, err := ts.Client().Post(ts.URL+bootstrap.EtcdMemberPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("etcd-member without Members: status %d, want 404", r.StatusCode)
	}
}

// TestServerRouteFailureClassification: the client helpers return a typed
// *ServerRouteError for a non-2xx answer, and IsPermanentServerRouteFailure classifies
// by status code and sentinel, never message text. A refusal of the request itself
// (400/401/403/409), a token that does not parse or is not the server class, and an
// existing server whose CA does not match the token's pin are permanent; a 404, a 429,
// every 5xx and a network failure are worth retrying.
func TestServerRouteFailureClassification(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	token := bootstrap.FormatServerToken(clusterCA.PinHash(), memberTestSecret)
	for _, tc := range []struct {
		code      int
		permanent bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusConflict, true},
		{http.StatusNotFound, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusServiceUnavailable, false},
	} {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// The message deliberately reads like the opposite class, so a
				// classifier that looked at text would get it wrong.
				http.Error(w, "permanent transient retry refused", tc.code)
			}))
			defer ts.Close()
			_, err := bootstrap.RequestEtcdMember(context.Background(), ts.URL, token, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, ts.Client())
			re, ok := errors.AsType[*bootstrap.ServerRouteError](err)
			if !ok || re.StatusCode != tc.code || re.Path != bootstrap.EtcdMemberPath {
				t.Fatalf("err = %v (%T), want a *ServerRouteError for %d on %s", err, err, tc.code, bootstrap.EtcdMemberPath)
			}
			if got := bootstrap.IsPermanentServerRouteFailure(err); got != tc.permanent {
				t.Errorf("IsPermanentServerRouteFailure(%d) = %v, want %v", tc.code, got, tc.permanent)
			}
			if got := bootstrap.IsPermanentServerRouteFailure(fmt.Errorf("wrapped: %w", err)); got != tc.permanent {
				t.Errorf("wrapped %d: IsPermanentServerRouteFailure = %v, want %v", tc.code, got, tc.permanent)
			}
		})
	}

	t.Run("a token that does not parse, or is a worker token: permanent", func(t *testing.T) {
		for _, bad := range []string{"not-a-token", bootstrap.FormatToken(clusterCA.PinHash(), "abcdef", "0123456789abcdef")} {
			_, err := bootstrap.RequestEtcdMember(context.Background(), "https://192.0.2.10:9345", bad, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, nil)
			if err == nil || !bootstrap.IsPermanentServerRouteFailure(err) {
				t.Errorf("token %q: err = %v, permanent = %v; want a permanent failure", bad, err, bootstrap.IsPermanentServerRouteFailure(err))
			}
		}
	})

	t.Run("the wrong cluster's CA: permanent", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("a request reached a server whose CA does not match the pin")
		}))
		defer ts.Close()
		// client nil: the helper builds the CA-pinned client from the token, and the
		// test server's certificate is not the cluster CA the token pins.
		_, err := bootstrap.RequestEtcdMember(context.Background(), ts.URL, token, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, nil)
		if err == nil || !errors.Is(err, certs.ErrPinMismatch) || !bootstrap.IsPermanentServerRouteFailure(err) {
			t.Errorf("err = %v; want a permanent failure wrapping certs.ErrPinMismatch", err)
		}
	})

	t.Run("a network failure: transient", func(t *testing.T) {
		ts := httptest.NewServer(http.NotFoundHandler())
		url := ts.URL
		ts.Close()
		_, err := bootstrap.RequestEtcdMember(context.Background(), url, token, bootstrap.EtcdMemberRequest{Name: "server-b", PeerURL: joinerPeer}, http.DefaultClient)
		if err == nil || bootstrap.IsPermanentServerRouteFailure(err) {
			t.Errorf("err = %v, permanent = %v; want a transient failure", err, bootstrap.IsPermanentServerRouteFailure(err))
		}
	})
}
