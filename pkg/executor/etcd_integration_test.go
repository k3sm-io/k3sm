//go:build integration

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

// The embedded-etcd integration tests: a REAL etcd, built from the pinned wrapper
// through the production stagedChild protocol, started from etcdArgs' output (never a
// hand-built argv) with leaves minted by provisionEtcdCerts from a throwaway
// hierarchy. No root, no network beyond loopback, no -race (three members on one
// small host need the CPU), one test at a time.
//
// Two things are loopback-specific, and both are deliberate:
//
//   - Every member peers on 127.0.0.1. The production entry points refuse that
//     (Validate and ClusterReset return ErrEtcdNeedsNodeIP, and the bootstrap member
//     route refuses a loopback peer URL), because a real server advertising loopback
//     would make every other server dial itself. So the members are started through
//     startEtcd (which renders etcdArgs and does not validate), and the reset goes
//     through clusterReset, the unexported body ClusterReset calls after validating.
//   - The bootstrap member route is the REAL handler (bootstrap.Server over
//     httptest, driven by the real RequestEtcdMember / PromoteEtcdMember clients),
//     but it sees each member under a documentation address (RFC 5737) instead of
//     127.0.0.1. itJoiner, the MemberJoiner it drives, translates between the two at
//     the seam: the route's add / reuse / stale-member logic runs unchanged against
//     real etcd membership, and etcd itself only ever sees loopback URLs. cmd/k3sm's
//     localMemberJoiner is the production adapter; it lives in package main, so this
//     is a copy of its shape plus the translation.

package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

const (
	// itHeartbeatMS / itElectionMS keep three members on one loaded laptop from
	// flapping leadership (etcd's 100 ms / 1000 ms defaults assume a quiet host).
	itHeartbeatMS = 250
	itElectionMS  = 2500
	// itBringUp bounds one member's bring-up: spawn, accept, promotion, quorum.
	itBringUp = 2 * time.Minute
	// itConverge bounds a poll for a cluster-wide state (members, a write landing).
	itConverge = 45 * time.Second
)

// itEtcd is the wrapper binary, built once per test binary and shared by the three
// tests; afterTestBinary removes it.
var itEtcd struct {
	once sync.Once
	bin  string
	skip string
	err  error
}

// itEtcdBinary returns the staged etcd binary, building it on first use. It skips
// only when there is no Go toolchain, or when the build cannot reach the module
// cache or proxy; any other build failure fails the test.
func itEtcdBinary(t *testing.T) string {
	t.Helper()
	itEtcd.once.Do(stageITEtcd)
	if itEtcd.skip != "" {
		t.Skip(itEtcd.skip)
	}
	if itEtcd.err != nil {
		t.Fatalf("stage the etcd wrapper: %v", itEtcd.err)
	}
	return itEtcd.bin
}

func stageITEtcd() {
	if _, err := lookPathGo(); err != nil {
		itEtcd.skip = "no Go toolchain on PATH to build the etcd wrapper: " + err.Error()
		return
	}
	dir, err := os.MkdirTemp("", "k3sm-etcd-it-")
	if err != nil {
		itEtcd.err = err
		return
	}
	afterTestBinary = append(afterTestBinary, func() { _ = os.RemoveAll(dir) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := ensureEtcdInto(ctx, dir, DefaultEtcdVersion); err != nil {
		switch {
		case errors.Is(err, ErrNoGoToolchain):
			itEtcd.skip = "no Go toolchain to build the etcd wrapper: " + err.Error()
		case moduleFetchFailed(err):
			itEtcd.skip = "the module cache/proxy is unreachable for the etcd wrapper build: " + err.Error()
		default:
			itEtcd.err = err
		}
		return
	}
	itEtcd.bin = filepath.Join(dir, etcdBinaryName)
}

// moduleFetchFailed reports a wrapper build that failed fetching modules, not
// compiling them: the one build failure that says nothing about the code.
func moduleFetchFailed(err error) bool {
	msg := err.Error()
	for _, s := range []string{"dial tcp", "no such host", "i/o timeout", "connection refused",
		"network is unreachable", "TLS handshake timeout", "module lookup disabled", "proxyconnect"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// itLogWriter routes a component's slog output into the test log.
type itLogWriter struct {
	t    *testing.T
	name string
}

func (w itLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("[%s] %s", w.name, bytes.TrimRight(p, "\n"))
	return len(p), nil
}

// itPorts hands out free loopback ports, never the same one twice in a test.
type itPorts struct{ seen map[int]bool }

func (p *itPorts) next(t *testing.T) int {
	t.Helper()
	if p.seen == nil {
		p.seen = map[int]bool{}
	}
	for {
		if port := freePort(t); !p.seen[port] {
			p.seen[port] = true
			return port
		}
	}
}

// itPeers maps each member's peer port to the documentation address the bootstrap
// route sees it under (see the file comment).
type itPeers map[int]string

// routeURL renders a loopback peer URL as the route sees it.
func (p itPeers) routeURL(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	port, _ := strconv.Atoi(pu.Port())
	ip, ok := p[port]
	if !ok {
		return u
	}
	return "https://" + net.JoinHostPort(ip, pu.Port())
}

// loopbackURL renders a route-side peer URL as etcd sees it.
func loopbackURL(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	return "https://" + net.JoinHostPort("127.0.0.1", pu.Port())
}

// loopbackCluster renders the route's --initial-cluster answer as etcd sees it.
func loopbackCluster(ic string) string {
	parts := strings.Split(ic, ",")
	for i, part := range parts {
		if name, u, ok := strings.Cut(part, "="); ok {
			parts[i] = name + "=" + loopbackURL(u)
		}
	}
	return strings.Join(parts, ",")
}

// itJoiner is bootstrap.MemberJoiner over the existing member's LocalEtcdAdmin, with
// the peer-URL translation at the seam.
type itJoiner struct {
	admin *LocalEtcdAdmin
	peers itPeers
}

func (j itJoiner) export(ms []EtcdMember) []bootstrap.EtcdMember {
	out := make([]bootstrap.EtcdMember, 0, len(ms))
	for _, m := range ms {
		bm := bootstrap.EtcdMember(m)
		bm.PeerURLs = nil
		for _, u := range m.PeerURLs {
			bm.PeerURLs = append(bm.PeerURLs, j.peers.routeURL(u))
		}
		out = append(out, bm)
	}
	return out
}

func (j itJoiner) MemberList(ctx context.Context) ([]bootstrap.EtcdMember, error) {
	ms, err := j.admin.MemberList(ctx)
	if err != nil {
		return nil, err
	}
	return j.export(ms), nil
}

func (j itJoiner) MemberAddAsLearner(ctx context.Context, peerURL string) (bootstrap.EtcdMember, []bootstrap.EtcdMember, error) {
	added, ms, err := j.admin.MemberAddAsLearner(ctx, loopbackURL(peerURL))
	if err != nil {
		return bootstrap.EtcdMember{}, nil, err
	}
	return j.export([]EtcdMember{added})[0], j.export(ms), nil
}

func (j itJoiner) MemberPromote(ctx context.Context, id uint64) error {
	return j.admin.MemberPromote(ctx, id)
}

func (j itJoiner) MemberRemove(ctx context.Context, id uint64) error {
	return j.admin.MemberRemove(ctx, id)
}

// itNoEnroll satisfies bootstrap.Enroller; the member routes never enroll.
type itNoEnroll struct{}

var errITNoEnroll = errors.New("the etcd integration test serves no worker join")

func (itNoEnroll) Enroll(context.Context, string, netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, bootstrap.Allocation, error) {
	return netv1.MeshEnrollResponse{}, bootstrap.Allocation{}, errITNoEnroll
}
func (itNoEnroll) ReleaseAllocation(context.Context, string, bootstrap.Allocation) error {
	return errITNoEnroll
}
func (itNoEnroll) RefreshEndpoint(context.Context, string, string, []netv1.EndpointCandidate) error {
	return errITNoEnroll
}
func (itNoEnroll) Deregister(context.Context, string) error { return errITNoEnroll }

// itRoute is an existing member's bootstrap server, serving the member routes.
type itRoute struct {
	url, token string
	client     *http.Client
	joiner     itJoiner
}

func newITRoute(t *testing.T, existing *itMember, h *certs.Hierarchy, peers itPeers) itRoute {
	t.Helper()
	admin, err := NewLocalEtcdAdmin(t.Context(), existing.wd, existing.cfg.KinePort)
	if err != nil {
		t.Fatalf("local etcd admin for %s: %v", existing.name, err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	joiner := itJoiner{admin: admin, peers: peers}
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     h.Cluster,
		SigningCA:     h.Signing,
		Tokens:        bootstrap.NewTokenStore(nil),
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      itNoEnroll{},
		SelfNodeName:  existing.name,
		ServerAuth:    bootstrap.NewStaticServerSecret(hex.EncodeToString(secret)),
		Members:       joiner,
		Logger:        slog.New(slog.NewTextHandler(itLogWriter{t, "route@" + existing.name}, nil)),
	})
	if err != nil {
		t.Fatalf("bootstrap server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return itRoute{url: ts.URL, token: bootstrap.FormatServerToken(h.Cluster.PinHash(), hex.EncodeToString(secret)),
		client: ts.Client(), joiner: joiner}
}

// itMember is one etcd member with its own work dir.
type itMember struct {
	name, docIP string
	wd          string
	cfg         Config
	s           *Supervised
	c           *component
}

// newITMember lays down a member's work dir the way a server's boot does: an init
// member mints the hierarchy, a joining one writes the one it was handed (the
// bundle import), then provisionEtcdCerts mints the leaves and the data dir.
func newITMember(t *testing.T, name, docIP string, role EtcdRole, h *certs.Hierarchy, ports *itPorts, peers itPeers) *itMember {
	t.Helper()
	bin := itEtcdBinary(t)
	wd := t.TempDir()
	if role == EtcdInit {
		if _, err := certs.EnsureHierarchy(wd); err != nil {
			t.Fatal(err)
		}
	} else if err := certs.WriteHierarchy(wd, h); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(binDir(wd), etcdBinaryName)); err != nil {
		t.Fatal(err)
	}
	m := &itMember{name: name, docIP: docIP, wd: wd, cfg: Config{
		WorkDir:  wd,
		KinePort: ports.next(t),
		Logger:   slog.New(slog.NewTextHandler(itLogWriter{t, name}, nil)),
		Etcd: &EtcdConfig{Role: role, Name: name, PeerIP: "127.0.0.1",
			PeerPort: ports.next(t), MetricsPort: ports.next(t)},
	}}
	peers[m.cfg.Etcd.PeerPort] = docIP
	m.provision(t)
	return m
}

func (m *itMember) provision(t *testing.T) {
	t.Helper()
	if err := provisionEtcdCerts(m.cfg); err != nil {
		t.Fatalf("provision %s: %v", m.name, err)
	}
}

// hierarchy loads the four CAs from an init member's work dir (what its bundle
// would carry).
func (m *itMember) hierarchy(t *testing.T) *certs.Hierarchy {
	t.Helper()
	h, err := certs.EnsureHierarchy(m.wd)
	if err != nil {
		t.Fatal(err)
	}
	if h.EtcdServer, h.EtcdPeer, err = certs.EnsureEtcdCAs(m.wd); err != nil {
		t.Fatal(err)
	}
	return h
}

func (m *itMember) clientURL() string { return etcdClientURL(m.cfg.KinePort) }

// routePeerURL is this member's peer URL as the bootstrap route sees it.
func (m *itMember) routePeerURL(t *testing.T) string {
	t.Helper()
	u, err := bootstrap.CanonicalPeerURL("https://" + net.JoinHostPort(m.docIP, strconv.Itoa(m.cfg.Etcd.PeerPort)))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// start spawns the member from etcdArgs (with the test timings) and waits for its
// client port, exactly as bring-up step 1 does.
func (m *itMember) start(t *testing.T, ctx context.Context) {
	t.Helper()
	s := NewSupervised(m.cfg)
	c, err := s.startEtcd(ctx, EtcdMemberExists(m.wd), func(in *etcdArgsInput) {
		in.HeartbeatMS, in.ElectionMS = itHeartbeatMS, itElectionMS
	})
	if err != nil {
		t.Fatalf("start %s: %v", m.name, err)
	}
	pid := c.cmd.Process.Pid
	spawnedChildren.track(c.cmd, "etcd member "+m.name)
	t.Cleanup(func() { stopITSupervisor(s, pid) })
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s etcd log tail:\n%s", m.name, RedactedLogTail(c.logPath))
		}
	})
	m.s, m.c = s, c
	if err := awaitHealthy(ctx, c.name, c.exited, c.exitedNow, s.etcd.ready(m.cfg.KinePort), componentReadyTimeout, 300*time.Millisecond, c.exitDetail); err != nil {
		t.Fatalf("%s not listening: %v", m.name, err)
	}
}

// bringUp is start plus the rest of bringUpEtcdMember's waits, through the SAME
// function production calls (promoteAndAwaitQuorum): a joining member that reports
// itself a learner — on its first boot or on any restart — is promoted, then the
// no-expiry quorum wait runs (bounded here by ctx).
func (m *itMember) bringUp(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), itBringUp)
	defer cancel()
	m.start(t, ctx)
	admin, err := dialEtcdAdmin(ctx, m.wd, m.clientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	if err := m.s.promoteAndAwaitQuorum(ctx, admin, m.c); err != nil {
		t.Fatalf("%s promotion/quorum: %v", m.name, err)
	}
}

// join adds m as a learner through route, then brings it up `existing` with the
// returned initial cluster, promoting it through the same route.
func (m *itMember) join(t *testing.T, route itRoute) bootstrap.EtcdMemberResponse {
	t.Helper()
	resp := m.requestMember(t, route)
	m.cfg.Etcd.Promote = func(ctx context.Context) error {
		return bootstrap.PromoteEtcdMember(ctx, route.url, route.token, m.name, route.client)
	}
	m.bringUp(t)
	return resp
}

// requestMember calls the member route and adopts its --initial-cluster answer. A
// refusal is retried, as the joining daemon retries a transient answer: etcd refuses a member add until
// every voting member has been connected for its health interval (5 s), so a learner
// add right after a promotion is answered 503 "unhealthy cluster".
func (m *itMember) requestMember(t *testing.T, route itRoute) bootstrap.EtcdMemberResponse {
	t.Helper()
	deadline := time.Now().Add(itConverge)
	var resp bootstrap.EtcdMemberResponse
	for {
		var err error
		resp, err = bootstrap.RequestEtcdMember(t.Context(), route.url, route.token, m.name, m.routePeerURL(t), route.client)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("member route for %s: %v", m.name, err)
		}
		t.Logf("member route for %s refused, retrying: %v", m.name, err)
		time.Sleep(time.Second)
	}
	m.cfg.Etcd.InitialCluster = loopbackCluster(resp.InitialCluster)
	m.cfg.Etcd.Promote = nil
	return resp
}

// kill SIGKILLs the member's etcd and releases its supervisor.
func (m *itMember) kill(t *testing.T) {
	t.Helper()
	pid := m.c.cmd.Process.Pid
	_ = syscall.Kill(pid, syscall.SIGKILL)
	select {
	case <-m.c.exited:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s survived SIGKILL", m.name)
	}
	stopITSupervisor(m.s, pid)
}

// stop stops the member gracefully.
func (m *itMember) stop(t *testing.T) {
	t.Helper()
	pid := m.c.cmd.Process.Pid
	stopITSupervisor(m.s, pid)
	if pidAlive(pid) {
		t.Fatalf("%s outlived Stop", m.name)
	}
}

func stopITSupervisor(s *Supervised, pid int) {
	ctx, cancel := context.WithTimeout(context.Background(), StopBound+5*time.Second)
	defer cancel()
	_ = s.Stop(ctx)
	if !pidAlive(pid) {
		spawnedChildren.forget(pid)
	}
}

// itClient is a clientv3 client with a member's client.crt identity.
func itClient(t *testing.T, wd string, endpoints ...string) *clientv3.Client {
	t.Helper()
	tlsCfg, err := etcdClientTLS(wd)
	if err != nil {
		t.Fatal(err)
	}
	return itClientTLS(t, tlsCfg, endpoints...)
}

func itClientTLS(t *testing.T, tlsCfg *tls.Config, endpoints ...string) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{Endpoints: endpoints, TLS: tlsCfg, DialTimeout: 5 * time.Second, Logger: zap.NewNop()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// putEventually retries a write until it commits or itConverge passes (a leader
// election in progress refuses writes for a moment).
func putEventually(t *testing.T, cli *clientv3.Client, key, val string) {
	t.Helper()
	deadline := time.Now().Add(itConverge)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_, err := cli.Put(ctx, key, val)
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("put %s: %v", key, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// mustGet reads key with a linearizable read (quorum) and checks its value.
func mustGet(t *testing.T, cli *clientv3.Client, key, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	r, err := cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	if len(r.Kvs) != 1 || string(r.Kvs[0].Value) != want {
		t.Fatalf("get %s = %v, want %q", key, r.Kvs, want)
	}
}

// awaitMembers polls the member list until want reports true, failing with the last
// list after itConverge.
func awaitMembers(t *testing.T, admin *LocalEtcdAdmin, what string, want func([]EtcdMember) bool) []EtcdMember {
	t.Helper()
	deadline := time.Now().Add(itConverge)
	var last []EtcdMember
	for {
		ms, err := admin.MemberList(t.Context())
		if err == nil {
			last = ms
			if want(ms) {
				return ms
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("members never reached %s; last list %+v (err %v)", what, last, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// votingExactly reports n started voting members and no learner.
func votingExactly(n int) func([]EtcdMember) bool {
	return func(ms []EtcdMember) bool {
		if len(ms) != n {
			return false
		}
		for _, m := range ms {
			if m.IsLearner || m.Name == "" {
				return false
			}
		}
		return true
	}
}

func localAdmin(t *testing.T, m *itMember) *LocalEtcdAdmin {
	t.Helper()
	a, err := NewLocalEtcdAdmin(t.Context(), m.wd, m.cfg.KinePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// threeMembers forms a three-member cluster on loopback: a inits, b and c join as
// learners through a's member route and are promoted through it.
func threeMembers(t *testing.T) (a, b, c *itMember, h *certs.Hierarchy, peers itPeers, ports *itPorts) {
	t.Helper()
	ports, peers = &itPorts{}, itPeers{}
	a = newITMember(t, "etcd-a", "192.0.2.10", EtcdInit, nil, ports, peers)
	a.bringUp(t)
	h = a.hierarchy(t)
	route := newITRoute(t, a, h, peers)
	b = newITMember(t, "etcd-b", "192.0.2.11", EtcdJoin, h, ports, peers)
	b.join(t, route)
	c = newITMember(t, "etcd-c", "198.51.100.12", EtcdJoin, h, ports, peers)
	c.join(t, route)
	awaitMembers(t, localAdmin(t, a), "three voting members", votingExactly(3))
	return a, b, c, h, peers, ports
}

// rawTLSRefusal opens a TLS connection with cfg, speaks the HTTP/2 preface and reads
// once. A member that accepts the client answers with a SETTINGS frame (nil error);
// a member that refuses it fails the handshake or the first read with the TLS alert.
func rawTLSRefusal(addr string, cfg *tls.Config) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 9))
	return err
}

// TestEtcdChildBootsWithTLSAndServesKV boots one member from etcdArgs, serves KV to
// the etcd client identity, refuses every other client at the live listener, and
// saves a snapshot that opens as bbolt.
func TestEtcdChildBootsWithTLSAndServesKV(t *testing.T) {
	a := newITMember(t, "etcd-a", "192.0.2.10", EtcdInit, nil, &itPorts{}, itPeers{})
	a.bringUp(t)
	h := a.hierarchy(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.cfg.KinePort))

	cli := itClient(t, a.wd, a.clientURL())
	putEventually(t, cli, "/k3sm-it/kv", "served")
	mustGet(t, cli, "/k3sm-it/kv", "served")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(h.EtcdServer.CertPEM)
	good, err := etcdClientTLS(a.wd)
	if err != nil {
		t.Fatal(err)
	}
	nodeCert, nodeKey, err := h.Signing.IssueClient("system:node:x", []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	nodePair, err := tls.X509KeyPair(nodeCert, nodeKey)
	if err != nil {
		t.Fatal(err)
	}

	// The control: the same raw probe with client.crt is answered.
	h2 := func(c *tls.Config) *tls.Config { c = c.Clone(); c.NextProtos = []string{"h2"}; return c }
	if err := rawTLSRefusal(addr, h2(good)); err != nil {
		t.Fatalf("control: the raw probe with client.crt was refused: %v", err)
	}
	// The node cert is presented unconditionally: Go's client would otherwise drop a
	// certificate whose issuer is not among the CAs the server asks for, and the
	// refusal would be "no certificate", not the server rejecting this one.
	refused := map[string]struct {
		cfg  *tls.Config
		want string
	}{
		"no client certificate": {&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, "certificate required"},
		"a signing-CA system:node:x cert": {&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &nodePair, nil },
		}, "unknown certificate authority"},
	}
	for what, tc := range refused {
		cfg := tc.cfg
		err := rawTLSRefusal(addr, h2(cfg))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the listener did not refuse the handshake with %q (err %v)", what, tc.want, err)
		} else {
			t.Logf("%s: refused by the handshake: %v", what, err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		_, perr := itClientTLS(t, cfg, a.clientURL()).Put(ctx, "/k3sm-it/denied", what)
		cancel()
		if perr == nil {
			t.Errorf("%s: a write succeeded", what)
		}
	}

	// Plain TCP: the client listener speaks no plaintext gRPC.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	_, perr := itClientTLS(t, nil, "http://"+addr).Put(ctx, "/k3sm-it/denied", "plain")
	cancel()
	if perr == nil {
		t.Error("plain TCP: a write succeeded")
	} else {
		t.Logf("plain TCP: write refused: %v", perr)
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	buf := make([]byte, 9)
	if n, _ := conn.Read(buf); n == 9 && buf[3] == 0x4 {
		t.Error("plain TCP: the listener answered an HTTP/2 SETTINGS frame in plaintext")
	}
	_ = conn.Close()
	gctx, gcancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer gcancel()
	if r, err := cli.Get(gctx, "/k3sm-it/denied"); err != nil || len(r.Kvs) != 0 {
		t.Errorf("a refused client's write landed: %v (err %v)", r, err)
	}

	// An online snapshot through the production path, verified, and openable as bbolt
	// with the KV write in its key bucket.
	dst := filepath.Join(t.TempDir(), "etcd.snapshot")
	if err := SnapshotEtcd(t.Context(), a.wd, dst); err != nil {
		t.Fatalf("SnapshotEtcd: %v", err)
	}
	db, err := bolt.Open(dst, 0o400, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatalf("the snapshot does not open as bbolt: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("key"))
		if b == nil {
			return errors.New("no key bucket")
		}
		found := false
		_ = b.ForEach(func(_, v []byte) error {
			found = found || bytes.Contains(v, []byte("/k3sm-it/kv"))
			return nil
		})
		if !found {
			return errors.New("the KV write is not in the key bucket")
		}
		return nil
	}); err != nil {
		t.Errorf("snapshot content: %v", err)
	}
}

// TestEtcdThreeMemberLearnerJoinLoopback forms three members through the real member
// route (learner add, then promotion), kills the leader, and checks the two survivors
// elect a new one and keep committing writes.
func TestEtcdThreeMemberLearnerJoinLoopback(t *testing.T) {
	a, b, c, _, _, _ := threeMembers(t)
	members := []*itMember{a, b, c}

	cli := itClient(t, a.wd, a.clientURL(), b.clientURL(), c.clientURL())
	putEventually(t, cli, "/k3sm-it/before-kill", "3")

	admin := localAdmin(t, a)
	leaderID := awaitLeader(t, a)
	ms, err := admin.MemberList(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var victim *itMember
	for _, m := range ms {
		if m.ID == leaderID {
			for _, im := range members {
				if im.name == m.Name {
					victim = im
				}
			}
		}
	}
	if victim == nil {
		t.Fatalf("leader %x is not one of the three members %+v", leaderID, ms)
	}
	t.Logf("killing the leader %s", victim.name)
	victim.kill(t)

	var survivors []*itMember
	for _, m := range members {
		if m != victim {
			survivors = append(survivors, m)
		}
	}
	scli := itClient(t, survivors[0].wd, survivors[0].clientURL(), survivors[1].clientURL())
	putEventually(t, scli, "/k3sm-it/after-kill", "2")
	for _, m := range survivors {
		one := itClient(t, m.wd, m.clientURL())
		mustGet(t, one, "/k3sm-it/after-kill", "2")
		mustGet(t, one, "/k3sm-it/before-kill", "3")
	}
}

// TestEtcdRestartPromotesStrandedLearnerLoopback: a joiner whose learner started and
// was then stopped before any promotion restarts from its data dir as a learner (no
// member add, no initial cluster), and the production bring-up path promotes it: the
// cluster ends with two voting members and the restarted member serves the data.
func TestEtcdRestartPromotesStrandedLearnerLoopback(t *testing.T) {
	ports, peers := &itPorts{}, itPeers{}
	a := newITMember(t, "etcd-a", "192.0.2.10", EtcdInit, nil, ports, peers)
	a.bringUp(t)
	h := a.hierarchy(t)
	route := newITRoute(t, a, h, peers)
	putEventually(t, itClient(t, a.wd, a.clientURL()), "/k3sm-it/before-join", "a")

	b := newITMember(t, "etcd-b", "192.0.2.11", EtcdJoin, h, ports, peers)
	added := b.requestMember(t, route)
	startCtx, cancelStart := context.WithTimeout(t.Context(), itBringUp)
	defer cancelStart()
	b.start(t, startCtx)
	aadmin := localAdmin(t, a)
	awaitMembers(t, aadmin, "a started learner "+b.name, func(ms []EtcdMember) bool {
		for _, m := range ms {
			if m.ID == added.MemberID {
				return m.IsLearner && m.Name == b.name
			}
		}
		return false
	})

	// The crash window: stopped after its learner started, before any promotion.
	b.stop(t)
	if !EtcdMemberExists(b.wd) {
		t.Fatalf("%s has no member dir after its learner ran; the restart would not be a restart", b.name)
	}
	b.cfg.Etcd.Promote = func(ctx context.Context) error {
		return bootstrap.PromoteEtcdMember(ctx, route.url, route.token, b.name, route.client)
	}
	b.bringUp(t)

	ms := awaitMembers(t, aadmin, "two voting members", votingExactly(2))
	for _, m := range ms {
		if m.Name == b.name && m.ID != added.MemberID {
			t.Fatalf("the restart re-added %s as %x instead of promoting %x", b.name, m.ID, added.MemberID)
		}
	}
	bcli := itClient(t, b.wd, b.clientURL())
	mustGet(t, bcli, "/k3sm-it/before-join", "a")
	putEventually(t, bcli, "/k3sm-it/after-promote", "b")
}

// awaitLeader returns the leader the member reports, waiting for one.
func awaitLeader(t *testing.T, m *itMember) uint64 {
	t.Helper()
	admin, err := dialEtcdAdmin(t.Context(), m.wd, m.clientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	deadline := time.Now().Add(itConverge)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		st, err := admin.Status(ctx)
		cancel()
		if err == nil && st.Leader != 0 {
			return st.Leader
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s reports no leader: %v", m.name, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestEtcdResetAndRejoinLoopback: from three members kill two, reset the survivor,
// check it serves alone with its data, then rejoin a wiped member as a fresh learner.
//
// After --force-new-cluster the old members are gone from the list, so the first
// rejoin request takes the route's plain learner-add path. The stale-member path
// (a STARTED member under the joiner's name, whose data dir was wiped) is then
// produced for real: the rejoined learner is started, killed before promotion and
// wiped again, and its next request must remove the started learner and add a new
// one. A learner does not count toward quorum, so the single survivor can commit
// that removal.
func TestEtcdResetAndRejoinLoopback(t *testing.T) {
	a, b, c, h, peers, _ := threeMembers(t)
	cli := itClient(t, b.wd, b.clientURL())
	putEventually(t, cli, "/k3sm-it/before-reset", "kept")

	a.kill(t)
	c.kill(t)
	b.stop(t)

	resetCtx, cancel := context.WithTimeout(t.Context(), clusterResetTimeout+time.Minute)
	defer cancel()
	if err := clusterReset(resetCtx, b.cfg, defaultEtcdSeams()); err != nil {
		t.Fatalf("cluster reset of %s: %v", b.name, err)
	}

	b.bringUp(t)
	badmin := localAdmin(t, b)
	ms := awaitMembers(t, badmin, "exactly the survivor", votingExactly(1))
	if ms[0].Name != b.name {
		t.Fatalf("after the reset the only member is %q, want %q", ms[0].Name, b.name)
	}
	mustGet(t, itClient(t, b.wd, b.clientURL()), "/k3sm-it/before-reset", "kept")
	putEventually(t, itClient(t, b.wd, b.clientURL()), "/k3sm-it/after-reset", "alone")

	route := newITRoute(t, b, h, peers)

	// Rejoin c with a wiped data dir: the reset removed its old identity, so this is
	// a plain learner add.
	c.wipe(t)
	first := c.requestMember(t, route)
	startCtx, cancelStart := context.WithTimeout(t.Context(), itBringUp)
	defer cancelStart()
	c.start(t, startCtx)
	awaitMembers(t, badmin, "a started learner "+c.name, func(ms []EtcdMember) bool {
		for _, m := range ms {
			if m.ID == first.MemberID {
				return m.IsLearner && m.Name == c.name
			}
		}
		return false
	})

	// The stale-member path: the started learner dies and its data dir is wiped.
	c.kill(t)
	c.wipe(t)
	before, err := route.joiner.MemberList(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !hasMember(before, first.MemberID, c.name) {
		t.Fatalf("the started learner %x (%s) is not listed before the stale rejoin: %+v", first.MemberID, c.name, before)
	}
	second := c.join(t, route)
	if second.MemberID == first.MemberID {
		t.Fatalf("the stale rejoin reused member %x instead of replacing it", first.MemberID)
	}

	ms = awaitMembers(t, badmin, "two voting members", votingExactly(2))
	for _, m := range ms {
		if m.ID == first.MemberID {
			t.Fatalf("the stale learner %x is still a member: %+v", first.MemberID, ms)
		}
	}
	ccli := itClient(t, c.wd, c.clientURL())
	mustGet(t, ccli, "/k3sm-it/before-reset", "kept")
	mustGet(t, ccli, "/k3sm-it/after-reset", "alone")
	putEventually(t, ccli, "/k3sm-it/after-rejoin", "two")
}

// wipe deletes the member's etcd data dir and re-provisions it (an operator's
// `rm -rf <work-dir>/etcd` before a rejoin; the PKI stays).
func (m *itMember) wipe(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(EtcdDataDir(m.wd)); err != nil {
		t.Fatal(err)
	}
	m.provision(t)
}

func hasMember(ms []bootstrap.EtcdMember, id uint64, name string) bool {
	for _, m := range ms {
		if m.ID == id && m.Name == name {
			return true
		}
	}
	return false
}
