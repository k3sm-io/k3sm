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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
)

// The embedded-etcd HA join, from both ends.
//
// The JOINING server (--server-join --server <existing server's LAN address>) runs,
// in order and before its executor starts: the CA-bundle import (importServerCABundle,
// which also writes the etcd CAs), then — on a first boot only — the member route on
// the existing server, which adds it as an etcd LEARNER and answers with the
// --initial-cluster set its member must start with. The executor then starts the
// member `existing` and promotes it through the same existing server — on EVERY boot
// whose member still reports itself a learner, so a joiner restarted before its
// promotion landed is promoted on the restart instead of stranded. Both calls ride
// the underlay: the existing server's bootstrap listener serves every interface, and
// the mesh is not on this path at all (it comes up afterwards, through this server's
// own apiserver, exactly as on any server).
//
// The EXISTING server's side is localMemberJoiner: the bootstrap package's member
// routes driving this server's own etcd member over its loopback client.

// memberRoute adds this server as an etcd learner through an existing server and
// returns the route's answer; promoteRoute asks it to promote the learner. Both are
// seams so the join step is testable with no network and no etcd.
type (
	memberRoute  func(ctx context.Context, req bootstrap.EtcdMemberRequest) (bootstrap.EtcdMemberResponse, error)
	promoteRoute func(ctx context.Context, name string) error
)

// memberIdentity is what a joining server presents on the member route beside its
// name and peer URL: its own node-password, which binds the name to this Mac, and
// — on the mesh path — the claim on its mesh range, which the existing server
// reserves before it adds the member.
type memberIdentity struct {
	nodePassword string
	claim        *bootstrap.MeshClaim
}

// errEtcdMemberRoute marks a failure of the member route step, which is the existing
// server's answer (or this server's configuration), never a crash of this server's
// control plane. A TRANSIENT answer never leaves the step (it is retried in-process),
// so what reaches the caller is either a PERMANENT refusal, which also wraps
// errEtcdMemberRoutePermanent, or the step's ctx ending (a shutdown, never counted).
var errEtcdMemberRoute = errors.New("etcd member route")

// errEtcdMemberRoutePermanent marks a member-route failure no retry can heal: the
// existing server refused the request itself (a 400/401/403/409 — a bad or foreign
// token, a refused name or peer URL), the token does not parse, the server's CA does
// not match the token's pin (the wrong cluster), or this server's own configuration
// cannot form the request. The daemon records it as a PERMANENT bring-up failure, so
// the breaker parks on the first one instead of launchd re-asking forever.
var errEtcdMemberRoutePermanent = errors.New("permanent")

// etcdMemberRouteRetry is the in-process retry cadence of a transient member-route
// answer.
const etcdMemberRouteRetry = 5 * time.Second

// etcdMemberRouteComponent is the component a permanent member-route refusal is
// recorded under on the crash-loop breaker.
const etcdMemberRouteComponent = "etcd-member-route"

// etcdMemberRouteRemedy is the fix a permanent member-route refusal names.
// The status row appends the clear-crashloop step itself.
const etcdMemberRouteRemedy = "the existing server refused to add this server's etcd member: re-install this server with --server naming a server of THIS cluster, --token set to that cluster's server token, and a valid node name and --node-ip"

// etcdMemberRouteMeshRemedy is the fix when the refusal was this server's mesh
// range (bootstrap.RefusalMeshRangeClaimed / RefusalMeshClaimRefused). Nothing was
// added to the cluster: the existing server refuses before its member add.
const etcdMemberRouteMeshRemedy = "the existing server refused this server's mesh range, so no etcd member was added: choose a free --mesh-ip (the first address of an unused /24 in 100.64.0.0/10) and re-install this server, or remove the stale MeshPeer and its claim on the existing server (`kubectl delete meshpeer <holder>`, `kubectl -n kube-system delete lease <claim>`), then clear the crash-loop record and restart this server"

// etcdMemberRouteUnacknowledgedRemedy is the fix when the existing server added the
// member without acknowledging this server's mesh claim: it predates claims, so it
// reserved nothing.
const etcdMemberRouteUnacknowledgedRemedy = "the existing server did not acknowledge this server's mesh claim, so it runs a k3sm that predates server mesh ranges: upgrade every existing server first, then clear the crash-loop record and restart this server. The unstarted learner it added holds no vote; the next member request for this name removes it"

// errMeshClaimUnacknowledged marks a member route that answered without
// acknowledging the mesh claim this server sent.
var errMeshClaimUnacknowledged = errors.New("the existing server did not acknowledge this server's mesh claim")

// etcdMemberRouteRemedyFor is the remedy a permanent member-route failure names,
// chosen by the refusal reason the route set (never by its message text).
func etcdMemberRouteRemedyFor(err error) string {
	if errors.Is(err, errMeshClaimUnacknowledged) {
		return etcdMemberRouteUnacknowledgedRemedy
	}
	if re, ok := errors.AsType[*bootstrap.ServerRouteError](err); ok {
		switch re.Reason {
		case bootstrap.RefusalMeshRangeClaimed, bootstrap.RefusalMeshClaimRefused, bootstrap.RefusalMeshClaimInvalid:
			return etcdMemberRouteMeshRemedy
		}
	}
	return etcdMemberRouteRemedy
}

// serverEtcdJoin is the joining server's member step.
type serverEtcdJoin struct {
	// memberExists reports a restart: the work dir already holds an etcd member, so
	// it starts from its own data dir and is never re-added.
	memberExists func() bool
	member       memberRoute
	// identity reads this server's node-password and, on the mesh path, builds its
	// mesh claim for the etcd peer IP the route is asked with. Nil presents
	// neither (a server with no work dir to read them from).
	identity func(peerIP string) (memberIdentity, error)
	// wait sleeps between transient member-route answers; a seam so the retry is
	// testable without real time. Nil is a real timer.
	wait func(ctx context.Context, d time.Duration) error
	// promote is nil when this boot has no existing server to ask (no --server or
	// no --token), which only a restart can survive: the executor then logs the
	// stranded-learner remedy if its member is still a learner.
	promote promoteRoute
}

// newServerEtcdJoin wires the member and promote routes against the existing
// server's bootstrap listener (https://<--server>:9345), over the CA-pinned TLS the
// server token carries. It returns nil when this is not a --server-join.
func newServerEtcdJoin(opts serverOptions) *serverEtcdJoin {
	if !opts.serverJoin {
		return nil
	}
	base := "https://" + net.JoinHostPort(opts.joinServer, strconv.Itoa(bootstrapPort))
	token := opts.token
	j := &serverEtcdJoin{
		memberExists: func() bool { return executor.EtcdMemberExists(opts.workDir) },
		member: func(ctx context.Context, req bootstrap.EtcdMemberRequest) (bootstrap.EtcdMemberResponse, error) {
			return bootstrap.RequestEtcdMember(ctx, base, token, req, nil)
		},
		identity: func(peerIP string) (memberIdentity, error) {
			return serverMemberIdentity(opts.workDir, opts.meshIP, peerIP)
		},
	}
	if opts.joinServer != "" && token != "" {
		j.promote = func(ctx context.Context, name string) error {
			return bootstrap.PromoteEtcdMember(ctx, base, token, name, nil)
		}
	}
	return j
}

// serverMemberIdentity reads (minting on first use) this server's persisted
// node-password and wireguard key from workDir — the same files its own mesh enrol
// reads later — and, when meshIP is set, builds the claim on the range it names.
// The claim's endpoint is the etcd peer IP: the one address this server has already
// declared to the existing server, which is the only endpoint host the route
// accepts. Only the PUBLIC key leaves this function.
func serverMemberIdentity(workDir, meshIP, peerIP string) (memberIdentity, error) {
	pw, err := loadOrCreateServerNodePassword(workDir)
	if err != nil {
		return memberIdentity{}, err
	}
	id := memberIdentity{nodePassword: pw}
	if meshIP == "" {
		return id, nil
	}
	_, pub, err := loadOrCreateServerMeshKey(workDir)
	if err != nil {
		return memberIdentity{}, err
	}
	id.claim = &bootstrap.MeshClaim{
		MeshIP:    meshIP,
		PublicKey: pub,
		Endpoint:  net.JoinHostPort(peerIP, strconv.Itoa(serverMeshListenPort)),
	}
	return id, nil
}

// joinEtcdMember returns the Config the executor starts with. On a joining server's
// FIRST boot it first asks the existing server to add this member as a learner, and
// the returned Config carries the route's --initial-cluster set. On EVERY boot that
// can reach an existing server it carries a Promote that asks that server to promote
// this member: the executor calls it only while its member reports itself a learner,
// which on a restart is the joiner that died between its learner's first start and
// the promotion. A restart (the member dir exists) skips the member route entirely.
// j nil is every other server, whose Config is returned unchanged. The caller's
// EtcdConfig is never mutated.
func joinEtcdMember(ctx context.Context, j *serverEtcdJoin, joinServer string, cfg executor.Config, logger *slog.Logger) (executor.Config, error) {
	if j == nil || cfg.Etcd == nil {
		return cfg, nil
	}
	if j.memberExists() {
		logger.Info("HA server-join: this server's etcd member already exists; starting it from its data dir with no member add",
			"member", cfg.Etcd.Name, "can-promote", j.promote != nil)
		return withPromote(cfg, j.promote), nil
	}
	if joinServer == "" {
		return cfg, fmt.Errorf("%w (%w): the first start of a --server-join member needs --server (the existing server's address) to add it to the cluster", errEtcdMemberRoute, errEtcdMemberRoutePermanent)
	}
	peerURL, err := joinerPeerURL(*cfg.Etcd)
	if err != nil {
		return cfg, fmt.Errorf("%w (%w): %w", errEtcdMemberRoute, errEtcdMemberRoutePermanent, err)
	}
	name := cfg.Etcd.Name
	req := bootstrap.EtcdMemberRequest{Name: name, PeerURL: peerURL}
	if j.identity != nil {
		id, err := j.identity(cfg.Etcd.PeerIP)
		if err != nil {
			return cfg, fmt.Errorf("%w (%w): read this server's join identity: %w", errEtcdMemberRoute, errEtcdMemberRoutePermanent, err)
		}
		req.NodePassword, req.MeshClaim = id.nodePassword, id.claim
	}
	logger.Info("HA server-join: asking the existing server to add this server as an etcd learner",
		"server", joinServer, "member", name, "peer-url", peerURL, "mesh-claim", req.MeshClaim != nil)
	resp, err := requestMemberUntilAnswered(ctx, j, joinServer, req, logger)
	if err != nil {
		return cfg, err
	}
	// THE CAPABILITY HANDSHAKE. A server that predates mesh claims ignores the
	// claim and adds the member anyway, so its silence is not consent: this
	// server's range was never reserved, and starting the member would make a
	// cluster member whose pods could collide with another node's. The learner it
	// added holds no vote, so refusing here costs the existing server nothing.
	if req.MeshClaim != nil && resp.MeshClaim != bootstrap.MeshClaimReserved {
		return cfg, fmt.Errorf("%w (%w): %w (it answered meshClaim=%q)", errEtcdMemberRoute, errEtcdMemberRoutePermanent, errMeshClaimUnacknowledged, resp.MeshClaim)
	}
	logger.Info("HA server-join: added as an etcd learner", "member", name,
		"member-id", strconv.FormatUint(resp.MemberID, 16), "initial-cluster", resp.InitialCluster)
	etcd := *cfg.Etcd
	etcd.InitialCluster = resp.InitialCluster
	cfg.Etcd = &etcd
	return withPromote(cfg, j.promote), nil
}

// requestMemberUntilAnswered calls the member route until it answers. A TRANSIENT
// failure — a network error, a 503 (an unhealthy cluster, which etcd reports for a
// few seconds after any membership change), a 404, a 429 — is logged and retried
// every etcdMemberRouteRetry with no expiry: the existing server being briefly
// unreachable is a wait, and it is never counted by the crash-loop breaker. A
// PERMANENT refusal (bootstrap.IsPermanentServerRouteFailure, classified by status
// code and sentinel, never by message) returns at once, wrapping
// errEtcdMemberRoutePermanent. It ends early only on ctx.
func requestMemberUntilAnswered(ctx context.Context, j *serverEtcdJoin, joinServer string, req bootstrap.EtcdMemberRequest, logger *slog.Logger) (bootstrap.EtcdMemberResponse, error) {
	wait := j.wait
	if wait == nil {
		wait = sleepCtx
	}
	for attempt := 1; ; attempt++ {
		resp, err := j.member(ctx, req)
		if err == nil {
			return resp, nil
		}
		if bootstrap.IsPermanentServerRouteFailure(err) {
			return resp, fmt.Errorf("%w (%w): add this server as an etcd learner through %s: %w",
				errEtcdMemberRoute, errEtcdMemberRoutePermanent, joinServer, err)
		}
		if ctx.Err() != nil {
			return resp, fmt.Errorf("%w: add this server as an etcd learner through %s: %w", errEtcdMemberRoute, joinServer, ctx.Err())
		}
		logger.Info("HA server-join: the existing server did not add this server's etcd learner yet; retrying",
			"server", joinServer, "member", req.Name, "attempt", attempt, "retry-in", etcdMemberRouteRetry, "err", err)
		if werr := wait(ctx, etcdMemberRouteRetry); werr != nil {
			return resp, fmt.Errorf("%w: add this server as an etcd learner through %s: %w", errEtcdMemberRoute, joinServer, werr)
		}
	}
}

// sleepCtx waits d, ending early (with ctx's error) when ctx does.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// withPromote returns cfg with its EtcdConfig copied and Promote bound to promote for
// this member's name; a nil promote leaves Promote nil. cfg's own EtcdConfig is never
// mutated.
func withPromote(cfg executor.Config, promote promoteRoute) executor.Config {
	if promote == nil {
		return cfg
	}
	etcd := *cfg.Etcd
	name := etcd.Name
	etcd.Promote = func(ctx context.Context) error { return promote(ctx, name) }
	cfg.Etcd = &etcd
	return cfg
}

// joinerPeerURL renders this member's peer URL, https://<node IP>:<peer port>, in
// the one canonical spelling the member route accepts.
func joinerPeerURL(e executor.EtcdConfig) (string, error) {
	addr, err := netip.ParseAddr(e.PeerIP)
	if err != nil {
		return "", fmt.Errorf("etcd peer IP %q: %w", e.PeerIP, err)
	}
	port := e.PeerPort
	if port == 0 {
		port = executor.DefaultEtcdPeerPort
	}
	return bootstrap.CanonicalPeerURL("https://" + net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(port)))
}

// localMemberJoiner is the existing server's side: bootstrap.MemberJoiner over this
// server's own etcd member, reached on loopback with its etcd client identity. It is
// a thin adapter because the executor's member type is its own and pkg/executor does
// not import pkg/bootstrap.
type localMemberJoiner struct {
	admin localEtcdMembers
}

// localEtcdMembers is the part of executor.LocalEtcdAdmin the adapter uses.
type localEtcdMembers interface {
	MemberList(ctx context.Context) ([]executor.EtcdMember, error)
	MemberAddAsLearner(ctx context.Context, peerURL string) (executor.EtcdMember, []executor.EtcdMember, error)
	MemberPromote(ctx context.Context, id uint64) error
	MemberRemove(ctx context.Context, id uint64) error
}

func (j localMemberJoiner) MemberList(ctx context.Context) ([]bootstrap.EtcdMember, error) {
	ms, err := j.admin.MemberList(ctx)
	if err != nil {
		return nil, err
	}
	return toBootstrapMembers(ms), nil
}

func (j localMemberJoiner) MemberAddAsLearner(ctx context.Context, peerURL string) (bootstrap.EtcdMember, []bootstrap.EtcdMember, error) {
	added, ms, err := j.admin.MemberAddAsLearner(ctx, peerURL)
	if err != nil {
		return bootstrap.EtcdMember{}, nil, err
	}
	return bootstrap.EtcdMember(added), toBootstrapMembers(ms), nil
}

func (j localMemberJoiner) MemberPromote(ctx context.Context, id uint64) error {
	return j.admin.MemberPromote(ctx, id)
}

func (j localMemberJoiner) MemberRemove(ctx context.Context, id uint64) error {
	return j.admin.MemberRemove(ctx, id)
}

func toBootstrapMembers(ms []executor.EtcdMember) []bootstrap.EtcdMember {
	out := make([]bootstrap.EtcdMember, 0, len(ms))
	for _, m := range ms {
		out = append(out, bootstrap.EtcdMember(m))
	}
	return out
}
