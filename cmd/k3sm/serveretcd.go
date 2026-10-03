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
// member `existing` and promotes it through the same existing server. Both calls ride
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
	memberRoute  func(ctx context.Context, name, peerURL string) (bootstrap.EtcdMemberResponse, error)
	promoteRoute func(ctx context.Context, name string) error
)

// errEtcdMemberRoute marks a failure of the member route itself, which is the
// existing server's answer (or its absence), never a crash of this server's control
// plane: the caller does not count it toward the crash-loop breaker.
var errEtcdMemberRoute = errors.New("etcd member route")

// serverEtcdJoin is the joining server's member step.
type serverEtcdJoin struct {
	// memberExists reports a restart: the work dir already holds an etcd member, so
	// it starts from its own data dir and is never re-added.
	memberExists func() bool
	member       memberRoute
	promote      promoteRoute
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
	return &serverEtcdJoin{
		memberExists: func() bool { return executor.EtcdMemberExists(opts.workDir) },
		member: func(ctx context.Context, name, peerURL string) (bootstrap.EtcdMemberResponse, error) {
			return bootstrap.RequestEtcdMember(ctx, base, token, name, peerURL, nil)
		},
		promote: func(ctx context.Context, name string) error {
			return bootstrap.PromoteEtcdMember(ctx, base, token, name, nil)
		},
	}
}

// joinEtcdMember returns the Config the executor starts with. On a joining server's
// FIRST boot it first asks the existing server to add this member as a learner, and
// the returned Config carries the route's --initial-cluster set and a Promote that
// asks the same server to promote it. A restart (the member dir exists) skips the
// route entirely. j nil is every other server, whose Config is returned unchanged.
// The caller's EtcdConfig is never mutated.
func joinEtcdMember(ctx context.Context, j *serverEtcdJoin, joinServer string, cfg executor.Config, logger *slog.Logger) (executor.Config, error) {
	if j == nil || cfg.Etcd == nil {
		return cfg, nil
	}
	if j.memberExists() {
		logger.Info("HA server-join: this server's etcd member already exists; starting it from its data dir with no member add",
			"member", cfg.Etcd.Name)
		return cfg, nil
	}
	if joinServer == "" {
		return cfg, fmt.Errorf("%w: the first start of a --server-join member needs --server (the existing server's address) to add it to the cluster", errEtcdMemberRoute)
	}
	peerURL, err := joinerPeerURL(*cfg.Etcd)
	if err != nil {
		return cfg, fmt.Errorf("%w: %w", errEtcdMemberRoute, err)
	}
	name := cfg.Etcd.Name
	logger.Info("HA server-join: asking the existing server to add this server as an etcd learner",
		"server", joinServer, "member", name, "peer-url", peerURL)
	resp, err := j.member(ctx, name, peerURL)
	if err != nil {
		return cfg, fmt.Errorf("%w: add this server as an etcd learner through %s: %w", errEtcdMemberRoute, joinServer, err)
	}
	logger.Info("HA server-join: added as an etcd learner", "member", name,
		"member-id", strconv.FormatUint(resp.MemberID, 16), "initial-cluster", resp.InitialCluster)
	etcd := *cfg.Etcd
	etcd.InitialCluster = resp.InitialCluster
	promote := j.promote
	etcd.Promote = func(ctx context.Context) error { return promote(ctx, name) }
	cfg.Etcd = &etcd
	return cfg, nil
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
