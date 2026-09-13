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
	"net"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// meshRefreshInterval is how often a node re-derives the address it advertises as
// its wireguard endpoint. It equals darwin-net's meshResyncPeriod (30s), so a
// published change is picked up by the peers' next full resync rather than
// sitting a fraction of a period ahead of it; and with the two-tick debounce
// below, a genuine move is published about a minute after it happens.
const meshRefreshInterval = 30 * time.Second

// meshEndpointRefresher republishes this node's wireguard endpoint when the
// address it is reachable at changes.
//
// The endpoint is derived ONCE, at join (a worker) or at self-enroll (the
// server), and then never again — so a DHCP lease change, a move between Wi-Fi
// and Ethernet, or a docked-to-undocked transition leaves every peer's MeshPeer
// naming an address this Mac no longer owns. Wireguard's roaming hides that for
// as long as this node keeps sending: a peer learns the new source address from
// an authenticated packet. It stops hiding it at the next FULL RESYNC on the peer
// (device Up, netd or server restart, a failed IpcSet), which re-programs the
// stale endpoint from the CR and blackholes the node until its next keepalive.
//
// Both roles run one. The seams are the two things that differ between them:
//
//   - derive re-runs the SAME derivation the initial publish used — a worker
//     re-probes the control plane so the kernel's own route lookup answers
//     "which of this Mac's addresses reaches the server", the control-plane node
//     re-scans its underlay interfaces;
//   - publish is the write — the node-certificate-authenticated POST for a
//     worker, an in-process enroller call for the server.
//
// Locking: none. Run is the single reader and writer of every field below, and
// the seams are called from it.
type meshEndpointRefresher struct {
	derive   func(ctx context.Context) (string, error)
	publish  func(ctx context.Context, endpoint string) error
	interval time.Duration
	log      *slog.Logger

	// tick replaces the internal ticker in tests. Nil in production.
	tick <-chan time.Time

	// published is the value peers currently hold: the join-time endpoint at
	// start, and every value this loop has successfully written since. A
	// derivation equal to it is not a change and produces no RPC and no log.
	published string
	// candidate is a differing value seen ONCE and awaiting confirmation. The
	// debounce is what keeps an interface flap from stomping a good endpoint:
	// during a Wi-Fi transition a single scan can return the address of an
	// interface that is about to go away, and publishing it would point every
	// peer at a dead address for a full resync period. Two consecutive identical
	// derivations cost one extra interval and cannot be produced by a single
	// transient sample.
	candidate string
	// announced is the candidate already named in the "mesh endpoint changed"
	// log line, so a publish that fails and is retried does not repeat it.
	announced string
}

// Run drives the refresh loop until ctx is done, returning ctx.Err().
//
// Unlike the node-status loop this pattern is borrowed from, it does NOT publish
// once before the first tick: the value it starts with is precisely the value the
// join or self-enroll just wrote, so an immediate publish would be a redundant
// write on every node start. Every failure is logged and the loop continues —
// the next tick re-derives and retries, and a permanently failing refresh is
// already visible as a MeshPeer whose endpoint goes stale.
func (r *meshEndpointRefresher) Run(ctx context.Context) error {
	interval := r.interval
	if interval <= 0 {
		interval = meshRefreshInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	ticks := r.tick
	if ticks == nil {
		ticks = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			r.tickOnce(ctx)
		}
	}
}

// tickOnce runs one derive → debounce → publish cycle. It is the whole decision,
// and it is deliberately the only place any of the three fields moves.
func (r *meshEndpointRefresher) tickOnce(ctx context.Context) {
	endpoint, err := r.derive(ctx)
	if err != nil {
		// The last published value stays published, and a pending candidate stays
		// pending. A node that cannot currently tell which of its addresses
		// reaches the cluster knows strictly less than the value peers already
		// hold, so withdrawing or replacing it would trade a possibly-stale
		// endpoint for a certainly-wrong one; and a failed probe is not evidence
		// against a sighting it never contradicted.
		r.log.Warn("could not re-derive this node's wireguard endpoint; keeping the published one",
			"published", r.published, "err", err)
		return
	}
	if endpoint == r.published {
		r.candidate = ""
		return
	}
	if endpoint != r.candidate {
		r.candidate = endpoint
		return
	}
	if r.announced != endpoint {
		r.log.Info("mesh endpoint changed", "old", r.published, "new", endpoint)
		r.announced = endpoint
	}
	if err := r.publish(ctx, endpoint); err != nil {
		if errors.Is(err, bootstrap.ErrNoMeshPeer) {
			r.log.Warn("the cluster has no MeshPeer for this node; rejoin it (`k3sm agent --server ... --token ...`)",
				"endpoint", endpoint, "err", err)
			return
		}
		r.log.Warn("could not publish this node's new wireguard endpoint; retrying on the next interval",
			"endpoint", endpoint, "err", err)
		return
	}
	r.published = endpoint
	r.candidate = ""
}

// newWorkerEndpointRefresher builds the joined worker's refresher: it re-probes
// the control plane's bootstrap port to learn which local address reaches it, and
// publishes over the node-certificate-authenticated refresh verb.
//
// The publishing client is built ONCE, here, and presents the node's own
// system:node keypair — the credential that lasts as long as the node. The join
// TOKEN is not retained: it is TTL-bounded (24 h by default), so a refresh gated
// on it would stop working after a day and silently restore the staleness this
// exists to remove. The server pin the client verifies is re-derived from the
// cluster CA the join returned, which is public material the node already trusts.
func newWorkerEndpointRefresher(opts agentOptions, res *bootstrap.JoinResult, joinHost, initialEndpoint string, logger *slog.Logger) (*meshEndpointRefresher, error) {
	client, err := bootstrap.NodeIdentityClient(res.ClusterCAPEM, res.NodeClientCertPEM, res.NodeClientKeyPEM)
	if err != nil {
		return nil, err
	}
	serverURL := "https://" + joinHost
	return &meshEndpointRefresher{
		derive: func(ctx context.Context) (string, error) {
			// A FRESH dialer each time. Reusing the join's dialer would keep its
			// captured address when a probe fails, which is exactly the stale
			// value this loop exists to replace; a fresh one reports nothing and
			// underlayMeshEndpoint falls back to its interface scan.
			d := &localAddrDialer{dialer: net.Dialer{Timeout: 5 * time.Second}}
			d.probe(ctx, joinHost)
			return underlayMeshEndpoint(d.localIP(), opts.nodeIP, opts.meshPort)
		},
		publish: func(ctx context.Context, endpoint string) error {
			return bootstrap.RefreshMeshEndpoint(ctx, client, serverURL, opts.nodeName, endpoint)
		},
		interval:  meshRefreshInterval,
		log:       logger,
		published: initialEndpoint,
		announced: initialEndpoint,
	}, nil
}

// newServerEndpointRefresher builds the control-plane node's refresher. It writes
// through the same locked enroller the join RPC uses (no HTTP, no certificate —
// this process IS the supervisor), and re-derives with serverMeshEndpoint, whose
// tunnel-excluding scan is what keeps a periodic re-derivation from picking this
// node's own mesh utun.
func newServerEndpointRefresher(e *meshEnroller, opts serverOptions, initialEndpoint string, logger *slog.Logger) *meshEndpointRefresher {
	return &meshEndpointRefresher{
		derive: func(context.Context) (string, error) {
			return serverMeshEndpoint(opts.nodeIP, opts.meshIP, serverMeshListenPort)
		},
		publish: func(ctx context.Context, endpoint string) error {
			return e.RefreshEndpoint(ctx, opts.nodeName, endpoint)
		},
		interval:  meshRefreshInterval,
		log:       logger,
		published: initialEndpoint,
		announced: initialEndpoint,
	}
}
