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

package registrysvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"
)

// The MESH/GUEST RELAY: a TCP forwarder that accepts on an address other
// machines (or this Mac's own vm guests) can reach and hands every connection to
// the registry's loopback listener.
//
// WHY A RELAY AND NOT A SECOND BIND. The ingest registry binds 127.0.0.1 and New
// refuses anything else, because that single fact is what makes anonymous pull
// plus plaintext push safe (see LoopbackAddress). Widening the bind would trade
// that property for reachability. A relay buys the reachability without touching
// the property: the registry still binds loopback only, and the ONE address that
// is exposed, to the ONE set of peers named below, is a decision made here rather
// than a configuration the registry accepts.
//
// WHAT REACHABILITY BUYS, AND WHAT IT DOES NOT. Pull inside the mesh is
// anonymous, exactly as it is on loopback — that is the point: a peer node's
// puller falls back to this node when its own ingest registry misses a
// node-relative reference. PUSH is unchanged and still needs the per-boot
// credential, which lives in a 0600 file on the pushing node and is never
// distributed; the relay carries the bytes and enforces nothing, because the
// htpasswd gate is zot's and sits behind it. So a peer can read what this cluster
// runs and cannot plant an image it will run.
//
// THE TWO ADDRESSES, and why they are the only two:
//
//   - THE MESH ADDRESS — this node's wireguard address, inside
//     podnet.ClusterPodCIDR. Traffic to it is already encrypted and
//     authenticated by wireguard, so plaintext HTTP over it is re-using a secure
//     transport rather than forgoing one, and only enrolled peers can address it.
//   - THE VM NAT GATEWAY — the host side of the segment macOS's vmnet hands this
//     node's Linux guests, derived from the NAT subnet. A guest reaches a host
//     listener bound on the gateway address or the wildcard, and NEVER a
//     loopback-bound one (measured; hack/spike/m11/findings-s5.md criterion 1a),
//     so this bind is what lets an in-cluster build pod push to the node's own
//     registry. The wildcard would serve the same guests and every other network
//     this Mac is on, which is precisely the widening the loopback invariant
//     exists to prevent.
//
// Anything else is refused by NewRelay rather than documented as a hazard.
const (
	// relayBindAttempts / relayBindBackoff bound one address's bind+serve retry.
	// The failures worth retrying here are transient by nature (an interface
	// mid-configuration, a port a dying process still holds) and the budget spans
	// the relay's whole life rather than resetting on a successful serve — the
	// same contract, and the same reasoning, as the node's runtimed control
	// socket: resetting turns a listener that binds and immediately fails into an
	// unbounded hot loop.
	relayBindAttempts = 5
	relayBindBackoff  = 2 * time.Second
	// relayDialTimeout bounds the dial to the loopback registry. It is short
	// because the target is on this host: a loopback dial that has not completed
	// in a second is not going to.
	relayDialTimeout = 1 * time.Second
)

// Relay refusals. They are sentinels because the callers respond differently: a
// node with no relayable address is the ordinary single-node posture, while a
// bind this relay will never do is a configuration error someone must fix.
var (
	// ErrNoRelayAddress: neither a mesh address nor a vm NAT segment was
	// configured, so there is no address to relay on and no relay to start.
	ErrNoRelayAddress = errors.New("no mesh or vm-gateway address to relay the ingest registry on")
	// ErrNonRelayableBind: an address was configured that is not one of the two
	// this relay exposes.
	ErrNonRelayableBind = errors.New("the ingest registry relay binds a mesh or vm-gateway address only")
)

// RelayConfig configures a Relay.
type RelayConfig struct {
	// Port is the registry's loopback port. It is BOTH the port every relay listener
	// binds and the port it forwards to, deliberately: a peer that read this
	// node's advertisement dials the port the advertisement named, and the
	// advertisement names the registry's own port.
	Port int
	// MeshIP is this node's wireguard mesh address. Empty is the single-node
	// posture and contributes no listener.
	MeshIP string
	// VMNetSubnet is the NAT segment macOS's vmnet hands this node's guests, in
	// CIDR form (netserve.DefaultVMNetSubnet). Empty means this node hosts no
	// guests and contributes no listener. The GATEWAY — the first host of the
	// segment — is what gets bound; the subnet is what the caller already knows.
	VMNetSubnet string
	// Logger receives bind and forward events. nil means slog.Default.
	Logger *slog.Logger
}

// Relay forwards connections from the node's reachable addresses to the ingest
// registry's loopback listener.
//
// The zero value is not usable — construct one with NewRelay, which is where the
// bind discipline is enforced.
type Relay struct {
	port  int
	binds []netip.Addr
	log   *slog.Logger

	// listen and dial are seams so the accept/forward mechanics are testable over
	// a loopback pair, with no mesh and no guest. Production wires net.Listen and
	// a net.Dialer.
	listen func(addr string) (net.Listener, error)
	dial   func(ctx context.Context, addr string) (net.Conn, error)
}

// NewRelay validates cfg and returns a Relay.
//
// It REFUSES any address that is not one of the two named above, with
// ErrNonRelayableBind — including a loopback address (the registry already binds
// it, and relaying loopback to loopback exposes nothing new while looking like it
// does) and the wildcard (which is the widening this whole design exists to
// avoid). A configuration with neither address is ErrNoRelayAddress: there is
// nothing to relay, which is the ordinary single-node, no-guests posture and not
// a failure.
func NewRelay(cfg RelayConfig) (*Relay, error) {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("relay the ingest registry: port %d is out of range 1-65535", cfg.Port)
	}
	binds, err := relayBinds(cfg.MeshIP, cfg.VMNetSubnet)
	if err != nil {
		return nil, err
	}
	return newRelay(cfg.Port, binds, cfg.Logger), nil
}

// newRelay assembles a Relay over the PRODUCTION seams. It is the one place they
// are wired, so a test that drives the accept/forward mechanics over a loopback
// pair exercises the same listener and dialer the shipped relay uses.
func newRelay(port int, binds []netip.Addr, log *slog.Logger) *Relay {
	if log == nil {
		log = slog.Default()
	}
	return &Relay{
		port:  port,
		binds: binds,
		log:   log,
		listen: func(addr string) (net.Listener, error) {
			return net.Listen("tcp", addr)
		},
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: relayDialTimeout}
			return d.DialContext(ctx, "tcp", addr)
		},
	}
}

// relayBinds resolves the addresses cfg asks for, refusing every address that is
// not a mesh address or a vm NAT gateway. It is PURE, so the whole bind
// discipline is assertable without a socket.
func relayBinds(meshIP, vmNetSubnet string) ([]netip.Addr, error) {
	var binds []netip.Addr
	if meshIP != "" {
		addr, err := netip.ParseAddr(meshIP)
		if err != nil {
			return nil, fmt.Errorf("%w: mesh address %q is not an IP address", ErrNonRelayableBind, meshIP)
		}
		// The mesh CIDR is the membership test, and it is the RIGHT one rather
		// than "not loopback, not wildcard": a mesh address is carved from
		// podnet.ClusterPodCIDR by construction, so an address outside it did not
		// come from this cluster's IPAM and exposing the registry on it would
		// serve a network nobody enrolled.
		if !podnet.ClusterPodCIDR.Contains(addr) {
			return nil, fmt.Errorf("%w: %s is not in the cluster mesh range %s", ErrNonRelayableBind, addr, podnet.ClusterPodCIDR)
		}
		binds = append(binds, addr)
	}
	if vmNetSubnet != "" {
		gw, err := VMNetGateway(vmNetSubnet)
		if err != nil {
			return nil, err
		}
		binds = append(binds, gw)
	}
	if len(binds) == 0 {
		return nil, ErrNoRelayAddress
	}
	return binds, nil
}

// VMNetGateway returns the host side of a vm NAT segment — the first host
// address of the subnet, which is the address Apple's vmnet assigns itself and
// the address a guest routes through (192.168.64.1 for 192.168.64.0/24).
//
// It is DERIVED from the segment rather than written down, for the same reason
// the in-cluster apiserver VIP is derived from the service CIDR: two constants
// that must agree are one constant and one bug waiting for the segment to move.
func VMNetGateway(subnet string) (netip.Addr, error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: vm NAT subnet %q is not a CIDR prefix", ErrNonRelayableBind, subnet)
	}
	gw := p.Masked().Addr().Next()
	if !p.Contains(gw) {
		return netip.Addr{}, fmt.Errorf("%w: vm NAT subnet %q has no host address", ErrNonRelayableBind, subnet)
	}
	return gw, nil
}

// Addresses returns the listen addresses this relay serves, in bind order. It is
// diagnostic — the caller logs it, and a test asserts it.
func (r *Relay) Addresses() []string {
	out := make([]string, 0, len(r.binds))
	for _, a := range r.binds {
		out = append(out, r.addrString(a))
	}
	return out
}

// addrString renders one bind address as a listen address.
func (r *Relay) addrString(a netip.Addr) string {
	return net.JoinHostPort(a.String(), strconv.Itoa(r.port))
}

// target is the loopback registry every accepted connection is forwarded to.
func (r *Relay) target() string {
	return net.JoinHostPort(LoopbackAddress, strconv.Itoa(r.port))
}

// Run serves every configured address until ctx ends.
//
// IT NEVER RETURNS AN ERROR, and that is the contract: a relay that cannot bind
// leaves a node whose registry is reachable only on loopback — exactly the
// behavior of every k3sm release before this one — while a bring-up aborted over
// it leaves a node that runs nothing. This is the same log-and-continue posture
// the ingest registry itself, the ingress listeners and the runtimed control
// socket are started under.
//
// Each address is served INDEPENDENTLY, so a vm segment that does not exist on
// this Mac cannot cost the mesh address its listener.
func (r *Relay) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, a := range r.binds {
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			r.serve(ctx, r.addrString(a))
		}(a)
	}
	wg.Wait()
}

// serve binds addr and forwards until ctx is done or the failure budget is spent.
func (r *Relay) serve(ctx context.Context, addr string) {
	for attempt := 1; ctx.Err() == nil; attempt++ {
		ln, err := r.listen(addr)
		if err != nil {
			// EADDRNOTAVAIL means the address is not configured on this host —
			// for the vm gateway, that this Mac has never started a guest, so no
			// bridge interface exists. It is a STATE, not a fault: reporting it
			// once and stopping this listener is honest, where retrying would
			// spend the budget logging a condition nothing here can change.
			if errors.Is(err, syscall.EADDRNOTAVAIL) {
				r.log.Info("ingest registry relay: the address is not configured on this host, so nothing is relayed on it",
					"addr", addr)
				return
			}
			if !r.retry(ctx, attempt, "bind", addr, err) {
				return
			}
			continue
		}
		r.log.Info("relaying the ingest registry", "addr", addr, "target", r.target())
		serveErr := r.accept(ctx, ln)
		if cerr := ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			r.log.Warn("closing an ingest registry relay listener", "addr", addr, "err", cerr)
		}
		if serveErr == nil {
			r.log.Info("ingest registry relay stopped", "addr", addr)
			return
		}
		if !r.retry(ctx, attempt, "serve", addr, serveErr) {
			return
		}
	}
}

// retry reports whether serve should make another attempt, logging at the
// severity the remaining budget justifies and pausing for the backoff.
func (r *Relay) retry(ctx context.Context, attempt int, stage, addr string, err error) bool {
	if attempt >= relayBindAttempts {
		r.log.Error("ingest registry relay disabled on this address: peers and vm guests cannot pull from this node's registry (its own pods are unaffected)",
			"addr", addr, "stage", stage, "attempts", attempt, "err", err)
		return false
	}
	r.log.Warn("ingest registry relay attempt failed; retrying",
		"addr", addr, "stage", stage, "attempt", attempt, "backoff", relayBindBackoff, "err", err)
	t := time.NewTimer(relayBindBackoff)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// accept runs the accept+forward loop over ln. It returns nil on a clean stop
// (ctx cancelled or the listener closed) so serve can tell "we are shutting
// down" from "this listener broke".
func (r *Relay) accept(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go r.forward(ctx, conn)
	}
}

// forward proxies client↔registry bytes both ways with TCP half-close
// propagation, returning only once BOTH directions have finished.
//
// Waiting for both, and propagating the half-close rather than treating it as a
// session end, is the same discipline the apiserver load balancer's forwarder
// documents: a registry push sends a large body and then reads a response, and a
// pull streams a blob long after the request ended. Tearing the pair down when
// EITHER direction finished would truncate both.
func (r *Relay) forward(ctx context.Context, client net.Conn) {
	defer client.Close()
	registry, err := r.dial(ctx, r.target())
	if err != nil {
		// DEBUG, not WARN: the registry being down is a state a peer's puller
		// already handles (it reads a connection refusal as "this mirror does not
		// have it" and moves on), and one dead node must not fill every peer's log.
		r.log.Debug("ingest registry relay could not reach the local registry", "target", r.target(), "err", err)
		return
	}
	defer registry.Close()

	// Close both conns on ctx cancel so shutdown drains in-flight forwards; the
	// deferred cancel reaps the watcher when the forward ends first.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		_ = client.Close()
		_ = registry.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(registry, client)
		relayCloseWrite(registry)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, registry)
		relayCloseWrite(client)
	}()
	wg.Wait()
}

// relayCloseWrite propagates a half-close where the conn supports it (TCP), so
// the peer reads EOF on that direction while the other stays open.
func relayCloseWrite(c net.Conn) {
	if hc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
	}
}
