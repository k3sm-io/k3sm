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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// The MESH/GUEST RELAY: an HTTPS front that accepts on an address other machines
// (or this Mac's own vm guests) can reach, serves the push gate there, and hands
// every request the gate admits to the registry's loopback listener.
//
// IT SERVES HTTPS AND NOTHING ELSE. TLS terminates here, under a certificate the
// cluster CA issues (serving.go), so a ServiceAccount token presented for a push
// and the image bytes alike are encrypted on every hop a caller can see, whether
// it arrived over the mesh, over a vm guest's NAT segment or through a Service
// VIP. A plain-HTTP request to a relay address is answered with 400 and never
// reaches the gate. zot behind it stays plain HTTP on loopback.
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
// node-relative reference. A WRITE is not carried blindly: every relay address
// serves the push gate (gate.go), which forwards a write only for a pod whose
// own ServiceAccount token the apiserver vouches for, in a namespace that opted
// in, under that namespace's repository prefix, with an RBAC grant to push, and
// which refuses DELETE outright. The registry's own per-boot credential for the
// local CLI is never presented here and never leaves the node; the gate holds a
// second, in-memory credential that can create and update but never delete. So
// a peer can read what this cluster runs and cannot plant an image it will run
// unless the cluster's own RBAC said it may.
//
// THE TWO ADDRESSES, and why they are the only two:
//
//   - THE MESH ADDRESS — this node's wireguard address, inside
//     podnet.ClusterPodCIDR. Only enrolled peers can address it, and wireguard
//     already encrypts the traffic between nodes; TLS on top covers the hops
//     wireguard does not (a Pod to its own node's proxy, a guest to its gateway).
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
	// relayReadHeaderTimeout, relayMaxHeaderBytes, relayIdleTimeout and
	// relayMaxConns bound what one client can hold of a relay address before
	// the gate has decided anything, and relaylimit.go divides relayMaxConns
	// into per-source shares. There is no read or write timeout: a blob is as
	// large as an image layer and streams for as long as it takes.
	relayReadHeaderTimeout = 10 * time.Second
	relayMaxHeaderBytes    = 16 << 10
	relayIdleTimeout       = 90 * time.Second
	relayMaxConns          = 256
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
	// Auth is the push gate's apiserver clients, under the gate's own narrow
	// identity. Incomplete (the identity could not be built) serves reads and
	// refuses every write with 503; there is no raw-forward fallback.
	Auth GateAuth
	// GateCredential is the registry credential an authorized write is
	// forwarded with (Service.GateCredential). Empty refuses every write.
	GateCredential Credential
	// Serving is the TLS identity every relay address presents. Required:
	// NewRelay refuses a relay without one (ErrNoServingIdentity) rather than
	// serve plain HTTP off loopback.
	Serving *ServingIdentity
	// Listen binds one admitted address. nil means a TCP listener with the
	// segment clamp. It is a seam for tests that serve the relay over loopback;
	// the address it is handed is always one relayBinds admitted, so it cannot
	// widen the bind discipline, only redirect where a test listens.
	Listen func(addr string) (net.Listener, error)
	// Logger receives bind, forward and push-decision events. nil means
	// slog.Default.
	Logger *slog.Logger
}

// Relay forwards connections from the node's reachable addresses to the ingest
// registry's loopback listener.
//
// The zero value is not usable — construct one with NewRelay, which is where the
// bind discipline is enforced.
type Relay struct {
	// port is the port every bind listens on; upstream is the registry's
	// loopback port the gate forwards to. They are equal for the mesh/guest
	// relay and differ for the loopback gate (loopbackgate.go).
	port     int
	upstream int
	binds    []netip.Addr
	log      *slog.Logger
	// limits are the connection caps the listener applies; limiter is the
	// handler in front of the gate that applies the per-source buckets, and
	// handler is the limiter.
	limits  relayLimits
	limiter *sourceLimiter
	handler http.Handler
	// tls is the server configuration every accepted connection is wrapped in.
	// NewRelay always sets it; only this package's tests of the gate mechanics
	// build a relay without it.
	tls *tls.Config

	// listen is a seam so the serve mechanics are testable over a loopback
	// listener, with no mesh and no guest. Production wires a segment-clamped
	// net.Listen.
	listen func(addr string) (net.Listener, error)
	// onListen, when set, is called with each address once it is bound, so a
	// caller records a listener only after it exists.
	onListen func(addr string)
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
	if cfg.Serving == nil {
		return nil, ErrNoServingIdentity
	}
	r := newRelay(cfg.Port, cfg.Port, binds, cfg.Logger, cfg.Auth, cfg.GateCredential)
	r.tls = cfg.Serving.TLSConfig()
	if cfg.Listen != nil {
		r.listen = cfg.Listen
	}
	return r, nil
}

// newRelay assembles a Relay over the PRODUCTION seams. It is the one place they
// are wired, so a test that drives the serve mechanics over a loopback listener
// exercises the same listener and gate the shipped relay uses.
//
// port is the port every bind listens on and upstream the registry's loopback
// port the gate forwards to.
func newRelay(port, upstream int, binds []netip.Addr, log *slog.Logger, auth GateAuth, cred Credential) *Relay {
	if log == nil {
		log = slog.Default()
	}
	r := &Relay{
		port:     port,
		upstream: upstream,
		binds:    binds,
		log:      log,
		limits:   defaultRelayLimits,
		// The relay binds a mesh address and the vm NAT gateway, which local pods
		// reach over lo0, so every accepted connection's TCP segment size is
		// clamped. The gate's upstream dial is not: it targets the registry's
		// 127.0.0.1 listener, and 127/8 is permanently on lo0, so that connection
		// never re-routes.
		listen: func(addr string) (net.Listener, error) {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return nil, err
			}
			return tcpseg.WrapListener(ln), nil
		},
	}
	r.limiter = newSourceLimiter(newGate(gateConfig{Upstream: r.target(), Auth: auth, Credential: cred, Logger: log}), r.limits, time.Now)
	r.handler = r.limiter
	return r
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
	return net.JoinHostPort(LoopbackAddress, strconv.Itoa(r.upstream))
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
		if r.onListen != nil {
			r.onListen(addr)
		}
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

// accept serves the push gate over ln, over TLS, at most relayMaxConns
// connections at a time and at most relayMaxConnsPerSource from one address. It returns nil on a clean stop (ctx cancelled or the listener closed)
// so serve can tell "we are shutting down" from "this listener broke".
//
// One http.Server per address, with the gate mounted directly as its handler.
// Cancelling ctx closes the server and every connection on it at once, as the
// raw relay did, because the registry it fronts is about to stop.
func (r *Relay) accept(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           r.handler,
		ReadHeaderTimeout: relayReadHeaderTimeout,
		MaxHeaderBytes:    relayMaxHeaderBytes,
		IdleTimeout:       relayIdleTimeout,
		ErrorLog:          slog.NewLogLogger(r.log.Handler(), slog.LevelDebug),
		ConnContext:       r.limiter.ConnContext,
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		_ = srv.Close()
	}()
	var served net.Listener = newLimitListener(ln, r.limits.maxConns, r.limits.maxConnsPerSource)
	if r.tls != nil {
		// TLS wraps the connection cap, not the reverse: the *tls.Conn the
		// server sees is what lets it answer a plain-HTTP request with 400,
		// and closing it closes the capped connection and frees its slot.
		served = tls.NewListener(served, r.tls)
	}
	err := srv.Serve(served)
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("serve: %w", err)
}

// limitListener caps the connections a listener has open at once, in total
// and per remote address. Accept blocks while the total cap is reached, so
// clients holding connections open cost other clients a wait, never this
// process its file descriptors. A connection from an address already at its
// share is closed on accept instead: queueing it would make every other
// address wait behind it.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	perSource int
	open      sourceCounts
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(ln net.Listener, total, perSource int) *limitListener {
	return &limitListener{
		Listener:  ln,
		sem:       make(chan struct{}, total),
		perSource: perSource,
		open:      sourceCounts{n: map[string]int{}},
		done:      make(chan struct{}),
	}
}

// Accept waits for a free slot, then accepts a connection from an address
// under its share.
func (l *limitListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.sem <- struct{}{}:
		case <-l.done:
			return nil, net.ErrClosed
		}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		src := sourceOf(c.RemoteAddr())
		if !l.open.take(src, l.perSource) {
			_ = c.Close()
			<-l.sem
			continue
		}
		return &limitConn{Conn: c, release: func() { l.open.give(src); <-l.sem }}, nil
	}
}

// Close closes the listener and wakes an Accept waiting for a slot.
func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// limitConn frees its slot exactly once, on Close.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
