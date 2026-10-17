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

package svclb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
)

// ListenFunc binds one stream listener on ap (netbind.Binder.Listen's shape).
type ListenFunc func(ctx context.Context, network string, ap netip.AddrPort) (net.Listener, error)

// streamNetwork is the network a stream listener on a binds with: "tcp4" for
// an IPv4 address, the wildcard included, and "tcp" otherwise.
//
// On macOS `net.Listen("tcp", "0.0.0.0:p")` opens a DUAL-STACK AF_INET6 socket,
// and that socket binds successfully beside an IPv4-only process already
// holding *:p: wildcard-vs-wildcard fails EADDRINUSE only within one address
// family. The listener would then be reported bound while the IPv4 holder
// answers every IPv4 connection. The cluster serves no IPv6, so binding IPv4
// only loses nothing and makes the conflict a bind error.
func streamNetwork(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "tcp4"
	}
	return "tcp"
}

// ErrNoBindAddress is the named refusal of an address set that leaves a port
// nothing to bind (an empty set, or a set of loopback addresses only on a port
// below 1024; see EffectiveBindAddrs).
var ErrNoBindAddress = errors.New("no address to bind")

// privilegedPortMax is the highest port macOS reserves: below 1024 only root
// may bind a SPECIFIC address, while a wildcard bind needs no privilege.
const privilegedPortMax = 1023

// EffectiveBindAddrs is where a listener on port binds under the address set
// addrs: the IPv4 wildcard alone when the set holds it (every interface
// already covers every other address), or the set itself, sorted and
// deduplicated.
//
// On a port below 1024 the loopback addresses are dropped from a specific set.
// No unprivileged process can bind a specific address there, and the one
// broker that can (the netd helper, for the ingress and LoadBalancer
// listeners) admits this node's own address and never loopback; the node's
// address answers on this Mac anyway. The result may be empty, which a caller refuses with
// ErrNoBindAddress rather than binding nothing quietly.
func EffectiveBindAddrs(addrs []netip.Addr, port uint16) []netip.Addr {
	return effectiveBindAddrs(addrs, port, false)
}

// effectiveBindAddrs is EffectiveBindAddrs, keeping loopback below 1024 when
// keepLoopback is set: the svclb hoster's binder brokers those binds through
// the netd helper, which can bind 127.0.0.1 for a listed port.
func effectiveBindAddrs(addrs []netip.Addr, port uint16, keepLoopback bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		if a.IsUnspecified() && a.Is4() {
			return []netip.Addr{a}
		}
		if port <= privilegedPortMax && a.IsLoopback() && !keepLoopback {
			continue
		}
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// IsWildcard reports whether addrs is the every-interface set (it holds the
// IPv4 wildcard).
func IsWildcard(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if a.Unmap().IsUnspecified() {
			return true
		}
	}
	return false
}

// AddrSetListener is one port listened on at every address of a set, accepted
// as one listener. The set can be swapped while it serves: Prepare binds the
// addresses the new set adds, then Commit closes the ones it drops (or Abort
// closes what Prepare added). Closing an address never closes a connection
// already accepted on it.
//
// Locking discipline: mu guards lns and pending. Accept, Close and Addr may be
// called from any goroutine; Prepare, Commit and Abort are called by the one
// owner of the listener and never concurrently with each other.
type AddrSetListener struct {
	port   uint16
	listen ListenFunc
	// keepLoopback keeps loopback below 1024 (effectiveBindAddrs).
	keepLoopback bool

	mu sync.Mutex
	// lns is the committed set's listeners; pending is what the last Prepare
	// opened. An address in neither has been closed on purpose, which is how
	// the accept goroutines tell a swap from a failure.
	lns     map[netip.Addr]net.Listener
	pending map[netip.Addr]net.Listener

	conns  chan accepted
	closed chan struct{}
	once   sync.Once
}

// accepted is one result of an underlying listener's Accept.
type accepted struct {
	conn net.Conn
	err  error
}

// ListenAddrSet binds port on every address of EffectiveBindAddrs(addrs,
// port), all or nothing: a failed bind closes the listeners already opened
// and the error names the address.
func ListenAddrSet(ctx context.Context, listen ListenFunc, addrs []netip.Addr, port uint16) (*AddrSetListener, error) {
	return listenAddrSet(ctx, listen, addrs, port, false)
}

// listenAddrSet is ListenAddrSet, keeping loopback below 1024 for the whole
// life of the set when keepLoopback is set.
func listenAddrSet(ctx context.Context, listen ListenFunc, addrs []netip.Addr, port uint16, keepLoopback bool) (*AddrSetListener, error) {
	l := &AddrSetListener{
		port:         port,
		listen:       listen,
		keepLoopback: keepLoopback,
		lns:          make(map[netip.Addr]net.Listener),
		conns:        make(chan accepted),
		closed:       make(chan struct{}),
	}
	opened, err := l.bind(ctx, l.effective(addrs))
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.lns = opened
	l.mu.Unlock()
	for _, ln := range opened {
		go l.serve(ln)
	}
	return l, nil
}

// effective is where this set binds under addrs.
func (l *AddrSetListener) effective(addrs []netip.Addr) []netip.Addr {
	return effectiveBindAddrs(addrs, l.port, l.keepLoopback)
}

// bind opens want, all or nothing.
func (l *AddrSetListener) bind(ctx context.Context, want []netip.Addr) (map[netip.Addr]net.Listener, error) {
	if len(want) == 0 {
		return nil, fmt.Errorf("port %d: %w", l.port, ErrNoBindAddress)
	}
	out := make(map[netip.Addr]net.Listener, len(want))
	for _, a := range want {
		ap := netip.AddrPortFrom(a, l.port)
		ln, err := l.listen(ctx, streamNetwork(a), ap)
		if err != nil {
			for _, o := range out {
				_ = o.Close()
			}
			return nil, fmt.Errorf("listen %s: %w", ap, err)
		}
		out[a] = ln
	}
	return out, nil
}

// serve feeds ln's connections to Accept until ln closes. A listener closed by
// a swap ends quietly; any other accept error is handed to Accept.
func (l *AddrSetListener) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if l.retired(ln) {
				return
			}
			select {
			case l.conns <- accepted{err: err}:
			case <-l.closed:
			}
			return
		}
		select {
		case l.conns <- accepted{conn: c}:
		case <-l.closed:
			_ = c.Close()
			return
		}
	}
}

// retired reports whether ln was closed on purpose (it is in neither map).
func (l *AddrSetListener) retired(ln net.Listener) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range []map[netip.Addr]net.Listener{l.lns, l.pending} {
		for _, o := range m {
			if o == ln {
				return false
			}
		}
	}
	return true
}

// Accept returns the next connection accepted on any address of the set.
func (l *AddrSetListener) Accept() (net.Conn, error) {
	select {
	case a := <-l.conns:
		return a.conn, a.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close closes every address of the set (and anything a Prepare left
// pending). Connections already accepted keep running.
func (l *AddrSetListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		lns, pending := l.lns, l.pending
		l.lns, l.pending = nil, nil
		l.mu.Unlock()
		close(l.closed)
		for _, m := range []map[netip.Addr]net.Listener{lns, pending} {
			for _, ln := range m {
				_ = ln.Close()
			}
		}
	})
	return nil
}

// Addr returns the address of one listener of the set (the lowest), or the
// unspecified address on port when none is open.
func (l *AddrSetListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := make([]netip.Addr, 0, len(l.lns))
	for a := range l.lns {
		keys = append(keys, a)
	}
	if len(keys) == 0 {
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), l.port))
	}
	slices.SortFunc(keys, func(a, b netip.Addr) int { return a.Compare(b) })
	return l.lns[keys[0]].Addr()
}

// Addrs returns the committed set's addresses, sorted.
func (l *AddrSetListener) Addrs() []netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]netip.Addr, 0, len(l.lns))
	for a := range l.lns {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// Prepare binds the addresses of EffectiveBindAddrs(addrs, port) the set does
// not already listen on, all or nothing, and starts serving them beside the
// current ones. On error nothing is left pending and the current set is
// untouched. A Prepare replaces an earlier one that was never finished.
func (l *AddrSetListener) Prepare(ctx context.Context, addrs []netip.Addr) error {
	l.Abort()
	want := l.effective(addrs)
	if len(want) == 0 {
		return fmt.Errorf("port %d: %w", l.port, ErrNoBindAddress)
	}
	l.mu.Lock()
	var missing []netip.Addr
	for _, a := range want {
		if _, ok := l.lns[a]; !ok {
			missing = append(missing, a)
		}
	}
	l.mu.Unlock()
	if len(missing) == 0 {
		l.mu.Lock()
		l.pending = map[netip.Addr]net.Listener{}
		l.mu.Unlock()
		return nil
	}
	opened, err := l.bind(ctx, missing)
	if err != nil {
		return err
	}
	l.mu.Lock()
	if l.lns == nil { // closed meanwhile
		l.mu.Unlock()
		for _, ln := range opened {
			_ = ln.Close()
		}
		return net.ErrClosed
	}
	l.pending = opened
	l.mu.Unlock()
	for _, ln := range opened {
		go l.serve(ln)
	}
	return nil
}

// Commit makes addrs (the set the last Prepare was given) the committed set:
// it closes every committed address outside EffectiveBindAddrs(addrs, port)
// and keeps what Prepare opened.
func (l *AddrSetListener) Commit(addrs []netip.Addr) {
	want := l.effective(addrs)
	l.mu.Lock()
	var drop []net.Listener
	for a, ln := range l.lns {
		if !slices.Contains(want, a) {
			drop = append(drop, ln)
			delete(l.lns, a)
		}
	}
	for a, ln := range l.pending {
		if l.lns != nil {
			l.lns[a] = ln
		}
	}
	l.pending = nil
	l.mu.Unlock()
	for _, ln := range drop {
		_ = ln.Close()
	}
}

// Abort closes whatever the last Prepare opened; the committed set is
// untouched. Abort with nothing pending is a no-op.
func (l *AddrSetListener) Abort() {
	l.mu.Lock()
	pending := l.pending
	l.pending = nil
	l.mu.Unlock()
	for _, ln := range pending {
		_ = ln.Close()
	}
}
