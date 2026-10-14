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

package ingresshost

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// trackingBinder opens closable in-memory listeners, refusing the AddrPorts in
// deny, and remembers every listener by AddrPort.
type trackingBinder struct {
	mu   sync.Mutex
	deny map[netip.AddrPort]bool
	open map[netip.AddrPort]*closeListener
}

type closeListener struct {
	ap     netip.AddrPort
	closed chan struct{}
	once   sync.Once
}

func (l *closeListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *closeListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (l *closeListener) Addr() net.Addr            { return net.TCPAddrFromAddrPort(l.ap) }
func (l *closeListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

func (b *trackingBinder) Listen(_ context.Context, _ string, ap netip.AddrPort) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deny[ap] {
		return nil, errors.New("bind refused")
	}
	if b.open == nil {
		b.open = map[netip.AddrPort]*closeListener{}
	}
	l := &closeListener{ap: ap, closed: make(chan struct{})}
	b.open[ap] = l
	return l, nil
}

func (b *trackingBinder) get(t *testing.T, ap string) *closeListener {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.open[netip.MustParseAddrPort(ap)]
	if l == nil {
		t.Fatalf("no listener opened on %s", ap)
	}
	return l
}

// TestIngressHostRebind pins the ingress listeners' address swap: the bound
// HTTP and HTTPS listeners bind the new set (loopback left out below 1024)
// before the old addresses close; a refused bind on either listener keeps the
// old set on both; and a listener opened after a commit binds the new set.
func TestIngressHostRebind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	wildcard := []netip.Addr{netip.IPv4Unspecified()}
	local := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("100.64.0.1")}

	newHost := func(t *testing.T, b *trackingBinder) *Host {
		t.Helper()
		h, err := New(Config{Client: fake.NewClientset(), BindAddr: netip.IPv4Unspecified(), HTTPPort: 80, HTTPSPort: 443, NodeName: "n", Binder: b})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	listen := func(t *testing.T, h *Host, port uint16) net.Listener {
		t.Helper()
		ln, err := countingBinder{h: h}.Listen(ctx, "tcp", netip.AddrPortFrom(netip.IPv4Unspecified(), port))
		if err != nil {
			t.Fatalf("listen %d: %v", port, err)
		}
		return ln
	}

	t.Run("off and on again", func(t *testing.T) {
		t.Parallel()
		b := &trackingBinder{}
		h := newHost(t, b)
		http, https := listen(t, h, 80), listen(t, h, 443)
		defer http.Close()
		defer https.Close()
		rb, err := h.PrepareBindAddrs(ctx, local)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		if b.get(t, "0.0.0.0:80").isClosed() {
			t.Fatal("prepare closed the wildcard")
		}
		rb.Commit()
		for _, ap := range []string{"0.0.0.0:80", "0.0.0.0:443"} {
			if !b.get(t, ap).isClosed() {
				t.Errorf("commit left %s open", ap)
			}
		}
		for _, ap := range []string{"100.64.0.1:80", "100.64.0.1:443"} {
			if b.get(t, ap).isClosed() {
				t.Errorf("commit closed %s", ap)
			}
		}
		b.mu.Lock()
		_, loop := b.open[netip.MustParseAddrPort("127.0.0.1:80")]
		b.mu.Unlock()
		if loop {
			t.Error("a privileged ingress port bound loopback (the netd helper never brokers it)")
		}
		if got := h.BindAddrs(); !slices.Equal(got, local) {
			t.Errorf("BindAddrs = %v, want %v", got, local)
		}
		later := listen(t, h, 8443)
		defer later.Close()
		b.get(t, "127.0.0.1:8443")
		b.get(t, "100.64.0.1:8443")

		rb, err = h.PrepareBindAddrs(ctx, wildcard)
		if err != nil {
			t.Fatal(err)
		}
		rb.Commit()
		if !b.get(t, "100.64.0.1:80").isClosed() {
			t.Error("going back to the wildcard left the node address open")
		}
	})

	t.Run("a refused bind keeps the old set on every listener", func(t *testing.T) {
		t.Parallel()
		b := &trackingBinder{deny: map[netip.AddrPort]bool{netip.MustParseAddrPort("100.64.0.1:443"): true}}
		h := newHost(t, b)
		http, https := listen(t, h, 80), listen(t, h, 443)
		defer http.Close()
		defer https.Close()
		if _, err := h.PrepareBindAddrs(ctx, local); err == nil {
			t.Fatal("prepare succeeded with a refused bind")
		}
		if b.get(t, "0.0.0.0:80").isClosed() || b.get(t, "0.0.0.0:443").isClosed() {
			t.Error("a refused swap closed an old listener")
		}
		b.mu.Lock()
		if l := b.open[netip.MustParseAddrPort("100.64.0.1:80")]; l != nil && !l.isClosed() {
			t.Error("a refused swap left the other listener's new address open")
		}
		b.mu.Unlock()
		if got := h.BindAddrs(); !slices.Equal(got, wildcard) {
			t.Errorf("BindAddrs after a refused swap = %v, want the wildcard", got)
		}
		// The set lock was released: another listener can still open.
		ln := listen(t, h, 8080)
		_ = ln.Close()
	})
}
