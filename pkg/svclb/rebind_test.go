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
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// pipeListener is an in-memory listener a test can connect to: each connect
// hands Accept the server end of a net.Pipe.
type pipeListener struct {
	ap     netip.AddrPort
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener(ap netip.AddrPort) *pipeListener {
	return &pipeListener{ap: ap, conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.ap) }

func (l *pipeListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

// connect opens a connection through the listener and returns the client end.
func (l *pipeListener) connect(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client
	case <-l.closed:
		t.Fatalf("connect %s: listener closed", l.ap)
	case <-time.After(5 * time.Second):
		t.Fatalf("connect %s: never accepted", l.ap)
	}
	return nil
}

// setBinder binds pipeListeners, refusing the AddrPorts in deny with their
// error, and keeps the last listener opened per AddrPort.
type setBinder struct {
	mu   sync.Mutex
	deny map[netip.AddrPort]error
	open map[netip.AddrPort]*pipeListener
}

func (b *setBinder) Listen(_ context.Context, _ string, ap netip.AddrPort) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.deny[ap]; err != nil {
		return nil, err
	}
	if b.open == nil {
		b.open = map[netip.AddrPort]*pipeListener{}
	}
	l := newPipeListener(ap)
	b.open[ap] = l
	return l, nil
}

func (b *setBinder) get(t *testing.T, ap string) *pipeListener {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.open[netip.MustParseAddrPort(ap)]
	if l == nil {
		t.Fatalf("no listener was opened on %s", ap)
	}
	return l
}

// echoTwice writes msg on c and reads it back.
func echoTwice(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo %q, want %q", buf, msg)
	}
	return nil
}

var (
	wildcard = []netip.Addr{netip.IPv4Unspecified()}
	local    = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("100.64.0.1")}
)

// TestAddrSetListenerSwaps pins the address-set listener every LoadBalancer
// and ingress listener is built on: the bind set rule, a swap that binds the
// new addresses before it closes the old, an aborted swap, and an accepted
// connection that outlives the address it arrived on.
func TestAddrSetListenerSwaps(t *testing.T) {
	t.Parallel()

	t.Run("effective bind addresses", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name  string
			addrs []netip.Addr
			port  uint16
			want  []netip.Addr
		}{
			{"the wildcard swallows the rest", append(slices.Clone(local), wildcard...), 8080, wildcard},
			{"a specific set is sorted", []netip.Addr{local[1], local[0]}, 8080, []netip.Addr{local[1], local[0]}},
			{"below 1024 loopback is left out", local, 80, []netip.Addr{local[1]}},
			{"below 1024 loopback alone leaves nothing", local[:1], 443, nil},
			{"the wildcard binds below 1024", wildcard, 80, wildcard},
		}
		for _, tc := range cases {
			got := EffectiveBindAddrs(tc.addrs, tc.port)
			slices.SortFunc(tc.want, func(a, b netip.Addr) int { return a.Compare(b) })
			if !slices.Equal(got, tc.want) {
				t.Errorf("%s: EffectiveBindAddrs(%v, %d) = %v, want %v", tc.name, tc.addrs, tc.port, got, tc.want)
			}
		}
	})

	t.Run("swap with a connection in flight", func(t *testing.T) {
		t.Parallel()
		b := &setBinder{}
		ctx := context.Background()
		set, err := ListenAddrSet(ctx, b.Listen, wildcard, 8080)
		if err != nil {
			t.Fatal(err)
		}
		defer set.Close()
		go func() {
			for {
				c, err := set.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		wild := b.get(t, "0.0.0.0:8080")
		client := wild.connect(t)
		defer client.Close()
		if err := echoTwice(client, "before"); err != nil {
			t.Fatal(err)
		}
		if err := set.Prepare(ctx, local); err != nil {
			t.Fatal(err)
		}
		if wild.isClosed() {
			t.Fatal("Prepare closed the old address")
		}
		set.Commit(local)
		if !wild.isClosed() {
			t.Fatal("Commit left the wildcard open")
		}
		if got := set.Addrs(); !slices.Equal(got, []netip.Addr{local[1], local[0]}) {
			t.Fatalf("Addrs after the commit = %v", got)
		}
		if err := echoTwice(client, "after"); err != nil {
			t.Fatalf("the connection accepted on the closed address did not survive: %v", err)
		}
		// A new connection on a new address is served.
		c2 := b.get(t, "100.64.0.1:8080").connect(t)
		defer c2.Close()
		if err := echoTwice(c2, "new"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a failed prepare leaves the old set and nothing pending", func(t *testing.T) {
		t.Parallel()
		b := &setBinder{deny: map[netip.AddrPort]error{netip.MustParseAddrPort("127.0.0.1:8081"): errors.New("address already in use")}}
		ctx := context.Background()
		set, err := ListenAddrSet(ctx, b.Listen, wildcard, 8081)
		if err != nil {
			t.Fatal(err)
		}
		defer set.Close()
		if err := set.Prepare(ctx, local); err == nil {
			t.Fatal("Prepare succeeded with an unbindable address")
		}
		if mesh := b.get(t, "100.64.0.1:8081"); !mesh.isClosed() {
			t.Error("the address bound before the failure was left open")
		}
		if b.get(t, "0.0.0.0:8081").isClosed() {
			t.Error("a failed Prepare closed the old address")
		}
	})
}

// TestHosterRebind pins the hoster's address swap: every bound Service moves
// to the new set; a Service the new set cannot serve (a port below 1024 on a
// specific set) is withdrawn from the bound report BEFORE its listener closes
// and is re-reported only once it binds again; and an ordinary bind failure
// refuses the whole swap with the old set still in force.
func TestHosterRebind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// prepare runs one swap request the way Run does, on a goroutine of its
	// own, and returns the prepared swap.
	prepare := func(h *Hoster, addrs []netip.Addr) (*Rebind, error) {
		req := rebindRequest{addrs: addrs, reply: make(chan rebindReply, 1)}
		go h.handleRebind(ctx, req)
		r := <-req.reply
		return r.rb, r.err
	}

	t.Run("move, withdraw before unbind, re-report after bind", func(t *testing.T) {
		t.Parallel()
		eacces := fmt.Errorf("listen: %w", syscall.EACCES)
		b := &setBinder{deny: map[netip.AddrPort]error{netip.MustParseAddrPort("100.64.0.1:80"): eacces}}
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		h := newTestHoster(t, cs, testNode, nil, map[int32]bool{}, nil)
		h.dir = b
		web := lbService("default", "web", "10.43.0.5", 8080)
		www := lbService("default", "www", "10.43.0.6", 80)
		svcs := []*corev1.Service{web, www}
		h.reconcile(ctx, svcs)
		if r := reportOf(t, cs, testNode); !r.entries[reportEntry(web)] || !r.entries[reportEntry(www)] {
			t.Fatalf("precondition: both services reported on the wildcard, got %v", r.entries)
		}
		port80 := b.get(t, "0.0.0.0:80")

		// The withdraw must land while the port-80 listener is still open.
		var mu sync.Mutex
		var withdrawnWhileOpen, sawWithdraw bool
		cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
			p, ok := a.(k8stesting.PatchAction)
			if !ok {
				return false, nil, nil
			}
			body := string(p.GetPatch())
			if !strings.Contains(body, reportEntry(www)) && strings.Contains(body, reportEntry(web)) {
				mu.Lock()
				if !sawWithdraw {
					sawWithdraw = true
					withdrawnWhileOpen = !port80.isClosed()
				}
				mu.Unlock()
			}
			return false, nil, nil
		})

		rb, err := prepare(h, local)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		if !slices.Equal(rb.Unserved, []string{"default/www"}) {
			t.Fatalf("Unserved = %v, want default/www", rb.Unserved)
		}
		if err := rb.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
		mu.Lock()
		if !sawWithdraw || !withdrawnWhileOpen {
			t.Errorf("the report withdrawal (seen=%v) must land before the listener closes (open at withdrawal=%v)", sawWithdraw, withdrawnWhileOpen)
		}
		mu.Unlock()
		if !port80.isClosed() {
			t.Error("the unserved service's listener is still open")
		}
		if !b.get(t, "0.0.0.0:8080").isClosed() {
			t.Error("the moved service still listens on the wildcard")
		}
		b.get(t, "127.0.0.1:8080")
		b.get(t, "100.64.0.1:8080")

		h.reconcile(ctx, svcs)
		r := reportOf(t, cs, testNode)
		if !r.entries[reportEntry(web)] || r.entries[reportEntry(www)] {
			t.Fatalf("after the swap: report = %v, want web only", r.entries)
		}

		// Back to the wildcard: port 80 binds again and only then is reported.
		rb, err = prepare(h, wildcard)
		if err != nil {
			t.Fatal(err)
		}
		if err := rb.Commit(); err != nil {
			t.Fatal(err)
		}
		h.reconcile(ctx, svcs)
		if r := reportOf(t, cs, testNode); !r.entries[reportEntry(www)] || !r.entries[reportEntry(web)] {
			t.Fatalf("back on the wildcard: report = %v, want both", r.entries)
		}
	})

	t.Run("an ordinary bind failure refuses the swap", func(t *testing.T) {
		t.Parallel()
		b := &setBinder{deny: map[netip.AddrPort]error{netip.MustParseAddrPort("127.0.0.1:9090"): errors.New("address already in use")}}
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		h := newTestHoster(t, cs, testNode, nil, map[int32]bool{}, nil)
		h.dir = b
		web := lbService("default", "web", "10.43.0.7", 9090)
		h.reconcile(ctx, []*corev1.Service{web})
		if _, err := prepare(h, local); err == nil {
			t.Fatal("prepare succeeded with an address in use")
		}
		if b.get(t, "0.0.0.0:9090").isClosed() {
			t.Error("a refused swap closed the old listener")
		}
		if !b.get(t, "100.64.0.1:9090").isClosed() {
			t.Error("a refused swap left a new listener open")
		}
		if !IsWildcard(h.BindAddrs()) {
			t.Errorf("BindAddrs after a refused swap = %v, want the wildcard", h.BindAddrs())
		}
	})
}
