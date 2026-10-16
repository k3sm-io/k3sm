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

package netserve

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeListener is a TCP listener stand-in. Its first len(errs) Accepts return errs
// in order; after that every Accept returns final when it is set, and otherwise
// hands out the connections pushed on conns. Accepts after Close fail with
// net.ErrClosed, as a real listener's do.
type fakeListener struct {
	errs  []error
	final error
	conns chan net.Conn

	mu     sync.Mutex
	next   int
	done   chan struct{}
	closer sync.Once
	closed atomic.Bool
}

func newFakeListener(final error, errs ...error) *fakeListener {
	return &fakeListener{errs: errs, final: final, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	l.mu.Lock()
	if l.next < len(l.errs) {
		err := l.errs[l.next]
		l.next++
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	if l.final != nil {
		return nil, l.final
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closer.Do(func() { l.closed.Store(true); close(l.done) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(10, 43, 0, 10), Port: 53} }

// tcpRebindBinder hands out one UDP socket, the listener first on the first
// listenTCP and then next on every later one, signalling each later bind on
// rebound.
type tcpRebindBinder struct {
	udp      net.PacketConn
	first    net.Listener
	next     net.Listener
	udpBinds atomic.Int64
	tcpBinds atomic.Int64
	bound    chan struct{}
	rebound  chan struct{}
}

func (b *tcpRebindBinder) ensureAlias(context.Context, netip.Addr) error { return nil }

func (b *tcpRebindBinder) listenUDP(context.Context, netip.AddrPort) (net.PacketConn, error) {
	b.udpBinds.Add(1)
	return b.udp, nil
}

func (b *tcpRebindBinder) listenTCP(context.Context, netip.AddrPort) (net.Listener, error) {
	if b.tcpBinds.Add(1) == 1 {
		close(b.bound)
		return b.first, nil
	}
	select {
	case b.rebound <- struct{}{}:
	default:
	}
	return b.next, nil
}

func acceptError(errno syscall.Errno) error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", errno)}
}

// queryFakeTCP sends one length-prefixed query on a fresh connection accepted by ln
// and returns the response.
func queryFakeTCP(t *testing.T, ln *fakeListener, name string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	select {
	case ln.conns <- server:
	case <-time.After(5 * time.Second):
		_ = server.Close()
		t.Fatalf("the TCP listener accepted no connection for %s", name)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	q := buildAQuery(t, name)
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame, uint16(len(q)))
	copy(frame[2:], q)
	if _, err := client.Write(frame); err != nil {
		t.Fatalf("write TCP query: %v", err)
	}
	var lenbuf [2]byte
	if _, err := io.ReadFull(client, lenbuf[:]); err != nil {
		t.Fatalf("read TCP response length: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenbuf[:]))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read TCP response: %v", err)
	}
	return resp
}

// queryFakeUDP sends one query on pc and returns the reply.
func queryFakeUDP(t *testing.T, pc *queueConn, name string) []byte {
	t.Helper()
	pc.in <- buildAQuery(t, name)
	select {
	case resp := <-pc.out:
		return resp
	case <-time.After(5 * time.Second):
		t.Fatalf("no UDP answer for %s", name)
		return nil
	}
}

func wantAPIVIP(t *testing.T, transport string, resp []byte) {
	t.Helper()
	rcode, addrs := parseResponse(t, resp)
	if rcode != dnsmessage.RCodeSuccess || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("10.43.0.1") {
		t.Errorf("%s answer = %v %v, want NOERROR 10.43.0.1", transport, rcode, addrs)
	}
}

// TestResolverRebindsWhenTheTCPListenerDies is the regression for an accept error
// on the adopted TCP DNS listener stopping the whole resolver: serveTCP returned
// it, the errgroup cancelled the UDP side with it, and the node had no cluster DNS
// on either transport until the server was restarted. A listener whose Accept fails
// for good must be closed and re-bound, TCP side only, within one retry interval,
// and the new listener must answer, with UDP answering throughout; a temporary
// accept error must be retried on the same listener without a re-bind.
func TestResolverRebindsWhenTheTCPListenerDies(t *testing.T) {
	cases := []struct {
		name       string
		first      func() *fakeListener
		wantRebind bool
	}{
		{"listener closed", func() *fakeListener { return newFakeListener(net.ErrClosed) }, true},
		{"bad descriptor", func() *fakeListener { return newFakeListener(acceptError(syscall.EBADF)) }, true},
		{"not listening", func() *fakeListener { return newFakeListener(acceptError(syscall.EINVAL)) }, true},
		{"three non-temporary errors", func() *fakeListener {
			return newFakeListener(acceptError(syscall.EOPNOTSUPP))
		}, true},
		{"temporary errors are retried", func() *fakeListener {
			return newFakeListener(nil, acceptError(syscall.ECONNABORTED), acceptError(syscall.EMFILE))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
				Spec:       corev1.ServiceSpec{ClusterIP: "10.43.0.1", Ports: []corev1.ServicePort{{Port: 443}}},
			})
			s := New(Config{
				Client:        cs,
				WorkDir:       t.TempDir(),
				DNSVIP:        "10.43.0.10",
				ClusterDomain: "cluster.local",
				PodCIDR:       "100.64.1.0/24",
			})
			s.log = testLogger()
			udp := newQueueConn(4)
			first := tc.first()
			next := newFakeListener(nil)
			b := &tcpRebindBinder{udp: udp, first: first, next: next, bound: make(chan struct{}), rebound: make(chan struct{}, 1)}
			s.binder = b

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); s.runResolver(ctx) }()

			select {
			case <-b.bound:
			case <-time.After(10 * time.Second):
				t.Fatal("the resolver never bound the DNS VIP")
			}

			live := first
			if tc.wantRebind {
				select {
				case <-b.rebound:
				case <-done:
					t.Fatal("the resolver stopped when the TCP listener died; want a TCP re-bind")
				case <-time.After(dnsBindRetryInitial):
					t.Fatalf("no TCP re-bind within one retry interval (%s)", dnsBindRetryInitial)
				}
				if !first.closed.Load() {
					t.Errorf("the dead listener was not closed before the re-bind")
				}
				live = next
			}

			wantAPIVIP(t, "UDP", queryFakeUDP(t, udp, "kubernetes.default.svc.cluster.local"))
			wantAPIVIP(t, "TCP", queryFakeTCP(t, live, "kubernetes.default.svc.cluster.local"))
			wantAPIVIP(t, "UDP", queryFakeUDP(t, udp, "kubernetes.default.svc.cluster.local"))

			wantTCPBinds := int64(1)
			if tc.wantRebind {
				wantTCPBinds = 2
			}
			if n := b.tcpBinds.Load(); n != wantTCPBinds {
				t.Errorf("TCP binds = %d, want %d", n, wantTCPBinds)
			}
			if n := b.udpBinds.Load(); n != 1 {
				t.Errorf("UDP binds = %d, want 1: the UDP side must keep its socket", n)
			}

			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the resolver did not return after cancellation")
			}
		})
	}
}

// TestAcceptErrorClassification pins which accept errors end a listener, which are
// temporary, and which count toward tcpAcceptFailLimit.
func TestAcceptErrorClassification(t *testing.T) {
	cases := []struct {
		name          string
		err           error
		wantDead      bool
		wantTemporary bool
	}{
		{"closed", net.ErrClosed, true, false},
		{"EBADF", acceptError(syscall.EBADF), true, false},
		{"EINVAL", acceptError(syscall.EINVAL), true, false},
		{"ECONNABORTED", acceptError(syscall.ECONNABORTED), false, true},
		{"EMFILE", acceptError(syscall.EMFILE), false, true},
		{"ENFILE", acceptError(syscall.ENFILE), false, true},
		{"unclassified", errors.New("accept: something else"), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, dead := acceptErrorEndsListener(tc.err); dead != tc.wantDead {
				t.Errorf("ends listener = %v, want %v", dead, tc.wantDead)
			}
			if got := isTemporaryAcceptError(tc.err); got != tc.wantTemporary {
				t.Errorf("temporary = %v, want %v", got, tc.wantTemporary)
			}
		})
	}
}
