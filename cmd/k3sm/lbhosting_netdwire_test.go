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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"k3sm.io/darwin-net/pkg/netbind"
)

// wireContractNetd stands in for the netd daemon at the binder seam: it
// refuses any protocol other than "tcp" or "udp", as netd's BindPort handler
// does ("bindPort: unsupported protocol"), and hands back a listener that
// holds no socket for an accepted one. It records the protocol of every
// request.
type wireContractNetd struct{ protocols []string }

func (w *wireContractNetd) Listen(_ context.Context, network string, ap netip.AddrPort) (net.Listener, error) {
	w.protocols = append(w.protocols, network)
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("netd bind %s %s: netd BindPort rejected: bindPort: unsupported protocol %q", network, ap, network)
	}
	return socketlessListener{ap: ap}, nil
}

// socketlessListener is a net.Listener that owns no socket.
type socketlessListener struct{ ap netip.AddrPort }

func (socketlessListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (socketlessListener) Close() error              { return nil }
func (l socketlessListener) Addr() net.Addr          { return net.TCPAddrFromAddrPort(l.ap) }

// TestHosterBinderSpeaksTheNetdWireProtocol drives the svclb hoster's binder
// with the "tcp4" network svclb asks for on an IPv4 address, against a daemon
// stand-in that refuses every protocol but "tcp" and "udp". A listed port must
// bind on the wildcard and on a specific address through the netdBinder
// adapter lbHosterConfig puts on the netd leg; the same requests handed to the
// daemon with no adapter are refused, which keeps the test non-vacuous.
func TestHosterBinderSpeaksTheNetdWireProtocol(t *testing.T) {
	opts := gateNodeOptions()
	opts.lbPrivilegedPorts = []uint16{80}
	hb, ok := lbHosterConfig(nil, opts, nil).Binder.(hosterBinder)
	if !ok {
		t.Fatal("no hosterBinder in the helper posture")
	}
	adapter, ok := hb.privileged.(netdBinder)
	if !ok {
		t.Fatalf("hosterBinder privileged leg = %T, want the netdBinder adapter", hb.privileged)
	}
	if _, ok := adapter.netd.(*netbind.Netd); !ok {
		t.Fatalf("the adapter wraps %T, want *netbind.Netd", adapter.netd)
	}
	addrs := []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:80"), netip.MustParseAddrPort("100.64.0.1:80")}

	daemon := &wireContractNetd{}
	adapter.netd = daemon
	hb.privileged = adapter
	for _, ap := range addrs {
		if _, err := hb.Listen(context.Background(), "tcp4", ap); err != nil {
			t.Errorf("hoster bind of listed %s over tcp4 failed: %v", ap, err)
		}
	}
	if !slices.Equal(daemon.protocols, []string{"tcp", "tcp"}) {
		t.Errorf("the daemon saw protocols %v, want tcp for both binds", daemon.protocols)
	}

	bare := &wireContractNetd{}
	hb.privileged = bare
	for _, ap := range addrs {
		if _, err := hb.Listen(context.Background(), "tcp4", ap); err == nil {
			t.Fatalf("a binder with no adapter bound %s over tcp4; the stand-in proves nothing", ap)
		}
	}
}
