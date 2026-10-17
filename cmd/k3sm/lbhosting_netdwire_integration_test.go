//go:build integration && darwin

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
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"k3sm.io/darwin-net/pkg/netbind"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// fakeWireNetd is a netd daemon on a unix socket that speaks the BindPort
// verb as the real one does on the protocol field: it refuses any protocol
// other than "tcp" or "udp" ("bindPort: unsupported protocol"), and for an
// accepted request hands back, by SCM_RIGHTS, a listener it opened on an
// ephemeral loopback port (the requested address is recorded, not bound: the
// test checks the wire contract, not a root bind).
type fakeWireNetd struct {
	socket string

	mu        sync.Mutex
	protocols []string
	addrs     []string
}

func newFakeWireNetd(t *testing.T) *fakeWireNetd {
	t.Helper()
	// A short path: a unix socket path is capped near 104 bytes.
	dir, err := os.MkdirTemp("", "b556")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeWireNetd{socket: filepath.Join(dir, "n.sock")}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: f.socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			go f.serve(t, conn)
		}
	}()
	return f
}

func (f *fakeWireNetd) serve(t *testing.T, conn *net.UnixConn) {
	defer conn.Close()
	payload, err := wire.ReadFrame(conn, wire.DefaultMaxRequestBytes)
	if err != nil {
		return
	}
	var req wire.Request
	if err := json.Unmarshal(payload, &req); err != nil || req.BindPort == nil {
		f.reply(conn, wire.Response{Version: wire.CurrentVersion(), Error: "bad request"}, nil)
		return
	}
	f.mu.Lock()
	f.protocols = append(f.protocols, req.BindPort.Protocol)
	f.addrs = append(f.addrs, req.BindPort.NodeAddr)
	f.mu.Unlock()
	if p := req.BindPort.Protocol; p != "" && p != "tcp" && p != "udp" {
		f.reply(conn, wire.Response{Version: wire.CurrentVersion(), Error: "bindPort: unsupported protocol \"" + p + "\""}, nil)
		return
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Errorf("fake netd listen: %v", err)
		return
	}
	defer ln.Close()
	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Errorf("fake netd file: %v", err)
		return
	}
	defer file.Close()
	f.reply(conn, wire.Response{Version: wire.CurrentVersion(), OK: true, FDPassed: true, BoundAddr: req.BindPort.NodeAddr}, file)
}

func (f *fakeWireNetd) reply(conn *net.UnixConn, resp wire.Response, file *os.File) {
	payload, _ := json.Marshal(resp)
	var oob []byte
	if file != nil {
		oob = syscall.UnixRights(int(file.Fd()))
	}
	_, _, _ = conn.WriteMsgUnix(wire.Frame(payload), oob, nil)
}

func (f *fakeWireNetd) seen() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.protocols...), append([]string(nil), f.addrs...)
}

// TestHosterBinderSpeaksTheNetdWireProtocolOverASocket drives the svclb hoster's binder,
// as lbHosterConfig builds it, with the "tcp4" network svclb asks for on an
// IPv4 address, against a daemon that refuses every protocol but "tcp" and
// "udp" as netd does. A listed port must bind on the wildcard and on a
// specific address; a raw *netbind.Netd handed the same request is refused,
// which is what keeps this test non-vacuous. It opens real unix and loopback
// sockets, so it is integration-tier; TestHosterBinderSpeaksTheNetdWireProtocol
// is the unit-tier half at the binder seam.
func TestHosterBinderSpeaksTheNetdWireProtocolOverASocket(t *testing.T) {
	fake := newFakeWireNetd(t)
	opts := gateNodeOptions()
	opts.netMode.Socket = fake.socket
	opts.lbPrivilegedPorts = []uint16{80}
	b := lbHosterConfig(nil, opts, nil).Binder
	if b == nil {
		t.Fatal("no binder in the helper posture")
	}
	for _, ap := range []netip.AddrPort{
		netip.MustParseAddrPort("0.0.0.0:80"),
		netip.MustParseAddrPort("100.64.0.1:80"),
	} {
		ln, err := b.Listen(context.Background(), "tcp4", ap)
		if err != nil {
			t.Errorf("hoster bind of listed %s over tcp4 failed: %v", ap, err)
			continue
		}
		_ = ln.Close()
	}
	protocols, addrs := fake.seen()
	if strings.Join(protocols, ",") != "tcp,tcp" || strings.Join(addrs, ",") != "0.0.0.0,100.64.0.1" {
		t.Errorf("netd saw protocols %v for %v, want tcp for 0.0.0.0 and 100.64.0.1", protocols, addrs)
	}

	raw := &netbind.Netd{Client: wire.NewClient(fake.socket)}
	if ln, err := raw.Listen(context.Background(), "tcp4", netip.MustParseAddrPort("0.0.0.0:80")); err == nil {
		_ = ln.Close()
		t.Fatal("the fake daemon accepted protocol tcp4; the assertions above prove nothing")
	} else if !strings.Contains(err.Error(), "unsupported protocol") {
		t.Errorf("raw tcp4 refusal = %v, want the unsupported-protocol refusal", err)
	}
}
