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
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestLoopbackGateBindsLoopbackOnly pins the loopback gate's one bind:
// 127.0.0.1 at its own port, never the wildcard, never another address, never
// the registry's own port, and never without a serving certificate. It also
// pins that NewRelay still refuses a loopback bind, and that the shipped
// listener is bound on 127.0.0.1 and nothing else.
func TestLoopbackGateBindsLoopbackOnly(t *testing.T) {
	if GatePort(6450) != 6451 {
		t.Errorf("GatePort(6450) = %d, want 6451", GatePort(6450))
	}
	if _, err := NewRelay(RelayConfig{Port: 6450, MeshIP: "127.0.0.1", Serving: testServing(t)}); !errors.Is(err, ErrNonRelayableBind) {
		t.Errorf("NewRelay on loopback = %v, want ErrNonRelayableBind", err)
	}
	for _, tc := range []struct {
		name string
		cfg  LoopbackGateConfig
		want error
	}{
		{"its own port", LoopbackGateConfig{RegistryPort: 6450, Port: 6450, Serving: testServing(t)}, ErrLoopbackGatePort},
		{"out of range", LoopbackGateConfig{RegistryPort: 6450, Port: 70000, Serving: testServing(t)}, ErrLoopbackGatePort},
		{"no certificate", LoopbackGateConfig{RegistryPort: 6450, Port: 6451}, ErrNoServingIdentity},
	} {
		if _, err := NewLoopbackGate(tc.cfg); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	var mu sync.Mutex
	var bound []string
	gate, err := NewLoopbackGate(LoopbackGateConfig{
		RegistryPort: 6450, Port: port, Serving: testServing(t), Logger: quietLogger(),
		OnListen: func(addr string) { mu.Lock(); bound = append(bound, addr); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "127.0.0.1:" + strconv.Itoa(port)
	if got := gate.Addresses(); len(got) != 1 || got[0] != want {
		t.Fatalf("Addresses = %v, want [%s]", got, want)
	}
	if gate.target() != "127.0.0.1:6450" {
		t.Errorf("upstream = %s, want the registry's 127.0.0.1:6450", gate.target())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { gate.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(bound)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if len(bound) != 1 || bound[0] != want {
		t.Fatalf("bound = %v, want [%s]", bound, want)
	}
	mu.Unlock()
	c, err := net.DialTimeout("tcp", want, time.Second)
	if err != nil {
		t.Fatalf("dial the gate on loopback: %v", err)
	}
	c.Close()
	// Another address of this Mac reaches nothing on the gate's port.
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), strconv.Itoa(port)), 500*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("the gate answered on %s, want loopback only", ipn.IP)
		}
	}
}
