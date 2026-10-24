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
	"sync"
	"testing"
	"time"
)

// TestLoopbackGateBindsLoopbackOnly pins the loopback gate's one bind:
// 127.0.0.1 at its own port, never the wildcard, never another address, never
// the registry's own port, and never without a serving certificate. It also
// pins that NewRelay still refuses a loopback bind. The bind goes through the
// Listen seam onto an in-memory listener, so no socket is opened; the shipped
// TCP bind is proven by the integration-tagged
// TestLoopbackGateAnswersOnLoopbackOnly.
func TestLoopbackGateBindsLoopbackOnly(t *testing.T) {
	if LoopbackAddress != "127.0.0.1" {
		t.Errorf("LoopbackAddress = %q, want 127.0.0.1", LoopbackAddress)
	}
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

	ln := newMemListener()
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var listened, bound []string
	gate, err := NewLoopbackGate(LoopbackGateConfig{
		RegistryPort: 6450, Port: 6451, Serving: testServing(t), Logger: quietLogger(),
		Listen: func(addr string) (net.Listener, error) {
			mu.Lock()
			listened = append(listened, addr)
			mu.Unlock()
			return ln, nil
		},
		OnListen: func(addr string) { mu.Lock(); bound = append(bound, addr); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = "127.0.0.1:6451"
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
	waitBound(t, &mu, &bound)
	mu.Lock()
	if len(listened) != 1 || listened[0] != want {
		t.Errorf("listened on %v, want [%s]", listened, want)
	}
	if len(bound) != 1 || bound[0] != want {
		t.Errorf("bound = %v, want [%s]", bound, want)
	}
	mu.Unlock()
	c, err := ln.dial()
	if err != nil {
		t.Fatalf("connect to the gate's listener: %v", err)
	}
	c.Close()
}

// waitBound waits up to five seconds for the first OnListen call.
func waitBound(t *testing.T, mu *sync.Mutex, bound *[]string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(*bound)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
