//go:build integration

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
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestLoopbackGateAnswersOnLoopbackOnly proves the shipped TCP listener: the
// loopback gate binds 127.0.0.1 and nothing else, so it answers on loopback and
// on no other address of this Mac. It binds real sockets, so it is
// integration-tagged; TestLoopbackGateBindsLoopbackOnly pins the same bind
// address through the Listen seam.
func TestLoopbackGateAnswersOnLoopbackOnly(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { gate.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitBound(t, &mu, &bound)
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
