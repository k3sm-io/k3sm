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
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// TestNodePortServiceOpensWildcardListener is the M3.1-a1 rootless rehearsal: a
// NodePort Service object, fed to a running netserve.Server through its embedded
// darwin-net Service watcher (fake clientset), makes the in-process proxy open the
// node-wide *:NodePort TCP listener (dialed here via loopback) and load-balance to
// the Ready backend — proving k3sm's server wiring surfaces NodePort end-to-end
// (the watch carries NodePort, the proxy binds it directly, >=1024, no helper).
// The live cross-Mac reachability is the M3 two-Mac lab e2e; this pins the wiring.
//
// The proxy's lo0-alias manager is root-gated (it shells out to ifconfig) and its
// rootless test double is unexported in darwin-net, so the ClusterIP alias is made
// to succeed without privilege by stubbing ifconfig on PATH; the ClusterIP
// (127.0.0.1) and *:NodePort sockets then bind for real. Not parallel: it sets
// PATH process-wide via t.Setenv.
func TestNodePortServiceOpensWildcardListener(t *testing.T) {
	stubIfconfig(t)

	const (
		ns      = "default"
		svcName = "web"
	)
	backend := newEchoBackend(t, "np-backend")
	defer backend.close()
	backendIP, backendPort := backend.addrPort()

	// Both ports come from the NodePort range, NOT bind(:0) — see safePort.
	clusterPort := safePort(t, "127.0.0.1")
	nodePort := safePort(t, "0.0.0.0") // the unprivileged proxy binds it directly
	for nodePort == clusterPort {
		nodePort = safePort(t, "0.0.0.0")
	}

	ready := true
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeNodePort,
			ClusterIP: "127.0.0.1",
			Ports: []corev1.ServicePort{{
				Port:       clusterPort,
				TargetPort: intstr.FromInt(int(backendPort)),
				Protocol:   corev1.ProtocolTCP,
				NodePort:   nodePort,
			}},
		},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName + "-0",
			Namespace: ns,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svcName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{backendIP},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
		Ports: []discoveryv1.EndpointPort{{Port: &backendPort}},
	}

	s := New(Config{
		Client:        fake.NewClientset(svc, slice),
		WorkDir:       t.TempDir(),
		DNSVIP:        "10.43.0.10",
		ClusterDomain: "cluster.local",
	})

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()

	// The *:NodePort listener comes up (dialed via loopback) once the watcher
	// reconciles the Service — the core M3.1-a1 assertion.
	waitListen(t, nodePort, runErr)
	// And it splices through to the Ready backend (LB via the userspace proxy).
	if got := readIDWithRetry(t, nodePort, "np-backend"); got != "np-backend" {
		t.Fatalf("NodePort served %q, want np-backend", got)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Errorf("Run returned %v, want nil on clean shutdown", err)
	}
	// Teardown is leak-free: the listener closes with the proxy.
	waitClosed(t, nodePort)
}

// echoBackend is a tiny TCP server that writes a fixed id then closes; it stands
// in for a pod backend so the proxy data path is exercised without privilege.
type echoBackend struct {
	id   string
	ln   net.Listener
	done chan struct{}
}

func newEchoBackend(t *testing.T, id string) *echoBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend: %v", err)
	}
	b := &echoBackend{id: id, ln: ln, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, id)
			}(c)
		}
	}()
	return b
}

func (b *echoBackend) addrPort() (string, int32) {
	ap := b.ln.Addr().(*net.TCPAddr)
	return ap.IP.String(), int32(ap.Port)
}

func (b *echoBackend) close() {
	_ = b.ln.Close()
	<-b.done
}

// stubIfconfig prepends a temp dir with an ifconfig that exits 0 to PATH, so the
// proxy's root-gated lo0-alias manager (which shells out to ifconfig) succeeds
// rootlessly without mutating lo0. t.Setenv restores PATH after the test.
func stubIfconfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "ifconfig"), []byte(script), 0o755); err != nil {
		t.Fatalf("write ifconfig stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// freePort returns a currently-free TCP port on host (bind :0, read, release).
func freePort(t *testing.T, host string) int32 {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("reserve free port on %s: %v", host, err)
	}
	port := int32(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

// safePort returns a free port on host drawn from the NodePort range
// (30000-32767) rather than an OS-assigned ephemeral one.
//
// freePort's bind(:0) draws from the darwin ephemeral range
// (net.inet.ip.portrange.first=49152 .. last=65535) and then releases the port
// before the proxy binds it. Under `go test ./...` the module's packages run as
// concurrent processes all allocating ephemeral sockets, so that window can be
// lost to another process; the proxy's later bind then fails for good and the
// listener never appears. 30000-32767 is outside the range the OS allocator
// draws from, so a concurrent socket cannot be handed the same port — only
// another copy of this test could collide, which the retry covers.
func safePort(t *testing.T, host string) int32 {
	t.Helper()
	const (
		lo       = 30000 // pkg/ports.NodePortRange() == "30000-32767"
		hi       = 32767
		attempts = 20
	)
	for range attempts {
		port := int32(lo + rand.IntN(hi-lo+1))
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			continue // in use; try another
		}
		_ = ln.Close()
		return port
	}
	t.Fatalf("no free port on %s in %d-%d after %d attempts", host, lo, hi, attempts)
	return 0
}

// waitListen blocks until 127.0.0.1:port accepts a connection or the deadline
// elapses (the listener came up).
//
// runErr carries the server's Run result. Run returning early means the proxy
// never got as far as a listener, so the wait reports THAT error rather than
// spending the deadline to report the symptom ("never came up") and discarding
// the cause — the failure mode that made the ephemeral-port steal above so
// hard to read.
// DEADLINE IS NOT THE ROOT CAUSE — see B156.
//
// An earlier fix raised this from 5s to 30s, concluding the cut simply sat inside
// a load-proportional bring-up distribution (measured idle: 4.36s, 4.68s, 4.70s,
// 5.25s, 5.56s). That conclusion was WRONG, or at best partial: the same failure
// then reproduced at 30s under a parallel-lane gate AND at 180s on an otherwise
// ordinary run. At three minutes the listener is not slow, it never arrives —
// while s.Run() returns no error, so the server is up and the proxy simply never
// binds. In isolation the same test takes ~0.9s and passes 5/5.
//
// So there is a real intermittent wedge in the bring-up path. This deadline is
// deliberately NOT inflated further: raising it only makes CI spend longer to
// report a genuine hang. 30s is far outside the normal distribution, so a failure
// here means the wedge, not slowness. The runErr select below is what
// distinguishes "server died" from "server alive, listener never bound".
func waitListen(t *testing.T, port int32, runErr <-chan error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			t.Fatalf("server Run exited before the listener on *:%d came up: %v", port, err)
		default:
		}
		c, err := net.DialTimeout("tcp", hostPort(port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("listener on *:%d never came up", port)
}

// waitClosed blocks until 127.0.0.1:port refuses connections or the deadline
// elapses (the listener was torn down).
func waitClosed(t *testing.T, port int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostPort(port), 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("listener on *:%d still open after shutdown", port)
}

// readIDWithRetry dials 127.0.0.1:port and returns the backend id the proxy
// steered to, retrying until it matches want or the deadline elapses (the
// EndpointSlice backend may land a beat after the listener opens).
func readIDWithRetry(t *testing.T, port int32, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		last = readOnce(port)
		if last == want {
			return last
		}
		time.Sleep(25 * time.Millisecond)
	}
	return last
}

// readOnce dials 127.0.0.1:port once and returns whatever the proxy wrote back
// (empty on any dial/read error or when no backend was selected).
func readOnce(port int32) string {
	c, err := net.DialTimeout("tcp", hostPort(port), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf, _ := io.ReadAll(c)
	return string(buf)
}

func hostPort(port int32) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}
