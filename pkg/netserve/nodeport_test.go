package netserve

import (
	"context"
	"io"
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

	clusterPort := freePort(t, "127.0.0.1")
	nodePort := freePort(t, "0.0.0.0") // >=1024 in practice; the unprivileged proxy binds it directly

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
	waitListen(t, nodePort)
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

// waitListen blocks until 127.0.0.1:port accepts a connection or the deadline
// elapses (the listener came up).
func waitListen(t *testing.T, port int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
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
