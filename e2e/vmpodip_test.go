//go:build e2e

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

package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// vm pod IP reachability: the lab twin of darwin-net's
// TestPublishedVMPodAddressRelaysToLive. A vm Pod's status.podIP is a /32 its
// node aliases on lo0 and relays, per declared TCP containerPort and per
// Service-targeted port, to the guest's vmnet lease. This proves it from every
// vantage a native pod IP is reachable from: another node (the test process, on
// the server), the pod's own host (a hostNetwork pod on the worker), and a
// native pod on that node. The Service-path cross-node proof is
// TestAdmissionWebhookDeliveryThroughProxy (m16_test.go); this test does not
// repeat it.
//
// RUN IT (two-Mac rig, from the server; the conftool helper must exist at the
// same path on the worker, as TestM3_InPodKubectlAndDNSOnWorker needs):
//
//	KUBECONFIG=<path> K3SM_WORKER=<worker node> CGO_ENABLED=1 go test -tags e2e \
//	  -run '^TestVMPodIPReachableAcrossNodes$' -timeout 30m ./e2e/ -v

const (
	// vmPodIPServedPort is the port each guest declares and serves its banner on.
	vmPodIPServedPort = 8080
	// vmPodIPHiddenPort is a port the first guest ALSO serves on but does not
	// declare and no Service targets: the relay must refuse it, and because the
	// guest really listens there, a refusal is the relay's verdict, not an empty
	// port.
	vmPodIPHiddenPort = 9090
)

// vmBannerPy serves "BANNER=<name>" on every port in PORTS, one line per accepted
// connection, on all interfaces (the relay dials the guest from outside it).
const vmBannerPy = `import os, socket, threading
name = os.environ["BANNER"]
def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        try:
            c.sendall(("BANNER=%s\n" % name).encode())
        finally:
            c.close()
ports = [int(p) for p in os.environ["PORTS"].split(",")]
for p in ports[1:]:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
serve(ports[0])
`

// TestVMPodIPReachableAcrossNodes is the B440 lab gate for the k3sm half: two vm
// Pods on the worker, each answering its own banner; a dial of either's
// status.podIP reaches that Pod and never the other, from the server, from the
// worker host and from a native pod on the worker; an undeclared, non-Service
// port is refused; and once a Pod is deleted a dial of its address fails fast
// rather than hanging.
func TestVMPodIPReachableAcrossNodes(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	worker := os.Getenv("K3SM_WORKER")
	if worker == "" {
		t.Skip("LAB-ONLY: set $K3SM_WORKER to a joined worker node (two-Mac rig); single-node gates do not run this")
	}
	bin := helperBin(t, "conftool")

	ns := "vmpodip-" + runSuffix(t)
	t.Cleanup(func() {
		err := c.Client.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("cleanup: delete namespace %s: %v", ns, err)
		}
	})
	if _, err := c.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %s: %v", ns, err)
	}

	node, err := c.Client.CoreV1().Nodes().Get(ctx, worker, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get worker node %s: %v", worker, err)
	}
	nodeCIDR, err := netip.ParsePrefix(node.Spec.PodCIDR)
	if err != nil {
		t.Fatalf("worker %s has no usable spec.podCIDR %q: %v", worker, node.Spec.PodCIDR, err)
	}

	a := createVMBannerPod(t, c, ns, "alpha", worker, vmPodIPHiddenPort)
	b := createVMBannerPod(t, c, ns, "beta", worker)
	ipA := waitPodIPInCIDR(t, c, ns, a, nodeCIDR)
	ipB := waitPodIPInCIDR(t, c, ns, b, nodeCIDR)
	if ipA == ipB {
		t.Fatalf("both vm Pods report status.podIP %s; each must publish its own address", ipA)
	}
	for _, ip := range []netip.Addr{ipA, ipB} {
		for _, na := range node.Status.Addresses {
			if na.Address == ip.String() {
				t.Fatalf("status.podIP %s is the worker's own %s address; a vm Pod must publish its own /32", ip, na.Type)
			}
		}
	}
	addrA := net.JoinHostPort(ipA.String(), fmt.Sprint(vmPodIPServedPort))
	addrB := net.JoinHostPort(ipB.String(), fmt.Sprint(vmPodIPServedPort))

	t.Run("from another node", func(t *testing.T) {
		// The first dial absorbs the guest lease lag (the relay exists only once
		// the node learned the lease), so it polls; each answer must be the right
		// Pod's, every time.
		expectBanner(t, addrA, "alpha", 3*time.Minute)
		expectBanner(t, addrB, "beta", 3*time.Minute)
	})

	t.Run("from the pod's own host", func(t *testing.T) {
		p := workerDialPod(ns, "host-dial", worker, bin, true, addrA, "alpha")
		applyAndWaitSucceeded(t, c, p, 4*time.Minute)
	})

	t.Run("from a native pod on that node", func(t *testing.T) {
		p := workerDialPod(ns, "pod-dial", worker, bin, false, addrB, "beta")
		applyAndWaitSucceeded(t, c, p, 4*time.Minute)
	})

	t.Run("an undeclared non-Service port is refused", func(t *testing.T) {
		hidden := net.JoinHostPort(ipA.String(), fmt.Sprint(vmPodIPHiddenPort))
		if err := expectRefused(hidden); err != nil {
			t.Error(err)
		}
	})

	t.Run("after delete the address fails fast", func(t *testing.T) {
		if err := c.Client.CoreV1().Pods(ns).Delete(ctx, a, metav1.DeleteOptions{}); err != nil {
			t.Fatalf("delete pod %s/%s: %v", ns, a, err)
		}
		gone := pollUntil(3*time.Minute, func() bool {
			_, err := c.Client.CoreV1().Pods(ns).Get(ctx, a, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		})
		if !gone {
			t.Fatalf("pod %s/%s still present 3m after delete", ns, a)
		}
		var last error
		if !pollUntil(time.Minute, func() bool {
			last = expectRefused(addrA)
			return last == nil
		}) {
			t.Errorf("deleted pod's address %s never failed fast: %v", addrA, last)
		}
		// The surviving Pod is untouched by its neighbour's teardown.
		expectBanner(t, addrB, "beta", 30*time.Second)
	})
}

// createVMBannerPod creates a vm Pod pinned to worker that serves its banner on
// vmPodIPServedPort (declared) and on every extra port (NOT declared), and
// returns its name once it is Running.
func createVMBannerPod(t *testing.T, c *Cluster, ns, name, worker string, extra ...int) string {
	t.Helper()
	ports := []string{fmt.Sprint(vmPodIPServedPort)}
	for _, p := range extra {
		ports = append(ports, fmt.Sprint(p))
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"app": name}},
		Spec: corev1.PodSpec{
			RuntimeClassName: ptr("vm"),
			NodeSelector: map[string]string{
				"kubernetes.io/os":       "darwin",
				"kubernetes.io/hostname": worker,
			},
			Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			Containers: []corev1.Container{{
				Name:    "banner",
				Image:   webhookImage(),
				Command: []string{"python3", "-c", vmBannerPy},
				Env: []corev1.EnvVar{
					{Name: "BANNER", Value: name},
					{Name: "PORTS", Value: strings.Join(ports, ",")},
				},
				Ports: []corev1.ContainerPort{{Name: "banner", ContainerPort: vmPodIPServedPort}},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("512Mi"),
					},
				},
			}},
		},
	}
	if _, err := c.Client.CoreV1().Pods(ns).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create vm pod %s/%s: %v", ns, name, err)
	}
	got := c.WaitPodPhase(t, ns, name, corev1.PodRunning, 8*time.Minute)
	if got.Spec.NodeName != worker {
		t.Fatalf("vm pod %s/%s scheduled on %s, want the worker %s", ns, name, got.Spec.NodeName, worker)
	}
	return name
}

// waitPodIPInCIDR waits for the pod's status.podIP and asserts it lies in the
// worker's pod /24: the published address the node aliases and relays.
func waitPodIPInCIDR(t *testing.T, c *Cluster, ns, name string, cidr netip.Prefix) netip.Addr {
	t.Helper()
	var ip netip.Addr
	if !pollUntil(2*time.Minute, func() bool {
		p, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		ip, err = netip.ParseAddr(p.Status.PodIP)
		return err == nil
	}) {
		t.Fatalf("pod %s/%s never reported a status.podIP", ns, name)
	}
	if !cidr.Contains(ip) {
		t.Fatalf("pod %s/%s status.podIP %s is outside the worker's pod CIDR %s", ns, name, ip, cidr)
	}
	return ip
}

// expectBanner dials addr from the test process until the first line names want,
// failing at once if another Pod's banner answers.
func expectBanner(t *testing.T, addr, want string, within time.Duration) {
	t.Helper()
	var last string
	ok := pollUntil(within, func() bool {
		line, err := readFirstLine(addr)
		if err != nil {
			last = err.Error()
			return false
		}
		if line != "BANNER="+want {
			t.Fatalf("dial %s answered %q, want BANNER=%s (another pod answered)", addr, line, want)
		}
		return true
	})
	if !ok {
		t.Fatalf("dial %s: no BANNER=%s within %s; last: %s", addr, want, within, last)
	}
}

// expectRefused dials addr once and reports why it is not a fast refusal: a
// connection, or an error that is a timeout (a hang), is a failure.
func expectRefused(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err == nil {
		line, _ := bufio.NewReader(conn).ReadString('\n') // only for the message
		_ = conn.Close()                                  // the check already failed
		return fmt.Errorf("dial %s connected (first line %q), want a fast refusal", addr, strings.TrimSpace(line))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("dial %s timed out (a hang), want a fast refusal: %w", addr, err)
	}
	return nil
}

// readFirstLine dials addr and returns the first line the peer writes.
func readFirstLine(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }() // read-only use; nothing to flush
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// workerDialPod is a one-shot native Pod pinned to the worker that runs conftool
// dial against addr and succeeds only when want's banner answers. hostNetwork
// selects the worker host's own network stack (the pod's own host as a vantage)
// rather than a pod address of its own.
func workerDialPod(ns, name, worker, bin string, hostNetwork bool, addr, want string) *corev1.Pod {
	p := nativePod(name, bin, "dial", "-addr", addr, "-expect", "BANNER="+want, "-for", "3m")
	p.Namespace = ns
	p.Spec.HostNetwork = hostNetwork
	p.Spec.NodeSelector = map[string]string{
		"kubernetes.io/os":       "darwin",
		"kubernetes.io/hostname": worker,
	}
	return p
}
