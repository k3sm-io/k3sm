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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// The canonical ingress objects the server provisions (pkg/ingresshost).
const (
	ingressClassName      = "k3sm"
	ingressControllerName = "k3sm.io/ingress"
	ingressSvcNamespace   = "kube-system"
	ingressSvcName        = "k3sm-ingress"
)

// TestM10_Ingress is the ingress criterion: the SERVER-PROCESS-hosted L7
// ingress (darwin-net pkg/ingress behind pkg/ingresshost) routes by host+path
// to a backend Service's ClusterIP VIP, the k3sm IngressClass exists, statuses
// are honest (written only once the listeners are bound), and svclb
// advertises a plain LoadBalancer Service only once a host reports it bound
// (each node's hoster binds and reports on its own Node; the server's decider
// writes the status). The unit-level contracts are pinned by pkg/ingresshost
// TestIngressHostingSecretDiscipline / TestIngressClassAndStatus and pkg/svclb
// TestSvclbBindHonesty / TestNodePoolSelection; the shell gate is
// hack/acceptance/m10-ingress.sh.
//
// WHICH PORTS. The criterion reads the ports from the cluster, never assumes
// them: the canonical kube-system/k3sm-ingress Service's "http" and "https"
// ports, dialed on the node InternalIP its status advertises. A server started
// on the unprivileged high-port listener (--ingress-http-port/
// --ingress-https-port) still declares 80/443 on that Service, so for that
// posture the listener ports are given as K3SM_E2E_INGRESS_HTTP_PORT /
// K3SM_E2E_INGRESS_HTTPS_PORT.
//
// Legs:
//
//  1. the IngressClass k3sm (controller k3sm.io/ingress) and the canonical
//     LoadBalancer Service (ports http+https, no selector, svclb-ignored) exist,
//     and the Service advertises the node under test;
//  2. an Ingress (class k3sm, a per-run host, path /) in front of a backend pod
//     and ClusterIP Service: GET with that Host answers the run's backend
//     identity, and an unclaimed Host answers 404;
//  3. the Ingress status.loadBalancer.ingress names the node InternalIP, and
//     whenever it does, the listener answers (bind-then-advertise);
//  4. a plain type=LoadBalancer Service on a free high port fronting the same
//     pod: its status names the node InternalIP and nodeIP:port reaches the
//     backend; a second LoadBalancer on the SAME port keeps an empty status
//     (the honesty negative: no host could bind it);
//  5. an Ingress tls[] block naming a kubernetes.io/tls Secret: SNI on the
//     https port serves exactly that certificate, and after the Secret is
//     rotated the next reconcile serves the new one. The reconcile is
//     triggered by touching the Ingress, because the host deliberately keeps
//     no Secret informer (it re-reads the Secrets an Ingress names on every
//     reconcile), so a Secret write alone is not an event it sees.
func TestM10_Ingress(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	node := m10Node(t, c)
	nodeIP := m10NodeIP(t, c, node)
	ns := m10Namespace(t, c)
	host := ns + ".ingress.test"
	identity := "m10-ingress-" + ns

	// Leg 1: the class and the canonical Service, and the ports to dial.
	ic, err := c.Client.NetworkingV1().IngressClasses().Get(ctx, ingressClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("leg 1: get IngressClass %s: %v", ingressClassName, err)
	}
	if ic.Spec.Controller != ingressControllerName {
		t.Errorf("leg 1: IngressClass %s controller %q, want %q", ingressClassName, ic.Spec.Controller, ingressControllerName)
	}
	lb, err := c.Client.CoreV1().Services(ingressSvcNamespace).Get(ctx, ingressSvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("leg 1: get Service %s/%s: %v", ingressSvcNamespace, ingressSvcName, err)
	}
	if lb.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("leg 1: %s/%s type %s, want LoadBalancer", ingressSvcNamespace, ingressSvcName, lb.Spec.Type)
	}
	if len(lb.Spec.Selector) != 0 {
		t.Errorf("leg 1: %s/%s has selector %v, want none (the server process is the implementation)", ingressSvcNamespace, ingressSvcName, lb.Spec.Selector)
	}
	if lb.Labels["svclb.k3sm.io/ignore"] != "true" {
		t.Errorf("leg 1: %s/%s lacks svclb.k3sm.io/ignore=true (svclb would race the ingress for its ports)", ingressSvcNamespace, ingressSvcName)
	}
	var httpPort, httpsPort int32
	for _, p := range lb.Spec.Ports {
		switch p.Name {
		case "http":
			httpPort = p.Port
		case "https":
			httpsPort = p.Port
		}
	}
	if httpPort == 0 {
		t.Fatalf("leg 1: %s/%s declares no port named http: %+v", ingressSvcNamespace, ingressSvcName, lb.Spec.Ports)
	}
	httpPort = envPort(t, "K3SM_E2E_INGRESS_HTTP_PORT", httpPort)
	if httpsPort != 0 {
		httpsPort = envPort(t, "K3SM_E2E_INGRESS_HTTPS_PORT", httpsPort)
	}
	if !lbAdvertises(lb, nodeIP) {
		t.Fatalf("leg 1: %s/%s status %+v does not advertise node %s (%s): the ingress listener is not bound there, so no leg below can reach it",
			ingressSvcNamespace, ingressSvcName, lb.Status.LoadBalancer.Ingress, node, nodeIP)
	}
	t.Logf("ingress on node %s at %s: http :%d, https :%d", node, nodeIP, httpPort, httpsPort)

	// The backend: an HTTP responder bound to its own pod IP answering the
	// run's identity, and its ClusterIP Service.
	body := identity
	backend := m10PinnedPod(ns, "backend", node, corev1.RestartPolicyAlways, fmt.Sprintf(
		`while :; do printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' | /usr/bin/nc -l "$K3SM_POD_IP" 8080 >/dev/null 2>&1 || sleep 1; done`,
		len(body), body))
	backend.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080}}
	m10Create(t, c, backend)
	if _, err := c.Client.CoreV1().Services(ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "backend"},
			Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create backend service: %v", err)
	}
	c.WaitPodReady(t, ns, "backend", 2*time.Minute)
	c.WaitServiceReadyEndpoints(t, ns, "backend", time.Minute)

	// Leg 2: host routing and the unclaimed-host negative.
	prefix := networkingv1.PathTypePrefix
	className := ingressClassName
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Path:     "/",
						PathType: &prefix,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: "backend", Port: networkingv1.ServiceBackendPort{Number: 80},
						}},
					}},
				}},
			}},
		},
	}
	if _, err := c.Client.NetworkingV1().Ingresses(ns).Create(ctx, ing, metav1.CreateOptions{}); err != nil {
		t.Fatalf("leg 2: create ingress: %v", err)
	}
	base := "http://" + hostPort(nodeIP, httpPort) + "/"
	var code int
	var got string
	if !pollUntil(90*time.Second, func() bool {
		code, got = hostGet(base, host)
		return code == http.StatusOK && got == identity
	}) {
		t.Fatalf("leg 2: GET %s Host:%s never answered the backend identity %q (last %d %q)", base, host, identity, code, got)
	}
	if code, got := hostGet(base, "unclaimed-"+host); code != http.StatusNotFound {
		t.Errorf("leg 2: GET %s Host:unclaimed-%s answered %d %q, want 404 (no default backend invented)", base, host, code, got)
	}

	// Leg 3: the status names the node, and the listener answers whenever it does.
	var status []networkingv1.IngressLoadBalancerIngress
	if !pollUntil(time.Minute, func() bool {
		cur, err := c.Client.NetworkingV1().Ingresses(ns).Get(ctx, "web", metav1.GetOptions{})
		if err != nil {
			return false
		}
		status = cur.Status.LoadBalancer.Ingress
		for _, s := range status {
			if s.IP == nodeIP {
				return true
			}
		}
		return false
	}) {
		t.Errorf("leg 3: ingress status.loadBalancer.ingress %+v never named node %s", status, nodeIP)
	} else if code, got := hostGet(base, host); code != http.StatusOK || got != identity {
		t.Errorf("leg 3: status advertises %s but the listener answered %d %q", nodeIP, code, got)
	}

	// Leg 4: svclb, and the conflicting-port honesty negative.
	port := freeLBPort(t, c, nodeIP)
	mkLB := func(name string) {
		if _, err := c.Client.CoreV1().Services(ns).Create(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeLoadBalancer,
				Selector: map[string]string{"app": "backend"},
				Ports:    []corev1.ServicePort{{Port: port, TargetPort: intstr.FromInt32(8080)}},
			},
		}, metav1.CreateOptions{}); err != nil {
			t.Fatalf("leg 4: create LoadBalancer %s: %v", name, err)
		}
	}
	lbStatus := func(name string) []corev1.LoadBalancerIngress {
		s, err := c.Client.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("leg 4: get service %s: %v", name, err)
		}
		return s.Status.LoadBalancer.Ingress
	}
	mkLB("lb-first")
	var first []corev1.LoadBalancerIngress
	if !pollUntil(90*time.Second, func() bool {
		first = lbStatus("lb-first")
		for _, s := range first {
			if s.IP == nodeIP {
				return true
			}
		}
		return false
	}) {
		t.Errorf("leg 4: LoadBalancer lb-first on :%d status %+v never named node %s", port, first, nodeIP)
	} else {
		lbURL := "http://" + hostPort(nodeIP, port) + "/"
		var b string
		if !pollUntil(30*time.Second, func() bool {
			_, b = hostGet(lbURL, "")
			return b == identity
		}) {
			t.Errorf("leg 4: lb-first advertises %s but GET %s answered %q, want %q", nodeIP, lbURL, b, identity)
		}
		mkLB("lb-conflict")
		// Several reconcile rounds: the conflicting Service must never be
		// advertised, since its port is already held by lb-first.
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if s := lbStatus("lb-conflict"); len(s) != 0 {
				t.Errorf("leg 4: lb-conflict on the already-bound port %d was advertised %+v; its status must stay empty", port, s)
				break
			}
			time.Sleep(2 * time.Second)
		}
		if s := lbStatus("lb-first"); len(s) == 0 {
			t.Errorf("leg 4: lb-first lost its status after the conflicting Service arrived")
		}
	}

	// Leg 5: TLS by SNI, and rotation.
	t.Run("tls", func(t *testing.T) {
		if httpsPort == 0 {
			t.Skipf("the canonical %s/%s declares no https port, so this cluster serves no TLS ingress", ingressSvcNamespace, ingressSvcName)
		}
		certA, keyA := selfSignedPair(t, host)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Namespace: ns},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: certA, corev1.TLSPrivateKeyKey: keyA},
		}
		if _, err := c.Client.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create tls secret: %v", err)
		}
		patch := fmt.Sprintf(`{"spec":{"tls":[{"hosts":[%q],"secretName":"web-tls"}]}}`, host)
		if _, err := c.Client.NetworkingV1().Ingresses(ns).Patch(ctx, "web", types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
			t.Fatalf("add tls to ingress: %v", err)
		}
		addr := hostPort(nodeIP, httpsPort)
		waitServedCert(t, addr, host, certA, identity)

		certB, keyB := selfSignedPair(t, host)
		secret.Data = map[string][]byte{corev1.TLSCertKey: certB, corev1.TLSPrivateKeyKey: keyB}
		if _, err := c.Client.CoreV1().Secrets(ns).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("rotate tls secret: %v", err)
		}
		touch := fmt.Sprintf(`{"metadata":{"annotations":{"m10.k3sm.io/rotated":%q}}}`, time.Now().UTC().Format(time.RFC3339Nano))
		if _, err := c.Client.NetworkingV1().Ingresses(ns).Patch(ctx, "web", types.MergePatchType, []byte(touch), metav1.PatchOptions{}); err != nil {
			t.Fatalf("touch ingress after the rotation: %v", err)
		}
		waitServedCert(t, addr, host, certB, identity)
	})
}

// envPort returns the port in env var name when set, else def.
func envPort(t *testing.T, name string, def int32) int32 {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	p, err := strconv.ParseInt(v, 10, 32)
	if err != nil || p <= 0 || p > 65535 {
		t.Fatalf("%s=%q is not a port", name, v)
	}
	return int32(p)
}

// lbAdvertises reports whether svc's load-balancer status names ip.
func lbAdvertises(svc *corev1.Service, ip string) bool {
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if s.IP == ip {
			return true
		}
	}
	return false
}

// hostGet GETs url with the given Host header ("" for the URL's own) and
// returns the status code and up to 4 KiB of body; code 0 on a transport error.
func hostGet(url, host string) (int, string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err.Error()
	}
	if host != "" {
		req.Host = host
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(b)
}

// freeLBPort picks a port for the LoadBalancer leg that no Service in the
// cluster declares and nothing answers on at nodeIP.
func freeLBPort(t *testing.T, c *Cluster, nodeIP string) int32 {
	t.Helper()
	svcs, err := c.Client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	used := map[int32]bool{}
	for _, s := range svcs.Items {
		for _, p := range s.Spec.Ports {
			used[p.Port] = true
			used[p.NodePort] = true
		}
	}
	for range 50 {
		p := int32(20000 + mrand.IntN(10000))
		if used[p] {
			continue
		}
		conn, err := net.DialTimeout("tcp", hostPort(nodeIP, p), time.Second)
		if err == nil {
			_ = conn.Close()
			continue
		}
		return p
	}
	t.Fatalf("no free port in 20000-29999 on %s after 50 tries", nodeIP)
	return 0
}

// selfSignedPair mints a throwaway ECDSA certificate for host (PEM cert, PEM key).
func selfSignedPair(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// waitServedCert polls a TLS handshake to addr with SNI host, trusting ONLY
// certPEM, until the served leaf is exactly that certificate and a GET over
// the connection answers identity.
func waitServedCert(t *testing.T, addr, host string, certPEM []byte, identity string) {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	var last string
	if pollUntil(90*time.Second, func() bool {
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}}
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			last = err.Error()
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, block.Bytes) {
			last = "served a different certificate"
			return false
		}
		last = fmt.Sprintf("%d %q", resp.StatusCode, b)
		return resp.StatusCode == http.StatusOK && string(b) == identity
	}) {
		return
	}
	t.Fatalf("https://%s via %s with SNI %s never served the expected certificate and backend (last: %s)", host, addr, host, last)
}
