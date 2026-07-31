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

package ingresshost

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/darwin-net/pkg/ingress"

	"k3sm.io/k3sm/pkg/svclb"
)

// makeKeyPair mints a self-signed PEM certificate/key for host (test-only).
func makeKeyPair(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// tlsSecret builds a Secret of the given type carrying a tls.crt/tls.key pair.
func tlsSecret(namespace, name string, secretType corev1.SecretType, certPEM, keyPEM []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       secretType,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
}

// The B116 fixture addresses: BIND is the wildcard, ADVERTISE is the node's
// derived .1 inside testPodCIDR. Deliberately different values, so an assertion
// that reads the wrong field cannot pass by coincidence.
var (
	testBindAddr      = netip.AddrFrom4([4]byte{}) // 0.0.0.0
	testAdvertiseAddr = netip.MustParseAddr("100.64.2.1")
	testPodCIDR       = netip.MustParsePrefix("100.64.0.0/10")
)

// newTestHost builds a Host over cs with a buffered log sink.
func newTestHost(t *testing.T, cs kubernetes.Interface, httpPort, httpsPort uint16) (*Host, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h, err := New(Config{
		Client:        cs,
		BindAddr:      testBindAddr,
		AdvertiseAddr: testAdvertiseAddr,
		PodCIDR:       testPodCIDR,
		HTTPPort:      httpPort,
		HTTPSPort:     httpsPort,
		Logger:        slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, &buf
}

// TestIngressHostingSecretDiscipline pins the M10.3 SECURITY-BINDING TLS
// Secret handling: Secrets are fetched by targeted Get (never an informer), a
// non-kubernetes.io/tls type is rejected by name, a parse failure is logged
// with the NAME and never the data, and a subsequent reconcile callback
// re-reads the Secret so rotation takes effect without any extra machinery.
func TestIngressHostingSecretDiscipline(t *testing.T) {
	certPEM, keyPEM := makeKeyPair(t, "web.test")
	otherCert, otherKey := makeKeyPair(t, "opaque.test")

	cs := fake.NewClientset(
		tlsSecret("default", "web-tls", corev1.SecretTypeTLS, certPEM, keyPEM),
		tlsSecret("default", "opaque-tls", corev1.SecretTypeOpaque, otherCert, otherKey),
		tlsSecret("default", "garbage-tls", corev1.SecretTypeTLS, []byte("not a certificate"), []byte("not a key")),
	)
	h, buf := newTestHost(t, cs, 8080, 8443)
	ctx := context.Background()

	refs := []ingress.SecretRef{
		{Namespace: "default", Name: "web-tls", Hosts: []string{"web.test"}},
		{Namespace: "default", Name: "opaque-tls", Hosts: []string{"opaque.test"}},
		{Namespace: "default", Name: "garbage-tls", Hosts: []string{"garbage.test"}},
		{Namespace: "default", Name: "absent-tls", Hosts: []string{"absent.test"}},
	}
	h.installCertificates(ctx, refs)

	t.Run("valid kubernetes.io/tls secret installed for its hosts", func(t *testing.T) {
		c, ok := h.certs.Certificate("web.test")
		if !ok {
			t.Fatal("certificate for web.test must be installed")
		}
		want, err := ingress.ParseKeyPair("want", certPEM, keyPEM)
		if err != nil {
			t.Fatalf("parse reference pair: %v", err)
		}
		if !bytes.Equal(c.Certificate[0], want.Certificate[0]) {
			t.Error("installed certificate does not match the secret's pair")
		}
	})
	t.Run("non-tls secret type rejected by name", func(t *testing.T) {
		if _, ok := h.certs.Certificate("opaque.test"); ok {
			t.Error("a Secret whose type is not kubernetes.io/tls must be rejected")
		}
		if !strings.Contains(buf.String(), "default/opaque-tls") {
			t.Error("the rejection must be logged with the secret NAME")
		}
	})
	t.Run("parse failure logged with the name, never the data", func(t *testing.T) {
		if _, ok := h.certs.Certificate("garbage.test"); ok {
			t.Error("an unparseable pair must not be installed")
		}
		logs := buf.String()
		if !strings.Contains(logs, "default/garbage-tls") {
			t.Error("the parse failure must carry the secret NAME")
		}
		if strings.Contains(logs, "not a certificate") || strings.Contains(logs, "not a key") {
			t.Error("the parse failure must NEVER echo secret bytes into the log")
		}
	})
	t.Run("missing secret skipped; other hosts still served", func(t *testing.T) {
		if _, ok := h.certs.Certificate("absent.test"); ok {
			t.Error("a missing secret must leave its host unserved")
		}
		if _, ok := h.certs.Certificate("web.test"); !ok {
			t.Error("per-host isolation: a bad ref must not degrade a good one")
		}
	})
	t.Run("rotation is an event-driven re-read", func(t *testing.T) {
		newCert, newKey := makeKeyPair(t, "web.test")
		rotated := tlsSecret("default", "web-tls", corev1.SecretTypeTLS, newCert, newKey)
		if _, err := cs.CoreV1().Secrets("default").Update(ctx, rotated, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("rotate secret: %v", err)
		}
		h.installCertificates(ctx, refs) // the next reconcile callback
		c, ok := h.certs.Certificate("web.test")
		if !ok {
			t.Fatal("certificate for web.test must survive rotation")
		}
		want, err := ingress.ParseKeyPair("want", newCert, newKey)
		if err != nil {
			t.Fatalf("parse rotated pair: %v", err)
		}
		if !bytes.Equal(c.Certificate[0], want.Certificate[0]) {
			t.Error("rotation must re-read the secret: the OLD certificate is still served")
		}
	})
}

// classIngress builds a minimal Ingress with the given class pointer.
func classIngress(namespace, name string, class *string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       networkingv1.IngressSpec{IngressClassName: class},
	}
}

// TestIngressClassAndStatus pins the M10.3 provisioning + status contract: the
// k3sm IngressClass (controller k3sm.io/ingress) and the canonical
// kube-system/k3sm-ingress LoadBalancer Service (ports 80+443, svclb-ignored,
// selector-less) are provisioned idempotently, and the status writer stamps
// the node IP onto Ingresses of the OWN class only — and only while the
// listeners are actually bound (never before), with the LB Service advertised
// only in the production 80/443 posture (never from the high-port mode).
func TestIngressClassAndStatus(t *testing.T) {
	own, foreign := ClassName, "nginx"
	cs := fake.NewClientset(
		classIngress("default", "mine", &own),
		classIngress("default", "theirs", &foreign),
		classIngress("default", "classless", nil),
	)
	h, _ := newTestHost(t, cs, 80, 443)
	ctx := context.Background()

	t.Run("ingressclass provisioned idempotently", func(t *testing.T) {
		for range 2 { // second call must tolerate AlreadyExists
			if err := h.ensureIngressClass(ctx); err != nil {
				t.Fatalf("ensureIngressClass: %v", err)
			}
		}
		ic, err := cs.NetworkingV1().IngressClasses().Get(ctx, ClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get ingressclass: %v", err)
		}
		if ic.Spec.Controller != ControllerName {
			t.Errorf("controller = %q, want %q", ic.Spec.Controller, ControllerName)
		}
	})
	t.Run("canonical loadbalancer service provisioned idempotently", func(t *testing.T) {
		for range 2 {
			if err := h.ensureLBService(ctx); err != nil {
				t.Fatalf("ensureLBService: %v", err)
			}
		}
		svc, err := cs.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get service: %v", err)
		}
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			t.Errorf("type = %q, want LoadBalancer (the declaring subject for the privileged bind)", svc.Spec.Type)
		}
		ports := map[int32]bool{}
		for _, p := range svc.Spec.Ports {
			ports[p.Port] = true
		}
		if !ports[80] || !ports[443] {
			t.Errorf("ports = %v, want 80+443 declared", svc.Spec.Ports)
		}
		if svc.Labels[svclb.IgnoreLabel] != "true" {
			t.Error("the canonical service must carry the svclb ignore label (the ingress server owns its listeners)")
		}
		if len(svc.Spec.Selector) != 0 {
			t.Error("the canonical service must be selector-less (the in-process server IS the implementation)")
		}
	})
	t.Run("no status while not serving (bind-then-advertise)", func(t *testing.T) {
		h.syncStatus(ctx)
		ing, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
		if len(ing.Status.LoadBalancer.Ingress) != 0 {
			t.Error("status must NOT be written before the listeners are bound")
		}
	})
	t.Run("status written for own class only, plus the LB service", func(t *testing.T) {
		h.serving.Store(true)
		h.syncStatus(ctx)
		ing, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
		if len(ing.Status.LoadBalancer.Ingress) != 1 || ing.Status.LoadBalancer.Ingress[0].IP != testAdvertiseAddr.String() {
			t.Errorf("own-class ingress status = %+v, want the ADVERTISE address", ing.Status.LoadBalancer.Ingress)
		}
		for _, name := range []string{"theirs", "classless"} {
			other, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, name, metav1.GetOptions{})
			if len(other.Status.LoadBalancer.Ingress) != 0 {
				t.Errorf("ingress %q (not our class) must never be touched", name)
			}
		}
		svc, _ := cs.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
		if len(svc.Status.LoadBalancer.Ingress) != 1 || svc.Status.LoadBalancer.Ingress[0].IP != testAdvertiseAddr.String() {
			t.Errorf("canonical LB service status = %+v, want the ADVERTISE address (production 80/443 posture)", svc.Status.LoadBalancer.Ingress)
		}
	})
	t.Run("high-port mode never advertises the 80/443 LB service", func(t *testing.T) {
		cs2 := fake.NewClientset()
		h2, _ := newTestHost(t, cs2, 8080, 8443)
		if err := h2.ensureLBService(ctx); err != nil {
			t.Fatalf("ensureLBService: %v", err)
		}
		h2.serving.Store(true)
		h2.syncStatus(ctx)
		svc, _ := cs2.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("the high-port mode must not claim the LB service's declared 80/443 (honesty rule)")
		}
	})
}

// TestIngressHostNewValidationAsymmetry pins the B116 construction contract,
// which had NO test before: BindAddr must be valid but MAY be the wildcard, while
// AdvertiseAddr may be the ZERO Addr.
//
// The relaxation is load-bearing beyond legibility. New's old IsUnspecified
// rejection was the FOURTH wildcard rejection on this path, and the one that
// fires FIRST — it would have disabled the ingress at construction, before
// darwin-net's relaxed ingress.NewServer was ever reached, while compiling green.
func TestIngressHostNewValidationAsymmetry(t *testing.T) {
	tests := []struct {
		name      string
		bind      netip.Addr
		advertise netip.Addr
		wantErr   bool
	}{
		{"wildcard bind accepted", netip.AddrFrom4([4]byte{}), testAdvertiseAddr, false},
		{"specific bind accepted", netip.MustParseAddr("192.168.7.20"), testAdvertiseAddr, false},
		{"zero bind rejected", netip.Addr{}, testAdvertiseAddr, true},
		{"zero advertise accepted (serve, never advertise)", netip.AddrFrom4([4]byte{}), netip.Addr{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{
				Client:        fake.NewClientset(),
				BindAddr:      tt.bind,
				AdvertiseAddr: tt.advertise,
				HTTPPort:      80,
				Logger:        slog.New(slog.DiscardHandler),
			})
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("New err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
	if _, err := New(Config{Client: fake.NewClientset(), BindAddr: netip.AddrFrom4([4]byte{})}); err == nil {
		t.Error("New must still reject a config that enables no listener")
	}
}

// TestIngressHostDerivationFailureServesButNeverAdvertises is gate assert (c) for
// the ingress half: with no derivable advertise address the host still SERVES
// (h.serving is true — the listeners are bound) and writes exactly ZERO status
// entries. len == 0, deliberately not "!= 127.0.0.1": the zero netip.Addr
// stringifies to "invalid IP", which a negative check would let through.
func TestIngressHostDerivationFailureServesButNeverAdvertises(t *testing.T) {
	own := ClassName
	cs := fake.NewClientset(classIngress("default", "mine", &own))
	h, err := New(Config{
		Client:        cs,
		BindAddr:      testBindAddr,
		AdvertiseAddr: netip.Addr{}, // the derivation failed
		PodCIDR:       testPodCIDR,
		HTTPPort:      80,
		HTTPSPort:     443,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := h.ensureLBService(ctx); err != nil {
		t.Fatalf("ensureLBService: %v", err)
	}
	h.serving.Store(true) // the listeners ARE bound; only the address is missing
	h.syncStatus(ctx)

	ing, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
	if n := len(ing.Status.LoadBalancer.Ingress); n != 0 {
		t.Errorf("ingress status has %d entries (%+v), want 0", n, ing.Status.LoadBalancer.Ingress)
	}
	svc, _ := cs.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
	if n := len(svc.Status.LoadBalancer.Ingress); n != 0 {
		t.Errorf("canonical LB service status has %d entries (%+v), want 0", n, svc.Status.LoadBalancer.Ingress)
	}
}

// TestIngressHostRetractsWhenNotServing pins the retraction path this host did
// NOT have before B116: syncStatus returned early on !serving and never removed
// anything, so after "ingress bind retries exhausted" every k3sm-class Ingress
// kept advertising a dead address forever.
//
// The named case is the one a mechanical rename could not have caught: a stale
// 127.0.0.1 entry (and a previous podCIDR's derived .1) is dropped even though it
// is NEITHER the bind nor the advertise address; a foreign entry is never touched,
// and neither is a foreign-class Ingress.
func TestIngressHostRetractsWhenNotServing(t *testing.T) {
	own, foreign := ClassName, "nginx"
	mine := classIngress("default", "mine", &own)
	mine.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
		{IP: testAdvertiseAddr.String()}, // the current advertise address
		{IP: "127.0.0.1"},                // the pre-B116 default
		{IP: "100.64.0.1"},               // a previous enrollment's derived .1
		{IP: "203.0.113.9"},              // foreign: never ours
	}
	theirs := classIngress("default", "theirs", &foreign)
	theirs.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: testAdvertiseAddr.String()}}
	cs := fake.NewClientset(mine, theirs)

	h, _ := newTestHost(t, cs, 80, 443)
	ctx := context.Background()
	if err := h.ensureLBService(ctx); err != nil {
		t.Fatalf("ensureLBService: %v", err)
	}
	// Advertise first (serving), then lose the listeners.
	h.serving.Store(true)
	h.syncStatus(ctx)
	svc, _ := cs.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
	if len(svc.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("precondition: the canonical LB service must be advertised while serving, got %+v", svc.Status.LoadBalancer.Ingress)
	}

	h.serving.Store(false)
	h.syncStatus(ctx)

	got, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != "203.0.113.9" {
		t.Errorf("own-class ingress status = %+v, want ONLY the foreign entry (advertise, loopback and the previous derived .1 all retracted)", got.Status.LoadBalancer.Ingress)
	}
	other, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "theirs", metav1.GetOptions{})
	if len(other.Status.LoadBalancer.Ingress) != 1 {
		t.Errorf("a foreign-class ingress must never be touched, got %+v", other.Status.LoadBalancer.Ingress)
	}
	svc, _ = cs.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
	if len(svc.Status.LoadBalancer.Ingress) != 0 {
		t.Errorf("canonical LB service status = %+v, want retracted once the listeners are gone", svc.Status.LoadBalancer.Ingress)
	}
}

// TestIngressHostDoesNotRetractBeforeItEverAdvertises pins the first-advertise
// latch. serving is FALSE at construction and THREE independent producers can
// kick the status writer before the first bind completes (the Watcher's
// OnTLSSecrets callback, countingBinder, serveLoop), so retracting on a bare
// !serving observation transiently EMPTIES status.loadBalancer on every
// k3sm-class Ingress and on the canonical LB Service at each ordinary
// `launchctl kickstart -k` — a self-inflicted outage window on a healthy
// restart.
//
// The invariant: a !serving observation retracts only once this run has actually
// advertised, i.e. only when live listeners were genuinely LOST. The "never bound
// at all" case is covered instead by serveLoop's definitive terminal retraction
// (unconditional, once the bounded retry is exhausted), so a stale entry from a
// previous run is still cleaned up — just not from a pre-bind kick.
func TestIngressHostDoesNotRetractBeforeItEverAdvertises(t *testing.T) {
	own := ClassName
	mine := classIngress("default", "mine", &own)
	// What a healthy previous run left behind, and what this run will re-advertise.
	mine.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: testAdvertiseAddr.String()}}
	cs := fake.NewClientset(mine)
	h, _ := newTestHost(t, cs, 80, 443)
	ctx := context.Background()
	if err := h.ensureLBService(ctx); err != nil {
		t.Fatalf("ensureLBService: %v", err)
	}

	// The pre-first-bind kicks: serving is still false.
	h.syncStatus(ctx)
	h.syncStatus(ctx)

	got, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != testAdvertiseAddr.String() {
		t.Errorf("ingress status = %+v, want the previous advertisement UNTOUCHED: a kick before the first bind must not empty it (restart flapping)", got.Status.LoadBalancer.Ingress)
	}

	// Once the listeners bind, the latch arms and a genuine loss retracts.
	h.serving.Store(true)
	h.syncStatus(ctx)
	if !h.advertised.Load() {
		t.Fatal("the latch must arm on the first successful advertise")
	}
	h.serving.Store(false)
	h.syncStatus(ctx)
	got, _ = cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 0 {
		t.Errorf("ingress status = %+v, want retracted once live listeners are LOST", got.Status.LoadBalancer.Ingress)
	}
}

// TestIngressHostRetractsImmediatelyWithNoDerivableAddress pins the other side of
// the latch: an invalid AdvertiseAddr is STATIC for the whole run — this host will
// never advertise — so there is no race to protect against and a stale entry from
// a previous run is retracted on the first sync, latch or no latch.
func TestIngressHostRetractsImmediatelyWithNoDerivableAddress(t *testing.T) {
	own := ClassName
	mine := classIngress("default", "mine", &own)
	mine.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
		{IP: "100.64.0.1"}, {IP: "203.0.113.9"},
	}
	cs := fake.NewClientset(mine)
	h, err := New(Config{
		Client:        cs,
		BindAddr:      testBindAddr,
		AdvertiseAddr: netip.Addr{},
		PodCIDR:       testPodCIDR,
		HTTPPort:      80,
		HTTPSPort:     443,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	h.syncStatus(ctx) // not serving, never advertised — but the address is undecidable

	got, _ := cs.NetworkingV1().Ingresses("default").Get(ctx, "mine", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != "203.0.113.9" {
		t.Errorf("ingress status = %+v, want the stale pod-space entry retracted and the foreign one kept", got.Status.LoadBalancer.Ingress)
	}
}
