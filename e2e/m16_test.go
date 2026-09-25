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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
)

// M16 webhook-delivery criteria — the two tests the M16 plan's R14 names, and the
// only part of the m16.2 rung that can be proven WITHOUT the upstream serving
// chart. They stand on their own: the chart's operator ships both a validating
// admission webhook and a CRD conversion webhook referenced BY SERVICE, and on
// k3sm both of those calls leave the embedded kube-apiserver, cross darwin-net's
// userspace Service proxy, and land inside a Linux micro-VM. Nothing upstream
// exercises that path, and nothing else in this suite does either.
//
// WHAT EACH TEST PROVES
//
//	TestAdmissionWebhookDeliveryThroughProxy   the apiserver DELIVERS an
//	    AdmissionReview to a `service:`-referenced ValidatingWebhookConfiguration
//	    whose backend is a `runtimeClassName: vm` Pod, and honours the answer. The
//	    rejection is matched on a sentinel only the in-guest handler emits, so a
//	    Fail-policy webhook that was never reached (which rejects with the
//	    apiserver's own "failed calling webhook" text) cannot pass this test.
//
//	TestConversionWebhookDeliveryThroughProxy  the apiserver DELIVERS a
//	    ConversionReview to the same kind of backend for a CRD whose two versions
//	    have DISJOINT schemas. Its two cases are the apiserver's two conversion
//	    CALL SITES, not a symmetry: with v1beta1 as the storage version, reading a
//	    stored object as v1alpha1 is the READ-path call, and creating through
//	    v1alpha1 is the WRITE-path call. Only the webhook can bridge v1beta1
//	    `spec.greeting` and v1alpha1 `spec.message`, so a field carrying the
//	    handler's transform is a delivery proof, not a no-op round-trip.
//
// THE PATH EXERCISED. `k3sm server` runs the embedded apiserver with
// --service-cluster-ip-range 10.43.0.0/16 (pkg/executor/supervised.go:579), and
// kube-apiserver's default (non-aggregator-routing) service resolver hands the
// webhook client the Service's ClusterIP. On a Mac there is no kube-proxy and no
// iptables: that ClusterIP:443 socket exists only because darwin-net's userspace
// proxy bound a lo0 alias for it (darwin-net pkg/proxy/proxy.go:646 openListener —
// net.Listen on clusterIP:port, never :port). The proxy then splices to the vm
// Pod's live guest transport, which the provider learns from runtimed's guest
// lease (runtimed pkg/runtime/guestlease.go:61 defaultGuestLeasePoll = 5s, fed
// into the proxy by pkg/provider/transportoverride.go:190 observeTransport). Both
// tests dial ClusterIP:443 from the TEST PROCESS before registering any webhook,
// which is simultaneously the traversal proof and the wait that absorbs that lease
// lag — otherwise the first admission call races the transport override and a
// Fail-policy webhook turns the race into a flake.
//
// TLS. The serving pair is minted in-test (mintWebhookServingPair, which does NOT
// borrow pkg/certs) carrying DNS SANs <svc>.<ns>.svc and
// <svc>.<ns>.svc.cluster.local, and the same PEM is the clientConfig.caBundle.
// That works because the apiserver's webhook client sets the TLS ServerName to the
// service hostname and only then dials the resolved ClusterIP:
// k8s.io/apiserver@v0.36.5/pkg/util/webhook/client.go:187 builds
// serverName = <name>.<namespace>.svc, :193-195 assigns it to
// cfg.TLSClientConfig.ServerName, and :202-210 substitutes the resolved endpoint
// address at dial time only — so the certificate is verified against the hostname,
// never against the VIP. (The ClusterIP is added as an IP SAN anyway: it costs one
// field, it is not load-bearing given that finding, and it keeps the cert honest
// for any client that dials the address without SNI.)
//
// RUN IT
//
//	KUBECONFIG=<path> CGO_ENABLED=1 go test -tags e2e \
//	  -run '^Test(Admission|Conversion)WebhookDeliveryThroughProxy$' \
//	  -timeout 20m ./e2e/ -v
//
// These carry no TestM16 prefix by design (R14 fixes the names), so the future
// hack/acceptance/m16.sh m16.2 rung selects them with that -run pattern.

// webhookProbeImage is the vm-Pod backend image, DIGEST-PINNED. It is the spike's
// python:3.12-alpine (hack/spike/m16/lib.sh:74) with the mutable tag nailed to the
// index digest it resolved to, because a tag is a moving target and a gate that
// silently changes its own backend is not a gate.
//
// The digest is the multi-arch INDEX digest; the `vm` path selects its linux/arm64
// child manifest (sha256:6c251882dcd56a1b1f20e174a09465f68a6b85c1d066becd954889099177ec34,
// platform {architecture: arm64, os: linux, variant: v8}) from it. Resolved
// 2026-09-17 straight from the registry, anonymous pull token, no daemon:
//
//	TOKEN=$(curl -sS 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull' \
//	  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
//	curl -sS -D - -o index.json -H "Authorization: Bearer $TOKEN" \
//	  -H 'Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json' \
//	  https://registry-1.docker.io/v2/library/python/manifests/3.12-alpine
//	# docker-content-digest: sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a
//
// $K3SM_M16_WEBHOOK_IMAGE overrides it (a mirror, or a newer pin under test).
const webhookProbeImage = "docker.io/library/python:3.12-alpine@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a"

// webhookRefusalSentinel is emitted ONLY by the in-guest handler, in the status
// message of a denied AdmissionReview. Asserting on it is what makes the admission
// test a DELIVERY test: an unreachable failurePolicy: Fail webhook also rejects the
// create, but with the apiserver's own "failed calling webhook" text, which does
// not contain this string.
const webhookRefusalSentinel = "b286: refused by the vm-backed webhook"

// webhookProbeAnswer is the only spec.answer the handler admits.
const webhookProbeAnswer = 42

// webhookContainerPort is the in-guest HTTPS port; the Service maps 443 onto it.
const webhookContainerPort int32 = 8443

// webhookRunLabel labels the per-run namespace so the ValidatingWebhookConfiguration
// can carry a namespaceSelector for it — a second containment ring around the
// unique API group, so a failurePolicy: Fail webhook can never see an object
// outside this test's own namespace.
const webhookRunLabel = "e2e.k3sm.io/b286-run"

// webhookServerPy is the whole backend: a stdlib-only HTTPS server that answers
// three paths — GET anything (the test's own reachability probe), POST /validate
// (AdmissionReview) and POST /convert (ConversionReview). It rides a ConfigMap, so
// the image stays a stock interpreter and nothing has to be built or published.
//
// The conversion is deliberately LOSSY-LOOKING in one direction: v1beta1
// spec.greeting becomes v1alpha1 spec.message = "converted:<greeting>". No
// apiserver-side default, no schema and no client can produce that prefix, so a
// v1alpha1 read carrying it proves this handler ran.
const webhookServerPy = `
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SENTINEL = os.environ["B286_SENTINEL"]
ANSWER = int(os.environ["B286_ANSWER"])
PORT = int(os.environ["B286_PORT"])
CERT = os.environ["B286_CERT"]
KEY = os.environ["B286_KEY"]
PREFIX = "converted:"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("webhook: " + (fmt % args), flush=True)

    def _reply(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(200, b"ok", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            review = json.loads(raw or b"{}")
        except ValueError:
            self._reply(400, b'{"error":"malformed review"}')
            return
        req = review.get("request") or {}
        if self.path.startswith("/validate"):
            resp = self.validate(req)
        elif self.path.startswith("/convert"):
            resp = self.convert(req)
        else:
            self._reply(404, b'{"error":"no such path"}')
            return
        out = {
            "apiVersion": review.get("apiVersion") or "admission.k8s.io/v1",
            "kind": review.get("kind") or "AdmissionReview",
            "response": resp,
        }
        self._reply(200, json.dumps(out).encode("utf-8"))

    def validate(self, req):
        uid = req.get("uid") or ""
        spec = ((req.get("object") or {}).get("spec")) or {}
        answer = spec.get("answer")
        if answer == ANSWER:
            return {"uid": uid, "allowed": True}
        return {
            "uid": uid,
            "allowed": False,
            "status": {"code": 403, "message": "%s (answer=%s)" % (SENTINEL, answer)},
        }

    def convert(self, req):
        uid = req.get("uid") or ""
        desired = req.get("desiredAPIVersion") or ""
        converted = []
        for obj in req.get("objects") or []:
            spec = dict(obj.get("spec") or {})
            greeting = spec.pop("greeting", None)
            message = spec.pop("message", None)
            if desired.endswith("/v1alpha1"):
                if greeting is not None:
                    spec["message"] = PREFIX + greeting
                elif message is not None:
                    spec["message"] = message
            elif desired.endswith("/v1beta1"):
                if message is not None:
                    if message.startswith(PREFIX):
                        spec["greeting"] = message[len(PREFIX):]
                    else:
                        spec["greeting"] = "unconverted:" + message
                elif greeting is not None:
                    spec["greeting"] = greeting
            obj["spec"] = spec
            obj["apiVersion"] = desired
            converted.append(obj)
        return {
            "uid": uid,
            "result": {"status": "Success"},
            "convertedObjects": converted,
        }


tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls_ctx.load_cert_chain(CERT, KEY)
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.socket = tls_ctx.wrap_socket(server.socket, server_side=True)
print("webhook: serving https on 0.0.0.0:%d" % PORT, flush=True)
server.serve_forever()
`

// webhookBackend is a live, reachable webhook server: a vm Pod behind a ClusterIP
// Service whose serving certificate the test minted, proven answering on
// https://<clusterIP>:443 before it is handed to any webhook configuration.
type webhookBackend struct {
	suffix    string // the per-run uniqueness token every object name carries
	ns        string
	svc       string
	clusterIP string
	caPEM     []byte // the self-signed serving cert, doubling as the caBundle
	group     string // the test-only API group this run's CRDs live in
}

// hostname is the name the apiserver's webhook client puts in SNI and verifies the
// certificate against (pkg/util/webhook/client.go:187).
func (b *webhookBackend) hostname() string { return b.svc + "." + b.ns + ".svc" }

// webhookImage returns the backend image: the pinned digest, or $K3SM_M16_WEBHOOK_IMAGE.
func webhookImage() string {
	if v := os.Getenv("K3SM_M16_WEBHOOK_IMAGE"); v != "" {
		return v
	}
	return webhookProbeImage
}

// runSuffix returns a per-run token derived from the test name plus 4 random bytes.
// EVERY object this file creates — namespace, Service, Secret, ConfigMap, Pod,
// ValidatingWebhookConfiguration, both CRDs and the API group itself — carries it,
// so two runs (or a run against a cluster holding a previous run's wreckage) can
// never collide, and a leaked cluster-scoped object can never match a later run's
// resources.
func runSuffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("read random suffix: %v", err)
	}
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, strings.TrimPrefix(t.Name(), "Test"))
	if len(name) > 12 {
		name = name[:12]
	}
	return name + "-" + hex.EncodeToString(b[:])
}

// cleanupClusterScoped registers a t.Cleanup that foreground-deletes a
// CLUSTER-SCOPED object and waits, bounded, for it to be gone. It is registered
// BEFORE the create it protects, so a create that panics — or one that succeeds and
// is then abandoned by a t.Fatalf — still cleans up.
//
// It reports a failure when the object outlives the wait, because the two objects
// it guards are exactly the two that poison a rerun: a failurePolicy: Fail
// ValidatingWebhookConfiguration whose backend namespace is gone rejects every
// matching create with an unreachable-webhook error, and a surviving CRD keeps its
// stale conversion webhook wired to a dead Service.
func cleanupClusterScoped(t *testing.T, kind, name string, del func(context.Context, metav1.DeleteOptions) error, get func(context.Context) error) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		policy := metav1.DeletePropagationForeground
		if err := del(ctx, metav1.DeleteOptions{PropagationPolicy: &policy}); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("cleanup: delete %s %s: %v", kind, name, err)
			return
		}
		if !pollUntil(2*time.Minute, func() bool { return apierrors.IsNotFound(get(ctx)) }) {
			t.Errorf("cleanup: %s %s still present 2m after a foreground delete — a rerun would meet stale state", kind, name)
		}
	})
}

// startWebhookBackend brings up one run's whole backend and returns it only once
// the test process has itself completed a TLS handshake and an HTTP GET against
// https://<clusterIP>:443.
//
// Cleanup shape: the namespace cleanup is registered BEFORE the namespace is
// created, and every other object here is namespaced, so one registration covers
// them all — a create that panics leaves nothing behind. Cluster-scoped objects are
// registered individually by the callers via cleanupClusterScoped.
func startWebhookBackend(t *testing.T, c *Cluster) *webhookBackend {
	t.Helper()
	ctx := context.Background()
	suffix := runSuffix(t)
	b := &webhookBackend{
		suffix: suffix,
		ns:     "b286-" + suffix,
		svc:    "webhook-" + suffix,
		group:  "webhookprobe-" + suffix + ".k3sm.io",
	}

	t.Cleanup(func() {
		policy := metav1.DeletePropagationForeground
		err := c.Client.CoreV1().Namespaces().Delete(context.Background(), b.ns, metav1.DeleteOptions{PropagationPolicy: &policy})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("cleanup: delete namespace %s: %v", b.ns, err)
			return
		}
		// Not a failure when it is slow: a vm Pod's guest has to shut down first,
		// and the namespace name carries this run's random suffix, so a lingering
		// one cannot be met by any future run.
		if !pollUntil(3*time.Minute, func() bool {
			_, err := c.Client.CoreV1().Namespaces().Get(context.Background(), b.ns, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}) {
			t.Logf("cleanup: namespace %s still terminating after 3m (vm guest shutdown); it is uniquely named, so no rerun can meet it", b.ns)
		}
	})
	if _, err := c.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: b.ns, Labels: map[string]string{webhookRunLabel: suffix}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %s: %v", b.ns, err)
	}

	// The Service comes FIRST so its ClusterIP is known before the certificate is
	// minted (the IP SAN below) and before the Secret that carries it.
	svc, err := c.Client.CoreV1().Services(b.ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: b.svc, Namespace: b.ns},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{"app": b.svc},
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromInt32(webhookContainerPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create service %s/%s: %v", b.ns, b.svc, err)
	}
	b.clusterIP = svc.Spec.ClusterIP
	if b.clusterIP == "" || b.clusterIP == corev1.ClusterIPNone {
		t.Fatalf("service %s/%s got no ClusterIP (%q) — the webhook has nothing to be resolved to", b.ns, b.svc, b.clusterIP)
	}
	t.Logf("service %s/%s ClusterIP %s (from the apiserver's --service-cluster-ip-range)", b.ns, b.svc, b.clusterIP)

	certPEM, keyPEM := mintWebhookServingPair(t, b)
	b.caPEM = certPEM

	if _, err := c.Client.CoreV1().Secrets(b.ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook-tls-" + suffix, Namespace: b.ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create tls secret: %v", err)
	}
	if _, err := c.Client.CoreV1().ConfigMaps(b.ns).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook-script-" + suffix, Namespace: b.ns},
		Data:       map[string]string{"webhook.py": webhookServerPy},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create script configmap: %v", err)
	}

	if _, err := c.Client.CoreV1().Pods(b.ns).Create(ctx, webhookPod(b), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create webhook pod: %v", err)
	}
	pod := c.WaitPodReady(t, b.ns, b.svc, 8*time.Minute)
	t.Logf("webhook pod %s/%s Ready on node %s (image %s)", b.ns, pod.Name, pod.Spec.NodeName, webhookImage())

	addrs := c.WaitServiceReadyEndpoints(t, b.ns, b.svc, 3*time.Minute)
	t.Logf("EndpointSlice for %s/%s has Ready endpoints %v", b.ns, b.svc, addrs)

	waitWebhookReachable(t, b, 2*time.Minute)
	return b
}

// mintWebhookServingPair returns the PEM cert/key for the backend: a self-signed
// ECDSA P-256 leaf good for 24 hours, whose SANs are the two names a
// service-referenced webhook can be verified under plus the ClusterIP as an IP SAN
// (see the file comment — belt and braces, not required, since the apiserver sets
// ServerName to the hostname).
//
// It is minted HERE rather than through pkg/certs.SelfSignedServing on purpose.
// That helper's doc comment scopes it to the single-node, dev and standalone
// `k3sm node` kubelet serving path and says in as many words that using it
// elsewhere is a defect. A test fixture borrowing it would make that scope
// statement false, and would couple this file to SAN and lifetime choices made for
// a different consumer — choices that could be tightened for that consumer's sake
// and silently break a webhook backend nobody was thinking about.
//
// The certificate is its own trust anchor: the same PEM goes into every caBundle
// here, and Go accepts a self-signed leaf that is present in the verifier's root
// pool, which is why no CA bit is set and no separate issuer is minted.
func mintWebhookServingPair(t *testing.T, b *webhookBackend) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate serving key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	ips := []net.IP{}
	if ip := net.ParseIP(b.clusterIP); ip != nil {
		ips = append(ips, ip)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "b286-webhook"},
		// Backdated a few minutes for clock skew between this process, the
		// apiserver and the guest; the lifetime itself is 24h, which outlives any
		// run of this suite by a wide margin and expires long before a leaked
		// Secret could matter.
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{b.hostname(), b.hostname() + ".cluster.local"},
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create serving certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal serving key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// webhookPod is the backend Pod. The four fields that look optional and are not are
// the ones examples/temporal/temporal-dev-server.yaml names: runtimeClassName: vm
// (without it a Linux image has no meaning on the native path), the darwin
// nodeSelector (no node is ever kubernetes.io/os=linux, and a ValidatingAdmissionPolicy
// denies a Pod that omits the key), the k3sm.io/provider:NoSchedule toleration
// (every node carries that taint), and binding 0.0.0.0 rather than localhost (the
// Service proxy dials the guest from OUTSIDE it).
//
// There is deliberately NO readiness probe: httpGet/tcpSocket probes are dialed at
// the published pod IP, which for a vm Pod is an identity rather than a live
// address. The test's own TLS dial in waitWebhookReachable is the readiness signal.
//
// Resources size the guest: on the vm path the memory limits are summed into the
// guest's RAM ceiling and the CPU limits into whole vCPUs.
func webhookPod(b *webhookBackend) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.svc,
			Namespace: b.ns,
			Labels:    map[string]string{"app": b.svc},
		},
		Spec: corev1.PodSpec{
			RuntimeClassName: ptr("vm"),
			NodeSelector:     map[string]string{"kubernetes.io/os": "darwin"},
			Tolerations: []corev1.Toleration{{
				Key:      "k3sm.io/provider",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}},
			Containers: []corev1.Container{{
				Name:    "webhook",
				Image:   webhookImage(),
				Command: []string{"python3", "/srv/webhook.py"},
				Env: []corev1.EnvVar{
					{Name: "B286_SENTINEL", Value: webhookRefusalSentinel},
					{Name: "B286_ANSWER", Value: fmt.Sprintf("%d", webhookProbeAnswer)},
					{Name: "B286_PORT", Value: fmt.Sprintf("%d", webhookContainerPort)},
					{Name: "B286_CERT", Value: "/tls/" + corev1.TLSCertKey},
					{Name: "B286_KEY", Value: "/tls/" + corev1.TLSPrivateKeyKey},
				},
				Ports: []corev1.ContainerPort{{Name: "https", ContainerPort: webhookContainerPort}},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "script", MountPath: "/srv", ReadOnly: true},
					{Name: "tls", MountPath: "/tls", ReadOnly: true},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("1Gi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("1Gi"),
					},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "script", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "webhook-script-" + b.suffix},
				}}},
				{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
					SecretName: "webhook-tls-" + b.suffix,
				}}},
			},
		},
	}
}

// waitWebhookReachable dials https://<clusterIP>:443 from the TEST PROCESS, with a
// client that trusts only the minted certificate and sets ServerName to the service
// hostname — the same two things the apiserver's webhook client does. On this host
// that ClusterIP socket exists only as darwin-net's lo0-alias listener, so a
// successful handshake plus GET is the proxy-traversal proof; and because it also
// waits out the vm guest-lease poll, it removes the race that would otherwise make
// the first admission call flaky.
func waitWebhookReachable(t *testing.T, b *webhookBackend, timeout time.Duration) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.caPEM) {
		t.Fatal("minted certificate is not usable as a trust root")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: b.hostname(),
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	url := "https://" + net.JoinHostPort(b.clusterIP, "443") + "/healthz"
	var last string
	ok := pollUntil(timeout, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			last = err.Error()
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		last = fmt.Sprintf("status %d body %q", resp.StatusCode, body)
		return resp.StatusCode == http.StatusOK
	})
	if !ok {
		t.Fatalf("GET %s (ServerName %s) never succeeded within %s — the Service proxy never carried the test to the vm backend; last: %s",
			url, b.hostname(), timeout, last)
	}
	t.Logf("reached the vm-backed webhook through the Service proxy at %s (%s)", url, last)
}

// apiextensionsClient builds the CRD client against the same rest.Config as Cluster.
func apiextensionsClient(t *testing.T, c *Cluster) apiextensionsclient.Interface {
	t.Helper()
	cl, err := apiextensionsclient.NewForConfig(c.Config)
	if err != nil {
		t.Fatalf("build apiextensions client: %v", err)
	}
	return cl
}

// dynamicClient builds the unstructured client used to drive the test-only CRs.
func dynamicClient(t *testing.T, c *Cluster) dynamic.Interface {
	t.Helper()
	cl, err := dynamic.NewForConfig(c.Config)
	if err != nil {
		t.Fatalf("build dynamic client: %v", err)
	}
	return cl
}

// createCRD registers the cleanup, creates the CRD, and returns once it is
// Established and its names are accepted.
func createCRD(t *testing.T, cl apiextensionsclient.Interface, crd *apiextensionsv1.CustomResourceDefinition) {
	t.Helper()
	ctx := context.Background()
	name := crd.Name
	crds := cl.ApiextensionsV1().CustomResourceDefinitions()
	cleanupClusterScoped(t, "CustomResourceDefinition", name,
		func(ctx context.Context, o metav1.DeleteOptions) error { return crds.Delete(ctx, name, o) },
		func(ctx context.Context) error {
			_, err := crds.Get(ctx, name, metav1.GetOptions{})
			return err
		})
	if _, err := crds.Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create CRD %s: %v", name, err)
	}
	var last string
	ok := pollUntil(2*time.Minute, func() bool {
		got, err := crds.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			last = err.Error()
			return false
		}
		established, named := false, false
		for _, cond := range got.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1.Established:
				established = cond.Status == apiextensionsv1.ConditionTrue
			case apiextensionsv1.NamesAccepted:
				named = cond.Status == apiextensionsv1.ConditionTrue
			}
		}
		last = fmt.Sprintf("Established=%v NamesAccepted=%v", established, named)
		return established && named
	})
	if !ok {
		t.Fatalf("CRD %s never became Established within 2m (last %s)", name, last)
	}
}

// TestAdmissionWebhookDeliveryThroughProxy proves the embedded kube-apiserver
// delivers an AdmissionReview to a `service:`-referenced validating webhook whose
// backend is a `runtimeClassName: vm` Pod, through darwin-net's userspace Service
// proxy — see the file comment for the path, the TLS ServerName finding
// (k8s.io/apiserver@v0.36.5/pkg/util/webhook/client.go:187,193-195) and the run
// command.
//
// CONTAINMENT. The webhook's rules match ONE resource in ONE API group that exists
// only for this run (webhookprobe-<suffix>.k3sm.io/probes), and its
// namespaceSelector matches only this run's namespace. No cluster-internal object —
// a system Pod, the VK node's own registration, an RBAC object — can ever be
// submitted to a failurePolicy: Fail webhook whose backend is a test Pod.
func TestAdmissionWebhookDeliveryThroughProxy(t *testing.T) {
	c := Up(t)
	ctx := context.Background()

	b := startWebhookBackend(t, c)
	createCRD(t, apiextensionsClient(t, c), probeCRD(b))

	vwcName := "b286-probe-" + b.suffix
	vwcs := c.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	cleanupClusterScoped(t, "ValidatingWebhookConfiguration", vwcName,
		func(ctx context.Context, o metav1.DeleteOptions) error { return vwcs.Delete(ctx, vwcName, o) },
		func(ctx context.Context) error {
			_, err := vwcs.Get(ctx, vwcName, metav1.GetOptions{})
			return err
		})
	if _, err := vwcs.Create(ctx, probeWebhookConfig(b, vwcName), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ValidatingWebhookConfiguration %s: %v", vwcName, err)
	}

	dyn := dynamicClient(t, c)
	gvr := schema.GroupVersionResource{Group: b.group, Version: "v1", Resource: "probes"}

	// (1) A bad Probe is REJECTED, and the message carries the sentinel only the
	// in-guest handler emits. The poll is for webhook-configuration propagation
	// (the apiserver reads the configuration through an informer), NOT for the
	// verdict: every attempt uses a FRESH name, so the one that is rejected is the
	// one assertion (3) then proves absent.
	var rejectedName, lastErr string
	attempt := 0
	rejected := pollUntil(2*time.Minute, func() bool {
		attempt++
		name := fmt.Sprintf("bad-%s-%d", b.suffix, attempt)
		_, err := dyn.Resource(gvr).Namespace(b.ns).Create(ctx, probeObject(b, name, 7), metav1.CreateOptions{})
		if err == nil {
			// Admitted: the configuration has not reached the admission chain yet.
			// The object is deleted rather than left behind, and a failure to delete
			// it is LOGGED, not swallowed: it would leave a Probe this test never
			// meant to persist, and it is the first thing worth knowing if the
			// namespace later refuses to finish terminating.
			lastErr = "create was ADMITTED (webhook configuration not yet in effect)"
			if derr := dyn.Resource(gvr).Namespace(b.ns).Delete(ctx, name, metav1.DeleteOptions{}); derr != nil {
				t.Logf("delete prematurely admitted Probe %s/%s: %v", b.ns, name, derr)
			}
			return false
		}
		lastErr = err.Error()
		if strings.Contains(lastErr, webhookRefusalSentinel) {
			rejectedName = name
			return true
		}
		return false
	})
	if !rejected {
		t.Fatalf("a Probe with spec.answer=7 was never rejected with the in-guest sentinel %q within 2m; last outcome: %s\n"+
			"(an apiserver-side \"failed calling webhook\" error here means the AdmissionReview never reached the vm backend)",
			webhookRefusalSentinel, lastErr)
	}
	t.Logf("rejected as expected: %s", lastErr)

	// (2) A good Probe is ADMITTED by the same webhook — so the rejection above was
	// a decision the handler made, not a blanket failure of the path.
	goodName := "good-" + b.suffix
	if _, err := dyn.Resource(gvr).Namespace(b.ns).Create(ctx, probeObject(b, goodName, webhookProbeAnswer), metav1.CreateOptions{}); err != nil {
		t.Fatalf("Probe with spec.answer=%d was rejected, want admitted: %v", webhookProbeAnswer, err)
	}
	if _, err := dyn.Resource(gvr).Namespace(b.ns).Get(ctx, goodName, metav1.GetOptions{}); err != nil {
		t.Fatalf("get admitted Probe %s/%s: %v", b.ns, goodName, err)
	}

	// (3) The rejected object does not exist: a denied admission never persists.
	if _, err := dyn.Resource(gvr).Namespace(b.ns).Get(ctx, rejectedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("rejected Probe %s/%s: want NotFound, got %v", b.ns, rejectedName, err)
	}
}

// probeCRD is the test-only CRD the validating webhook guards: group
// webhookprobe-<suffix>.k3sm.io, kind Probe, a single served+storage version v1.
// A run-unique group is what keeps a failurePolicy: Fail webhook from ever being
// consulted for anything the cluster itself depends on.
func probeCRD(b *webhookBackend) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "probes." + b.group},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: b.group,
			Scope: apiextensionsv1.NamespaceScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: "probes", Singular: "probe", Kind: "Probe", ListKind: "ProbeList",
			},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"spec": {
								Type: "object",
								Properties: map[string]apiextensionsv1.JSONSchemaProps{
									"answer": {Type: "integer"},
								},
							},
						},
					},
				},
			}},
		},
	}
}

// probeObject builds a Probe with the given spec.answer.
func probeObject(b *webhookBackend, name string, answer int64) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"answer": answer},
	}}
	u.SetAPIVersion(b.group + "/v1")
	u.SetKind("Probe")
	u.SetNamespace(b.ns)
	u.SetName(name)
	return u
}

// probeWebhookConfig is the ValidatingWebhookConfiguration under test. Every field
// that narrows it is load-bearing: the rule names one group/resource that exists
// only for this run, the namespaceSelector names only this run's namespace, and
// failurePolicy: Fail is what makes a NON-delivered review visible as a rejection
// the sentinel assertion then refuses to accept.
func probeWebhookConfig(b *webhookBackend, name string) *admissionregistrationv1.ValidatingWebhookConfiguration {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "probes." + b.group,
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service: &admissionregistrationv1.ServiceReference{
					Namespace: b.ns,
					Name:      b.svc,
					Path:      ptr("/validate"),
					Port:      ptr(int32(443)),
				},
				CABundle: b.caPEM,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				// CREATE only, and that is a teardown invariant, not a minimalism
				// preference. Matching Update or Delete would put this Fail-policy
				// webhook in the path of the CRD finalizer's own instance deletes
				// during cleanup, by which time the backend Pod and its namespace are
				// going away: the finalizer's deletes would fail against an
				// unreachable webhook, the CRD would never finish deleting, and the
				// namespace would wedge in Terminating. Everything this test asserts
				// is observable on CREATE, so nothing is bought by widening it.
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{b.group},
					APIVersions: []string{"v1"},
					Resources:   []string{"probes"},
					Scope:       ptr(admissionregistrationv1.NamespacedScope),
				},
			}},
			NamespaceSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{webhookRunLabel: b.suffix}},
			FailurePolicy:           ptr(admissionregistrationv1.Fail),
			MatchPolicy:             ptr(admissionregistrationv1.Equivalent),
			SideEffects:             ptr(admissionregistrationv1.SideEffectClassNone),
			TimeoutSeconds:          ptr(int32(20)),
			AdmissionReviewVersions: []string{"v1"},
		}},
	}
}

// TestConversionWebhookDeliveryThroughProxy proves the embedded kube-apiserver
// delivers a ConversionReview to a `service:`-referenced conversion webhook backed
// by a `runtimeClassName: vm` Pod, through darwin-net's userspace Service proxy —
// the same path, TLS finding and run command as the admission test (see the file
// comment).
//
// TWO CALL SITES, NOT TWO DIRECTIONS. v1beta1 is the storage version, so the two
// cases below are not mirror images of one another; each exercises exactly one of
// the apiserver's two conversion call sites, and neither exercises both.
//
//   - The FORWARD case creates a v1beta1 object, which is already the storage
//     version and so is written with NO conversion call at all, and then reads it
//     as v1alpha1. That read is the READ-path conversion.
//   - The REVERSE case creates through v1alpha1, which must be converted on its
//     way into storage: that create is the WRITE-path conversion. The v1beta1 read
//     that checks the result is of the storage version and needs no conversion.
//
// WHY IT CANNOT PASS WITHOUT DELIVERY. The CRD's two versions have DISJOINT
// schemas: v1beta1 (served + storage) has spec.greeting, v1alpha1 (served only) has
// spec.message. Nothing in the apiserver can map one onto the other — no default,
// no schema rule, no client-side round-trip — and an unconverted field is PRUNED
// against the reading version's schema, so a field carrying the handler's
// "converted:" transform can only have come from the handler inside the guest.
func TestConversionWebhookDeliveryThroughProxy(t *testing.T) {
	c := Up(t)

	b := startWebhookBackend(t, c)
	createCRD(t, apiextensionsClient(t, c), greetingCRD(b))

	dyn := dynamicClient(t, c)
	beta := schema.GroupVersionResource{Group: b.group, Version: "v1beta1", Resource: "greetings"}
	alpha := schema.GroupVersionResource{Group: b.group, Version: "v1alpha1", Resource: "greetings"}

	// FORWARD, the READ-path call site: the create needs no conversion (v1beta1 IS
	// storage), so the v1alpha1 read is the only place the webhook can have run.
	forwardName := "fwd-" + b.suffix
	greeting := "hello-" + b.suffix
	createGreeting(t, dyn, beta, greetingObject(b, "v1beta1", forwardName, "greeting", greeting))
	got := getGreetingField(t, dyn, alpha, b.ns, forwardName, "message")
	if want := "converted:" + greeting; got != want {
		t.Fatalf("v1alpha1 read of %s/%s: spec.message = %q, want %q — the ConversionReview did not reach the vm backend",
			b.ns, forwardName, got, want)
	}
	t.Logf("v1beta1 spec.greeting=%q read back as v1alpha1 spec.message=%q", greeting, got)

	// REVERSE, the WRITE-path call site: the create through v1alpha1 is converted on
	// its way into storage, and the v1beta1 read that checks it needs no conversion.
	// The handler strips its own prefix, so the assertion is on a value the write
	// never contained and no read-path transform could have introduced.
	reverseName := "rev-" + b.suffix
	bare := "hola-" + b.suffix
	createGreeting(t, dyn, alpha, greetingObject(b, "v1alpha1", reverseName, "message", "converted:"+bare))
	got = getGreetingField(t, dyn, beta, b.ns, reverseName, "greeting")
	if got != bare {
		t.Fatalf("v1beta1 read of %s/%s: spec.greeting = %q, want %q — the reverse ConversionReview did not reach the vm backend",
			b.ns, reverseName, got, bare)
	}
	t.Logf("v1alpha1 spec.message=%q read back as v1beta1 spec.greeting=%q", "converted:"+bare, got)
}

// greetingCRD is the two-version CRD whose conversion runs in the guest. v1beta1 is
// served + storage with spec.greeting; v1alpha1 is served with spec.message. The
// webhook clientConfig points at the same Service the admission test uses, on
// /convert, with the same minted caBundle.
func greetingCRD(b *webhookBackend) *apiextensionsv1.CustomResourceDefinition {
	specOf := func(field string) apiextensionsv1.CustomResourceValidation {
		return apiextensionsv1.CustomResourceValidation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"spec": {
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							field: {Type: "string"},
						},
					},
				},
			},
		}
	}
	betaSchema, alphaSchema := specOf("greeting"), specOf("message")
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "greetings." + b.group},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: b.group,
			Scope: apiextensionsv1.NamespaceScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: "greetings", Singular: "greeting", Kind: "Greeting", ListKind: "GreetingList",
			},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1beta1", Served: true, Storage: true, Schema: &betaSchema},
				{Name: "v1alpha1", Served: true, Storage: false, Schema: &alphaSchema},
			},
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{
					ClientConfig: &apiextensionsv1.WebhookClientConfig{
						Service: &apiextensionsv1.ServiceReference{
							Namespace: b.ns,
							Name:      b.svc,
							Path:      ptr("/convert"),
							Port:      ptr(int32(443)),
						},
						CABundle: b.caPEM,
					},
					ConversionReviewVersions: []string{"v1"},
				},
			},
		},
	}
}

// greetingObject builds a Greeting in the named version carrying one spec field.
func greetingObject(b *webhookBackend, version, name, field, value string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{field: value},
	}}
	u.SetAPIVersion(b.group + "/" + version)
	u.SetKind("Greeting")
	u.SetNamespace(b.ns)
	u.SetName(name)
	return u
}

// createGreeting creates the object, polling briefly because a just-Established
// CRD's endpoint can 404 until the apiserver's handler picks it up.
func createGreeting(t *testing.T, dyn dynamic.Interface, gvr schema.GroupVersionResource, obj *unstructured.Unstructured) {
	t.Helper()
	ctx := context.Background()
	var last string
	ok := pollUntil(time.Minute, func() bool {
		_, err := dyn.Resource(gvr).Namespace(obj.GetNamespace()).Create(ctx, obj.DeepCopy(), metav1.CreateOptions{})
		if err == nil {
			return true
		}
		last = err.Error()
		return false
	})
	if !ok {
		t.Fatalf("create %s %s/%s: %s", gvr.Version, obj.GetNamespace(), obj.GetName(), last)
	}
}

// getGreetingField reads the object in the named version and returns spec.<field>.
func getGreetingField(t *testing.T, dyn dynamic.Interface, gvr schema.GroupVersionResource, ns, name, field string) string {
	t.Helper()
	got, err := dyn.Resource(gvr).Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s %s/%s: %v", gvr.Version, ns, name, err)
	}
	v, found, err := unstructured.NestedString(got.Object, "spec", field)
	if err != nil {
		t.Fatalf("read spec.%s of %s %s/%s: %v", field, gvr.Version, ns, name, err)
	}
	if !found {
		t.Fatalf("%s read of %s/%s has no spec.%s — the conversion webhook produced %v",
			gvr.Version, ns, name, field, got.Object["spec"])
	}
	return v
}
