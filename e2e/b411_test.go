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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

// B411 — the apiserver aggregation layer's request-header trust, proven against a
// live kube-apiserver on the rig. Run by hack/acceptance/B411.sh under K3SM_LAB=1 on
// the server Mac, which sets:
//
//	B411_WORK_DIR     the server's work dir (default /var/lib/k3sm/server)
//	B411_SERVER_NODE  the server's node name; the backend is pinned there so the
//	                  aggregator's dial never crosses the server-to-worker Service
//	                  path (recorded RED separately), which would read as a B411 defect.
//
// Files the server keeps 0600 (the CA keys, the proxy key) are read through
// `sudo -n cat` into memory when this account cannot open them: nothing is
// written anywhere, and the forged certificates below live only in this process.

const (
	b411Group   = "b411.test.k3sm.io"
	b411Version = "v1alpha1"
	b411Port    = 8443
)

// b411WorkDir is the server work dir the assertions read the PKI from.
func b411WorkDir() string {
	if d := os.Getenv("B411_WORK_DIR"); d != "" {
		return d
	}
	return "/var/lib/k3sm/server"
}

// readHostFile reads a server file, through `sudo -n cat` when this account may not
// open it. The bytes stay in memory.
func readHostFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err == nil {
		return b
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("read %s: %v", path, err)
	}
	out, serr := exec.Command("sudo", "-n", "/bin/cat", path).Output()
	if serr != nil {
		t.Fatalf("read %s: %v (and sudo -n cat: %v)", path, err, serr)
	}
	return out
}

// pemPins returns the pin of every CERTIFICATE block in bundle.
func pemPins(t *testing.T, bundle []byte) []string {
	t.Helper()
	var pins []string
	for {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			return pins
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		pin, err := certs.CertPin(pem.EncodeToMemory(block))
		if err != nil {
			t.Fatalf("pin a trusted CA: %v", err)
		}
		pins = append(pins, pin)
	}
}

// TestB411_ExtensionAPIServerAuthenticationCarriesRequestHeaderCA proves the
// apiserver publishes the request-header trust k3s publishes: exactly one CA in
// requestheader-client-ca-file, and it is this server's (a second one would be a
// second impersonation root, a finding to investigate, never noise); the one allowed
// name; and the three header names.
func TestB411_ExtensionAPIServerAuthenticationCarriesRequestHeaderCA(t *testing.T) {
	c := Up(t)
	localPin, err := certs.CertPin(readHostFile(t, certs.RequestHeaderCACertPath(b411WorkDir())))
	if err != nil {
		t.Fatalf("this server's request-header CA: %v", err)
	}
	want := map[string]string{
		"requestheader-allowed-names":        `["system:auth-proxy"]`,
		"requestheader-username-headers":     `["X-Remote-User"]`,
		"requestheader-group-headers":        `["X-Remote-Group"]`,
		"requestheader-extra-headers-prefix": `["X-Remote-Extra-"]`,
	}
	var cm *corev1.ConfigMap
	var last string
	// The trust controller syncs on a loop: poll, bounded.
	ok := pollUntil(2*time.Minute, func() bool {
		got, err := c.Client.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "extension-apiserver-authentication", metav1.GetOptions{})
		if err != nil {
			last = err.Error()
			return false
		}
		cm = got
		if _, ok := got.Data["requestheader-client-ca-file"]; !ok {
			last = "no requestheader-client-ca-file key yet"
			return false
		}
		return true
	})
	if !ok {
		t.Fatalf("kube-system/extension-apiserver-authentication never carried requestheader-client-ca-file within 2m: %s", last)
	}
	pins := pemPins(t, []byte(cm.Data["requestheader-client-ca-file"]))
	if len(pins) != 1 || pins[0] != localPin {
		t.Errorf("requestheader-client-ca-file trusts %v, want exactly this server's request-header CA [%s]", pins, localPin)
	}
	for key, val := range want {
		if got := cm.Data[key]; got != val {
			t.Errorf("%s = %q, want %q", key, got, val)
		}
	}
	if _, set := cm.Data["requestheader-uid-headers"]; set {
		t.Errorf("requestheader-uid-headers is set (%q); k3s sets none", cm.Data["requestheader-uid-headers"])
	}
}

// b411Backend is the native echo backend behind a ClusterIP Service.
type b411Backend struct {
	webhookBackend
}

// startB411Backend runs b411-echo as a native pod pinned to the server node, behind
// a ClusterIP Service, and returns it only once the TEST PROCESS has reached it
// through the ClusterIP: a failure there is the native-pod Service proxy path, and is
// reported as that rather than as the aggregation layer.
func startB411Backend(t *testing.T, c *Cluster) *b411Backend {
	t.Helper()
	ctx := context.Background()
	node := os.Getenv("B411_SERVER_NODE")
	if node == "" {
		t.Fatal("B411_SERVER_NODE is unset: run via hack/acceptance/B411.sh, which pins the backend to the server node")
	}
	suffix := runSuffix(t)
	b := &b411Backend{webhookBackend{suffix: suffix, ns: "b411-" + suffix, svc: "echo-" + suffix}}
	t.Cleanup(func() {
		policy := metav1.DeletePropagationForeground
		if err := c.Client.CoreV1().Namespaces().Delete(context.Background(), b.ns, metav1.DeleteOptions{PropagationPolicy: &policy}); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("cleanup: delete namespace %s: %v", b.ns, err)
		}
	})
	if _, err := c.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: b.ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %s: %v", b.ns, err)
	}
	svc, err := c.Client.CoreV1().Services(b.ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: b.svc, Namespace: b.ns},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{"app": b.svc},
			Ports:    []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt32(b411Port), Protocol: corev1.ProtocolTCP}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	b.clusterIP = svc.Spec.ClusterIP
	certPEM, keyPEM := mintWebhookServingPair(t, &b.webhookBackend)
	b.caPEM = certPEM
	if _, err := c.Client.CoreV1().Secrets(b.ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-" + suffix, Namespace: b.ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create tls secret: %v", err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: b.svc, Namespace: b.ns, Labels: map[string]string{"app": b.svc}},
		Spec: corev1.PodSpec{
			NodeName:     node,
			NodeSelector: map[string]string{"kubernetes.io/os": "darwin"},
			Tolerations:  []corev1.Toleration{{Key: "k3sm.io/provider", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
			Containers: []corev1.Container{{
				Name:         "echo",
				Image:        "native",
				Command:      []string{helperBin(t, "b411-echo"), "-addr", fmt.Sprintf(":%d", b411Port), "-cert", "/tls/tls.crt", "-key", "/tls/tls.key", "-group-version", b411Group + "/" + b411Version},
				Ports:        []corev1.ContainerPort{{Name: "https", ContainerPort: b411Port}},
				VolumeMounts: []corev1.VolumeMount{{Name: "tls", MountPath: "/tls", ReadOnly: true}},
			}},
			Volumes: []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "tls-" + suffix}}}},
		},
	}
	if _, err := c.Client.CoreV1().Pods(b.ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create echo pod: %v", err)
	}
	c.WaitPodReady(t, b.ns, b.svc, 3*time.Minute)
	c.WaitServiceReadyEndpoints(t, b.ns, b.svc, 2*time.Minute)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.caPEM)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: b.hostname(), MinVersion: tls.VersionTLS12},
	}}
	url := "https://" + net.JoinHostPort(b.clusterIP, "443") + "/healthz"
	var last string
	if !pollUntil(2*time.Minute, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			last = err.Error()
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		last = resp.Status
		return resp.StatusCode == http.StatusOK
	}) {
		t.Fatalf("NOT A B411 RESULT: the test process never reached the native echo backend through its ClusterIP %s (the native-pod Service proxy path); last: %s", url, last)
	}
	return b
}

// TestB411_AggregatorPresentsProxyClientCert registers an APIService for a native
// backend and proves the aggregator calls it with the front-proxy client cert (CN
// system:auth-proxy, chaining to the request-header CA) and the caller's identity in
// X-Remote-User.
func TestB411_AggregatorPresentsProxyClientCert(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	rhCA := readHostFile(t, certs.RequestHeaderCACertPath(b411WorkDir()))
	b := startB411Backend(t, c)

	dyn := dynamicClient(t, c)
	gvr := schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}
	name := b411Version + "." + b411Group
	// Registered AFTER the namespace cleanup, so it runs FIRST: a failed run never
	// leaves an APIService that degrades discovery.
	cleanupClusterScoped(t, "APIService", name,
		func(ctx context.Context, o metav1.DeleteOptions) error { return dyn.Resource(gvr).Delete(ctx, name, o) },
		func(ctx context.Context) error {
			_, err := dyn.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
			return err
		})
	_ = dyn.Resource(gvr).Delete(ctx, name, metav1.DeleteOptions{})
	apisvc := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiregistration.k8s.io/v1",
		"kind":       "APIService",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"group":                b411Group,
			"version":              b411Version,
			"service":              map[string]any{"namespace": b.ns, "name": b.svc, "port": int64(443)},
			"caBundle":             b.caPEM,
			"groupPriorityMinimum": int64(1000),
			"versionPriority":      int64(15),
		},
	}}
	if _, err := dyn.Resource(gvr).Create(ctx, apisvc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create APIService %s: %v", name, err)
	}
	var cond string
	if !pollUntil(3*time.Minute, func() bool {
		got, err := dyn.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			cond = err.Error()
			return false
		}
		conds, _, _ := unstructured.NestedSlice(got.Object, "status", "conditions")
		for _, raw := range conds {
			m, _ := raw.(map[string]any)
			if m["type"] == "Available" {
				cond = fmt.Sprintf("Available=%v reason=%v message=%v", m["status"], m["reason"], m["message"])
				return m["status"] == "True"
			}
		}
		cond = "no Available condition yet"
		return false
	}) {
		t.Fatalf("APIService %s never became Available within 3m: %s", name, cond)
	}

	review, err := c.Client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("SelfSubjectReview as the admin: %v", err)
	}
	caller := review.Status.UserInfo.Username
	body, err := c.Client.Discovery().RESTClient().Get().AbsPath("/apis/" + b411Group + "/" + b411Version + "/whoami").DoRaw(ctx)
	if err != nil {
		t.Fatalf("GET through the aggregator: %v", err)
	}
	var seen struct {
		ClientCertPEM string   `json:"clientCertPEM"`
		User          string   `json:"user"`
		Groups        []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &seen); err != nil {
		t.Fatalf("decode the backend's answer %q: %v", body, err)
	}
	if seen.User != caller {
		t.Errorf("X-Remote-User = %q, want the caller %q", seen.User, caller)
	}
	block, _ := pem.Decode([]byte(seen.ClientCertPEM))
	if block == nil {
		t.Fatalf("the aggregator presented no client certificate to the backend")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != certs.ProxyClientCN {
		t.Errorf("the aggregator's client cert CN = %q, want %q", leaf.Subject.CommonName, certs.ProxyClientCN)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rhCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the aggregator's client cert does not chain to this server's request-header CA: %v", err)
	}
}

// probeConfig is the admin's rest.Config with every credential replaced by the given
// client cert and, when headers is non-nil, those request headers on every call.
func probeConfig(base *rest.Config, certPEM, keyPEM []byte, headers http.Header) *rest.Config {
	cfg := rest.AnonymousClientConfig(base)
	cfg.CertData, cfg.KeyData = certPEM, keyPEM
	if headers != nil {
		cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return roundTripFunc(func(r *http.Request) (*http.Response, error) {
				r = r.Clone(r.Context())
				for k, vs := range headers {
					for _, v := range vs {
						r.Header.Add(k, v)
					}
				}
				return rt.RoundTrip(r)
			})
		}
	}
	return cfg
}

// whoAmI returns the username kube-apiserver authenticated cfg as, or "" with the
// reason when the request was not authenticated (or not authorized to ask).
func whoAmI(t *testing.T, cfg *rest.Config) (string, string) {
	t.Helper()
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cs.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", err.Error()
	}
	return r.Status.UserInfo.Username, ""
}

// TestB411_ForgedFrontProxyRejected is the live negative at the component that
// enforces the boundary: kube-apiserver's request-header authenticator. A
// CN=system:auth-proxy cert from the signing CA or the cluster CA, sent with forged
// X-Remote-User/X-Remote-Group headers, is not authenticated as the forged user; the
// real proxy cert without headers is not authenticated as system:auth-proxy; and the
// real proxy cert WITH headers is authenticated as the forged user, which pins in a
// test what the plan states in prose: the proxy key is an impersonation credential.
// A --requestheader-client-ca-file pointing at the signing CA turns (a) red.
func TestB411_ForgedFrontProxyRejected(t *testing.T) {
	c := Up(t)
	wd := b411WorkDir()
	load := func(cert, key string) *certs.CA {
		ca, err := certs.LoadCA(readHostFile(t, cert), readHostFile(t, key))
		if err != nil {
			t.Fatalf("load %s: %v", cert, err)
		}
		return ca
	}
	forged := http.Header{"X-Remote-User": {"b411-probe"}, "X-Remote-Group": {"system:masters"}}

	for _, tc := range []struct {
		name string
		ca   *certs.CA
	}{
		{"(a) signing CA, CN=system:auth-proxy", load(certs.SigningCACertPath(wd), certs.SigningCAKeyPath(wd))},
		{"(b) cluster CA, CN=system:auth-proxy", load(certs.ClusterCACertPath(wd), certs.ClusterCAKeyPath(wd))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM, err := tc.ca.IssueClient(certs.ProxyClientCN, nil, 10*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			user, why := whoAmI(t, probeConfig(c.Config, certPEM, keyPEM, forged))
			if user == "b411-probe" {
				t.Fatalf("a %s cert with forged headers was authenticated as b411-probe: the request-header trust accepts a CA other than the request-header CA", tc.name)
			}
			t.Logf("authenticated as %q %s (the cert's own identity, or none)", user, why)
		})
	}

	proxyCert := readHostFile(t, executor.ProxyClientCertPath(wd))
	proxyKey := readHostFile(t, executor.ProxyClientKeyPath(wd))
	t.Run("(c) the real proxy cert without headers", func(t *testing.T) {
		user, why := whoAmI(t, probeConfig(c.Config, proxyCert, proxyKey, nil))
		if user == certs.ProxyClientCN {
			t.Fatalf("the proxy cert alone was authenticated as %s; it must be no x509 identity at kube-apiserver", user)
		}
		t.Logf("authenticated as %q %s", user, why)
	})
	t.Run("(d) the real proxy cert with headers impersonates", func(t *testing.T) {
		user, why := whoAmI(t, probeConfig(c.Config, proxyCert, proxyKey, forged))
		if user != "b411-probe" {
			t.Fatalf("the proxy cert with X-Remote-User was authenticated as %q (%s), want b411-probe: the request-header authenticator is not wired", user, why)
		}
	})
}
