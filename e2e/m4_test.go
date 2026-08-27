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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/rbac"
)

// defaultServerWorkDir is the root-posture control-plane state root (mirrors
// executor.DefaultWorkDir without importing the cgo/kine package into the e2e build).
// The signing CA + cluster CA live under <workDir>/tls; override via K3SM_WORK_DIR.
const defaultServerWorkDir = "/var/lib/k3sm/server"

// TestM4_RBACEnforced is the M4.1 capability gate (DESIGN §9 M4; docs/stockkitty-
// readiness.md → stockkitty-snapshot-manager). On a cluster running
// --authorization-mode=Node,RBAC + NodeRestriction it proves both halves of the flip:
//
//  1. a self-issued joined-worker identity (CN=system:node:<name>, O=system:nodes,
//     signed by the cluster's SIGNING CA) is AUTHORIZED for the datapath reads its
//     Service proxy / DNS resolver / mesh watcher need (services, endpointslices,
//     meshpeers — the pkg/rbac node-datapath ClusterRole), but is DENIED a non-granted
//     verb and a cross-node Node write (the Node authorizer + NodeRestriction);
//  2. a restricted ServiceAccount (the in-pod-kubectl reference SA) is AUTHORIZED for
//     its granted reads yet DENIED everything else (e.g. secrets).
//
// This is the integration/lab tier — it does not run in unit CI. The node-cert leg is
// skipped unless the cluster was brought up with the CA hierarchy + --client-ca-file
// (the multi-node trust path); the SA leg runs on any RBAC-enforcing cluster. The
// matching M4.1-a1 acceptance stays met:false (integration-pending) until this runs
// green against a live control plane.
func TestM4_RBACEnforced(t *testing.T) {
	c := Up(t) // admin (system:masters) client; skips if $KUBECONFIG is unset
	ctx := context.Background()

	t.Run("joined-worker system:node identity", func(t *testing.T) {
		nodeCS, ok := nodeIdentityClient(t)
		if !ok {
			t.Skip("no signing CA on disk (single-node-no-mesh bring-up) — the node-cert leg needs --client-ca-file wired; set K3SM_WORK_DIR to the multi-node server work dir")
		}

		// The datapath reads are AUTHORIZED (the node-datapath ClusterRole grant);
		// meshpeers especially can ONLY come from that ClusterRole, since the Node
		// authorizer knows nothing of CRDs. A non-granted verb is DENIED.
		for _, tc := range []struct {
			name string
			ra   authzv1.ResourceAttributes
			want bool
		}{
			{"list services", authzv1.ResourceAttributes{Verb: "list", Resource: "services"}, true},
			{"watch endpointslices", authzv1.ResourceAttributes{Verb: "watch", Group: "discovery.k8s.io", Resource: "endpointslices"}, true},
			{"list meshpeers", authzv1.ResourceAttributes{Verb: "list", Group: "net.k3sm.io", Resource: "meshpeers"}, true},
			{"create services (not granted)", authzv1.ResourceAttributes{Verb: "create", Resource: "services"}, false},
			{"list secrets (not granted)", authzv1.ResourceAttributes{Verb: "list", Resource: "secrets"}, false},
		} {
			if got := ssarAllowed(t, nodeCS, tc.ra); got != tc.want {
				t.Errorf("system:node SSAR %q: allowed=%v, want %v", tc.name, got, tc.want)
			}
		}

		// A cross-node Node write is denied by NODERESTRICTION ADMISSION -- not by the
		// Node authorizer. The stock system:node ClusterRole is bound to the whole
		// system:nodes group and grants patch/update on "nodes" with no per-name
		// scoping (a static ClusterRole cannot express "only your own node"), so
		// authorization ALLOWS this request; NodeRestriction is the control that
		// confines the identity to its own object (pkg/executor/supervised.go calls it
		// "the admission half of the Node authorizer").
		//
		// That distinction decides how this must be asserted. Admission only sees the
		// request once the target object EXISTS: Node's REST strategy sets
		// AllowCreateOnUpdate()==false, so patching a name nobody registered returns
		// NotFound from inside the registry's GuaranteedUpdate BEFORE admission runs.
		// Against a nonexistent node the check is therefore vacuous -- it would behave
		// identically with NodeRestriction switched off entirely. Create the foreign
		// node as admin so the write actually reaches admission.
		foreign := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "e2e-rbac-foreign"}}
		if _, err := c.Client.CoreV1().Nodes().Create(ctx, foreign, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create foreign node (admin): %v", err)
		}
		t.Cleanup(func() {
			_ = c.Client.CoreV1().Nodes().Delete(context.Background(), foreign.Name, metav1.DeleteOptions{})
		})

		_, err := nodeCS.CoreV1().Nodes().Patch(ctx, foreign.Name, types.StrategicMergePatchType,
			[]byte(`{"metadata":{"labels":{"k3sm.io/e2e":"x"}}}`), metav1.PatchOptions{})
		if !apierrors.IsForbidden(err) {
			t.Errorf("cross-node Node write: err = %v, want Forbidden (NodeRestriction admission)", err)
		}
	})

	t.Run("restricted ServiceAccount", func(t *testing.T) {
		ns, sa := rbac.ConformanceNamespace, rbac.ConformanceServiceAccount
		if _, err := c.Client.CoreV1().ServiceAccounts(ns).Create(ctx,
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create conformance SA %s/%s: %v", ns, sa, err)
		}
		tok, err := c.Client.CoreV1().ServiceAccounts(ns).CreateToken(ctx, sa,
			&authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{Audiences: []string{"https://kubernetes.default.svc.cluster.local"}}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("mint token for SA %s/%s: %v", ns, sa, err)
		}
		saCS := tokenClient(t, tok.Status.Token)

		// Granted by the in-pod reader RoleBinding pkg/rbac provisioned.
		if !ssarAllowed(t, saCS, authzv1.ResourceAttributes{Namespace: ns, Verb: "get", Resource: "pods"}) {
			t.Errorf("conformance SA must be AUTHORIZED to get pods in %s (in-pod reader grant)", ns)
		}
		// Not granted — default-deny must reject it.
		if ssarAllowed(t, saCS, authzv1.ResourceAttributes{Namespace: ns, Verb: "get", Resource: "secrets"}) {
			t.Errorf("conformance SA must be DENIED get secrets (not granted)")
		}
	})
}

// ssarAllowed asks the apiserver, AS the identity cs authenticates, whether ra is
// permitted (a SelfSubjectAccessReview — authoritative, side-effect-free).
func ssarAllowed(t *testing.T, cs kubernetes.Interface, ra authzv1.ResourceAttributes) bool {
	t.Helper()
	r, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(context.Background(),
		&authzv1.SelfSubjectAccessReview{Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &ra}},
		metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("SSAR(%s %s/%s): %v", ra.Verb, ra.Group, ra.Resource, err)
	}
	return r.Status.Allowed
}

// nodeIdentityClient mints a CN=system:node:e2e-rbac-fake, O=system:nodes client cert
// signed by the cluster's SIGNING CA (loaded from the server work dir, reusing
// pkg/certs + pkg/bootstrap) and returns a clientset authenticated as that joined-
// worker identity. ok is false when no signing CA is present (a single-node-no-mesh
// bring-up has no --client-ca-file, so node-cert auth is not wired) — the caller skips.
func nodeIdentityClient(t *testing.T) (kubernetes.Interface, bool) {
	t.Helper()
	wd := os.Getenv("K3SM_WORK_DIR")
	if wd == "" {
		wd = defaultServerWorkDir
	}
	if _, err := os.Stat(certs.SigningCACertPath(wd)); err != nil {
		return nil, false
	}
	h, err := certs.EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("load CA hierarchy from %s: %v", wd, err)
	}

	const nodeName, nodeIP = "e2e-rbac-fake", "127.0.0.1"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "system:node:" + nodeName, Organization: []string{"system:nodes"}},
		DNSNames:    []string{nodeName},
		IPAddresses: []net.IP{net.ParseIP(nodeIP)},
	}, key)
	if err != nil {
		t.Fatalf("create node CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse node CSR: %v", err)
	}
	certPEM, err := bootstrap.ApproveAndSignNodeCSR(h.Signing, csr, bootstrap.NodeIdentity{NodeName: nodeName, InternalIP: nodeIP}, time.Hour)
	if err != nil {
		t.Fatalf("sign node CSR: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal node key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	base, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatalf("load admin kubeconfig: %v", err)
	}
	cfg := rest.CopyConfig(base)
	cfg.BearerToken, cfg.BearerTokenFile = "", ""
	cfg.Username, cfg.Password = "", ""
	// Attach ONLY the client identity and keep the admin kubeconfig's
	// server-verification posture (what tokenClient below does for the same reason).
	// Replacing the whole struct with CAData: h.Cluster.CertPEM asserts that the
	// apiserver SERVES a cert issued by the cluster CA, which is not true of this
	// bring-up -- it serves a self-signed cert from --cert-dir, which is exactly why
	// the admin kubeconfig sets insecure-skip-tls-verify. That made the leg fail with
	// "x509: certificate signed by unknown authority" before it could test anything.
	//
	// Server-cert provenance is not what this leg is for: it proves how the apiserver
	// AUTHORIZES a system:node client identity. That identity -- the CA-signed cert
	// below -- is still fully exercised.
	cfg.TLSClientConfig.CAFile, cfg.TLSClientConfig.CAData = base.TLSClientConfig.CAFile, base.TLSClientConfig.CAData
	cfg.TLSClientConfig.Insecure = base.TLSClientConfig.Insecure
	cfg.TLSClientConfig.CertFile, cfg.TLSClientConfig.KeyFile = "", ""
	cfg.TLSClientConfig.CertData, cfg.TLSClientConfig.KeyData = certPEM, keyPEM
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build system:node client: %v", err)
	}
	return cs, true
}

// tokenClient returns a clientset authenticated with a bearer token (a minted SA
// token), reusing the admin kubeconfig's server-verification settings.
func tokenClient(t *testing.T, token string) kubernetes.Interface {
	t.Helper()
	base, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatalf("load admin kubeconfig: %v", err)
	}
	cfg := rest.CopyConfig(base)
	cfg.BearerToken = token
	cfg.BearerTokenFile = ""
	cfg.CertData, cfg.KeyData = nil, nil
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build SA token client: %v", err)
	}
	return cs
}
