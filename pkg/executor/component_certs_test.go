package executor

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/certs"
)

// loadComponentClientCert loads a per-component kubeconfig and returns its single
// AuthInfo, the named cluster, and the parsed client-certificate leaf.
func loadComponentClientCert(t *testing.T, path string) (*clientcmdapi.AuthInfo, *clientcmdapi.Cluster, *x509.Certificate) {
	t.Helper()
	cfg, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load kubeconfig %s: %v", path, err)
	}
	cl := cfg.Clusters["k3sm"]
	if cl == nil {
		t.Fatalf("kubeconfig %s missing the k3sm cluster", path)
	}
	if cfg.CurrentContext == "" || cfg.Contexts[cfg.CurrentContext] == nil {
		t.Fatalf("kubeconfig %s has no current context", path)
	}
	user := cfg.AuthInfos[cfg.Contexts[cfg.CurrentContext].AuthInfo]
	if user == nil {
		t.Fatalf("kubeconfig %s missing its AuthInfo", path)
	}
	if len(user.ClientCertificateData) == 0 {
		t.Fatalf("kubeconfig %s must authenticate with a client certificate, not a token", path)
	}
	if user.Token != "" {
		t.Fatalf("kubeconfig %s must NOT carry a static bearer token", path)
	}
	block, _ := pem.Decode(user.ClientCertificateData)
	if block == nil {
		t.Fatalf("kubeconfig %s client-certificate-data is not PEM", path)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert in %s: %v", path, err)
	}
	return user, cl, leaf
}

// TestSchedulerKubeconfigSystemSchedulerIdentity proves the scheduler authenticates as
// its OWN identity: provisionComponentCerts writes a kube-scheduler.kubeconfig whose
// client cert is CN=system:kube-scheduler, ExtKeyUsage ClientAuth, signed by the SIGNING
// CA (= the apiserver --client-ca-file), and schedulerArgs points the scheduler at THAT
// kubeconfig — not the system:masters admin kubeconfig. The apiserver's bootstrap
// system:kube-scheduler ClusterRoleBinding then constrains it (the k3s model).
func TestSchedulerKubeconfigSystemSchedulerIdentity(t *testing.T) {
	t.Parallel()
	wd := t.TempDir()
	s := NewSupervised(Config{WorkDir: wd, APIServerPort: 6444})
	if err := s.provisionComponentCerts(); err != nil {
		t.Fatalf("provision component certs: %v", err)
	}
	h, err := certs.EnsureHierarchy(wd) // idempotent — loads the hierarchy provision created
	if err != nil {
		t.Fatalf("load hierarchy: %v", err)
	}

	path := schedulerKubeconfigPath(wd)
	_, cl, leaf := loadComponentClientCert(t, path)

	if leaf.Subject.CommonName != schedulerCN {
		t.Errorf("scheduler client cert CN = %q, want %q", leaf.Subject.CommonName, schedulerCN)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("scheduler client cert must be signed by the signing CA: %v", err)
	}
	if !hasClientAuthEKU(leaf) {
		t.Errorf("scheduler client cert must carry ExtKeyUsageClientAuth, got %v", leaf.ExtKeyUsage)
	}
	// Single-node (no ServingCertFile): the co-located loopback component skips server
	// verification, matching the admin kubeconfig's single-node posture.
	if !cl.InsecureSkipTLSVerify {
		t.Errorf("single-node scheduler kubeconfig should use insecure-skip-tls-verify (self-signed loopback apiserver)")
	}

	// The scheduler is actually WIRED to its own kubeconfig, not the admin one.
	if got := flagValue(schedulerArgs(s.cfg), "--kubeconfig"); got != path {
		t.Errorf("scheduler --kubeconfig = %q, want the per-component %q", got, path)
	}
	if got := flagValue(schedulerArgs(s.cfg), "--kubeconfig"); got == kubeconfigPath(wd) {
		t.Errorf("scheduler must NOT use the system:masters admin kubeconfig %q", kubeconfigPath(wd))
	}
	for _, f := range []string{"--authentication-kubeconfig", "--authorization-kubeconfig"} {
		if got := flagValue(schedulerArgs(s.cfg), f); got != path {
			t.Errorf("scheduler %s = %q, want %q", f, got, path)
		}
	}
}

// TestKCMKubeconfigSystemKCMIdentity proves the controller-manager authenticates as its
// OWN identity (CN=system:kube-controller-manager, signed by the signing CA) via its own
// kubeconfig, AND that --use-service-account-credentials=true is set so each controller
// runs under its system:controller:<name> SA (required — the system:kube-controller-
// manager ClusterRole is not a superset of the per-controller roles).
func TestKCMKubeconfigSystemKCMIdentity(t *testing.T) {
	t.Parallel()
	wd := t.TempDir()
	s := NewSupervised(Config{WorkDir: wd, APIServerPort: 6444})
	if err := s.provisionComponentCerts(); err != nil {
		t.Fatalf("provision component certs: %v", err)
	}
	h, err := certs.EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("load hierarchy: %v", err)
	}

	path := controllerManagerKubeconfigPath(wd)
	_, _, leaf := loadComponentClientCert(t, path)

	if leaf.Subject.CommonName != controllerManagerCN {
		t.Errorf("KCM client cert CN = %q, want %q", leaf.Subject.CommonName, controllerManagerCN)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("KCM client cert must be signed by the signing CA: %v", err)
	}
	if !hasClientAuthEKU(leaf) {
		t.Errorf("KCM client cert must carry ExtKeyUsageClientAuth, got %v", leaf.ExtKeyUsage)
	}

	args := controllerManagerArgs(s.cfg)
	if got := flagValue(args, "--kubeconfig"); got != path {
		t.Errorf("KCM --kubeconfig = %q, want the per-component %q", got, path)
	}
	if got := flagValue(args, "--kubeconfig"); got == kubeconfigPath(wd) {
		t.Errorf("KCM must NOT use the system:masters admin kubeconfig %q", kubeconfigPath(wd))
	}
	if !hasArg(args, "--use-service-account-credentials=true") {
		t.Errorf("KCM must set --use-service-account-credentials=true so controllers use their own SAs, args=%v", args)
	}
}

// TestComponentKubeconfigClusterCAVerifiedWhenServingCertSet proves the mesh posture:
// when the apiserver presents a cluster-CA-signed serving cert (ServingCertFile set), the
// per-component kubeconfig pins the cluster CA (certificate-authority-data) instead of
// insecure-skip — so the component verifies the apiserver, not just authenticates to it.
func TestComponentKubeconfigClusterCAVerifiedWhenServingCertSet(t *testing.T) {
	t.Parallel()
	wd := t.TempDir()
	s := NewSupervised(Config{
		WorkDir:         wd,
		APIServerPort:   6444,
		ServingCertFile: "/some/apiserver.crt",
		ServingKeyFile:  "/some/apiserver.key",
	})
	if err := s.provisionComponentCerts(); err != nil {
		t.Fatalf("provision component certs: %v", err)
	}
	h, err := certs.EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("load hierarchy: %v", err)
	}
	for _, path := range []string{schedulerKubeconfigPath(wd), controllerManagerKubeconfigPath(wd)} {
		_, cl, _ := loadComponentClientCert(t, path)
		if cl.InsecureSkipTLSVerify {
			t.Errorf("%s must NOT skip TLS verification when the apiserver serves a cluster-CA cert", path)
		}
		if string(cl.CertificateAuthorityData) != string(h.Cluster.CertPEM) {
			t.Errorf("%s must pin the cluster CA for server verification", path)
		}
	}
}

// hasClientAuthEKU reports whether cert carries the ClientAuth extended key usage.
func hasClientAuthEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
