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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// gateRegistry is an in-process registry standing in for a push gate: HTTPS
// under a certificate a throwaway cluster CA issued for registry-k3sm and
// 127.0.0.1, as both gates' certificates are.
type gateRegistry struct {
	port  int
	probe *authProbe
	caPEM []byte
}

func startGateRegistry(t *testing.T) gateRegistry {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "k3sm-cluster-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "registry-k3sm"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost", "registry-k3sm"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	probe := &authProbe{inner: registry.New(registry.Logger(log.New(io.Discard, "", 0)))}
	srv := httptest.NewUnstartedServer(probe)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	return gateRegistry{port: n, probe: probe, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
}

// clusterAPIFor points clusterRegistryClient at a fake apiserver that mints
// fakeBuilderTokenToken for k3sm-registry/builder and serves objs, with the
// gate registry's CA as the kubeconfig's cluster CA. It returns the token
// requests seen.
func clusterAPIFor(t *testing.T, g gateRegistry, objs ...runtime.Object) *int {
	t.Helper()
	cs := fake.NewClientset(objs...)
	minted := 0
	cs.PrependReactor("create", "serviceaccounts", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "token" || a.GetNamespace() != "k3sm-registry" {
			return false, nil, nil
		}
		minted++
		out, err := issue(a.(ktesting.CreateAction).GetObject().(*authnv1.TokenRequest).Spec)
		return true, out, err
	})
	prev := clusterRegistryClient
	clusterRegistryClient = func() (clusterRegistryAPI, error) {
		return clusterRegistryAPI{
			tokens: cs.CoreV1().ServiceAccounts("k3sm-registry"),
			slices: cs.DiscoveryV1().EndpointSlices("k3sm-registry"),
			caPEM:  g.caPEM,
		}, nil
	}
	t.Cleanup(func() { clusterRegistryClient = prev })
	return &minted
}

// TestPushUsesBuilderTokenFromKubeconfig is the gate: every write k3sm makes to
// the cluster registry presents a builder token minted through the caller's
// kubeconfig, over HTTPS verified against the kubeconfig's cluster CA, on the
// server (to the loopback gate the state record names) and on a worker (to the
// server's cluster address from the flat Service's EndpointSlice). The
// per-boot credential is not presented: the work dir holds none.
func TestPushUsesBuilderTokenFromKubeconfig(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("builder:"+fakeBuilderTokenToken))

	cases := []struct {
		name  string
		setup func(t *testing.T, g gateRegistry) (workDir string, minted *int)
	}{
		{"the server pushes to its loopback gate", func(t *testing.T, g gateRegistry) (string, *int) {
			minted := clusterAPIFor(t, g)
			return asServer(t, g.port), minted
		}},
		{"a worker pushes to the server's cluster address", func(t *testing.T, g gateRegistry) (string, *int) {
			minted := clusterAPIFor(t, g, flatSlice("127.0.0.1", int32(g.port)))
			dir := t.TempDir()
			t.Setenv("K3SM_WORK_DIR", dir)
			return dir, minted
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := startGateRegistry(t)
			workDir, minted := tc.setup(t, g)
			img, err := random.Image(64, 1)
			if err != nil {
				t.Fatal(err)
			}
			ref, _ := name.NewTag("registry-k3sm:6450/team/app:v1")
			var warmed []string
			warm := func(_ context.Context, r name.Tag) error { warmed = append(warmed, r.String()); return nil }
			if err := recordInto(t.Context(), ref, built{image: img}, workDir, pushBuilt, warm); err != nil {
				t.Fatalf("record: %v", err)
			}
			if *minted != 1 {
				t.Errorf("builder tokens minted = %d, want 1", *minted)
			}
			if !containsHeader(g.probe.headers(), want) {
				t.Errorf("the builder token was never presented; headers = %q", g.probe.headers())
			}
			for _, h := range g.probe.headers() {
				if h != "" && h != want {
					t.Errorf("a credential other than the builder token was presented: %q", h)
				}
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(g.caPEM)
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "registry-k3sm"}
			back, _ := name.NewTag("127.0.0.1:" + strconv.Itoa(g.port) + "/team/app:v1")
			got, err := remote.Image(back, remote.WithTransport(tr))
			if err != nil {
				t.Fatalf("pull back: %v", err)
			}
			gd, _ := got.Digest()
			wd, _ := img.Digest()
			if gd != wd {
				t.Errorf("registry holds %s, want %s", gd, wd)
			}
			if len(warmed) != 1 || warmed[0] != "registry-k3sm:6450/team/app:v1" {
				t.Errorf("warm pulls = %v, want the flat name", warmed)
			}
		})
	}

	t.Run("image push to the flat name goes through the gate", func(t *testing.T) {
		g := startGateRegistry(t)
		clusterAPIFor(t, g)
		workDir := asServer(t, g.port)
		img, _ := random.Image(64, 1)
		ref, _ := name.ParseReference("registry-k3sm:6450/app:v2")
		target, shown, dest, err := imagePushTarget(t.Context(), ref, workDir)
		if err != nil {
			t.Fatal(err)
		}
		if target.String() != "127.0.0.1:"+strconv.Itoa(g.port)+"/app:v2" || shown.String() != "registry-k3sm:6450/app:v2" {
			t.Errorf("target %s shown %s", target, shown)
		}
		if err := pushImage(t.Context(), target, img, dest); err != nil {
			t.Fatalf("push: %v", err)
		}
		if !containsHeader(g.probe.headers(), want) {
			t.Errorf("image push did not present the builder token; headers = %q", g.probe.headers())
		}
	})
}

// TestBuildWithoutKubeconfigNamesRemedy pins the refusal on a Mac with no
// kubeconfig (a worker writes none): the build stops before any upload with
// errNoUserKubeconfig naming the `k3sm kubeconfig --write` remedy.
func TestBuildWithoutKubeconfigNamesRemedy(t *testing.T) {
	noKubeconfig(t)
	ctxDir := pushCtx(t)
	var log []string
	pusher := &recordingPush{log: &log}
	err := buildWith(t.Context(), buildOptions{
		dockerfile: filepath.Join(ctxDir, "Dockerfile"),
		tag:        "myapp:v1",
		format:     "docker",
		contextDir: ctxDir,
	}, io.Discard, engineBuildWith(noStore), recordInRegistry(pusher.push, func(context.Context, name.Tag) error { return nil }), pusher.push)
	if !errors.Is(err, errNoUserKubeconfig) {
		t.Fatalf("build = %v, want errNoUserKubeconfig", err)
	}
	if !strings.Contains(err.Error(), "k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write") {
		t.Errorf("err = %v, want the k3sm kubeconfig remedy", err)
	}
	if len(pusher.targets) != 0 {
		t.Errorf("uploads = %v, want none", pusher.targets)
	}
}
