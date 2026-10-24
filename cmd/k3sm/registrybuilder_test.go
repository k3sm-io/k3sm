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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// fakeBuilderTokenToken is the token the fake apiserver mints. It is a secret
// in spirit: no test output may carry it except the one stdout it belongs on.
const fakeBuilderTokenToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJidWlsZGVyIn0.c2lnbmVk"

// tokenRequestSeen is what the fake apiserver was asked.
type tokenRequestSeen struct {
	namespace, name string
	spec            authnv1.TokenRequestSpec
}

// fakeTokenAPI points builderTokenClient at a fake clientset whose
// serviceaccounts/token answers with answer, and returns what it was asked.
func fakeTokenAPI(t *testing.T, answer func(spec authnv1.TokenRequestSpec) (*authnv1.TokenRequest, error)) *[]tokenRequestSeen {
	t.Helper()
	cs := fake.NewClientset()
	var seen []tokenRequestSeen
	cs.PrependReactor("create", "serviceaccounts", func(a ktesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(ktesting.CreateAction)
		if !ok || a.GetSubresource() != "token" {
			return false, nil, nil
		}
		tr := ca.GetObject().(*authnv1.TokenRequest)
		name := ""
		if impl, ok := a.(ktesting.CreateActionImpl); ok {
			name = impl.Name
		}
		seen = append(seen, tokenRequestSeen{namespace: a.GetNamespace(), name: name, spec: tr.Spec})
		out, err := answer(tr.Spec)
		return true, out, err
	})
	fakeClusterAPI(t, cs)
	return &seen
}

// fakeClusterAPI points clusterRegistryClient at cs, with fakeKubeconfigCA as the
// kubeconfig's cluster CA.
func fakeClusterAPI(t *testing.T, cs *fake.Clientset) {
	t.Helper()
	prev := clusterRegistryClient
	clusterRegistryClient = func() (clusterRegistryAPI, error) {
		return clusterRegistryAPI{
			tokens: cs.CoreV1().ServiceAccounts("k3sm-registry"),
			slices: cs.DiscoveryV1().EndpointSlices("k3sm-registry"),
			caPEM:  []byte(fakeKubeconfigCA),
		}, nil
	}
	t.Cleanup(func() { clusterRegistryClient = prev })
}

// fakeKubeconfigCA stands in for the kubeconfig's cluster CA where only its bytes
// matter.
const fakeKubeconfigCA = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

// asServer records a serving registry with its loopback gate on gatePort in a
// fresh work dir, as this Mac's server would, and points the CLI at it.
func asServer(t *testing.T, gatePort int) string {
	t.Helper()
	dir := t.TempDir()
	if err := registrysvc.WriteState(dir, registrysvc.State{State: registrysvc.StateServing, Port: 6450, Addr: "127.0.0.1:6450", GatePort: gatePort}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("K3SM_WORK_DIR", dir)
	return dir
}

// issue answers a TokenRequest with the fake token, valid for what was asked.
func issue(spec authnv1.TokenRequestSpec) (*authnv1.TokenRequest, error) {
	exp := time.Now().Add(time.Duration(*spec.ExpirationSeconds) * time.Second)
	return &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: fakeBuilderTokenToken, ExpirationTimestamp: metav1.NewTime(exp)}}, nil
}

// TestRegistryTokenPrintsBuilderToken pins `k3sm registry token`: one
// TokenRequest for k3sm-registry/builder, audience k3sm-registry, for the
// default hour or the asked --duration, and the token alone on stdout. A
// lifetime the cluster clamps (above its maximum) or below the minimum is
// refused, and no token is printed then.
func TestRegistryTokenPrintsBuilderToken(t *testing.T) {
	t.Run("the default lifetime", func(t *testing.T) {
		seen := fakeTokenAPI(t, issue)
		var out, errOut bytes.Buffer
		if err := runRegistry([]string{"token"}, &out, &errOut); err != nil {
			t.Fatalf("registry token: %v", err)
		}
		if got := out.String(); got != fakeBuilderTokenToken+"\n" {
			t.Errorf("stdout = %q, want the token and a newline", got)
		}
		if errOut.Len() != 0 {
			t.Errorf("stderr = %q, want nothing", errOut.String())
		}
		if len(*seen) != 1 {
			t.Fatalf("token requests = %d, want 1", len(*seen))
		}
		r := (*seen)[0]
		if r.namespace != "k3sm-registry" || r.name != "builder" {
			t.Errorf("token requested for %s/%s, want k3sm-registry/builder", r.namespace, r.name)
		}
		if len(r.spec.Audiences) != 1 || r.spec.Audiences[0] != "k3sm-registry" {
			t.Errorf("audiences = %v, want [k3sm-registry]", r.spec.Audiences)
		}
		if r.spec.ExpirationSeconds == nil || *r.spec.ExpirationSeconds != 3600 {
			t.Errorf("expirationSeconds = %v, want 3600", r.spec.ExpirationSeconds)
		}
		if r.spec.BoundObjectRef != nil {
			t.Errorf("boundObjectRef = %+v, want none", r.spec.BoundObjectRef)
		}
	})
	t.Run("an asked duration", func(t *testing.T) {
		seen := fakeTokenAPI(t, issue)
		var out bytes.Buffer
		if err := runRegistry([]string{"token", "--duration", "20m"}, &out, &bytes.Buffer{}); err != nil {
			t.Fatalf("registry token: %v", err)
		}
		if got := *(*seen)[0].spec.ExpirationSeconds; got != 1200 {
			t.Errorf("expirationSeconds = %d, want 1200", got)
		}
	})
	t.Run("above the cluster's maximum is refused", func(t *testing.T) {
		fakeTokenAPI(t, func(spec authnv1.TokenRequestSpec) (*authnv1.TokenRequest, error) {
			return &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{
				Token: fakeBuilderTokenToken, ExpirationTimestamp: metav1.NewTime(time.Now().Add(time.Hour)),
			}}, nil
		})
		var out bytes.Buffer
		err := runRegistry([]string{"token", "--duration", "48h"}, &out, &bytes.Buffer{})
		if !errors.Is(err, errBuilderTokenDuration) {
			t.Fatalf("err = %v, want errBuilderTokenDuration", err)
		}
		if out.Len() != 0 || strings.Contains(err.Error(), fakeBuilderTokenToken) {
			t.Errorf("a refused token reached the output: stdout %q, err %v", out.String(), err)
		}
	})
	t.Run("below the minimum is refused before any request", func(t *testing.T) {
		seen := fakeTokenAPI(t, issue)
		err := runRegistry([]string{"token", "--duration", "5m"}, &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.Is(err, errBuilderTokenDuration) || len(*seen) != 0 {
			t.Fatalf("err = %v, requests = %d; want errBuilderTokenDuration and none", err, len(*seen))
		}
	})
}

// TestRegistryTokenRefusedWithoutTokenRight pins the refusal a kubeconfig that
// may not create the builder's token gets: errBuilderTokenRefused naming the
// k3sm:registry-builder-token role, and nothing on stdout. A Mac with no
// kubeconfig at all is told the remedy.
func TestRegistryTokenRefusedWithoutTokenRight(t *testing.T) {
	t.Run("forbidden", func(t *testing.T) {
		fakeTokenAPI(t, func(authnv1.TokenRequestSpec) (*authnv1.TokenRequest, error) {
			return nil, apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts/token"}, "builder", errors.New("RBAC: access denied"))
		})
		for _, verb := range []string{"token", "login"} {
			t.Setenv("DOCKER_CONFIG", t.TempDir())
			var out bytes.Buffer
			err := runRegistry([]string{verb}, &out, &bytes.Buffer{})
			if !errors.Is(err, errBuilderTokenRefused) || !strings.Contains(err.Error(), "k3sm:registry-builder-token") {
				t.Errorf("%s: err = %v, want errBuilderTokenRefused naming the token role", verb, err)
			}
			if out.Len() != 0 {
				t.Errorf("%s: stdout = %q, want nothing", verb, out.String())
			}
			if _, serr := os.Stat(filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json")); serr == nil {
				t.Errorf("%s: a refused mint wrote a docker config", verb)
			}
		}
	})
	t.Run("no kubeconfig names the remedy", func(t *testing.T) {
		t.Setenv("K3SM_WORK_DIR", filepath.Join(t.TempDir(), "server"))
		t.Setenv("KUBECONFIG", "")
		t.Setenv("HOME", t.TempDir())
		err := runRegistry([]string{"token"}, &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.Is(err, errNoUserKubeconfig) {
			t.Fatalf("err = %v, want errNoUserKubeconfig", err)
		}
		if !strings.Contains(err.Error(), "k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write") {
			t.Errorf("err = %v, want it to name the k3sm kubeconfig remedy", err)
		}
	})
}

// TestRegistryLoginWritesDockerConfigEntry pins `k3sm registry login`: it sets
// auths["registry-k3sm:6450"] to a Basic credential carrying the minted token,
// keeps every other key and registry the file held, writes mode 0600, prints
// no token, and refuses a config whose credential store would shadow the entry.
func TestRegistryLoginWritesDockerConfigEntry(t *testing.T) {
	seen := fakeTokenAPI(t, issue)
	_ = seen
	asServer(t, 6451)
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"auths":{"ghcr.io":{"auth":"b3RoZXI="}},"experimental":"enabled"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runRegistry([]string{"login"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("registry login: %v", err)
	}
	if strings.Contains(out.String(), fakeBuilderTokenToken) {
		t.Errorf("login printed the token: %q", out.String())
	}
	caPath := filepath.Join(dir, "certs.d", "localhost:6451", "ca.crt")
	for _, want := range []string{"localhost:6451", path, caPath} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("login output %q does not say what it wrote (%s)", out.String(), want)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("docker config mode = %v, want 0600", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	var doc struct {
		Auths        map[string]struct{ Auth string } `json:"auths"`
		Experimental string                           `json:"experimental"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse the written config: %v", err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("builder:" + fakeBuilderTokenToken))
	if doc.Auths["localhost:6451"].Auth != want {
		t.Errorf("localhost:6451 entry = %q, want builder:<token>", doc.Auths["localhost:6451"].Auth)
	}
	if doc.Auths["ghcr.io"].Auth != "b3RoZXI=" || doc.Experimental != "enabled" {
		t.Errorf("login dropped the existing config: %s", raw)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil || string(ca) != fakeKubeconfigCA {
		t.Errorf("certs.d CA = %q (%v), want the kubeconfig's cluster CA", ca, err)
	}
	if fi, err := os.Stat(caPath); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("certs.d CA mode = %v (%v), want 0644", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Dir(caPath)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("certs.d dir mode = %v (%v), want 0755", fi.Mode().Perm(), err)
	}

	t.Run("a worker logs in to the server's cluster address", func(t *testing.T) {
		cs := fake.NewClientset(flatSlice("100.64.0.1", 6450))
		cs.PrependReactor("create", "serviceaccounts", func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() != "token" {
				return false, nil, nil
			}
			out, err := issue(a.(ktesting.CreateAction).GetObject().(*authnv1.TokenRequest).Spec)
			return true, out, err
		})
		fakeClusterAPI(t, cs)
		t.Setenv("K3SM_WORK_DIR", t.TempDir())
		wdir := t.TempDir()
		t.Setenv("DOCKER_CONFIG", wdir)
		if err := runRegistry([]string{"login"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatalf("registry login: %v", err)
		}
		raw, _ := os.ReadFile(filepath.Join(wdir, "config.json"))
		if !strings.Contains(string(raw), `"100.64.0.1:6450"`) {
			t.Errorf("worker docker config = %s, want an entry for 100.64.0.1:6450", raw)
		}
		if _, err := os.Stat(filepath.Join(wdir, "certs.d", "100.64.0.1:6450", "ca.crt")); err != nil {
			t.Errorf("worker certs.d CA: %v", err)
		}
	})

	t.Run("a credential store refuses rather than writing a shadowed entry", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(`{"credsStore":"desktop"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		err := runRegistry([]string{"login"}, &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.Is(err, errDockerCredentialStore) || !strings.Contains(err.Error(), "docker login localhost:6451 -u builder --password-stdin") {
			t.Fatalf("err = %v, want errDockerCredentialStore naming the docker login pipe", err)
		}
		raw, _ := os.ReadFile(path)
		if string(raw) != `{"credsStore":"desktop"}` {
			t.Errorf("the refused login changed the file: %s", raw)
		}
	})
}

// flatSlice is the flat registry-k3sm Service's EndpointSlice naming one ready
// endpoint, as the server publishes it.
func flatSlice(addr string, port int32) *discoveryv1.EndpointSlice {
	name, ready := "registry", true
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "registry-k3sm", Namespace: "k3sm-registry",
			Labels: map[string]string{discoveryv1.LabelServiceName: "registry-k3sm"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &name, Port: &port}},
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{addr}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
	}
}
