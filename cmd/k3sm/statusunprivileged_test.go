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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/install"
)

// TestStatusServingChainReadsTheHandshake pins the reader the serving-cert row
// uses as an ordinary account: it hands back the chain the server presents and
// the CA the kubeconfig pins, and verifies nothing itself.
func TestStatusServingChainReadsTheHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	read := statusServingChain(restKube{cfg: &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}})
	if read == nil {
		t.Fatal("no reader for a client with a rest config")
	}
	pc, err := read(context.Background())
	if err != nil {
		t.Fatalf("read the handshake: %v", err)
	}
	if len(pc.Chain) == 0 || !pc.Chain[0].Equal(srv.Certificate()) {
		t.Fatalf("chain = %d certificates, want the server's leaf first", len(pc.Chain))
	}
	if pc.Host != "127.0.0.1" || string(pc.CA) != string(ca) || pc.Server != srv.URL {
		t.Errorf("presented = host %q server %q, CA carried %v", pc.Host, pc.Server, string(pc.CA) == string(ca))
	}
	if statusServingChain(nil) != nil {
		t.Error("a reader was built with no client")
	}
}

// TestStatusUserKubeReadsTheInvokingAccountsKubeconfig pins the agent fallback's
// reader: it exists on an agent only, builds the client from the k3sm context
// of the account's own kubeconfig, and names that file and context.
func TestStatusUserKubeReadsTheInvokingAccountsKubeconfig(t *testing.T) {
	if statusUserKubeFor(install.RoleServer) != nil {
		t.Error("a server got the agent's kubeconfig fallback")
	}
	path := filepath.Join(t.TempDir(), "config")
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://100.64.0.1:6444"}
	cfg.AuthInfos["k3sm"] = &clientcmdapi.AuthInfo{Token: "not-a-real-token"}
	cfg.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "k3sm"}
	cfg.Contexts["other"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "k3sm"}
	cfg.CurrentContext = "other"
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	if installedKubeconfigName() != installedContextName {
		t.Skip("this Mac's install names its own kubeconfig context")
	}
	kube, source, err := statusUserKubeFor(install.RoleAgent)()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if kube.Server() != "https://100.64.0.1:6444" {
		t.Errorf("server = %q, want the k3sm context's", kube.Server())
	}
	if want := path + ` context "k3sm"`; source != want {
		t.Errorf("source = %q, want %q", source, want)
	}
}
