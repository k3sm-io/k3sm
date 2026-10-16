//go:build integration

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
	"testing"

	"k8s.io/client-go/rest"
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
