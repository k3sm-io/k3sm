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

// Command b411-echo is the B411 e2e extension-apiserver stand-in: a TLS server that
// REQUESTS (never verifies) a client certificate and reports what the aggregator
// presented, so the test, not this binary, decides whether that certificate chains
// to the request-header CA.
//
//	GET /healthz                                 ok
//	GET /apis/<group>/<version>                  an empty APIResourceList (discovery)
//	GET /apis/<group>/<version>/whoami           {"clientCertPEM", "user", "groups"}
//
// Anything else is 404, which is what a backend without aggregated discovery
// answers, so the aggregator falls back to the per-version document above.
package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	certFile := flag.String("cert", "", "serving certificate PEM")
	keyFile := flag.String("key", "", "serving key PEM")
	gv := flag.String("group-version", "b411.test.k3sm.io/v1alpha1", "the API group/version this backend serves")
	flag.Parse()

	base := "/apis/" + *gv
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch strings.TrimSuffix(r.URL.Path, "/") {
		case base:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": *gv, "resources": []any{},
			})
		case base + "/whoami":
			var certPEM string
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.TLS.PeerCertificates[0].Raw}))
			}
			log.Printf("whoami: user=%q groups=%v client-cert=%v", r.Header.Get("X-Remote-User"), r.Header.Values("X-Remote-Group"), certPEM != "")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientCertPEM": certPEM,
				"user":          r.Header.Get("X-Remote-User"),
				"groups":        r.Header.Values("X-Remote-Group"),
			})
		default:
			http.NotFound(w, r)
		}
	})
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert},
	}
	log.Printf("b411-echo serving %s on %s", base, *addr)
	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatalf("serve %s: %v", *addr, err)
	}
}
