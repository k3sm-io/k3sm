// Command hello-http is the controllable HTTP server the k3sm e2e conformance
// suite runs as a native pod "image" (TestM2_Probes, TestM3_NodePort). It serves
// a fixed identity on "/", and health endpoints (/healthz, /livez) that can be
// configured to FLIP from healthy to failing after a delay — so a readiness or
// liveness probe TRANSITION (the M2.2 endpoint-removal / restart semantics) is
// exercised deterministically instead of waiting on an external event.
//
// stdlib only: it builds CGO_ENABLED=0 and, once ad-hoc-signed (codesign -s -),
// execs under the default-deny Seatbelt profile.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	id := flag.String("id", hostnameOr("hello"), "identity string served on GET /")
	addr := flag.String("addr", ":8080", "listen address")
	healthyFor := flag.Duration("healthy-for", 0, "if >0, GET /healthz returns 200 for this long after start, then 503 (readiness transition)")
	liveFor := flag.Duration("live-for", 0, "if >0, GET /livez returns 200 for this long after start, then 500 (liveness transition)")
	flag.Parse()

	start := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, *id)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if *healthyFor > 0 && time.Since(start) > *healthyFor {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		if *liveFor > 0 && time.Since(start) > *liveFor {
			http.Error(w, "dead", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	})

	log.Printf("hello-http id=%s addr=%s healthy-for=%s live-for=%s", *id, *addr, *healthyFor, *liveFor)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("serve %s: %v", *addr, err)
	}
}

// hostnameOr returns the host name (the pod name under the VK provider) or def.
func hostnameOr(def string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return def
}
