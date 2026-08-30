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

package mlx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const probeTestModel = "qwen2.5-0.5b-instruct-4bit"

// probeTimeout is the bound used throughout this table. It is short enough
// that the timeout subtest below (a handler that outlives it) does not make
// the suite slow, but long enough that a scheduling hiccup on a loaded CI box
// does not flake the non-timeout cases.
const probeTimeout = 100 * time.Millisecond

// TestServingProbeVerdictFromOpenAISurface is B65's gate: an httptest fake
// server table proving ProbeOpenAISurface derives the right ProbeVerdict from
// the OpenAI-compatible surface alone, reading NOTHING engine-specific (S5,
// hack/spike/m8/findings-s5.md §3–4).
func TestServingProbeVerdictFromOpenAISurface(t *testing.T) {
	t.Run("silent_or_refused_is_the_downloading_verdict", func(t *testing.T) {
		// A server stood up then immediately closed: the port refuses the
		// connection, exactly like a pod whose serving container has not
		// bound its port yet because it is still fetching weights.
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler must not be reached: the server is closed before probing")
		}))
		srv.Close()

		got := probeAt(t, srv.URL)
		if got != ProbeUnreachable {
			t.Fatalf("got %q, want %q (ProbeUnreachable)", got, ProbeUnreachable)
		}
	})

	t.Run("health_ok_model_missing_is_loading", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				writeJSON(w, `{"status":"ok"}`)
			case "/v1/models":
				// A different model is being served — this replica has not
				// (or not yet) loaded the one this MLXModel names.
				writeJSON(w, `{"object":"list","data":[{"id":"a-different-model","object":"model"}]}`)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		got := probeAt(t, srv.URL)
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (ProbeLoading)", got, ProbeLoading)
		}
	})

	t.Run("health_ok_model_listed_is_serving", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				// vllm-mlx's richer shape (S5 §3) — deliberately NOT read by
				// the client; a bare {"status":"ok"} would do exactly as well.
				writeJSON(w, `{"status":"healthy","model_loaded":true,"model_name":"`+probeTestModel+`"}`)
			case "/v1/models":
				writeJSON(w, `{"object":"list","data":[{"id":"`+probeTestModel+`","object":"model","owned_by":"k3sm"}]}`)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		got := probeAt(t, srv.URL)
		if got != ProbeServing {
			t.Fatalf("got %q, want %q (ProbeServing)", got, ProbeServing)
		}
	})

	t.Run("malformed_json_is_not_serving_never_panics", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": not-json-at-all`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		var got ProbeVerdict
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ProbeOpenAISurface panicked on malformed JSON: %v", r)
				}
			}()
			got = probeAt(t, srv.URL)
		}()
		if got == ProbeServing {
			t.Fatalf("got %q, want anything but %q (a malformed /health body must never read as serving)", got, ProbeServing)
		}
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (health answered — malformed but not silent — so it is not Unreachable)", got, ProbeLoading)
		}
	})

	t.Run("malformed_models_json_is_not_serving_never_panics", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				writeJSON(w, `{"status":"ok"}`)
			case "/v1/models":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`not json`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		var got ProbeVerdict
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ProbeOpenAISurface panicked on malformed /v1/models JSON: %v", r)
				}
			}()
			got = probeAt(t, srv.URL)
		}()
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (health is well-formed, models is not — not serving, not unreachable)", got, ProbeLoading)
		}
	})

	t.Run("timeout_is_bounded_a_hung_handler_does_not_hang_the_test", func(t *testing.T) {
		// release is closed explicitly AFTER probeAt returns below — never on
		// a deferred/context-cancellation path — so this test's own hygiene
		// (srv.Close() draining the outstanding request) does not itself
		// depend on the client-cancellation behavior under test. What IS
		// under test is that ProbeOpenAISurface returns on its own, bounded
		// by probeTimeout, while the handler is still blocked.
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			<-release
		}))
		defer srv.Close()

		start := time.Now()
		got := probeAt(t, srv.URL)
		elapsed := time.Since(start)
		close(release) // let the handler return so the deferred srv.Close() above doesn't block

		if got != ProbeUnreachable {
			t.Fatalf("got %q, want %q (a probe that never got a response is silent, not degraded)", got, ProbeUnreachable)
		}
		// Generous multiple of probeTimeout: bounded means "does not hang
		// indefinitely", not "returns in exactly one timeout" — this asserts
		// the former without flaking on a loaded machine.
		if budget := 20 * probeTimeout; elapsed > budget {
			t.Fatalf("ProbeOpenAISurface took %s against a %s timeout (budget %s) — the hung handler was not bounded", elapsed, probeTimeout, budget)
		}
	})

	t.Run("health_unreachable_skips_the_models_request", func(t *testing.T) {
		modelsHit := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				http.Error(w, "boom", http.StatusInternalServerError)
			case "/v1/models":
				modelsHit = true
				writeJSON(w, `{"object":"list","data":[{"id":"`+probeTestModel+`"}]}`)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		got := probeAt(t, srv.URL)
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (500 from /health is degraded, not unreachable)", got, ProbeLoading)
		}
		if modelsHit {
			t.Fatal("/v1/models was called despite /health degraded — a probe should not spend its bounded budget on a request whose answer cannot change the verdict")
		}
	})
}

// probeAt runs ProbeOpenAISurface against srv for probeTestModel, using the
// default transport (loopback httptest servers carry no TLS, so
// NewProbeTransport's relaxed verification is not exercised here — that is
// covered by the transport's own construction, not by this table).
func probeAt(t *testing.T, baseURL string) ProbeVerdict {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ProbeOpenAISurface(ctx, http.DefaultTransport, baseURL, probeTestModel, probeTimeout)
}

// writeJSON writes body verbatim with a JSON content type and a 200 status —
// a tiny helper so each table case states its fixture as a literal, not a
// struct that would obscure the malformed-JSON cases' whole point.
func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
