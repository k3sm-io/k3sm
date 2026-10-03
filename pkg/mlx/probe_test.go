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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const probeTestModel = "qwen2.5-0.5b-instruct-4bit"

// probeHangTimeout is the bound handed to the ONE case whose subject IS the
// bound — a transport that never answers — plus the refused-connection case,
// whose verdict is the same whatever the budget is. It is short so that case
// does not make the suite slow.
const probeHangTimeout = 100 * time.Millisecond

// probeContentBudget is the bound handed to every case whose subject is the
// VERDICT DERIVED FROM A RESPONSE. It is deliberately enormous relative to the
// work those cases do, because its only job is to keep a wedged run from
// hanging forever — it must never be the thing that decides a verdict.
//
// Sharing one short budget across both roles is what made this table flake
// (B206): health_ok_model_missing_is_loading answered a real loopback request
// well inside 100ms unloaded, but on a loaded machine the round trip lost that
// race, ProbeOpenAISurface saw a client-timeout error instead of a response and
// correctly returned Unreachable — a verdict about the machine, asserted as if
// it were a verdict about the fixture. No case in this file touches the network
// at all (see serveInProcess, refusedTransport, hungTransport); this budget is
// the residual guard, not a race the content cases have to win. The real-socket
// cases live in probe_integration_test.go.
const probeContentBudget = 30 * time.Second

// TestServingProbeVerdictFromOpenAISurface is B65's gate: an httptest fake
// server table proving ProbeOpenAISurface derives the right ProbeVerdict from
// the OpenAI-compatible surface alone, reading NOTHING engine-specific (S5,
// hack/spike/m8/findings-s5.md §3–4).
func TestServingProbeVerdictFromOpenAISurface(t *testing.T) {
	t.Run("silent_or_refused_is_the_downloading_verdict", func(t *testing.T) {
		// A refused connection, exactly like a pod whose serving container has
		// not bound its port yet because it is still fetching weights. The fake
		// returns the error a refused TCP dial produces, so the verdict is
		// derived from the transport's answer and from nothing a loaded machine
		// can change. The budget cannot change it either — a refusal and an
		// elapsed budget are both "no response", both Unreachable — so the short
		// one costs nothing here. The same case over a real closed port is in
		// probe_integration_test.go.
		var rt refusedTransport
		got := probeVia(t, &rt, probeTestBaseURL, probeHangTimeout)
		if got != ProbeUnreachable {
			t.Fatalf("got %q, want %q (ProbeUnreachable)", got, ProbeUnreachable)
		}
		if rt.calls.Load() == 0 {
			t.Fatal("the transport was never asked: Unreachable must be the answer to a refused dial, not to a request that was never made")
		}
	})

	t.Run("health_ok_model_missing_is_loading", func(t *testing.T) {
		var served []string
		got := probeServed(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served = append(served, r.URL.Path)
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
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (ProbeLoading)", got, ProbeLoading)
		}
		// The REASON, not just the verdict: Loading here must be the answer to
		// two answered requests, not the by-product of a request that never
		// completed. serveInProcess cannot time out, so this can only fail if
		// the client stopped asking — which would make the verdict above a
		// coincidence.
		if want := []string{"/health", "/v1/models"}; !slices.Equal(served, want) {
			t.Fatalf("served %v, want %v (the Loading verdict must come from both answers)", served, want)
		}
	})

	t.Run("health_ok_model_listed_is_serving", func(t *testing.T) {
		got := probeServed(t, servingHandler())
		if got != ProbeServing {
			t.Fatalf("got %q, want %q (ProbeServing)", got, ProbeServing)
		}
	})

	t.Run("malformed_json_is_not_serving_never_panics", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": not-json-at-all`))
			default:
				http.NotFound(w, r)
			}
		})

		var got ProbeVerdict
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ProbeOpenAISurface panicked on malformed JSON: %v", r)
				}
			}()
			got = probeServed(t, h)
		}()
		if got == ProbeServing {
			t.Fatalf("got %q, want anything but %q (a malformed /health body must never read as serving)", got, ProbeServing)
		}
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (health answered — malformed but not silent — so it is not Unreachable)", got, ProbeLoading)
		}
	})

	t.Run("malformed_models_json_is_not_serving_never_panics", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		})

		var got ProbeVerdict
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ProbeOpenAISurface panicked on malformed /v1/models JSON: %v", r)
				}
			}()
			got = probeServed(t, h)
		}()
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (health is well-formed, models is not — not serving, not unreachable)", got, ProbeLoading)
		}
	})

	t.Run("timeout_is_bounded_a_hung_handler_does_not_hang_the_test", func(t *testing.T) {
		// A transport that never answers: it blocks until the request's context
		// is done, the way a connection to a wedged server does. What is under
		// test is that ProbeOpenAISurface returns on its own, bounded by
		// probeHangTimeout — the client's own Timeout is the only thing that can
		// end the request, because the helper's outer context allows a minute.
		var rt hungTransport
		start := time.Now()
		got := probeVia(t, &rt, probeTestBaseURL, probeHangTimeout)
		elapsed := time.Since(start)

		if got != ProbeUnreachable {
			t.Fatalf("got %q, want %q (a probe that never got a response is silent, not degraded)", got, ProbeUnreachable)
		}
		if rt.calls.Load() == 0 {
			t.Fatal("the transport was never asked: the bound must be the one that ended a hung request")
		}
		// Generous multiple of probeHangTimeout: bounded means "does not hang
		// indefinitely", not "returns in exactly one timeout" — this asserts
		// the former without flaking on a loaded machine.
		if budget := 20 * probeHangTimeout; elapsed > budget {
			t.Fatalf("ProbeOpenAISurface took %s against a %s timeout (budget %s) — the hung handler was not bounded", elapsed, probeHangTimeout, budget)
		}
	})

	t.Run("health_unreachable_skips_the_models_request", func(t *testing.T) {
		modelsHit := false
		got := probeServed(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if got != ProbeLoading {
			t.Fatalf("got %q, want %q (500 from /health is degraded, not unreachable)", got, ProbeLoading)
		}
		if modelsHit {
			t.Fatal("/v1/models was called despite /health degraded — a probe should not spend its bounded budget on a request whose answer cannot change the verdict")
		}
	})
}

// serveInProcess is an http.RoundTripper that hands the request straight to h
// on the CALLER's goroutine and returns what h recorded. No listener, no dial,
// no accept, no scheduler in the path — so a case using it derives its verdict
// from the fixture's bytes and from nothing else.
//
// It never returns an error, which is the property the content cases need:
// ProbeUnreachable is reachable ONLY through a transport error, so a case
// running here cannot be handed the "silent surface" verdict by a loaded
// machine. The two cases whose subject is the transport's failure — a refused
// connection and a handler that never answers — use refusedTransport and
// hungTransport instead, which fail the way the network does without opening a
// socket.
type serveInProcess struct{ h http.Handler }

func (s serveInProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// refusedTransport is an http.RoundTripper that fails every request the way a
// dial to a port with no listener fails: a *net.OpError wrapping ECONNREFUSED
// from connect(2), the shape net.Dialer returns. http.Client wraps it in a
// *url.Error itself, as it would a real refusal.
type refusedTransport struct{ calls atomic.Int32 }

func (r *refusedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
	}
}

// hungTransport is an http.RoundTripper that never answers: it blocks until the
// request's context is done and returns that context's error, so the only thing
// that can end a request is a deadline or a cancellation from the caller.
type hungTransport struct{ calls atomic.Int32 }

func (h *hungTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h.calls.Add(1)
	<-req.Context().Done()
	err := req.Context().Err()
	if err == nil {
		err = errors.New("hung transport released without a context error")
	}
	return nil, err
}

// probeTestBaseURL is a syntactically valid absolute URL that is never resolved:
// every fake transport answers before any resolution would happen.
const probeTestBaseURL = "http://replica.mlx.invalid:8000"

// probeServed runs ProbeOpenAISurface against h with no network in between,
// under the liveness-only probeContentBudget.
func probeServed(t *testing.T, h http.Handler) ProbeVerdict {
	t.Helper()
	return probeVia(t, serveInProcess{h: h}, probeTestBaseURL, probeContentBudget)
}

// probeVia runs ProbeOpenAISurface for probeTestModel through rt against
// baseURL, under a one-minute outer context so a wedged run cannot hang the
// suite. timeout is per-case: see probeHangTimeout / probeContentBudget. The
// integration tier passes http.DefaultTransport and a real loopback URL
// (loopback httptest servers carry no TLS, so NewProbeTransport's relaxed
// verification is not exercised there — that is covered by the transport's own
// construction, not by this table).
func probeVia(t *testing.T, rt http.RoundTripper, baseURL string, timeout time.Duration) ProbeVerdict {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return ProbeOpenAISurface(ctx, rt, baseURL, probeTestModel, timeout)
}

// servingHandler is the "this replica serves probeTestModel" fixture, shared by
// the in-process serving case here and the real-socket serving case in
// probe_integration_test.go, so the two cannot drift into asserting the same
// verdict about different bytes.
func servingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})
}

// writeJSON writes body verbatim with a JSON content type and a 200 status —
// a tiny helper so each table case states its fixture as a literal, not a
// struct that would obscure the malformed-JSON cases' whole point.
func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
