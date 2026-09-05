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
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ProbeOpenAISurface derives one replica's ProbeVerdict by probing its
// OpenAI-compatible HTTP serving surface: GET /health for reachability, then
// GET /v1/models for whether model is being served. The result is exactly the
// ProbeVerdict DeriveStatus (status.go) consumes through PodState.Probe.
//
// It is deliberately ENGINE-AGNOSTIC — the S5 spike (hack/spike/m8/findings-s5.md
// §3–4) found the three candidate serving engines disagree on almost
// everything about /health: mlx-lm answers a bare {"status":"ok"} before any
// weights are loaded, vllm-mlx adds a "model_loaded" bool, oMLX adds a whole
// engine-pool gauge whose "loaded_count" reads 0 while genuinely ready. None of
// that vocabulary is read here — reading it would pin the operator to one
// engine's JSON shape, which defeats the whole point of choosing the engine by
// image digest. What every OpenAI-compatible surface DOES agree on is
// (a) whether it answers at all and (b) whether /v1/models lists a served
// model by id — so those are the only two signals this function reads.
//
// It makes AT MOST two HTTP requests, each bounded by timeout, and retries
// NEITHER — the caller (a reconcile loop) is what retries, on its own
// schedule and its own backoff, so a probe that fails fast is what keeps that
// loop responsive rather than blocking it inside one probe call.
//
// The verdict:
//
//   - /health cannot be reached at all (dial refused, connection reset, or the
//     bounded timeout elapses before any response) -> ProbeUnreachable. The
//     serving surface is entirely silent, which — per ProbeUnreachable's own
//     doc in status.go — is indistinguishable from "still fetching weights",
//     and is reported as exactly that.
//   - /health answers but is not a well-formed 2xx JSON response (a non-2xx
//     status, or a body that fails to decode as JSON) -> ProbeLoading. The
//     process accepted a connection — it is not silent — but has not reached a
//     state this client can call healthy.
//   - /health is a well-formed 2xx JSON response, but /v1/models is
//     unreachable, non-2xx, fails to decode, or its data[].id set does not
//     contain model -> ProbeLoading. The server is alive; it has not (yet, or
//     ever) advertised the model this replica is meant to serve.
//   - Both requests succeed and model appears in /v1/models's data[].id ->
//     ProbeServing.
//
// rt is the transport (NewProbeTransport for production use; a fake
// RoundTripper or an httptest server's default transport in tests) — probe
// targets are pod-local addresses with no cluster PKI, so, like the kubelet
// probe handlers (pkg/provider/probe_handlers.go), verification is relaxed by
// NewProbeTransport rather than by this function reaching for insecure
// defaults itself.
func ProbeOpenAISurface(ctx context.Context, rt http.RoundTripper, baseURL, model string, timeout time.Duration) ProbeVerdict {
	client := &http.Client{
		Transport: rt,
		Timeout:   timeout,
		// A probe never follows a redirect: a 3xx from a serving surface is not
		// the answer this client is asking for, and following one risks leaving
		// the pod network entirely.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	switch probeHealth(ctx, client, baseURL) {
	case healthUnreachable:
		return ProbeUnreachable
	case healthDegraded:
		return ProbeLoading
	}

	if probeModelListed(ctx, client, baseURL, model) {
		return ProbeServing
	}
	return ProbeLoading
}

// NewProbeTransport is the HTTP transport for OpenAI-surface probes. Probe
// targets are pod-local addresses with no cluster PKI, so — mirroring
// pkg/provider/probe_handlers.go's newProbeTransport, whose hardening this
// reuses — server certificates are not verified and connections are not
// pooled: each probe call is a fresh, short-lived request, never one held open
// across a reconcile loop's iterations against a replica that may have
// restarted with a new pod IP.
func NewProbeTransport() *http.Transport {
	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // probe targets are pod-local, no PKI (kubelet parity)
	}
}

// healthState is probeHealth's tri-state result: the two failure states are
// deliberately distinct because ProbeOpenAISurface maps them to different
// verdicts (silent -> Unreachable, answering-but-not-well-formed -> Loading).
type healthState int

const (
	healthUnreachable healthState = iota
	healthDegraded
	healthOK
)

// probeHealth issues one GET to baseURL/health, bounded by client's Timeout.
// It never panics on a malformed body: a decode failure is a typed
// healthDegraded result, not an error the caller must recover from.
func probeHealth(ctx context.Context, client *http.Client, baseURL string) healthState {
	resp, err := probeGet(ctx, client, baseURL, "health")
	if err != nil {
		return healthUnreachable
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return healthDegraded
	}
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return healthDegraded
	}
	return healthOK
}

// modelsList is the OpenAI /v1/models response shape this client reads: only
// the id each entry advertises. Every other field (owned_by, max_model_len,
// created — S5 §4 found these vary by engine) is left unread on purpose.
type modelsList struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// probeModelListed issues one GET to baseURL/v1/models, bounded by client's
// Timeout, and reports whether model appears among the response's data[].id
// entries.
// Any failure to reach the endpoint, a non-2xx status, or a body that fails to
// decode is reported as false (not listed) — never a panic, and never treated
// as "listed" by default, because a probe that fails open on a parse error
// would report a model serving that this client never actually confirmed.
func probeModelListed(ctx context.Context, client *http.Client, baseURL, model string) bool {
	resp, err := probeGet(ctx, client, baseURL, "v1", "models")
	if err != nil {
		return false
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var list modelsList
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&list); err != nil {
		return false
	}
	for _, m := range list.Data {
		if m.ID == model {
			return true
		}
	}
	return false
}

// probeGet issues one GET to baseURL joined with elem, on ctx. The bound is
// client.Timeout alone — deliberately NOT a derived context.WithTimeout: the
// net/http docs guarantee client.Timeout "includes connection time, any
// redirects, and reading the response body", so it already covers everything
// this call and its caller's subsequent body read do. A derived context
// cancelled on probeGet's own return (the obvious-looking pattern) would fire
// BEFORE the caller reads the body — client.Do returns once headers arrive,
// not once the body is drained — and every response read after that would
// fail with "context canceled" instead of the body this function exists to
// read. ctx itself still propagates the caller's own cancellation (a
// reconcile loop shutting down), just not a second, shorter deadline.
func probeGet(ctx context.Context, client *http.Client, baseURL string, elem ...string) (*http.Response, error) {
	u, err := url.JoinPath(baseURL, elem...)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// drainAndClose discards up to 4KiB of resp's body then closes it, so the
// underlying connection can be reclaimed promptly — the same idiom
// pkg/provider/probe_handlers.go's httpProbe uses for the same reason.
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4<<10))
	_ = body.Close()
}
