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

package registrysvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// The sweep a forced prune asks for.
//
// Prune deletes untagged manifests through the registry's API, and the layers
// they held stay on disk until the collector's next scheduled sweep. So once a
// forced prune has deleted at least one manifest it asks the server, over the
// same loopback listener and with the same push credential, to sweep exactly
// the repositories it deleted from. The server runs that sweep through its own
// collector (gc.Collector.SweepRepositories): the same grace, the same
// repository locks, the same brakes and review marker as a scheduled sweep,
// one at a time with it and never beside a dedupe pass. The route is not part
// of the distribution API, the push gate forwards only /v2/ paths, and only a
// principal that may delete (the push credential) is allowed it.

// CollectPath is the server's route for the sweep after a forced prune.
const CollectPath = "/k3sm/v1/collect"

// Bounds on a collect request.
const (
	// maxCollectBody is the largest collect request body the server reads.
	maxCollectBody = 1 << 20
	// maxCollectRepositories is the most repositories one request names.
	maxCollectRepositories = 4096
	// maxCollectResponse is the largest collect answer the client reads.
	maxCollectResponse = 4 << 20
)

// CollectTimeout bounds a collect request from the client's side: the sweep
// of a few repositories reads their manifests and deletes under their locks,
// which takes seconds, so ten minutes is a hung server, not a slow sweep.
const CollectTimeout = 10 * time.Minute

// collectRequest is the body of a collect request.
type collectRequest struct {
	Repositories []string `json:"repositories"`
}

// CollectResult is what the sweep after a forced prune did.
type CollectResult struct {
	// Repositories are the repositories the sweep was asked to collect: the
	// ones the prune deleted a manifest from.
	Repositories []string `json:"repositories"`
	// Manifests and Blobs count what the sweep reaped, and Bytes is the size
	// of those blobs. A blob whose inode another repository still links gives
	// its space back only with its last link.
	Manifests int   `json:"manifests"`
	Blobs     int   `json:"blobs"`
	Bytes     int64 `json:"bytes"`
	// Stopped are repositories the mass-delete brake stopped; nothing was
	// reaped in them, and the sweep is not retried.
	Stopped []string `json:"stopped,omitempty"`
	// Failed are repositories whose sweep failed for another reason.
	Failed []string `json:"failed,omitempty"`
	// Reviewing are repositories no scheduled sweep has reviewed yet; the
	// sweep only reported on them, as a scheduled one would.
	Reviewing []string `json:"reviewing,omitempty"`
	// Error says why the sweep did not run, or did not complete, when it did
	// not: too soon after the registry started, a brake, or the request
	// itself failing. The prune's deletions stand either way.
	Error string `json:"error,omitempty"`
}

// collectAuthorizer is the part of auth.Access the collect route uses.
type collectAuthorizer interface {
	Authorize(r *http.Request, verb api.Verb, n ref.Name) error
	Principal(r *http.Request) string
}

// repositorySweeper sweeps the named repositories (gc.Collector.SweepRepositories,
// behind the server's sweep fence). It returns errSweepBusy, having swept
// nothing, when a scheduled sweep or a dedupe pass holds the fence.
type repositorySweeper func(ctx context.Context, names []ref.Name) (gc.RepositoriesReport, error)

// errSweepBusy is a collect that found the fence held.
var errSweepBusy = errors.New("a sweep or dedupe pass is running")

// Limits of the collect route.
const (
	// collectBodyTimeout bounds the read of a collect request's body, so a
	// body trickled in a byte at a time cannot hold the handler.
	collectBodyTimeout = 10 * time.Second
	// collectMinInterval is the least time between the starts of two collects.
	collectMinInterval = time.Minute
	// collectRetryBusy is the Retry-After, in seconds, of a collect refused
	// because another collect, a sweep or a dedupe pass is running.
	collectRetryBusy = 60
)

// The fixed texts a collect answers in CollectResult.Error. The detail is in
// the server's log, never in the answer.
const (
	collectErrTooSoon    = "the registry started less than one grace period ago, so its garbage collection does not sweep yet"
	collectErrIncomplete = "the sweep did not complete; the registry log has the detail"
)

// collectGate admits one collect at a time, and none within
// collectMinInterval of the last one's start.
type collectGate struct {
	now func() time.Time
	// mu guards busy and last.
	mu   sync.Mutex
	busy bool
	last time.Time
}

// enter admits a collect, or returns how long to wait before another.
func (g *collectGate) enter() (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy {
		return collectRetryBusy * time.Second, false
	}
	if !g.last.IsZero() {
		if wait := g.last.Add(collectMinInterval).Sub(g.now()); wait > 0 {
			return wait, false
		}
	}
	g.busy = true
	return 0, true
}

// started records the start of an admitted collect that ran a sweep.
func (g *collectGate) started(at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.last = at
}

// leave ends an admitted collect.
func (g *collectGate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.busy = false
}

// tooMany answers 429 with a Retry-After of at least one second.
func tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int((wait + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	http.Error(w, "a collect is running or ran less than a minute ago; retry later", http.StatusTooManyRequests)
}

// collectRoute serves CollectPath with sweep and passes every other request to
// next. now is the clock of the minimum interval (time.Now when nil).
//
// The credential is checked once, before the body is read: the permission
// matrix (auth.Access) is global, a principal may delete in every repository
// or in none, so there is nothing per repository to check. Then one collect
// runs at a time and none within collectMinInterval of the last one's start;
// a refused one gets 429 and Retry-After, never a queued wait. The body has
// collectBodyTimeout to arrive. The sweep takes the fence only if it is free.
func collectRoute(next http.Handler, authz collectAuthorizer, sweep repositorySweeper, log *slog.Logger, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	gate := &collectGate{now: now}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CollectPath {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// The zero name: the matrix has no repository dimension.
		if err := authz.Authorize(r, api.VerbDelete, ref.Name{}); err != nil {
			switch {
			case errors.Is(err, api.ErrUnauthenticated):
				w.Header().Set("WWW-Authenticate", `Basic realm="k3sm"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
			case errors.Is(err, api.ErrRateLimited):
				http.Error(w, "too many requests", http.StatusTooManyRequests)
			default:
				http.Error(w, "requested access to the resource is denied", http.StatusForbidden)
			}
			return
		}
		wait, ok := gate.enter()
		if !ok {
			tooMany(w, wait)
			return
		}
		defer gate.leave()

		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Now().Add(collectBodyTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var req collectRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCollectBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "the collect request is not a repository list", http.StatusBadRequest)
			return
		}
		if err := rc.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(req.Repositories) == 0 || len(req.Repositories) > maxCollectRepositories {
			http.Error(w, fmt.Sprintf("a collect request names 1 to %d repositories", maxCollectRepositories), http.StatusBadRequest)
			return
		}
		names := make([]ref.Name, 0, len(req.Repositories))
		for _, s := range req.Repositories {
			n, err := ref.ParseName(s)
			if err != nil {
				http.Error(w, "the collect request names an invalid repository", http.StatusBadRequest)
				return
			}
			names = append(names, n)
		}
		at := now()
		rep, err := sweep(r.Context(), names)
		if errors.Is(err, errSweepBusy) {
			tooMany(w, collectRetryBusy*time.Second)
			return
		}
		gate.started(at)
		res := CollectResult{
			Repositories: req.Repositories,
			Stopped:      rep.Stopped,
			Failed:       rep.Failed,
			Reviewing:    rep.Reviewing,
		}
		if !rep.ReportOnly {
			res.Manifests = rep.Count(gc.KindManifest)
			res.Blobs = rep.Count(gc.KindBlob)
			res.Bytes = rep.BlobBytes
		}
		switch {
		case errors.Is(err, gc.ErrTooSoon):
			res.Error = collectErrTooSoon
		case err != nil:
			res.Error = collectErrIncomplete
		}
		log.Info("registry gc: swept the repositories a prune deleted from", "principal", authz.Principal(r),
			"source", r.RemoteAddr, "repositories", req.Repositories, "manifests", res.Manifests, "blobs", res.Blobs,
			"bytes", res.Bytes, "stopped", res.Stopped, "failed", res.Failed, "reviewing", res.Reviewing, "err", err)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			log.Debug("registry gc: the collect answer was not delivered", "err", err)
		}
	})
}

// prunedRepositories lists, sorted and once each, the repositories deleted
// names a manifest in.
func prunedRepositories(deleted []StoredManifest) []string {
	var repos []string
	for _, m := range deleted {
		repos = append(repos, m.Repository)
	}
	slices.Sort(repos)
	return slices.Compact(repos)
}

// CollectPruned asks the registry at authority (host:port, on loopback) to
// sweep the repositories deleted names a manifest in, as the push credential
// cred, and returns what the sweep did. It sends nothing when deleted is
// empty. The returned result names the repositories even when the request
// fails.
//
// The request has CollectTimeout to be answered, whatever ctx allows. Every
// string the registry answers with is passed through Printable, so a reply
// cannot write terminal controls into the operator's report.
//
// rt carries the request (nil uses http.DefaultTransport).
func CollectPruned(ctx context.Context, authority string, deleted []StoredManifest, cred Credential, rt http.RoundTripper) (CollectResult, error) {
	res := CollectResult{Repositories: prunedRepositories(deleted)}
	if len(res.Repositories) == 0 {
		return res, nil
	}
	ctx, cancel := context.WithTimeout(ctx, CollectTimeout)
	defer cancel()
	if rt == nil {
		rt = http.DefaultTransport
	}
	body, err := json.Marshal(collectRequest{Repositories: res.Repositories})
	if err != nil {
		return res, fmt.Errorf("collect the pruned repositories: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+authority+CollectPath, bytes.NewReader(body))
	if err != nil {
		return res, fmt.Errorf("collect the pruned repositories: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cred.Username, cred.Password)
	client := &http.Client{
		Transport: rt,
		// The answer comes from the registry itself; a redirect is not one.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, fmt.Errorf("collect the pruned repositories: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("collect the pruned repositories: the registry answered %s", Printable(resp.Status))
	}
	var got CollectResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCollectResponse)).Decode(&got); err != nil {
		return res, fmt.Errorf("collect the pruned repositories: read the answer: %w", err)
	}
	got.Repositories = res.Repositories
	got.Stopped = printables(got.Stopped)
	got.Failed = printables(got.Failed)
	got.Reviewing = printables(got.Reviewing)
	got.Error = Printable(got.Error)
	return got, nil
}

// Printable returns s without control or format characters (bidi overrides
// among them) and without invalid UTF-8, for printing a string another
// process supplied.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// printables is Printable over each string of ss.
func printables(ss []string) []string {
	for i, s := range ss {
		ss[i] = Printable(s)
	}
	return ss
}
