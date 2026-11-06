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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/auth"
	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// testClock is a clock the test moves; the store stamps blob writes with it
// and the collector reads it.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// collectServer is the registry server as runServer assembles it: the real
// access check and API over st, behind the collect route and its fenced sweep.
type collectServer struct {
	rt       handlerTransport
	cred     Credential
	gateCred Credential
	collects atomic.Int32
}

func newCollectServer(t *testing.T, st *store.Store, c *gc.Collector) *collectServer {
	t.Helper()
	s := &collectServer{
		cred:     Credential{Username: auth.UserPush, Password: "collect-test-secret"},
		gateCred: Credential{Username: auth.UserGate, Password: "collect-test-gate-secret"},
	}
	access, err := auth.New(auth.Config{Principals: []auth.Principal{
		{User: auth.UserPush, SecretSHA256: auth.HashSecret(s.cred.Password)},
		{User: auth.UserGate, SecretSHA256: auth.HashSecret(s.gateCred.Password)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := auth.NewServer(access, api.Config{Store: st, GCGrace: serveGCGrace, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	h := collectRoute(srv, access, fencedSweep(c, newSweepFence()), log, nil)
	s.rt = handlerTransport{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == CollectPath {
			s.collects.Add(1)
		}
		h.ServeHTTP(w, r)
	})}
	return s
}

// forcedPrune is one `k3sm image prune` of the registry half as the command
// runs it: plan each repository, re-check and conditionally DELETE each
// planned manifest under --force, then ask the server to collect the
// repositories it deleted from. A dry run plans only.
func (s *collectServer) prune(t *testing.T, workDir string, now time.Time, force bool) ([]StoredManifest, CollectResult) {
	t.Helper()
	repos, err := Repositories(workDir)
	if err != nil {
		t.Fatal(err)
	}
	auth := authn.FromConfig(authn.AuthConfig{Username: s.cred.Username, Password: s.cred.Password})
	var deleted []StoredManifest
	for _, repo := range repos {
		for _, m := range PlanRepository(workDir, repo, now).Delete {
			if !force {
				continue
			}
			reason, state := Recheck(workDir, m, now)
			if reason != "" {
				t.Fatalf("recheck %s@%s = %q; want it deletable", m.Repository, m.Digest, reason)
			}
			r, err := name.NewDigest("localhost:5000/" + m.Repository + "@" + m.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := DeleteManifest(t.Context(), r, state, auth, s.rt); err != nil {
				t.Fatalf("delete %s: %v", r, err)
			}
			deleted = append(deleted, m)
		}
	}
	res, err := CollectPruned(t.Context(), "localhost:5000", deleted, s.cred, s.rt)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return deleted, res
}

// storeImage uploads config and layers to n and puts a manifest naming them,
// under tag or by digest when tag is "". It returns the manifest's descriptor.
func storeImage(t *testing.T, st *store.Store, n ref.Name, tag string, config []byte, layers ...[]byte) ispec.Descriptor {
	t.Helper()
	put := func(b []byte, mediaType string) ispec.Descriptor {
		d := digest.FromBytes(b)
		if err := st.PutBlob(t.Context(), n, d, bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
		return ispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(b))}
	}
	m := ispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageManifest, Config: put(config, ispec.MediaTypeImageConfig)}
	for _, l := range layers {
		m.Layers = append(m.Layers, put(l, ispec.MediaTypeImageLayer))
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r := ref.Reference{Tag: tag}
	if tag == "" {
		r = ref.Reference{Digest: digest.FromBytes(body)}
	}
	desc, err := st.PutManifest(t.Context(), n, r, ispec.MediaTypeImageManifest, body)
	if err != nil {
		t.Fatal(err)
	}
	return desc
}

// TestPruneForceCollectsThePrunedRepositories proves a forced prune frees the
// layers of the manifests it deleted at once, through the server's collector
// and on its terms: a pruned model's layers older than the grace are gone after
// one forced prune, a layer written inside the grace stays, a layer another tag
// still holds stays, a repository the prune deleted nothing from is not swept,
// and a dry run frees nothing and asks for no sweep.
func TestPruneForceCollectsThePrunedRepositories(t *testing.T) {
	wd := t.TempDir()
	st, err := store.OpenWorkDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Truncate(time.Second)
	clk := &testClock{now: base.Add(-3 * time.Hour)}
	st.SetClock(clk.Now)
	collector, err := gc.New(st, gc.Options{Grace: serveGCGrace, Now: clk.Now, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	models, err := ref.ParseName("models/llama")
	if err != nil {
		t.Fatal(err)
	}
	other, err := ref.ParseName("other")
	if err != nil {
		t.Fatal(err)
	}

	// Two hours ago: a tagged model and an untagged one sharing a layer with
	// it, and, in another repository, a tagged image and an orphan blob.
	clk.set(base.Add(-2 * time.Hour))
	shared := []byte("shared base layer")
	oldLayer := []byte("pruned model weights")
	freshLayer := []byte("pruned model layer written again just now")
	storeImage(t, st, models, "v2", []byte(`{"model":"v2"}`), shared)
	pruned := storeImage(t, st, models, "", []byte(`{"model":"v1"}`), oldLayer, freshLayer, shared)
	storeImage(t, st, other, "v1", []byte(`{"other":"v1"}`), []byte("other layer"))
	orphan := []byte("an orphan blob in a repository the prune does not touch")
	if err := st.PutBlob(t.Context(), other, digest.FromBytes(orphan), bytes.NewReader(orphan)); err != nil {
		t.Fatal(err)
	}
	// Ten minutes ago a push wrote one of the pruned model's layers again,
	// which touches it: it is inside the grace.
	clk.set(base.Add(-10 * time.Minute))
	if err := st.PutBlob(t.Context(), models, digest.FromBytes(freshLayer), bytes.NewReader(freshLayer)); err != nil {
		t.Fatal(err)
	}
	clk.set(base)
	if err := gc.WriteMarker(st, base); err != nil {
		t.Fatal(err)
	}

	srv := newCollectServer(t, st, collector)
	has := func(n ref.Name, b []byte) bool {
		_, err := st.StatBlob(n, digest.FromBytes(b))
		return err == nil
	}
	hasDigest := func(n ref.Name, d digest.Digest) bool {
		_, err := st.StatBlob(n, d)
		return err == nil
	}
	modelConfig := []byte(`{"model":"v1"}`)
	mustStay := map[string]func() bool{
		"the fresh layer":           func() bool { return has(models, freshLayer) },
		"the layer v2 still holds":  func() bool { return has(models, shared) },
		"the orphan in other":       func() bool { return has(other, orphan) },
		"other's tagged image":      func() bool { return has(other, []byte("other layer")) },
		"the tagged model's config": func() bool { return has(models, []byte(`{"model":"v2"}`)) },
	}

	t.Run("a dry run frees nothing and asks for no sweep", func(t *testing.T) {
		deleted, res := srv.prune(t, wd, base, false)
		if len(deleted) != 0 || res.Blobs != 0 || res.Bytes != 0 || srv.collects.Load() != 0 {
			t.Fatalf("dry run: deleted %v, collect %+v, %d collect requests; want nothing", deleted, res, srv.collects.Load())
		}
		if !hasDigest(models, pruned.Digest) || !has(models, oldLayer) || !has(models, modelConfig) {
			t.Fatal("a dry run freed a blob")
		}
	})

	t.Run("one forced prune collects the pruned model", func(t *testing.T) {
		deleted, res := srv.prune(t, wd, base, true)
		if len(deleted) != 1 || deleted[0].Digest != pruned.Digest.String() {
			t.Fatalf("deleted %v; want only the untagged model %s", deleted, pruned.Digest)
		}
		if srv.collects.Load() != 1 {
			t.Errorf("%d collect requests; want one", srv.collects.Load())
		}
		if strings.Join(res.Repositories, ",") != "models/llama" {
			t.Errorf("collected %v; want exactly the repository the prune deleted from", res.Repositories)
		}
		if res.Error != "" || len(res.Stopped) != 0 || len(res.Failed) != 0 || len(res.Reviewing) != 0 {
			t.Errorf("collect %+v; want a clean sweep", res)
		}
		for what, b := range map[string][]byte{"the old layer": oldLayer, "the config": modelConfig} {
			if has(models, b) {
				t.Errorf("%s of the pruned model survived the forced prune", what)
			}
		}
		if hasDigest(models, pruned.Digest) {
			t.Error("the pruned manifest's body survived the forced prune")
		}
		wantBytes := pruned.Size + int64(len(oldLayer)) + int64(len(modelConfig))
		if res.Blobs != 3 || res.Bytes != wantBytes {
			t.Errorf("collect freed %d blobs, %d bytes; want 3 blobs, %d bytes", res.Blobs, res.Bytes, wantBytes)
		}
		for what, stays := range mustStay {
			if !stays() {
				t.Errorf("%s went", what)
			}
		}
	})
}

// TestCollectRouteRefusesWhatMayNotDelete proves the collect route is the push
// credential's alone and passes every other request through untouched.
func TestCollectRouteRefusesWhatMayNotDelete(t *testing.T) {
	wd := t.TempDir()
	st, err := store.OpenWorkDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	clk := &testClock{now: time.Now().Add(-2 * serveGCGrace)}
	collector, err := gc.New(st, gc.Options{Grace: serveGCGrace, Now: clk.Now, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	clk.set(time.Now())
	srv := newCollectServer(t, st, collector)
	send := func(method, path string, cred *Credential, body string) int {
		req, err := http.NewRequestWithContext(context.Background(), method, "http://localhost:5000"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if cred != nil {
			req.SetBasicAuth(cred.Username, cred.Password)
		}
		resp, err := srv.rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body) // drained only to close
		resp.Body.Close()
		return resp.StatusCode
	}
	wrong := Credential{Username: auth.UserPush, Password: "not the secret"}
	for _, tc := range []struct {
		name   string
		method string
		cred   *Credential
		body   string
		want   int
	}{
		{"anonymous", http.MethodPost, nil, `{"repositories":["app"]}`, http.StatusUnauthorized},
		{"a wrong secret", http.MethodPost, &wrong, `{"repositories":["app"]}`, http.StatusUnauthorized},
		{"the push gate", http.MethodPost, &srv.gateCred, `{"repositories":["app"]}`, http.StatusForbidden},
		{"a GET", http.MethodGet, &srv.cred, ``, http.StatusMethodNotAllowed},
		{"no repository", http.MethodPost, &srv.cred, `{"repositories":[]}`, http.StatusBadRequest},
		{"an invalid name", http.MethodPost, &srv.cred, `{"repositories":["../app"]}`, http.StatusBadRequest},
		{"an unknown field", http.MethodPost, &srv.cred, `{"repositories":["app"],"grace":"0s"}`, http.StatusBadRequest},
		{"the push credential", http.MethodPost, &srv.cred, `{"repositories":["app"]}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := send(tc.method, CollectPath, tc.cred, tc.body); got != tc.want {
				t.Errorf("status %d; want %d", got, tc.want)
			}
		})
	}
	if got := send(http.MethodGet, "/v2/", &srv.cred, ""); got != http.StatusOK {
		t.Errorf("GET /v2/ through the route: %d; want the API's own 200", got)
	}
}

// collectAccess is the real access check over the two test principals.
func collectAccess(t *testing.T) (*auth.Access, Credential, Credential) {
	t.Helper()
	push := Credential{Username: auth.UserPush, Password: "collect-test-secret"}
	gate := Credential{Username: auth.UserGate, Password: "collect-test-gate-secret"}
	access, err := auth.New(auth.Config{Principals: []auth.Principal{
		{User: auth.UserPush, SecretSHA256: auth.HashSecret(push.Password)},
		{User: auth.UserGate, SecretSHA256: auth.HashSecret(gate.Password)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return access, push, gate
}

// readCounter is a request body that counts the reads made of it.
type readCounter struct {
	r     io.Reader
	reads atomic.Int32
}

func (c *readCounter) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.r.Read(p)
}

// collectCall sends one collect through h and returns the status, the
// Retry-After header and the decoded answer on 200.
func collectCall(t *testing.T, h http.Handler, cred *Credential, body io.Reader) (int, string, CollectResult) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost:5000"+CollectPath, body)
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
	resp, err := handlerTransport{h: h}.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res CollectResult
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, resp.Header.Get("Retry-After"), res
}

// TestCollectRouteChecksTheCredentialBeforeTheBody proves a collect without a
// credential that may delete is refused before a byte of its body is read.
func TestCollectRouteChecksTheCredentialBeforeTheBody(t *testing.T) {
	access, _, gate := collectAccess(t)
	swept := false
	h := collectRoute(http.NotFoundHandler(), access, func(context.Context, []ref.Name) (gc.RepositoriesReport, error) {
		swept = true
		return gc.RepositoriesReport{}, nil
	}, slog.New(slog.DiscardHandler), nil)
	for _, tc := range []struct {
		name string
		cred *Credential
		want int
	}{
		{"anonymous", nil, http.StatusUnauthorized},
		{"the push gate", &gate, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &readCounter{r: strings.NewReader(`{"repositories":["app"]}`)}
			if got, _, _ := collectCall(t, h, tc.cred, body); got != tc.want {
				t.Errorf("status %d; want %d", got, tc.want)
			}
			if n := body.reads.Load(); n != 0 {
				t.Errorf("the body was read %d times before the refusal", n)
			}
		})
	}
	if swept {
		t.Error("a refused collect swept")
	}
}

// TestCollectRouteAdmitsOneAtATime proves the route runs one collect at a
// time, none within a minute of the last, and none while the fence is held,
// answering each refusal with 429 and Retry-After rather than a queued wait.
func TestCollectRouteAdmitsOneAtATime(t *testing.T) {
	access, push, _ := collectAccess(t)
	body := func() io.Reader { return strings.NewReader(`{"repositories":["app"]}`) }
	log := slog.New(slog.DiscardHandler)

	t.Run("a second collect while one runs", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		h := collectRoute(http.NotFoundHandler(), access, func(context.Context, []ref.Name) (gc.RepositoriesReport, error) {
			close(entered)
			<-release
			return gc.RepositoriesReport{}, nil
		}, log, nil)
		first := make(chan int, 1)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost:5000"+CollectPath, body())
		req.SetBasicAuth(push.Username, push.Password)
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			first <- rec.Code
		}()
		<-entered
		got, retry, _ := collectCall(t, h, &push, body())
		close(release)
		if got != http.StatusTooManyRequests || retry == "" {
			t.Errorf("concurrent collect: status %d, Retry-After %q; want 429 with Retry-After", got, retry)
		}
		if got := <-first; got != http.StatusOK {
			t.Errorf("first collect: status %d; want 200", got)
		}
	})

	t.Run("a collect within a minute of the last", func(t *testing.T) {
		clk := &testClock{now: time.Now()}
		h := collectRoute(http.NotFoundHandler(), access, func(context.Context, []ref.Name) (gc.RepositoriesReport, error) {
			return gc.RepositoriesReport{}, nil
		}, log, clk.Now)
		if got, _, _ := collectCall(t, h, &push, body()); got != http.StatusOK {
			t.Fatalf("first collect: %d", got)
		}
		clk.set(clk.Now().Add(20 * time.Second))
		if got, retry, _ := collectCall(t, h, &push, body()); got != http.StatusTooManyRequests || retry != "40" {
			t.Errorf("20 s later: status %d, Retry-After %q; want 429, 40", got, retry)
		}
		clk.set(clk.Now().Add(41 * time.Second))
		if got, _, _ := collectCall(t, h, &push, body()); got != http.StatusOK {
			t.Errorf("61 s later: status %d; want 200", got)
		}
	})

	t.Run("a collect while a sweep or pass holds the fence", func(t *testing.T) {
		wd := t.TempDir()
		st, err := store.OpenWorkDir(wd)
		if err != nil {
			t.Fatal(err)
		}
		c, err := gc.New(st, gc.Options{Grace: serveGCGrace, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		fence := newSweepFence()
		h := collectRoute(http.NotFoundHandler(), access, fencedSweep(c, fence), log, nil)
		fence.mu.Lock()
		got, retry, _ := collectCall(t, h, &push, body())
		fence.mu.Unlock()
		if got != http.StatusTooManyRequests || retry == "" {
			t.Errorf("fenced collect: status %d, Retry-After %q; want 429 with Retry-After", got, retry)
		}
		// A refusal for the fence is not a collect: the next one is admitted.
		if got, _, _ := collectCall(t, h, &push, body()); got != http.StatusOK {
			t.Errorf("after the fence: status %d; want 200", got)
		}
	})
}

// TestCollectRouteAnswersFixedErrors proves the answer carries one of two
// fixed texts, never the collector's error, which names server paths.
func TestCollectRouteAnswersFixedErrors(t *testing.T) {
	access, push, _ := collectAccess(t)
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"too soon", fmt.Errorf("%w: started then", gc.ErrTooSoon), collectErrTooSoon},
		{"a failure", fmt.Errorf("gc app: open /private/state/registry/app/index.json: %w", gc.ErrUnreadable), collectErrIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := collectRoute(http.NotFoundHandler(), access, func(context.Context, []ref.Name) (gc.RepositoriesReport, error) {
				return gc.RepositoriesReport{}, tc.err
			}, slog.New(slog.DiscardHandler), nil)
			got, _, res := collectCall(t, h, &push, strings.NewReader(`{"repositories":["app"]}`))
			if got != http.StatusOK || res.Error != tc.want {
				t.Errorf("status %d, error %q; want 200, %q", got, res.Error, tc.want)
			}
		})
	}
}

// TestCollectPrunedSanitisesAndBoundsTheAnswer proves the client strips
// control and format characters from what the registry answers, and gives
// the request its own deadline.
func TestCollectPrunedSanitisesAndBoundsTheAnswer(t *testing.T) {
	deleted := []StoredManifest{{Repository: "app", Digest: "sha256:aa"}}
	var deadline time.Time
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, _ = r.Context().Deadline()
		body := `{"stopped":["ap\u001b[2Jp"],"reviewing":["x\u202ey"],"error":"bad\u0007\nnews\u001b]0;title\u0007"}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})
	start := time.Now()
	res, err := CollectPruned(context.Background(), "localhost:5000", deleted, Credential{Username: "k3sm", Password: "pw"}, rt)
	if err != nil {
		t.Fatal(err)
	}
	if deadline.IsZero() || deadline.After(start.Add(CollectTimeout+time.Second)) {
		t.Errorf("request deadline %v; want one within %s", deadline, CollectTimeout)
	}
	if got := strings.Join(res.Stopped, ","); got != "ap[2Jp" {
		t.Errorf("stopped %q; want the escape stripped", got)
	}
	if got := strings.Join(res.Reviewing, ","); got != "xy" {
		t.Errorf("reviewing %q; want the bidi override stripped", got)
	}
	if res.Error != "badnews]0;title" {
		t.Errorf("error %q; want the controls stripped", res.Error)
	}
}
