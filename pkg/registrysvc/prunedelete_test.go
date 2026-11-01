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
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestPruneDeleteIsConditionalOnPlannedState proves a prune DELETE names the
// repository state its re-check read, and that the registry server refuses it
// once a push has changed the repository in between: the window Recheck alone
// leaves open, between its read and the request. Each case re-checks a
// planned manifest, then lands a push (as one arriving mid-request would),
// then sends the delete through the real API server over the same store.
func TestPruneDeleteIsConditionalOnPlannedState(t *testing.T) {
	old := 2 * time.Hour

	type setup struct {
		wd   string
		st   *store.Store
		repo ref.Name
	}
	newRepo := func(t *testing.T, bodies ...[]byte) setup {
		t.Helper()
		wd := t.TempDir()
		st, err := store.OpenWorkDir(wd)
		if err != nil {
			t.Fatal(err)
		}
		repo, err := ref.ParseName("app")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Init(t.Context(), repo); err != nil {
			t.Fatal(err)
		}
		for _, b := range bodies {
			if _, err := st.PutManifest(t.Context(), repo, ref.Reference{Digest: digest.FromBytes(b)}, manifestType, b); err != nil {
				t.Fatal(err)
			}
			ageBlobs(t, wd, "app", old, digestOf(b))
		}
		return setup{wd: wd, st: st, repo: repo}
	}
	server := func(t *testing.T, st *store.Store) handlerTransport {
		t.Helper()
		srv, err := api.New(api.Config{Store: st, GCGrace: time.Hour, Authorize: api.AllowAll, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return handlerTransport{h: srv}
	}
	recheck := func(t *testing.T, s setup, body []byte) (StoredManifest, string) {
		t.Helper()
		m := StoredManifest{Repository: "app", Digest: digestOf(body)}
		reason, state := Recheck(s.wd, m, time.Now())
		if reason != "" || state == "" {
			t.Fatalf("recheck %s = %q, state %q; want it deletable with a state", m.Digest, reason, state)
		}
		return m, state
	}
	digestRef := func(t *testing.T, m StoredManifest) name.Digest {
		t.Helper()
		r, err := name.NewDigest("127.0.0.1:6450/" + m.Repository + "@" + m.Digest)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	present := func(s setup, body []byte) bool {
		_, _, err := s.st.Manifest(s.repo, ref.Reference{Digest: digest.FromBytes(body)})
		return err == nil
	}

	t.Run("a tag pushed onto the planned digest after the re-check is kept", func(t *testing.T) {
		a := manifestBody("a")
		s := newRepo(t, a)
		m, state := recheck(t, s, a)
		if _, err := s.st.PutManifest(t.Context(), s.repo, ref.Reference{Tag: "v1"}, manifestType, a); err != nil {
			t.Fatal(err)
		}
		err := DeleteManifest(t.Context(), digestRef(t, m), state, authn.Anonymous, server(t, s.st))
		if !errors.Is(err, ErrChangedSincePlan) {
			t.Fatalf("delete = %v; want ErrChangedSincePlan", err)
		}
		if d, err := s.st.Resolve(s.repo, ref.Reference{Tag: "v1"}); err != nil || d.Digest.String() != m.Digest {
			t.Errorf("v1 = %v, %v; the tag pushed after the re-check must survive", d, err)
		}
	})

	t.Run("a referrer whose subject is tagged after the re-check is kept", func(t *testing.T) {
		subj := manifestBody("subject")
		refr := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":%q,"subject":{"mediaType":%q,"digest":%q,"size":%d}}`, manifestType, manifestType, digestOf(subj), len(subj))
		s := newRepo(t, subj, refr)
		m, state := recheck(t, s, refr)
		if _, err := s.st.PutManifest(t.Context(), s.repo, ref.Reference{Tag: "v1"}, manifestType, subj); err != nil {
			t.Fatal(err)
		}
		if err := DeleteManifest(t.Context(), digestRef(t, m), state, authn.Anonymous, server(t, s.st)); !errors.Is(err, ErrChangedSincePlan) {
			t.Fatalf("delete = %v; want ErrChangedSincePlan", err)
		}
		if !present(s, refr) {
			t.Error("the referrer of a subject tagged after the re-check was deleted")
		}
	})

	t.Run("an unchanged repository deletes", func(t *testing.T) {
		a, b := manifestBody("a"), manifestBody("b")
		s := newRepo(t, a, b)
		m, state := recheck(t, s, a)
		if err := DeleteManifest(t.Context(), digestRef(t, m), state, authn.Anonymous, server(t, s.st)); err != nil {
			t.Fatalf("delete = %v; want it accepted", err)
		}
		if present(s, a) || !present(s, b) {
			t.Errorf("after the delete a present %v, b present %v; want only a gone", present(s, a), present(s, b))
		}
	})

	t.Run("a registry that ignores If-Match deletes unconditionally", func(t *testing.T) {
		// zot implements no conditional DELETE: for it the window stays open,
		// and this is the loss the k3sm server refuses above.
		a := manifestBody("a")
		s := newRepo(t, a)
		m, state := recheck(t, s, a)
		if _, err := s.st.PutManifest(t.Context(), s.repo, ref.Reference{Tag: "v1"}, manifestType, a); err != nil {
			t.Fatal(err)
		}
		cred := Credential{Username: "k3sm", Password: "pw"}
		auth := authn.FromConfig(authn.AuthConfig{Username: cred.Username, Password: cred.Password})
		if err := DeleteManifest(t.Context(), digestRef(t, m), state, auth, handlerTransport{h: fakeDeleteAPI(t, s.st, cred)}); err != nil {
			t.Fatalf("delete = %v", err)
		}
		if _, err := s.st.Resolve(s.repo, ref.Reference{Tag: "v1"}); !errors.Is(err, store.ErrManifestUnknown) {
			t.Errorf("v1 = %v; a registry ignoring If-Match drops the tag", err)
		}
	})
}

// TestRecheckFailsClosed proves the re-check keeps a planned manifest whenever
// it cannot read the repository's current state, and reports a repository the
// store no longer holds as gone rather than unreadable.
func TestRecheckFailsClosed(t *testing.T) {
	old := 2 * time.Hour
	a, b := manifestBody("a"), manifestBody("b")
	plan := func(t *testing.T) (string, PrunePlan) {
		t.Helper()
		wd := t.TempDir()
		layoutRepo(t, wd, "r", idx(row(a, manifestType, ""), row(b, manifestType, "")), map[string][]byte{digestOf(a): a, digestOf(b): b}, old)
		p := PlanRepository(wd, "r", time.Now())
		if len(p.Delete) != 2 {
			t.Fatalf("delete = %v; want both planned", digests(p.Delete))
		}
		return wd, p
	}
	repoDir := func(wd string) string { return filepath.Join(StateDir(wd), "r") }

	for _, tc := range []struct {
		name    string
		breakIt func(t *testing.T, wd string)
		want    KeepReason
	}{
		{"an index that no longer parses", func(t *testing.T, wd string) {
			if err := os.WriteFile(filepath.Join(repoDir(wd), "index.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a store root that can no longer be opened", func(t *testing.T, wd string) {
			if err := os.RemoveAll(StateDir(wd)); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a sibling manifest that can no longer be read", func(t *testing.T, wd string) {
			if err := os.Remove(filepath.Join(repoDir(wd), "blobs", "sha256", digest.Digest(digestOf(b)).Encoded())); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository the store no longer holds", func(t *testing.T, wd string) {
			if err := os.RemoveAll(repoDir(wd)); err != nil {
				t.Fatal(err)
			}
		}, GoneSincePlan},
		// A directory still there but failing the store's repository check
		// is damaged, not gone: the store calls both ErrRepositoryUnknown.
		{"a repository directory missing its layout file", func(t *testing.T, wd string) {
			if err := os.Remove(filepath.Join(repoDir(wd), "oci-layout")); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository directory missing its index", func(t *testing.T, wd string) {
			if err := os.Remove(filepath.Join(repoDir(wd), "index.json")); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository directory whose index is a directory", func(t *testing.T, wd string) {
			p := filepath.Join(repoDir(wd), "index.json")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository directory whose index is a symlink", func(t *testing.T, wd string) {
			p := filepath.Join(repoDir(wd), "index.json")
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".real", p); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository directory missing its blobs", func(t *testing.T, wd string) {
			if err := os.RemoveAll(filepath.Join(repoDir(wd), "blobs")); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository directory replaced by a symlink", func(t *testing.T, wd string) {
			real := filepath.Join(wd, "elsewhere")
			if err := os.Rename(repoDir(wd), real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, repoDir(wd)); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
		{"a repository path that is now a file", func(t *testing.T, wd string) {
			if err := os.RemoveAll(repoDir(wd)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(repoDir(wd), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, KeepUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wd, p := plan(t)
			tc.breakIt(t, wd)
			reason, state := Recheck(wd, p.Delete[0], time.Now())
			if reason != tc.want || state != "" {
				t.Errorf("recheck = %q, state %q; want %q and no state", reason, state, tc.want)
			}
			again := PlanRepository(wd, "r", time.Now())
			switch {
			case len(again.Delete) != 0:
				t.Errorf("plan after the break deletes %v; want nothing", digests(again.Delete))
			case tc.want == GoneSincePlan && len(again.Unreadable) != 0:
				t.Errorf("plan of a repository gone from the store = %+v; want nothing unreadable", again)
			case tc.want == KeepUnreadable && len(again.Unreadable) == 0 && len(again.Kept) == 0:
				t.Errorf("plan of a damaged repository = %+v; want it unreadable or every manifest kept", again)
			}
		})
	}
}

// TestRecheckReasonWording pins the two words a report prints for a repository
// the re-check cannot plan: an absent one is gone, a damaged one is unreadable.
func TestRecheckReasonWording(t *testing.T) {
	if GoneSincePlan != "already gone since the plan" {
		t.Errorf("GoneSincePlan = %q", GoneSincePlan)
	}
	if KeepUnreadable != "repository not fully readable" {
		t.Errorf("KeepUnreadable = %q", KeepUnreadable)
	}
}

// TestDeleteManifestRefusesNoState proves an empty state is an error and
// sends no request at all: the delete is never unconditional by omission.
func TestDeleteManifestRefusesNoState(t *testing.T) {
	var sent int
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		sent++
		return nil, errors.New("no request may be sent")
	})
	r, err := name.NewDigest("127.0.0.1:6450/app@" + digestOf(manifestBody("a")))
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteManifest(t.Context(), r, "", authn.Anonymous, rt); !errors.Is(err, ErrNoState) {
		t.Errorf("delete with no state = %v; want ErrNoState", err)
	}
	if sent != 0 {
		t.Errorf("%d requests sent; want none", sent)
	}
}

// roundTripFunc is an http.RoundTripper from a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
