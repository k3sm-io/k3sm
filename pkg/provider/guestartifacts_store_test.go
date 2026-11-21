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

package provider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The worker-side guest-artifact wiring: the pair comes from the cluster store
// once the runtime exists, and the runtime's vm backend takes it late. As with
// the release-host tests, the store's MECHANISM (layer matching, the digest
// refusal, the atomic install) is runtimed's; what is asserted here is the
// chain this repo owns: config -> store ensure -> refresh -> capability.

// testRegistryHost is the cluster registry authority the tests configure.
const testRegistryHost = "registry-k3sm:6450"

// fakeClusterStore serves one guest artifact by reference from memory.
type fakeClusterStore struct {
	mu sync.Mutex
	// layers maps a reference to its file name -> digest layers.
	layers map[string]map[string]string
	// blobs maps a "sha256:<hex>" digest to its bytes.
	blobs map[string][]byte
	// err, when non-nil, is returned by every pull.
	err error
	// pulled records each reference pulled.
	pulled []string
}

// newFakeClusterStore publishes pin's pair, with the bytes fetcher serves for
// it, under the active pin's store reference at testRegistryHost.
func newFakeClusterStore(t *testing.T, pin guestartifacts.GuestKernelPin, fetcher *fakeFetcher) *fakeClusterStore {
	t.Helper()
	art, err := guestartifacts.NewStoreArtifact(guestartifacts.ActiveGuestKernel, pin)
	if err != nil {
		t.Fatalf("NewStoreArtifact: %v", err)
	}
	s := &fakeClusterStore{layers: map[string]map[string]string{}, blobs: map[string][]byte{}}
	layers := map[string]string{}
	for _, l := range art.Layers {
		layers[l.FileName] = l.Digest
		s.blobs[l.Digest] = fetcher.files[pin.ReleaseURL+"/"+l.FileName]
	}
	s.layers[art.Reference(testRegistryHost)] = layers
	return s
}

func (s *fakeClusterStore) PullGuest(_ context.Context, ref string) (map[string]string, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pulled = append(s.pulled, ref)
	if s.err != nil {
		return nil, nil, s.err
	}
	l, ok := s.layers[ref]
	if !ok {
		return nil, nil, errors.New("fake store: no artifact at " + ref)
	}
	return l, func() {}, nil
}

func (s *fakeClusterStore) OpenBlob(digest string) (io.ReadCloser, error) {
	b, ok := s.blobs[digest]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (s *fakeClusterStore) pulls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.pulled...)
}

// fakeGuestRuntime records RefreshGuestArtifacts calls and answers with err.
type fakeGuestRuntime struct {
	err       error
	refreshed []EnsuredGuestArtifacts
}

func (f *fakeGuestRuntime) GuestClusterStore(*image.RegistryCredential) *artifact.GuestStore {
	return &artifact.GuestStore{}
}

func (f *fakeGuestRuntime) RefreshGuestArtifacts(pin guestartifacts.GuestKernelPin, art sandbox.GuestArtifacts) error {
	f.refreshed = append(f.refreshed, EnsuredGuestArtifacts{Pin: pin, Artifacts: art})
	return f.err
}

// TestEnsureGuestArtifactsFromClusterStore drives the worker-side ensure
// against a fake store and a fake runtime: which source it pulls, what it hands
// the vm backend, and how a refusal at either step degrades.
func TestEnsureGuestArtifactsFromClusterStore(t *testing.T) {
	pin, fetcher := mintedPin()
	ref := func(t *testing.T) string {
		art, err := guestartifacts.NewStoreArtifact(guestartifacts.ActiveGuestKernel, pin)
		if err != nil {
			t.Fatalf("NewStoreArtifact: %v", err)
		}
		return art.Reference(testRegistryHost)
	}

	tests := []struct {
		name        string
		storeErr    error
		refreshErr  error
		wantOK      bool
		wantRefresh bool
		wantLog     string
	}{
		{
			name:        "the store path is used and the ensured set is refreshed into the runtime",
			wantOK:      true,
			wantRefresh: true,
			wantLog:     "verified from the cluster store",
		},
		{
			name:        "a refresh error is logged and withholds the capability without crashing",
			refreshErr:  errors.New("vm backend refused"),
			wantRefresh: true,
			wantLog:     "vm backend refused",
		},
		{
			name:     "a store that cannot serve the pin withholds the capability and refreshes nothing",
			storeErr: errors.New("connection refused"),
			wantLog:  "could not be ensured from the cluster store",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			store := newFakeClusterStore(t, pin, fetcher)
			store.err = tc.storeErr
			rt := &fakeGuestRuntime{err: tc.refreshErr}
			var logs syncBuffer
			log := slog.New(slog.NewTextHandler(&logs, nil))
			src := GuestArtifactSource{Pin: pinFunc(pin, nil), Store: store, Fetcher: &fakeFetcher{err: errors.New("the release host must not be contacted")}, Timeout: 30 * time.Second}

			ga, ok := src.ensureFromStore(t.Context(), root, testRegistryHost, rt, log)
			if ok != tc.wantOK {
				t.Fatalf("ensureFromStore ok = %v, want %v; log:\n%s", ok, tc.wantOK, logs.String())
			}
			if got := store.pulls(); len(got) != 1 || got[0] != ref(t) {
				t.Errorf("store pulls = %q, want exactly [%q]", got, ref(t))
			}
			if src.Fetcher.(*fakeFetcher).calls != 0 {
				t.Errorf("the release-host fetcher was called on the cluster-store path")
			}
			if !tc.wantRefresh {
				if len(rt.refreshed) != 0 {
					t.Errorf("RefreshGuestArtifacts called %d times after a failed ensure", len(rt.refreshed))
				}
			} else {
				if len(rt.refreshed) != 1 {
					t.Fatalf("RefreshGuestArtifacts called %d times, want 1", len(rt.refreshed))
				}
				got := rt.refreshed[0]
				if got.Pin.SetDigest() != pin.SetDigest() {
					t.Errorf("refreshed pin %q, want %q", got.Pin.SetDigest(), pin.SetDigest())
				}
				if got.Artifacts.KernelPath == "" || got.Artifacts.InitramfsPath == "" || got.Artifacts.Cmdline != pin.Cmdline {
					t.Errorf("refreshed artifacts = %+v, want the ensured set with the pin's cmdline", got.Artifacts)
				}
				for _, p := range []string{got.Artifacts.KernelPath, got.Artifacts.InitramfsPath} {
					if _, err := os.Stat(p); err != nil {
						t.Errorf("refreshed artifact not on disk: %v", err)
					}
				}
				if tc.wantOK && got != ga {
					t.Errorf("refreshed %+v, but ensure returned %+v", got, ga)
				}
			}
			if !tc.wantOK && ga != (EnsuredGuestArtifacts{}) {
				t.Errorf("a failed ensure returned a set: %+v", ga)
			}
			if !strings.Contains(logs.String(), tc.wantLog) {
				t.Errorf("log does not mention %q:\n%s", tc.wantLog, logs.String())
			}
		})
	}
}

// TestNewRuntimedGuestFromClusterStore asserts the store ensure through the
// production constructor: a worker ensures from the store once the runtime
// exists, a worker with no cluster registry gets no release-host fallback, and a
// node that is not a worker keeps the release-host set wired at construction.
func TestNewRuntimedGuestFromClusterStore(t *testing.T) {
	pin, fetcher := mintedPin()
	flat := image.FlatRegistry{Host: testRegistryHost, Endpoint: image.RegistryEndpoint{Addr: "127.0.0.1:1"}}

	tests := []struct {
		name      string
		worker    bool
		flat      image.FlatRegistry
		preEnsure bool
		wantPull  bool
		wantCaps  bool
		wantLog   string
	}{
		{
			name:     "a worker with a cluster registry ensures from the store after construction",
			worker:   true,
			flat:     flat,
			wantPull: true,
			wantCaps: true,
		},
		{
			name:    "a worker with no cluster registry withholds the capability with no release-host fallback",
			worker:  true,
			wantLog: errGuestStoreUnavailable.Error(),
		},
		{
			name:      "a node that is not a worker keeps the release-host set wired at construction",
			preEnsure: true,
			wantCaps:  true,
		},
		{
			name: "a node that is not a worker never touches the store, registry or not",
			flat: flat,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stageExecShim(t)
			root := t.TempDir()
			store := newFakeClusterStore(t, pin, fetcher)
			var logs syncBuffer
			cfg := RuntimedConfig{
				NodeName: "n1",
				Root:     root, PodLogsDir: root,
				FlatRegistry: tc.flat,
				Logger:       slog.New(slog.NewTextHandler(&logs, nil)),
			}
			if tc.worker {
				cfg.GuestStore = &GuestArtifactSource{Pin: pinFunc(pin, nil), Store: store, Timeout: 30 * time.Second}
			}
			// The caller (cmd/k3sm) runs the release-host ensure iff this is false,
			// so a worker must report true even with no registry mapped.
			if got := cfg.GuestFromClusterStore(); got != tc.worker {
				t.Fatalf("GuestFromClusterStore() = %v, want %v", got, tc.worker)
			}
			if tc.preEnsure {
				ga, ok := GuestArtifactSource{Pin: pinFunc(pin, nil), Fetcher: fetcher, Timeout: 30 * time.Second}.
					Ensure(t.Context(), root, slog.New(slog.DiscardHandler))
				if !ok {
					t.Fatalf("release-host Ensure failed")
				}
				cfg.GuestArtifacts = &ga
			}
			rt, err := NewRuntimed(context.Background(), cfg)
			if err != nil {
				t.Fatalf("NewRuntimed: %v (a guest-artifact outcome must never fail daemon start)", err)
			}
			if pulled := len(store.pulls()) > 0; pulled != tc.wantPull {
				t.Errorf("cluster store pulled = %v, want %v", pulled, tc.wantPull)
			}
			if caps := rt.Capabilities(t.Context()); caps.VMArtifacts != tc.wantCaps {
				t.Errorf("Capabilities().VMArtifacts = %v, want %v", caps.VMArtifacts, tc.wantCaps)
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Errorf("log does not name %q:\n%s", tc.wantLog, logs.String())
			}
			if !tc.wantCaps && !artifactDirEmpty(t, root) {
				t.Errorf("a withheld ensure left a guest-artifact set in %s", GuestArtifactsDir(root))
			}
			assertRuntimeStillServes(t, rt)
		})
	}
}
