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
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
	"k3sm.io/runtimed/pkg/image"
)

// TestServerRuntimedConfigCarriesLocalBlobSource pins the runtime config a
// server builds: it names the registry store it serves, and the runtimed
// config hands the puller a source that reads exactly that store, so a blob
// the registry holds is offered to the image cache.
func TestServerRuntimedConfigCarriesLocalBlobSource(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "registry")
	st, err := store.Open(root, filepath.Join(work, "registry-state"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := ref.ParseName("apps/web")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("a layer pushed to the cluster registry\n")
	d := digest.FromBytes(body)
	if err := st.PutBlob(context.Background(), n, d, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}

	cfg := runtimedConfigOf(RuntimedConfig{RegistryStoreRoot: root}, slog.New(slog.DiscardHandler), "", "")
	if cfg.LocalBlobSource == nil {
		t.Fatal("a server's runtimed config carries no local blob source")
	}
	src, ok := cfg.LocalBlobSource.(*store.LocalBlobSource)
	if !ok {
		t.Fatalf("LocalBlobSource is %T, want *store.LocalBlobSource", cfg.LocalBlobSource)
	}
	if src.Root() != root {
		t.Fatalf("LocalBlobSource reads %q, want the registry store %q", src.Root(), root)
	}
	f, size, err := cfg.LocalBlobSource.OpenBlob(d.String())
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(body)) || !bytes.Equal(got, body) {
		t.Fatalf("OpenBlob = %d bytes %q, want %q", size, got, body)
	}
	if _, _, err := cfg.LocalBlobSource.OpenBlob(digest.FromBytes([]byte("absent")).String()); !errors.Is(err, image.ErrBlobNotLocal) {
		t.Fatalf("OpenBlob(absent) = %v, want ErrBlobNotLocal", err)
	}
}

// TestAgentRuntimedConfigHasNoLocalBlobSource pins the other side: a config
// that names no registry store (an agent, a standalone node, a server whose
// registry did not start) leaves runtimed with no source at all — a nil
// interface, not a typed nil the puller would call.
func TestAgentRuntimedConfigHasNoLocalBlobSource(t *testing.T) {
	cfg := runtimedConfigOf(RuntimedConfig{}, slog.New(slog.DiscardHandler), "", "")
	if cfg.LocalBlobSource != nil {
		t.Fatalf("an agent's runtimed config carries a local blob source: %#v", cfg.LocalBlobSource)
	}
}
