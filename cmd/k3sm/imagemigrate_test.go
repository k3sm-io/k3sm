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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// fakeNodeStore is a node store the migration reads. It has no write verb at
// all, so "the migration never deletes" holds by construction; what the tests
// still check is that every entry is accounted for and that a resumed run does
// not export again.
type fakeNodeStore struct {
	mu      sync.Mutex
	entries []storeEntry
	images  map[string]ggcrv1.Image // by manifest digest
	broken  map[string]bool         // digests whose export fails
	exports []string
}

func (s *fakeNodeStore) List(context.Context) ([]storeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]storeEntry(nil), s.entries...), nil
}

func (s *fakeNodeStore) Export(_ context.Context, e storeEntry) (ggcrv1.Image, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exports = append(s.exports, e.Reference+"|"+e.Platform)
	if s.broken[e.Digest] {
		return nil, nil, errors.New("the store cannot export it")
	}
	img, ok := s.images[e.Digest]
	if !ok {
		return nil, nil, errors.New("no such digest")
	}
	return img, func() {}, nil
}

// add records img in the store under ref and platform.
func (s *fakeNodeStore) add(t *testing.T, ref, platform string, img ggcrv1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if s.images == nil {
		s.images = map[string]ggcrv1.Image{}
	}
	s.images[d.String()] = img
	s.entries = append(s.entries, storeEntry{Reference: ref, Platform: platform, Digest: d.String()})
	return d.String()
}

func randomImage(t *testing.T) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// countingPusher wraps the production pusher, counting uploads and failing
// the ones fail selects.
type countingPusher struct {
	mu    sync.Mutex
	calls []string
	fail  func(ref name.Reference) bool
}

func (p *countingPusher) push(ctx context.Context, ref name.Reference, b built, dest pushDest) error {
	p.mu.Lock()
	p.calls = append(p.calls, ref.String())
	p.mu.Unlock()
	if p.fail != nil && p.fail(ref) {
		return errors.New("the registry went away")
	}
	return pushBuilt(ctx, ref, b, dest)
}

// migrationRig is a real in-memory registry on loopback, this server's push
// credential for it, and a node store. Its migrator writes the way the
// server's daemon does (serverMigrationRoute).
type migrationRig struct {
	host    string
	workDir string
	store   *fakeNodeStore
	pusher  *countingPusher
	// upstream is the set of (reference, digest) its own registry serves.
	upstream map[string]string
}

func newMigrationRig(t *testing.T) *migrationRig {
	t.Helper()
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")
	host, _ := startRegistry(t, "")
	workDir, _ := stageLocalCredential(t, host)
	return &migrationRig{host: host, workDir: workDir, store: &fakeNodeStore{}, pusher: &countingPusher{}, upstream: map[string]string{}}
}

func (r *migrationRig) migrator() imageMigrator {
	return imageMigrator{
		workDir:  r.workDir,
		source:   r.store,
		route:    serverMigrationRoute(r.workDir),
		digestAt: registryDigestAt,
		push:     r.pusher.push,
		upstream: func(_ context.Context, ref, digest string) bool { return r.upstream[ref] == digest },
		isLocal:  func(ref string) bool { return namesClusterRegistry(ref, r.workDir) },
		now:      func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) },
	}
}

// loopbackRef spells a registry-k3sm:6450 reference as this Mac reaches it.
func (r *migrationRig) loopbackRef(t *testing.T, flat string) string {
	t.Helper()
	target, err := migrationWriter{authority: r.host}.target(flat)
	if err != nil {
		t.Fatal(err)
	}
	return target.String()
}

// registryDigest is the digest the registry holds at a flat reference, or "".
func (r *migrationRig) registryDigest(t *testing.T, flat string) string {
	t.Helper()
	ref, err := name.ParseReference(r.loopbackRef(t, flat))
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref, remote.WithContext(t.Context()))
	if err != nil {
		return ""
	}
	return desc.Digest.String()
}

// TestStoreMigrationImportsEveryUserImageAndLosesNone is B911's gate: every
// user image in the node store reaches the cluster registry at its digest; a
// public cache entry is left a cache entry; a tag the registry holds at
// another digest keeps the registry's image while the node's copy lands under
// the -k3sm-migrated-<12hex> suffix; an unexportable image stays held; and the
// node store is exactly what it was.
func TestStoreMigrationImportsEveryUserImageAndLosesNone(t *testing.T) {
	rig := newMigrationRig(t)
	s := rig.store

	appDigest := s.add(t, "docker.io/library/app:dev", "darwin/arm64", randomImage(t))
	local := s.add(t, rig.host+"/team/svc:v1", "darwin/arm64", randomImage(t))
	amd := s.add(t, "example.test/multi:v2", "linux/amd64", randomImage(t))
	arm := s.add(t, "example.test/multi:v2", "linux/arm64", randomImage(t))
	nginx := s.add(t, "docker.io/library/nginx:1.27", "linux/arm64", randomImage(t))
	rig.upstream["docker.io/library/nginx:1.27"] = nginx
	conflict := s.add(t, "example.test/conflict:v1", "darwin/arm64", randomImage(t))
	broken := s.add(t, "example.test/broken:v1", "darwin/arm64", randomImage(t))
	s.broken = map[string]bool{broken: true}
	pinnedImg := randomImage(t)
	pinnedDigest, _ := pinnedImg.Digest()
	pinned := s.add(t, "example.test/pinned@"+pinnedDigest.String(), "darwin/arm64", pinnedImg)

	// A build since the upgrade already wrote conflict:v1 into the registry.
	newer := randomImage(t)
	newerDigest, _ := newer.Digest()
	if err := pushBuilt(t.Context(), mustTag(t, rig.loopbackRef(t, "registry-k3sm:6450/conflict:v1")), built{image: newer}, pushDest{workDir: rig.workDir}); err != nil {
		t.Fatalf("seed the registry: %v", err)
	}

	before, _ := s.List(t.Context())
	j, err := rig.migrator().run(t.Context())
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	after, _ := s.List(t.Context())
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("the node store changed:\nbefore %v\nafter  %v", before, after)
	}
	if !j.Complete {
		t.Errorf("the journal is not complete after a full run")
	}

	renamed := "registry-k3sm:6450/conflict:v1-k3sm-migrated-" + strings.TrimPrefix(conflict, "sha256:")[:12]
	pinnedTarget := "registry-k3sm:6450/pinned:k3sm-migrated-" + strings.TrimPrefix(pinned, "sha256:")[:12]
	want := map[string]struct{ outcome, target, digest string }{
		"docker.io/library/app:dev":     {migrationMigrated, "registry-k3sm:6450/app:dev", appDigest},
		rig.host + "/team/svc:v1":       {migrationMigrated, "registry-k3sm:6450/team/svc:v1", local},
		"example.test/conflict:v1":      {migrationRenamed, renamed, conflict},
		"example.test/broken:v1":        {migrationUnexportable, "", ""},
		"docker.io/library/nginx:1.27":  {migrationCached, "", ""},
		"example.test/pinned@" + pinned: {migrationMigrated, pinnedTarget, pinned},
		"example.test/multi:v2":         {migrationMigrated, "registry-k3sm:6450/multi:v2", ""},
	}
	if len(j.Images) != len(want) {
		t.Fatalf("journal has %d images, want %d: %+v", len(j.Images), len(want), j.Images)
	}
	for _, rec := range j.Images {
		w, ok := want[rec.Reference]
		if !ok {
			t.Errorf("unexpected journal record %+v", rec)
			continue
		}
		if rec.Outcome != w.outcome || rec.Target != w.target {
			t.Errorf("%s: outcome %s target %q, want %s %q (%s)", rec.Reference, rec.Outcome, rec.Target, w.outcome, w.target, rec.Detail)
		}
		if w.digest != "" && rec.Digest != w.digest {
			t.Errorf("%s: journaled digest %s, want %s", rec.Reference, rec.Digest, w.digest)
		}
		// Nothing is lost: what the journal says is in the registry is there,
		// at the digest it says.
		if migrationInRegistry(rec.Outcome) {
			if got := rig.registryDigest(t, rec.Target); got != rec.Digest {
				t.Errorf("%s: registry holds %q at %s, journal says %s", rec.Reference, got, rec.Target, rec.Digest)
			}
		}
	}

	// The multi-platform reference is one index holding both platforms.
	idxRef, _ := name.ParseReference(rig.loopbackRef(t, "registry-k3sm:6450/multi:v2"))
	idx, err := remote.Index(idxRef, remote.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("read back the migrated index: %v", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	var children []string
	for _, m := range im.Manifests {
		children = append(children, m.Digest.String()+"@"+m.Platform.String())
	}
	if wantChildren := []string{amd + "@linux/amd64", arm + "@linux/arm64"}; !reflect.DeepEqual(children, wantChildren) {
		t.Errorf("index children %v, want %v", children, wantChildren)
	}

	// The registry's newer image keeps its tag.
	if got := rig.registryDigest(t, "registry-k3sm:6450/conflict:v1"); got != newerDigest.String() {
		t.Errorf("conflict:v1 now holds %s, want the registry's own %s", got, newerDigest)
	}
	// The cache entry was never exported or pushed.
	for _, e := range s.exports {
		if strings.HasPrefix(e, "docker.io/library/nginx") {
			t.Errorf("the public cache entry was exported")
		}
	}

	var report bytes.Buffer
	renderMigrationReport(&report, j)
	if !strings.Contains(report.String(), "image migration complete: 4 migrated, 0 already present, 1 renamed, 1 cache entries left, 1 held (unexportable)") {
		t.Errorf("report:\n%s", report.String())
	}
}

// TestStoreMigrationResumes pins resumability: an interrupted run leaves a
// journal the next run continues from without exporting finished images again,
// a finished run re-checks the registry and exports nothing, and an image the
// registry lost since is pushed again.
func TestStoreMigrationResumes(t *testing.T) {
	t.Run("an interrupted run resumes where it stopped", func(t *testing.T) {
		rig := newMigrationRig(t)
		rig.store.add(t, "example.test/app-a:v1", "darwin/arm64", randomImage(t))
		rig.store.add(t, "example.test/app-b:v1", "darwin/arm64", randomImage(t))
		rig.store.add(t, "example.test/app-c:v1", "darwin/arm64", randomImage(t))
		rig.pusher.fail = func(ref name.Reference) bool { return strings.Contains(ref.String(), "/app-b:") }

		j, err := rig.migrator().run(t.Context())
		if err == nil {
			t.Fatalf("a failed push did not stop the run")
		}
		if j.Complete {
			t.Errorf("an interrupted run journaled complete")
		}
		onDisk, rerr := readMigrationJournal(rig.workDir)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if len(onDisk.Images) != 1 || onDisk.Images[0].Reference != "example.test/app-a:v1" || onDisk.Complete {
			t.Fatalf("journal after the interruption: %+v", onDisk)
		}

		rig.pusher.fail = nil
		rig.store.exports = nil
		j, err = rig.migrator().run(t.Context())
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		if !j.Complete || j.summary().Migrated != 3 {
			t.Errorf("after resuming: %+v", j)
		}
		if want := []string{"example.test/app-b:v1|darwin/arm64", "example.test/app-c:v1|darwin/arm64"}; !reflect.DeepEqual(rig.store.exports, want) {
			t.Errorf("the resumed run exported %v, want only %v", rig.store.exports, want)
		}
	})

	t.Run("a finished run exports and pushes nothing", func(t *testing.T) {
		rig := newMigrationRig(t)
		rig.store.add(t, "example.test/app-a:v1", "darwin/arm64", randomImage(t))
		if _, err := rig.migrator().run(t.Context()); err != nil {
			t.Fatal(err)
		}
		rig.store.exports, rig.pusher.calls = nil, nil
		j, err := rig.migrator().run(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(rig.store.exports) != 0 || len(rig.pusher.calls) != 0 {
			t.Errorf("the re-run exported %v and pushed %v", rig.store.exports, rig.pusher.calls)
		}
		if j.summary().Migrated != 1 {
			t.Errorf("the re-run changed the record: %+v", j.Images)
		}
	})

	t.Run("an image the registry already holds is recorded present, not pushed", func(t *testing.T) {
		rig := newMigrationRig(t)
		img := randomImage(t)
		rig.store.add(t, "example.test/app-a:v1", "darwin/arm64", img)
		if err := pushBuilt(t.Context(), mustTag(t, rig.loopbackRef(t, "registry-k3sm:6450/app-a:v1")), built{image: img}, pushDest{workDir: rig.workDir}); err != nil {
			t.Fatal(err)
		}
		j, err := rig.migrator().run(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(rig.pusher.calls) != 0 || j.Images[0].Outcome != migrationPresent {
			t.Errorf("pushed %v, record %+v", rig.pusher.calls, j.Images[0])
		}
	})

	t.Run("an unexportable image is retried and migrates once it can be read", func(t *testing.T) {
		rig := newMigrationRig(t)
		d := rig.store.add(t, "example.test/app-a:v1", "darwin/arm64", randomImage(t))
		rig.store.broken = map[string]bool{d: true}
		j, err := rig.migrator().run(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if j.Images[0].Outcome != migrationUnexportable {
			t.Fatalf("record %+v", j.Images[0])
		}
		rig.store.broken = nil
		j, err = rig.migrator().run(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if j.Images[0].Outcome != migrationMigrated {
			t.Errorf("after the retry: %+v", j.Images[0])
		}
	})

	t.Run("a journal of an unknown schema is refused", func(t *testing.T) {
		rig := newMigrationRig(t)
		if err := os.MkdirAll(migrationDir(rig.workDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(migrationJournalPath(rig.workDir), []byte(`{"schema":9,"images":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := rig.migrator().run(t.Context()); err == nil || !strings.Contains(err.Error(), "schema 9") {
			t.Errorf("err = %v, want the schema refusal", err)
		}
	})
}

// TestMigrationTarget pins how a node-store reference is named in the
// cluster registry.
func TestMigrationTarget(t *testing.T) {
	const d = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ in, want string }{
		{"app:dev", "registry-k3sm:6450/app:dev"},
		{"docker.io/library/app:dev", "registry-k3sm:6450/app:dev"},
		{"index.docker.io/library/app:dev", "registry-k3sm:6450/app:dev"},
		{"docker.io/me/app:dev", "registry-k3sm:6450/me/app:dev"},
		{"localhost:6450/team/svc:v1", "registry-k3sm:6450/team/svc:v1"},
		{"registry-k3sm:6450/team/svc:v1", "registry-k3sm:6450/team/svc:v1"},
		{"ghcr.io/org/tool:1.0", "registry-k3sm:6450/org/tool:1.0"},
		{"example.test/pinned@" + d, "registry-k3sm:6450/pinned:k3sm-migrated-0123456789ab"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := migrationTarget(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Errorf("migrationTarget(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
	h, _ := ggcrv1.NewHash(d)
	if got := renamedTag(strings.Repeat("x", 128), h); len(got) != 128 || !strings.HasSuffix(got, "-k3sm-migrated-0123456789ab") {
		t.Errorf("renamedTag of a 128-char tag = %q (%d)", got, len(got))
	}
}

// migrateListDaemon is the shared Images fake plus the one verb the migration
// still reads the node store through.
type migrateListDaemon struct {
	*fakeImagesDaemon
	listResp *runtimev1.ListImagesResponse
}

func (m *migrateListDaemon) ListImages(context.Context, *runtimev1.ListImagesRequest) (*runtimev1.ListImagesResponse, error) {
	return m.listResp, nil
}

// migrateDaemon is a fake runtimed whose store holds one image under ref, and
// the socket it serves on.
func migrateDaemon(t *testing.T, ref string) (fake *fakeImagesDaemon, sock, digest string) {
	t.Helper()
	layout := fixtureLayout(t, ref, "migrate-payload")
	digest = layoutDigest(t, layout)
	archive := tarLayout(t, layout)
	fake = &fakeImagesDaemon{
		saveChunks:   [][]byte{archive},
		saveTerminal: &runtimev1.SaveImageResponse{Digest: digest, SentBytes: int64(len(archive))},
	}
	srv := &migrateListDaemon{
		fakeImagesDaemon: fake,
		listResp: &runtimev1.ListImagesResponse{Images: []*runtimev1.Image{{
			ManifestDescriptor: &runtimev1.Descriptor{Digest: digest},
			Manifest:           &runtimev1.ImageManifest{Reference: ref, Platform: &runtimev1.Platform{Os: "darwin", Architecture: "arm64"}},
		}}},
	}
	sock = serveFakeImages(t, srv)
	return fake, sock, digest
}

// assertStoreOnlyRead fails when anything but list and export reached the
// node store.
func assertStoreOnlyRead(t *testing.T, fake *fakeImagesDaemon, digest string) {
	t.Helper()
	if fake.gotSave.GetDigest() != digest {
		t.Errorf("exported %q, want by digest %s", fake.gotSave.GetDigest(), digest)
	}
	if fake.loadCalls != 0 || fake.gotTag != nil || fake.gotUntag != nil || fake.pullCalls != 0 || fake.gotPrune != nil {
		t.Errorf("the migration wrote the node store: load=%d tag=%v untag=%v pull=%d prune=%v",
			fake.loadCalls, fake.gotTag, fake.gotUntag, fake.pullCalls, fake.gotPrune)
	}
}

// gateDigest is the digest the push gate g holds at the cluster-registry
// repository and tag repoTag, or "".
func gateDigest(t *testing.T, g gateRegistry, repoTag string) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(g.caPEM)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "registry-k3sm"}
	tr.DialContext = g.dial
	ref, err := name.NewTag("127.0.0.1:" + strconv.Itoa(g.port) + "/" + repoTag)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref, remote.WithTransport(tr))
	if err != nil {
		return ""
	}
	return desc.Digest.String()
}

// TestUserImageMigratePushesWithBuilderTokenAndJournals drives `k3sm image
// migrate` as a user runs it, against a fake runtimed over a real socket: on
// a worker it pushes to the server's cluster address and on a server to its
// loopback gate, in both cases with a builder token minted from the user's
// kubeconfig and no other credential, and it journals on the node it ran on.
// The node store is only listed and exported: no load, tag, untag, pull or
// prune reaches the daemon.
func TestUserImageMigratePushesWithBuilderTokenAndJournals(t *testing.T) {
	// The node store's reference names a registry on a closed loopback port,
	// so the "is this a pull cache entry" question is answered no, offline.
	const ref = "localhost:1/app:v1"
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("builder:"+fakeBuilderTokenToken))
	cases := []struct {
		name string
		// setup returns the node's work dir and the builder-token count.
		setup func(t *testing.T, g gateRegistry) (string, *int)
	}{
		{"on a worker, to the server's cluster address", func(t *testing.T, g gateRegistry) (string, *int) {
			minted := clusterAPIFor(t, g, flatSlice("127.0.0.1", int32(g.port)))
			dir := t.TempDir()
			t.Setenv("K3SM_WORK_DIR", dir)
			return dir, minted
		}},
		{"on the server, to its loopback gate", func(t *testing.T, g gateRegistry) (string, *int) {
			minted := clusterAPIFor(t, g)
			return asServer(t, g.port), minted
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			empty := t.TempDir()
			t.Setenv("HOME", empty)
			t.Setenv("DOCKER_CONFIG", empty)
			t.Setenv(registryTokenEnv, "")
			g := startGateRegistry(t)
			workDir, minted := tc.setup(t, g)
			fake, sock, digest := migrateDaemon(t, ref)

			o, err := parseImageMigrateArgs([]string{"--socket", sock, "--work-dir", workDir}, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := imageMigrateCommand(t.Context(), o, &out, dialRuntimed); err != nil {
				t.Fatalf("migrate: %v\n%s", err, out.String())
			}
			assertStoreOnlyRead(t, fake, digest)
			if *minted != 1 {
				t.Errorf("builder tokens minted = %d, want 1", *minted)
			}
			if !containsHeader(g.probe.headers(), want) {
				t.Errorf("the builder token was never presented; headers = %q", g.probe.headers())
			}
			for _, h := range g.probe.headers() {
				if h != "" && h != want {
					t.Errorf("a credential other than the builder token was presented: %q", h)
				}
			}
			if got := gateDigest(t, g, "app:v1"); got != digest {
				t.Errorf("registry holds %q, want %s", got, digest)
			}
			if !strings.Contains(out.String(), "migrated     "+ref+" -> registry-k3sm:6450/app:v1") {
				t.Errorf("report:\n%s", out.String())
			}
			j, err := readMigrationJournal(workDir)
			if err != nil {
				t.Fatal(err)
			}
			if !j.Complete || len(j.Images) != 1 || j.Images[0].Outcome != migrationMigrated {
				t.Errorf("journal on this node = %+v, want one migrated image, complete", j)
			}

			// --report prints the journal without dialling anything.
			o.report, o.socket = true, "/nonexistent.sock"
			out.Reset()
			if err := imageMigrateCommand(t.Context(), o, &out, dialRuntimed); err != nil {
				t.Fatalf("--report: %v", err)
			}
			if !strings.Contains(out.String(), "image migration complete: 1 migrated") {
				t.Errorf("--report:\n%s", out.String())
			}
		})
	}
}

// TestServerStartupMigrationUsesItsOwnCredential: the run the server's daemon
// starts after an upgrade writes to the registry's loopback listener with the
// per-boot push credential under its work dir, mints no builder token (the
// daemon is not a user), and journals there.
func TestServerStartupMigrationUsesItsOwnCredential(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")
	prev := clusterRegistryClient
	clusterRegistryClient = func() (clusterRegistryAPI, error) {
		t.Error("the server's start-up migration resolved a user kubeconfig")
		return clusterRegistryAPI{}, errors.New("unexpected")
	}
	t.Cleanup(func() { clusterRegistryClient = prev })

	perBoot := "Basic " + base64.StdEncoding.EncodeToString([]byte("k3sm:per-boot-secret"))
	host, probe := startRegistry(t, perBoot)
	workDir, _ := stageLocalCredential(t, host)
	const ref = "localhost:1/app:v1"
	fake, sock, digest := migrateDaemon(t, ref)

	cases := []struct {
		name string
		// wantExport is whether this run exports the image.
		wantExport bool
	}{
		{"the first start copies the image", true},
		{"a later start finds the journal complete and does nothing", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake.gotSave = nil
			finished, err := migrateOnce(t.Context(), workDir, dialRuntimed, sock, slog.New(slog.DiscardHandler))
			if err != nil || !finished {
				t.Fatalf("migrateOnce = %v, %v; want finished", finished, err)
			}
			if got := fake.gotSave != nil; got != tc.wantExport {
				t.Errorf("exported = %v, want %v", got, tc.wantExport)
			}
			if tc.wantExport {
				assertStoreOnlyRead(t, fake, digest)
			}
		})
	}
	for _, h := range probe.headers() {
		if h != "" && h != perBoot {
			t.Errorf("a credential other than the server's own was presented: %q", h)
		}
	}
	if !containsHeader(probe.headers(), perBoot) {
		t.Errorf("the server's push credential was never presented; headers = %q", probe.headers())
	}
	back, _ := name.NewTag(host + "/app:v1")
	desc, err := remote.Head(back, remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: "k3sm", Password: "per-boot-secret"})))
	if err != nil {
		t.Errorf("read back %s: %v", back, err)
	} else if desc.Digest.String() != digest {
		t.Errorf("registry holds %s, want %s", desc.Digest, digest)
	}
	if j, err := readMigrationJournal(workDir); err != nil || !j.Complete {
		t.Errorf("journal = %+v, %v; want complete", j, err)
	}
}

// TestImageMigrateNeedsTheRuntimeSocket: a run that cannot open the installed
// runtime's socket is refused before anything is dialled, naming sudo; root
// and the service user run, and so does a --socket naming another path.
func TestImageMigrateNeedsTheRuntimeSocket(t *testing.T) {
	cases := []struct {
		name       string
		euid       int
		socket     string
		wantRefuse bool
	}{
		{"an ordinary account on the installed socket", 501, runtimed.DefaultSocketPath, true},
		{"root on the installed socket", 0, runtimed.DefaultSocketPath, false},
		{"the service user on the installed socket", 270, runtimed.DefaultSocketPath, false},
		{"an ordinary account on its own socket", 501, "/tmp/k3sm-dev.sock", false},
	}
	prevEUID, prevSvc := migrateGeteuid, migrateServiceUID
	t.Cleanup(func() { migrateGeteuid, migrateServiceUID = prevEUID, prevSvc })
	migrateServiceUID = func() int { return 270 }
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			migrateGeteuid = func() int { return tc.euid }
			err := migrateRuntimeAccess(tc.socket)
			if tc.wantRefuse != (err != nil) {
				t.Fatalf("migrateRuntimeAccess = %v, want refused %v", err, tc.wantRefuse)
			}
			if err != nil && (!strings.Contains(err.Error(), "sudo k3sm image migrate") || !strings.Contains(err.Error(), tc.socket)) {
				t.Errorf("refusal %q does not name the socket and sudo", err)
			}
		})
	}
}

// TestImageMigrationLock pins that two migrations never share the journal.
func TestImageMigrationLock(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockImageMigration(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A second process's run is refused while the lock file stands. The
	// in-process mutex is released first so the refusal comes from the file.
	migrationLock.Unlock()
	if _, err := lockImageMigration(dir); err == nil {
		t.Errorf("a second migration took the lock")
	}
	migrationLock.Lock()
	unlock()
	unlock2, err := lockImageMigration(dir)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	unlock2()
}
