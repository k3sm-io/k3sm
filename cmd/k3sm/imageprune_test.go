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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// pruneStore is a hand-built zot storage root: OCI image layouts under the
// registry state dir, the shape zot writes and prune reads.
type pruneStore struct {
	t       *testing.T
	workDir string
}

const (
	ociManifestType = "application/vnd.oci.image.manifest.v1+json"
	ociIndexType    = "application/vnd.oci.image.index.v1+json"
)

// blob writes body as a blob of repo with the given age and returns its digest.
func (s pruneStore) blob(repo string, body []byte, age time.Duration) string {
	s.t.Helper()
	sum := sha256.Sum256(body)
	hexd := hex.EncodeToString(sum[:])
	dir := filepath.Join(registrysvc.StateDir(s.workDir), filepath.FromSlash(repo), "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.t.Fatal(err)
	}
	p := filepath.Join(dir, hexd)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		s.t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		s.t.Fatal(err)
	}
	return "sha256:" + hexd
}

// manifest writes an image manifest, optionally a referrer of subject.
func (s pruneStore) manifest(repo, seed, subject string, age time.Duration) string {
	m := map[string]any{"schemaVersion": 2, "mediaType": ociManifestType, "annotations": map[string]string{"seed": seed}}
	if subject != "" {
		m["subject"] = map[string]any{"mediaType": ociManifestType, "digest": subject, "size": 1}
	}
	b, _ := json.Marshal(m)
	return s.blob(repo, b, age)
}

// index writes an image index naming children.
func (s pruneStore) index(repo, seed string, age time.Duration, children ...string) string {
	var ms []map[string]any
	for _, c := range children {
		ms = append(ms, map[string]any{"mediaType": ociManifestType, "digest": c, "size": 1})
	}
	b, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociIndexType, "manifests": ms, "annotations": map[string]string{"seed": seed}})
	return s.blob(repo, b, age)
}

type indexEntry struct {
	digest, mediaType, tag string
}

// layout writes repo's oci-layout and index.json.
func (s pruneStore) layout(repo string, entries ...indexEntry) {
	s.t.Helper()
	dir := filepath.Join(registrysvc.StateDir(s.workDir), filepath.FromSlash(repo))
	var ms []map[string]any
	for _, e := range entries {
		d := map[string]any{"mediaType": e.mediaType, "digest": e.digest, "size": 100}
		if e.tag != "" {
			d["annotations"] = map[string]string{"org.opencontainers.image.ref.name": e.tag}
		}
		ms = append(ms, d)
	}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": ms})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o644); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

// pruneFixture is the store every prune test reads: two repositories holding
// each case the plan must tell apart.
type pruneFixture struct {
	tagged, overwritten, recent, referrer       string // repo app
	tagIndex, child1, child2, oldIndex, oldLeaf string // repo multi
}

func buildPruneFixture(t *testing.T, workDir string) pruneFixture {
	s := pruneStore{t: t, workDir: workDir}
	old := 2 * time.Hour
	var f pruneFixture
	f.tagged = s.manifest("app", "v2", "", old)
	f.overwritten = s.manifest("app", "v1", "", old)
	f.recent = s.manifest("app", "pushing", "", time.Minute)
	f.referrer = s.manifest("app", "sig", f.tagged, old)
	s.layout("app",
		indexEntry{f.tagged, ociManifestType, "v2"},
		indexEntry{f.overwritten, ociManifestType, ""},
		indexEntry{f.recent, ociManifestType, ""},
		indexEntry{f.referrer, ociManifestType, ""},
	)
	f.child1 = s.manifest("multi", "arm64", "", old)
	f.child2 = s.manifest("multi", "amd64", "", old)
	f.tagIndex = s.index("multi", "v1", old, f.child1, f.child2)
	f.oldLeaf = s.manifest("multi", "old-arm64", "", old)
	f.oldIndex = s.index("multi", "v0", old, f.oldLeaf)
	s.layout("multi",
		indexEntry{f.child1, ociManifestType, ""},
		indexEntry{f.child2, ociManifestType, ""},
		indexEntry{f.tagIndex, ociIndexType, "v1"},
		indexEntry{f.oldLeaf, ociManifestType, ""},
		indexEntry{f.oldIndex, ociIndexType, ""},
	)
	return f
}

// fakeZot is the registry's manifestDeleter seam: it records every deletion
// the prune makes, as the dist-spec request it stands for, and the identity
// it authenticated as, and accepts each.
type fakeZot struct {
	mu        sync.Mutex
	requests  []string
	users     []string
	authority []string
}

func (z *fakeZot) delete(_ context.Context, ref name.Digest, auth authn.Authenticator) error {
	cfg, err := auth.Authorization()
	if err != nil {
		return err
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.requests = append(z.requests, http.MethodDelete+" /v2/"+ref.Context().RepositoryStr()+"/manifests/"+ref.DigestStr())
	z.users = append(z.users, cfg.Username)
	z.authority = append(z.authority, ref.Context().RegistryStr())
	return nil
}

// fakeZotPort is the port the fake registry's credential names.
const fakeZotPort = 6450

// serveFakeZot writes this node's push credential naming the registry, the
// way the server's registry does at boot, and returns the deleter that stands
// in for it.
func serveFakeZot(t *testing.T, workDir string) *fakeZot {
	t.Helper()
	if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", fakeZotPort)
	if err := registrysvc.WriteCredential(workDir, registrysvc.Credential{Address: addr, Username: "k3sm", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	return &fakeZot{}
}

// runPruneCmd runs `k3sm image` with the fake registry as the deleter.
func runPruneCmd(t *testing.T, z *fakeZot, args []string) (string, error) {
	t.Helper()
	opts, err := parseImageArgs(args, io.Discard)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	err = imageCommandWith(ctx, opts, &out, dialRuntimed, z.delete)
	return out.String(), err
}

// pruneJSON is the -o json document, decoded independently of the command's
// own types so the test pins the wire shape the app reads.
type pruneJSON struct {
	DryRun   bool `json:"dryRun"`
	Registry struct {
		Name      string `json:"name"`
		Skipped   string `json:"skipped"`
		Manifests []struct {
			Repository string `json:"repository"`
			Digest     string `json:"digest"`
			MediaType  string `json:"mediaType"`
			Size       int64  `json:"size"`
		} `json:"manifests"`
		Kept []struct {
			Repository string `json:"repository"`
			Digest     string `json:"digest"`
			MediaType  string `json:"mediaType"`
			Size       int64  `json:"size"`
			Reason     string `json:"reason"`
		} `json:"kept"`
		Unreadable []string `json:"unreadable"`
		Failed     []struct {
			Repository string `json:"repository"`
			Digest     string `json:"digest"`
			MediaType  string `json:"mediaType"`
			Size       int64  `json:"size"`
			Error      string `json:"error"`
		} `json:"failed"`
	} `json:"registry"`
	Cache struct {
		Blobs          []string       `json:"blobs"`
		ReclaimedBytes uint64         `json:"reclaimedBytes"`
		Kept           map[string]int `json:"kept"`
	} `json:"cache"`
}

func decodePrune(t *testing.T, out string) pruneJSON {
	t.Helper()
	var doc pruneJSON
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("prune -o json is not the documented shape: %v\n%s", err, out)
	}
	return doc
}

func manifestList(doc pruneJSON) []string {
	var got []string
	for _, m := range doc.Registry.Manifests {
		got = append(got, m.Repository+"@"+m.Digest)
	}
	return got
}

// TestImagePruneDryRunReportsRegistryAndCache is the gate for the prune plan: `k3sm image
// prune` plans the deletion of the registry's untagged manifests AND the
// eviction of this node's cache, deletes nothing without --force, and reports
// both halves in one -o json document.
func TestImagePruneDryRunReportsRegistryAndCache(t *testing.T) {
	workDir := t.TempDir()
	zot := serveFakeZot(t, workDir)
	f := buildPruneFixture(t, workDir)
	fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{
		RemovedDigests: []string{"sha256:aaaa"},
		ReclaimedBytes: 2048,
		Skipped:        []*runtimev1.SkippedBlob{{Digest: "sha256:bbbb", Reason: runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE}},
	}}
	sock := serveFakeImages(t, fake)

	out, err := runPruneCmd(t, zot, []string{"--socket", sock, "--work-dir", workDir, "prune", "-o", "json"})
	if err != nil {
		t.Fatalf("image prune -o json: %v", err)
	}
	doc := decodePrune(t, out)

	if !doc.DryRun {
		t.Errorf("dryRun = false with no --force")
	}
	if fake.gotPrune == nil || !fake.gotPrune.GetDryRun() {
		t.Errorf("the node cache was not asked for a dry run: %+v", fake.gotPrune)
	}
	if len(zot.requests) != 0 {
		t.Errorf("a dry run reached the registry: %v", zot.requests)
	}
	if doc.Registry.Name != "registry-k3sm:6450" || doc.Registry.Skipped != "" {
		t.Errorf("registry = %q skipped %q; want registry-k3sm:6450 planned", doc.Registry.Name, doc.Registry.Skipped)
	}
	// The overwritten tag's manifest goes, and so does the untagged index with
	// its child, the index first because zot refuses to delete a child an index
	// still names.
	want := []string{"app@" + f.overwritten, "multi@" + f.oldIndex, "multi@" + f.oldLeaf}
	if got := manifestList(doc); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("manifests = %v\nwant        %v", got, want)
	}
	wantKept := map[string]string{
		"app@" + f.recent:   "younger than the grace period",
		"app@" + f.referrer: "referrer of a kept manifest",
		"multi@" + f.child1: "named by a kept index",
		"multi@" + f.child2: "named by a kept index",
	}
	gotKept := map[string]string{}
	for _, k := range doc.Registry.Kept {
		gotKept[k.Repository+"@"+k.Digest] = k.Reason
	}
	if fmt.Sprint(gotKept) != fmt.Sprint(wantKept) {
		t.Errorf("kept = %v\nwant   %v", gotKept, wantKept)
	}
	for _, m := range doc.Registry.Manifests {
		if m.Digest == f.tagged || m.Digest == f.tagIndex {
			t.Errorf("a tagged manifest is planned for deletion: %s", m.Digest)
		}
	}
	if strings.Join(doc.Cache.Blobs, ",") != "sha256:aaaa" || doc.Cache.ReclaimedBytes != 2048 {
		t.Errorf("cache = %+v; want the daemon's sha256:aaaa, 2048 bytes", doc.Cache)
	}
	if doc.Cache.Kept["in use by a pod"] != 1 {
		t.Errorf("cache kept = %v; want one in use by a pod", doc.Cache.Kept)
	}

	t.Run("the table names both halves and the dry run", func(t *testing.T) {
		out, err := runPruneCmd(t, zot, []string{"--socket", sock, "--work-dir", workDir, "prune"})
		if err != nil {
			t.Fatalf("image prune: %v", err)
		}
		for _, w := range []string{"registry registry-k3sm:6450", "would delete app@" + f.overwritten, "node cache", "would delete sha256:aaaa", "dry run"} {
			if !strings.Contains(out, w) {
				t.Errorf("output missing %q:\n%s", w, out)
			}
		}
	})
}

// TestImagePruneForceDeletesUntaggedThroughTheRegistry proves --force deletes
// through zot's API on loopback, as this node's push user, index before child,
// and never a tagged manifest.
func TestImagePruneForceDeletesUntaggedThroughTheRegistry(t *testing.T) {
	workDir := t.TempDir()
	zot := serveFakeZot(t, workDir)
	f := buildPruneFixture(t, workDir)
	fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{RemovedDigests: []string{"sha256:cccc"}}}
	sock := serveFakeImages(t, fake)

	out, err := runPruneCmd(t, zot, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"})
	if err != nil {
		t.Fatalf("image prune --force: %v", err)
	}
	doc := decodePrune(t, out)
	if doc.DryRun || fake.gotPrune.GetDryRun() {
		t.Errorf("--force ran as a dry run (report %v, daemon %v)", doc.DryRun, fake.gotPrune.GetDryRun())
	}
	want := []string{
		"DELETE /v2/app/manifests/" + f.overwritten,
		"DELETE /v2/multi/manifests/" + f.oldIndex,
		"DELETE /v2/multi/manifests/" + f.oldLeaf,
	}
	zot.mu.Lock()
	defer zot.mu.Unlock()
	if strings.Join(zot.requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("registry requests:\n%s\nwant:\n%s", strings.Join(zot.requests, "\n"), strings.Join(want, "\n"))
	}
	for i, u := range zot.users {
		if u != "k3sm" {
			t.Errorf("request %d authenticated as %q; want this node's push user", i, u)
		}
	}
	wantAuthority := registrysvc.LoopbackAuthority(fakeZotPort)
	for i, a := range zot.authority {
		if a != wantAuthority {
			t.Errorf("request %d went to %q; want the registry on loopback, %q", i, a, wantAuthority)
		}
	}
	if len(doc.Registry.Manifests) != 3 || len(doc.Registry.Failed) != 0 {
		t.Errorf("report manifests %d failed %d; want 3 and 0", len(doc.Registry.Manifests), len(doc.Registry.Failed))
	}
}

// TestImagePruneReportsARefusedDeletion proves a deletion the registry
// refuses is listed under failed and fails the command, while the rest stands.
func TestImagePruneReportsARefusedDeletion(t *testing.T) {
	workDir := t.TempDir()
	serveFakeZot(t, workDir)
	f := buildPruneFixture(t, workDir)
	sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
	opts, err := parseImageArgs([]string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	refuse := func(_ context.Context, ref name.Digest, _ authn.Authenticator) error {
		if ref.DigestStr() == f.oldLeaf {
			return errors.New("MANIFEST_UNKNOWN")
		}
		return nil
	}
	var out bytes.Buffer
	err = imageCommandWith(context.Background(), opts, &out, dialRuntimed, refuse)
	if !errors.Is(err, errPruneIncomplete) {
		t.Fatalf("err = %v; want errPruneIncomplete", err)
	}
	doc := decodePrune(t, out.String())
	if len(doc.Registry.Failed) != 1 || doc.Registry.Failed[0].Digest != f.oldLeaf || doc.Registry.Failed[0].Error != "MANIFEST_UNKNOWN" {
		t.Errorf("failed = %+v; want the one refused leaf", doc.Registry.Failed)
	}
	if len(doc.Registry.Manifests) != 2 {
		t.Errorf("deleted %d; want the two the registry accepted", len(doc.Registry.Manifests))
	}
}

// TestImagePruneOnANodeWithoutARegistry proves an agent prunes its cache and
// says the registry half belongs to the server, rather than failing or
// pretending the registry had nothing to prune.
func TestImagePruneOnANodeWithoutARegistry(t *testing.T) {
	fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{RemovedDigests: []string{"sha256:dddd"}}}
	sock := serveFakeImages(t, fake)
	out, err := runImageCmd(t, []string{"--socket", sock, "--work-dir", t.TempDir(), "prune", "-o", "json"})
	if err != nil {
		t.Fatalf("image prune: %v", err)
	}
	doc := decodePrune(t, out)
	if !strings.Contains(doc.Registry.Skipped, "runs no registry") {
		t.Errorf("skipped = %q; want it to say this node runs no registry", doc.Registry.Skipped)
	}
	if doc.Registry.Manifests == nil || doc.Registry.Kept == nil || doc.Cache.Blobs == nil {
		t.Errorf("empty lists must render as [], not null:\n%s", out)
	}
	if strings.Join(doc.Cache.Blobs, ",") != "sha256:dddd" {
		t.Errorf("cache blobs = %v", doc.Cache.Blobs)
	}
}

// TestImagePruneOutputFlag pins -o for prune: json or the table, nothing else.
func TestImagePruneOutputFlag(t *testing.T) {
	if _, err := parseImageArgs([]string{"prune", "-o", "yaml"}, io.Discard); err == nil || !strings.Contains(err.Error(), "prune renders a table") {
		t.Errorf("prune -o yaml: err = %v; want a refusal naming json", err)
	}
	o, err := parseImageArgs([]string{"prune", "-o", "json"}, io.Discard)
	if err != nil || o.output != "json" {
		t.Errorf("prune -o json: %+v, %v", o, err)
	}
}
