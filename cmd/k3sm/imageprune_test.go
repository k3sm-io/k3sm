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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// pruneStore is a hand-built store root: OCI image layouts under the
// registry state dir, the shape the registry writes and prune reads.
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
		// The row carries the blob's real size, as the registry writes it: the
		// store checks every manifest body against its row.
		fi, err := os.Stat(filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(e.digest, "sha256:")))
		if err != nil {
			s.t.Fatal(err)
		}
		d := map[string]any{"mediaType": e.mediaType, "digest": e.digest, "size": fi.Size()}
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

// fakePruneRegistry is the registry's manifestDeleter seam: it records every deletion
// the prune makes, as the dist-spec request it stands for, and the identity
// it authenticated as, and accepts each.
type fakePruneRegistry struct {
	mu        sync.Mutex
	requests  []string
	users     []string
	authority []string
	// collects records each sweep asked for: authority, user, repositories.
	collects []string
	sweep    registrysvc.CollectResult
	sweepErr error
}

func (z *fakePruneRegistry) delete(_ context.Context, ref name.Digest, _ string, auth authn.Authenticator) error {
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

// collect is the registry's prunedCollector seam: it records each sweep the
// prune asks for and answers with z.sweep, or z.sweepErr.
func (z *fakePruneRegistry) collect(_ context.Context, authority string, deleted []registrysvc.StoredManifest, cred registrysvc.Credential) (registrysvc.CollectResult, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	res := z.sweep
	res.Repositories = nil
	for _, m := range deleted {
		if !slices.Contains(res.Repositories, m.Repository) {
			res.Repositories = append(res.Repositories, m.Repository)
		}
	}
	z.collects = append(z.collects, fmt.Sprintf("%s %s %v", authority, cred.Username, res.Repositories))
	return res, z.sweepErr
}

// acceptCollect is a prunedCollector that sweeps nothing and fails nothing.
func acceptCollect(_ context.Context, _ string, deleted []registrysvc.StoredManifest, _ registrysvc.Credential) (registrysvc.CollectResult, error) {
	return registrysvc.CollectResult{Repositories: []string{deleted[0].Repository}}, nil
}

// fakePruneRegistryPort is the port the fake registry's credential names.
const fakePruneRegistryPort = 6450

// serveFakePruneRegistry writes this node's push credential naming the registry, the
// way the server's registry does at boot, and returns the deleter that stands
// in for it.
func serveFakePruneRegistry(t *testing.T, workDir string) *fakePruneRegistry {
	t.Helper()
	if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", fakePruneRegistryPort)
	if err := registrysvc.WriteCredential(workDir, registrysvc.Credential{Address: addr, Username: "k3sm", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	return &fakePruneRegistry{}
}

// runPruneCmd runs `k3sm image` with the fake registry as the deleter.
func runPruneCmd(t *testing.T, z *fakePruneRegistry, args []string) (string, error) {
	t.Helper()
	opts, err := parseImageArgs(args, io.Discard)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	err = imageCommandWith(ctx, opts, &out, dialRuntimed, z.delete, z.collect)
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
		Sweep *struct {
			Repositories []string `json:"repositories"`
			Manifests    int      `json:"manifests"`
			Blobs        int      `json:"blobs"`
			Bytes        int64    `json:"bytes"`
			Stopped      []string `json:"stopped"`
			Failed       []string `json:"failed"`
			Reviewing    []string `json:"reviewing"`
			Error        string   `json:"error"`
		} `json:"sweep"`
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
	reg := serveFakePruneRegistry(t, workDir)
	f := buildPruneFixture(t, workDir)
	fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{
		RemovedDigests: []string{"sha256:aaaa"},
		ReclaimedBytes: 2048,
		Skipped:        []*runtimev1.SkippedBlob{{Digest: "sha256:bbbb", Reason: runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE}},
	}}
	sock := serveFakeImages(t, fake)

	out, err := runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "-o", "json"})
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
	if len(reg.requests) != 0 {
		t.Errorf("a dry run reached the registry: %v", reg.requests)
	}
	if doc.Registry.Name != "registry-k3sm:6450" || doc.Registry.Skipped != "" {
		t.Errorf("registry = %q skipped %q; want registry-k3sm:6450 planned", doc.Registry.Name, doc.Registry.Skipped)
	}
	// The overwritten tag's manifest goes, and so does the untagged index with
	// its child, the index first because the registry refuses to delete a child an index
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
		out, err := runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune"})
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

// TestImagePruneForceSweepsThePrunedRepositories proves a forced prune that
// deleted manifests asks the registry, on loopback and as this node's push
// user, to sweep exactly the repositories it deleted from, reports what that
// freed in the table and in -o json, and reports a sweep the brake stopped or
// that could not run without failing the command. A dry run asks for no sweep.
func TestImagePruneForceSweepsThePrunedRepositories(t *testing.T) {
	newPrune := func(t *testing.T) (string, string, *fakePruneRegistry) {
		t.Helper()
		workDir := t.TempDir()
		reg := serveFakePruneRegistry(t, workDir)
		buildPruneFixture(t, workDir)
		sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
		return workDir, sock, reg
	}
	wantCollect := registrysvc.LoopbackAuthority(fakePruneRegistryPort) + " k3sm [app multi]"

	t.Run("a dry run asks for no sweep", func(t *testing.T) {
		workDir, sock, reg := newPrune(t)
		out, err := runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "-o", "json"})
		if err != nil {
			t.Fatal(err)
		}
		if doc := decodePrune(t, out); doc.Registry.Sweep != nil || len(reg.collects) != 0 {
			t.Errorf("dry run: sweep %+v, collects %v; want none", doc.Registry.Sweep, reg.collects)
		}
	})

	t.Run("the sweep's frees are reported in json and the table", func(t *testing.T) {
		workDir, sock, reg := newPrune(t)
		reg.sweep = registrysvc.CollectResult{Blobs: 4, Bytes: 3 << 20}
		out, err := runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(reg.collects, ";") != wantCollect {
			t.Errorf("collects %v; want one, %q", reg.collects, wantCollect)
		}
		doc := decodePrune(t, out)
		if sw := doc.Registry.Sweep; sw == nil || sw.Blobs != 4 || sw.Bytes != 3<<20 || strings.Join(sw.Repositories, ",") != "app,multi" {
			t.Errorf("json sweep %+v; want app and multi, 4 blobs, %d bytes", sw, 3<<20)
		}
		out, err = runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force"})
		if err != nil {
			t.Fatal(err)
		}
		// The summary line is the app's contract and stays as it was; the
		// sweep is reported on the line after it.
		want := "  deleted 3 untagged manifest(s); the registry's garbage collection reclaims their layers on its next sweep\n" +
			"  swept app, multi: freed 4 blob(s), " + humanBytes(3<<20) + "\n"
		if !strings.Contains(out, want) {
			t.Errorf("table does not carry the summary and then the sweep:\n%s", out)
		}
	})

	t.Run("a braked or failed sweep is reported and the prune still succeeds", func(t *testing.T) {
		workDir, sock, reg := newPrune(t)
		reg.sweep = registrysvc.CollectResult{Stopped: []string{"multi"}, Error: "gc multi: mass delete"}
		out, err := runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force"})
		if err != nil {
			t.Fatalf("a braked sweep failed the prune: %v", err)
		}
		for _, w := range []string{"sweep stopped by the mass-delete brake, nothing freed: multi", "sweep: gc multi: mass delete"} {
			if !strings.Contains(out, w) {
				t.Errorf("table missing %q:\n%s", w, out)
			}
		}
		if len(reg.collects) != 1 {
			t.Errorf("collects %v; a braked sweep is not retried", reg.collects)
		}

		workDir, sock, reg = newPrune(t)
		reg.sweep = registrysvc.CollectResult{Failed: []string{"multi\x1b[2J"}, Error: "bad\x1b]0;owned\x07 news\u202e"}
		out, err = runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(out, "\x1b\x07\u202e") {
			t.Errorf("table carries control characters from the sweep's answer: %q", out)
		}
		for _, w := range []string{"sweep failed, nothing freed: multi[2J\n", "sweep: bad]0;owned news;"} {
			if !strings.Contains(out, w) {
				t.Errorf("table missing %q:\n%s", w, out)
			}
		}

		workDir, sock, reg = newPrune(t)
		reg.sweepErr = errors.New("connection refused")
		out, err = runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"})
		if err != nil {
			t.Fatalf("an unreachable sweep failed the prune: %v", err)
		}
		if sw := decodePrune(t, out).Registry.Sweep; sw == nil || sw.Error != "connection refused" {
			t.Errorf("json sweep %+v; want the request's error", sw)
		}
	})
}

// TestImagePruneForceDeletesUntaggedThroughTheRegistry proves --force deletes
// through the registry's API on loopback, as this node's push user, index before child,
// and never a tagged manifest.
func TestImagePruneForceDeletesUntaggedThroughTheRegistry(t *testing.T) {
	workDir := t.TempDir()
	reg := serveFakePruneRegistry(t, workDir)
	f := buildPruneFixture(t, workDir)
	fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{RemovedDigests: []string{"sha256:cccc"}}}
	sock := serveFakeImages(t, fake)

	out, err := runPruneCmd(t, reg, []string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"})
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
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if strings.Join(reg.requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("registry requests:\n%s\nwant:\n%s", strings.Join(reg.requests, "\n"), strings.Join(want, "\n"))
	}
	for i, u := range reg.users {
		if u != "k3sm" {
			t.Errorf("request %d authenticated as %q; want this node's push user", i, u)
		}
	}
	wantAuthority := registrysvc.LoopbackAuthority(fakePruneRegistryPort)
	for i, a := range reg.authority {
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
	serveFakePruneRegistry(t, workDir)
	f := buildPruneFixture(t, workDir)
	sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
	opts, err := parseImageArgs([]string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	refuse := func(_ context.Context, ref name.Digest, _ string, _ authn.Authenticator) error {
		if ref.DigestStr() == f.oldLeaf {
			return errors.New("MANIFEST_UNKNOWN")
		}
		return nil
	}
	var out bytes.Buffer
	err = imageCommandWith(context.Background(), opts, &out, dialRuntimed, refuse, acceptCollect)
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

// TestImagePruneRechecksEachPlannedDigestBeforeItsDelete proves a manifest a
// push tags after the plan was read is not deleted: a delete by digest drops
// every row with that digest, so deleting it would lose the new tag. The
// deleter is the hook between plan and DELETE: its first call tags the second
// planned manifest, as a push landing mid-prune would, and then deletes
// through the store the way the registry does.
func TestImagePruneRechecksEachPlannedDigestBeforeItsDelete(t *testing.T) {
	workDir := t.TempDir()
	serveFakePruneRegistry(t, workDir)
	st, err := store.OpenWorkDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	repo, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Init(ctx, repo); err != nil {
		t.Fatal(err)
	}
	first := []byte(`{"schemaVersion":2,"mediaType":"` + ociManifestType + `","annotations":{"seed":"first"}}`)
	second := []byte(`{"schemaVersion":2,"mediaType":"` + ociManifestType + `","annotations":{"seed":"second"}}`)
	for _, b := range [][]byte{first, second} {
		if _, err := st.PutManifest(ctx, repo, ref.Reference{Digest: digest.FromBytes(b)}, ociManifestType, b); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, b := range [][]byte{first, second} {
		p := filepath.Join(registrysvc.StateDir(workDir), "app", "blobs", "sha256", digest.FromBytes(b).Encoded())
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	firstDigest, secondDigest := digest.FromBytes(first), digest.FromBytes(second)

	var deleted []string
	del := func(ctx context.Context, rf name.Digest, _ string, _ authn.Authenticator) error {
		if len(deleted) == 0 {
			if _, err := st.PutManifest(ctx, repo, ref.Reference{Tag: "v1"}, ociManifestType, second); err != nil {
				return err
			}
		}
		deleted = append(deleted, rf.DigestStr())
		return st.DeleteDigest(ctx, repo, digest.Digest(rf.DigestStr()))
	}
	sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
	opts, err := parseImageArgs([]string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := imageCommandWith(ctx, opts, &out, dialRuntimed, del, acceptCollect); err != nil {
		t.Fatalf("image prune --force: %v\n%s", err, out.String())
	}

	if strings.Join(deleted, ",") != firstDigest.String() {
		t.Errorf("deleted %v; want only %s, the manifest still untagged at its delete", deleted, firstDigest)
	}
	d, err := st.Resolve(repo, ref.Reference{Tag: "v1"})
	if err != nil {
		t.Fatalf("the tag pushed between plan and delete is lost: %v", err)
	}
	if d.Digest != secondDigest {
		t.Errorf("v1 names %s; want %s", d.Digest, secondDigest)
	}
	if got := manifestList(decodePrune(t, out.String())); strings.Join(got, ",") != "app@"+firstDigest.String() {
		t.Errorf("report manifests = %v; want only app@%s", got, firstDigest)
	}
}

// TestImagePruneRecheckAppliesTheKeepClosure proves the re-check before each
// DELETE re-derives what is kept from the repository's current state, not
// from the digest alone. The repository holds an untagged index L with its
// child LC, an untagged index I with its child C, and a stale manifest S, all
// old, so the plan deletes all five, L first. The first DELETE (of L) first tags I, as a push landing mid-prune
// would, and deletes a stale manifest S behind the prune's back. I must then
// be skipped as tagged, C as named by a kept index, and S reported as already
// gone without a DELETE or a count.
func TestImagePruneRecheckAppliesTheKeepClosure(t *testing.T) {
	workDir := t.TempDir()
	serveFakePruneRegistry(t, workDir)
	st, err := store.OpenWorkDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	repo, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Init(ctx, repo); err != nil {
		t.Fatal(err)
	}
	manifest := func(seed string) []byte {
		return []byte(`{"schemaVersion":2,"mediaType":"` + ociManifestType + `","annotations":{"seed":"` + seed + `"}}`)
	}
	index := func(seed string, children ...[]byte) []byte {
		var ms []map[string]any
		for _, c := range children {
			ms = append(ms, map[string]any{"mediaType": ociManifestType, "digest": digest.FromBytes(c).String(), "size": len(c)})
		}
		b, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociIndexType, "manifests": ms, "annotations": map[string]string{"seed": seed}})
		return b
	}
	loneChild := manifest("lone-child")
	lone := index("lone", loneChild)
	child := manifest("child")
	ix := index("ix", child)
	stale := manifest("stale")
	puts := []struct {
		body      []byte
		mediaType string
	}{{loneChild, ociManifestType}, {lone, ociIndexType}, {child, ociManifestType}, {ix, ociIndexType}, {stale, ociManifestType}}
	for _, p := range puts {
		if _, err := st.PutManifest(ctx, repo, ref.Reference{Digest: digest.FromBytes(p.body)}, p.mediaType, p.body); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range puts {
		path := filepath.Join(registrysvc.StateDir(workDir), "app", "blobs", "sha256", digest.FromBytes(p.body).Encoded())
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	loneChildD := digest.FromBytes(loneChild)
	loneD, childD, ixD, staleD := digest.FromBytes(lone), digest.FromBytes(child), digest.FromBytes(ix), digest.FromBytes(stale)

	var deleted []string
	del := func(ctx context.Context, rf name.Digest, _ string, _ authn.Authenticator) error {
		if len(deleted) == 0 {
			if _, err := st.PutManifest(ctx, repo, ref.Reference{Tag: "v1"}, ociIndexType, ix); err != nil {
				return err
			}
			if err := st.DeleteDigest(ctx, repo, staleD); err != nil {
				return err
			}
		}
		deleted = append(deleted, rf.DigestStr())
		return st.DeleteDigest(ctx, repo, digest.Digest(rf.DigestStr()))
	}
	sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
	opts, err := parseImageArgs([]string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := imageCommandWith(ctx, opts, &buf, dialRuntimed, del, acceptCollect); err != nil {
		t.Fatalf("image prune --force: %v\n%s", err, buf.String())
	}
	out := buf.String()

	if got, want := strings.Join(deleted, ","), loneD.String()+","+loneChildD.String(); got != want {
		t.Errorf("deleted %v; want only %s", deleted, want)
	}
	d, err := st.Resolve(repo, ref.Reference{Tag: "v1"})
	if err != nil || d.Digest != ixD {
		t.Fatalf("v1 = %v, %v; want the index tagged mid-prune, %s", d, err, ixD)
	}
	if _, _, err := st.Manifest(repo, ref.Reference{Digest: childD}); err != nil {
		t.Errorf("the child of the index tagged mid-prune was deleted: %v", err)
	}
	doc := decodePrune(t, out)
	if got, want := strings.Join(manifestList(doc), ","), "app@"+loneD.String()+",app@"+loneChildD.String(); got != want {
		t.Errorf("report manifests = %v; want only %s (a gone manifest is not a delete)", got, want)
	}
	kept := map[string]string{}
	for _, k := range doc.Registry.Kept {
		kept[k.Digest] = k.Reason
	}
	want := map[string]registrysvc.KeepReason{
		ixD.String():    registrysvc.KeepTaggedSincePlan,
		childD.String(): registrysvc.KeepChildOfKept,
		staleD.String(): registrysvc.GoneSincePlan,
	}
	for dg, reason := range want {
		if kept[dg] != string(reason) {
			t.Errorf("report kept %s = %q; want %q", dg, kept[dg], reason)
		}
	}
	if len(doc.Registry.Failed) != 0 {
		t.Errorf("report failed = %+v; want none", doc.Registry.Failed)
	}
}

// TestImagePruneReportsRecheckSkips pins how the delete loop reports the
// planned manifests it does not delete: a repository the re-check cannot read
// is listed as unreadable once, however many of its manifests were skipped; a
// repository gone since the plan is reported under kept only, never as
// unreadable; and a delete the registry refused because the repository
// changed after the re-check is kept, not failed. The deleter's first call
// deletes through the store and then breaks the repository as the case needs,
// so the re-checks of the other two planned manifests meet the broken state.
// Each case runs once for the JSON report and once, on a fresh fixture, for
// the table.
func TestImagePruneReportsRecheckSkips(t *testing.T) {
	for _, tc := range []struct {
		name           string
		breakRepo      func(t *testing.T, workDir string)
		refuse         bool
		wantReason     registrysvc.KeepReason
		wantKept       int
		wantUnreadable []string
	}{
		{"an index the re-check cannot read", func(t *testing.T, workDir string) {
			if err := os.WriteFile(filepath.Join(registrysvc.StateDir(workDir), "app", "index.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false, registrysvc.KeepUnreadable, 2, []string{"app"}},
		{"a repository gone since the plan", func(t *testing.T, workDir string) {
			if err := os.RemoveAll(filepath.Join(registrysvc.StateDir(workDir), "app")); err != nil {
				t.Fatal(err)
			}
		}, false, registrysvc.GoneSincePlan, 2, nil},
		{"a repository changed at the delete", nil, true, registrysvc.KeepChangedSincePlan, 3, nil},
	} {
		for _, output := range []string{"json", "table"} {
			t.Run(tc.name+"/"+output, func(t *testing.T) {
				workDir := t.TempDir()
				serveFakePruneRegistry(t, workDir)
				st, err := store.OpenWorkDir(workDir)
				if err != nil {
					t.Fatal(err)
				}
				ctx := t.Context()
				repo, err := ref.ParseName("app")
				if err != nil {
					t.Fatal(err)
				}
				if err := st.Init(ctx, repo); err != nil {
					t.Fatal(err)
				}
				old := time.Now().Add(-2 * time.Hour)
				for _, seed := range []string{"one", "two", "three"} {
					b := []byte(`{"schemaVersion":2,"mediaType":"` + ociManifestType + `","annotations":{"seed":"` + seed + `"}}`)
					if _, err := st.PutManifest(ctx, repo, ref.Reference{Digest: digest.FromBytes(b)}, ociManifestType, b); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(filepath.Join(registrysvc.StateDir(workDir), "app", "blobs", "sha256", digest.FromBytes(b).Encoded()), old, old); err != nil {
						t.Fatal(err)
					}
				}

				var calls int
				del := func(ctx context.Context, rf name.Digest, state string, _ authn.Authenticator) error {
					calls++
					if state == "" {
						t.Errorf("the DELETE of %s named no repository state", rf.DigestStr())
					}
					if tc.refuse {
						return fmt.Errorf("delete %s: %w", rf, registrysvc.ErrChangedSincePlan)
					}
					if err := st.DeleteDigest(ctx, repo, digest.Digest(rf.DigestStr())); err != nil {
						return err
					}
					if calls == 1 {
						tc.breakRepo(t, workDir)
					}
					return nil
				}
				sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
				args := []string{"--socket", sock, "--work-dir", workDir, "prune", "--force"}
				if output == "json" {
					args = append(args, "-o", "json")
				}
				opts, err := parseImageArgs(args, io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				var out bytes.Buffer
				if err := imageCommandWith(ctx, opts, &out, dialRuntimed, del, acceptCollect); err != nil {
					t.Fatalf("image prune --force: %v\n%s", err, out.String())
				}

				if output == "table" {
					if got := strings.Count(out.String(), "  unreadable, left alone: app\n"); got != len(tc.wantUnreadable) {
						t.Errorf("table carries %d unreadable lines for app; want %d:\n%s", got, len(tc.wantUnreadable), out.String())
					}
					want := fmt.Sprintf("    %-28s %d\n", tc.wantReason, tc.wantKept)
					if !strings.Contains(out.String(), want) {
						t.Errorf("table lacks the kept line %q:\n%s", want, out.String())
					}
					return
				}
				doc := decodePrune(t, out.String())
				if strings.Join(doc.Registry.Unreadable, ",") != strings.Join(tc.wantUnreadable, ",") {
					t.Errorf("report unreadable = %v; want %v", doc.Registry.Unreadable, tc.wantUnreadable)
				}
				if len(doc.Registry.Failed) != 0 {
					t.Errorf("report failed = %+v; want none", doc.Registry.Failed)
				}
				if len(doc.Registry.Kept) != tc.wantKept {
					t.Errorf("report kept %d; want %d: %+v", len(doc.Registry.Kept), tc.wantKept, doc.Registry.Kept)
				}
				for _, k := range doc.Registry.Kept {
					if k.Reason != string(tc.wantReason) {
						t.Errorf("report kept %s = %q; want %q", k.Digest, k.Reason, tc.wantReason)
					}
				}
			})
		}
	}
}
