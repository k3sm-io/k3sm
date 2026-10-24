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
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// clusterRegistry is an in-process registry standing in for the server's, with
// this node's push credential pointing at it.
type clusterRegistry struct {
	workDir string
	// authority is the loopback spelling the CLI uploads to: localhost:<port>.
	authority string
	probe     *authProbe
}

// withClusterRegistry starts an in-process registry and writes this node's push
// credential for it into a fresh work dir.
func withClusterRegistry(t *testing.T) clusterRegistry {
	t.Helper()
	host, probe := startRegistry(t, "")
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(registrysvc.StateDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := registrysvc.WriteCredential(dir, registrysvc.Credential{
		Address: host, Username: "k3sm", Password: "secret",
	}); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	t.Setenv("K3SM_WORK_DIR", dir)
	return clusterRegistry{workDir: dir, authority: "localhost:" + port, probe: probe}
}

// seed uploads a random image under repoTag (repository:tag) and returns it.
func (r clusterRegistry) seed(t *testing.T, repoTag string) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(r.authority + "/" + repoTag)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img, remote.WithContext(t.Context())); err != nil {
		t.Fatalf("seed %s: %v", repoTag, err)
	}
	return img
}

// digestOf is the digest the registry serves for repoTag.
func (r clusterRegistry) digestOf(t *testing.T, repoTag string) string {
	t.Helper()
	ref, err := name.ParseReference(r.authority + "/" + repoTag)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref, remote.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("head %s: %v", repoTag, err)
	}
	return desc.Digest.String()
}

func mustDigest(t *testing.T, img ggcrv1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

// TestTagRefusesRepointWithoutForce pins that `k3sm image tag` adds a name to a
// manifest the cluster registry already holds, and never silently moves an
// existing name onto other content: re-pointing takes --force.
func TestTagRefusesRepointWithoutForce(t *testing.T) {
	reg := withClusterRegistry(t)
	a := reg.seed(t, "app:v1")
	b := reg.seed(t, "app:v2")
	args := func(extra ...string) []string {
		return append([]string{"--work-dir", reg.workDir, "tag"}, extra...)
	}

	out, err := runImageCmd(t, args("app:v1", "registry-k3sm:6450/app:stable"))
	if err != nil {
		t.Fatalf("tag a new name: %v\n%s", err, out)
	}
	if got := reg.digestOf(t, "app:stable"); got != mustDigest(t, a) {
		t.Errorf("app:stable = %s, want %s (the same manifest bytes)", got, mustDigest(t, a))
	}
	if !strings.Contains(out, "registry-k3sm:6450/app:stable") {
		t.Errorf("the output does not name the new tag:\n%s", out)
	}

	out, err = runImageCmd(t, args("app:v1", "app:stable"))
	if err != nil || !strings.Contains(out, "already tagged") {
		t.Errorf("re-tagging the same digest = %v, %q; want an already-tagged success", err, out)
	}

	_, err = runImageCmd(t, args("app:v2", "app:stable"))
	if !errors.Is(err, errTagRepoint) {
		t.Fatalf("re-pointing without --force err = %v, want errTagRepoint", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the refusal does not name --force: %v", err)
	}
	if got := reg.digestOf(t, "app:stable"); got != mustDigest(t, a) {
		t.Errorf("a refused re-point moved app:stable to %s", got)
	}

	out, err = runImageCmd(t, args("--force", "app:v2", "app:stable"))
	if err != nil {
		t.Fatalf("re-point with --force: %v\n%s", err, out)
	}
	if got := reg.digestOf(t, "app:stable"); got != mustDigest(t, b) {
		t.Errorf("app:stable = %s after --force, want %s", got, mustDigest(t, b))
	}

	// A digest source names a manifest in the new tag's repository.
	out, err = runImageCmd(t, args(mustDigest(t, a), "app:pinned"))
	if err != nil {
		t.Fatalf("tag by digest: %v\n%s", err, out)
	}
	if got := reg.digestOf(t, "app:pinned"); got != mustDigest(t, a) {
		t.Errorf("app:pinned = %s, want %s", got, mustDigest(t, a))
	}

	if _, err := runImageCmd(t, args("app:v1", "ghcr.io/org/app:v1")); !errors.Is(err, errForeignTag) {
		t.Errorf("tagging onto another registry err = %v, want errForeignTag", err)
	}
}

// TestImageUntagDeletesOneTag pins that `k3sm image untag` removes a name from
// the cluster registry with this node's push credential, and only that name.
func TestImageUntagDeletesOneTag(t *testing.T) {
	reg := withClusterRegistry(t)
	img := reg.seed(t, "app:v1")
	if _, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "tag", "app:v1", "app:keep"}); err != nil {
		t.Fatalf("tag: %v", err)
	}
	untag := func(extra ...string) (string, error) {
		return runImageCmd(t, append([]string{"--work-dir", reg.workDir, "untag"}, extra...))
	}

	other := "sha256:" + strings.Repeat("0", 64)
	if _, err := untag("app:v1", "--digest", other); err == nil || !strings.Contains(err.Error(), "nothing was removed") {
		t.Errorf("untag with a stale --digest = %v, want a refusal", err)
	}
	out, err := untag("registry-k3sm:6450/app:v1", "--digest", mustDigest(t, img))
	if err != nil {
		t.Fatalf("untag: %v\n%s", err, out)
	}
	if !strings.Contains(out, "untagged registry-k3sm:6450/app:v1") {
		t.Errorf("output = %q", out)
	}
	if got := reg.digestOf(t, "app:keep"); got != mustDigest(t, img) {
		t.Errorf("app:keep = %s after untagging app:v1, want it untouched", got)
	}
	if _, err := untag("app:v1"); !errors.Is(err, errNotInRegistry) {
		t.Errorf("untag of an absent tag = %v, want errNotInRegistry", err)
	}
	if _, err := untag("app@" + mustDigest(t, img)); err == nil || !strings.Contains(err.Error(), "not a digest") {
		t.Errorf("untag by digest = %v, want a refusal", err)
	}
	if _, err := untag("ghcr.io/org/app:v1"); !errors.Is(err, errForeignTag) {
		t.Errorf("untag on another registry = %v, want errForeignTag", err)
	}
	var sawDelete bool
	for _, h := range reg.probe.headers() {
		if h != "" {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Errorf("the registry saw no credential; untag must present this node's push credential")
	}
}

// TestImageInspectReadsTheRegistry pins that `k3sm image inspect` reports the
// manifest and config the cluster registry serves.
func TestImageInspectReadsTheRegistry(t *testing.T) {
	reg := withClusterRegistry(t)
	base, err := random.Image(64, 2)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := base.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "darwin", "arm64"
	cf.Config.User = "app"
	cf.Config.Entrypoint = []string{"/app"}
	img, err := mutate.ConfigFile(base, cf)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(reg.authority + "/team/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img, remote.WithContext(t.Context())); err != nil {
		t.Fatal(err)
	}

	out, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "inspect", "team/app:v1"})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	for _, want := range []string{"registry-k3sm:6450/team/app:v1", mustDigest(t, img), "darwin/arm64", "USER        app", `["/app"]`, "LAYERS      2"} {
		if !strings.Contains(out, want) {
			t.Errorf("the table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "WORKDIR") {
		t.Errorf("an unset working directory got a row:\n%s", out)
	}

	out, err = runImageCmd(t, []string{"--work-dir", reg.workDir, "inspect", "team/app@" + mustDigest(t, img), "-o", "json"})
	if err != nil {
		t.Fatalf("inspect -o json: %v", err)
	}
	var view struct {
		Digest string          `json:"digest"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal([]byte(out), &view); err != nil {
		t.Fatalf("parse the JSON: %v\n%s", err, out)
	}
	raw, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	var gotCfg, wantCfg bytes.Buffer
	if err := json.Compact(&gotCfg, view.Config); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&wantCfg, raw); err != nil {
		t.Fatal(err)
	}
	if view.Digest != mustDigest(t, img) || gotCfg.String() != wantCfg.String() {
		t.Errorf("json digest %s config %s, want %s and the registry's config", view.Digest, view.Config, mustDigest(t, img))
	}

	if _, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "inspect", "team/app:v1", "--platform", "linux/amd64"}); err == nil {
		t.Errorf("inspect --platform linux/amd64 of a darwin image succeeded")
	}
	if _, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "inspect", mustDigest(t, img)}); err == nil || !strings.Contains(err.Error(), "names no repository") {
		t.Errorf("inspect of a bare digest = %v, want the repository refusal", err)
	}
	if _, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "inspect", "team/app:absent"}); !errors.Is(err, errNotInRegistry) {
		t.Errorf("inspect of an absent tag = %v, want errNotInRegistry", err)
	}
}

// TestImageSaveExportsFromTheRegistry pins that `k3sm image save` writes the
// registry's image as a tarred OCI layout that import reads back under the
// same name, and that an index is saved whole unless --platform picks one.
func TestImageSaveExportsFromTheRegistry(t *testing.T) {
	reg := withClusterRegistry(t)
	img := reg.seed(t, "app:v1")
	dir := t.TempDir()
	target := filepath.Join(dir, "app.tar")

	out, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "save", "app:v1", "-o", target})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !strings.Contains(out, mustDigest(t, img)) {
		t.Errorf("save printed no digest:\n%s", out)
	}
	assertOnlyFile(t, dir, "app.tar")
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := inspectArchive(f, runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT)
	f.Close()
	if err != nil || reference != "registry-k3sm:6450/app:v1" {
		t.Errorf("the archive names %q (%v), want registry-k3sm:6450/app:v1", reference, err)
	}
	layoutDir := filepath.Join(t.TempDir(), "layout")
	if err := extractOCILayout(target, layoutDir); err != nil {
		t.Fatal(err)
	}
	got, err := layoutImage(layoutDir)
	if err != nil {
		t.Fatal(err)
	}
	if mustDigest(t, got) != mustDigest(t, img) {
		t.Errorf("the saved image is %s, want %s", mustDigest(t, got), mustDigest(t, img))
	}

	// An index is saved whole, or as one platform's child.
	arm, amd := platformImage(t, "linux", "arm64"), platformImage(t, "linux", "amd64")
	idx := mutate.AppendManifests(testIndex(t, arm), mutate.IndexAddendum{Add: amd, Descriptor: ggcrv1.Descriptor{Platform: &ggcrv1.Platform{OS: "linux", Architecture: "amd64"}}})
	idxRef, err := name.ParseReference(reg.authority + "/multi:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(idxRef, idx, remote.WithContext(t.Context())); err != nil {
		t.Fatal(err)
	}
	whole := filepath.Join(t.TempDir(), "whole.tar")
	if _, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "save", "multi:v1", "-o", whole}); err != nil {
		t.Fatalf("save an index: %v", err)
	}
	b, cleanup, err := readArchive(whole, runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT)
	if err != nil {
		t.Fatalf("read the saved index: %v", err)
	}
	cleanup()
	if b.index == nil {
		t.Errorf("an index was saved as a single image")
	}
	one := filepath.Join(t.TempDir(), "one.tar")
	if _, err := runImageCmd(t, []string{"--work-dir", reg.workDir, "save", "multi:v1", "--platform", "linux/amd64", "-o", one}); err != nil {
		t.Fatalf("save one platform: %v", err)
	}
	oneDir := filepath.Join(t.TempDir(), "layout")
	if err := extractOCILayout(one, oneDir); err != nil {
		t.Fatal(err)
	}
	p, err := layout.FromPath(oneDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Image(mustDigestHash(t, amd)); err != nil {
		t.Errorf("the linux/amd64 save does not hold the amd64 child: %v", err)
	}
}

// platformImage is a random image whose config declares os/arch.
func platformImage(t *testing.T, os, arch string) ggcrv1.Image {
	t.Helper()
	base, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := base.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = os, arch
	img, err := mutate.ConfigFile(base, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func mustDigestHash(t *testing.T, img ggcrv1.Image) ggcrv1.Hash {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
