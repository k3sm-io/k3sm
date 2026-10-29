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
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// cachedImageFixture is the image fixture with a description cache in a test
// directory.
func cachedImageFixture(t *testing.T) imageFixture {
	t.Helper()
	f := newImageFixture(t, true)
	f.env.cacheRoot = t.TempDir()
	return f
}

// cacheEntries lists the description cache's files.
func cacheEntries(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".json") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func imageListRows(t *testing.T, doc string) map[string]imageRow {
	t.Helper()
	var rep imageListReport
	if err := json.Unmarshal([]byte(doc), &rep); err != nil {
		t.Fatal(err)
	}
	rows := map[string]imageRow{}
	for _, r := range rep.Images {
		rows[r.Reference] = r
	}
	return rows
}

// TestImageLsReusesDescriptionsAcrossRuns: a second listing reads each tag's
// digest with a HEAD and describes nothing it described before: no manifest
// GET by tag, no manifest GET by digest, no config blob GET.
func TestImageLsReusesDescriptionsAcrossRuns(t *testing.T) {
	f := cachedImageFixture(t)
	runImageReport(t, f.env, "ls", "-o", "json")
	if got := cacheEntries(t, f.env.cacheRoot); len(got) != 3 {
		t.Fatalf("cold run cached %d descriptions (%v); want one per distinct tag digest, 3", len(got), got)
	}
	for _, p := range cacheEntries(t, f.env.cacheRoot) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v; want 0600", p, fi.Mode().Perm())
		}
	}
	f.reg.ResetRequests()
	runImageReport(t, f.env, "ls", "-o", "json")
	for _, c := range []struct {
		method, class string
		want          int
	}{
		{http.MethodGet, registrytest.ClassManifestTag, 0},
		{http.MethodGet, registrytest.ClassManifestDigest, 0},
		{http.MethodGet, registrytest.ClassBlob, 0},
		{http.MethodHead, registrytest.ClassManifestTag, 3},
	} {
		if got := f.reg.Requests(c.method, c.class); got != c.want {
			t.Errorf("warm run: %d %s %s requests; want %d", got, c.method, c.class, c.want)
		}
	}
}

// TestImageLsRetagIsNeverStale: the tag-to-digest mapping is read live every
// run, so a tag re-pointed between runs is reported at its new content.
func TestImageLsRetagIsNeverStale(t *testing.T) {
	f := cachedImageFixture(t)
	runImageReport(t, f.env, "ls", "-o", "json")
	if len(cacheEntries(t, f.env.cacheRoot)) == 0 {
		t.Fatal("the cold run cached nothing, so a warm run cannot be told from a cold one")
	}
	moved := f.reg.Image("app", "v1", registryclient.Platform{OS: "linux", Architecture: "amd64"}, []byte("a rebuilt layer of a different size"))
	cold := newImageFixture(t, true)
	cold.reg.Image("app", "v1", registryclient.Platform{OS: "linux", Architecture: "amd64"}, []byte("a rebuilt layer of a different size"))
	want := imageListRows(t, runImageReport(t, cold.env, "ls", "-o", "json"))["registry-k3sm:6450/app:v1"]

	got := imageListRows(t, runImageReport(t, f.env, "ls", "-o", "json"))["registry-k3sm:6450/app:v1"]
	if got.Digest != moved.Digest || strings.Join(got.Platforms, ",") != "linux/amd64" || got.SizeBytes != want.SizeBytes {
		t.Errorf("app:v1 after a retag = digest %s platforms %v size %d; want %s linux/amd64 %d",
			got.Digest, got.Platforms, got.SizeBytes, moved.Digest, want.SizeBytes)
	}
}

// TestImageLsOutputSameWarmAndCold: a listing answered from the cache writes
// exactly what one that described everything writes. The -o ndjson image lines
// come in completion order, so its lines are compared as a set, progress lines
// aside (they report how far a listing had got when they were written).
func TestImageLsOutputSameWarmAndCold(t *testing.T) {
	f := cachedImageFixture(t)
	cold := runImageReport(t, f.env, "ls", "-o", "json")
	if warm := runImageReport(t, f.env, "ls", "-o", "json"); warm != cold {
		t.Errorf("-o json differs warm and cold:\n--- warm\n%s\n--- cold\n%s", warm, cold)
	}
	if warm, cold := runImageReport(t, f.env, "df", "-o", "json"), runImageReport(t, newImageFixture(t, true).env, "df", "-o", "json"); warm != cold {
		t.Errorf("df -o json differs warm and cold:\n--- warm\n%s\n--- cold\n%s", warm, cold)
	}
	stream := func(env imageRegistryEnv) []string {
		var out []string
		for _, l := range strings.Split(runImageReport(t, env, "ls", "-o", "ndjson"), "\n") {
			if l != "" && !strings.Contains(l, `"type":"progress"`) {
				out = append(out, l)
			}
		}
		sort.Strings(out)
		return out
	}
	g := cachedImageFixture(t)
	coldLines := stream(g.env)
	if len(cacheEntries(t, g.env.cacheRoot)) == 0 {
		t.Fatal("the ndjson cold run cached nothing")
	}
	g.reg.ResetRequests()
	warmLines := stream(g.env)
	if g.reg.Requests(http.MethodGet, registrytest.ClassBlob) != 0 {
		t.Error("the ndjson warm run read config blobs")
	}
	if strings.Join(warmLines, "\n") != strings.Join(coldLines, "\n") {
		t.Errorf("-o ndjson differs warm and cold:\n--- warm\n%s\n--- cold\n%s", strings.Join(warmLines, "\n"), strings.Join(coldLines, "\n"))
	}
}

// TestImageLsCorruptCacheEntryIsRedescribed: an entry that does not decode, or
// decodes to a description of another digest, is ignored: the tag is
// described afresh and the entry rewritten.
func TestImageLsCorruptCacheEntryIsRedescribed(t *testing.T) {
	f := cachedImageFixture(t)
	cold := runImageReport(t, f.env, "ls", "-o", "json")
	entries := cacheEntries(t, f.env.cacheRoot)
	if len(entries) != 3 {
		t.Fatalf("cold run cached %d descriptions; want 3", len(entries))
	}
	good, err := os.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entries[0], []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(entries[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entries[1], other, 0o600); err != nil {
		t.Fatal(err)
	}
	f.reg.ResetRequests()
	if warm := runImageReport(t, f.env, "ls", "-o", "json"); warm != cold {
		t.Errorf("a corrupt cache changed the listing:\n--- warm\n%s\n--- cold\n%s", warm, cold)
	}
	if got := f.reg.Requests(http.MethodGet, registrytest.ClassManifestDigest); got < 2 {
		t.Errorf("%d manifest reads by digest; want the two corrupt entries re-described", got)
	}
	rewritten, err := os.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(rewritten) != string(good) {
		t.Errorf("the corrupt entry was not rewritten: %q", rewritten)
	}
}

// TestImageLsUncreatableCacheIsNoCache: a cache root that cannot be created
// lists exactly what a listing with no cache does.
func TestImageLsUncreatableCacheIsNoCache(t *testing.T) {
	f := newImageFixture(t, true)
	want := runImageReport(t, f.env, "ls", "-o", "json")
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.env.cacheRoot = filepath.Join(file, "cache")
	if got := runImageReport(t, f.env, "ls", "-o", "json"); got != want {
		t.Errorf("an uncreatable cache changed the listing:\n--- got\n%s\n--- want\n%s", got, want)
	}
}
