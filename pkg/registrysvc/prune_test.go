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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// layoutRepo writes a repository with the given index.json entries and blobs.
func layoutRepo(t *testing.T, workDir, repo string, index any, blobs map[string][]byte, age time.Duration) {
	t.Helper()
	dir := filepath.Join(StateDir(workDir), filepath.FromSlash(repo))
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	for dg, body := range blobs {
		p := blobPath(dir, dg)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func entry(dg, tag string) map[string]any {
	e := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": dg, "size": 1}
	if tag != "" {
		e["annotations"] = map[string]string{refNameAnnotation: tag}
	}
	return e
}

func idx(entries ...map[string]any) map[string]any {
	return map[string]any{"schemaVersion": 2, "manifests": entries}
}

func TestPruneGraceIsTheGCDelay(t *testing.T) {
	d, err := time.ParseDuration(gcDelay)
	if err != nil || d != PruneGrace {
		t.Errorf("PruneGrace = %v, gcDelay = %q (%v): they must agree", PruneGrace, gcDelay, err)
	}
}

func TestPlanRepositoryFailsClosed(t *testing.T) {
	old := 2 * time.Hour
	a, b := []byte(`{"schemaVersion":2,"a":1}`), []byte(`{"schemaVersion":2,"b":1}`)
	da, db := digestOf(a), digestOf(b)

	t.Run("a digest tagged by any entry is tagged", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", idx(entry(da, ""), entry(da, "v1"), entry(db, "")), map[string][]byte{da: a, db: b}, old)
		p := PlanRepository(wd, "r", time.Now())
		if len(p.Delete) != 1 || p.Delete[0].Digest != db {
			t.Errorf("delete = %+v; want only %s (zot's delete by digest would drop v1)", p.Delete, db)
		}
	})

	t.Run("a missing manifest blob keeps every untagged manifest", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", idx(entry(da, "v1"), entry(db, "")), map[string][]byte{db: b}, old)
		p := PlanRepository(wd, "r", time.Now())
		if len(p.Delete) != 0 || len(p.Kept) != 1 || p.Kept[0].Reason != KeepUnreadable {
			t.Errorf("plan = %+v; want %s kept as unreadable", p, db)
		}
	})

	t.Run("a digest that is no digest makes the repository unreadable", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", idx(entry("sha256:../../etc", "")), nil, old)
		p := PlanRepository(wd, "r", time.Now())
		if len(p.Delete) != 0 || len(p.Unreadable) != 1 {
			t.Errorf("plan = %+v; want the repository unreadable", p)
		}
	})

	t.Run("an unparsable index makes the repository unreadable", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", "not an index", nil, old)
		if p := PlanRepository(wd, "r", time.Now()); len(p.Unreadable) != 1 {
			t.Errorf("plan = %+v; want the repository unreadable", p)
		}
	})
}

func TestRepositoriesFindsNestedLayoutsOnly(t *testing.T) {
	wd := t.TempDir()
	layoutRepo(t, wd, "a", idx(), nil, 0)
	layoutRepo(t, wd, "team/b", idx(), nil, 0)
	// A layout-shaped directory inside a repository's blobs is never a
	// repository, and zot's own files at the root are not either.
	layoutRepo(t, wd, "a/blobs/fake", idx(), nil, 0)
	if err := WriteCredential(wd, Credential{Address: "127.0.0.1:6450", Username: "k3sm", Password: "x"}); err != nil {
		t.Fatal(err)
	}
	got, err := Repositories(wd)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "team/b" {
		t.Errorf("repositories = %v; want [a team/b]", got)
	}
}
