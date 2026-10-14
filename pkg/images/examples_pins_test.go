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

package images

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// unpinnedAllowed names the registry references that are knowingly NOT pinned by digest,
// each with the reason. An entry is a visible gap, not a waiver: the test fails when an
// entry matches nothing or when the reference it names has since been pinned, so the list
// can only shrink by deleting lines.
var unpinnedAllowed = map[string]string{}

// expectedRepos are the references the scan must find. They make the test non-vacuous in
// a stronger sense than "found at least one": a scanner that silently stops matching a
// file, or a refactor that moves one of these images, reds here.
var expectedRepos = []string{
	"ghcr.io/k3sm-io/mlx-serve",
	"docker.io/temporalio/temporal",
	"docker.io/temporalio/ui",
	"ghcr.io/cirruslabs/macos-sequoia-base",
}

var (
	// imageLine matches a YAML `image:` key, including the `- image:` list form.
	imageLine = regexp.MustCompile(`^\s*(?:-\s+)?image:\s*(\S.*)$`)
	// labBaseLine is the one line of hack/lab-vm.sh that carries the default base image.
	labBaseLine = regexp.MustCompile(`^BASE_IMAGE="\$\{K3SM_LAB_VM_BASE:-([^}]+)\}"\s*$`)
	// digestSuffix is a canonical sha256 digest at the end of a reference.
	digestSuffix = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// imageRef is one registry reference found in a scanned file.
type imageRef struct {
	file string
	line int
	ref  string
}

// pinnedByDigest reports whether ref names its content by a sha256 digest.
func pinnedByDigest(ref string) bool {
	return digestSuffix.MatchString(ref) && !strings.HasPrefix(ref, "@")
}

// repoOf strips the digest and tag from a reference, leaving the repository.
func repoOf(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

// yamlImageRefs returns the registry references on the `image:` lines of a YAML document.
// Comment lines, the `native` sentinel and absolute host paths (the native-pod forms,
// which name no registry) are not registry references and are skipped.
func yamlImageRefs(file, content string) []imageRef {
	var out []imageRef
	sc := bufio.NewScanner(strings.NewReader(content))
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		m := imageLine.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		v := m[1]
		if i := strings.Index(v, " #"); i >= 0 {
			v = v[:i]
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if v == "" || v == "native" || strings.HasPrefix(v, "/") {
			continue
		}
		out = append(out, imageRef{file: file, line: n, ref: v})
	}
	return out
}

// labBaseRef returns the default base image hack/lab-vm.sh boots its guests from.
func labBaseRef(file, content string) (imageRef, bool) {
	sc := bufio.NewScanner(strings.NewReader(content))
	for n := 1; sc.Scan(); n++ {
		if m := labBaseLine.FindStringSubmatch(sc.Text()); m != nil {
			return imageRef{file: file, line: n, ref: m[1]}, true
		}
	}
	return imageRef{}, false
}

// moduleRoot finds this module's root from the test's own source location, so the result
// does not depend on the directory `go test` was started in.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(self) {
		t.Fatalf("cannot locate this test's source file (got %q); run without -trimpath", self)
	}
	for dir := filepath.Dir(self); ; dir = filepath.Dir(dir) {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.HasPrefix(string(b), "module k3sm.io/k3sm\n") {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatalf("no go.mod for k3sm.io/k3sm above %s", self)
		}
	}
}

// TestExamplesAndLabPinImagesByDigest is the gate that every registry image the examples
// apply, and the base image the lab VM harness boots, is named by digest. A tag is
// mutable: the same example applied a week apart could run different bytes.
func TestExamplesAndLabPinImagesByDigest(t *testing.T) {
	t.Run("checker flags a tag-only reference", func(t *testing.T) {
		const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		cases := []struct {
			name    string
			yaml    string
			refs    int
			flagged int
		}{
			{"tag only", "    image: docker.io/library/nginx:1.27\n", 1, 1},
			{"list form tag only", "  - image: \"quay.io/x/y:v1\" # trailing\n", 1, 1},
			{"latest", "image: ghcr.io/a/b:latest\n", 1, 1},
			{"short digest", "image: ghcr.io/a/b:1@sha256:abcd\n", 1, 1},
			{"tag and digest", "    image: docker.io/library/nginx:1.27@" + digest + "\n", 1, 0},
			{"digest only", "    image: ghcr.io/a/b@" + digest + "\n", 1, 0},
			{"native sentinel", "    image: native\n", 0, 0},
			{"absolute host path", "    image: /opt/app/bin/app\n", 0, 0},
			{"comment line", "    # image: docker.io/library/nginx:1.27\n", 0, 0},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				refs := yamlImageRefs("fixture.yaml", c.yaml)
				flagged := 0
				for _, r := range refs {
					if !pinnedByDigest(r.ref) {
						flagged++
					}
				}
				if len(refs) != c.refs || flagged != c.flagged {
					t.Fatalf("refs=%d flagged=%d, want refs=%d flagged=%d (%+v)", len(refs), flagged, c.refs, c.flagged, refs)
				}
			})
		}
		if _, ok := labBaseRef("lab", "BASE_IMAGE=\"${K3SM_LAB_VM_BASE:-ghcr.io/x/y:latest}\"\n"); !ok {
			t.Fatal("lab base line not recognized")
		}
	})

	root := moduleRoot(t)
	var refs []imageRef

	err := filepath.WalkDir(filepath.Join(root, "examples"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		refs = append(refs, yamlImageRefs(rel, string(b))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk examples: %v", err)
	}

	labPath := filepath.Join("hack", "lab-vm.sh")
	b, err := os.ReadFile(filepath.Join(root, labPath))
	if err != nil {
		t.Fatalf("read %s: %v", labPath, err)
	}
	base, ok := labBaseRef(labPath, string(b))
	if !ok {
		t.Fatalf("%s: no BASE_IMAGE default line; this test reads it to check the pin", labPath)
	}
	refs = append(refs, base)

	if len(refs) == 0 {
		t.Fatal("found zero image references; the scan is broken, not the tree clean")
	}

	seen := make(map[string]bool)
	allowUsed := make(map[string]bool)
	for _, r := range refs {
		seen[repoOf(r.ref)] = true
		if pinnedByDigest(r.ref) {
			continue
		}
		if _, ok := unpinnedAllowed[r.ref]; ok {
			allowUsed[r.ref] = true
			continue
		}
		t.Errorf("%s:%d: image %q is not pinned by digest; use name:tag@sha256:<digest>", r.file, r.line, r.ref)
	}
	for _, repo := range expectedRepos {
		if !seen[repo] {
			t.Errorf("expected an image reference to %s; none found (scanned %d references)", repo, len(refs))
		}
	}
	var stale []string
	for ref := range unpinnedAllowed {
		if !allowUsed[ref] {
			stale = append(stale, ref)
		}
	}
	sort.Strings(stale)
	for _, ref := range stale {
		t.Errorf("unpinnedAllowed entry %q matches no unpinned reference; delete it", ref)
	}
}
