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

package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// zotFixture is the store the pinned zot left after hack/capture-zot-layout.sh
// pushed its set; zotFixtureList is the capture's listing of it.
const (
	zotFixture     = "testdata/zot-v2.1.22.tar.gz"
	zotFixtureList = "testdata/zot-v2.1.22.txt"
)

// extractFixture unpacks the captured store into a fresh work dir and returns
// the root, keeping its hardlinks and modes.
func extractFixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "registry")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(zotFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, filepath.FromSlash(h.Name))
		if rel, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("fixture entry %q escapes the root", h.Name)
		}
		mode := os.FileMode(h.Mode).Perm()
		switch h.Typeflag {
		case tar.TypeDir:
			if p != root {
				if err := os.MkdirAll(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
		case tar.TypeReg:
			w, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(w, tr); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
		case tar.TypeLink:
			if err := os.Link(filepath.Join(root, filepath.FromSlash(h.Linkname)), p); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("fixture entry %q has type %c", h.Name, h.Typeflag)
		}
	}
	return root
}

func openAt(t *testing.T, root string) *Store {
	t.Helper()
	s, err := Open(root, filepath.Join(filepath.Dir(root), "registry-state"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func name(t *testing.T, s string) ref.Name {
	t.Helper()
	n, err := ref.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func reference(t *testing.T, s string) ref.Reference {
	t.Helper()
	r, err := ref.ParseReference(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// fileStamp is what "never read, written or deleted" can be checked by: the
// bytes, the mtime and the inode.
type fileStamp struct {
	sum   [32]byte
	mtime int64
	ino   uint64
}

func stamp(t *testing.T, p string) fileStamp {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fileStamp{sha256.Sum256(b), fi.ModTime().UnixNano(), fi.Sys().(*syscall.Stat_t).Ino}
}

func sameInode(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(fa, fb)
}

// TestStoreReadsZotLayout reads the store a real zot left (the capture in
// testdata) through the store's read API, checks every row against the push
// set the capture made, then writes into it and checks zot's databases are
// untouched.
func TestStoreReadsZotLayout(t *testing.T) {
	root := extractFixture(t)
	s := openAt(t, root)

	repos, err := s.Repositories()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range repos {
		got = append(got, r.String())
	}
	want := []string{"dangling/only", "dedupe/one", "dedupe/two", "docker/app", "multi/app"}
	if !slices.Equal(got, want) {
		t.Fatalf("Repositories() = %v, want %v", got, want)
	}

	wantTags := map[string][]string{
		"dangling/only": nil,
		"dedupe/one":    {"latest", "v1"},
		"dedupe/two":    {"latest"},
		"docker/app":    {"latest"},
		"multi/app":     {"stable", "v1"},
	}
	for repo, tags := range wantTags {
		got, err := s.Tags(name(t, repo))
		if err != nil || !slices.Equal(got, tags) {
			t.Errorf("Tags(%s) = %v, %v; want %v", repo, got, err, tags)
		}
	}

	// Every row resolves, every manifest verifies, and every blob a manifest
	// names is present and hashes to its digest.
	blobsSeen := 0
	for _, n := range repos {
		idx, err := s.Index(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range idx.Manifests {
			desc, body, err := s.Manifest(n, ref.Reference{Digest: row.Digest})
			if err != nil {
				t.Fatalf("Manifest(%s, %s) = %v", n, row.Digest, err)
			}
			if desc.MediaType != row.MediaType {
				t.Errorf("%s %s: media type %q, row %q", n, row.Digest, desc.MediaType, row.MediaType)
			}
			var m struct {
				Config    *ispec.Descriptor  `json:"config"`
				Layers    []ispec.Descriptor `json:"layers"`
				Manifests []ispec.Descriptor `json:"manifests"`
			}
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			refs := slices.Clone(m.Layers)
			if m.Config != nil {
				refs = append(refs, *m.Config)
			}
			for _, d := range refs {
				f, err := s.OpenBlob(n, d.Digest)
				if err != nil {
					t.Fatalf("OpenBlob(%s, %s) = %v", n, d.Digest, err)
				}
				v := d.Digest.Verifier()
				size, _ := io.Copy(v, f)
				f.Close()
				if !v.Verified() || size != d.Size {
					t.Errorf("blob %s in %s does not verify", d.Digest, n)
				}
				blobsSeen++
			}
			for _, child := range m.Manifests {
				// An index's children are untagged rows of the same repository.
				crow, err := s.Resolve(n, ref.Reference{Digest: child.Digest})
				if err != nil || crow.Annotations[ispec.AnnotationRefName] != "" {
					t.Errorf("child %s of %s: row %+v, %v", child.Digest, n, crow, err)
				}
			}
		}
	}
	if blobsSeen == 0 {
		t.Fatal("no blob was read: the fixture is empty")
	}

	// The Docker v2 schema2 row keeps the media type it was PUT with.
	d, err := s.Resolve(name(t, "docker/app"), reference(t, "latest"))
	if err != nil || d.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		t.Errorf("docker/app:latest = %+v, %v", d, err)
	}
	// The tag overwrite left the old manifest as an untagged row.
	idx, err := s.Index(name(t, "dedupe/two"))
	if err != nil || len(idx.Manifests) != 2 || idx.Manifests[0].Annotations != nil {
		t.Errorf("dedupe/two rows = %+v, %v", idx.Manifests, err)
	}

	// The shared layer is one inode across three repositories.
	layer := digest.FromString("shared layer bytes\n")
	var paths []string
	for _, r := range []string{"dedupe/one", "dedupe/two", "multi/app"} {
		p, err := s.blobPath(name(t, r), layer)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	if !sameInode(t, paths[0], paths[1]) || !sameInode(t, paths[0], paths[2]) {
		t.Error("the shared layer is not one inode across dedupe/one, dedupe/two and multi/app")
	}

	// The leftover and the dangling sessions read as sessions, length as offset.
	for repo, size := range map[string]int64{"dedupe/one": 20, "dangling/only": 14} {
		ups, err := s.Uploads(name(t, repo))
		if err != nil || len(ups) != 1 || ups[0].Size != size {
			t.Errorf("Uploads(%s) = %+v, %v; want one of %d bytes", repo, ups, err, size)
			continue
		}
		got, err := s.UploadSize(context.Background(), name(t, repo), ups[0].ID)
		if err != nil || got != size {
			t.Errorf("UploadSize(%s) = %d, %v", repo, got, err)
		}
	}

	// Writing into zot's store: a resumed leftover session, a mount, a new tag.
	// zot's databases are neither read nor written nor deleted, and the root
	// gains nothing beside the repositories.
	before := map[string]fileStamp{}
	for _, db := range []string{"cache.db", "meta.db"} {
		before[db] = stamp(t, filepath.Join(root, db))
	}
	rootBefore, _ := os.ReadDir(root)
	ctx := context.Background()
	one := name(t, "dedupe/one")
	ups, _ := s.Uploads(one)
	rest := []byte(" and the rest")
	if _, err := s.AppendUpload(ctx, one, ups[0].ID, 20, bytes.NewReader(rest)); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitUpload(ctx, one, ups[0].ID, digest.FromBytes(append([]byte("partial upload bytes"), rest...))); err != nil {
		t.Fatal(err)
	}
	if err := s.MountBlob(ctx, name(t, "docker/app"), one, layer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutManifest(ctx, one, reference(t, "again"), ispec.MediaTypeImageManifest, mustManifest(t, s, one, "v1")); err != nil {
		t.Fatal(err)
	}
	for db, st := range before {
		if got := stamp(t, filepath.Join(root, db)); got != st {
			t.Errorf("%s changed under the store", db)
		}
	}
	rootAfter, _ := os.ReadDir(root)
	if fmt.Sprint(entryNames(rootBefore)) != fmt.Sprint(entryNames(rootAfter)) {
		t.Errorf("root entries %v became %v", entryNames(rootBefore), entryNames(rootAfter))
	}
	if tags, _ := s.Tags(one); !slices.Equal(tags, []string{"again", "latest", "v1"}) {
		t.Errorf("Tags(dedupe/one) after a tag PUT = %v", tags)
	}
}

func mustManifest(t *testing.T, s *Store, n ref.Name, tag string) []byte {
	t.Helper()
	_, b, err := s.Manifest(n, reference(t, tag))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func entryNames(es []os.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// pushSet replays hack/capture-zot-layout.sh's push set through the store, with
// the same bytes in the same order. Where zot deduplicated an upload through its
// cache.db, the replay mounts from the repository that holds the blob, which is
// how a k3sm client gets the same link.
func pushSet(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	const (
		ociM = ispec.MediaTypeImageManifest
		ociI = ispec.MediaTypeImageIndex
		ociC = ispec.MediaTypeImageConfig
		ociL = ispec.MediaTypeImageLayerGzip
		dM   = "application/vnd.docker.distribution.manifest.v2+json"
		dC   = "application/vnd.docker.container.image.v1+json"
		dL   = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	)
	desc := func(mt string, b []byte) string {
		return fmt.Sprintf(`{"mediaType":"%s","digest":"%s","size":%d}`, mt, digest.FromBytes(b), len(b))
	}
	blob := func(repo string, b []byte) {
		if err := s.PutBlob(ctx, name(t, repo), digest.FromBytes(b), bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}
	mount := func(repo, from string, b []byte) {
		if err := s.MountBlob(ctx, name(t, repo), name(t, from), digest.FromBytes(b)); err != nil {
			t.Fatal(err)
		}
	}
	manifest := func(repo, r, mt string, b []byte) {
		if _, err := s.PutManifest(ctx, name(t, repo), reference(t, r), mt, b); err != nil {
			t.Fatal(err)
		}
	}
	leftover := func(repo, b string) {
		id, err := s.NewUpload(ctx, name(t, repo))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendUpload(ctx, name(t, repo), id, 0, strings.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}

	layer := []byte("shared layer bytes\n")
	layer2 := []byte("second layer bytes\n")
	config := []byte(`{"architecture":"arm64","os":"darwin","rootfs":{"type":"layers","diff_ids":[]}}`)
	m1 := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s],"annotations":{"org.opencontainers.image.title":"capture"}}`,
		ociM, desc(ociC, config), desc(ociL, layer)))
	m2 := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s,%s]}`,
		ociM, desc(ociC, config), desc(ociL, layer), desc(ociL, layer2)))

	blob("dedupe/one", config)
	blob("dedupe/one", layer)
	mount("dedupe/two", "dedupe/one", config)
	mount("dedupe/two", "dedupe/one", layer)
	blob("dedupe/one", layer2)
	manifest("dedupe/one", "v1", ociM, m1)
	manifest("dedupe/one", "latest", ociM, m1)
	manifest("dedupe/two", "latest", ociM, m1)
	manifest("dedupe/one", digest.FromBytes(m2).String(), ociM, m2)
	mount("dedupe/two", "dedupe/one", layer2)
	manifest("dedupe/two", "latest", ociM, m2)
	leftover("dedupe/one", "partial upload bytes")

	cfg := map[string][]byte{
		"amd64": []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`),
		"arm64": []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`),
	}
	blob("multi/app", cfg["amd64"])
	blob("multi/app", cfg["arm64"])
	mount("multi/app", "dedupe/one", layer)
	child := map[string][]byte{}
	for _, a := range []string{"amd64", "arm64"} {
		child[a] = []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s]}`,
			ociM, desc(ociC, cfg[a]), desc(ociL, layer)))
		manifest("multi/app", digest.FromBytes(child[a]).String(), ociM, child[a])
	}
	platform := func(a string) string {
		d := desc(ociM, child[a])
		return d[:len(d)-1] + fmt.Sprintf(`,"platform":{"architecture":"%s","os":"linux"}}`, a)
	}
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","manifests":[%s,%s]}`, ociI, platform("amd64"), platform("arm64")))
	manifest("multi/app", "v1", ociI, index)
	manifest("multi/app", "stable", ociI, index)

	dconfig := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}`)
	dlayer := []byte("docker layer bytes\n")
	blob("docker/app", dconfig)
	blob("docker/app", dlayer)
	dm := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","config":%s,"layers":[%s]}`, dM, desc(dC, dconfig), desc(dL, dlayer)))
	manifest("docker/app", "latest", dM, dm)

	leftover("dangling/only", "dangling bytes")
}

// treeEntry is one store entry as the round trip compares it: upload session
// names are random, so they compare as ".uploads/<session>" with their size.
type treeEntry struct {
	path string
	mode fs.FileMode
	size int64
}

// tree lists root's store entries (zot's databases and its _sessions dir
// aside), and groups the blob files by inode.
func tree(t *testing.T, root string) ([]treeEntry, [][]string, map[string][]byte) {
	t.Helper()
	var entries []treeEntry
	inodes := map[uint64][]string{}
	content := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == "cache.db" || rel == "meta.db" {
			return nil
		}
		if rel == "_sessions" {
			return fs.SkipDir
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := treeEntry{path: rel, mode: fi.Mode()}
		if fi.Mode().IsRegular() {
			e.size = fi.Size()
			if dir := filepath.Base(filepath.Dir(p)); dir == ".uploads" {
				e.path = filepath.ToSlash(filepath.Join(filepath.Dir(rel), "<session>"))
			} else {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				content[rel] = b
			}
			if strings.Contains(rel, "/blobs/") {
				ino := fi.Sys().(*syscall.Stat_t).Ino
				inodes[ino] = append(inodes[ino], rel)
			}
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(entries, func(a, b treeEntry) int { return strings.Compare(a.path, b.path) })
	var groups [][]string
	for _, g := range inodes {
		slices.Sort(g)
		groups = append(groups, g)
	}
	slices.SortFunc(groups, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
	return entries, groups, content
}

// TestStoreRoundTripMatchesZot writes the capture's push set with the store and
// compares the result with what zot wrote for the same pushes: the same
// directories and files with the same modes, byte-identical index.json,
// oci-layout, manifests and blobs, the same hardlink sets, and the same upload
// sessions by size. A layout the store writes is therefore one zot reads, since
// zot wrote those same bytes. When K3SM_STORE_ROUNDTRIP_OUT names a directory
// that does not exist yet, the written store is left there for
// `hack/capture-zot-layout.sh --serve-check <dir>/registry` to serve with zot.
func TestStoreRoundTripMatchesZot(t *testing.T) {
	work := t.TempDir()
	if out := os.Getenv("K3SM_STORE_ROUNDTRIP_OUT"); out != "" {
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("K3SM_STORE_ROUNDTRIP_OUT %s must not exist yet", out)
		}
		work = out
	}
	s, err := OpenWorkDir(work)
	if err != nil {
		t.Fatal(err)
	}
	pushSet(t, s)

	gotEntries, gotGroups, gotContent := tree(t, s.Root())
	wantEntries, wantGroups, wantContent := tree(t, extractFixture(t))
	if !slices.Equal(gotEntries, wantEntries) {
		t.Errorf("store tree differs from zot's:\n got %v\nwant %v", gotEntries, wantEntries)
	}
	if fmt.Sprint(gotGroups) != fmt.Sprint(wantGroups) {
		t.Errorf("hardlink sets differ:\n got %v\nwant %v", gotGroups, wantGroups)
	}
	for p, want := range wantContent {
		if got, ok := gotContent[p]; !ok || !bytes.Equal(got, want) {
			t.Errorf("%s differs from zot's:\n got %s\nwant %s", p, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(work, "registry-state", "locks")); err != nil {
		t.Errorf("no lock dir in the state dir: %v", err)
	}
}

// TestFixtureListingMatchesArchive keeps the committed listing honest: every
// path it names is in the archive.
func TestFixtureListingMatchesArchive(t *testing.T) {
	b, err := os.ReadFile(zotFixtureList)
	if err != nil {
		t.Fatal(err)
	}
	root := extractFixture(t)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 4 || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(f[3]))); err != nil {
			t.Errorf("listing names %s: %v", f[3], err)
		}
		n++
	}
	if n < 40 {
		t.Fatalf("listing names %d entries; the capture has more", n)
	}
}
