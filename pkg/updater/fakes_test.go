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

package updater

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/updater/layout"
)

// k3smUID is the uid the tests deliver archives as.
const k3smUID = 501

// testFS is OSFS over a temporary root, reporting every path as root-owned
// except the overrides, and every ancestor of the root as a sound root
// directory, so the trust checks run without privilege.
type testFS struct {
	*OSFS
	root string

	mu      sync.Mutex
	uid     map[string]uint32
	flags   map[string]uint32
	acl     map[string]bool
	onClose map[string]func()
	syncs   []string
	// crashAt makes the nth WriteFileAtomic or Rename (1-based) fail
	// before it happens; 0 never fails.
	crashAt int
	ops     int
}

var errCrash = errors.New("injected crash")

func newTestFS(t *testing.T) *testFS {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &testFS{root: root, uid: map[string]uint32{}, flags: map[string]uint32{}, acl: map[string]bool{}, onClose: map[string]func(){}}
	f.OSFS = &OSFS{FullSync: func(file *os.File) error {
		f.mu.Lock()
		f.syncs = append(f.syncs, file.Name())
		f.mu.Unlock()
		return nil
	}}
	return f
}

func (f *testFS) adjust(path string, info Info) Info {
	f.mu.Lock()
	defer f.mu.Unlock()
	if path != f.root && !strings.HasPrefix(path, f.root+"/") {
		if info.Mode.IsDir() {
			info.Mode = fs.ModeDir | 0o755
		}
		info.UID = 0
		return info
	}
	info.UID = 0
	if u, ok := f.uid[path]; ok {
		info.UID = u
	}
	info.Flags = f.flags[path]
	info.HasACL = f.acl[path]
	return info
}

func (f *testFS) step() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops++
	if f.crashAt != 0 && f.ops == f.crashAt {
		return errCrash
	}
	return nil
}

type testFile struct {
	File
	f    *testFS
	path string
}

func (t testFile) Info() (Info, error) {
	info, err := t.File.Info()
	if err != nil {
		return info, err
	}
	return t.f.adjust(t.path, info), nil
}

func (t testFile) Close() error {
	err := t.File.Close()
	t.f.mu.Lock()
	hook := t.f.onClose[t.path]
	delete(t.f.onClose, t.path)
	t.f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (f *testFS) OpenRead(path string) (File, error) {
	file, err := f.OSFS.OpenRead(path)
	if err != nil {
		return nil, err
	}
	return testFile{File: file, f: f, path: filepath.Clean(path)}, nil
}

func (f *testFS) Lstat(path string) (Info, error) {
	info, err := f.OSFS.Lstat(path)
	if err != nil {
		return info, err
	}
	return f.adjust(filepath.Clean(path), info), nil
}

func (f *testFS) WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := f.step(); err != nil {
		return err
	}
	return f.OSFS.WriteFileAtomic(path, data, mode)
}

func (f *testFS) Rename(oldpath, newpath string) error {
	if err := f.step(); err != nil {
		return err
	}
	return f.OSFS.Rename(oldpath, newpath)
}

// tree builds the layout's directories under the root.
func (f *testFS) tree(t *testing.T) layout.Layout {
	t.Helper()
	l := layout.New(f.root)
	for _, d := range []string{l.VersionsDir(), l.StateDir(), l.WorkDir(), filepath.Dir(l.TrustCA()), l.UpdaterDir(), filepath.Join(f.root, "inbox")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.uid[filepath.Join(f.root, "inbox")] = k3smUID
	writeFile(t, l.TrustCA(), "CA PEM", 0o644)
	return l
}

func writeFile(t *testing.T, p, data string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// machO is a member body that starts with the 64-bit Mach-O magic.
func machO(name string) string { return "\xcf\xfa\xed\xfe" + name }

// release is a test release: members by path, and the manifest fields.
type release struct {
	version, compatibleFrom string
	requiresInstaller       bool
	files                   map[string]string
	// extra are tar members the manifest does not list.
	extra map[string]string
	// kinds overrides a member's declared kind.
	kinds map[string]MemberKind
}

func newRelease(ver string) release {
	files := map[string]string{"LICENSE": "license text"}
	for _, m := range RequiredMembers {
		files[m] = machO(m + ver)
	}
	files["cp-payload/kube-apiserver"] = machO("apiserver" + ver)
	return release{version: ver, compatibleFrom: "0.1.0", files: files}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// build returns the tar archive and the manifest JSON.
func (r release) build(t *testing.T) ([]byte, []byte) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	all := map[string]string{}
	for k, v := range r.files {
		all[k] = v
	}
	for k, v := range r.extra {
		all[k] = v
	}
	names := make([]string, 0, len(all))
	for k := range all {
		names = append(names, k)
	}
	slices.Sort(names)
	var members []testMember
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(all[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(all[n])); err != nil {
			t.Fatal(err)
		}
		if _, ok := r.files[n]; !ok {
			continue
		}
		kind := MemberData
		if strings.HasPrefix(all[n], "\xcf\xfa\xed\xfe") {
			kind = MemberMachO
		}
		if k, ok := r.kinds[n]; ok {
			kind = k
		}
		members = append(members, testMember{Path: n, SHA256: sum(all[n]), Kind: kind})
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := json.Marshal(testManifest{
		Version: r.version, KubeMinor: "1.35", CompatibleFrom: r.compatibleFrom,
		RequiresInstaller: r.requiresInstaller, ArchiveSHA256: sum(buf.String()), Members: members,
	})
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), m
}

type testMember struct {
	Path   string     `json:"path"`
	SHA256 string     `json:"sha256"`
	Kind   MemberKind `json:"kind"`
}

type testManifest struct {
	Version           string       `json:"version"`
	KubeMinor         string       `json:"kubeMinor"`
	CompatibleFrom    string       `json:"compatibleFrom"`
	RequiresInstaller bool         `json:"requiresInstaller"`
	ArchiveSHA256     string       `json:"archiveSHA256"`
	Members           []testMember `json:"members"`
}

// goodSig is the signature the fake verifier accepts.
const goodSig = "sig-ok"

// fakePayload is the k3sm leg: the signature must be goodSig and the CA the
// trust copy, the archive's sha256 the manifest's; every tar member is
// written into dst.
type fakePayload struct {
	archiveName string
	sawArchive  []byte
}

func (p *fakePayload) VerifyPayload(_ context.Context, in SignedInput, archive io.ReadSeeker, dst string) (*Manifest, error) {
	if string(in.Signature) != goodSig || string(in.ClusterCAPEM) != "CA PEM" {
		return nil, errors.New("fake: signature refused")
	}
	if f, ok := archive.(interface{ Name() string }); ok {
		p.archiveName = f.Name()
	}
	data, err := io.ReadAll(archive)
	if err != nil {
		return nil, err
	}
	p.sawArchive = data
	var tm testManifest
	if err := json.Unmarshal(in.Manifest, &tm); err != nil {
		return nil, err
	}
	if sum(string(data)) != tm.ArchiveSHA256 {
		return nil, errors.New("fake: archive digest")
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dst, filepath.FromSlash(hdr.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			return nil, err
		}
	}
	m := &Manifest{Version: tm.Version, KubeMinor: tm.KubeMinor, CompatibleFrom: tm.CompatibleFrom,
		RequiresInstaller: tm.RequiresInstaller, ArchiveSHA256: tm.ArchiveSHA256}
	for _, mem := range tm.Members {
		m.Members = append(m.Members, Member(mem))
	}
	return m, nil
}

// fakeCode is the Apple leg: it refuses every path under a refused version
// directory or with a refused base name.
type fakeCode struct {
	mu      sync.Mutex
	refuse  map[string]bool
	checked []string
}

func (c *fakeCode) VerifyCode(_ context.Context, path, binary, version string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked = append(c.checked, path)
	if c.refuse[binary] || c.refuse[filepath.Base(filepath.Dir(path))] || c.refuse[version] {
		return fmt.Errorf("fake: %s refused", binary)
	}
	return nil
}

// fakeClock is the clock seam.
type fakeClock struct {
	mu   sync.Mutex
	now  time.Time
	boot string
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) BootID() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.boot, nil
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) reboot(id string) {
	c.mu.Lock()
	c.boot = id
	c.mu.Unlock()
}

type fakePods []string

func (p fakePods) InUseVersions(context.Context) ([]string, error) { return p, nil }

// installVersion puts a full, sound version directory in the tree.
func installVersion(t *testing.T, l layout.Layout, ver string) {
	t.Helper()
	dir := filepath.Join(l.VersionsDir(), ver)
	for name, body := range newRelease(ver).files {
		writeFile(t, filepath.Join(dir, name), body, 0o755)
	}
}

// link points a layout link at a version, as the installer leaves it.
func link(t *testing.T, fsys FS, plan func(string) ([]layout.Step, error), ver string) {
	t.Helper()
	steps, err := plan(ver)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySteps(fsys, steps); err != nil {
		t.Fatal(err)
	}
}
