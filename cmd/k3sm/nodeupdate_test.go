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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/version"
)

const (
	updTestNode    = "k3sm-worker"
	updTestTag     = "v0.2.0"
	updTestURL     = "https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
	updTestKube    = "v1.34.1"
	updTestRunning = "0.1.0"
)

// updTarEntry is one member of a test archive.
type updTarEntry struct {
	name     string
	typeflag byte
	body     string
	link     string
}

// releaseEntries is a release archive's member list: the build set, the
// cp-payload directory, and the three members the archive ships that are not
// part of the set.
func releaseEntries() []updTarEntry {
	out := []updTarEntry{{name: "cp-payload/", typeflag: tar.TypeDir}}
	for _, m := range update.SetMembers() {
		out = append(out, updTarEntry{name: m, typeflag: tar.TypeReg, body: "bytes of " + m})
	}
	for _, m := range []string{"LICENSE", "NOTICE", "k3sm-netd"} {
		out = append(out, updTarEntry{name: m, typeflag: tar.TypeReg, body: m})
	}
	return out
}

func buildUpdArchive(t *testing.T, entries []updTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o755, Linkname: e.link, Size: int64(len(e.body))}
		if e.typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func updSHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeFetcher serves one archive and records the URLs it was asked for.
type fakeFetcher struct {
	archive []byte
	urls    []string
}

func (f *fakeFetcher) Fetch(_ context.Context, u string) (io.ReadCloser, error) {
	f.urls = append(f.urls, u)
	return io.NopCloser(bytes.NewReader(f.archive)), nil
}

// fakeNetd records the ApplyUpdate request and, at the moment of the call,
// re-hashes every file the request names, so a set that was not fully
// extracted before the verb ran is caught. It streams Verifying, Installing
// and then reports Restarting, as the real client does when the installer
// restarts the helper.
type fakeNetd struct {
	t        *testing.T
	calls    []wire.ApplyUpdateArgs
	onDisk   map[string]string
	result   wire.UpdateResult
	err      error
	onCalled func()
}

func (n *fakeNetd) ApplyUpdate(_ context.Context, args wire.ApplyUpdateArgs, progress func(wire.UpdatePhase)) (wire.UpdateResult, error) {
	n.calls = append(n.calls, args)
	if n.onCalled != nil {
		n.onCalled()
	}
	n.onDisk = map[string]string{}
	for rel := range args.Manifest {
		b, err := os.ReadFile(filepath.Join(args.SourceDir, filepath.FromSlash(rel)))
		if err != nil {
			n.t.Errorf("ApplyUpdate ran before %s was extracted: %v", rel, err)
			continue
		}
		n.onDisk[rel] = updSHA256Hex(b)
	}
	for _, ph := range []wire.UpdatePhase{wire.UpdatePhaseVerifying, wire.UpdatePhaseInstalling} {
		progress(ph)
	}
	if n.err != nil {
		return n.result, n.err
	}
	res := n.result
	if res.Phase == "" {
		res.Phase = wire.UpdatePhaseRestarting
	}
	progress(res.Phase)
	return res, nil
}

func handedOverNode(payload update.Payload, extra map[string]string) *corev1.Node {
	b, _ := json.Marshal(payload)
	ann := map[string]string{
		updatesv1alpha1.AnnotationUpdateVersion: updTestTag,
		updatesv1alpha1.AnnotationUpdatePayload: string(b),
	}
	for k, v := range controllerAnnotations {
		ann[k] = v
	}
	for k, v := range extra {
		ann[k] = v
	}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: updTestNode, Annotations: ann}}
}

// phasesWritten is every phase annotation value the watcher patched, in order,
// and fails the test when a patch touches any other key.
func phasesWritten(t *testing.T, cs *fake.Clientset) []string {
	t.Helper()
	var out []string
	for _, a := range cs.Actions() {
		pa, ok := a.(k8stesting.PatchAction)
		if !ok {
			continue
		}
		var p struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(pa.GetPatch(), &p); err != nil {
			t.Fatalf("decode patch: %v", err)
		}
		for k, v := range p.Metadata.Annotations {
			if k != updatesv1alpha1.AnnotationUpdatePhase {
				t.Errorf("the watcher patched %s; it may write only the phase annotation", k)
			}
			out = append(out, v)
		}
	}
	return out
}

func phaseNames(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		p, _ := update.ParsePhase(v)
		out[i] = string(p)
	}
	return out
}

type updateRun struct {
	cs    *fake.Clientset
	fetch *fakeFetcher
	netd  *fakeNetd
	root  string
}

// controllerAnnotations are the controller's own update records on a handed
// over Node, which the node side must leave exactly as they are.
var controllerAnnotations = map[string]string{
	"k3sm.io/update-cordoned":       "true",
	"k3sm.io/update-handed-over-at": "2026-10-15T12:00:00Z",
	"k3sm.io/update-ready-at":       "2026-10-15T12:10:00Z",
}

func runUpdateSync(t *testing.T, node *corev1.Node, archive []byte, running string, netd *fakeNetd) updateRun {
	t.Helper()
	return runUpdateSyncReady(t, node, archive, running, netd, nil)
}

func runUpdateSyncReady(t *testing.T, node *corev1.Node, archive []byte, running string, netd *fakeNetd, ready func(context.Context) bool) updateRun {
	t.Helper()
	cs := fake.NewClientset(node)
	ff := &fakeFetcher{archive: archive}
	if netd == nil {
		netd = &fakeNetd{}
	}
	netd.t = t
	root := filepath.Join(t.TempDir(), "updates")
	opts := nodeOptions{
		nodeName:   updTestNode,
		netMode:    hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/var/lib/k3sm/run/netd.sock"},
		updateRoot: root,
	}
	w, err := newNodeUpdater(opts, cs, nodeUpdateDeps{
		fetcher: ff,
		netd:    netd,
		running: version.Info{Version: running, KubeVersion: updTestKube},
		ready:   ready,
	}, slog.New(slog.DiscardHandler))
	if err != nil || w == nil {
		t.Fatalf("newNodeUpdater = %v, %v", w, err)
	}
	if err := w.Sync(context.Background()); err != nil {
		t.Fatalf("Sync = %v", err)
	}
	after, err := cs.CoreV1().Nodes().Get(context.Background(), updTestNode, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	for k, v := range node.Annotations {
		if k == updatesv1alpha1.AnnotationUpdatePhase {
			continue
		}
		if after.Annotations[k] != v {
			t.Errorf("annotation %s = %q after Sync, want it left at %q", k, after.Annotations[k], v)
		}
	}
	return updateRun{cs: cs, fetch: ff, netd: netd, root: root}
}

// extractedFiles lists the regular files under every attempt's set directory.
func extractedFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	sets, _ := filepath.Glob(filepath.Join(root, "attempt-*", "set"))
	for _, s := range sets {
		_ = filepath.WalkDir(s, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

// TestUpdateApplyVerifiesBeforeInstall is the gate for the node half of the
// managed update: the archive's checksum is verified before anything is
// extracted, the set is extracted before the root helper's verb runs, every
// refusal (checksum, symlink, unlisted member, downgrade, host) stops before
// the verb, RequireTeamSignature follows the signature policy, and the phase
// annotation moves in order, ending in Done only on the restarted build.
func TestUpdateApplyVerifiesBeforeInstall(t *testing.T) {
	t.Parallel()
	good := buildUpdArchive(t, releaseEntries())
	goodPayload := update.Payload{URL: updTestURL, SHA256: updSHA256Hex(good), Signature: updatesv1alpha1.UpdateSignatureIfSigned}

	t.Run("a verified set is extracted, then handed to the root helper", func(t *testing.T) {
		t.Parallel()
		r := runUpdateSync(t, handedOverNode(goodPayload, nil), good, updTestRunning, nil)
		if got, want := phaseNames(phasesWritten(t, r.cs)), []string{"Downloading", "Verifying", "Installing", "Restarting"}; !slices.Equal(got, want) {
			t.Fatalf("phases = %v, want %v", got, want)
		}
		if !slices.Equal(r.fetch.urls, []string{updTestURL}) {
			t.Errorf("fetched %v, want exactly %s", r.fetch.urls, updTestURL)
		}
		if len(r.netd.calls) != 1 {
			t.Fatalf("ApplyUpdate called %d times, want 1", len(r.netd.calls))
		}
		args := r.netd.calls[0]
		if args.Version != updTestTag || args.AllowDowngrade || args.RequireTeamSignature {
			t.Errorf("args = %+v, want version %s, no downgrade, no team signature requirement under if-signed", args, updTestTag)
		}
		var names []string
		for rel, sum := range args.Manifest {
			names = append(names, rel)
			if r.netd.onDisk[rel] != sum {
				t.Errorf("manifest %s = %s, the file on disk at the call hashes %s", rel, sum, r.netd.onDisk[rel])
			}
			if want := updSHA256Hex([]byte("bytes of " + rel)); sum != want {
				t.Errorf("manifest %s = %s, want %s", rel, sum, want)
			}
		}
		slices.Sort(names)
		want := update.SetMembers()
		slices.Sort(want)
		if !slices.Equal(names, want) {
			t.Errorf("manifest names %v, want exactly the set %v", names, want)
		}
		if !strings.HasPrefix(args.SourceDir, r.root+"/attempt-") {
			t.Errorf("SourceDir = %s, want a fresh directory under %s", args.SourceDir, r.root)
		}
		for _, skipped := range []string{"LICENSE", "NOTICE", "k3sm-netd"} {
			if _, err := os.Lstat(filepath.Join(args.SourceDir, skipped)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s was written into the set (lstat: %v)", skipped, err)
			}
		}
	})

	t.Run("the restarted daemon on the tag writes Done", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(goodPayload, map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Restarting"})
		r := runUpdateSync(t, node, good, "0.2.0", nil)
		if got := phasesWritten(t, r.cs); !slices.Equal(got, []string{"Done"}) {
			t.Fatalf("phases = %v, want [Done]", got)
		}
		if len(r.fetch.urls) != 0 || len(r.netd.calls) != 0 {
			t.Errorf("the build already on the tag fetched %v and called ApplyUpdate %d times", r.fetch.urls, len(r.netd.calls))
		}
	})

	t.Run("the restarted daemon holds Done until its runtime answers", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(goodPayload, map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Restarting"})
		r := runUpdateSyncReady(t, node, good, "0.2.0", nil, func(context.Context) bool { return false })
		if got := phasesWritten(t, r.cs); len(got) != 0 {
			t.Fatalf("phases = %v, want none before the daemon is fully up", got)
		}
		r = runUpdateSyncReady(t, node, good, "0.2.0", nil, func(context.Context) bool { return true })
		if got := phasesWritten(t, r.cs); !slices.Equal(got, []string{"Done"}) {
			t.Fatalf("phases = %v, want [Done] once it is", got)
		}
	})

	t.Run("a daemon still on the old build after Restarting writes nothing", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(goodPayload, map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Restarting"})
		r := runUpdateSync(t, node, good, updTestRunning, nil)
		if got := phasesWritten(t, r.cs); len(got) != 0 {
			t.Fatalf("phases = %v, want none (the restart is the root helper's)", got)
		}
		if len(r.netd.calls) != 0 {
			t.Errorf("ApplyUpdate called %d times, want 0", len(r.netd.calls))
		}
	})

	t.Run("required signature sets RequireTeamSignature", func(t *testing.T) {
		t.Parallel()
		p := goodPayload
		p.Signature = updatesv1alpha1.UpdateSignatureRequired
		r := runUpdateSync(t, handedOverNode(p, nil), good, updTestRunning, nil)
		if len(r.netd.calls) != 1 || !r.netd.calls[0].RequireTeamSignature {
			t.Fatalf("ApplyUpdate calls = %+v, want one with RequireTeamSignature", r.netd.calls)
		}
	})

	t.Run("an empty signature policy is if-signed", func(t *testing.T) {
		t.Parallel()
		p := goodPayload
		p.Signature = ""
		r := runUpdateSync(t, handedOverNode(p, nil), good, updTestRunning, nil)
		if len(r.netd.calls) != 1 || r.netd.calls[0].RequireTeamSignature {
			t.Fatalf("ApplyUpdate calls = %+v, want one without RequireTeamSignature", r.netd.calls)
		}
	})

	t.Run("a downgrade with allowDowngrade proceeds and passes it on", func(t *testing.T) {
		t.Parallel()
		p := goodPayload
		p.AllowDowngrade = true
		r := runUpdateSync(t, handedOverNode(p, nil), good, "0.3.0", nil)
		if len(r.netd.calls) != 1 || !r.netd.calls[0].AllowDowngrade {
			t.Fatalf("ApplyUpdate calls = %+v, want one with AllowDowngrade", r.netd.calls)
		}
	})

	t.Run("a failed install writes Failed with the message", func(t *testing.T) {
		t.Parallel()
		netd := &fakeNetd{err: errors.New("netd ApplyUpdate failed: the installer failed: exit status 1"),
			result: wire.UpdateResult{Phase: wire.UpdatePhaseFailed, Log: "line one\ninstall: refused\x07 the staged build"}}
		r := runUpdateSync(t, handedOverNode(goodPayload, nil), good, updTestRunning, netd)
		got := phasesWritten(t, r.cs)
		if names := phaseNames(got); !slices.Equal(names, []string{"Downloading", "Verifying", "Installing", "Failed"}) {
			t.Fatalf("phases = %v", names)
		}
		last := got[len(got)-1]
		if !strings.Contains(last, "exit status 1") || !strings.Contains(last, "install: refused the staged build") || strings.ContainsRune(last, '\x07') {
			t.Errorf("Failed value = %q, want the error and the installer's last line, control characters stripped", last)
		}
		if _, msg := update.ParsePhase(last); len(msg) > update.MaxMessageBytes {
			t.Errorf("message is %d bytes, over %d", len(msg), update.MaxMessageBytes)
		}
		if dirs, _ := filepath.Glob(filepath.Join(r.root, "attempt-*")); len(dirs) != 1 {
			t.Errorf("attempt directories after a failure = %v, want the one kept for diagnosis", dirs)
		}
	})

	refusals := []struct {
		name       string
		payload    func(update.Payload) update.Payload
		archive    []byte
		running    string
		wantPhases []string
		wantMsg    string
		wantFetch  bool
	}{
		{name: "checksum mismatch refuses before extracting", wantFetch: true,
			payload:    func(p update.Payload) update.Payload { p.SHA256 = strings.Repeat("0", 64); return p },
			wantPhases: []string{"Downloading", "Verifying", "Failed"}, wantMsg: "sha256"},
		{name: "a symlink in the archive refuses", wantFetch: true,
			archive:    buildUpdArchive(t, append(releaseEntries(), updTarEntry{name: "evil", typeflag: tar.TypeSymlink, link: "/etc/sudoers"})),
			wantPhases: []string{"Downloading", "Verifying", "Failed"}, wantMsg: "is a link"},
		{name: "an unlisted file refuses", wantFetch: true,
			archive:    buildUpdArchive(t, append(releaseEntries(), updTarEntry{name: "cp-payload/extra", typeflag: tar.TypeReg, body: "x"})),
			wantPhases: []string{"Downloading", "Verifying", "Failed"}, wantMsg: "not in the build set"},
		{name: "a parent path refuses", wantFetch: true,
			archive:    buildUpdArchive(t, append(releaseEntries(), updTarEntry{name: "../k3sm", typeflag: tar.TypeReg, body: "x"})),
			wantPhases: []string{"Downloading", "Verifying", "Failed"}, wantMsg: "not a clean relative path"},
		{name: "a downgrade without allowDowngrade refuses", running: "0.3.0",
			wantPhases: []string{"Failed"}, wantMsg: "older than the running"},
		{name: "a host off the pin refuses",
			payload: func(p update.Payload) update.Payload {
				p.URL = "https://example.com/k3sm_0.2.0_darwin_arm64.tar.gz"
				return p
			},
			wantPhases: []string{"Failed"}, wantMsg: "is not one of"},
		{name: "plain http refuses",
			payload: func(p update.Payload) update.Payload {
				p.URL = "http://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
				return p
			},
			wantPhases: []string{"Failed"}, wantMsg: "not https"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			archive := tc.archive
			if archive == nil {
				archive = good
			}
			p := goodPayload
			p.SHA256 = updSHA256Hex(archive)
			if tc.payload != nil {
				p = tc.payload(p)
			}
			running := tc.running
			if running == "" {
				running = updTestRunning
			}
			r := runUpdateSync(t, handedOverNode(p, nil), archive, running, nil)
			got := phasesWritten(t, r.cs)
			if names := phaseNames(got); !slices.Equal(names, tc.wantPhases) {
				t.Fatalf("phases = %v, want %v", names, tc.wantPhases)
			}
			if last := got[len(got)-1]; !strings.Contains(last, tc.wantMsg) {
				t.Errorf("Failed value = %q, want it to say %q", last, tc.wantMsg)
			}
			if len(r.netd.calls) != 0 {
				t.Errorf("ApplyUpdate was called after a refusal: %+v", r.netd.calls)
			}
			if fetched := len(r.fetch.urls) > 0; fetched != tc.wantFetch {
				t.Errorf("fetched = %v, want %v", fetched, tc.wantFetch)
			}
			if tc.name == "checksum mismatch refuses before extracting" {
				if files := extractedFiles(t, r.root); len(files) != 0 {
					t.Errorf("files were extracted from an archive whose checksum failed: %v", files)
				}
			}
		})
	}
}
