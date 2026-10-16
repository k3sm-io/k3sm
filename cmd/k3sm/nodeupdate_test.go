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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/certs"
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

// updTestArchive stands for the release archive: the node no longer opens
// it (the root helper extracts it), so its bytes are only hashed and handed on.
var updTestArchive = []byte("a release archive the node downloads and never opens")

// updSigning is the cluster CA the test node pins and the update signer it
// issued, as the server mints it.
var updSigning = sync.OnceValue(func() struct {
	ca     *certs.CA
	signer *certs.UpdateSigner
} {
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		panic(err)
	}
	s, err := ca.IssueUpdateSigner()
	if err != nil {
		panic(err)
	}
	return struct {
		ca     *certs.CA
		signer *certs.UpdateSigner
	}{ca, s}
})

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
// re-reads the archive it names, so an archive that was not fully downloaded
// before the verb ran is caught. It streams Verifying, Installing and then
// Restarting, as the real client does when the installer restarts the helper.
type fakeNetd struct {
	t       *testing.T
	calls   []wire.ApplyUpdateArgs
	archive []byte
	result  wire.UpdateResult
	err     error
}

func (n *fakeNetd) ApplyUpdate(_ context.Context, args wire.ApplyUpdateArgs, progress func(wire.UpdatePhase)) (wire.UpdateResult, error) {
	n.calls = append(n.calls, args)
	b, err := os.ReadFile(args.ArchivePath)
	if err != nil {
		n.t.Errorf("ApplyUpdate ran before the archive was downloaded: %v", err)
	}
	n.archive = b
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

// signedAnnotations is the controller's handover of p: the canonical payload,
// its signature by signer and the signer certificate.
func signedAnnotations(t *testing.T, p update.Payload, signer *certs.UpdateSigner) map[string]string {
	t.Helper()
	raw, err := update.EncodePayload(p)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := update.SignPayload(signer, raw)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		update.AnnotationUpdatePayload:    string(raw),
		update.AnnotationUpdatePayloadSig: sig,
		update.AnnotationUpdateSigner:     string(signer.CertPEM),
	}
}

// handedOverNode is the Node the controller hands p to, signed by the
// cluster's update signer, with extra annotations on top (a node rewriting
// its own annotations is an extra).
func handedOverNode(t *testing.T, p update.Payload, extra map[string]string) *corev1.Node {
	t.Helper()
	ann := map[string]string{updatesv1alpha1.AnnotationUpdateVersion: updTestTag}
	for k, v := range signedAnnotations(t, p, updSigning().signer) {
		ann[k] = v
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

// updateCase is one watcher run: the node, the archive served, the running
// build, and the seams that vary.
type updateCase struct {
	node     *corev1.Node
	archive  []byte
	running  string
	netd     *fakeNetd
	ready    func(context.Context) bool
	base     string
	pinnedCA []byte
}

func runNodeUpdate(t *testing.T, c updateCase) updateRun {
	t.Helper()
	if c.archive == nil {
		c.archive = updTestArchive
	}
	if c.running == "" {
		c.running = updTestRunning
	}
	if c.netd == nil {
		c.netd = &fakeNetd{}
	}
	if c.pinnedCA == nil {
		c.pinnedCA = updSigning().ca.CertPEM
	}
	c.netd.t = t
	cs := fake.NewClientset(c.node)
	ff := &fakeFetcher{archive: c.archive}
	root := filepath.Join(t.TempDir(), "updates")
	opts := nodeOptions{
		nodeName:           updTestNode,
		netMode:            hostnet.Mode{Backend: hostnet.BackendHelper, Socket: "/var/lib/k3sm/run/netd.sock"},
		updateRoot:         root,
		updateClusterCAPEM: c.pinnedCA,
	}
	w, err := newNodeUpdater(opts, cs, nodeUpdateDeps{
		fetcher:     ff,
		netd:        c.netd,
		running:     version.Info{Version: c.running, KubeVersion: updTestKube},
		ready:       c.ready,
		releaseBase: mustReleaseBase(t, c.base),
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
	for k, v := range c.node.Annotations {
		if k != updatesv1alpha1.AnnotationUpdatePhase && after.Annotations[k] != v {
			t.Errorf("annotation %s = %q after Sync, want it left at %q", k, after.Annotations[k], v)
		}
	}
	return updateRun{cs: cs, fetch: ff, netd: c.netd, root: root}
}

func mustReleaseBase(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := releaseBase(raw)
	if err != nil {
		t.Fatalf("releaseBase(%q) = %v", raw, err)
	}
	return u
}

// TestUpdateApplyVerifiesBeforeInstall is the gate for the node half of the
// managed update: the payload's signature by the cluster's update signer is
// verified before anything else (an unsigned, node-forged or foreign-signed
// payload is never even downloaded), the archive is downloaded and its
// checksum checked before the root helper's verb runs, the verb receives
// exactly the signed bytes, every refusal (signature, version, host,
// downgrade, checksum) stops before the verb, and the phase annotation moves
// in order, ending in Done only on the restarted build.
func TestUpdateApplyVerifiesBeforeInstall(t *testing.T) {
	t.Parallel()
	good := update.Payload{Version: updTestTag, URL: updTestURL, SHA256: updSHA256Hex(updTestArchive), Signature: updatesv1alpha1.UpdateSignatureIfSigned}

	t.Run("a signed payload is downloaded, checked, then handed to the root helper", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(t, good, nil)
		r := runNodeUpdate(t, updateCase{node: node})
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
		ann := node.Annotations
		if string(args.Payload) != ann[update.AnnotationUpdatePayload] || string(args.SignerCert) != ann[update.AnnotationUpdateSigner] {
			t.Errorf("the verb did not receive the exact signed payload and signer")
		}
		if sig, _ := base64.StdEncoding.DecodeString(ann[update.AnnotationUpdatePayloadSig]); !bytes.Equal(args.Signature, sig) {
			t.Errorf("Signature is not the DER of the annotation")
		}
		if !bytes.Equal(r.netd.archive, updTestArchive) {
			t.Errorf("the archive the verb names holds %q", r.netd.archive)
		}
		if !strings.HasPrefix(args.ArchivePath, r.root+"/attempt-") {
			t.Errorf("ArchivePath = %s, want a fresh directory under %s", args.ArchivePath, r.root)
		}
		if _, err := update.VerifySignedPayload(update.CAPool(updSigning().ca.CertPEM), args.Payload, base64.StdEncoding.EncodeToString(args.Signature), string(args.SignerCert), time.Now()); err != nil {
			t.Errorf("the verb's arguments do not verify as the root helper checks them: %v", err)
		}
	})

	t.Run("the restarted daemon on the tag writes Done", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(t, good, map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Restarting"})
		r := runNodeUpdate(t, updateCase{node: node, running: "0.2.0"})
		if got := phasesWritten(t, r.cs); !slices.Equal(got, []string{"Done"}) {
			t.Fatalf("phases = %v, want [Done]", got)
		}
		if len(r.fetch.urls) != 0 || len(r.netd.calls) != 0 {
			t.Errorf("the build already on the tag fetched %v and called ApplyUpdate %d times", r.fetch.urls, len(r.netd.calls))
		}
	})

	t.Run("the restarted daemon holds Done until its runtime answers", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(t, good, map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Restarting"})
		r := runNodeUpdate(t, updateCase{node: node, running: "0.2.0", ready: func(context.Context) bool { return false }})
		if got := phasesWritten(t, r.cs); len(got) != 0 {
			t.Fatalf("phases = %v, want none before the daemon is fully up", got)
		}
		r = runNodeUpdate(t, updateCase{node: node, running: "0.2.0", ready: func(context.Context) bool { return true }})
		if got := phasesWritten(t, r.cs); !slices.Equal(got, []string{"Done"}) {
			t.Fatalf("phases = %v, want [Done] once it is", got)
		}
	})

	t.Run("a daemon still on the old build after Restarting writes nothing", func(t *testing.T) {
		t.Parallel()
		node := handedOverNode(t, good, map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Restarting"})
		r := runNodeUpdate(t, updateCase{node: node})
		if got := phasesWritten(t, r.cs); len(got) != 0 {
			t.Fatalf("phases = %v, want none (the restart is the root helper's)", got)
		}
		if len(r.netd.calls) != 0 {
			t.Errorf("ApplyUpdate called %d times, want 0", len(r.netd.calls))
		}
	})

	t.Run("a downgrade with allowDowngrade proceeds", func(t *testing.T) {
		t.Parallel()
		p := good
		p.AllowDowngrade = true
		r := runNodeUpdate(t, updateCase{node: handedOverNode(t, p, nil), running: "0.3.0"})
		if len(r.netd.calls) != 1 {
			t.Fatalf("ApplyUpdate calls = %d, want 1", len(r.netd.calls))
		}
	})

	t.Run("a failed install writes Failed with the message", func(t *testing.T) {
		t.Parallel()
		netd := &fakeNetd{err: errors.New("netd ApplyUpdate failed: the installer failed: exit status 1"),
			result: wire.UpdateResult{Phase: wire.UpdatePhaseFailed, Log: "line one\ninstall: refused\x07 the staged build"}}
		r := runNodeUpdate(t, updateCase{node: handedOverNode(t, good, nil), netd: netd})
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

	t.Run("a recorded release base admits its host and nothing more", func(t *testing.T) {
		t.Parallel()
		const base = "http://192.168.0.50:8080/releases"
		p := good
		p.URL = base + "/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
		r := runNodeUpdate(t, updateCase{node: handedOverNode(t, p, nil), base: base})
		if len(r.netd.calls) != 1 || !slices.Equal(r.fetch.urls, []string{p.URL}) {
			t.Fatalf("lab base: fetched %v, ApplyUpdate calls %d; want the archive fetched and installed", r.fetch.urls, len(r.netd.calls))
		}
		p.URL = "https://example.com/k3sm_0.2.0_darwin_arm64.tar.gz"
		r = runNodeUpdate(t, updateCase{node: handedOverNode(t, p, nil), base: base})
		if got := phaseNames(phasesWritten(t, r.cs)); !slices.Equal(got, []string{"Failed"}) || len(r.fetch.urls) != 0 {
			t.Fatalf("foreign host beside a recorded base: phases %v, fetched %v; want Failed and no fetch", got, r.fetch.urls)
		}
		p.URL = base + "/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
		r = runNodeUpdate(t, updateCase{node: handedOverNode(t, p, nil)})
		if got := phaseNames(phasesWritten(t, r.cs)); !slices.Equal(got, []string{"Failed"}) || len(r.fetch.urls) != 0 {
			t.Fatalf("lab host with no recorded base: phases %v, fetched %v; want Failed and no fetch", got, r.fetch.urls)
		}
	})

	other, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	foreignSigner, err := other.IssueUpdateSigner()
	if err != nil {
		t.Fatal(err)
	}
	forged := good
	forged.SHA256 = updSHA256Hex([]byte("an attacker's archive"))
	forgedRaw, err := update.EncodePayload(forged)
	if err != nil {
		t.Fatal(err)
	}
	refusals := []struct {
		name       string
		node       *corev1.Node
		archive    []byte
		running    string
		wantPhases []string
		wantMsg    string
		wantFetch  bool
	}{
		{name: "an unsigned payload is refused before any download",
			node:       handedOverNode(t, good, map[string]string{update.AnnotationUpdatePayloadSig: "", update.AnnotationUpdateSigner: ""}),
			wantPhases: []string{"Failed"}, wantMsg: "not signed"},
		{name: "a payload the node rewrote under the server's signature is refused",
			node:       handedOverNode(t, good, map[string]string{update.AnnotationUpdatePayload: string(forgedRaw)}),
			wantPhases: []string{"Failed"}, wantMsg: "does not verify"},
		{name: "a payload signed by a foreign CA's signer is refused",
			node: func() *corev1.Node {
				n := handedOverNode(t, good, nil)
				for k, v := range signedAnnotations(t, forged, foreignSigner) {
					n.Annotations[k] = v
				}
				return n
			}(),
			wantPhases: []string{"Failed"}, wantMsg: "does not chain to the cluster CA"},
		{name: "a signed payload for another tag is refused",
			node: func() *corev1.Node {
				p := good
				p.Version = "v0.3.0"
				return handedOverNode(t, p, nil)
			}(),
			wantPhases: []string{"Failed"}, wantMsg: "the Node asks for"},
		{name: "a checksum mismatch is refused before the root helper", wantFetch: true,
			archive:    []byte("not the archive the payload names"),
			node:       handedOverNode(t, good, nil),
			wantPhases: []string{"Downloading", "Verifying", "Failed"}, wantMsg: "sha256"},
		{name: "a downgrade without allowDowngrade is refused", running: "0.3.0",
			node:       handedOverNode(t, good, nil),
			wantPhases: []string{"Failed"}, wantMsg: "older than the running"},
		{name: "a host off the pin is refused",
			node: func() *corev1.Node {
				p := good
				p.URL = "https://example.com/k3sm_0.2.0_darwin_arm64.tar.gz"
				return handedOverNode(t, p, nil)
			}(),
			wantPhases: []string{"Failed"}, wantMsg: "is not one of"},
		{name: "plain http is refused",
			node: func() *corev1.Node {
				p := good
				p.URL = "http://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
				return handedOverNode(t, p, nil)
			}(),
			wantPhases: []string{"Failed"}, wantMsg: "not https"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := runNodeUpdate(t, updateCase{node: tc.node, archive: tc.archive, running: tc.running})
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
		})
	}

	t.Run("a node pinning another cluster's CA refuses this cluster's signer", func(t *testing.T) {
		t.Parallel()
		r := runNodeUpdate(t, updateCase{node: handedOverNode(t, good, nil), pinnedCA: other.CertPEM})
		if got := phaseNames(phasesWritten(t, r.cs)); !slices.Equal(got, []string{"Failed"}) || len(r.fetch.urls) != 0 || len(r.netd.calls) != 0 {
			t.Fatalf("phases %v, fetched %v, calls %d; want Failed before any download", got, r.fetch.urls, len(r.netd.calls))
		}
	})
}
