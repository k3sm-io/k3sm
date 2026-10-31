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

package updatectl

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/update"
)

// risingKubeMinor is a manifest kube minor above the one oldKubelet runs.
const risingKubeMinor = "1.35"

// failedReason is the reason on the Update's Failed condition, or "".
func failedReason(u *updatesv1alpha1.Update) string {
	if c := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed); c != nil && c.Status == "True" {
		return c.Reason
	}
	return ""
}

// releaseArchive is a gzip tar holding one data member, and the manifest
// that describes it.
func releaseArchive(t *testing.T) (archive []byte, sum string, manifest []byte) {
	t.Helper()
	body := []byte("Apache License 2.0\n")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "LICENSE", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	hex256 := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	sum = hex256(buf.Bytes())
	manifest = testManifest(target, rigKubeMinor, rigCompatibleFrom, sum,
		[]certs.PayloadMember{{Path: "LICENSE", SHA256: hex256(body), Kind: certs.PayloadData}})
	return buf.Bytes(), sum, manifest
}

// TestOrderServerFirstOnKubeMinorRise is the rolling order, the
// compatibility window, the resume on the controller's own server, the halt
// at a node that rolled back, refused or lost its data root, and the signed
// manifest a node is handed.
func TestOrderServerFirstOnKubeMinorRise(t *testing.T) {
	workersFirst := []string{
		"cordon w1", "handover w1", "uncordon w1",
		"cordon w2", "handover w2", "uncordon w2",
		"cordon srv", "handover srv", "uncordon srv",
	}
	serverFirst := []string{
		"cordon srv", "handover srv", "uncordon srv",
		"cordon w1", "handover w1", "uncordon w1",
		"cordon w2", "handover w2", "uncordon w2",
	}
	for _, tc := range []struct {
		name  string
		setup func(r *rig)
		// run drives the roll; nil means one controller to the end.
		run   func(t *testing.T, r *rig)
		check func(t *testing.T, r *rig, u *updatesv1alpha1.Update)
	}{
		{
			name: "workers first when kubeMinor holds",
			check: func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
				if got := r.log(); !reflect.DeepEqual(got, workersFirst) {
					t.Fatalf("node actions:\n got %v\nwant %v", got, workersFirst)
				}
				if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
					t.Fatalf("phase %q", u.Status.Phase)
				}
			},
		},
		{
			name: "server first when kubeMinor rises",
			setup: func(r *rig) {
				r.resolver.manifest = testManifest(target, risingKubeMinor, rigCompatibleFrom, targetSum, nil)
			},
			check: func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
				if got := r.log(); !reflect.DeepEqual(got, serverFirst) {
					t.Fatalf("node actions:\n got %v\nwant %v", got, serverFirst)
				}
				var names []string
				for _, e := range u.Status.Nodes {
					names = append(names, e.Name)
				}
				if !reflect.DeepEqual(names, []string{serverName, "w1", "w2"}) {
					t.Fatalf("status order %v", names)
				}
				if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
					t.Fatalf("phase %q", u.Status.Phase)
				}
			},
		},
		{
			name: "OutsideCompatibilityWindow before any cordon",
			setup: func(r *rig) {
				r.resolver.manifest = testManifest(target, rigKubeMinor, "v0.1.5", targetSum, nil)
			},
			check: func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
				if got := r.log(); len(got) != 0 {
					t.Fatalf("a node was touched outside the window: %v", got)
				}
				if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || failedReason(u) != ReasonOutsideCompatibilityWindow {
					t.Fatalf("phase %q reason %q, want Failed %s", u.Status.Phase, failedReason(u), ReasonOutsideCompatibilityWindow)
				}
				c := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
				if !strings.Contains(c.Message, "w1 runs v0.1.0") || !strings.Contains(c.Message, "v0.1.5") {
					t.Fatalf("the refusal does not name the node and the window: %q", c.Message)
				}
				for _, n := range []string{"w1", "w2", serverName} {
					if nd := r.node(n); nd.Spec.Unschedulable || nd.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != "" {
						t.Errorf("node %s was cordoned or handed over", n)
					}
				}
			},
		},
		{
			name: "resume after the controller's own server restarts",
			setup: func(r *rig) {
				r.resolver.manifest = testManifest(target, risingKubeMinor, rigCompatibleFrom, targetSum, nil)
			},
			run: func(t *testing.T, r *rig) {
				// The first controller hands its own server over, then stops
				// with it: the install restarts the server on the target.
				r.drive(r.controller(), func() bool {
					return phases(r.update(updatesv1alpha1.UpdateName))[serverName] == updatesv1alpha1.UpdateNodePhaseDownloading
				})
				if got := r.log(); !reflect.DeepEqual(got, []string{"cordon srv", "handover srv"}) {
					t.Fatalf("before the restart: %v", got)
				}
				r.nodeSide()
				r.now = r.now.Add(r.step)
				// A new controller, with no signer and no manifest in memory,
				// resumes from the persisted status.
				r.drive(r.controller(), nil)
			},
			check: func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
				if got := r.log(); !reflect.DeepEqual(got, serverFirst) {
					t.Fatalf("node actions:\n got %v\nwant %v", got, serverFirst)
				}
				if u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
					t.Fatalf("phase %q", u.Status.Phase)
				}
				if r.resolver.calls != 1 {
					t.Fatalf("resolved %d times across the restart, want once", r.resolver.calls)
				}
				if r.resolver.manifestCalls != 2 {
					t.Fatalf("read the manifest %d times, want once per controller", r.resolver.manifestCalls)
				}
				ann := r.node("w2").Annotations
				if _, err := update.VerifySignedPayload(update.CAPool(testSigning().ca.CertPEM), []byte(ann[update.AnnotationUpdatePayload]),
					ann[update.AnnotationUpdatePayloadSig], ann[update.AnnotationUpdateSigner], r.now); err != nil {
					t.Fatalf("the payload handed over after the restart does not verify: %v", err)
				}
			},
		},
		{
			name:  "halt on rolled-back",
			setup: func(r *rig) { r.reportNodes["w1"] = "Restarting: rolled-back: the health deadline passed" },
			check: haltCheck("w1", ReasonNodeRolledBack, []string{"cordon w1", "handover w1"}, "rolled-back: the health deadline passed"),
		},
		{
			name:  "halt on refused",
			setup: func(r *rig) { r.reportNodes["w1"] = "Verifying: refused: the payload digest does not match" },
			check: haltCheck("w1", ReasonNodeRefused, []string{"cordon w1", "handover w1"}, "refused: the payload digest does not match"),
		},
		{
			name:  "halt on data-root-unmounted",
			setup: func(r *rig) { r.reportNodes["w2"] = "Failed: data-root-unmounted" },
			check: haltCheck("w2", ReasonDataRootUnmounted,
				[]string{"cordon w1", "handover w1", "uncordon w1", "cordon w2", "handover w2"}, dataRootRemedy),
		},
		{
			name: "the manifest annotation signed by the same signer as the payload",
			check: func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
				// The rig serves a real archive and its manifest (set below);
				// the node's verifier accepts what was handed over.
				ann := r.node("w1").Annotations
				signed, err := update.VerifySignedPayload(update.CAPool(testSigning().ca.CertPEM), []byte(ann[update.AnnotationUpdatePayload]),
					ann[update.AnnotationUpdatePayloadSig], ann[update.AnnotationUpdateSigner], r.now)
				if err != nil {
					t.Fatalf("the payload does not verify: %v", err)
				}
				sig, err := base64.StdEncoding.DecodeString(ann[update.AnnotationUpdateManifestSig])
				if err != nil {
					t.Fatalf("the manifest signature is not base64: %v", err)
				}
				dst := filepath.Join(t.TempDir(), "stage", "release.partial")
				if err := os.MkdirAll(dst, 0o700); err != nil {
					t.Fatal(err)
				}
				m, err := certs.VerifySignedPayload(context.Background(), certs.SignedPayload{
					ClusterCAPEM:  testSigning().ca.CertPEM,
					SignerCertPEM: signed.SignerPEM,
					Manifest:      []byte(ann[update.AnnotationUpdateManifest]),
					Signature:     sig,
					Now:           r.now,
				}, bytes.NewReader(r.archive), dst)
				if err != nil {
					t.Fatalf("the handed-over manifest does not verify under the payload's signer: %v", err)
				}
				if m.ArchiveSHA256 != signed.Payload.SHA256 || m.Version != target {
					t.Fatalf("manifest %+v does not describe payload %+v", m, signed.Payload)
				}
				// Another signer from the same CA does not stand in.
				other, err := testSigning().ca.IssueUpdateSigner()
				if err != nil {
					t.Fatal(err)
				}
				dst2 := filepath.Join(t.TempDir(), "stage", "release.partial")
				if err := os.MkdirAll(dst2, 0o700); err != nil {
					t.Fatal(err)
				}
				if _, err := certs.VerifySignedPayload(context.Background(), certs.SignedPayload{
					ClusterCAPEM: testSigning().ca.CertPEM, SignerCertPEM: other.CertPEM,
					Manifest: []byte(ann[update.AnnotationUpdateManifest]), Signature: sig, Now: r.now,
				}, bytes.NewReader(r.archive), dst2); !errors.Is(err, certs.ErrPayloadSignature) {
					t.Fatalf("another signer's certificate verified the manifest: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, threeNodes()...)
			if strings.HasPrefix(tc.name, "the manifest annotation") {
				r.archive, r.resolver.sha, r.resolver.manifest = releaseArchive(t)
			}
			if tc.setup != nil {
				tc.setup(r)
			}
			r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
			if tc.run != nil {
				tc.run(t, r)
			} else {
				r.drive(r.controller(), nil)
			}
			tc.check(t, r, r.update(updatesv1alpha1.UpdateName))
		})
	}
}

// haltCheck asserts the roll stopped Failed with reason at node, which stays
// cordoned with a message containing msg, after exactly the actions want,
// and that every later node is still Pending.
func haltCheck(node, reason string, want []string, msg string) func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
	return func(t *testing.T, r *rig, u *updatesv1alpha1.Update) {
		if got := r.log(); !reflect.DeepEqual(got, want) {
			t.Fatalf("node actions:\n got %v\nwant %v", got, want)
		}
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || failedReason(u) != reason {
			t.Fatalf("phase %q reason %q, want Failed %s", u.Status.Phase, failedReason(u), reason)
		}
		after := false
		for _, e := range u.Status.Nodes {
			switch {
			case e.Name == node:
				after = true
				if e.Phase != updatesv1alpha1.UpdateNodePhaseFailed || !strings.Contains(e.Message, msg) {
					t.Fatalf("%s entry %+v", node, e)
				}
			case after && e.Phase != updatesv1alpha1.UpdateNodePhasePending:
				t.Errorf("node %s after the halt is %s, want Pending", e.Name, e.Phase)
			}
		}
		if !r.node(node).Spec.Unschedulable {
			t.Errorf("the halted node %s was uncordoned", node)
		}
	}
}

// TestHTTPResolverManifest pins the manifest asset's name, its bound and the
// definitive refusals.
func TestHTTPResolverManifest(t *testing.T) {
	if got, err := ManifestAssetName("v0.3.0"); err != nil || got != "k3sm_0.3.0_darwin_arm64.manifest.json" {
		t.Fatalf("asset name %q, %v", got, err)
	}
	body := testManifest("v0.3.0", "1.35", "v0.2.0", targetSum, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/download/v0.3.0/k3sm_0.3.0_darwin_arm64.manifest.json":
			_, _ = w.Write(body)
		case "/download/v0.4.0/k3sm_0.4.0_darwin_arm64.manifest.json":
			_, _ = w.Write(bytes.Repeat([]byte(" "), certs.MaxPayloadManifestBytes+1))
		case "/download/v0.5.0/k3sm_0.5.0_darwin_arm64.manifest.json":
			w.WriteHeader(http.StatusBadGateway)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()
	r := HTTPResolver{Base: srv.URL}
	for _, tc := range []struct {
		tag       string
		want      []byte
		definite  bool
		transient bool
	}{
		{tag: "v0.3.0", want: body},
		{tag: "v0.4.0", definite: true},
		{tag: "v0.6.0", definite: true},
		{tag: "v0.5.0", transient: true},
		{tag: "-bad", definite: true},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			got, err := r.Manifest(context.Background(), tc.tag)
			switch {
			case tc.want != nil:
				if err != nil || !bytes.Equal(got, tc.want) {
					t.Fatalf("manifest %q, %v", got, err)
				}
			case tc.definite:
				if !errors.Is(err, ErrRelease) {
					t.Fatalf("err %v, want ErrRelease", err)
				}
			case tc.transient:
				if err == nil || errors.Is(err, ErrRelease) {
					t.Fatalf("err %v, want a transient error", err)
				}
			}
		})
	}
}

// TestManifestMismatchStopsBeforeAnyCordon pins that a manifest that does not
// describe the resolved release, or cannot be read, ends the roll untouched.
func TestManifestMismatchStopsBeforeAnyCordon(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest []byte
		err      error
	}{
		{"another archive digest", testManifest(target, rigKubeMinor, rigCompatibleFrom, strings.Repeat("f", 64), nil), nil},
		{"another version", testManifest("v0.3.0", rigKubeMinor, rigCompatibleFrom, targetSum, nil), nil},
		{"a kubeMinor that is not MAJOR.MINOR", testManifest(target, "one", rigCompatibleFrom, targetSum, nil), nil},
		{"an unknown key", append([]byte(`{"extra":true,`), testManifest(target, rigKubeMinor, rigCompatibleFrom, targetSum, nil)[1:]...), nil},
		{"invalid UTF-8", bytes.Replace(testManifest(target, rigKubeMinor, rigCompatibleFrom, targetSum, nil), []byte("LICENSE"), []byte("LIC\xffNSE"), 1), nil},
		{"no manifest published", nil, ErrRelease},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, threeNodes()...)
			r.resolver.manifest = tc.manifest
			r.resolver.manifestErr = tc.err
			r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
			r.drive(r.controller(), nil)
			u := r.update(updatesv1alpha1.UpdateName)
			if got := r.log(); len(got) != 0 {
				t.Fatalf("a node was touched: %v", got)
			}
			if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || failedReason(u) != ReasonManifestMismatch {
				t.Fatalf("phase %q reason %q", u.Status.Phase, failedReason(u))
			}
		})
	}
}

// TestKubeMinor pins the minor parse and the rise decision.
func TestKubeMinor(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want kubeMinor
		ok   bool
	}{
		{"1.35", kubeMinor{1, 35}, true},
		{"v1.35", kubeMinor{1, 35}, true},
		{"v1.34.1+k3sm.0.2.0", kubeMinor{1, 34}, true},
		{"v1.34.1-rc.1", kubeMinor{1, 34}, true},
		{"1", kubeMinor{}, false},
		{"1.x", kubeMinor{}, false},
		{"", kubeMinor{}, false},
	} {
		got, ok := parseKubeMinor(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseKubeMinor(%q) = %v %v, want %v %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	m := &certs.PayloadManifest{KubeMinor: "1.35"}
	if kubeMinorRises(m, []*corev1.Node{node("a", "v1.35.0+k3sm.0.2.0", false)}) {
		t.Error("a node on the target minor was counted as a rise")
	}
	if !kubeMinorRises(m, []*corev1.Node{node("a", "v1.35.0+k3sm.0.2.0", false), node("b", "v1.34.2+k3sm.0.1.0", false)}) {
		t.Error("an older node minor was not counted as a rise")
	}
	if !kubeMinorRises(m, []*corev1.Node{node("a", "unknown", false)}) {
		t.Error("an unreadable node minor did not put the server first")
	}
}
