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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/update"
)

// manifestPinWorkDir is a work dir with a pin for target, the rig's archive
// digest and manifestSum.
func manifestPinWorkDir(t *testing.T, manifestSum string) string {
	t.Helper()
	wd := t.TempDir()
	pin := ReleasePin{Version: target, SHA256: targetSum, ManifestSHA256: manifestSum, At: rigStart}
	if err := writeReleasePin(wd, pin, testOwner()); err != nil {
		t.Fatal(err)
	}
	return wd
}

// TestReleasePinBindsTheManifest pins the manifest digest a release pin may
// carry: absent, the manifest passes through (the archive-only scope every
// earlier pin has); present, the manifest bytes must hash to it, and a
// different manifest fails the roll with ReleasePinMismatch before any node
// is cordoned.
func TestReleasePinBindsTheManifest(t *testing.T) {
	ctx := context.Background()
	served := testManifest(target, rigKubeMinor, rigCompatibleFrom, targetSum, nil)
	t.Run("resolver", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			pin     *ReleasePin
			inner   error
			wantErr error
		}{
			{name: "no pin passes the manifest through"},
			{name: "an archive-only pin passes the manifest through", pin: &ReleasePin{Version: target, SHA256: targetSum}},
			{name: "a manifest pin for another version is ignored", pin: &ReleasePin{Version: "v0.1.9", SHA256: targetSum, ManifestSHA256: otherSum}},
			{name: "a matching manifest pin", pin: &ReleasePin{Version: target, SHA256: targetSum, ManifestSHA256: sha256Hex(served)}},
			{name: "a mismatching manifest pin", pin: &ReleasePin{Version: target, SHA256: targetSum, ManifestSHA256: otherSum}, wantErr: ErrReleasePinMismatch},
			{name: "no manifest published under a manifest pin", pin: &ReleasePin{Version: target, SHA256: targetSum, ManifestSHA256: sha256Hex(served)},
				inner: fmt.Errorf("%w: no manifest", ErrRelease), wantErr: ErrReleasePinMismatch},
			{name: "a transient read under a manifest pin is retried", pin: &ReleasePin{Version: target, SHA256: targetSum, ManifestSHA256: sha256Hex(served)},
				inner: errors.New("connection refused")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wd := t.TempDir()
				if tc.pin != nil {
					pin := *tc.pin
					pin.At = rigStart
					if err := writeReleasePin(wd, pin, testOwner()); err != nil {
						t.Fatal(err)
					}
				}
				got, err := pinned(&fakeResolver{manifest: served, manifestErr: tc.inner}, wd).Manifest(ctx, target)
				switch {
				case tc.wantErr != nil:
					if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrRelease) {
						t.Fatalf("err = %v, want %v wrapping ErrRelease", err, tc.wantErr)
					}
				case tc.inner != nil:
					if err == nil || errors.Is(err, ErrRelease) {
						t.Fatalf("err = %v, want the transient error unchanged", err)
					}
				case err != nil:
					t.Fatalf("manifest: %v", err)
				case !bytes.Equal(got, served):
					t.Fatalf("manifest %s, want the served bytes", got)
				}
			})
		}
	})

	t.Run("an untrusted pin refuses the manifest read", func(t *testing.T) {
		wd := pinWorkDir(t, target, targetSum)
		chmod(t, ReleasePinPath(wd), 0o664)
		if _, err := pinned(&fakeResolver{}, wd).Manifest(ctx, target); !errors.Is(err, ErrReleasePinMismatch) {
			t.Fatalf("err = %v, want ErrReleasePinMismatch", err)
		}
	})

	t.Run("a pin file without the field reads as archive-only", func(t *testing.T) {
		wd := pinWorkDir(t, target, targetSum)
		write(t, ReleasePinPath(wd), `{"version":"v0.2.0","sha256":"`+targetSum+`","at":"2026-10-18T00:00:00Z"}`)
		pin, err := readReleasePin(wd, testOwner())
		if err != nil || pin == nil || pin.ManifestSHA256 != "" {
			t.Fatalf("pin %+v, %v", pin, err)
		}
	})

	t.Run("the writer round-trips the field and omits it when empty", func(t *testing.T) {
		wd := manifestPinWorkDir(t, sha256Hex(served))
		pin, err := readReleasePin(wd, testOwner())
		if err != nil || pin == nil || pin.ManifestSHA256 != sha256Hex(served) {
			t.Fatalf("pin %+v, %v", pin, err)
		}
		b, err := json.Marshal(ReleasePin{Version: target, SHA256: targetSum})
		if err != nil || strings.Contains(string(b), "manifest") {
			t.Fatalf("an archive-only pin encodes %s, %v", b, err)
		}
	})

	t.Run("a malformed manifest digest is refused", func(t *testing.T) {
		if err := (ReleasePin{Version: target, SHA256: targetSum, ManifestSHA256: "ABC"}).Validate(); err == nil {
			t.Fatal("a malformed manifest digest validated")
		}
		wd := pinWorkDir(t, target, targetSum)
		write(t, ReleasePinPath(wd), `{"version":"v0.2.0","sha256":"`+targetSum+`","at":"2026-10-18T00:00:00Z","manifestSHA256":"ABC"}`)
		if _, err := pinned(&fakeResolver{}, wd).Manifest(ctx, target); !errors.Is(err, ErrReleasePinMismatch) {
			t.Fatalf("err = %v, want ErrReleasePinMismatch", err)
		}
	})

	t.Run("a mismatch fails the Update before any node is cordoned", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.resolver.manifest = served
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(pinnedController(r, manifestPinWorkDir(t, otherSum)), nil)
		u := r.update(updatesv1alpha1.UpdateName)
		failed := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || failed == nil || failed.Reason != ReasonReleasePinMismatch ||
			!strings.Contains(failed.Message, otherSum) || !strings.Contains(failed.Message, sha256Hex(served)) {
			t.Fatalf("phase %q, Failed %+v", u.Status.Phase, failed)
		}
		if got := r.log(); len(got) != 0 {
			t.Fatalf("a node was touched: %v", got)
		}
	})

	t.Run("a match rolls and hands over the pinned bytes", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.resolver.manifest = served
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(pinnedController(r, manifestPinWorkDir(t, sha256Hex(served))), nil)
		if u := r.update(updatesv1alpha1.UpdateName); u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q", u.Status.Phase)
		}
		for _, n := range []string{"w1", "w2", serverName} {
			if got := r.node(n).Annotations[update.AnnotationUpdateManifest]; got != string(served) {
				t.Fatalf("node %s was handed %s", n, got)
			}
		}
	})
}

// TestRateLimitedForbiddenIsTransient pins the classification of a 403: one
// with GitHub's rate-limit signals is retried, any other is definitive, for
// both the checksums file and the manifest.
func TestRateLimitedForbiddenIsTransient(t *testing.T) {
	for _, tc := range []struct {
		name      string
		header    map[string]string
		transient bool
	}{
		{name: "no requests left", header: map[string]string{"X-RateLimit-Remaining": "0"}, transient: true},
		{name: "a secondary limit", header: map[string]string{"Retry-After": "60"}, transient: true},
		{name: "requests left", header: map[string]string{"X-RateLimit-Remaining": "12"}},
		{name: "a plain refusal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusForbidden)
			}))
			defer srv.Close()
			r := HTTPResolver{Base: srv.URL}
			_, rerr := r.Resolve(context.Background(), target)
			_, merr := r.Manifest(context.Background(), target)
			for what, err := range map[string]error{"resolve": rerr, "manifest": merr} {
				if err == nil {
					t.Fatalf("%s: a 403 succeeded", what)
				}
				if definitive := errors.Is(err, ErrRelease); definitive == tc.transient {
					t.Fatalf("%s: err = %v, transient %v", what, err, tc.transient)
				}
			}
		})
	}
}

// TestManifestReadRetryIsBounded pins that a manifest read failing with a
// transient error is retried for ResolveBound from the resolve, then fails
// the roll with ManifestMismatch before any node is cordoned.
func TestManifestReadRetryIsBounded(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.resolver.manifestErr = errors.New("connection reset by peer")
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	for i, step := range []time.Duration{0, 5 * time.Minute, 4 * time.Minute} {
		r.now = r.now.Add(step)
		if _, err := c.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if u := r.update(updatesv1alpha1.UpdateName); finished(u) {
			t.Fatalf("pass %d: the roll ended inside the bound: %q", i, u.Status.Phase)
		}
	}
	r.now = r.now.Add(2 * time.Minute)
	if _, err := c.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	u := r.update(updatesv1alpha1.UpdateName)
	f := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || f == nil || f.Reason != ReasonManifestMismatch ||
		!strings.Contains(f.Message, "connection reset by peer") {
		t.Fatalf("phase %q Failed %+v", u.Status.Phase, f)
	}
	if len(r.log()) != 0 {
		t.Fatalf("a node was touched: %v", r.log())
	}
	if r.resolver.calls != 1 {
		t.Fatalf("resolved %d times, want once", r.resolver.calls)
	}
}

// requiresInstallerManifest is the rig's manifest with requiresInstaller set.
func requiresInstallerManifest() []byte {
	b, err := json.Marshal(certs.PayloadManifest{
		Version: target, KubeMinor: rigKubeMinor, CompatibleFrom: rigCompatibleFrom, RequiresInstaller: true, ArchiveSHA256: targetSum,
		Members: []certs.PayloadMember{{Path: "LICENSE", SHA256: targetSum, Kind: certs.PayloadData}},
	})
	if err != nil {
		panic(err)
	}
	return b
}

// TestPreCordonRefusals pins the manifest policy the plan refuses before any
// node is cordoned, each under OutsideCompatibilityWindow with its own
// message prefix: a release that requires the installer, one that raises a
// node's Kubernetes minor by more than one or changes its major, a node whose
// kubeletVersion does not parse, and a node below compatibleFrom.
func TestPreCordonRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest []byte
		nodes    []*corev1.Node
		// prefix is the refusal's own message prefix; want is in the rest.
		prefix string
		want   string
	}{
		{name: "requires the installer", manifest: requiresInstallerManifest(), prefix: "requires the installer:", want: "cannot be applied in place"},
		{name: "a kube minor rise of two", manifest: testManifest(target, "1.36", rigCompatibleFrom, targetSum, nil),
			prefix: "Kubernetes minor step too large:", want: "w1 runs Kubernetes 1.34"},
		{name: "a kube major change", manifest: testManifest(target, "2.0", rigCompatibleFrom, targetSum, nil),
			prefix: "Kubernetes minor step too large:", want: "more than one minor"},
		{name: "one lagging node is enough", manifest: testManifest(target, "1.36", rigCompatibleFrom, targetSum, nil),
			nodes:  []*corev1.Node{node(serverName, "v1.35.0+k3sm.0.1.0", true), node("w1", "v1.35.0+k3sm.0.1.0", false), node("w2", oldKubelet, false)},
			prefix: "Kubernetes minor step too large:", want: "w2 runs Kubernetes 1.34"},
		{name: "an unreadable node kubelet version", manifest: testManifest(target, risingKubeMinor, rigCompatibleFrom, targetSum, nil),
			nodes:  []*corev1.Node{node(serverName, oldKubelet, true), node("w1", "unknown", false), node("w2", oldKubelet, false)},
			prefix: "unreadable node Kubernetes version:", want: `w1 reports kubeletVersion "unknown"`},
		{name: "outside the window", manifest: testManifest(target, rigKubeMinor, "v0.1.5", targetSum, nil),
			prefix: "outside the compatibility window:", want: "w1 runs v0.1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := tc.nodes
			if nodes == nil {
				nodes = threeNodes()
			}
			r := newRig(t, nodes...)
			r.resolver.manifest = tc.manifest
			r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
			r.drive(r.controller(), nil)
			u := r.update(updatesv1alpha1.UpdateName)
			f := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
			if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || f == nil || f.Reason != ReasonOutsideCompatibilityWindow ||
				!strings.HasPrefix(f.Message, tc.prefix) || !strings.Contains(f.Message, tc.want) {
				t.Fatalf("phase %q Failed %+v, want %s starting %q naming %q", u.Status.Phase, f, ReasonOutsideCompatibilityWindow, tc.prefix, tc.want)
			}
			if got := r.log(); len(got) != 0 {
				t.Fatalf("a node was touched: %v", got)
			}
			if len(u.Status.Nodes) != 0 {
				t.Fatalf("a refused roll recorded a plan: %+v", u.Status.Nodes)
			}
		})
	}
	t.Run("a rise of one rolls server first", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.resolver.manifest = testManifest(target, risingKubeMinor, rigCompatibleFrom, targetSum, nil)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(r.controller(), nil)
		if u := r.update(updatesv1alpha1.UpdateName); u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q", u.Status.Phase)
		}
	})
}

// TestHandoversCarryIdenticalManifestBytes pins that every node one
// controller hands over gets the same manifest bytes, the ones it read and
// checked, even when the release host would serve other bytes on a re-read.
func TestHandoversCarryIdenticalManifestBytes(t *testing.T) {
	r := newRig(t, threeNodes()...)
	first := testManifest(target, rigKubeMinor, rigCompatibleFrom, targetSum, nil)
	r.resolver.manifest = first
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	r.drive(c, func() bool { return r.node("w1").Annotations[update.AnnotationUpdateManifest] != "" })
	// The host now serves a different manifest for the same archive.
	r.resolver.mu.Lock()
	r.resolver.manifest = append([]byte(" "), first...)
	r.resolver.mu.Unlock()
	r.drive(c, nil)
	if u := r.update(updatesv1alpha1.UpdateName); u.Status.Phase != updatesv1alpha1.UpdatePhaseSucceeded {
		t.Fatalf("phase %q", u.Status.Phase)
	}
	for _, n := range []string{"w1", "w2", serverName} {
		if got := r.node(n).Annotations[update.AnnotationUpdateManifest]; got != string(first) {
			t.Fatalf("node %s was handed %q, want the bytes read at the plan", n, got)
		}
	}
	if r.resolver.manifestCalls != 1 {
		t.Fatalf("read the manifest %d times, want once", r.resolver.manifestCalls)
	}
}

// TestHandoverManifestReadRetryIsBounded pins the bound on a manifest read at
// a handover after a controller restart (the new controller holds no
// manifest): a transient failure is retried for ResolveBound, then the node
// being handed over is failed in place, still cordoned and never handed
// over, the Update fails with ManifestMismatch and every later node stays
// Pending.
func TestHandoverManifestReadRetryIsBounded(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	r.drive(r.controller(), func() bool {
		return phases(r.update(updatesv1alpha1.UpdateName))["w1"] == updatesv1alpha1.UpdateNodePhaseDownloading
	})
	r.resolver.mu.Lock()
	r.resolver.manifestErr = errors.New("connection reset by peer")
	r.resolver.mu.Unlock()
	start := r.now
	r.drive(r.controller(), nil)
	u := r.update(updatesv1alpha1.UpdateName)
	f := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
	if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || f == nil || f.Reason != ReasonManifestMismatch ||
		!strings.Contains(f.Message, "connection reset by peer") {
		t.Fatalf("phase %q Failed %+v", u.Status.Phase, f)
	}
	if elapsed := r.now.Sub(start); elapsed < ResolveBound {
		t.Fatalf("the roll failed after %s, inside the %s bound", elapsed, ResolveBound)
	}
	want := map[string]updatesv1alpha1.UpdateNodePhase{
		"w1": updatesv1alpha1.UpdateNodePhaseDone, "w2": updatesv1alpha1.UpdateNodePhaseFailed, serverName: updatesv1alpha1.UpdateNodePhasePending,
	}
	if got := phases(u); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("node phases %v, want %v", got, want)
	}
	w2 := r.node("w2")
	if !w2.Spec.Unschedulable || w2.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != "" {
		t.Fatalf("w2 was uncordoned or handed over: unschedulable=%v annotations %v", w2.Spec.Unschedulable, w2.Annotations)
	}
	for _, e := range u.Status.Nodes {
		if e.Name == "w2" && (!strings.Contains(e.Message, "not handed over") || e.FinishedAt == nil) {
			t.Fatalf("w2 entry %+v", e)
		}
	}
	if c := meta.FindStatusCondition(u.Status.Conditions, ConditionManifest); c == nil || c.Status != "False" || c.Reason != ReasonRetrying {
		t.Fatalf("Manifest condition %+v", c)
	}
}
