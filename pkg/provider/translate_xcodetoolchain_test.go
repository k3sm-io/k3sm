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

package provider

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errNoUnitTestToolchain is what the seam returns to every test in this package
// that has not deliberately injected an answer — see the init below.
var errNoUnitTestToolchain = errors.New("xcode-select -p: no toolchain in a unit test")

// The package's provider constructor resolves the node's developer directory at
// construction, and EVERY test that builds a provider goes through it. Pinning
// the seam here, once, keeps the real /usr/bin/xcode-select out of the unit
// tests entirely: a test's verdict must not depend on whether the machine
// running it happens to have Xcode installed. Tests that care about the value
// override the seam for their own case (withDeveloperDir).
func init() {
	lookupDeveloperDir = func() (string, error) { return "", errNoUnitTestToolchain }
}

// withDeveloperDir points the seam at dir (or, for an empty dir, at a node with
// no toolchain at all) for the duration of the test, restoring it afterwards.
// Not parallel-safe by construction — the seam is one package-level var, so no
// test using it calls t.Parallel.
func withDeveloperDir(t *testing.T, dir string) {
	t.Helper()
	prev := lookupDeveloperDir
	t.Cleanup(func() { lookupDeveloperDir = prev })
	if dir == "" {
		lookupDeveloperDir = func() (string, error) { return "", errNoUnitTestToolchain }
		return
	}
	lookupDeveloperDir = func() (string, error) { return dir, nil }
}

// TestXcodeToolchainOptIn is the B264 provider-side gate: the
// k3sm.io/xcode-toolchain annotation is read by PRESENCE and turns into
// SandboxProfile.xcode_toolchain_dir carrying the NODE's developer directory —
// and only ever that directory, never a pod-supplied path.
func TestXcodeToolchainOptIn(t *testing.T) {
	const devDir = "/Applications/Xcode.app/Contents/Developer"

	t.Run("annotation_presence", func(t *testing.T) {
		cases := []struct {
			name        string
			annotations map[string]string
			want        bool
		}{
			{name: "no annotations at all", annotations: nil, want: false},
			{name: "unrelated annotation", annotations: map[string]string{"k3sm.io/other": "1"}, want: false},
			{name: "empty value opts in", annotations: map[string]string{runtimev1.AnnotationXcodeToolchain: ""}, want: true},
			{name: "true opts in", annotations: map[string]string{runtimev1.AnnotationXcodeToolchain: "true"}, want: true},
			// Presence, not a parsed boolean: "false" on the key still opts in,
			// exactly like the internet-egress sibling. A pod that does not want
			// the grant omits the annotation.
			{name: "false still opts in (presence, not a boolean)", annotations: map[string]string{runtimev1.AnnotationXcodeToolchain: "false"}, want: true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations}}
				if got := podRequestsXcodeToolchain(pod); got != tc.want {
					t.Errorf("podRequestsXcodeToolchain() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	// The constant-not-literal pin: the provider must key on the apis constant.
	if runtimev1.AnnotationXcodeToolchain != "k3sm.io/xcode-toolchain" {
		t.Fatalf("runtimev1.AnnotationXcodeToolchain = %q, want k3sm.io/xcode-toolchain",
			runtimev1.AnnotationXcodeToolchain)
	}

	t.Run("apply", func(t *testing.T) {
		cases := []struct {
			name        string
			annotations map[string]string
			nodeDir     string
			want        string
		}{
			{
				name:        "annotation absent leaves the field empty",
				annotations: nil,
				nodeDir:     devDir,
				want:        "",
			},
			{
				name:        "annotation present on a node with a toolchain stamps the node's dir",
				annotations: map[string]string{runtimev1.AnnotationXcodeToolchain: ""},
				nodeDir:     devDir,
				want:        devDir,
			},
			{
				// A node with no toolchain honours the request by granting
				// nothing — the annotation is a request, not an assertion that
				// the host has a toolchain.
				name:        "annotation present on a node with no toolchain leaves it empty",
				annotations: map[string]string{runtimev1.AnnotationXcodeToolchain: "true"},
				nodeDir:     "",
				want:        "",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations}}
				profile := &runtimev1.SandboxProfile{}
				applyXcodeToolchain(profile, pod, tc.nodeDir)
				if got := profile.GetXcodeToolchainDir(); got != tc.want {
					t.Errorf("XcodeToolchainDir = %q, want %q", got, tc.want)
				}
			})
		}
	})

	// End-to-end through the provider: the node fact resolved at construction is
	// the one that reaches the box, and a pod cannot name a different directory.
	t.Run("buildBox_stamps_the_node_dir", func(t *testing.T) {
		withDeveloperDir(t, devDir)
		r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
			NodeName: "n", NodeIP: "10.0.0.5", Root: t.TempDir(),
		}, nil, nil)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: "build", UID: types.UID("uid-build"),
				Annotations: map[string]string{
					runtimev1.AnnotationXcodeToolchain: "",
					// A pod-supplied path must not become the grant.
					"k3sm.io/xcode-toolchain-dir": "/tmp/attacker",
				},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c0", Image: "img"}}},
		}
		box, err := r.buildBox(context.Background(), pod, "10.0.0.5")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		if got := box.GetSandboxProfile().GetXcodeToolchainDir(); got != devDir {
			t.Errorf("XcodeToolchainDir = %q, want the node's developer dir %q", got, devDir)
		}
	})

	t.Run("buildBox_leaves_an_unannotated_pod_empty", func(t *testing.T) {
		withDeveloperDir(t, devDir)
		r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
			NodeName: "n", NodeIP: "10.0.0.5", Root: t.TempDir(),
		}, nil, nil)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: types.UID("uid-web")},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c0", Image: "img"}}},
		}
		box, err := r.buildBox(context.Background(), pod, "10.0.0.5")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		if got := box.GetSandboxProfile().GetXcodeToolchainDir(); got != "" {
			t.Errorf("XcodeToolchainDir = %q, want empty for a pod that did not ask", got)
		}
	})
}

// TestResolveDeveloperDir pins the construction-time contract: the value is the
// seam's answer, and a node with no toolchain degrades to the empty grant plus
// exactly one WARN naming the annotation that now grants nothing.
func TestResolveDeveloperDir(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withDeveloperDir(t, "/Library/Developer/CommandLineTools")
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		if got := resolveDeveloperDir(log); got != "/Library/Developer/CommandLineTools" {
			t.Errorf("resolveDeveloperDir() = %q, want the seam's answer", got)
		}
		if strings.Contains(buf.String(), "no developer toolchain") {
			t.Errorf("warned about a missing toolchain on a node that has one: %s", buf.String())
		}
	})

	t.Run("absent warns once and grants nothing", func(t *testing.T) {
		withDeveloperDir(t, "")
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		if got := resolveDeveloperDir(log); got != "" {
			t.Errorf("resolveDeveloperDir() = %q, want empty when the node has no toolchain", got)
		}
		out := buf.String()
		if n := strings.Count(out, "no developer toolchain"); n != 1 {
			t.Errorf("want exactly 1 warning line, got %d: %s", n, out)
		}
		if !strings.Contains(out, runtimev1.AnnotationXcodeToolchain) {
			t.Errorf("the warning must name the annotation it makes inert: %s", out)
		}
	})
}
