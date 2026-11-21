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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/shadowset"

	"k3sm.io/k3sm/pkg/shadow"
)

// withXcodebuildCopy states the node's xcodebuild-copy fact for one test:
// problem "" is a healthy copy.
func withXcodebuildCopy(t *testing.T, problem string) {
	t.Helper()
	prev := xcodebuildCopyProblem
	t.Cleanup(func() { xcodebuildCopyProblem = prev })
	xcodebuildCopyProblem = func(context.Context, string, string) string { return problem }
}

// TestMsgXcodebuildCopyUnavailableGolden pins the Event text byte for byte: it
// is what an operator reads in `kubectl describe pod`, and the remedy it names
// is the one the docs page names.
func TestMsgXcodebuildCopyUnavailableGolden(t *testing.T) {
	got := msgXcodebuildCopyUnavailable("the node's shadow binary set /x/shadow has no xcodebuild copy")
	const want = "Pod has the Xcode toolchain, but an xcodebuild build cannot run in it: " +
		"the node's shadow binary set /x/shadow has no xcodebuild copy. " +
		"Run `sudo k3sm install` on this node (again after every Xcode update); " +
		"clang, swiftc and swift build are unaffected."
	if got != want {
		t.Fatalf("message drifted:\n got %q\nwant %q", got, want)
	}
}

// TestDiagnoseXcodebuildCopy walks every verdict over an injected host.
func TestDiagnoseXcodebuildCopy(t *testing.T) {
	const xcode = "/Applications/Xcode.app/Contents/Developer"
	const dir = "/opt/k3sm/shadow"
	manifest := func(m shadow.Manifest) []byte {
		m.Version = shadow.ManifestVersion
		b, err := shadow.Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	all := func() []shadow.Source {
		var out []shadow.Source
		for _, c := range xcodeBuildCopies() {
			out = append(out, shadow.Source{Name: c.name, Path: c.source, CDHash: "aa"})
		}
		return out
	}
	without := func(name string) []shadow.Source {
		var out []shadow.Source
		for _, s := range all() {
			if s.Name != name {
				out = append(out, s)
			}
		}
		return out
	}
	good := manifest(shadow.Manifest{Sources: all()})
	// host: missing names a copy file absent from the shadow dir; stale names a
	// source whose live hash moved; live "" makes every hash unreadable.
	host := func(missing string, mf []byte, stale, live string) xcodebuildCopyHost {
		return xcodebuildCopyHost{
			usable:  func(p string) bool { return strings.HasPrefix(p, dir+"/") && p != dir+"/"+missing },
			present: func(string) bool { return true },
			readFile: func(p string) ([]byte, error) {
				if mf == nil || p != dir+"/"+shadow.ManifestName {
					return nil, fs.ErrNotExist
				}
				return mf, nil
			},
			cdhash: func(p string) (string, error) {
				if live == "" {
					return "", errors.New("unreadable")
				}
				if p == stale {
					return "bb", nil
				}
				return live, nil
			},
		}
	}
	actool := "/Applications/Xcode.app/Contents/Developer/usr/bin/actool"
	cases := []struct {
		name, shadowDir, devDir string
		h                       xcodebuildCopyHost
		want                    string // "" healthy, else a substring
	}{
		{"healthy", dir, xcode, host("", good, "", "aa"), ""},
		{"stale after an Xcode update", dir, xcode, host("", good, shadowset.XcodebuildSource, "aa"), "changed since its copy was made"},
		{"stale actool", dir, xcode, host("", good, actool, "aa"), actool + " changed"},
		{"no shadow set", "", xcode, host("", good, "", "aa"), "no shadow binary set"},
		{"copy file gone or untrusted", dir, xcode, host("xcodebuild", good, "", "aa"), "has no usable xcodebuild copy"},
		{"an Xcode without ibtoold has nothing to copy", dir, xcode, func() xcodebuildCopyHost {
			h := host("", manifest(shadow.Manifest{Sources: without("ibtoold")}), "", "aa")
			h.present = func(p string) bool { return filepath.Base(p) != "ibtoold" }
			return h
		}(), ""},
		{"no manifest", dir, xcode, host("", nil, "", "aa"), "manifest could not be read"},
		{"install skipped xcodebuild", dir, xcode, host("", manifest(shadow.Manifest{Sources: without("xcodebuild"), Skipped: []shadow.Skipped{{Name: "xcodebuild", Path: shadowset.XcodebuildSource, Reason: "Xcode is writable by a non-admin"}}}), "", "aa"), "skipped the xcodebuild copy: Xcode is writable"},
		{"node installed before the ibtoold copy existed", dir, xcode, host("", manifest(shadow.Manifest{Sources: without("ibtoold")}), "", "aa"), "has no ibtoold copy"},
		{"live unreadable", dir, xcode, host("", good, "", ""), "could not be read"},
		{"another Xcode", dir, "/Applications/Xcode-beta.app/Contents/Developer", host("", good, "", "aa"), "makes its Xcode tool copies only from /Applications/Xcode.app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diagnoseXcodebuildCopy(tc.shadowDir, tc.devDir, tc.h)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("want healthy, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// TestXcodebuildCopyUnavailableEvent is the create-time preflight: only a pod
// whose grant took effect, on a node whose copy cannot serve it, hears it.
func TestXcodebuildCopyUnavailableEvent(t *testing.T) {
	const xcode = "/Applications/Xcode.app/Contents/Developer"
	const clt = "/Library/Developer/CommandLineTools"
	cases := []struct {
		name, nodeDir, problem string
		annotated, wantEvent   bool
	}{
		{"granted pod, missing copy, warns", xcode, "no xcodebuild copy", true, true},
		{"granted pod, healthy copy, silent", xcode, "", true, false},
		// The grant did not take effect: XcodeToolchainUngranted already speaks.
		{"ungranted pod is not this Event's business", clt, "no xcodebuild copy", true, false},
		{"unannotated pod stays silent", xcode, "no xcodebuild copy", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withDeveloperDir(t, tc.nodeDir)
			withXcodebuildCopy(t, tc.problem)
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
				NodeName: "n", NodeIP: "10.0.0.5", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
			}, nil, nil)
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "build", UID: types.UID("uid-" + tc.name)},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c0", Image: "img"}}},
			}
			if tc.annotated {
				pod.Annotations = map[string]string{runtimev1.AnnotationXcodeToolchain: ""}
			}
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			var got string
			deadline := 100 * time.Millisecond
			if tc.wantEvent {
				deadline = 3 * time.Second
			}
			for e := nextLifecycleEvent(rec.Events, deadline); e != ""; e = nextLifecycleEvent(rec.Events, 100*time.Millisecond) {
				if strings.Contains(e, reasonXcodebuildCopyUnavailable) {
					got = e
					break
				}
			}
			if !tc.wantEvent {
				if got != "" {
					t.Fatalf("unexpected Event %q", got)
				}
				return
			}
			want := "Warning " + reasonXcodebuildCopyUnavailable + " " + msgXcodebuildCopyUnavailable(tc.problem)
			if got != want {
				t.Fatalf("Event = %q, want %q", got, want)
			}
		})
	}
}

// TestCopyIsTrusted: only a regular file owned by root that nobody else can
// write counts as a copy. A test cannot make a root-owned file, so the positive
// case reads one the system ships.
func TestCopyIsTrusted(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "copy")
	if err := os.WriteFile(mine, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/bin/ls", link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		want       bool
	}{
		{"a root-owned system binary", "/bin/ls", true},
		{"a file the test user owns", mine, os.Geteuid() == 0},
		{"a link to a root-owned binary", link, false},
		{"a directory", dir, false},
		{"nothing there", filepath.Join(dir, "absent"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := copyIsTrusted(tc.path); got != tc.want {
				t.Errorf("copyIsTrusted(%s) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
