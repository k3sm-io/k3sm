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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// docTruthNetwork is a PodNetwork that records whether the host-process Setup
// path was taken. A vm pod must never reach it (no lo0 /32 for a guest).
type docTruthNetwork struct {
	setupCalls    []string
	hostNetMarked []string
}

func (n *docTruthNetwork) Setup(_ context.Context, podID string) (string, error) {
	n.setupCalls = append(n.setupCalls, podID)
	return "127.0.0.42", nil
}
func (n *docTruthNetwork) Teardown(string) error { return nil }
func (n *docTruthNetwork) MarkHostNetwork(podID string) {
	n.hostNetMarked = append(n.hostNetMarked, podID)
}

// TestPodIPDocMatchesVMBehaviour is the B167 gate: it binds the podIP doc
// comment to what podIP actually DOES for a vm-RuntimeClass pod, so the two
// cannot drift apart again.
//
// The comment used to assert, in the present tense, that for a vm pod "runtimed
// routes it to SetupGuest, never the host-process Setup". podnet.(*Network).
// SetupGuest is real and unit-tested in darwin-net, but nothing routes to it —
// there is no transport carrying a GuestNetwork to runtimed yet (M5.1-d2 / B6).
// That comment is the only explanation a reader finds for why every vm pod
// publishes the same status.podIP, so a false one actively teaches the wrong
// model of the vm datapath rather than merely being stale.
//
// Three assertions, each red on a different regression:
//  1. BEHAVIOUR — a vm pod resolves to the node IP and never reaches the
//     host-process Setup (the real, current dispatch).
//  2. NO PRODUCTION CALLER — no non-test file in this module calls SetupGuest.
//     When the transport finally lands and k3sm routes to it, this goes red and
//     forces the comment to be re-read, which is the point: the doc is pinned to
//     the wiring, not to a reviewer remembering.
//  3. NO REVIVED CLAIM — the comment does not re-assert present-tense routing to
//     SetupGuest while (2) still holds.
func TestPodIPDocMatchesVMBehaviour(t *testing.T) {
	t.Parallel()

	t.Run("vm pod resolves to the node IP and skips host-process Setup", func(t *testing.T) {
		vm := "vm"
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "guest", Namespace: "default", UID: "vm-uid"},
			Spec:       corev1.PodSpec{RuntimeClassName: &vm},
		}
		net := &docTruthNetwork{}
		r := &runtimedRuntime{nodeName: "n0", nodeIP: "10.0.0.5", network: net}

		ip, err := r.podIP(context.Background(), pod)
		if err != nil {
			t.Fatalf("podIP: %v", err)
		}
		if ip != "10.0.0.5" {
			t.Errorf("vm pod IP = %q, want the node IP 10.0.0.5 (the documented placeholder)", ip)
		}
		if len(net.setupCalls) != 0 {
			t.Errorf("vm pod reached the host-process Setup %v — a guest must get no lo0 /32", net.setupCalls)
		}
	})

	// A non-vm pod DOES take the host-process path — without this, assertion 1
	// would also pass on a podIP that never calls Setup for anything.
	t.Run("a normal pod still takes the host-process path", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "default", UID: "plain-uid"},
		}
		net := &docTruthNetwork{}
		r := &runtimedRuntime{nodeName: "n0", nodeIP: "10.0.0.5", network: net}
		ip, err := r.podIP(context.Background(), pod)
		if err != nil {
			t.Fatalf("podIP: %v", err)
		}
		if ip != "127.0.0.42" || len(net.setupCalls) != 1 {
			t.Errorf("normal pod: ip=%q setupCalls=%v, want the allocated /32 via exactly one Setup", ip, net.setupCalls)
		}
	})

	src, err := os.ReadFile("runtimed.go")
	if err != nil {
		t.Fatalf("read runtimed.go: %v", err)
	}
	wired := setupGuestHasProductionCaller(t)

	t.Run("SetupGuest still has no production caller in this module", func(t *testing.T) {
		if wired {
			t.Fatal("k3sm now calls SetupGuest in non-test code — the vm datapath changed. " +
				"Re-read podIP's doc comment: it documents the node-IP PLACEHOLDER and says the " +
				"guest-network routing is NOT wired. Update it to the new truth, then update this gate.")
		}
	})

	t.Run("the doc does not re-assert routing that is not wired", func(t *testing.T) {
		if wired {
			t.Skip("SetupGuest is wired; the claim would no longer be false")
		}
		doc := podIPDocComment(t, string(src))
		if doc == "" {
			t.Fatal("could not locate podIP's doc comment in runtimed.go")
		}
		// The false claim was "runtimed routes it to SetupGuest" stated as fact.
		claim := regexp.MustCompile(`(?i)routes\s+it\s+to\s+SetupGuest`)
		if claim.MatchString(doc) {
			t.Error("podIP's doc comment asserts runtimed routes vm pods to SetupGuest, but nothing calls it " +
				"(no transport for GuestNetwork to runtimed yet — M5.1-d2 / B6). State it as unbuilt intent, not behaviour.")
		}
		// It must still explain what actually happens, or the comment is merely vague.
		if !strings.Contains(doc, "NOT WIRED") && !strings.Contains(doc, "not wired") {
			t.Error("podIP's doc comment no longer records that the guest-network routing is unwired; " +
				"a reader needs that to understand why every vm pod publishes the same status.podIP")
		}
	})
}

// podIPDocComment returns the contiguous `//` comment block immediately above
// `func (r *runtimedRuntime) podIP(`.
func podIPDocComment(t *testing.T, src string) string {
	t.Helper()
	idx := strings.Index(src, "func (r *runtimedRuntime) podIP(")
	if idx < 0 {
		return ""
	}
	lines := strings.Split(src[:idx], "\n")
	var doc []string
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "//") {
			doc = append([]string{l}, doc...)
			continue
		}
		if l == "" && len(doc) == 0 {
			continue
		}
		break
	}
	return strings.Join(doc, "\n")
}

// setupGuestHasProductionCaller reports whether any non-test .go file in this
// module calls SetupGuest. Deliberately scoped to k3sm: the comment under test
// is k3sm's, and it is k3sm's dispatch it describes, so this stays correct in a
// standalone clone with no darwin-net checked out beside it.
func setupGuestHasProductionCaller(t *testing.T) bool {
	t.Helper()
	call := regexp.MustCompile(`\.SetupGuest\s*\(`)
	found := false
	root := "../.."
	err := filepathWalkGo(root, func(path string, b []byte) {
		if strings.HasSuffix(path, "_test.go") {
			return
		}
		if call.Match(b) {
			found = true
		}
	})
	if err != nil {
		t.Fatalf("scan module for SetupGuest callers: %v", err)
	}
	return found
}

// filepathWalkGo visits every .go file under root, handing the callback its
// path and contents. Vendor and hidden dirs are skipped.
func filepathWalkGo(root string, fn func(path string, b []byte)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || (strings.HasPrefix(name, ".") && name != "." && name != "..") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		fn(path, b)
		return nil
	})
}
