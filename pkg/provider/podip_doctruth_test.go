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

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// docTruthNetwork is a PodNetwork that records whether the host-process Setup
// path was taken. A vm pod must never reach it (no lo0 /32 for a guest).
type docTruthNetwork struct {
	setupCalls    []string
	guestSetups   []string
	hostNetMarked []string
}

func (n *docTruthNetwork) Setup(_ context.Context, podID string) (string, error) {
	n.setupCalls = append(n.setupCalls, podID)
	return "127.0.0.42", nil
}
func (n *docTruthNetwork) Teardown(string) error { return nil }
func (n *docTruthNetwork) SetupGuest(_ context.Context, podID string, _ netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	n.guestSetups = append(n.guestSetups, podID)
	return sandbox.GuestNetworkConfig{}, nil
}
func (n *docTruthNetwork) MarkHostNetwork(podID string) {
	n.hostNetMarked = append(n.hostNetMarked, podID)
}

// TestPodIPDocMatchesVMBehaviour is the B167 gate: it binds the podIP doc
// comment to what podIP actually DOES for a vm-RuntimeClass pod, so the two
// cannot drift apart again.
//
// HISTORY, because the gate's polarity flipped and that is the interesting part.
// The comment once asserted, in the present tense, that a vm pod was routed to
// SetupGuest — while nothing called it. The gate then pinned the ABSENCE of a
// production caller, so that landing the carrier would go red and force the doc
// to be re-read. M11.4-d4 landed it: buildBox -> setupGuestNetwork ->
// PodNetwork.SetupGuest allocates the guest's address and the adapter carries the
// config to runtimed as sandbox.VMSpec.Network. The gate went red exactly as
// designed, and is now inverted to pin the wiring's PRESENCE.
//
// What did NOT change is the reason this comment exists: podIP still returns the
// NODE IP for a vm pod, so every vm pod still publishes the same status.podIP.
// Reporting the guest's own address is the lab-gated question (a NAT attachment
// assigns it a macOS-chosen address), and this doc is the only place a reader
// learns that. A comment that quietly upgraded "the carrier is wired" into "the
// pod IP is the guest's" would teach the wrong datapath just as effectively as
// the original false claim did.
//
// Four assertions, each red on a different regression:
//  1. BEHAVIOUR — a vm pod resolves to the node IP and never reaches the
//     host-process Setup (the real, current dispatch).
//  2. CONTROL — a non-vm pod DOES take the host-process path.
//  3. PRODUCTION CALLER — a non-test file in this module calls SetupGuest. If the
//     B6 producer is ever unwired, this goes red and the doc must be restated.
//  4. THE DOC MATCHES — it names the wired carrier, still records the node-IP
//     placeholder, and does not revive the retired "no caller / NOT WIRED" claim.
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

	t.Run("SetupGuest has a production caller in this module", func(t *testing.T) {
		if !wired {
			t.Fatal("no non-test file in this module calls SetupGuest — the B6 producer wiring is gone. " +
				"It ran buildBox -> setupGuestNetwork -> PodNetwork.SetupGuest, and the adapter carried the " +
				"result to runtimed as sandbox.VMSpec.Network (runtime.GuestNetworker). Restore it; if it was " +
				"removed deliberately, restate podIP's doc comment for the datapath that replaced it and " +
				"re-point this gate at that truth.")
		}
	})

	t.Run("the doc names the wired carrier and keeps the node-IP placeholder", func(t *testing.T) {
		if !wired {
			t.Skip("SetupGuest has no production caller; the previous subtest owns that failure")
		}
		doc := podIPDocComment(t, string(src))
		if doc == "" {
			t.Fatal("could not locate podIP's doc comment in runtimed.go")
		}
		// It must NAME the carrier, so a reader of podIP can find where a vm pod's
		// network actually comes from.
		for _, want := range []string{"SetupGuest", "GuestNetworker"} {
			if !strings.Contains(doc, want) {
				t.Errorf("podIP's doc comment does not mention %q; a vm pod's network IS produced through it "+
					"(setupGuestNetwork), and this comment is where a reader goes looking", want)
			}
		}
		// And it must STILL explain the thing that did not change — otherwise the
		// comment reads as though a vm pod now reports its guest address.
		if !strings.Contains(doc, "placeholder") || !strings.Contains(doc, "node IP") {
			t.Error("podIP's doc comment no longer records that a vm pod publishes the NODE IP as a placeholder; " +
				"that is still what this function returns, and it is the only place a reader learns why")
		}
		// The retired claims: the carrier now exists, so re-asserting either of
		// these would be false in exactly the way this gate was built to catch.
		for _, stale := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)no\s+production\s+caller`),
			regexp.MustCompile(`NOT WIRED:`),
		} {
			if stale.MatchString(doc) {
				t.Errorf("podIP's doc comment revives the retired claim %q, but the guest-network carrier is wired "+
					"(setupGuestNetwork calls SetupGuest and the adapter serves runtime.GuestNetworker)", stale)
			}
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
