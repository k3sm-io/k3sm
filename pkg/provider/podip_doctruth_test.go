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
	"net/netip"
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

// The addresses this file pins podIP's dispatch to. Each is distinguishable from
// the others and from the node IP, so a branch that returned the wrong one cannot
// look right by coincidence.
const (
	docTruthGuestIP = "100.64.0.77" // what SetupGuest allocates for a guest
	docTruthHostIP  = "127.0.0.42"  // what the host-process Setup binds on lo0
	docTruthNodeIP  = "10.0.0.5"    // the node's own address
)

// docTruthNetwork is a PodNetwork that records which allocation path was taken.
// A vm pod must reach SetupGuest and never the host-process Setup (no lo0 /32 for
// a guest); a host-process pod must do the reverse.
//
// guestIP is what SetupGuest reports back. The zero value (an INVALID address) is
// the "the seam allocated nothing" case, which podIP must fail closed on rather
// than substituting the node IP.
type docTruthNetwork struct {
	guestIP       netip.Addr
	setupCalls    []string
	guestSetups   []string
	hostNetMarked []string
}

func newDocTruthNetwork() *docTruthNetwork {
	return &docTruthNetwork{guestIP: netip.MustParseAddr(docTruthGuestIP)}
}

func (n *docTruthNetwork) Setup(_ context.Context, podID string) (string, error) {
	n.setupCalls = append(n.setupCalls, podID)
	return docTruthHostIP, nil
}
func (n *docTruthNetwork) Teardown(string) error { return nil }
func (n *docTruthNetwork) SetupGuest(_ context.Context, podID string, _ netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	n.guestSetups = append(n.guestSetups, podID)
	return sandbox.GuestNetworkConfig{PodIP: n.guestIP}, nil
}
func (n *docTruthNetwork) MarkHostNetwork(podID string) {
	n.hostNetMarked = append(n.hostNetMarked, podID)
}

// TestPodIPDocMatchesVMBehaviour is the B167 gate: it binds the podIP doc
// comment to what podIP actually DOES for a vm-RuntimeClass pod, so the two
// cannot drift apart again.
//
// HISTORY, because the gate's polarity has now flipped TWICE and that is the
// interesting part. The comment once asserted, in the present tense, that a vm
// pod was routed to SetupGuest — while nothing called it; the gate pinned that
// ABSENCE. M11.4-d4 landed the carrier and the gate inverted to pin its
// PRESENCE, while still recording the thing that had NOT changed: podIP returned
// the NODE IP for a vm pod, so every vm pod on a node published the same
// status.podIP.
//
// B237 retires that stand-in, and this gate now pins the end state. podIP
// publishes the /32 SetupGuest allocated, because the two-address model needs a
// per-pod identity to key on: the published /32 is the pod's cluster identity
// (status.podIP, EndpointSlices, DNS, NetworkPolicy) and is live on no
// interface, while the guest's vmnet DHCP lease is its live TRANSPORT address,
// and observeTransport feeds the Service proxy a published->live override map
// keyed on exactly this /32. A node IP could key nothing, because every guest on
// the node would share it.
//
// Six assertions, each red on a different regression:
//  1. BEHAVIOUR — a vm pod resolves to the SetupGuest-allocated /32 and never
//     reaches the host-process Setup (no lo0 alias for a guest).
//  2. FAIL CLOSED — a guest seam that allocated nothing fails the create rather
//     than falling back to the node IP (which would be unaddressable as a
//     Service backend and indistinguishable from every other guest).
//  3. CONTROL — a non-vm pod DOES take the host-process path.
//  4. THE OTHER BRANCHES — hostNetwork and the nil adapter still resolve to the
//     node IP, and hostNetwork draws no guest address.
//  5. PRODUCTION CALLER — a non-test file in this module calls SetupGuest. If the
//     B6 producer is ever unwired, this goes red and the doc must be restated.
//  6. THE DOC MATCHES — it names the wired carrier, states the published/live
//     two-address split, and does not revive any retired claim.
func TestPodIPDocMatchesVMBehaviour(t *testing.T) {
	t.Parallel()

	t.Run("vm pod resolves to the allocated guest /32 and skips host-process Setup", func(t *testing.T) {
		vm := "vm"
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "guest", Namespace: "default", UID: "vm-uid"},
			Spec:       corev1.PodSpec{RuntimeClassName: &vm},
		}
		net := newDocTruthNetwork()
		r := &runtimedRuntime{nodeName: "n0", nodeIP: docTruthNodeIP, network: net}

		ip, err := r.podIP(context.Background(), pod)
		if err != nil {
			t.Fatalf("podIP: %v", err)
		}
		if ip != docTruthGuestIP {
			t.Errorf("vm pod IP = %q, want the SetupGuest-allocated /32 %q (its published cluster identity)", ip, docTruthGuestIP)
		}
		if ip == docTruthNodeIP {
			t.Error("vm pod IP is the node IP; the retired stand-in gave every guest on the node one identity")
		}
		if len(net.guestSetups) == 0 {
			t.Error("the vm pod never reached SetupGuest — its address did not come from the guest seam")
		}
		if len(net.setupCalls) != 0 {
			t.Errorf("vm pod reached the host-process Setup %v — a guest must get no lo0 /32", net.setupCalls)
		}
	})

	t.Run("a guest seam that allocates nothing fails the create", func(t *testing.T) {
		vm := "vm"
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "addressless", Namespace: "default", UID: "vm-none"},
			Spec:       corev1.PodSpec{RuntimeClassName: &vm},
		}
		net := newDocTruthNetwork()
		net.guestIP = netip.Addr{} // the seam reports no address
		r := &runtimedRuntime{nodeName: "n0", nodeIP: docTruthNodeIP, network: net}

		ip, err := r.podIP(context.Background(), pod)
		if err == nil {
			t.Fatalf("podIP = %q, nil; want a failure — falling back to the node IP would publish an unusable identity", ip)
		}
		if ip != "" {
			t.Errorf("podIP returned %q alongside its error, want the empty string", ip)
		}
	})

	// A non-vm pod DOES take the host-process path — without this, assertion 1
	// would also pass on a podIP that never calls Setup for anything.
	t.Run("a normal pod still takes the host-process path", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "default", UID: "plain-uid"},
		}
		net := newDocTruthNetwork()
		r := &runtimedRuntime{nodeName: "n0", nodeIP: docTruthNodeIP, network: net}
		ip, err := r.podIP(context.Background(), pod)
		if err != nil {
			t.Fatalf("podIP: %v", err)
		}
		if ip != docTruthHostIP || len(net.setupCalls) != 1 {
			t.Errorf("normal pod: ip=%q setupCalls=%v, want the allocated /32 via exactly one Setup", ip, net.setupCalls)
		}
		if len(net.guestSetups) != 0 {
			t.Errorf("a host-process pod reached SetupGuest %v", net.guestSetups)
		}
	})

	// The two branches B237 did NOT touch. Both still resolve to the node IP, and
	// neither draws a guest address — the vm flip must not have widened into them.
	t.Run("hostNetwork and the nil adapter still resolve to the node IP", func(t *testing.T) {
		hostNet := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "hostnet", Namespace: "default", UID: "hostnet-uid"},
			Spec:       corev1.PodSpec{HostNetwork: true},
		}
		net := newDocTruthNetwork()
		r := &runtimedRuntime{nodeName: "n0", nodeIP: docTruthNodeIP, network: net}
		ip, err := r.podIP(context.Background(), hostNet)
		if err != nil {
			t.Fatalf("podIP(hostNetwork): %v", err)
		}
		if ip != docTruthNodeIP {
			t.Errorf("hostNetwork pod IP = %q, want the node IP %q", ip, docTruthNodeIP)
		}
		if len(net.hostNetMarked) != 1 || len(net.guestSetups) != 0 || len(net.setupCalls) != 0 {
			t.Errorf("hostNetwork pod: marked=%v guestSetups=%v setupCalls=%v, want exactly one mark and no allocation",
				net.hostNetMarked, net.guestSetups, net.setupCalls)
		}

		// --network none: no adapter at all.
		bare := &runtimedRuntime{nodeName: "n0", nodeIP: docTruthNodeIP}
		vm := "vm"
		vmPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "guest", Namespace: "default", UID: "vm-uid"},
			Spec:       corev1.PodSpec{RuntimeClassName: &vm},
		}
		if ip, err := bare.podIP(context.Background(), vmPod); err != nil || ip != docTruthNodeIP {
			t.Errorf("podIP with no adapter = (%q, %v), want (%q, nil)", ip, err, docTruthNodeIP)
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
				"result to runtimed as sandbox.VMSpec.Network (runtime.GuestNetworker); podIP publishes the " +
				"address it returns. Restore it; if it was removed deliberately, restate podIP's doc comment " +
				"for the datapath that replaced it and re-point this gate at that truth.")
		}
	})

	t.Run("the doc names the carrier and the two-address split", func(t *testing.T) {
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
		// And it must explain WHY the guest's /32 is published while no interface
		// holds it — the published-identity / live-transport split is the whole
		// reason this branch returns what it returns, and this is the only place a
		// reader of podIP learns it.
		for _, want := range []string{"published", "lease", "transport", "SetTransportOverrides"} {
			if !strings.Contains(doc, want) {
				t.Errorf("podIP's doc comment does not mention %q; without the published-identity vs "+
					"live-lease-transport split, returning an address no interface holds reads as a bug", want)
			}
		}
		// The retired claims. Each was true once and is false now, and re-asserting
		// any of them is exactly the drift this gate was built to catch: the first
		// two predate the wired carrier, the third is the node-IP stand-in B237
		// retired.
		for _, stale := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)no\s+production\s+caller`),
			regexp.MustCompile(`NOT WIRED:`),
			regexp.MustCompile(`(?i)placeholder`),
		} {
			if stale.MatchString(doc) {
				t.Errorf("podIP's doc comment revives the retired claim %q; the guest-network carrier is wired "+
					"and podIP publishes the address it allocated, not the node IP", stale)
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
