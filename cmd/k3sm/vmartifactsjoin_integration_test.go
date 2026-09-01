//go:build integration && darwin

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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// The B108 cluster-join leg: two k3sm nodes, one control plane, and the question
// of whether a JOINED worker derives its guest-artifact state for itself.
//
// # What is actually at risk
//
// Guest artifacts are ensured per node, at that node's own daemon start, against
// a pin compiled into that node's own binary. Nothing about them is replicated,
// scheduled or reconciled — which is the design, and which is also exactly why it
// can go wrong invisibly: a worker that silently inherited the server's verdict,
// or that never ran ensure at all because the wiring sits on a path only
// `k3sm server` takes, would look identical to a correct cluster on any
// single-node gate. Every unit test in this repo, including the ones beside this
// file, runs one node in one process and cannot see that failure.
//
// # Why the assertions are two-sided
//
// The shipped pin is UNMINTED (guestartifacts.ErrPinIncomplete), so today both
// nodes correctly report no artifacts. A test that asserted that literal — label
// absent, cache empty — would be asserting the CURRENT STATE OF THE PIN, and
// would go red the day the guest build lands its digests, on a cluster that had
// become MORE correct. So nothing here is compared against a constant: the two
// nodes' verdicts are compared against EACH OTHER, and each node's advertisement
// is compared against its own disk. Both properties are the ones that must hold
// before and after the mint, and the test's meaning does not change when the pin
// does.
//
// # Why one Mac
//
// The mesh is genuinely two-machine and is not tested here. What IS tested here
// is per-node derivation, and two daemons on one host exercise that fully: they
// have separate work dirs, separate pod roots, separate artifact caches and
// separate ensure calls. The one thing that has to be arranged for is the
// kubelet port — `k3sm agent` has no --kubelet-port, so the SERVER's node is
// moved instead (see agent_up's preconditions in hack/lib/clusterup.sh).

// joinTestServerNode / joinTestAgentNode are the two node names, distinct from
// every other gate's so a stale object from another run is never mistaken for
// this run's.
const (
	joinTestServerNode = "k3sm-b108-server"
	joinTestAgentNode  = "k3sm-b108-agent"
	// joinTestKubeletPort moves the SERVER's node off the default, leaving :10250
	// for the joined agent (which cannot be renumbered).
	joinTestKubeletPort = "10251"
	// joinTestMeshIP enables the worker-join supervisor. Loopback is legitimate:
	// one host, one mesh member, and the join path is address-agnostic.
	joinTestMeshIP = "127.0.0.1"
)

// TestIntegrationGuestArtifactsAgreeAcrossJoinedNodes brings up a server, joins
// an agent to it, and asserts the two nodes agree about guest artifacts — in
// their advertisement AND on their disks.
//
// It is `integration && darwin` tagged and additionally gated on root +
// K3SM_LAB=1: it builds this repo, stages pod-support artifacts under /Library,
// downloads a control plane, and runs two daemons for minutes. Root is not
// optional — the runtimed posture is the only one that ensures artifacts at all
// (the hostprocess runtime has no runtimed to wire them into), and staging its
// pod-readable artifacts needs it.
//
// Run it with a real timeout, e.g.:
//
//	sudo K3SM_LAB=1 go test -tags 'integration darwin' -timeout 30m \
//	    -run TestIntegrationGuestArtifactsAgreeAcrossJoinedNodes ./cmd/k3sm/
func TestIntegrationGuestArtifactsAgreeAcrossJoinedNodes(t *testing.T) {
	if os.Getenv("K3SM_LAB") != "1" {
		// LOUD, never silent: this is the only proof that a JOINED node ensures its
		// own artifacts, so a reader of a green run must be able to tell that it did
		// not run rather than assume it passed.
		t.Skip("B108 JOIN LEG NOT RUN: set K3SM_LAB=1 (it builds the repo, downloads a control plane and runs two daemons for minutes)")
	}
	if os.Geteuid() != 0 {
		t.Skip("B108 JOIN LEG NOT RUN: needs root — the runtimed posture stages pod-readable artifacts under /Library, and only the runtimed runtime wires guest artifacts at all")
	}

	kubeconfig, serverPodRoot, agentPodRoot := bringUpJoinedPair(t)

	cs := joinTestClient(t, kubeconfig)
	server := getNode(t, cs, joinTestServerNode)
	agent := getNode(t, cs, joinTestAgentNode)

	// (i) The two nodes derived the SAME guest-artifact verdict.
	//
	// Compared as a pair, never against a literal: see the file comment. Both-false
	// (today, unminted pin) and both-true (after the mint) are equally green; a
	// SPLIT verdict on one host, from one binary, against one pin, is the failure —
	// it means one of the two paths is not running ensure.
	serverLabel, serverHas := server.Labels[runtimeclass.LabelVMArtifacts]
	agentLabel, agentHas := agent.Labels[runtimeclass.LabelVMArtifacts]
	if serverHas != agentHas || serverLabel != agentLabel {
		t.Errorf("the two nodes disagree about %s: %s has %s=%q (present=%v), %s has %q (present=%v). "+
			"Both run the same binary with the same in-code pin on the same host, so their verdicts cannot legitimately differ; "+
			"one of the two bring-up paths is not running the guest-artifact ensure.",
			provider.ConditionVMArtifactsAvailable, joinTestServerNode, runtimeclass.LabelVMArtifacts, serverLabel, serverHas,
			joinTestAgentNode, agentLabel, agentHas)
	}

	// (i, second half) Each node's ADVERTISEMENT matches its own DISK.
	//
	// This is what makes the equality above non-vacuous: two nodes that both failed
	// to run ensure at all would agree perfectly. Tying each label to the cache it
	// describes means agreement can only be reached by both nodes actually doing
	// the work.
	serverDigest := artifactTreeDigest(t, provider.GuestArtifactsDir(serverPodRoot))
	agentDigest := artifactTreeDigest(t, provider.GuestArtifactsDir(agentPodRoot))
	if serverDigest != agentDigest {
		t.Errorf("the two nodes' guest-artifact caches differ: %s = %s, %s = %s. "+
			"The cache is content-addressed off one in-code pin, so two nodes of the same build must materialise byte-identical trees.",
			joinTestServerNode, serverDigest, joinTestAgentNode, agentDigest)
	}
	for _, n := range []struct {
		name, podRoot, digest string
		labelled              bool
	}{
		{joinTestServerNode, serverPodRoot, serverDigest, serverHas},
		{joinTestAgentNode, agentPodRoot, agentDigest, agentHas},
	} {
		populated := n.digest != emptyArtifactTree
		if n.labelled != populated {
			t.Errorf("%s advertises %s present=%v but its cache at %s is populated=%v: the label must describe THIS node's own verified cache",
				n.name, runtimeclass.LabelVMArtifacts, n.labelled, provider.GuestArtifactsDir(n.podRoot), populated)
		}
	}

	// (ii) The vm capability labels agree between the nodes.
	//
	// Same host, same silicon, same binary — so the VZ probe and both Rosetta
	// probes must reach the same answer on both. A disagreement here is not a
	// capability difference, it is a probe that ran on one bring-up path and not
	// the other, which is the same class of defect as (i) one layer down.
	for _, key := range []string{
		runtimeclass.LabelVirtualization,
		runtimeclass.LabelRosetta,
		runtimeclass.LabelRosettaLinux,
	} {
		sv, sok := server.Labels[key]
		av, aok := agent.Labels[key]
		if sok != aok || sv != av {
			t.Errorf("the two nodes disagree about %s: %s has %q (present=%v), %s has %q (present=%v) — one host, one binary, one probe set",
				key, joinTestServerNode, sv, sok, joinTestAgentNode, av, aok)
		}
	}
}

// emptyArtifactTree is the digest sentinel for a cache directory that is absent
// or holds nothing. It is a fixed non-hex string so it can never collide with a
// real tree digest.
const emptyArtifactTree = "<no artifacts>"

// artifactTreeDigest reduces a guest-artifact cache directory to one comparable
// value: the sha256 over every regular file's relative path and content digest,
// in sorted order.
//
// WHOLE-TREE and content-addressed on purpose. Comparing file names alone would
// call two nodes equal while one held a truncated download; comparing sizes would
// miss a flipped bit. And an absent directory and an empty one collapse to the
// same sentinel because they mean the same thing to a vm pod — no bootable set —
// and which of the two a failed ensure leaves behind depends only on where it
// failed.
func artifactTreeDigest(t *testing.T, dir string) string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		entries = append(entries, rel+":"+hex.EncodeToString(h.Sum(nil)))
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return emptyArtifactTree
	}
	if err != nil {
		t.Fatalf("digest the guest-artifact cache %s: %v", dir, err)
	}
	if len(entries) == 0 {
		return emptyArtifactTree
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:])
}

// bringUpJoinedPair runs the clusterup.sh harness once — server, then joined
// agent — and returns the cluster kubeconfig plus each node's runtimed pod root
// (the parent of its guest-artifact cache).
//
// It drives ONE bash process because the harness keeps its state in shell
// variables ($K3SM_CMD, $SERVER_WORKDIR, the pids), and it reads the two pod
// roots back out of that same process rather than re-deriving them here: a second
// derivation of a path is how a test ends up confidently digesting a directory no
// daemon ever wrote to.
//
// Teardown is registered BEFORE the bring-up runs, so a bring-up that dies half
// way still hands the host back its ports and lo0 aliases.
func bringUpJoinedPair(t *testing.T) (kubeconfig, serverPodRoot, agentPodRoot string) {
	t.Helper()
	root := repoRootForJoinTest(t)
	lib := filepath.Join(root, "hack", "lib", "clusterup.sh")

	t.Cleanup(func() {
		out, err := exec.Command("bash", "-c",
			fmt.Sprintf("set -u; . %q; cluster_down", lib)).CombinedOutput()
		if err != nil {
			t.Logf("cluster_down reported %v:\n%s", err, out)
		}
	})

	script := fmt.Sprintf(`set -euo pipefail
. %q
server_up %q runtimed none %q %q
agent_up %q runtimed none
printf 'RESULT KUBECONFIG=%%s\n' "$KUBECONFIG"
printf 'RESULT SERVER_POD_ROOT=%%s\n' "$K3SM_WORKDIR/pods"
printf 'RESULT AGENT_POD_ROOT=%%s\n' "$AGENT_POD_ROOT"
`, lib, joinTestServerNode, joinTestMeshIP, joinTestKubeletPort, joinTestAgentNode)

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	t.Logf("clusterup output:\n%s", out)
	if err != nil {
		t.Fatalf("bring up the joined pair: %v", err)
	}

	results := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "RESULT ")
		if !ok {
			continue
		}
		if k, v, ok := strings.Cut(rest, "="); ok {
			results[k] = v
		}
	}
	for _, k := range []string{"KUBECONFIG", "SERVER_POD_ROOT", "AGENT_POD_ROOT"} {
		if results[k] == "" {
			t.Fatalf("the harness did not report %s; it cannot have completed the bring-up", k)
		}
	}
	return results["KUBECONFIG"], results["SERVER_POD_ROOT"], results["AGENT_POD_ROOT"]
}

// repoRootForJoinTest resolves this repo's root from the test's working
// directory (cmd/k3sm), so the harness is found regardless of where `go test`
// was invoked from.
func repoRootForJoinTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "hack", "lib", "clusterup.sh")); err != nil {
		t.Fatalf("resolve the repo root from %s: %v", wd, err)
	}
	return root
}

// joinTestClient builds an apiserver client from the cluster kubeconfig.
func joinTestClient(t *testing.T, kubeconfig string) kubernetes.Interface {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("load kubeconfig %s: %v", kubeconfig, err)
	}
	cfg.Timeout = 30 * time.Second
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	return cs
}

// getNode fetches one Node object, failing the test if it is absent — which for
// the agent means the join itself did not complete.
func getNode(t *testing.T, cs kubernetes.Interface, name string) *corev1.Node {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(t.Context(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", name, err)
	}
	return n
}
