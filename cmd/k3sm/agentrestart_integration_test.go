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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// The LIVE half of the B284 gate: a joined agent, killed and restarted with NO
// token anywhere, comes back as the same node.
//
// The hermetic gate (TestAgentRestartReusesItsNodeCredential) proves the store
// round-trips and that the start decision is right. It cannot prove the thing an
// operator actually cares about — that the restarted process authenticates to a
// real apiserver with the credential it loaded — because that needs a control
// plane, a bootstrap supervisor that would reject a stale token, and a second
// daemon. This test is that proof, and it is deliberately tokenless: the restart
// is run with K3SM_TOKEN unset and no --token, so a process that still needed a
// join could not possibly come back.
//
// The two assertions are chosen so neither can pass by accident:
//
//  1. the four credential files are byte-identical across the restart (a restart
//     that re-joined would have re-issued the certs, changing every hash), and
//  2. the node's Ready condition carries a heartbeat NEWER than the restart (the
//     Ready status alone is stale state that outlives a dead kubelet by a full
//     node-monitor grace period, so it proves nothing on its own).
//
// Tier: lab. It is `integration && darwin` and additionally gated on root +
// K3SM_LAB=1, like its sibling join test — it builds this repo, stages
// pod-support artifacts under /Library, downloads a control plane, and runs two
// daemons for minutes.
//
//	sudo K3SM_LAB=1 go test -tags 'integration darwin' -timeout 30m \
//	    -run TestIntegrationAgentRestartReusesItsNodeCredential ./cmd/k3sm/
const (
	restartTestServerNode = "k3sm-b284-server"
	restartTestAgentNode  = "k3sm-b284-agent"
	// restartSettle is how long the restarted agent is watched before its files
	// are hashed: long enough for the resume, the endpoint refresh and the node
	// registration, short enough to stay inside a lab session.
	restartSettle = 30 * time.Second
	// restartHeartbeatWait bounds the wait for a POST-restart heartbeat.
	restartHeartbeatWait = 120 * time.Second
)

func TestIntegrationAgentRestartReusesItsNodeCredential(t *testing.T) {
	if os.Getenv("K3SM_LAB") != "1" {
		// LOUD, never silent: this is the only proof that a restart does not need a
		// join token, so a reader of a green run must be able to tell it did not run.
		t.Skip("B284 RESTART LEG NOT RUN: set K3SM_LAB=1 (it builds the repo, downloads a control plane and runs two daemons for minutes)")
	}
	if os.Geteuid() != 0 {
		t.Skip("B284 RESTART LEG NOT RUN: needs root — the runtimed posture stages pod-readable artifacts under /Library")
	}

	res := bringUpAndRestartAgent(t)

	if res["HASH_BEFORE"] == "" || res["HASH_AFTER"] == "" {
		t.Fatal("the harness reported no credential hashes; it cannot have completed the restart")
	}
	if res["HASH_BEFORE"] != res["HASH_AFTER"] {
		t.Errorf("the stored node credential changed across the restart:\n  before %s\n  after  %s\n"+
			"A restart must PRESENT the credential, not re-issue it — differing hashes mean the agent re-ran its join.",
			res["HASH_BEFORE"], res["HASH_AFTER"])
	}

	restartedAt, err := strconv.ParseInt(res["RESTART_EPOCH"], 10, 64)
	if err != nil {
		t.Fatalf("the harness reported no restart timestamp: %v", err)
	}
	restart := time.Unix(restartedAt, 0)

	cs := joinTestClient(t, res["KUBECONFIG"])
	deadline := time.Now().Add(restartHeartbeatWait)
	for {
		node := getNode(t, cs, restartTestAgentNode)
		var ready *corev1.NodeCondition
		for i := range node.Status.Conditions {
			if node.Status.Conditions[i].Type == corev1.NodeReady {
				ready = &node.Status.Conditions[i]
			}
		}
		switch {
		case ready == nil:
			t.Fatalf("node %s has no Ready condition after the restart", restartTestAgentNode)
		case ready.Status == corev1.ConditionTrue && ready.LastHeartbeatTime.Time.After(restart):
			return // the restarted, tokenless process is the live kubelet for this node
		case time.Now().After(deadline):
			t.Fatalf("node %s did not heartbeat within %s of its tokenless restart (Ready=%s, last heartbeat %s, restart %s): "+
				"the restarted agent is not authenticating to the apiserver with its stored credential",
				restartTestAgentNode, restartHeartbeatWait, ready.Status,
				ready.LastHeartbeatTime.Time.Format(time.RFC3339), restart.Format(time.RFC3339))
		}
		time.Sleep(5 * time.Second)
	}
}

// bringUpAndRestartAgent brings up a server + joined agent through the shared
// clusterup harness, then kills the agent and restarts it WITHOUT a token, in one
// shell so the harness's own pids and paths stay in scope (and so cluster_down
// reaps the restarted process — AGENT_PID is reassigned to it).
//
// The restart deliberately re-runs the same argv agent_up used, minus the token:
// `env -u K3SM_TOKEN` guarantees the joined credential is the only thing the
// process can start from.
func bringUpAndRestartAgent(t *testing.T) map[string]string {
	t.Helper()
	root := repoRootForJoinTest(t)
	lib := root + "/hack/lib/clusterup.sh"

	t.Cleanup(func() {
		out, err := exec.Command("bash", "-c",
			fmt.Sprintf("set -u; . %q; cluster_down", lib)).CombinedOutput()
		if err != nil {
			t.Logf("cluster_down reported %v:\n%s", err, out)
		}
	})

	script := fmt.Sprintf(`set -euo pipefail
. %[1]q
server_up %[2]q runtimed none %[3]q %[4]q
agent_up %[5]q runtimed none

cred_hash() { shasum -a 256 \
  "$AGENT_WORKDIR/node.kubeconfig" \
  "$AGENT_WORKDIR/kubelet-serving.crt" \
  "$AGENT_WORKDIR/kubelet-serving.key" \
  "$AGENT_WORKDIR/kubelet-client-ca.crt" | awk '{print $1}' | tr '\n' ' '; }

printf 'RESULT KUBECONFIG=%%s\n' "$KUBECONFIG"
printf 'RESULT AGENT_WORKDIR=%%s\n' "$AGENT_WORKDIR"
printf 'RESULT HASH_BEFORE=%%s\n' "$(cred_hash)"

kill "$AGENT_PID" 2>/dev/null || true
n=0; while kill -0 "$AGENT_PID" 2>/dev/null; do sleep 1; n=$((n+1)); [ $n -gt 60 ] && { echo "agent did not exit" >&2; exit 1; }; done

printf 'RESULT RESTART_EPOCH=%%s\n' "$(date +%%s)"
nohup env -u K3SM_TOKEN CGO_ENABLED=1 "${K3SM_CMD[@]}" agent \
  --server 127.0.0.1 --node-name %[5]q --node-ip 127.0.0.1 \
  --work-dir "$AGENT_WORKDIR" --pod-root "$AGENT_POD_ROOT" \
  --runtime runtimed --network none --api-port "$APISERVER_PORT" \
  > "$K3SM_WORKDIR/agent-restart.log" 2>&1 &
AGENT_PID=$!

sleep %[6]d
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
  echo "the tokenless restart exited — its log:" >&2
  tail -40 "$K3SM_WORKDIR/agent-restart.log" >&2
  exit 1
fi
printf 'RESULT HASH_AFTER=%%s\n' "$(cred_hash)"
tail -40 "$K3SM_WORKDIR/agent-restart.log" >&2
`, lib, restartTestServerNode, joinTestMeshIP, joinTestKubeletPort, restartTestAgentNode, int(restartSettle/time.Second))

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	t.Logf("clusterup output:\n%s", out)
	if err != nil {
		t.Fatalf("bring up and restart the joined agent: %v", err)
	}

	results := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "RESULT ")
		if !ok {
			continue
		}
		if k, v, ok := strings.Cut(rest, "="); ok {
			results[k] = strings.TrimSpace(v)
		}
	}
	if results["KUBECONFIG"] == "" {
		t.Fatal("the harness did not report a kubeconfig; it cannot have completed the bring-up")
	}
	return results
}
