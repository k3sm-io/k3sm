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

package operator

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
)

// TestShardExitStatusesMatchTheScript pins that the exit statuses the
// operator reads are the ones k3sm_shard.py exits with.
func TestShardExitStatusesMatchTheScript(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "hack", "images", "mlx-serve", "k3sm_shard.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want int
	}{
		{"REFUSED_STATUS", shardRefusedExit},
		{"MISPLACED_STATUS", shardMisplacedExit},
	} {
		m := regexp.MustCompile(`(?m)^`+tc.name+` = (\d+)$`).FindAllSubmatch(src, -1)
		if len(m) != 1 {
			t.Errorf("k3sm_shard.py defines %s %d times, want once", tc.name, len(m))
			continue
		}
		if got, _ := strconv.Atoi(string(m[0][1])); got != tc.want {
			t.Errorf("k3sm_shard.py %s = %d, the operator reads %d", tc.name, got, tc.want)
		}
	}
	if shardRefusedExit == shardMisplacedExit {
		t.Error("the refused and misplaced statuses are the same value")
	}
}

// failedRank is a thunderbolt rank Pod that failed with exit code, its attach
// recorded as attach (nil: no condition).
func failedRank(name string, code int32, attach *corev1.ConditionStatus) corev1.Pod {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{
			mlx.AnnotationInterconnect: string(mlxv1alpha1.MLXInterconnectThunderbolt),
		}},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "mlx-serve", State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{ExitCode: code},
			}}},
		},
	}
	if attach != nil {
		pod.Status.Conditions = []corev1.PodCondition{{Type: netv1alpha1.ConditionInterconnectAttached, Status: *attach}}
	}
	return pod
}

// TestLostRanksSkipsAMisplacedRank pins that a rank exiting with k3sm-shard's
// misplaced status is not an interconnect loss but a placement error, while
// exit 2 stays a loss.
func TestLostRanksSkipsAMisplacedRank(t *testing.T) {
	attached := corev1.ConditionTrue
	for _, tc := range []struct {
		name            string
		pod             corev1.Pod
		lost, misplaced bool
	}{
		{"misplaced_attached", failedRank("r0", shardMisplacedExit, &attached), false, true},
		{"misplaced_without_attach_condition", failedRank("r0", shardMisplacedExit, nil), false, true},
		{"refused", failedRank("r0", shardRefusedExit, &attached), true, false},
		{"refused_without_attach_condition", failedRank("r0", shardRefusedExit, nil), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pods := []corev1.Pod{tc.pod}
			if got := len(lostRanks(pods)) > 0; got != tc.lost {
				t.Errorf("lostRanks = %v, want lost %v", lostRanks(pods), tc.lost)
			}
			if got := len(misplacedRanks(pods)) > 0; got != tc.misplaced {
				t.Errorf("misplacedRanks = %v, want misplaced %v", misplacedRanks(pods), tc.misplaced)
			}
		})
	}
	network := failedRank("r0", shardMisplacedExit, &attached)
	network.Annotations[mlx.AnnotationInterconnect] = string(mlxv1alpha1.MLXInterconnectNetwork)
	if got := misplacedRanks([]corev1.Pod{network}); len(got) != 0 {
		t.Errorf("misplacedRanks on the network path = %v, want none", got)
	}
}

// TestMisplacedRankReplacesOnTheCable pins that a rank that exited with the
// misplaced status restarts the gang as a placement error: no interconnect
// loss, no restart record, and the gang goes back onto the cable.
func TestMisplacedRankReplacesOnTheCable(t *testing.T) {
	tb := mlxv1alpha1.MLXInterconnectThunderbolt
	h := shardedHarness(t, interconnectModel(tb), twoMacs(),
		thunderbolt(netv1alpha1.InterconnectFallbackNetwork, up("mac-a", "seg-0"), up("mac-b", "seg-0")))
	h.reconcile(t)
	if got := h.gangPath(t); got != tb {
		t.Fatalf("precondition: gang path %q, want thunderbolt", got)
	}
	attached := corev1.ConditionTrue
	pod := h.rankPods(t)[0]
	failed := failedRank(pod.Name, shardMisplacedExit, &attached)
	pod.Status = failed.Status
	if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	if n := len(h.rankPods(t)); n != 0 {
		t.Fatalf("%d rank pods survived, want a gang restart", n)
	}
	c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady)
	if !strings.Contains(c.Message, "placement error") || strings.Contains(c.Message, "interconnect lost") {
		t.Errorf("Ready = %s %q, want a placement-error gang restart, not an interconnect loss", c.Status, c.Message)
	}
	raw, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Get(context.Background(), testModelName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := raw.GetAnnotations()[mlx.AnnotationInterconnectRestartedAt]; ok {
		t.Errorf("%s = %q recorded, want no interconnect restart record", mlx.AnnotationInterconnectRestartedAt, v)
	}
	h.reconcile(t)
	if got := h.gangPath(t); got != tb {
		t.Errorf("re-placed on %q, want thunderbolt (the cable is up)", got)
	}
}
