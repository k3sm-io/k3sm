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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/interconnect"
	"k3sm.io/k3sm/pkg/mlx"
)

// icMember is one Interconnect status member.
type icMember struct {
	node    string
	state   netv1alpha1.InterconnectMemberState
	segment string
}

// thunderbolt builds an enabled thunderbolt Interconnect with the given
// fallback and members.
func thunderbolt(fallback netv1alpha1.InterconnectFallback, members ...icMember) *netv1alpha1.Interconnect {
	ic := &netv1alpha1.Interconnect{Spec: netv1alpha1.InterconnectSpec{
		Medium: netv1alpha1.MediumThunderbolt, Fallback: fallback, Enabled: true,
	}}
	for _, m := range members {
		ic.Status.Members = append(ic.Status.Members, netv1alpha1.InterconnectMember{
			Node: m.node, Index: int32(testIndices[m.node]), State: m.state, Segment: m.segment,
		})
	}
	return ic
}

func up(node, segment string) icMember {
	return icMember{node, netv1alpha1.InterconnectMemberUp, segment}
}

func down(node, segment string) icMember {
	return icMember{node, netv1alpha1.InterconnectMemberDown, segment}
}

// interconnectModel is a two-rank ring asking for path.
func interconnectModel(path mlxv1alpha1.MLXInterconnect) *mlxv1alpha1.MLXModel {
	m := shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing)
	m.Spec.Distributed.Interconnect = path
	return m
}

// gangPath reads the resolved path the rank Pods were placed for, failing on a
// gang that is not whole or that disagrees with itself.
func (h *harness) gangPath(t *testing.T) mlxv1alpha1.MLXInterconnect {
	t.Helper()
	pods := h.rankPods(t)
	if len(pods) != 2 {
		t.Fatalf("%d rank pods, want a whole gang of 2", len(pods))
	}
	path := pods[0].Annotations[mlx.AnnotationInterconnect]
	for _, pod := range pods {
		env := map[string]string{}
		for _, e := range pod.Spec.Containers[0].Env {
			env[e.Name] = e.Value
		}
		_, opted := pod.Annotations[netv1alpha1.AnnotationInterconnects]
		_, hosts := env["K3SM_MLX_HOSTS"]
		tb := path == string(mlxv1alpha1.MLXInterconnectThunderbolt)
		if pod.Annotations[mlx.AnnotationInterconnect] != path || opted != tb || hosts != tb {
			t.Fatalf("rank pod %s: path %q, opted in %v, hosts %v; the gang's path is %q",
				pod.Name, pod.Annotations[mlx.AnnotationInterconnect], opted, hosts, path)
		}
	}
	return mlxv1alpha1.MLXInterconnect(path)
}

// rankUIDs identifies the current rank Pods, to tell a restart from none.
func (h *harness) rankUIDs(t *testing.T) string {
	t.Helper()
	var uids []string
	for _, p := range h.rankPods(t) {
		uids = append(uids, p.Name+"="+string(p.UID))
	}
	return strings.Join(uids, ",")
}

// TestInterconnectPathSelection pins this contract:
// spec.distributed.interconnect resolved at placement over the thunderbolt
// Interconnect, and what a lost segment member costs a placed gang.
func TestInterconnectPathSelection(t *testing.T) {
	tb, nw, auto := mlxv1alpha1.MLXInterconnectThunderbolt, mlxv1alpha1.MLXInterconnectNetwork, mlxv1alpha1.MLXInterconnectAuto
	fbNetwork, fbNone := netv1alpha1.InterconnectFallbackNetwork, netv1alpha1.InterconnectFallbackNone
	oneSegment := thunderbolt(fbNetwork, up("mac-a", "seg-0"), up("mac-b", "seg-0"))

	placement := []struct {
		name     string
		path     mlxv1alpha1.MLXInterconnect
		ic       *netv1alpha1.Interconnect
		indices  map[string]int // nil keeps testIndices
		wantPath mlxv1alpha1.MLXInterconnect
		wantMsg  string // a placement refusal (NoInterconnectSegment) when set
	}{
		{name: "network_ignores_the_cable", path: nw, ic: oneSegment, wantPath: nw},
		{name: "thunderbolt_all_ranks_in_one_up_segment", path: tb, ic: oneSegment, wantPath: tb},
		{name: "thunderbolt_rank_off_segment", path: tb,
			ic:      thunderbolt(fbNetwork, up("mac-a", "seg-0"), up("mac-b", "seg-1")),
			wantMsg: "sharing an up segment (none); fitting nodes with an address (mac-a, mac-b)"},
		{name: "thunderbolt_member_down", path: tb,
			ic:      thunderbolt(fbNetwork, up("mac-a", "seg-0"), down("mac-b", "seg-0")),
			wantMsg: "sharing an up segment (none)"},
		{name: "thunderbolt_index_beyond_the_ceiling", path: tb, ic: oneSegment,
			indices: map[string]int{"mac-a": 0, "mac-b": netv1alpha1.MaxInterconnectNodeIndex + 1},
			wantMsg: "sharing an up segment (mac-a, mac-b); fitting nodes with an address (mac-a)"},
		{name: "thunderbolt_without_an_interconnect", path: tb, wantMsg: "sharing an up segment (none); fitting nodes with an address (none)"},
		{name: "thunderbolt_disabled", path: tb, ic: func() *netv1alpha1.Interconnect {
			ic := oneSegment.DeepCopy()
			ic.Spec.Enabled = false
			return ic
		}(), wantMsg: "sharing an up segment (none); fitting nodes with an address (none)"},
		{name: "auto_picks_thunderbolt", path: auto, ic: oneSegment, wantPath: tb},
		{name: "auto_empty_means_auto", path: "", ic: oneSegment, wantPath: tb},
		{name: "auto_falls_back_to_network", path: auto,
			ic: thunderbolt(fbNetwork, up("mac-a", "seg-0"), down("mac-b", "seg-0")), wantPath: nw},
	}
	for _, tc := range placement {
		t.Run(tc.name, func(t *testing.T) {
			h := shardedHarness(t, interconnectModel(tc.path), twoMacs(), tc.ic)
			if tc.indices != nil {
				h.ctrl.indices = staticIndices(tc.indices)
			}
			h.reconcile(t)
			s := h.status(t)
			placed := condition(t, s, mlx.ConditionShardsPlaced)
			if tc.wantMsg != "" {
				if n := len(h.rankPods(t)); n != 0 {
					t.Fatalf("%d rank pods created; want none", n)
				}
				if placed.Status != metav1.ConditionFalse || placed.Reason != netv1alpha1.ReasonNoInterconnectSegment || !strings.Contains(placed.Message, tc.wantMsg) {
					t.Errorf("ShardsPlaced = %s/%s %q, want False/%s containing %q",
						placed.Status, placed.Reason, placed.Message, netv1alpha1.ReasonNoInterconnectSegment, tc.wantMsg)
				}
				if s.Phase != mlxv1alpha1.MLXModelPhasePending {
					t.Errorf("phase = %s, want Pending (the operator re-places on its own)", s.Phase)
				}
				return
			}
			if got := h.gangPath(t); got != tc.wantPath {
				t.Errorf("gang path = %q, want %q", got, tc.wantPath)
			}
			if placed.Status != metav1.ConditionTrue || !strings.Contains(placed.Message, "over "+string(tc.wantPath)) {
				t.Errorf("ShardsPlaced = %s %q, want True naming the %s path", placed.Status, placed.Message, tc.wantPath)
			}
			if c := condition(t, s, mlx.ConditionLinksHealthy); c.Status != metav1.ConditionTrue {
				t.Errorf("LinksHealthy = %s %q, want True", c.Status, c.Message)
			}
			if tc.wantPath == tb {
				// mac-a (index 0) and mac-b (index 1) slot-1 addresses, in rank order.
				const want = "169.254.0.2:29500,169.254.0.10:29500"
				for _, pod := range h.rankPods(t) {
					for _, e := range pod.Spec.Containers[0].Env {
						if e.Name == "K3SM_MLX_HOSTS" && e.Value != want {
							t.Errorf("rank pod %s K3SM_MLX_HOSTS = %q, want %q", pod.Name, e.Value, want)
						}
					}
				}
			}
		})
	}

	// placeOnCable places a ready two-rank gang on the thunderbolt path.
	placeOnCable := func(t *testing.T, fallback netv1alpha1.InterconnectFallback) *harness {
		t.Helper()
		h := shardedHarness(t, interconnectModel(tb), twoMacs(), thunderbolt(fallback, up("mac-a", "seg-0"), up("mac-b", "seg-0")))
		h.reconcile(t)
		h.markRanks(t, true)
		h.reconcile(t)
		if got := h.gangPath(t); got != tb {
			t.Fatalf("precondition: gang path %q, want thunderbolt", got)
		}
		if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); c.Status != metav1.ConditionTrue {
			t.Fatalf("precondition: Ready = %s %q", c.Status, c.Message)
		}
		return h
	}
	cut := func(t *testing.T, h *harness, fallback netv1alpha1.InterconnectFallback) {
		t.Helper()
		h.setInterconnect(t, thunderbolt(fallback, up("mac-a", "seg-0"), down("mac-b", "seg-0")))
	}
	mend := func(t *testing.T, h *harness, fallback netv1alpha1.InterconnectFallback) {
		t.Helper()
		h.setInterconnect(t, thunderbolt(fallback, up("mac-a", "seg-0"), up("mac-b", "seg-0")))
	}
	linksHealthy := func(t *testing.T, h *harness, want metav1.ConditionStatus, msg string) {
		t.Helper()
		c := condition(t, h.status(t), mlx.ConditionLinksHealthy)
		if c.Status != want || !strings.Contains(c.Message, msg) {
			t.Errorf("LinksHealthy = %s/%s %q, want %s containing %q", c.Status, c.Reason, c.Message, want, msg)
		}
	}

	t.Run("loss_with_fallback_network_rerenders_on_pod_ips", func(t *testing.T) {
		h := placeOnCable(t, fbNetwork)
		cut(t, h, fbNetwork)
		h.reconcile(t)
		if n := len(h.rankPods(t)); n != 0 {
			t.Fatalf("%d rank pods survived the interconnect loss, want a gang restart", n)
		}
		linksHealthy(t, h, metav1.ConditionFalse, "mac-a/mac-b is down")
		if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); !strings.Contains(c.Message, "re-rendering the gang on pod IPs") {
			t.Errorf("Ready = %s %q, want a gang restart onto pod IPs", c.Status, c.Message)
		}
		// The re-placement lands on the network although the spec asks for
		// thunderbolt and the segment no longer holds both ranks.
		h.reconcile(t)
		if got := h.gangPath(t); got != nw {
			t.Fatalf("re-placed gang path %q, want network", got)
		}
		// The fallback is visible: not a plain LinksUp, and it names when the
		// limit ends.
		until := fixedNow.Add(5 * time.Minute).UTC().Format(time.RFC3339)
		c := condition(t, h.status(t), mlx.ConditionLinksHealthy)
		if c.Status != metav1.ConditionFalse || c.Reason != mlx.ReasonDegradedToNetwork ||
			!strings.Contains(c.Message, "interconnect is thunderbolt") || !strings.Contains(c.Message, "until "+until) {
			t.Errorf("LinksHealthy = %s/%s %q, want False/%s naming thunderbolt and %s", c.Status, c.Reason, c.Message, mlx.ReasonDegradedToNetwork, until)
		}
		// Past the limit it stays degraded (no restart for a healthy gang), and
		// says the limit ended.
		h.ctrl.now = func() time.Time { return fixedNow.Add(6 * time.Minute) }
		h.reconcile(t)
		if c := condition(t, h.status(t), mlx.ConditionLinksHealthy); c.Reason != mlx.ReasonDegradedToNetwork || !strings.Contains(c.Message, "ended at "+until) {
			t.Errorf("LinksHealthy past the limit = %s %q, want %s saying the limit ended at %s", c.Reason, c.Message, mlx.ReasonDegradedToNetwork, until)
		}
	})

	// restartRank deletes rank 1, an unrelated gang restart, and lets the
	// operator tear down and re-place the gang.
	restartRank := func(t *testing.T, h *harness) {
		t.Helper()
		if err := h.kube.CoreV1().Pods(testNamespace).Delete(context.Background(), mlx.RankPodName(testModelName, 1), metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		h.reconcile(t)
		h.reconcile(t)
	}
	at := func(h *harness, d time.Duration) { h.ctrl.now = func() time.Time { return fixedNow.Add(d) } }

	t.Run("one_interconnect_restart_per_five_minutes", func(t *testing.T) {
		h := placeOnCable(t, fbNetwork)
		cut(t, h, fbNetwork)
		h.reconcile(t) // the interconnect-driven restart, at fixedNow
		h.reconcile(t) // re-placed on the network
		// The cable comes back. An unrelated gang restart inside the limit
		// stays on the network, so no second interconnect loss can arise.
		mend(t, h, fbNetwork)
		at(h, 4*time.Minute)
		restartRank(t, h)
		if got := h.gangPath(t); got != nw {
			t.Fatalf("a gang restart inside the limit placed on %q, want network", got)
		}
		// Past the limit the next gang restart re-resolves onto the cable.
		at(h, 5*time.Minute+time.Second)
		restartRank(t, h)
		if got := h.gangPath(t); got != tb {
			t.Fatalf("a gang restart past the limit placed on %q, want thunderbolt (re-resolved)", got)
		}
		// And a loss there restarts again: the limit has elapsed.
		h.markRanks(t, true)
		cut(t, h, fbNetwork)
		h.reconcile(t)
		if n := len(h.rankPods(t)); n != 0 {
			t.Fatalf("%d rank pods survived a loss past the limit, want a gang restart", n)
		}
	})

	// Every way a rank on the thunderbolt path cannot use the interconnect:
	// each is an interconnect loss with the five-minute limit, never the
	// generic gang restart that would re-resolve straight back onto the cable.
	attachCond := func(st corev1.ConditionStatus) []corev1.PodCondition {
		return []corev1.PodCondition{{
			Type: netv1alpha1.ConditionInterconnectAttached, Status: st,
			Reason: netv1alpha1.ReasonInterconnectSlotsExhausted, Message: "slot 1 is taken",
		}}
	}
	exited := func(code int32) []corev1.ContainerStatus {
		return []corev1.ContainerStatus{{Name: "mlx-serve", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code}}}}
	}
	for _, rc := range []struct {
		name   string
		conds  []corev1.PodCondition
		status []corev1.ContainerStatus
		why    string
	}{
		{"attach_refused", attachCond(corev1.ConditionFalse), exited(2), "attach refused, " + netv1alpha1.ReasonInterconnectSlotsExhausted},
		{"exit_2_with_attach_true", attachCond(corev1.ConditionTrue), exited(2), "exited 2"},
		{"exit_2_with_no_attach_condition", nil, exited(2), "exited 2"},
		{"failed_before_any_attach", nil, exited(1), "failed before its interconnect attach"},
	} {
		t.Run("rank_cannot_use_the_interconnect/"+rc.name, func(t *testing.T) {
			h := placeOnCable(t, fbNetwork)
			pod := h.rankPods(t)[1]
			pod.Status.Phase = corev1.PodFailed
			pod.Status.Conditions = rc.conds
			pod.Status.ContainerStatuses = rc.status
			if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			h.reconcile(t)
			if n := len(h.rankPods(t)); n != 0 {
				t.Fatalf("%d rank pods survived, want a gang restart", n)
			}
			linksHealthy(t, h, metav1.ConditionFalse, "interconnect lost by rank "+pod.Name+" ("+rc.why)
			if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); !strings.Contains(c.Message, "re-rendering the gang on pod IPs") {
				t.Errorf("Ready = %s %q, want a gang restart onto pod IPs", c.Status, c.Message)
			}
			h.reconcile(t)
			if got := h.gangPath(t); got != nw {
				t.Fatalf("re-placed on %q, want network", got)
			}
			// No thunderbolt attempt inside the limit, however the gang restarts.
			for _, d := range []time.Duration{time.Minute, 3 * time.Minute, 4*time.Minute + 59*time.Second} {
				at(h, d)
				restartRank(t, h)
				if got := h.gangPath(t); got != nw {
					t.Fatalf("at +%s the gang was placed on %q, want network inside the limit", d, got)
				}
			}
		})
	}

	t.Run("an_ordinary_rank_failure_is_the_generic_gang_restart", func(t *testing.T) {
		h := placeOnCable(t, fbNetwork)
		pod := h.rankPods(t)[1]
		pod.Status.Phase = corev1.PodFailed
		pod.Status.Conditions = attachCond(corev1.ConditionTrue)
		pod.Status.ContainerStatuses = exited(1)
		if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		h.reconcile(t)
		h.reconcile(t)
		if got := h.gangPath(t); got != tb {
			t.Errorf("an engine crash after a good attach re-placed on %q, want thunderbolt (no interconnect loss)", got)
		}
	})

	t.Run("the_limit_survives_an_operator_restart", func(t *testing.T) {
		h := placeOnCable(t, fbNetwork)
		cut(t, h, fbNetwork)
		h.reconcile(t) // the interconnect-driven restart, recorded on the model
		raw, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Get(context.Background(), testModelName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := raw.GetAnnotations()[mlx.AnnotationInterconnectRestartedAt], fixedNow.UTC().Format(time.RFC3339); got != want {
			t.Fatalf("%s = %q, want %q", mlx.AnnotationInterconnectRestartedAt, got, want)
		}
		mend(t, h, fbNetwork)
		// A fresh controller over the same API state (a restart or an HA
		// failover) places inside the limit on the network although the cable
		// is back and the spec asks for thunderbolt.
		fresh, err := New(Config{
			Client: h.kube, Dynamic: h.dyn, Options: h.ctrl.opts, ProbeTransport: refusingTransport{},
			InterconnectIndices: staticIndices(testIndices),
		})
		if err != nil {
			t.Fatal(err)
		}
		fresh.now = func() time.Time { return fixedNow.Add(4 * time.Minute) }
		h.ctrl = fresh
		h.reconcile(t)
		if got := h.gangPath(t); got != nw {
			t.Fatalf("a fresh controller placed on %q inside the limit, want network", got)
		}
		// Past it, the next gang restart re-resolves onto the cable.
		at(h, 5*time.Minute+time.Second)
		restartRank(t, h)
		if got := h.gangPath(t); got != tb {
			t.Errorf("past the limit the gang was placed on %q, want thunderbolt", got)
		}
	})

	t.Run("refused_attach_with_fallback_none_holds", func(t *testing.T) {
		h := placeOnCable(t, fbNone)
		before := h.rankUIDs(t)
		pod := h.rankPods(t)[0]
		pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
			Type: netv1alpha1.ConditionInterconnectAttached, Status: corev1.ConditionFalse,
			Reason: netv1alpha1.ReasonInterconnectUnsupportedRuntime, Message: "x",
		})
		if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		h.reconcile(t)
		if h.rankUIDs(t) != before {
			t.Fatal("fallback none restarted the gang over a refused attach")
		}
		linksHealthy(t, h, metav1.ConditionFalse, "fallback is none")
	})

	t.Run("loss_with_fallback_none_holds", func(t *testing.T) {
		h := placeOnCable(t, fbNone)
		before := h.rankUIDs(t)
		cut(t, h, fbNone)
		h.reconcile(t)
		if h.rankUIDs(t) != before {
			t.Fatal("fallback none restarted the gang")
		}
		linksHealthy(t, h, metav1.ConditionFalse, "fallback is none")
		if got := h.gangPath(t); got != tb {
			t.Errorf("held gang path %q, want thunderbolt", got)
		}
		// The link back clears it without a restart.
		mend(t, h, fbNone)
		h.reconcile(t)
		if h.rankUIDs(t) != before {
			t.Error("the cable coming back restarted a held gang")
		}
		linksHealthy(t, h, metav1.ConditionTrue, "all 1 placed links are up")
	})

	t.Run("recovered_cable_never_restarts_a_healthy_gang", func(t *testing.T) {
		h := placeOnCable(t, fbNetwork)
		cut(t, h, fbNetwork)
		h.reconcile(t)
		h.reconcile(t)
		h.markRanks(t, true)
		before := h.rankUIDs(t)
		mend(t, h, fbNetwork)
		for i := 0; i < 3; i++ {
			h.ctrl.now = func() time.Time { return fixedNow.Add(time.Duration(i+1) * time.Hour) }
			h.reconcile(t)
		}
		if h.rankUIDs(t) != before {
			t.Fatal("the cable coming back restarted a healthy gang on the network")
		}
		if got := h.gangPath(t); got != nw {
			t.Errorf("gang path %q, want network until the next gang restart", got)
		}
		if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); c.Status != metav1.ConditionTrue {
			t.Errorf("Ready = %s %q, want True", c.Status, c.Message)
		}
	})
}

// staticIndices is an InterconnectIndices source over a fixed map.
func staticIndices(idx map[string]int) func(context.Context) (interconnect.Indices, error) {
	return func(context.Context) (interconnect.Indices, error) {
		return interconnect.Indices{Index: idx}, nil
	}
}
