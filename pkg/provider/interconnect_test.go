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
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/interconnect"
)

// icNodeIndex is the fake node's cluster index; its slot addresses are
// 169.254.0.(8*2 + slot + 1).
const icNodeIndex = 2

func icAddr(t *testing.T, slot int) netip.Addr {
	t.Helper()
	a, err := netv1alpha1.InterconnectSlotAddress(icNodeIndex, slot)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fakeAliases is the root helper: it derives slot addresses the way netd does
// and records every call. ensureErr, when set, answers every ensure.
type fakeAliases struct {
	mu        sync.Mutex
	ensured   []int
	removed   []int
	ensureErr error
	lie       bool // answer an address of the wrong slot
}

func (f *fakeAliases) EnsureInterconnectAlias(_ context.Context, slot int) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, slot)
	if f.ensureErr != nil {
		return netip.Addr{}, f.ensureErr
	}
	s := slot
	if f.lie {
		s = (slot + 1) % (netv1alpha1.MaxInterconnectSlot + 1)
	}
	return netv1alpha1.InterconnectSlotAddress(icNodeIndex, s)
}

func (f *fakeAliases) RemoveInterconnectAlias(_ context.Context, slot int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, slot)
	return nil
}

func (f *fakeAliases) calls() (ensured, removed []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.ensured...), append([]int(nil), f.removed...)
}

// desiredValue encodes a desired annotation for the thunderbolt interconnect.
func desiredValue(t *testing.T, fallback netv1alpha1.InterconnectFallback, namespaces []string, models ...netv1alpha1.InterconnectModelRef) string {
	t.Helper()
	v, err := netv1alpha1.InterconnectDesired{
		Schema: netv1alpha1.InterconnectAnnotationSchema, Interconnect: netv1alpha1.MediumThunderbolt,
		Fallback: fallback, AllowedNamespaces: namespaces, MLXModels: models,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// icPod is a native pod in ns asking for the thunderbolt interconnect.
func icPod(ns, name string) *corev1.Pod {
	p := runtimedPod(ns, name)
	p.Annotations = map[string]string{netv1alpha1.AnnotationInterconnects: netv1alpha1.MediumThunderbolt}
	return p
}

// mlxOwned makes pod's controller an MLXModel named name with uid under
// apiVersion.
func mlxOwned(pod *corev1.Pod, apiVersion, name, uid string, controller bool) *corev1.Pod {
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: apiVersion, Kind: "MLXModel", Name: name, UID: types.UID(uid), Controller: &controller,
	}}
	return pod
}

func modelRef(ns, name, uid string) netv1alpha1.InterconnectModelRef {
	return netv1alpha1.InterconnectModelRef{Namespace: ns, Name: name, UID: uid}
}

type icHarness struct {
	r       *runtimedRuntime
	f       *fakeRuntimeServer
	aliases *fakeAliases
	rec     *record.FakeRecorder
	logs    *syncBuffer
}

// newICHarness builds the provider over the fake runtime with the attach
// wired to desired (synced) and the fake helper. A nil aliases wires no helper.
func newICHarness(t *testing.T, desired string, synced bool, aliases *fakeAliases) *icHarness {
	t.Helper()
	f := newFakeRuntimeServer()
	rec := record.NewFakeRecorder(64)
	cfg := InterconnectConfig{Desired: func() (string, bool) { return desired, synced }}
	if aliases != nil {
		cfg.Aliases = aliases
	}
	logs := &syncBuffer{}
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: testNodeIP, Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: rec, Interconnect: cfg,
	}, nil, slog.New(slog.NewTextHandler(logs, nil)))
	return &icHarness{r: r, f: f, aliases: aliases, rec: rec, logs: logs}
}

// env returns every value of every env var on the created box's first
// container, so a duplicate is visible.
func (h *icHarness) env(t *testing.T, uid string) map[string][]string {
	t.Helper()
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	box, ok := h.f.created[uid]
	if !ok {
		t.Fatalf("pod %s not created", uid)
	}
	out := map[string][]string{}
	for _, e := range box.GetContainers()[0].GetEnv() {
		out[e.GetName()] = append(out[e.GetName()], e.GetValue())
	}
	return out
}

func (h *icHarness) condition(t *testing.T, pod *corev1.Pod) *corev1.PodCondition {
	t.Helper()
	st, err := h.r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	var found *corev1.PodCondition
	for i := range st.Conditions {
		if st.Conditions[i].Type == corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached) {
			if found != nil {
				t.Fatalf("the attach condition is published twice: %+v", st.Conditions)
			}
			found = &st.Conditions[i]
		}
	}
	return found
}

func (h *icHarness) created(uid string) bool {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	_, ok := h.f.created[uid]
	return ok
}

func (h *icHarness) events() string {
	var out []string
	for {
		select {
		case e := <-h.rec.Events:
			out = append(out, e)
		default:
			return strings.Join(out, "\n")
		}
	}
}

// TestInterconnectAnnotationAttachesSecondAddress pins that a pod
// annotated k3sm.io/interconnects gets, at create, a slot of the node's
// interconnect /24 from the root helper, the K3SM_INTERCONNECT_* env after its
// own env, and the k3sm.io/InterconnectAttached condition; every refusal is
// named and decided by the fallback (network starts the pod without the
// address, condition False; none holds it with a Warning Event); teardown
// removes the alias and frees the slot; and slot 1 goes only to a verified
// MLXModel rank. The node reads its facts only from its desired annotation.
func TestInterconnectAnnotationAttachesSecondAddress(t *testing.T) {
	ctx := context.Background()
	const modelUID = "0f8b6c3e-1d2a-4b5c-9e7f-0123456789ab"
	llm := modelRef("ml", "llm", modelUID)
	cidr := netv1alpha1.InterconnectCIDR

	t.Run("happy path: address, env and condition True", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, &fakeAliases{})
		pod := icPod("default", "web")
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		want := icAddr(t, netv1alpha1.InterconnectSlotFirstPod)
		env := h.env(t, string(pod.UID))
		if got := env[podnet.EnvInterconnectIP]; len(got) != 1 || got[0] != want.String() {
			t.Errorf("%s = %v, want [%s]", podnet.EnvInterconnectIP, got, want)
		}
		if got := env[podnet.EnvInterconnectCIDRs]; len(got) != 1 || got[0] != cidr {
			t.Errorf("%s = %v, want [%s]", podnet.EnvInterconnectCIDRs, got, cidr)
		}
		c := h.condition(t, pod)
		if c == nil || c.Status != corev1.ConditionTrue || c.Reason != netv1alpha1.MediumThunderbolt || c.Message != want.String() {
			t.Fatalf("condition = %+v, want True, reason thunderbolt, message %s", c, want)
		}
		if ensured, _ := h.aliases.calls(); len(ensured) != 1 || ensured[0] != netv1alpha1.InterconnectSlotFirstPod {
			t.Errorf("ensured slots = %v, want [2]", ensured)
		}
		if n := attachedSlots(h.r.interconnect); n != 1 {
			t.Errorf("attached slots = %d, want 1", n)
		}
	})

	t.Run("a pod-supplied K3SM_INTERCONNECT_* value is overridden", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, &fakeAliases{})
		pod := icPod("default", "spoof")
		pod.Spec.Containers[0].Env = []corev1.EnvVar{
			{Name: podnet.EnvInterconnectIP, Value: "169.254.0.200"},
			{Name: podnet.EnvInterconnectCIDRs, Value: "169.254.0.0/16"},
			{Name: "K3SM_INTERCONNECT_EXTRA", Value: "x"},
			{Name: "APP", Value: "kept"},
		}
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		env := h.env(t, string(pod.UID))
		if got := env[podnet.EnvInterconnectIP]; len(got) != 1 || got[0] != icAddr(t, 2).String() {
			t.Errorf("%s = %v, want only the attached address", podnet.EnvInterconnectIP, got)
		}
		if got := env[podnet.EnvInterconnectCIDRs]; len(got) != 1 || got[0] != cidr {
			t.Errorf("%s = %v, want only %s", podnet.EnvInterconnectCIDRs, got, cidr)
		}
		if _, ok := env["K3SM_INTERCONNECT_EXTRA"]; ok {
			t.Error("a pod-supplied K3SM_INTERCONNECT_EXTRA survived")
		}
		if got := env["APP"]; len(got) != 1 || got[0] != "kept" {
			t.Errorf("the pod's own APP env = %v, want [kept]", got)
		}
	})

	t.Run("an un-annotated pod never keeps K3SM_INTERCONNECT_IP or _CIDRS", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, &fakeAliases{})
		pod := runtimedPod("default", "plainspoof")
		pod.Spec.Containers[0].Env = []corev1.EnvVar{
			{Name: podnet.EnvInterconnectIP, Value: icAddr(t, 4).String()},
			{Name: podnet.EnvInterconnectCIDRs, Value: cidr},
			{Name: "APP", Value: "kept"},
		}
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		env := h.env(t, string(pod.UID))
		for _, k := range []string{podnet.EnvInterconnectIP, podnet.EnvInterconnectCIDRs} {
			if v, ok := env[k]; ok {
				t.Errorf("an un-annotated pod kept its own %s=%v", k, v)
			}
		}
		if got := env["APP"]; len(got) != 1 || got[0] != "kept" {
			t.Errorf("the pod's own APP env = %v, want [kept]", got)
		}
		if ensured, _ := h.aliases.calls(); len(ensured) != 0 {
			t.Errorf("an un-annotated pod asked the helper for %v", ensured)
		}
	})

	t.Run("names beyond the node's interconnect are dropped and logged", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, &fakeAliases{})
		pod := icPod("default", "two")
		pod.Annotations[netv1alpha1.AnnotationInterconnects] = "thunderbolt, other"
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if r := h.r.interconnect.record(string(pod.UID)); r == nil || !r.attached {
			t.Fatalf("record = %+v, want attached to thunderbolt", r)
		}
		if logs := h.logs.String(); !strings.Contains(logs, "dropped=other") {
			t.Errorf("the dropped name was not logged:\n%s", logs)
		}
	})

	t.Run("an unreadable desired annotation is warned once", func(t *testing.T) {
		h := newICHarness(t, `{"schema":1,"interconnect":"thunderbolt","fallback":"sideways"}`, true, &fakeAliases{})
		for i := range 3 {
			if err := h.r.CreatePod(ctx, icPod("default", fmt.Sprintf("u%d", i))); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
		}
		if n := strings.Count(h.logs.String(), "desired annotation is unreadable"); n != 1 {
			t.Errorf("the parse error was logged %d times, want once:\n%s", n, h.logs.String())
		}
	})

	// Refusals under fallback network: the pod starts, without the address and
	// with the condition False carrying the named reason, and a Warning Event.
	// A node that is not a member (no desired annotation) cannot know the
	// fallback and degrades to network the same way.
	for _, tc := range []struct {
		name    string
		desired func(t *testing.T) string
		synced  bool
		aliases *fakeAliases
		pod     func() *corev1.Pod
		reason  string
		ensures bool
	}{
		{
			name: "namespace not allowed",
			desired: func(t *testing.T) string {
				return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, []string{"ml"})
			},
			aliases: &fakeAliases{}, pod: func() *corev1.Pod { return icPod("default", "p") },
			reason: ReasonInterconnectNamespaceNotAllowed,
		},
		{
			name:    "desired annotation absent",
			desired: func(*testing.T) string { return "" },
			aliases: &fakeAliases{}, pod: func() *corev1.Pod { return icPod("default", "p") },
			reason: ReasonInterconnectNotMember,
		},
		{
			name:    "desired annotation unreadable",
			desired: func(*testing.T) string { return "thunderbolt;fallback=network" },
			aliases: &fakeAliases{}, pod: func() *corev1.Pod { return icPod("default", "p") },
			reason: ReasonInterconnectNotMember,
		},
		{
			name:    "desired names another interconnect than the pod's",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			aliases: &fakeAliases{},
			pod: func() *corev1.Pod {
				p := icPod("default", "p")
				p.Annotations[netv1alpha1.AnnotationInterconnects] = "other"
				return p
			},
			reason: ReasonInterconnectNotMember,
		},
		{
			name:    "no root helper",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			pod:     func() *corev1.Pod { return icPod("default", "p") },
			reason:  ReasonInterconnectNoHelper,
		},
		{
			name:    "netd: no bridge0",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			aliases: &fakeAliases{ensureErr: fmt.Errorf("netd EnsureInterconnectAlias: %w", wire.ErrInterconnectNoBridge)},
			pod:     func() *corev1.Pod { return icPod("default", "p") },
			reason:  wire.ReasonInterconnectNoBridge, ensures: true,
		},
		{
			name:    "netd: index out of range",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			aliases: &fakeAliases{ensureErr: fmt.Errorf("netd: %w", wire.ErrInterconnectIndexOutOfRange)},
			pod:     func() *corev1.Pod { return icPod("default", "p") },
			reason:  wire.ReasonInterconnectIndexOutOfRange, ensures: true,
		},
		{
			name:    "netd: helper too old",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			aliases: &fakeAliases{ensureErr: fmt.Errorf("verb: %w", wire.ErrHelperTooOld)},
			pod:     func() *corev1.Pod { return icPod("default", "p") },
			reason:  interconnect.ReasonHelperTooOld, ensures: true,
		},
		{
			name:    "netd: unnamed error",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			aliases: &fakeAliases{ensureErr: errors.New("connection refused")},
			pod:     func() *corev1.Pod { return icPod("default", "p") },
			reason:  ReasonInterconnectHelperError, ensures: true,
		},
		{
			name:    "netd: an address of the wrong slot is refused",
			desired: func(t *testing.T) string { return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil) },
			aliases: &fakeAliases{lie: true},
			pod:     func() *corev1.Pod { return icPod("default", "p") },
			reason:  ReasonInterconnectHelperError, ensures: true,
		},
	} {
		t.Run("fallback network: "+tc.name, func(t *testing.T) {
			h := newICHarness(t, tc.desired(t), true, tc.aliases)
			pod := tc.pod()
			pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: podnet.EnvInterconnectIP, Value: "169.254.0.30"}}
			if err := h.r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod under fallback network: %v", err)
			}
			env := h.env(t, string(pod.UID))
			for k := range env {
				if strings.HasPrefix(k, envInterconnectPrefix) {
					t.Errorf("a refused pod carries %s=%v", k, env[k])
				}
			}
			c := h.condition(t, pod)
			if c == nil || c.Status != corev1.ConditionFalse || c.Reason != tc.reason {
				t.Fatalf("condition = %+v, want False with reason %s", c, tc.reason)
			}
			if attachedSlots(h.r.interconnect) != 0 {
				t.Error("a refused attach holds a slot")
			}
			if ev := h.events(); !strings.Contains(ev, "Warning "+ReasonInterconnectFailed) || !strings.Contains(ev, tc.reason) || !strings.Contains(ev, "fallback network") {
				t.Errorf("events = %q, want a Warning %s naming %s and the network fallback", ev, ReasonInterconnectFailed, tc.reason)
			}
			if tc.aliases != nil {
				ensured, _ := tc.aliases.calls()
				if got := len(ensured) > 0; got != tc.ensures {
					t.Errorf("root helper asked = %v (%v), want %v", got, ensured, tc.ensures)
				}
			}
		})
	}

	t.Run("fallback none holds the create with a Warning Event", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNone, []string{"ml"}), true, &fakeAliases{})
		pod := icPod("default", "held")
		err := h.r.CreatePod(ctx, pod)
		if err == nil || !strings.Contains(err.Error(), ReasonInterconnectNamespaceNotAllowed) {
			t.Fatalf("CreatePod = %v, want a hold naming %s", err, ReasonInterconnectNamespaceNotAllowed)
		}
		if h.created(string(pod.UID)) {
			t.Error("a held pod reached the runtime")
		}
		if ev := h.events(); !strings.Contains(ev, "Warning "+ReasonInterconnectFailed) || !strings.Contains(ev, ReasonInterconnectNamespaceNotAllowed) {
			t.Errorf("events = %q, want a Warning %s naming the reason", ev, ReasonInterconnectFailed)
		}
		if h.r.interconnect.record(string(pod.UID)) != nil {
			t.Error("a held attach was recorded; the retry would never re-check")
		}
	})

	t.Run("an unknown desired annotation holds the create under any fallback", func(t *testing.T) {
		h := newICHarness(t, "", false, &fakeAliases{})
		pod := icPod("default", "early")
		if err := h.r.CreatePod(ctx, pod); !errors.Is(err, errInterconnectDesiredUnknown) {
			t.Fatalf("CreatePod = %v, want errInterconnectDesiredUnknown", err)
		}
		if h.created(string(pod.UID)) {
			t.Error("a pod was started before its membership was known")
		}
	})

	t.Run("vm and container-vm are refused", func(t *testing.T) {
		for _, rc := range []string{string(runtimev1.HandlerVM), runtimeClassContainerVM} {
			for _, fb := range []netv1alpha1.InterconnectFallback{netv1alpha1.InterconnectFallbackNetwork, netv1alpha1.InterconnectFallbackNone} {
				h := newICHarness(t, desiredValue(t, fb, nil), true, &fakeAliases{})
				pod := icPod("default", "guest")
				pod.Spec.RuntimeClassName = &rc
				// The refusal is decided before the root helper is asked, under
				// the interconnect's fallback, like every other refusal.
				err := h.r.interconnect.attach(ctx, pod)
				r := h.r.interconnect.record(string(pod.UID))
				switch fb {
				case netv1alpha1.InterconnectFallbackNone:
					if err == nil || !strings.Contains(err.Error(), netv1alpha1.ReasonInterconnectUnsupportedRuntime) {
						t.Errorf("%s/none: attach = %v, want a hold naming the reason", rc, err)
					}
				default:
					if err != nil || r == nil || r.attached || r.cond.Reason != netv1alpha1.ReasonInterconnectUnsupportedRuntime {
						t.Errorf("%s/network: attach = %v, record %+v, want refused with %s", rc, err, r, netv1alpha1.ReasonInterconnectUnsupportedRuntime)
					}
				}
				if ensured, _ := h.aliases.calls(); len(ensured) != 0 {
					t.Errorf("%s: the root helper was asked for slots %v", rc, ensured)
				}
			}
		}
	})

	t.Run("slot 1 only for a verified MLXModel rank", func(t *testing.T) {
		mlxGV := "mlx.k3sm.io/v1alpha1"
		for _, tc := range []struct {
			name string
			pod  *corev1.Pod
			slot int
		}{
			{"matching namespace, name and UID", mlxOwned(icPod("ml", "rank"), mlxGV, "llm", modelUID, true), netv1alpha1.InterconnectSlotMLXRank},
			{"forged UID", mlxOwned(icPod("ml", "rank"), mlxGV, "llm", "forged-uid", true), netv1alpha1.InterconnectSlotFirstPod},
			{"real UID, other namespace", mlxOwned(icPod("other", "rank"), mlxGV, "llm", modelUID, true), netv1alpha1.InterconnectSlotFirstPod},
			{"real UID, other name", mlxOwned(icPod("ml", "rank"), mlxGV, "not-llm", modelUID, true), netv1alpha1.InterconnectSlotFirstPod},
			{"listed model, wrong group", mlxOwned(icPod("ml", "rank"), "evil.io/v1", "llm", modelUID, true), netv1alpha1.InterconnectSlotFirstPod},
			{"listed model, not the controller", mlxOwned(icPod("ml", "rank"), mlxGV, "llm", modelUID, false), netv1alpha1.InterconnectSlotFirstPod},
			{"no owner", icPod("ml", "rank"), netv1alpha1.InterconnectSlotFirstPod},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil, llm), true, &fakeAliases{})
				if err := h.r.CreatePod(ctx, tc.pod); err != nil {
					t.Fatalf("CreatePod: %v", err)
				}
				r := h.r.interconnect.record(string(tc.pod.UID))
				if r == nil || !r.attached || r.slot != tc.slot || r.addr != icAddr(t, tc.slot) {
					t.Fatalf("record = %+v, want slot %d", r, tc.slot)
				}
				if got := h.env(t, string(tc.pod.UID))[podnet.EnvInterconnectIP]; len(got) != 1 || got[0] != icAddr(t, tc.slot).String() {
					t.Errorf("env %s = %v, want slot %d's address", podnet.EnvInterconnectIP, got, tc.slot)
				}
			})
		}
	})

	t.Run("slots exhausted", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil, llm, modelRef("ml", "llm2", "uid-2")), true, &fakeAliases{})
		for i := range netv1alpha1.MaxInterconnectSlot - netv1alpha1.InterconnectSlotFirstPod + 1 {
			if err := h.r.CreatePod(ctx, icPod("default", fmt.Sprintf("p%d", i))); err != nil {
				t.Fatalf("CreatePod p%d: %v", i, err)
			}
		}
		extra := icPod("default", "seventh")
		if err := h.r.CreatePod(ctx, extra); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if c := h.condition(t, extra); c == nil || c.Status != corev1.ConditionFalse || c.Reason != netv1alpha1.ReasonInterconnectSlotsExhausted {
			t.Errorf("seventh general pod condition = %+v, want False %s", c, netv1alpha1.ReasonInterconnectSlotsExhausted)
		}
		// Slot 1 is never handed to a general pod, so the rank still gets it;
		// a second rank finds it taken and is refused, never moved to 2..7.
		rank := mlxOwned(icPod("ml", "rank0"), "mlx.k3sm.io/v1alpha1", "llm", modelUID, true)
		if err := h.r.CreatePod(ctx, rank); err != nil {
			t.Fatalf("CreatePod rank0: %v", err)
		}
		if r := h.r.interconnect.record(string(rank.UID)); r == nil || r.slot != netv1alpha1.InterconnectSlotMLXRank {
			t.Fatalf("rank0 record = %+v, want slot 1", r)
		}
		second := mlxOwned(icPod("ml", "rank1"), "mlx.k3sm.io/v1alpha1", "llm2", "uid-2", true)
		if err := h.r.CreatePod(ctx, second); err != nil {
			t.Fatalf("CreatePod rank1: %v", err)
		}
		if c := h.condition(t, second); c == nil || c.Reason != netv1alpha1.ReasonInterconnectSlotsExhausted {
			t.Errorf("second rank condition = %+v, want %s", c, netv1alpha1.ReasonInterconnectSlotsExhausted)
		}
		if n := attachedSlots(h.r.interconnect); n != netv1alpha1.MaxInterconnectSlot {
			t.Errorf("attached slots = %d, want %d", n, netv1alpha1.MaxInterconnectSlot)
		}
	})

	t.Run("teardown removes the alias and frees the slot, never slot 0", func(t *testing.T) {
		aliases := &fakeAliases{}
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, aliases)
		first := icPod("default", "first")
		if err := h.r.CreatePod(ctx, first); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := h.r.DeletePod(ctx, first); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if _, removed := aliases.calls(); len(removed) != 1 || removed[0] != netv1alpha1.InterconnectSlotFirstPod {
			t.Fatalf("removed slots = %v, want [2]", removed)
		}
		if n := attachedSlots(h.r.interconnect); n != 0 {
			t.Errorf("attached slots after delete = %d, want 0", n)
		}
		next := icPod("default", "next")
		if err := h.r.CreatePod(ctx, next); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if r := h.r.interconnect.record(string(next.UID)); r == nil || r.slot != netv1alpha1.InterconnectSlotFirstPod {
			t.Errorf("the freed slot was not reused: %+v", r)
		}
		// A refused (unattached) pod's teardown asks the helper nothing.
		refused := newICHarness(t, "", true, &fakeAliases{})
		p := icPod("default", "refused")
		if err := refused.r.CreatePod(ctx, p); err != nil {
			t.Fatal(err)
		}
		if err := refused.r.DeletePod(ctx, p); err != nil {
			t.Fatal(err)
		}
		ensured, removed := refused.aliases.calls()
		if len(ensured)+len(removed) != 0 {
			t.Errorf("a refused pod's lifecycle asked the helper: ensured %v removed %v", ensured, removed)
		}
		for _, s := range append(append([]int(nil), removed...), aliasesRemoved(aliases)...) {
			if s == netv1alpha1.InterconnectSlotNode {
				t.Fatal("the provider removed slot 0")
			}
		}
	})

	t.Run("a failed ensure frees its slot", func(t *testing.T) {
		aliases := &fakeAliases{ensureErr: errors.New("boom")}
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, aliases)
		if err := h.r.CreatePod(ctx, icPod("default", "a")); err != nil {
			t.Fatal(err)
		}
		aliases.mu.Lock()
		aliases.ensureErr = nil
		aliases.mu.Unlock()
		b := icPod("default", "b")
		if err := h.r.CreatePod(ctx, b); err != nil {
			t.Fatal(err)
		}
		if r := h.r.interconnect.record(string(b.UID)); r == nil || r.slot != netv1alpha1.InterconnectSlotFirstPod {
			t.Errorf("after a failed ensure the next pod got %+v, want slot 2", r)
		}
	})

	t.Run("a pod that asks for nothing is untouched", func(t *testing.T) {
		h := newICHarness(t, desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil), true, &fakeAliases{})
		pod := runtimedPod("default", "plain")
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached), Status: corev1.ConditionTrue}}
		if err := h.r.CreatePod(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if c := h.condition(t, pod); c != nil {
			t.Errorf("a pod without the annotation carries %+v", c)
		}
		if ensured, _ := h.aliases.calls(); len(ensured) != 0 {
			t.Errorf("the helper was asked for %v", ensured)
		}
	})

	t.Run("slot bookkeeping survives a node-daemon restart", func(t *testing.T) {
		started := time.Unix(1_700_000_000, 0)
		attachedAt := metav1.NewTime(started)
		survivor := attachTestPod("survivor", corev1.PodRunning, "100.64.0.7", started)
		survivor.Annotations = map[string]string{netv1alpha1.AnnotationInterconnects: netv1alpha1.MediumThunderbolt}
		survivor.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached), Status: corev1.ConditionTrue,
			Reason: netv1alpha1.MediumThunderbolt, Message: icAddr(t, 3).String(), LastTransitionTime: attachedAt,
		}}
		// A slot-1 condition restored before the desired annotation is known: a
		// forged rank naming the real UID under another name.
		slot1 := func(name, owner string) corev1.Pod {
			p := attachTestPod(name, corev1.PodRunning, "", started)
			p.Namespace = "ml"
			p.Annotations = map[string]string{netv1alpha1.AnnotationInterconnects: netv1alpha1.MediumThunderbolt}
			mlxOwned(&p, "mlx.k3sm.io/v1alpha1", owner, modelUID, true)
			p.Status.Conditions = []corev1.PodCondition{{
				Type: corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached), Status: corev1.ConditionTrue,
				Message: icAddr(t, 1).String(),
			}}
			return p
		}
		forged := slot1("forged", "not-llm")
		forged.Status.PodIP = "100.64.0.8"
		rt := newAttachRuntime()
		for id, ip := range map[string]string{"uid-survivor": "100.64.0.7", "uid-forged": "100.64.0.8"} {
			rt.results[id] = attachResult{status: &runtimev1.PodStatus{PodId: id, Phase: runtimev1.PodPhase_POD_PHASE_RUNNING, PodIp: ip}}
		}
		aliases := &fakeAliases{}
		ipam := newFakeIPAM(t, "100.64.0.0/24")
		r := newRuntimedWith(rt, RuntimedConfig{
			NodeName: "n", NodeIP: testNodeIP, Root: t.TempDir(), PodLogsDir: t.TempDir(),
			Network: NewPodNetAdapter(ipam, testNodeIP, nil),
			// Unknown this early: the restore must not depend on it.
			Interconnect: InterconnectConfig{Aliases: aliases, Desired: func() (string, bool) { return "", false }},
		}, nil, nil)
		r.podSource = &fakePodSource{listed: []corev1.Pod{survivor, forged}}
		r.adoptNodePods(ctx, rt)

		rec := r.interconnect.record("uid-survivor")
		if rec == nil || !rec.attached || rec.slot != 3 || rec.addr != icAddr(t, 3) {
			t.Fatalf("survivor record = %+v, want slot 3 restored", rec)
		}
		if !rec.cond.LastTransitionTime.Equal(&attachedAt) {
			t.Errorf("restored condition transition = %v, want the original %v", rec.cond.LastTransitionTime, attachedAt)
		}
		var boxIP string
		for _, e := range rt.boxes["uid-survivor"].GetContainers()[0].GetEnv() {
			if e.GetName() == podnet.EnvInterconnectIP {
				boxIP = e.GetValue()
			}
		}
		if boxIP != icAddr(t, 3).String() {
			t.Errorf("re-attach box %s = %q, want the restored %s", podnet.EnvInterconnectIP, boxIP, icAddr(t, 3))
		}
		// Unknown desired: the forged slot-1 pod is held provisionally.
		if fr := r.interconnect.record("uid-forged"); fr == nil || !fr.attached || !fr.provisional || fr.slot != 1 {
			t.Fatalf("forged record before the re-check = %+v, want provisional slot 1", fr)
		}

		// The desired annotation syncs: the re-check demotes the forged rank.
		r.interconnect.cfg.Desired = func() (string, bool) {
			return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil, llm), true
		}
		r.interconnect.recheck(ctx)
		fr := r.interconnect.record("uid-forged")
		if fr == nil || fr.attached || fr.cond.Status != corev1.ConditionFalse || fr.cond.Reason != ReasonInterconnectModelMismatch {
			t.Fatalf("forged record after the re-check = %+v, want demoted with %s", fr, ReasonInterconnectModelMismatch)
		}
		if _, removed := aliases.calls(); len(removed) != 1 || removed[0] != 1 {
			t.Errorf("demotion removed slots %v, want [1]", removed)
		}
		box := &runtimev1.PodBox{Containers: []*runtimev1.Container{{Env: []*runtimev1.EnvVar{{Name: podnet.EnvInterconnectIP, Value: icAddr(t, 1).String()}}}}}
		r.interconnect.injectEnv(&forged, box)
		if len(box.GetContainers()[0].GetEnv()) != 0 {
			t.Errorf("a demoted pod's rebuilt box keeps %v", box.GetContainers()[0].GetEnv())
		}

		// A real rank, restored provisionally on the now-free slot 1, is
		// confirmed by the re-check.
		r.interconnect.cfg.Desired = func() (string, bool) { return "", false }
		real := slot1("real", "llm")
		r.interconnect.restore(ctx, &real)
		r.interconnect.cfg.Desired = func() (string, bool) {
			return desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, nil, llm), true
		}
		r.interconnect.recheck(ctx)
		if rr := r.interconnect.record("uid-real"); rr == nil || !rr.attached || rr.provisional || rr.slot != 1 {
			t.Errorf("real rank after the re-check = %+v, want confirmed on slot 1", rr)
		}

		// With desired readable at restore time, a forged slot 1 is refused at once.
		r.interconnect.detach(&real)
		late := slot1("late", "not-llm")
		r.interconnect.restore(ctx, &late)
		if lr := r.interconnect.record("uid-late"); lr == nil || lr.attached || lr.cond.Reason != ReasonInterconnectModelMismatch {
			t.Errorf("late forged record = %+v, want refused with %s", lr, ReasonInterconnectModelMismatch)
		}

		// A vm pod carrying an attach condition is never restored.
		vmClass := string(runtimev1.HandlerVM)
		vm := attachTestPod("vmpod", corev1.PodRunning, "", started)
		vm.Annotations = map[string]string{netv1alpha1.AnnotationInterconnects: netv1alpha1.MediumThunderbolt}
		vm.Spec.RuntimeClassName = &vmClass
		vm.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached), Status: corev1.ConditionTrue,
			Message: icAddr(t, 5).String(),
		}}
		r.interconnect.restore(ctx, &vm)
		if vr := r.interconnect.record("uid-vmpod"); vr == nil || vr.attached || vr.cond.Reason != netv1alpha1.ReasonInterconnectUnsupportedRuntime {
			t.Errorf("vm record = %+v, want refused with %s", vr, netv1alpha1.ReasonInterconnectUnsupportedRuntime)
		}
		if _, removed := aliases.calls(); !slices.Contains(removed, 5) {
			t.Errorf("the vm pod's alias was not removed: removed %v", removed)
		}

		// A new pod after the restart never gets the survivor's slot.
		for i := range 2 {
			p := icPod("default", fmt.Sprintf("after%d", i))
			if err := r.CreatePod(ctx, p); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if got := r.interconnect.record(string(p.UID)); got == nil || got.slot == 3 {
				t.Fatalf("a post-restart pod got %+v; slot 3 is the survivor's", got)
			}
		}
	})
}

func aliasesRemoved(f *fakeAliases) []int {
	_, removed := f.calls()
	return removed
}

// attachedSlots is the number of pod slots (1..MaxInterconnectSlot) held.
func attachedSlots(a *interconnectAttacher) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for s := netv1alpha1.InterconnectSlotMLXRank; s <= netv1alpha1.MaxInterconnectSlot; s++ {
		if a.slots[s] != "" {
			n++
		}
	}
	return n
}
