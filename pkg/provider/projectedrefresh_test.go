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
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	"k3sm.io/runtimed/pkg/mount"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// fakeRefresher stands in for the in-process runtime's RefreshProjectedVolumes.
// Each call is recorded with the tick it happened in; the scripted result for a
// pod id is returned, and optional reads run through the provider's resolver on
// the call's context, as the real runtime's mount.Refresh does.
type fakeRefresher struct {
	mu       sync.Mutex
	tick     int
	calls    map[int][]string // tick -> pod ids refreshed
	results  map[string]fakeRefreshResult
	resolver mount.Resolver
	reads    []string // ConfigMap names each call reads through resolver
	idents   map[string]string
	called   chan string
}

type fakeRefreshResult struct {
	res mount.RefreshResult
	err error
}

func newFakeRefresher() *fakeRefresher {
	return &fakeRefresher{calls: map[int][]string{}, results: map[string]fakeRefreshResult{}, idents: map[string]string{}}
}

func (f *fakeRefresher) RefreshProjectedVolumes(ctx context.Context, podID string) (mount.RefreshResult, error) {
	f.mu.Lock()
	f.calls[f.tick] = append(f.calls[f.tick], podID)
	if id, ok := podIdentityFromContext(ctx); ok {
		f.idents[podID] = string(id.uid)
	}
	out := f.results[podID]
	reads := slices.Clone(f.reads)
	called := f.called
	f.mu.Unlock()
	for _, name := range reads {
		if _, err := f.resolver.ConfigMap(ctx, "default", name); err != nil {
			return mount.RefreshResult{}, err
		}
	}
	if called != nil {
		called <- podID
	}
	return out.res, out.err
}

func (f *fakeRefresher) set(podID string, res mount.RefreshResult, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[podID] = fakeRefreshResult{res: res, err: err}
}

func (f *fakeRefresher) nextTick() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tick++
}

func (f *fakeRefresher) callsIn(tick int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	got := slices.Clone(f.calls[tick])
	slices.Sort(got)
	return got
}

// refreshFixture is a runtimed provider with a fake refresher and a set of
// tracked pods, driven one tick at a time.
type refreshFixture struct {
	r   *runtimedRuntime
	f   *fakeRefresher
	rec *record.FakeRecorder
	log *captureHandler
}

func newRefreshFixture(t *testing.T, resolver mount.Resolver) *refreshFixture {
	t.Helper()
	rec := record.NewFakeRecorder(64)
	logs := newCaptureHandler()
	r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
	}, resolver, slog.New(logs))
	if r.refresher != nil {
		t.Fatal("a fake runtime server must not satisfy projectedRefresher")
	}
	f := newFakeRefresher()
	f.resolver = resolver
	r.refresher = f
	return &refreshFixture{r: r, f: f, rec: rec, log: logs}
}

// track installs pod as tracked and returns its track.
func (x *refreshFixture) track(pod *corev1.Pod) *podTrack {
	t := &podTrack{pod: pod}
	x.r.mu.Lock()
	x.r.track[string(pod.UID)] = t
	x.r.mu.Unlock()
	return t
}

// tick runs one refresh tick.
func (x *refreshFixture) tick() {
	x.f.nextTick()
	x.r.refreshProjectedOnce(context.Background())
}

// events drains every recorded Event.
func (x *refreshFixture) events() []string {
	var out []string
	for {
		select {
		case e := <-x.rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// warnings returns the Warn-level refresh records logged so far.
func (x *refreshFixture) warnings() []capturedRecord {
	var out []capturedRecord
	for _, r := range x.log.captured() {
		if r.level == slog.LevelWarn && strings.Contains(r.message, "projected volume refresh") {
			out = append(out, r)
		}
	}
	return out
}

func failed(name string, err error) mount.VolumeRefresh {
	return mount.VolumeRefresh{Name: name, Outcome: mount.RefreshFailed, Err: err}
}

func withVolumes(vs ...mount.VolumeRefresh) mount.RefreshResult {
	return mount.RefreshResult{Volumes: vs}
}

// TestProjectedRefreshLoopCallsRuntimeAndReportsFailures is the B234 gate for
// the provider half of the projected-volume refresh: once per tick the provider
// asks the in-process runtime to refresh every running non-vm pod it tracks,
// with the pod's identity bound for token re-minting; a failed volume is one
// Warning Event per volume per failure class; vm pods and the runtime's
// unsupported/not-found answers are silent; pods sharing a ConfigMap cost one
// apiserver read per tick; and the loop ends with its context.
func TestProjectedRefreshLoopCallsRuntimeAndReportsFailures(t *testing.T) {
	t.Run("refreshes every running non-vm pod once per tick with its identity bound", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		a, b := runtimedPod("default", "a"), runtimedPod("default", "b")
		x.track(a)
		x.track(b)
		vmPod := runtimedPod("default", "guest")
		vm := "vm"
		vmPod.Spec.RuntimeClassName = &vm
		x.track(vmPod)
		x.track(runtimedPod("default", "leaving")).markDeleting()
		parked := x.track(runtimedPod("default", "parked"))
		parked.parked = &createFailure{}

		x.tick()
		x.tick()
		for tick := 1; tick <= 2; tick++ {
			if got, want := x.f.callsIn(tick), []string{"uid-a", "uid-b"}; !slices.Equal(got, want) {
				t.Fatalf("tick %d refreshed %v, want %v (vm, deleting and parked pods excluded)", tick, got, want)
			}
		}
		for _, id := range []string{"uid-a", "uid-b"} {
			if x.f.idents[id] != id {
				t.Errorf("pod %s refreshed with bound identity uid %q, want its own", id, x.f.idents[id])
			}
		}
		if ev := x.events(); len(ev) != 0 {
			t.Errorf("a clean tick recorded events %v", ev)
		}
	})

	t.Run("a failed volume is one Warning Event per volume per class", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		pod := runtimedPod("default", "web")
		x.track(pod)
		gone := fmt.Errorf("configMap default/cfg: %w", os.ErrNotExist)
		forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "sec", errors.New("denied"))
		x.f.set("uid-web", withVolumes(
			failed("cfg", gone),
			failed("sec", fmt.Errorf("secret default/sec: %w", forbidden)),
			mount.VolumeRefresh{Name: "ok", Outcome: mount.RefreshUpdated},
			mount.VolumeRefresh{Name: "sub", Outcome: mount.RefreshSkipped, Reason: "subPath mounts are never refreshed"},
		), errors.New("refresh projected volumes: 2 volumes failed"))

		x.tick()
		x.tick()
		x.tick()
		ev := x.events()
		if len(ev) != 2 {
			t.Fatalf("three failing ticks recorded %d events %v, want exactly one per volume per class (2)", len(ev), ev)
		}
		for _, want := range []string{`volume "cfg" failed (NotFound)`, `volume "sec" failed (Forbidden)`} {
			if !slices.ContainsFunc(ev, func(e string) bool {
				return strings.HasPrefix(e, "Warning "+reasonProjectedVolumeRefreshFailed+" ") && strings.Contains(e, want)
			}) {
				t.Errorf("events %v: none is a %s Warning naming %s", ev, reasonProjectedVolumeRefreshFailed, want)
			}
		}
		if w := x.warnings(); len(w) != 6 {
			t.Errorf("got %d Warn records, want one per failed volume per tick (6)", len(w))
		}

		// A new failure class on the same volume is a new Event.
		x.f.set("uid-web", withVolumes(failed("cfg", context.DeadlineExceeded)), errors.New("failed"))
		x.tick()
		if ev := x.events(); len(ev) != 1 || !strings.Contains(ev[0], "(Timeout)") {
			t.Fatalf("a new class recorded %v, want one Timeout event", ev)
		}

		// A volume that refreshes again is forgotten: its next failure is announced.
		x.f.set("uid-web", withVolumes(mount.VolumeRefresh{Name: "cfg", Outcome: mount.RefreshUnchanged}), nil)
		x.tick()
		x.f.set("uid-web", withVolumes(failed("cfg", gone)), errors.New("failed"))
		x.tick()
		if ev := x.events(); len(ev) != 1 || !strings.Contains(ev[0], "(NotFound)") {
			t.Fatalf("after recovery a repeat failure recorded %v, want one NotFound event", ev)
		}

		// The bookkeeping dies with the track.
		x.r.mu.Lock()
		delete(x.r.track, "uid-web")
		x.r.mu.Unlock()
		fresh := x.track(pod)
		if len(fresh.refreshWarned) != 0 {
			t.Fatalf("a new track inherited refresh warnings %v", fresh.refreshWarned)
		}
	})

	t.Run("a housekeeping failure after the flip is a warning, never a failure", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		x.track(runtimedPod("default", "web"))
		gone := fmt.Errorf("configMap default/cfg: %w", os.ErrNotExist)
		x.f.set("uid-web", withVolumes(failed("cfg", gone)), errors.New("failed"))
		x.tick()
		if ev := x.events(); len(ev) != 1 || !strings.Contains(ev[0], reasonProjectedVolumeRefreshFailed) {
			t.Fatalf("setup: recorded %v, want one failure event", ev)
		}

		prune := errors.New("remove previous generation: operation not permitted")
		warned := withVolumes(mount.VolumeRefresh{Name: "cfg", Outcome: mount.RefreshUpdatedWithWarnings, Err: prune})
		x.f.set("uid-web", warned, errors.New("refresh volume cfg: updated, but housekeeping failed"))
		x.tick()
		x.tick()
		ev := x.events()
		if len(ev) != 1 {
			t.Fatalf("two ticks with a housekeeping failure recorded %v, want exactly one event", ev)
		}
		if !strings.HasPrefix(ev[0], "Warning "+reasonProjectedVolumeRefreshWarning+" ") ||
			!strings.Contains(ev[0], `"cfg"`) || !strings.Contains(ev[0], "operation not permitted") {
			t.Fatalf("event %q: want a %s Warning naming the volume and the housekeeping error", ev[0], reasonProjectedVolumeRefreshWarning)
		}
		w := x.warnings()
		var generic int
		for _, r := range w {
			if r.message == "projected volume refresh failed" {
				generic++
			}
		}
		if generic != 0 {
			t.Errorf("a warnings outcome fell through to the pod-level failure log %d times", generic)
		}
		if !slices.ContainsFunc(w, func(r capturedRecord) bool {
			return strings.Contains(r.message, "housekeeping failed") && r.attrs["volume"] == "cfg"
		}) {
			t.Errorf("no Warn record names the volume's housekeeping failure: %v", w)
		}

		// The flip landed, so the earlier failure is forgotten: a new failure of
		// the same class is announced again.
		x.f.set("uid-web", withVolumes(failed("cfg", gone)), errors.New("failed"))
		x.tick()
		if ev := x.events(); len(ev) != 1 || !strings.Contains(ev[0], reasonProjectedVolumeRefreshFailed) {
			t.Fatalf("after a warned flip a repeat failure recorded %v, want one failure event", ev)
		}
	})

	t.Run("the warning bookkeeping is bounded per pod", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		x.track(runtimedPod("default", "many"))
		var vs []mount.VolumeRefresh
		for i := range maxRefreshWarnings + 10 {
			vs = append(vs, failed(fmt.Sprintf("v%d", i), os.ErrNotExist))
		}
		x.f.set("uid-many", withVolumes(vs...), errors.New("failed"))
		x.rec = record.NewFakeRecorder(4 * maxRefreshWarnings)
		x.r.recorder = x.rec
		x.tick()
		if ev := x.events(); len(ev) != maxRefreshWarnings {
			t.Fatalf("recorded %d events, want the cap %d", len(ev), maxRefreshWarnings)
		}
	})

	t.Run("unsupported and not-found answers are silent", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		x.track(runtimedPod("default", "vmish"))
		x.track(runtimedPod("default", "gone"))
		x.f.set("uid-vmish", mount.RefreshResult{}, fmt.Errorf("pod uid-vmish: %w", runtimed.ErrProjectedRefreshUnsupported))
		x.f.set("uid-gone", mount.RefreshResult{}, fmt.Errorf("refresh: %w", runtimed.ErrPodNotFound))
		x.tick()
		if got := x.f.callsIn(1); len(got) != 2 {
			t.Fatalf("refreshed %v, want both pods asked", got)
		}
		if ev := x.events(); len(ev) != 0 {
			t.Errorf("recorded events %v, want none", ev)
		}
		if w := x.warnings(); len(w) != 0 {
			t.Errorf("logged warnings %v, want none", w)
		}
	})

	t.Run("a whole-pod failure is logged but records no Event", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		x.track(runtimedPod("default", "odd"))
		x.f.set("uid-odd", mount.RefreshResult{}, errors.New("pod uid-odd is being deleted"))
		x.tick()
		if ev := x.events(); len(ev) != 0 {
			t.Errorf("recorded events %v, want none", ev)
		}
		if w := x.warnings(); len(w) != 1 {
			t.Errorf("logged %d warnings, want 1", len(w))
		}
	})

	t.Run("the tick cache coalesces apiserver reads", func(t *testing.T) {
		cs := k8sfake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "shared"},
			Data:       map[string]string{"k": "v"},
		})
		var mu sync.Mutex
		gets := map[string]int{}
		cs.PrependReactor("get", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
			mu.Lock()
			defer mu.Unlock()
			gets[a.(k8stesting.GetAction).GetName()]++
			return false, nil, nil
		})
		count := func(name string) int {
			mu.Lock()
			defer mu.Unlock()
			return gets[name]
		}
		x := newRefreshFixture(t, newTestKubeResolver(cs))
		for _, n := range []string{"a", "b", "c"} {
			x.track(runtimedPod("default", n))
		}
		// Each pod reads the shared ConfigMap twice and a missing one once.
		x.f.reads = []string{"shared", "shared"}
		x.tick()
		if got := count("shared"); got != 1 {
			t.Fatalf("one tick over 3 pods issued %d GETs of the shared ConfigMap, want 1", got)
		}
		x.tick()
		if got := count("shared"); got != 2 {
			t.Fatalf("two ticks issued %d GETs, want 2 (the cache lives for one tick only)", got)
		}

		// A failed read is cached for the tick too.
		x.f.reads = []string{"absent"}
		x.tick()
		if got := count("absent"); got != 1 {
			t.Fatalf("a missing ConfigMap was fetched %d times in one tick, want 1", got)
		}

		// Outside a tick every read is live.
		res := newTestKubeResolver(cs)
		for range 2 {
			if _, err := res.ConfigMap(context.Background(), "default", "shared"); err != nil {
				t.Fatal(err)
			}
		}
		if got := count("shared"); got != 4 {
			t.Fatalf("uncached reads brought the GET count to %d, want 4", got)
		}
	})

	t.Run("the loop ticks at its own interval and stops with ctx", func(t *testing.T) {
		x := newRefreshFixture(t, nil)
		x.track(runtimedPod("default", "a"))
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		x.r.clk = clk
		x.f.called = make(chan string, 4)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			x.r.runProjectedRefresh(ctx)
			close(done)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for !clk.HasWaiters() {
			if time.Now().After(deadline) {
				t.Fatal("the loop never armed its ticker")
			}
			time.Sleep(time.Millisecond)
		}
		clk.Step(resyncInterval)
		select {
		case id := <-x.f.called:
			t.Fatalf("refreshed %s after resyncInterval; the refresh cadence is its own", id)
		case <-time.After(50 * time.Millisecond):
		}
		clk.Step(projectedRefreshInterval - resyncInterval)
		select {
		case <-x.f.called:
		case <-time.After(5 * time.Second):
			t.Fatal("no refresh after projectedRefreshInterval")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the loop did not stop with its context")
		}
	})
}
