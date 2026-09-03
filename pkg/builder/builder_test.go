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

package builder

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	workersHeader = "ID\t\t\tPLATFORMS"
	oneWorker     = workersHeader + "\nabc123def\t\tlinux/arm64, linux/amd64, linux/arm/v7"
)

// fakeExecer returns programmed readiness output. Each call consumes one entry,
// holding the last so a steady state persists across polls.
type fakeExecer struct {
	outputs []string
	err     error
	calls   int
}

func (f *fakeExecer) Exec(_ context.Context, _, _, _ string, _ []string) (string, string, error) {
	f.calls++
	if f.err != nil {
		return "", "", f.err
	}
	if len(f.outputs) == 0 {
		return "", "", nil
	}
	out := f.outputs[0]
	if len(f.outputs) > 1 {
		f.outputs = f.outputs[1:]
	}
	return out, "", nil
}

func builderPod(phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultNamespace, Name: DefaultName},
		Status:     corev1.PodStatus{Phase: phase},
	}
}

func builderService(clusterIP string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: DefaultNamespace, Name: DefaultName},
		Spec:       corev1.ServiceSpec{ClusterIP: clusterIP},
	}
}

func TestStatus(t *testing.T) {
	cases := []struct {
		name        string
		objs        []runtime.Object
		exec        *fakeExecer
		wantState   State
		wantWorkers int
		wantEP      string
	}{
		{
			name:      "absent when no pod",
			exec:      &fakeExecer{},
			wantState: StateAbsent,
		},
		{
			name:      "pending when pod not running",
			objs:      []runtime.Object{builderPod(corev1.PodPending)},
			exec:      &fakeExecer{},
			wantState: StatePending,
		},
		{
			name:      "starting when running but no worker",
			objs:      []runtime.Object{builderPod(corev1.PodRunning)},
			exec:      &fakeExecer{outputs: []string{workersHeader}},
			wantState: StateStarting,
		},
		{
			name:        "ready when a worker registers",
			objs:        []runtime.Object{builderPod(corev1.PodRunning), builderService("10.96.0.7")},
			exec:        &fakeExecer{outputs: []string{oneWorker}},
			wantState:   StateReady,
			wantWorkers: 1,
			wantEP:      "tcp://10.96.0.7:1234",
		},
		{
			name:      "starting when exec errors (daemon not up)",
			objs:      []runtime.Object{builderPod(corev1.PodRunning)},
			exec:      &fakeExecer{err: errors.New("dial: connection refused")},
			wantState: StateStarting,
		},
		{
			name:      "failed when pod failed",
			objs:      []runtime.Object{builderPod(corev1.PodFailed)},
			exec:      &fakeExecer{},
			wantState: StateFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			m := NewManager(cs, tc.exec, Config{}, nil)
			st, err := m.Status(context.Background())
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if st.State != tc.wantState {
				t.Errorf("state = %q, want %q", st.State, tc.wantState)
			}
			if st.Workers != tc.wantWorkers {
				t.Errorf("workers = %d, want %d", st.Workers, tc.wantWorkers)
			}
			if st.Endpoint != tc.wantEP {
				t.Errorf("endpoint = %q, want %q", st.Endpoint, tc.wantEP)
			}
		})
	}
}

// TestStatusAbsentIsLegible pins the legible-absence contract: the message names
// the fix.
func TestStatusAbsentIsLegible(t *testing.T) {
	m := NewManager(fake.NewSimpleClientset(), &fakeExecer{}, Config{}, nil)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != StateAbsent || st.Message != ErrAbsent.Error() {
		t.Errorf("absent status not legible: state=%q msg=%q", st.State, st.Message)
	}
}

func TestEndpoint(t *testing.T) {
	t.Run("absent service is ErrAbsent", func(t *testing.T) {
		m := NewManager(fake.NewSimpleClientset(), nil, Config{}, nil)
		_, err := m.Endpoint(context.Background())
		if !errors.Is(err, ErrAbsent) {
			t.Errorf("err = %v, want ErrAbsent", err)
		}
	})
	t.Run("no clusterIP yet is a transient error", func(t *testing.T) {
		m := NewManager(fake.NewSimpleClientset(builderService("")), nil, Config{}, nil)
		_, err := m.Endpoint(context.Background())
		if err == nil || errors.Is(err, ErrAbsent) {
			t.Errorf("err = %v, want a non-ErrAbsent transient error", err)
		}
	})
	t.Run("clusterIP yields tcp endpoint", func(t *testing.T) {
		m := NewManager(fake.NewSimpleClientset(builderService("10.96.1.2")), nil, Config{}, nil)
		ep, err := m.Endpoint(context.Background())
		if err != nil {
			t.Fatalf("Endpoint: %v", err)
		}
		if ep != "tcp://10.96.1.2:1234" {
			t.Errorf("endpoint = %q", ep)
		}
	})
}

// TestUpToReady drives the full lifecycle: a pre-scheduled Running pod plus a
// worker takes Up to Ready, and the missing PVC is created along the way.
func TestUpToReady(t *testing.T) {
	cs := fake.NewSimpleClientset(builderPod(corev1.PodRunning), builderService("10.96.0.9"))
	m := NewManager(cs, &fakeExecer{outputs: []string{oneWorker}}, Config{}, nil)
	m.pollInterval = time.Millisecond

	st, err := m.Up(context.Background())
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if st.State != StateReady || st.Workers != 1 {
		t.Errorf("up state = %q workers=%d, want Ready/1", st.State, st.Workers)
	}
	if st.Endpoint != "tcp://10.96.0.9:1234" {
		t.Errorf("up endpoint = %q", st.Endpoint)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); err != nil {
		t.Errorf("PVC was not created by Up: %v", err)
	}
}

// TestUpWaitsThenReady pins the poll loop: the first probe finds no worker, the
// second finds one.
func TestUpWaitsThenReady(t *testing.T) {
	ex := &fakeExecer{outputs: []string{workersHeader, oneWorker}}
	cs := fake.NewSimpleClientset(builderPod(corev1.PodRunning), builderService("10.96.0.9"))
	m := NewManager(cs, ex, Config{}, nil)
	m.pollInterval = time.Millisecond
	st, err := m.Up(context.Background())
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if st.State != StateReady {
		t.Errorf("state = %q, want Ready", st.State)
	}
	if ex.calls < 2 {
		t.Errorf("expected at least 2 readiness probes, got %d", ex.calls)
	}
}

// TestUpFailsOnFailedPod pins that a terminal pod aborts the wait.
func TestUpFailsOnFailedPod(t *testing.T) {
	cs := fake.NewSimpleClientset(builderPod(corev1.PodFailed), builderService("10.96.0.9"))
	m := NewManager(cs, &fakeExecer{}, Config{}, nil)
	m.pollInterval = time.Millisecond
	if _, err := m.Up(context.Background()); err == nil {
		t.Errorf("Up on a Failed pod should error")
	}
}

// TestUpTimesOut pins that Up honors context cancellation while never ready.
func TestUpTimesOut(t *testing.T) {
	cs := fake.NewSimpleClientset(builderPod(corev1.PodRunning), builderService("10.96.0.9"))
	m := NewManager(cs, &fakeExecer{outputs: []string{workersHeader}}, Config{}, nil)
	m.pollInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := m.Up(ctx); err == nil {
		t.Errorf("Up should time out when no worker ever registers")
	}
}

// TestUpRejectsBadConfig and TestUpNeedsExec pin the guards.
func TestUpGuards(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		m := NewManager(fake.NewSimpleClientset(), &fakeExecer{}, Config{TCPPort: 70000}, nil)
		if _, err := m.Up(context.Background()); err == nil {
			t.Errorf("Up must reject an out-of-range port")
		}
	})
	t.Run("no exec seam", func(t *testing.T) {
		m := NewManager(fake.NewSimpleClientset(), nil, Config{}, nil)
		if _, err := m.Up(context.Background()); err == nil {
			t.Errorf("Up without an exec seam must error")
		}
	})
}

// TestDownKeepsCache pins that Down removes the Pod and Service but keeps the PVC.
func TestDownKeepsCache(t *testing.T) {
	cfg := Config{}.Normalize()
	cs := fake.NewSimpleClientset(
		builderPod(corev1.PodRunning),
		builderService("10.96.0.9"),
		cfg.PersistentVolumeClaim(),
	)
	m := NewManager(cs, &fakeExecer{}, Config{}, nil)
	if err := m.Down(context.Background()); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if _, err := cs.CoreV1().Pods(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("pod should be gone, err=%v", err)
	}
	if _, err := cs.CoreV1().Services(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("service should be gone, err=%v", err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); err != nil {
		t.Errorf("cache PVC must be KEPT, err=%v", err)
	}
}

// TestDeleteRemovesCacheAndNamespace pins that Delete is the full reset: the Pod,
// Service, the cache PVC AND the builder namespace are all removed. It is the
// contrast to TestDownKeepsCache, which keeps the PVC for a warm rebuild — this
// goes red if Delete misses any of the four objects.
func TestDeleteRemovesCacheAndNamespace(t *testing.T) {
	cfg := Config{}.Normalize()
	cs := fake.NewSimpleClientset(
		cfg.NamespaceObject(),
		builderPod(corev1.PodRunning),
		builderService("10.96.0.9"),
		cfg.PersistentVolumeClaim(),
	)
	m := NewManager(cs, &fakeExecer{}, Config{}, nil)
	if err := m.Delete(context.Background()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.CoreV1().Pods(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("pod should be gone, err=%v", err)
	}
	if _, err := cs.CoreV1().Services(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("service should be gone, err=%v", err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(DefaultNamespace).Get(context.Background(), DefaultName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("cache PVC must be REMOVED on a full reset, err=%v", err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(context.Background(), DefaultNamespace, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("builder namespace must be REMOVED on a full reset, err=%v", err)
	}
}

// TestDeleteIdempotent pins that a Delete of an absent stack is success.
func TestDeleteIdempotent(t *testing.T) {
	m := NewManager(fake.NewSimpleClientset(), &fakeExecer{}, Config{}, nil)
	if err := m.Delete(context.Background()); err != nil {
		t.Errorf("Delete of an absent stack should succeed, got %v", err)
	}
}

// TestDownIdempotent pins that a Down of an absent stack is success.
func TestDownIdempotent(t *testing.T) {
	m := NewManager(fake.NewSimpleClientset(), &fakeExecer{}, Config{}, nil)
	if err := m.Down(context.Background()); err != nil {
		t.Errorf("Down of an absent stack should succeed, got %v", err)
	}
}

func TestCountWorkers(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
	}{
		{"empty", "", 0},
		{"header only", workersHeader, 0},
		{"one worker", oneWorker, 1},
		{"two workers", workersHeader + "\nw1\tlinux/arm64\nw2\tlinux/amd64", 2},
		{"trailing blank lines", oneWorker + "\n\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countWorkers(tc.out); got != tc.want {
				t.Errorf("countWorkers(%q) = %d, want %d", tc.out, got, tc.want)
			}
		})
	}
}

// TestUpCreatesNamespaceBeforePVC pins the ordering the live defect exposed: the
// builder namespace must be created BEFORE the PVC/Pod/Service that target it, or
// the create fails with "namespaces \"k3sm-builder\" not found". A reactor
// records create order; removing the ensureNamespace step makes this red (the
// namespace create never appears).
func TestUpCreatesNamespaceBeforePVC(t *testing.T) {
	cs := fake.NewSimpleClientset(builderPod(corev1.PodRunning), builderService("10.96.0.9"))
	var order []string
	cs.PrependReactor("create", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		order = append(order, a.GetResource().Resource)
		return false, nil, nil // let the default tracker handle it
	})
	m := NewManager(cs, &fakeExecer{outputs: []string{oneWorker}}, Config{}, nil)
	m.pollInterval = time.Millisecond
	if _, err := m.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}

	nsIdx, pvcIdx := -1, -1
	for i, r := range order {
		if r == "namespaces" && nsIdx == -1 {
			nsIdx = i
		}
		if r == "persistentvolumeclaims" && pvcIdx == -1 {
			pvcIdx = i
		}
	}
	if nsIdx == -1 {
		t.Fatalf("Up never created the builder namespace (create order: %v)", order)
	}
	if pvcIdx == -1 {
		t.Fatalf("Up never created the PVC (create order: %v)", order)
	}
	if nsIdx > pvcIdx {
		t.Errorf("namespace was created AFTER the PVC (order: %v) — the PVC targets a namespace that must exist first", order)
	}

	if _, err := cs.CoreV1().Namespaces().Get(context.Background(), DefaultNamespace, metav1.GetOptions{}); err != nil {
		t.Errorf("builder namespace was not created: %v", err)
	}
}

// TestUpNamespaceIdempotent pins that a pre-existing namespace is tolerated.
func TestUpNamespaceIdempotent(t *testing.T) {
	cfg := Config{}.Normalize()
	cs := fake.NewSimpleClientset(
		cfg.NamespaceObject(),
		builderPod(corev1.PodRunning),
		builderService("10.96.0.9"),
	)
	m := NewManager(cs, &fakeExecer{outputs: []string{oneWorker}}, Config{}, nil)
	m.pollInterval = time.Millisecond
	if _, err := m.Up(context.Background()); err != nil {
		t.Fatalf("Up with an existing namespace must succeed: %v", err)
	}
}
