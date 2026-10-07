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

package netserve

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// recordingHandler is a slog.Handler that keeps every record it is handed.
type recordingHandler struct {
	mu      sync.Mutex // guards records
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Clone())
	h.mu.Unlock()
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// podsWatchErrorWarns counts the policy watcher's Warn records about the pods
// informer failing to list/watch.
func (h *recordingHandler) podsWatchErrorWarns() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if r.Level != slog.LevelWarn || !strings.HasPrefix(r.Message, "networkpolicy watcher: informer") {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "resource" && a.Value.String() == "pods" {
				n++
				return false
			}
			return true
		})
	}
	return n
}

// TestWorkerStartsNoPolicyInformers pins the worker shape: a datapath that does
// not set EnforceNetworkPolicy (a joined worker, whose node identity is granted
// neither the cluster-wide NetworkPolicies nor the Namespaces read) lists and
// watches nothing for the policy table, says so in exactly one Info line, and
// logs no Warn. Before, the worker started the watcher anyway: its NetworkPolicies
// and Namespaces informers were refused on every retry, the table never synced,
// and every connection was allowed while the log claimed a watcher was running.
func TestWorkerStartsNoPolicyInformers(t *testing.T) {
	t.Parallel()
	cs := fake.NewClientset()
	var mu sync.Mutex // guards calls
	var calls []string
	note := func(a k8stesting.Action) {
		mu.Lock()
		calls = append(calls, a.GetVerb()+" "+a.GetResource().Resource)
		mu.Unlock()
	}
	cs.PrependReactor("list", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		note(a)
		return false, nil, nil
	})
	cs.PrependWatchReactor("*", func(a k8stesting.Action) (bool, watch.Interface, error) {
		note(a)
		return false, nil, nil
	})
	h := &recordingHandler{}
	srv := New(Config{
		Client:       cs,
		WorkDir:      t.TempDir(),
		DNSVIP:       "10.43.0.10",
		PodCIDR:      "100.64.2.0/24",
		MeshEgressIP: "100.64.2.1",
		PodScopeNode: "mac-worker-2",
		Logger:       slog.New(h),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := srv.RunPolicyWatch(ctx); err != nil {
		t.Fatalf("RunPolicyWatch: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 0 {
		t.Errorf("worker policy path issued %v; a worker must start no policy informer", calls)
	}
	var offInfo, warns int
	h.mu.Lock()
	for _, r := range h.records {
		switch {
		case r.Level == slog.LevelWarn:
			warns++
		case r.Level == slog.LevelInfo && strings.HasPrefix(r.Message, "NetworkPolicy enforcement is off on this node"):
			offInfo++
		}
	}
	h.mu.Unlock()
	if offInfo != 1 {
		t.Errorf("enforcement-off Info lines = %d, want exactly 1", offInfo)
	}
	if warns != 0 {
		t.Errorf("Warn lines = %d, want 0 (nothing was refused because nothing was asked)", warns)
	}
}

// TestScopedPolicyWatcherForbiddenWarnsOnce pins that an enforcing, node-scoped
// datapath (the shape a worker takes once it is granted the policy reads) whose
// pods list is refused surfaces the refusal through Config.Logger exactly once
// across several reflector retries, instead of one line per retry. The throttle
// lives in the watcher; this pins that the datapath hands it the configured
// logger, so the one line reaches the operator and the retries do not.
func TestScopedPolicyWatcherForbiddenWarnsOnce(t *testing.T) {
	t.Parallel()
	const node = "mac-worker-2"
	cs := fake.NewClientset()
	var lists atomic.Int32
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		lists.Add(1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "",
			errFake("node \""+node+"\" can only list pods bound to it"))
	})
	h := &recordingHandler{}
	srv := New(Config{
		Client:               cs,
		WorkDir:              t.TempDir(),
		DNSVIP:               "10.43.0.10",
		PodCIDR:              "100.64.2.0/24",
		MeshEgressIP:         "100.64.2.1",
		EnforceNetworkPolicy: true,
		PodScopeNode:         node,
		Logger:               slog.New(h),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.RunPolicyWatch(ctx) }()

	// Wait for at least three refused lists (the reflector backs off between
	// them), so the throttle is exercised past the first error.
	deadline := time.Now().Add(15 * time.Second)
	for lists.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunPolicyWatch did not return within 10s of cancellation")
	}

	if got := lists.Load(); got < 3 {
		t.Fatalf("only %d refused pods lists recorded; need >=3 retries to exercise the throttle", got)
	}
	if got := h.podsWatchErrorWarns(); got != 1 {
		t.Fatalf("pods watch-error Warn lines = %d over %d refused lists, want exactly 1", got, lists.Load())
	}
}

// errFake is a plain error carrying a fixed message.
type errFake string

func (e errFake) Error() string { return string(e) }
