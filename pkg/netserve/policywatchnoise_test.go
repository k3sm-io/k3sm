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

// TestWorkerPolicyWatcherForbiddenWarnsOnce pins that a worker-shaped datapath
// whose pods list is refused surfaces the refusal through Config.Logger exactly
// once across several reflector retries, instead of one line per retry. The
// throttle lives in the watcher; this pins that the datapath hands it the
// configured logger, so the one line reaches the operator and the retries do not.
func TestWorkerPolicyWatcherForbiddenWarnsOnce(t *testing.T) {
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
		Client:       cs,
		WorkDir:      t.TempDir(),
		DNSVIP:       "10.43.0.10",
		PodCIDR:      "100.64.2.0/24",
		MeshEgressIP: "100.64.2.1",
		PodScopeNode: node,
		Logger:       slog.New(h),
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
