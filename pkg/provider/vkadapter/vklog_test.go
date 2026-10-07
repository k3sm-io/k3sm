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

package vkadapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes slog makes from
// VK's goroutines. mu guards b.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// records parses every JSON log line written so far.
func (s *syncBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	text := s.b.String()
	s.mu.Unlock()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func findRecord(recs []map[string]any, msg string) map[string]any {
	for _, r := range recs {
		if r["msg"] == msg {
			return r
		}
	}
	return nil
}

// TestFailedStatusPatchLogsWarnThroughAdapter pins that Virtual Kubelet's own
// account of a failed node-status PATCH reaches the k3sm log at Warn, with the
// node name and the error. Before the adapter, VK's logger was its no-op
// default and the line was discarded, so a node whose status writes failed for
// half an hour logged nothing about it.
func TestFailedStatusPatchLogsWarnThroughAdapter(t *testing.T) {
	const name = "k3sm-patchfail"
	h := newNodeHarness(t)
	h.cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "status" {
			return true, nil, errors.New("injected: http2: client connection lost")
		}
		return false, nil, nil
	})
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	n, err := NewNode(name, NodeConfig{
		Client:         h.cs,
		Provider:       newRecordingProvider(),
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode:  func(*corev1.Node) {},
		Log:            logger,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	stop := runNode(t, n)
	defer func() { _ = stop() }()

	var rec map[string]any
	deadline := time.Now().Add(stepTimeout)
	for time.Now().Before(deadline) {
		if rec = findRecord(buf.records(t), "Failed to patch node status"); rec != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rec == nil {
		t.Fatalf("no \"Failed to patch node status\" line within %s; log:\n%v", stepTimeout, buf.records(t))
	}
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["node"] != name {
		t.Errorf("node = %v, want %q", rec["node"], name)
	}
	if e, _ := rec["error"].(string); !strings.Contains(e, "client connection lost") {
		t.Errorf("error = %v, want the injected PATCH error", rec["error"])
	}
	if p, _ := rec["patch"].(string); len(p) > vkLogMaxValue+len("...(truncated)") {
		t.Errorf("patch field is %d bytes, want it clamped to %d", len(p), vkLogMaxValue)
	}
}

// TestVKLoggerLevelsAndRepeats pins the level mapping and the repeat limiter:
// VK's Error and Warn surface at Warn, its Info is demoted to Debug, and an
// identical warning (same message, same error) inside the window is held back
// and counted on the next one let through.
func TestVKLoggerLevelsAndRepeats(t *testing.T) {
	buf := &syncBuffer{}
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	l := &vkLogger{
		log: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		lim: newRepeatLimiter(vkLogRepeatWindow, clock),
	}
	errA := errors.New("dial tcp: i/o timeout")

	l.WithError(errA).Error("failed to update node lease")
	l.WithError(errA).Error("failed to update node lease")                         // held back
	l.WithError(errA).WithField("retries", 2).Error("failed to update node lease") // held back: same key
	l.WithError(errors.New("other")).Error("failed to update node lease")          // different error: through
	l.Info("Updated k8s pod status")
	now = now.Add(vkLogRepeatWindow)
	l.WithError(errA).Error("failed to update node lease") // window passed: through, with the count

	recs := buf.records(t)
	if len(recs) != 4 {
		t.Fatalf("got %d lines, want 4: %v", len(recs), recs)
	}
	type want struct {
		level, msg, err string
		suppressed      float64
	}
	wants := []want{
		{"WARN", "failed to update node lease", errA.Error(), 0},
		{"WARN", "failed to update node lease", "other", 0},
		{"DEBUG", "Updated k8s pod status", "", 0},
		{"WARN", "failed to update node lease", errA.Error(), 2},
	}
	for i, w := range wants {
		r := recs[i]
		if r["level"] != w.level || r["msg"] != w.msg {
			t.Errorf("line %d = %v %q, want %s %q", i, r["level"], r["msg"], w.level, w.msg)
		}
		if w.err != "" && r["error"] != w.err {
			t.Errorf("line %d error = %v, want %q", i, r["error"], w.err)
		}
		got, _ := r["repeats_suppressed"].(float64)
		if got != w.suppressed {
			t.Errorf("line %d repeats_suppressed = %v, want %v", i, got, w.suppressed)
		}
	}
}
