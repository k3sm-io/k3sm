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

package podlogs

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// TestTerminationMessageTailRing pins the FallbackToLogsOnError message: the
// last 80 file lines, kept in a 2048-byte TAIL.
//
// The tail (rather than a truncating head) is the whole point. A process that
// dies prints its reason last, so a head-truncated message would reliably show
// the least useful 2048 bytes of a crash and would look like it was working.
func TestTerminationMessageTailRing(t *testing.T) {
	base := time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)

	t.Run("keeps the END when the output exceeds the byte ceiling", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 60; i++ {
			b.WriteString(line(base.Add(time.Duration(i)*time.Second), "stdout", "F", repeat("x", 100)))
		}
		b.WriteString(line(base.Add(time.Hour), "stderr", "F", "panic: the actual reason"))
		path := writeLog(t, b.String())

		msg := TerminationMessageFromLogs(context.Background(), path, nil)
		if len(msg) > MaxContainerTerminationMessageLogLength {
			t.Fatalf("message is %d bytes, want at most %d", len(msg), MaxContainerTerminationMessageLogLength)
		}
		if !strings.HasSuffix(msg, "panic: the actual reason\n") {
			t.Errorf("message does not end with the last thing the container printed; got the last 40 bytes as %q", msg[max(0, len(msg)-40):])
		}
	})

	t.Run("considers only the last 80 file lines", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(line(base, "stdout", "F", "the-very-first-line"))
		for i := 0; i < 100; i++ {
			b.WriteString(line(base.Add(time.Duration(i+1)*time.Second), "stdout", "F", fmt.Sprintf("l%d", i)))
		}
		path := writeLog(t, b.String())

		msg := TerminationMessageFromLogs(context.Background(), path, nil)
		if strings.Contains(msg, "the-very-first-line") {
			t.Error("the message reaches past the last 80 lines of the file")
		}
		if !strings.Contains(msg, "l99") {
			t.Errorf("the message does not contain the final line; got %q", msg)
		}
	})

	t.Run("stdout and stderr are interleaved in write order", func(t *testing.T) {
		path := writeLog(t,
			line(base, "stdout", "F", "starting")+
				line(base.Add(time.Second), "stderr", "F", "failing")+
				line(base.Add(2*time.Second), "stdout", "F", "done"))
		msg := TerminationMessageFromLogs(context.Background(), path, nil)
		if msg != "starting\nfailing\ndone\n" {
			t.Errorf("message = %q, want both streams in write order", msg)
		}
	})

	t.Run("an unreadable log becomes the upstream error text", func(t *testing.T) {
		msg := TerminationMessageFromLogs(context.Background(), filepath.Join(t.TempDir(), "gone.log"), nil)
		if !strings.HasPrefix(msg, "Error on reading termination message from logs: ") {
			t.Errorf("message = %q, want the kubelet's own error text", msg)
		}
	})

	t.Run("the ring keeps the tail across many small writes", func(t *testing.T) {
		r := newTailRing(5)
		for _, s := range []string{"abc", "de", "fgh"} {
			if _, err := r.Write([]byte(s)); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if got := string(r.Bytes()); got != "defgh" {
			t.Errorf("ring = %q, want %q", got, "defgh")
		}
		// A single write larger than the ring keeps its own tail.
		if _, err := r.Write([]byte("0123456789")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := string(r.Bytes()); got != "56789" {
			t.Errorf("ring = %q, want %q", got, "56789")
		}
	})
}

// TestShouldFallbackToLogs pins the four conditions, each of which is a way the
// fallback could otherwise replace a real message with an empty or wrong one.
func TestShouldFallbackToLogs(t *testing.T) {
	tests := []struct {
		name    string
		policy  corev1.TerminationMessagePolicy
		exit    int32
		reason  string
		message string
		want    bool
	}{
		{name: "the policy asked for it and the container failed", policy: corev1.TerminationMessageFallbackToLogsOnError, exit: 1, want: true},
		{name: "a different policy never falls back", policy: corev1.TerminationMessageReadFile, exit: 1},
		{name: "a clean exit is not an error", policy: corev1.TerminationMessageFallbackToLogsOnError, exit: 0},
		{name: "a container that could not run has no logs to read", policy: corev1.TerminationMessageFallbackToLogsOnError, exit: 1, reason: ReasonContainerCannotRun},
		{name: "a message the container wrote itself is never overwritten", policy: corev1.TerminationMessageFallbackToLogsOnError, exit: 1, message: "I said why"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldFallbackToLogs(tt.policy, tt.exit, tt.reason, tt.message); got != tt.want {
				t.Errorf("ShouldFallbackToLogs = %v, want %v", got, tt.want)
			}
		})
	}
}
