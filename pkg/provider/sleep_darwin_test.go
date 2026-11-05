//go:build darwin && cgo

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
	"os"
	"syscall"
	"testing"
	"time"
)

// TestSleepAckMatchesItsNotice drives the watcher's C ack wait over a pipe: a
// stale ack left by an earlier, timed-out notice is drained and cannot answer
// the next one, a byte for another notice is ignored, and only the notice's
// own sequence byte ends the wait.
func TestSleepAckMatchesItsNotice(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := r.Fd()
	if err := syscall.SetNonblock(int(fd), true); err != nil {
		t.Fatal(err)
	}

	t.Run("a stale ack is drained before the wait", func(t *testing.T) {
		if _, err := w.Write([]byte{7}); err != nil {
			t.Fatal(err)
		}
		drainAck(fd)
		start := time.Now()
		if got := waitAck(fd, 8, 200); got != 0 {
			t.Fatalf("waitAck = %d after a drained stale ack, want the timeout 0", got)
		}
		if time.Since(start) < 150*time.Millisecond {
			t.Fatal("waitAck returned before its bound")
		}
	})
	t.Run("another notice's byte is ignored", func(t *testing.T) {
		if _, err := w.Write([]byte{3}); err != nil {
			t.Fatal(err)
		}
		if got := waitAck(fd, 9, 200); got != 0 {
			t.Fatalf("waitAck = %d on a mismatched byte, want the timeout 0", got)
		}
	})
	t.Run("the notice's own byte ends the wait", func(t *testing.T) {
		go func() { time.Sleep(20 * time.Millisecond); _, _ = w.Write([]byte{4, 10}) }()
		if got := waitAck(fd, 10, 5000); got != 1 {
			t.Fatalf("waitAck = %d, want the match 1", got)
		}
	})
	t.Run("a closed writer ends the wait", func(t *testing.T) {
		_ = w.Close()
		if got := waitAck(fd, 11, 5000); got != -1 {
			t.Fatalf("waitAck = %d after close, want -1", got)
		}
	})
}

// TestSleepWakePredicateNeedsGraphics pins only the C classification
// predicates: a capability set is a full wake only with CPU and Graphics, and
// a capability change counts only when it has completed the gain of one. It
// claims nothing about which messages reach the watcher's port.
func TestSleepWakePredicateNeedsGraphics(t *testing.T) {
	const cpu, gfx, audio, net = 0x01, 0x02, 0x04, 0x08
	const will, did = 0x01, 0x02
	if !isFullWake(cpu | gfx | audio | net) {
		t.Error("a full wake was not taken as one")
	}
	if isFullWake(cpu | net) {
		t.Error("a dark wake (CPU and network, no graphics) was taken as a full wake")
	}
	if isFullWake(0) {
		t.Error("sleep was taken as a full wake")
	}
	if !capChangeIsFullWake(did, cpu|net, cpu|gfx|audio|net) {
		t.Error("a dark-to-full promotion was missed")
	}
	if capChangeIsFullWake(will, cpu|net, cpu|gfx|audio|net) {
		t.Error("a pending promotion was taken as done")
	}
	if capChangeIsFullWake(did, 0, cpu|net) {
		t.Error("a dark wake from sleep was taken as a full wake")
	}
	if capChangeIsFullWake(did, cpu|gfx, cpu|gfx|audio) {
		t.Error("a change within a full wake was taken as a new wake")
	}
}
