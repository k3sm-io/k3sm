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

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// TestSlowBringUpClassificationAndBackoff covers the record site: the host is
// sampled when the apiserver timeout is classified, a pressured timeout is a
// slow lap that does not count toward the park, an unpressured one or a failed
// read counts as before, and the backoff wait honours ctx. The timer is a seam;
// nothing sleeps.
func TestSlowBringUpClassificationAndBackoff(t *testing.T) {
	timeout := &executor.BringUpError{Component: "kube-apiserver", Phase: executor.PhaseBringUp,
		Err: fmt.Errorf("apiserver not healthy: %w", executor.ErrAPIServerHealthTimeout)}
	cases := []struct {
		name     string
		pressure func() (bool, string, error)
		err      error
		slow     bool
	}{
		{"pressured timeout is slow", func() (bool, string, error) { return true, "load sampled", nil }, timeout, true},
		{"unpressured timeout counts", func() (bool, string, error) { return false, "load sampled", nil }, timeout, false},
		{"pressure read error counts", func() (bool, string, error) { return false, "", errors.New("sysctl") }, timeout, false},
		{"fast failure under pressure counts", func() (bool, string, error) { return true, "load sampled", nil },
			&executor.BringUpError{Component: "kine", Phase: executor.PhaseBringUp, Err: errors.New("kine exited during bring-up")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := newCrashBreaker(dir, quietLogger())
			sampled := 0
			b.pressure = func() (bool, string, error) { sampled++; return tc.pressure() }
			for i := 0; i < executor.CrashLoopThreshold; i++ {
				noteBringUpFailure(context.Background(), b, quietLogger(), tc.err)
			}
			r, err := executor.ReadCrashRecord(b.path)
			if err != nil {
				t.Fatal(err)
			}
			if r.Tripped() == tc.slow {
				t.Fatalf("tripped = %v after %d failures, slow = %v", r.Tripped(), executor.CrashLoopThreshold, tc.slow)
			}
			if tc.slow && r.SlowStreak != executor.CrashLoopThreshold {
				t.Fatalf("streak = %d", r.SlowStreak)
			}
			if errors.Is(tc.err, executor.ErrAPIServerHealthTimeout) && sampled == 0 {
				t.Fatal("the host was not sampled at the timeout")
			}
			_, readOK, _ := tc.pressure()
			last, _ := r.Last()
			if sampledLoad := errors.Is(tc.err, executor.ErrAPIServerHealthTimeout) && readOK != ""; sampledLoad != strings.Contains(last.Detail, "load sampled") {
				t.Fatalf("Detail %q: want the sampled load iff it was read (%v)", last.Detail, sampledLoad)
			}
		})
	}

	t.Run("backoff waits on the record and honours ctx", func(t *testing.T) {
		dir := t.TempDir()
		b := newCrashBreaker(dir, quietLogger())
		now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
		b.now = func() time.Time { return now }
		b.pressure = func() (bool, string, error) { return true, "load sampled", nil }
		noteBringUpFailure(context.Background(), b, quietLogger(), timeout)
		noteBringUpFailure(context.Background(), b, quietLogger(), timeout)
		var asked time.Duration
		fire := make(chan time.Time, 1)
		b.after = func(d time.Duration) <-chan time.Time { asked = d; return fire }
		fire <- now
		if err := b.awaitBringUpBackoff(context.Background()); err != nil || asked != time.Minute {
			t.Fatalf("wait = %s, err %v; want 1m", asked, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := b.awaitBringUpBackoff(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled wait returned %v", err)
		}
		b.noteBringUpHealthy()
		b.after = func(time.Duration) <-chan time.Time { t.Fatal("waited after a healthy bring-up"); return nil }
		if err := b.awaitBringUpBackoff(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}
