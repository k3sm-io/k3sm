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
	"sync"
	"testing"
)

// TestGetPodsAndUpdatePodDoNotRaceOnTrackPod pins the one podTrack field r.mu
// guards that GetPods used to read outside it.
//
// podTrack is deliberately built so status reconstruction can run WITHOUT r.mu —
// readyMu, restartMu and hookMu each exist for that reason, and startTime is
// write-once. t.pod is the exception: UpdatePod reassigns it under r.mu, so
// GetPods reading it out in its loop was a genuine data race. It is reachable on
// every node, not just in theory: runBackstop calls GetPods on its own goroutine
// every 10s while VK's pod workers call UpdatePod.
//
// The fix snapshots the pointer inside the existing critical section. This test
// is the regression: it fails under -race against the unfixed code, and this
// package's suite runs with -race.
func TestGetPodsAndUpdatePodDoNotRaceOnTrackPod(t *testing.T) {
	r, _ := newRuntimedFake(t)
	ctx := context.Background()

	pod := runtimedPod("default", "web")
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}

	// One writer reassigning t.pod, one reader walking the tracks — the backstop
	// vs pod-worker interleaving. -race needs only one crossing, so the counts
	// stay small and the test stays fast and hermetic.
	const rounds = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range rounds {
			up := runtimedPod("default", "web")
			up.Labels = map[string]string{"round": string(rune('a' + i%26))}
			_ = r.UpdatePod(ctx, up)
		}
	}()
	go func() {
		defer wg.Done()
		for range rounds {
			pods, err := r.GetPods(ctx)
			if err != nil {
				continue
			}
			// Touch the result: a snapshot that is never read could not observe
			// a torn value even if one existed.
			for _, p := range pods {
				_ = p.Name
			}
		}
	}()
	wg.Wait()
}
