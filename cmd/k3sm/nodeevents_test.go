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
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"

	"k3sm.io/k3sm/pkg/provider"
)

// nsClock is a clock that advances one microsecond every fourth read, so Events
// stamped without a wait land in the same microsecond the way a macOS node's do.
type nsClock struct {
	mu sync.Mutex
	ns int64
}

func (c *nsClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ns++
	return time.Unix(0, c.ns/4*int64(time.Microsecond))
}

// nameRecorder names each Event the way client-go does, "<object>.<hex of the
// timestamp>" with the timestamp at microsecond resolution, and keeps the names.
type nameRecorder struct {
	clk   *nsClock
	mu    sync.Mutex
	names []string
}

func (r *nameRecorder) record() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, fmt.Sprintf("pod.%x", r.clk.Now().Truncate(time.Microsecond).UnixNano()))
}

func (r *nameRecorder) Event(runtime.Object, string, string, string) { r.record() }
func (r *nameRecorder) Eventf(runtime.Object, string, string, string, ...any) {
	r.record()
}
func (r *nameRecorder) AnnotatedEventf(runtime.Object, map[string]string, string, string, string, ...any) {
	r.record()
}

var _ record.EventRecorder = (*nameRecorder)(nil)

// TestNodeRecorderSpacesEvents pins that the recorder Virtual Kubelet records
// its pod Events through is wrapped by the SAME spacer the providers use, so a
// provider Event and a VK Event recorded in one (fake) microsecond still get
// distinct names. nodeEventRecorders is what the node wires; two separate
// spacers would let the two streams collide, and this test reds on that.
//
// Fails-before: nodeEventRecorders did not exist, and VK's recorder was not
// spaced at all.
func TestNodeRecorderSpacesEvents(t *testing.T) {
	clk := &nsClock{}
	inner := &nameRecorder{clk: clk}
	providerRec, vkRec := nodeEventRecorders(provider.NewEventSpacerClock(inner, clk.Now), inner)

	pod := &corev1.Pod{}
	for range 50 {
		providerRec.Event(pod, corev1.EventTypeNormal, "Created", "provider")
		vkRec.Event(pod, corev1.EventTypeNormal, "ProviderCreateSuccess", "vk")
	}

	seen := map[string]bool{}
	for _, n := range inner.names {
		if seen[n] {
			t.Fatalf("Event name %q recorded twice: the provider and VK recorders do not share one spacer", n)
		}
		seen[n] = true
	}
	if len(seen) != 100 {
		t.Fatalf("recorded %d distinct Event names, want 100", len(seen))
	}
}
