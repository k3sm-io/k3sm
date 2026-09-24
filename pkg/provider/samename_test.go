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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TestLookupDiscriminatesSameNameSuccessor pins how a name-keyed read resolves
// when two tracks share one (namespace, name) — the same-name churn window of a
// StatefulSet replica or a delete-and-recreate, where the successor is created
// before the predecessor's DeletePod has finished.
//
// Both lookup-served surfaces are asserted: the exec path (RunInContainer, which
// resolves through lookup and addresses the runtime by pod id) and
// VKProvider.GetPod (the read VK drives create-vs-update and orphan reaping
// from). Before the fix both returned whichever track the map yielded first; run
// 50 times over the first case below, lookup and VKProvider.GetPod returned the
// deleting predecessor roughly 40-45 times each. Every read here is repeated so
// an order-dependent answer cannot pass by luck.
func TestLookupDiscriminatesSameNameSuccessor(t *testing.T) {
	older := metav1.NewTime(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC))
	newer := metav1.NewTime(older.Add(time.Minute))

	type side struct {
		uid      types.UID
		created  metav1.Time
		deleting bool
	}
	tests := []struct {
		name string
		a, b side
		want types.UID
	}{
		{
			name: "predecessor deleting, successor live: successor wins",
			a:    side{"uid-pred", older, true},
			b:    side{"uid-succ", newer, false},
			want: "uid-succ",
		},
		{
			name: "reverse churn, successor deleting, predecessor live: predecessor wins",
			a:    side{"uid-pred", older, false},
			b:    side{"uid-succ", newer, true},
			want: "uid-pred",
		},
		{
			name: "both terminating: youngest wins",
			a:    side{"uid-pred", older, true},
			b:    side{"uid-succ", newer, true},
			want: "uid-succ",
		},
		{
			name: "both live: youngest wins",
			a:    side{"uid-pred", older, false},
			b:    side{"uid-succ", newer, false},
			want: "uid-succ",
		},
		{
			name: "both terminating, identical timestamps: smaller UID wins",
			a:    side{"uid-b", older, true},
			b:    side{"uid-a", older, true},
			want: "uid-a",
		},
		{
			name: "both live, identical timestamps: smaller UID wins",
			a:    side{"uid-b", older, false},
			b:    side{"uid-a", older, false},
			want: "uid-a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := &fakeStreamRuntime{}
			r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir()}, nil, nil)
			for _, s := range []side{tt.a, tt.b} {
				pod := runtimedPod("default", "web")
				pod.UID = s.uid
				pod.CreationTimestamp = s.created
				if err := r.CreatePod(ctx, pod); err != nil {
					t.Fatalf("CreatePod %s: %v", s.uid, err)
				}
				tr := r.track[string(s.uid)]
				tr.restartMu.Lock()
				tr.deleting = s.deleting
				tr.restartMu.Unlock()
				// The discrimination must ride t.deleting: the delete path never
				// stamps DeletionTimestamp onto the tracked object.
				if tr.pod.DeletionTimestamp != nil {
					t.Fatalf("track %s carries a DeletionTimestamp; the fixture must not", s.uid)
				}
			}

			v := NewVKProvider(r, "n")
			for i := range 50 {
				id, _, pod, ok := r.lookup("default", "web")
				if !ok || id != string(tt.want) || pod.UID != tt.want {
					t.Fatalf("read %d: lookup = %q (ok=%v), want %q", i, id, ok, tt.want)
				}
				got, err := v.GetPod(ctx, "default", "web")
				if err != nil {
					t.Fatalf("read %d: VKProvider.GetPod: %v", i, err)
				}
				if got.UID != tt.want {
					t.Fatalf("read %d: VKProvider.GetPod UID = %q, want %q", i, got.UID, tt.want)
				}
			}

			// The exec path: the runtime must be addressed by the chosen pod's id.
			attach := &fakeAttachIO{stdout: &syncBuffer{}, stderr: &syncBuffer{}}
			if err := r.RunInContainer(ctx, "default", "web", "c0", []string{"true"}, attach); err != nil {
				t.Fatalf("RunInContainer: %v", err)
			}
			f.mu.Lock()
			gotID := f.execPodID
			f.mu.Unlock()
			if gotID != string(tt.want) {
				t.Errorf("exec addressed pod %q, want %q", gotID, tt.want)
			}
		})
	}

	t.Run("unknown name is NotFound through VKProvider.GetPod", func(t *testing.T) {
		r, _ := newRuntimedFake(t)
		if _, err := NewVKProvider(r, "n").GetPod(context.Background(), "default", "ghost"); err == nil {
			t.Fatal("GetPod of an untracked name returned no error")
		}
	})
}
