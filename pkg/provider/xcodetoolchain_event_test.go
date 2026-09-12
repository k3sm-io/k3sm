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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestXcodeToolchainUngrantedEvent is the pod-visible-signal gate: a pod that
// asked for the node's developer toolchain and got nothing must say so ON THE
// POD, because after the CLT filter above the pod otherwise starts and reports
// perfectly healthy while its build silently uses a different toolchain. The
// daemon's construction-time WARN cannot cover this — it is written once, when
// the daemon starts, possibly days before this pod is scheduled.
func TestXcodeToolchainUngrantedEvent(t *testing.T) {
	const xcode = "/Applications/Xcode.app/Contents/Developer"
	const clt = "/Library/Developer/CommandLineTools"

	cases := []struct {
		name        string
		nodeDir     string // "" → a node with no toolchain at all
		annotated   bool
		wantEvent   bool
		wantInEvent []string
	}{
		{
			name:    "command line tools node warns and names what the node has",
			nodeDir: clt, annotated: true, wantEvent: true,
			wantInEvent: []string{runtimev1.AnnotationXcodeToolchain, clt, "xcode-select -s"},
		},
		{
			name:    "node with no toolchain warns",
			nodeDir: "", annotated: true, wantEvent: true,
			wantInEvent: []string{runtimev1.AnnotationXcodeToolchain, "no developer directory selected"},
		},
		// A granted pod has nothing to report; an Event here would train an
		// operator to ignore the one that matters.
		{name: "xcode node grants and stays silent", nodeDir: xcode, annotated: true, wantEvent: false},
		// The pod never asked, so the node's toolchain is not its business.
		{name: "unannotated pod on a CLT node stays silent", nodeDir: clt, annotated: false, wantEvent: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withDeveloperDir(t, tc.nodeDir)
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
				NodeName: "n", NodeIP: "10.0.0.5", Root: t.TempDir(), Recorder: rec,
			}, nil, nil)

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default", Name: "build", UID: types.UID("uid-" + tc.name),
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c0", Image: "img"}}},
			}
			if tc.annotated {
				pod.Annotations = map[string]string{runtimev1.AnnotationXcodeToolchain: ""}
			}
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}

			if !tc.wantEvent {
				if e := nextLifecycleEvent(rec.Events, 100*time.Millisecond); e != "" {
					t.Fatalf("unexpected Event %q", e)
				}
				return
			}
			got := nextLifecycleEvent(rec.Events, 3*time.Second)
			if !strings.HasPrefix(got, "Warning "+reasonXcodeToolchainUngranted+" ") {
				t.Fatalf("Event = %q, want a Warning %s", got, reasonXcodeToolchainUngranted)
			}
			for _, want := range tc.wantInEvent {
				if !strings.Contains(got, want) {
					t.Errorf("Event missing %q: %q", want, got)
				}
			}
		})
	}
}
