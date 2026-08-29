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
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// TestContainerStatusIdentityForwarded is the k3sm leg of the B132 gate: the
// provider's status translation carries the runtime's identity pair through to
// the corev1 ContainerStatus the apiserver serves.
//
// It exists as a SEPARATE leg because the runtimed leg
// (runtimed/pkg/runtime::TestContainerStatusIdentityFields) is in another Go
// module: a daemon that populates both fields perfectly proves nothing about a
// translation boundary that drops them, so each module carries the gate for its
// own behaviour.
func TestContainerStatusIdentityForwarded(t *testing.T) {
	const (
		configDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		liveID       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		deadID       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		imageRef     = "example.com/app:v1"
	)
	// The scheme is pinned as a LITERAL as well as against the constant. The
	// format is effectively irreversible — a field that was always empty has no
	// consumers, so the first published spelling becomes the compatibility
	// baseline — so a later rename must fail here and be decided, not absorbed.
	const scheme = "k3sm-runtimed://"
	if got := runtimed.RuntimeName + "://"; got != scheme {
		t.Fatalf("runtime scheme = %q, want %q (the published container_id format)", got, scheme)
	}

	rs := &runtimev1.PodStatus{
		PodId: "uid-identity",
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "10.0.0.9",
		ContainerStatuses: []*runtimev1.ContainerStatus{
			{
				Name:        "app",
				Image:       imageRef,
				ImageId:     configDigest,
				ContainerId: liveID,
				Ready:       true,
				State: &runtimev1.ContainerState{
					Running: &runtimev1.ContainerStateRunning{},
				},
				LastTerminationState: &runtimev1.ContainerState{
					Terminated: &runtimev1.ContainerStateTerminated{
						ExitCode:    1,
						Reason:      "Error",
						ContainerId: deadID,
					},
				},
			},
			{
				// A container with no identity yet (nothing spawned): the
				// translation must publish EMPTY, never a bare scheme.
				Name:  "pending",
				Image: imageRef,
				State: &runtimev1.ContainerState{
					Waiting: &runtimev1.ContainerStateWaiting{Reason: "ContainerCreating"},
				},
			},
		},
	}

	st := toPodStatus(nil, rs, "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)
	if len(st.ContainerStatuses) != 2 {
		t.Fatalf("ContainerStatuses = %d, want 2", len(st.ContainerStatuses))
	}
	cs := st.ContainerStatuses[0]

	// image_id is a content address the runtime resolved; this boundary carries it
	// VERBATIM and never substitutes the mutable reference for it.
	if cs.ImageID != configDigest {
		t.Errorf("ImageID = %q, want the runtime's config digest %q (forwarded verbatim)", cs.ImageID, configDigest)
	}
	if cs.ImageID == cs.Image {
		t.Errorf("ImageID = %q equals the image reference; a mutable tag in a content-addressable field resolves the WRONG artifact", cs.ImageID)
	}

	// container_id is scheme-qualified at this boundary — the `<runtime>://<id>`
	// form every kubelet consumer parses.
	if want := scheme + liveID; cs.ContainerID != want {
		t.Errorf("ContainerID = %q, want %q", cs.ContainerID, want)
	}
	if !strings.HasPrefix(cs.ContainerID, scheme) {
		t.Errorf("ContainerID %q carries no runtime scheme", cs.ContainerID)
	}

	// The terminated mirror carries the PREDECESSOR's id, equally qualified — a
	// consumer correlating a restart must not be handed the successor's id.
	term := cs.LastTerminationState.Terminated
	if term == nil {
		t.Fatal("LastTerminationState.Terminated missing")
	}
	if want := scheme + deadID; term.ContainerID != want {
		t.Errorf("terminated ContainerID = %q, want the predecessor's %q", term.ContainerID, want)
	}

	// An unset id stays unset: a bare scheme would claim an identity it does not name.
	if pending := st.ContainerStatuses[1]; pending.ContainerID != "" {
		t.Errorf("ContainerID = %q for a container with no runtime id, want empty", pending.ContainerID)
	}
}
