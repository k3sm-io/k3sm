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
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	netv1 "k3sm.io/apis/net/v1"
)

// TestLimitationsDocMatchesEgressDefault pins the user-facing limitations page
// to what toPodBox actually does: every plain native pod gets outbound network,
// so the page must not claim egress is denied without an annotation.
func TestLimitationsDocMatchesEgressDefault(t *testing.T) {
	t.Run("plain pod allows network", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "plain", UID: types.UID("uid-plain")},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c0", Image: "registry/plain:latest"}}},
		}
		box, err := toPodBox(pod, "10.42.0.5", "10.42.0.5", t.TempDir(), "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if !box.GetSandboxProfile().GetAllowNetwork() {
			t.Fatal("AllowNetwork = false for a plain pod; the doc's egress sentence would be wrong")
		}
	})

	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "docs", "user", "limitations.md"))
	if err != nil {
		t.Fatalf("read limitations.md: %v", err)
	}
	doc := strings.Join(strings.Fields(string(raw)), " ")

	for _, tc := range []struct {
		name    string
		phrase  string
		present bool
	}{
		{"stale egress-denied claim is gone", "denied unless it carries the `k3sm.io/internet-egress` annotation", false},
		{"plain egress statement is present", "every native Pod may open outbound connections on the host network stack", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Contains(doc, tc.phrase); got != tc.present {
				t.Errorf("doc contains %q = %v, want %v", tc.phrase, got, tc.present)
			}
		})
	}
}
