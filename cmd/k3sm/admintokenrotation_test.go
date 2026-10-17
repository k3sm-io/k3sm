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
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/updatectl"
)

// TestAdminTokenRotationIsReportedOnTheNode: the server's node publishes the
// release and time an install left in the rotation marker as one Node
// annotation, "<version> <time>", and then removes the marker. A patch that
// fails is retried until it lands; a node whose context ends first keeps the
// marker for the next start. No marker patches nothing, and a marker that is
// not a time and a version is removed without a patch.
func TestAdminTokenRotationIsReportedOnTheNode(t *testing.T) {
	const marker = "2026-10-17T09:30:00Z\n0.2.0\n"
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name       string
		marker     *string
		failures   int // patches refused before one lands; -1 refuses every one
		annotation string
		kept       bool
		patches    int
	}{
		{name: "a marker is published and consumed", marker: ptrTo(marker), annotation: "0.2.0 2026-10-17T09:30:00Z", patches: 1},
		{name: "a refused patch is retried until it lands", marker: ptrTo(marker), failures: 4, annotation: "0.2.0 2026-10-17T09:30:00Z", patches: 5},
		{name: "a patch that never lands keeps the marker", marker: ptrTo(marker), failures: -1, kept: true},
		{name: "no marker patches nothing"},
		{name: "a marker that is not a time is removed", marker: ptrTo("k3sm-not-a-time\n0.2.0\n")},
		{name: "a marker without a version is removed", marker: ptrTo("2026-10-17T09:30:00Z\n")},
		{name: "a marker whose version is not one is removed", marker: ptrTo("2026-10-17T09:30:00Z\n0.2.0 extra\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := install.AdminTokenRotatedMarkerPath(t.TempDir())
			if tc.marker != nil {
				if err := os.WriteFile(path, []byte(*tc.marker), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cs := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "studio"}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			patches := 0
			cs.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
				patches++
				if tc.failures < 0 || patches <= tc.failures {
					if tc.failures < 0 && patches == 6 {
						cancel() // the daemon stops before any patch lands
					}
					return true, nil, errors.New("apiserver unavailable")
				}
				return false, nil, nil
			})
			reportAdminTokenRotation(ctx, cs, "studio", path, time.Millisecond, 4*time.Millisecond, quiet)

			if tc.failures >= 0 && patches != tc.patches {
				t.Errorf("node patches = %d, want %d", patches, tc.patches)
			}
			n, err := cs.CoreV1().Nodes().Get(context.Background(), "studio", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := n.Annotations[updatectl.AdminTokenRotatedAnnotation]; got != tc.annotation {
				t.Errorf("annotation = %q, want %q", got, tc.annotation)
			}
			_, err = os.Stat(path)
			if kept := err == nil; kept != tc.kept {
				t.Errorf("marker kept = %v, want %v (stat: %v)", kept, tc.kept, err)
			}
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("stat the marker: %v", err)
			}
		})
	}

	t.Run("a marker a newer install rewrote while the patch was in flight is kept", func(t *testing.T) {
		path := install.AdminTokenRotatedMarkerPath(t.TempDir())
		if err := os.WriteFile(path, []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
		const newer = "2026-10-17T10:00:00Z\n0.2.1\n"
		cs := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "studio"}})
		cs.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			if err := os.WriteFile(path, []byte(newer), 0o600); err != nil {
				t.Error(err)
			}
			return false, nil, nil
		})
		reportAdminTokenRotation(context.Background(), cs, "studio", path, time.Millisecond, time.Millisecond, quiet)
		if got, err := os.ReadFile(path); err != nil || string(got) != newer {
			t.Errorf("the newer marker was not left in place: %q, %v", got, err)
		}
	})

	t.Run("only a node told its marker path reports", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		stop := startAdminTokenRotationReport(context.Background(), nodeOptions{nodeName: "laptop"}, cs, quiet)
		stop()
		if got := len(cs.Actions()); got != 0 {
			t.Errorf("a node with no marker path made %d API calls", got)
		}
		if got := install.AdminTokenRotatedMarkerPath("/var/lib/k3sm/server"); got != filepath.Join("/var/lib/k3sm/server", install.AdminTokenRotatedMarkerName) {
			t.Errorf("marker path = %s", got)
		}
	})
}

func ptrTo(s string) *string { return &s }
