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

package status

import (
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
)

// TestRenderTopStripsControlCharacters pins that the cluster-derived text
// RenderTop prints (the cluster error, node name and role, pod namespace, name
// and node) carries no terminal control, line-break or bidi characters, and
// that every table row stays one line.
func TestRenderTopStripsControlCharacters(t *testing.T) {
	dirty := func(tag string) string { return tag + "\u001b[31m\rx\ny\u202ez" }
	clean := func(tag string) string { return tag + "[31mxyz" }
	forbidden := []string{"\u001b", "\r", "\u202e"}

	check := func(t *testing.T, out string, rows map[string][]string) {
		t.Helper()
		for _, f := range forbidden {
			if strings.Contains(out, f) {
				t.Errorf("output holds %q:\n%q", f, out)
			}
		}
		lines := strings.Split(out, "\n")
		for first, want := range rows {
			found := false
			for _, l := range lines {
				if !strings.Contains(l, clean(first)) {
					continue
				}
				found = true
				for _, w := range want {
					if !strings.Contains(l, clean(w)) {
						t.Errorf("row of %s is not one line holding %q:\n%q", first, clean(w), out)
					}
				}
			}
			if !found {
				t.Errorf("no single line holds %q:\n%q", clean(first), out)
			}
		}
	}

	t.Run("cluster error", func(t *testing.T) {
		out := RenderTop(TopReport{ClusterError: dirty("err")}, Style{})
		check(t, out, map[string][]string{"err": nil})
		if n := strings.Count(out, "\n"); n != 1 {
			t.Errorf("cluster error spans %d lines, want 1:\n%q", n, out)
		}
	})

	t.Run("metrics condition", func(t *testing.T) {
		out := RenderTop(TopReport{Metrics: TopMetrics{Reason: dirty("reason"), Message: dirty("msg")}}, Style{})
		check(t, out, map[string][]string{"reason": {"msg"}})
	})

	t.Run("tables", func(t *testing.T) {
		r := TopReport{
			Nodes: []TopNode{{Name: dirty("node"), Role: dataroot.Role(dirty("role"))}},
			Pods: []TopPod{{
				Namespace: dirty("ns"),
				Name:      dirty("pod"),
				Node:      dirty("on"),
			}},
			PodsTotal: 1,
		}
		out := RenderTop(r, Style{})
		check(t, out, map[string][]string{
			"node": {"role"},
			"ns":   {"pod", "on"},
		})
	})

	t.Run("namespace and sort", func(t *testing.T) {
		r := TopReport{
			Namespace: dirty("ns"),
			Sort:      TopSort(dirty("sort")),
			Metrics:   TopMetrics{Available: true},
			Pods:      []TopPod{{Namespace: "a", Name: "p"}},
			PodsTotal: 1,
		}
		out := RenderTop(r, Style{})
		check(t, out, map[string][]string{"ns": {"sort"}})
	})
}
