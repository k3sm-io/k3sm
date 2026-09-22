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

package mlxfleet

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// recorded reads a testdata record whose file name carries ChartVersion, so a
// bump of the constant without a re-record fails here, by name, rather than
// passing against a stale file.
func recorded(t *testing.T, stem, ext string) []byte {
	t.Helper()
	path := filepath.Join("testdata", stem+"-"+ChartVersion+ext)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no record for chart %s: %v (re-record it from the S2 rung before bumping ChartVersion)", ChartVersion, err)
	}
	return b
}

// TestFleetGVKsMatchPin pins Resources to the CRD set recorded from the chart at
// ChartVersion: a re-pin that moves a group, a version or a kind, or that adds or
// drops a CRD, goes red here instead of a status row silently reading nothing.
func TestFleetGVKsMatchPin(t *testing.T) {
	t.Parallel()

	want := strings.Split(strings.TrimSpace(string(recorded(t, "crds", ".txt"))), "\n")
	var got []string
	for _, r := range Resources() {
		got = append(got, r.Record())
	}
	// Positive control: an empty record would make an empty package pass.
	if len(want) == 0 || want[0] == "" {
		t.Fatal("the CRD record is empty — it measures nothing")
	}
	if !slices.Equal(got, want) {
		t.Errorf("Resources() does not match the CRD set recorded at chart %s\n got: %s\nwant: %s",
			ChartVersion, strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}

	for _, r := range Resources() {
		t.Run(r.Plural, func(t *testing.T) {
			t.Parallel()
			if !slices.Contains(r.Served, r.Storage) {
				t.Errorf("storage version %s is not served (%v)", r.Storage, r.Served)
			}
			if g := r.GVK(); g.Group != Group || g.Version != r.Storage || g.Kind != r.Kind {
				t.Errorf("GVK() = %v", g)
			}
			if p := r.ListPath(); p != fmt.Sprintf("/apis/%s/%s/%s", Group, r.Storage, r.Plural) {
				t.Errorf("ListPath() = %q", p)
			}
		})
	}
}

// TestFleetOperatorRBACPinned pins the operator's cluster-scoped grant, which
// installing the chart confers, as a golden: the ClusterRole recorded verbatim
// at ChartVersion must flatten to the reviewed (group, resource, verb) list, and
// the properties decided when it was read must still hold. A re-pin that widens
// the grant is a diff in the grant file, not a surprise in a cluster.
func TestFleetOperatorRBACPinned(t *testing.T) {
	t.Parallel()

	var role rbacv1.ClusterRole
	if err := yaml.UnmarshalStrict(recorded(t, "operator-clusterrole", ".yaml"), &role); err != nil {
		t.Fatalf("parse the recorded ClusterRole: %v", err)
	}
	if role.Kind != "ClusterRole" || len(role.Rules) == 0 {
		t.Fatalf("the record is not a ClusterRole with rules (kind %q, %d rules)", role.Kind, len(role.Rules))
	}

	t.Run("record_names_the_pinned_chart", func(t *testing.T) {
		t.Parallel()
		if v := role.Labels["app.kubernetes.io/version"]; v != ChartVersion {
			t.Errorf("the recorded role is labelled version %q, ChartVersion is %q", v, ChartVersion)
		}
	})

	t.Run("grant_matches_the_reviewed_list", func(t *testing.T) {
		t.Parallel()
		want := strings.Split(strings.TrimSpace(string(recorded(t, "operator-grant", ".txt"))), "\n")
		got := flatten(role)
		if !slices.Equal(got, want) {
			t.Errorf("the ClusterRole flattens to %d grants, the reviewed list has %d; diff the two files under testdata/", len(got), len(want))
			for _, line := range difference(got, want) {
				t.Errorf("granted but not reviewed: %s", line)
			}
			for _, line := range difference(want, got) {
				t.Errorf("reviewed but not granted: %s", line)
			}
		}
	})

	t.Run("no_wildcard_anywhere", func(t *testing.T) {
		t.Parallel()
		for i, rule := range role.Rules {
			for _, list := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs} {
				if slices.Contains(list, "*") {
					t.Errorf("rule %d carries a wildcard: %v %v %v", i, rule.APIGroups, rule.Resources, rule.Verbs)
				}
			}
			if len(rule.NonResourceURLs) > 0 {
				t.Errorf("rule %d grants non-resource URLs %v", i, rule.NonResourceURLs)
			}
		}
	})

	// The one grant that was weighed rather than read: the operator mints and
	// rotates its own webhook serving certificate, which is why it holds every
	// verb on Secrets cluster-wide. A namespaced Role would confine it; the chart
	// does not ship one, and this is the record of that decision.
	t.Run("secrets_verbs_are_the_decided_set", func(t *testing.T) {
		t.Parallel()
		want := []string{"create", "delete", "get", "list", "patch", "update", "watch"}
		var got []string
		for _, rule := range role.Rules {
			if slices.Contains(rule.APIGroups, "") && slices.Contains(rule.Resources, "secrets") {
				got = append(got, rule.Verbs...)
			}
		}
		slices.Sort(got)
		if got = slices.Compact(got); !slices.Equal(got, want) {
			t.Errorf("secrets verbs = %v, want %v", got, want)
		}
	})
}

// flatten renders a ClusterRole as sorted "group resource verb" lines, the
// core group spelled core so every line has three words.
func flatten(role rbacv1.ClusterRole) []string {
	var lines []string
	for _, rule := range role.Rules {
		for _, g := range rule.APIGroups {
			if g == "" {
				g = "core"
			}
			for _, res := range rule.Resources {
				for _, verb := range rule.Verbs {
					lines = append(lines, g+" "+res+" "+verb)
				}
			}
		}
	}
	slices.Sort(lines)
	return slices.Compact(lines)
}

// difference returns the lines of a that b lacks; both are sorted.
func difference(a, b []string) []string {
	var out []string
	for _, line := range a {
		if _, found := slices.BinarySearch(b, line); !found {
			out = append(out, line)
		}
	}
	return out
}
