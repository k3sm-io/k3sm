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
	"errors"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestNodeNameFromHostname pins that the --node-name default is ALWAYS a valid
// canonical node name, whatever the hostname holds, and that a hostname which
// already gave a valid name keeps giving the same one.
func TestNodeNameFromHostname(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 70)
	for _, tc := range []struct {
		hostname, want string
	}{
		{"plain", "k3sm-plain"},
		{"Alexs-MacBook-Pro.local", "k3sm-alexs-macbook-pro"},
		{"worker-1.lab", "k3sm-worker-1.lab"},
		{"a--b", "k3sm-a--b"},
		{"Alex's MacBook", "k3sm-alex-s-macbook"},
		{"under_score", "k3sm-under-score"},
		{"\u00dcn\u00efcode", "k3sm--n-code"},
		{"host.local.", "k3sm-host"},
		{"host..lab", "k3sm-host.lab"},
		{"-edge-.-x-", "k3sm--edge.x"},
		{"", "k3sm-node"},
		{"\u00e9\u00e9", "k3sm-node"},
		{"...", "k3sm-node"},
		{long, "k3sm-" + long[:63-len("k3sm-")]},
	} {
		got := nodeNameFromHostname(tc.hostname)
		if got != tc.want {
			t.Errorf("nodeNameFromHostname(%q) = %q, want %q", tc.hostname, got, tc.want)
		}
		if c, err := bootstrap.CanonicalNodeName(got); err != nil || c != got {
			t.Errorf("nodeNameFromHostname(%q) = %q is not canonical: %q, %v", tc.hostname, got, c, err)
		}
	}
}

// TestCanonicalServerNodeName pins that the server's --node-name is refused,
// never silently renamed, when it is not already canonical.
func TestCanonicalServerNodeName(t *testing.T) {
	t.Parallel()
	if got, err := canonicalServerNodeName("k3sm-host"); err != nil || got != "k3sm-host" {
		t.Errorf("canonical name: got %q, %v", got, err)
	}
	for _, tc := range []struct {
		given, wantSub string
		invalid        bool
	}{
		{"K3sm-Host", "pass --node-name k3sm-host", false},
		{" k3sm-host", "pass --node-name k3sm-host", false},
		{"k3sm_host", "--node-name", true},
		{"k3sm-host.", "--node-name", true},
		{"\u212a3sm-host", "--node-name", true},
	} {
		_, err := canonicalServerNodeName(tc.given)
		if err == nil {
			t.Errorf("%q: accepted, want an error", tc.given)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%q: error %q does not contain %q", tc.given, err, tc.wantSub)
		}
		if got := errors.Is(err, bootstrap.ErrInvalidNodeName); got != tc.invalid {
			t.Errorf("%q: errors.Is(ErrInvalidNodeName) = %v, want %v", tc.given, got, tc.invalid)
		}
	}
}
