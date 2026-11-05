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

package order

import (
	"slices"
	"testing"
)

func TestStart(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       Role
		dataVolume bool
		want       []Job
	}{
		{"server", Server, false, []Job{{NetdLabel, false}, {ServerLabel, false}}},
		{"agent", Agent, false, []Job{{NetdLabel, false}, {AgentLabel, false}}},
		{"server with data volume", Server, true, []Job{{DatavolLabel, true}, {NetdLabel, false}, {ServerLabel, false}}},
		{"agent with data volume", Agent, true, []Job{{DatavolLabel, true}, {NetdLabel, false}, {AgentLabel, false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Start(tc.role, tc.dataVolume); !slices.Equal(got, tc.want) {
				t.Errorf("Start(%v, %v) = %v, want %v", tc.role, tc.dataVolume, got, tc.want)
			}
		})
	}
}

func TestStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		role Role
		want []Job
	}{
		{"server", Server, []Job{{ServerLabel, false}, {NetdLabel, false}}},
		{"agent", Agent, []Job{{AgentLabel, false}, {NetdLabel, false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Stop(tc.role); !slices.Equal(got, tc.want) {
				t.Errorf("Stop(%v) = %v, want %v", tc.role, got, tc.want)
			}
			// Stop must not alias LongRunning's result: a caller that
			// reverses one must not reorder the other.
			if lr := LongRunning(tc.role); lr[0].Label != NetdLabel {
				t.Errorf("LongRunning(%v) starts with %s, want %s", tc.role, lr[0].Label, NetdLabel)
			}
		})
	}
}

func TestNodeDaemon(t *testing.T) {
	for _, tc := range []struct {
		label string
		want  bool
	}{
		{ServerLabel, true},
		{AgentLabel, true},
		{NetdLabel, false},
		{DatavolLabel, false},
		{"", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := IsNodeDaemon(tc.label); got != tc.want {
				t.Errorf("IsNodeDaemon(%q) = %v, want %v", tc.label, got, tc.want)
			}
		})
	}
	if Server.NodeLabel() != ServerLabel || Agent.NodeLabel() != AgentLabel {
		t.Errorf("NodeLabel: server=%s agent=%s", Server.NodeLabel(), Agent.NodeLabel())
	}
}
