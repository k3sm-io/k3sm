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
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// TestTLSSANDNSNamesLeavesOutAddresses pins what reaches the join handler.
func TestTLSSANDNSNamesLeavesOutAddresses(t *testing.T) {
	got := tlsSANDNSNames([]string{"api.example.test", "192.0.2.5", "fd00::1", "lb.example.test"})
	if !slices.Equal(got, []string{"api.example.test", "lb.example.test"}) {
		t.Errorf("got %v", got)
	}
}

// TestWarnReservedNodeName pins what an installed node under a reserved name reads
// on restart: it is told, and only when it reuses its credential.
func TestWarnReservedNodeName(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	warnReservedNodeName(logger, startModeReuseCredential, "worker-a")
	warnReservedNodeName(logger, startModeTokenJoin, "localhost")
	if logs.Len() != 0 {
		t.Errorf("warned with nothing to say: %s", logs.String())
	}
	warnReservedNodeName(logger, startModeReuseCredential, "localhost")
	for _, want := range []string{"keeps running", "will be refused", "localhost", "--node-name"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("warning %q does not say %q", logs.String(), want)
		}
	}
}
