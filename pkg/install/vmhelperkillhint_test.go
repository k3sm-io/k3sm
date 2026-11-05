// Copyright The k3sm Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"strings"
	"testing"
)

// TestTeardownKillHintNamesThePod pins that the by-hand kill hint carries the
// pod's own command-line token (its run dir's log path) and not another pod's,
// so a recycled group running the same retained helper for a different pod
// does not pass the check.
func TestTeardownKillHintNamesThePod(t *testing.T) {
	exe := DefaultInstallDir + "/versions/0.2.8/" + VMHostName
	a := VMHostRecord{PodID: "pod-a", Pgid: 41, RunDir: "/var/run/pods/pod-a/run"}
	b := VMHostRecord{PodID: "pod-b", Pgid: 42, RunDir: "/var/run/pods/pod-b/run"}
	hint := vmHelperKillHint(a, exe)
	if !strings.Contains(hint, a.RunDir+"/") {
		t.Errorf("hint lacks the pod's own run dir token: %s", hint)
	}
	if strings.Contains(hint, b.RunDir) || strings.Contains(hint, "pod-b") {
		t.Errorf("hint carries another pod's token: %s", hint)
	}
	if !strings.Contains(hint, "command line") {
		t.Errorf("hint does not say the comparison is by command line: %s", hint)
	}
	if h := vmHelperKillHint(VMHostRecord{PodID: "pod-c", Pgid: 43}, exe); strings.Contains(h, "sudo kill") {
		t.Errorf("a record with no run dir must not offer the bare kill: %s", h)
	}
}
