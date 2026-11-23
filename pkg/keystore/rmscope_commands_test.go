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

package keystore

import (
	"strings"
	"testing"
)

// rmScopeCommands is the whole set of commands any rm-scope result may
// hold (docs/design/keystore.md § "The command rule"): its own rerun line,
// built from the integer uid; the verb's follow-up on success (printed by
// cmd/k3sm, listed so one set holds for both layers); the shared store
// lock's stop of the server (errStoreLockHeld); and the root-file helper's
// flag repair on a root-owned file in the data root (rootFileFlagRepair),
// whose path is root's, never the service user's.
var rmScopeCommands = []string{
	"sudo k3sm keys rm-scope user/1001 --yes",
	"sudo k3sm keys floor --rebuild",
	"sudo k3sm stop",
	"sudo chflags 0 '",
}

// checkRmScopeCommands fails when msg holds a sudo outside
// rmScopeCommands.
func checkRmScopeCommands(t *testing.T, msg string) {
	t.Helper()
	for rest := msg; ; {
		i := strings.Index(rest, "sudo")
		if i < 0 {
			return
		}
		ok := false
		for _, c := range rmScopeCommands {
			if strings.HasPrefix(rest[i:], c) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("the rm-scope result %q holds a command outside the set %q", msg, rmScopeCommands)
			return
		}
		rest = rest[i+len("sudo"):]
	}
}

// The command set holds for the results this round added: the
// newest-scope refusal, the delivery checks, and the keyless paths' notes,
// and for the shared helpers' texts rm-scope passes through.
func TestRmScopeCommandSet(t *testing.T) {
	for _, msg := range []string{
		errStoreLockHeld.Error(),
		scopeRemovedErr(1001).Error(),
		scopeRemovedUnverified("user/1001", errStoreLockHeld),
		scopeRemovedUnconfirmed("user/1001", heldKey{}, nil, 0),
		rmErrText(errFloorDegraded),
	} {
		checkRmScopeCommands(t, msg)
	}
	s, _, _ := fileLogScope(t)
	checkRmScopeCommands(t, (&rmRun{u: rmScopeOf(s, 1001)}).newestNote(errStoreLockHeld))
}
