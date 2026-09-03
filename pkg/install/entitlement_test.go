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

package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// TestInstallGatesOnVMHostEntitlement pins the fail-closed contract around the
// k3sm-vmhost copy: install refuses to lay down a helper whose signature does not
// grant the virtualization entitlement, because the copy preserves signatures
// verbatim and the consequence of getting this wrong appears nowhere near here
// (a node that loses its k3sm.io/virtualization label and vm pods that report
// only "didn't match node affinity/selector").
//
// The codesign probe is faked at the System seam — no unit test signs anything.
// The real probe is exercised by the integration-tier test in this package.
func TestInstallGatesOnVMHostEntitlement(t *testing.T) {
	const src = "/tmp/k3sm-vmhost"

	tests := []struct {
		name string
		// probe is what the faked codesign read reports for the staged helper.
		probe error
		// refuse is whether Install must stop rather than copy the helper.
		refuse bool
	}{
		{
			name:   "entitled helper is installed",
			probe:  nil,
			refuse: false,
		},
		{
			name:   "signed but unentitled helper is refused",
			probe:  fmt.Errorf("signature grants no %s", VirtualizationEntitlement),
			refuse: true,
		},
		{
			name: "unsigned helper is refused",
			// What codesign actually reports for a bare `go build` artifact that was
			// never signed at all: a non-zero exit, which the seam surfaces as a
			// plain error rather than a distinct arm.
			probe:  fmt.Errorf("codesign -d --entitlements - %s: exit status 1: %s: code object is not signed at all", src, src),
			refuse: true,
		},
		{
			name: "missing helper keeps the copy's own message",
			// Absence is NOT this gate's business: the probe reports fs.ErrNotExist
			// and install falls through to CopyToRootOwned, whose long-standing
			// error already tells an operator to build the helper.
			probe:  fmt.Errorf("stat %s: %w", src, fs.ErrNotExist),
			refuse: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			f.putEntitlement(src, tc.probe)
			err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"})

			copied := slices.Contains(f.calls, "CopyToRootOwned:/Library/k3sm/"+VMHostName)
			if !tc.refuse {
				if err != nil {
					t.Fatalf("Install: %v, want success", err)
				}
				if !copied {
					t.Errorf("helper was not copied; calls = %v", f.calls)
				}
				return
			}

			if err == nil {
				t.Fatal("Install succeeded, want a refusal before the helper is copied")
			}
			if copied {
				t.Error("helper was copied despite the refusal — the gate must run BEFORE the copy")
			}
			// The refusal is only worth having if it carries the fix. Each of these
			// is a distinct thing the operator needs: which file, which entitlement,
			// and the exact command that repairs a dev build.
			for _, want := range []string{
				src,
				VirtualizationEntitlement,
				"codesign --force --sign - --entitlements runtimed/cmd/k3sm-vmhost/vmhost.entitlements " + src,
				"never re-signs it",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not mention %q:\n%v", want, err)
				}
			}
			if !errors.Is(err, tc.probe) {
				t.Errorf("refusal does not wrap the probe verdict: %v", err)
			}
		})
	}
}
