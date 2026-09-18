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

			copied := slices.Contains(f.calls, "CopyToRootOwned:/Library/k3sm"+installStagingSuffix+"/"+VMHostName)
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

// TestInstallVerifiesTheVMHostBeforeWritingTheRoot is the gate for the defect
// TestInstallGatesOnVMHostEntitlement above could not catch: that test only
// asserts the k3sm-vmhost helper's OWN copy did not happen on a refusal, which
// already held even when the entitlement check ran immediately before that one
// copy — by then Install had already copied the binary, k3sm-execshim and both
// dylib shims into the install root. A real upgrade hit exactly that: it
// refused on an unsigned staged helper after those artifacts were already on
// disk beside the still-running old daemon, and because launchd's KeepAlive
// execs whatever is there, a daemon crash in that window would have promoted
// an untested mix of old and new binaries — an availability hazard, not mere
// untidiness.
//
// Install's own doc comment promises a refusal writes NOTHING (see the
// preflight block at the top of Install), so this asserts the strong form:
// zero CopyToRootOwned calls of ANY kind, not just the helper's.
func TestInstallVerifiesTheVMHostBeforeWritingTheRoot(t *testing.T) {
	const src = "/tmp/k3sm-vmhost"

	copyCalls := func(calls []string) []string {
		var out []string
		for _, c := range calls {
			if strings.HasPrefix(c, "CopyToRootOwned:") {
				out = append(out, c)
			}
		}
		return out
	}

	t.Run("an entitlement refusal writes nothing", func(t *testing.T) {
		f := &fakeSystem{}
		f.putEntitlement(src, fmt.Errorf("signature grants no %s", VirtualizationEntitlement))
		err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"})
		if err == nil {
			t.Fatal("Install succeeded, want a refusal before anything is copied")
		}
		if calls := copyCalls(f.calls); len(calls) != 0 {
			t.Errorf("install copied artifacts into the root before refusing: %v", calls)
		}
		for _, want := range []string{src, VirtualizationEntitlement, "codesign --force --sign -"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal does not mention %q: %v", want, err)
			}
		}
	})

	t.Run("no override still installs", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if calls := copyCalls(f.calls); len(calls) == 0 {
			t.Error("a clean install copied nothing at all")
		}
	})

	t.Run("a missing helper still installs", func(t *testing.T) {
		f := &fakeSystem{}
		f.putEntitlement(src, fmt.Errorf("stat %s: %w", src, fs.ErrNotExist))
		if err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}); err != nil {
			t.Fatalf("Install: %v, want success (a missing helper is not this gate's business)", err)
		}
		if !slices.Contains(f.calls, "CopyToRootOwned:/Library/k3sm"+installStagingSuffix+"/"+VMHostName) {
			t.Errorf("the vmhost copy itself did not run; calls = %v", f.calls)
		}
	})

	t.Run("a carried datastore-endpoint-file that is gone refuses with zero copies", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		path := stagedEndpointPath(cfg)

		configureServerArgs(f, cfg, "--datastore-endpoint-file", path)
		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install succeeded with a --datastore-endpoint-file naming a file that is not there")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the refusal does not name the missing file: %v", err)
		}
		if calls := copyCalls(f.calls); len(calls) != 0 {
			t.Errorf("install copied artifacts into the root before refusing: %v", calls)
		}
	})
}
