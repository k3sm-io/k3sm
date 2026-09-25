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
	"fmt"
	"testing"

	"k3sm.io/k3sm/pkg/builder"
)

// The fixtures are codesign -dv output shapes recorded on macOS 26. The
// Developer ID shape interpolates the Team ID so the expected signer lives only
// in pkg/builder.
func developerIDOutput(team string) string {
	return fmt.Sprintf(`Executable=/tmp/buildx-v0.37.1.darwin-arm64
Identifier=buildx
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=491626 flags=0x10000(runtime) hashes=15356+2 location=embedded
Signature size=9043
Timestamp=Sep 12, 2026 at 1:02:03 PM
Info.plist=not bound
TeamIdentifier=%s
Runtime Version=15.0.0
Sealed Resources=none
Internal requirements count=1 size=208
`, team)
}

const (
	// codesign -dv on a binary after `codesign --remove-signature`.
	unsignedOutput = "/tmp/u: code object is not signed at all\n"

	// codesign -dv after `codesign -s -`.
	adHocOutput = `Executable=/tmp/a
Identifier=a-555549449c5af3e9678239a19fdd6886c1386ff8
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=259 flags=0x2(adhoc) hashes=2+2 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=0 size=12
`

	// codesign -dv on a freshly linked arm64 binary (the linker's own signature).
	linkerSignedOutput = `Executable=/tmp/m
Identifier=m
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=250 flags=0x20002(adhoc,linker-signed) hashes=5+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
`

	// codesign -dv on a platform binary: signed, not ad-hoc, but team-less.
	platformOutput = `Executable=/usr/bin/true
Identifier=com.apple.true
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=231 flags=0x0(none) hashes=2+2 location=embedded
Platform identifier=26
Signature size=4567
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=1 size=64
`

	// A Developer ID shape with the TeamIdentifier line absent (a truncated or
	// differently-formatted codesign answer must not read as a pass).
	noTeamLineOutput = `Executable=/tmp/buildx
Identifier=buildx
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=491626 flags=0x10000(runtime) hashes=15356+2 location=embedded
Signature size=9043
Sealed Resources=none
`

	// retiredTeam is the individual maintainer's Team ID that signed buildx
	// darwin releases through v0.35.0. It must be rejected.
	retiredTeam = "F32M533787"
)

func TestDecide(t *testing.T) {
	want := builder.HostBuildxTeamID
	tests := []struct {
		name       string
		verifyExit int
		dv         string
		wantErr    error
		wantExit   int
	}{
		{"developer ID with the pinned team passes", 0, developerIDOutput(want), nil, exitOK},
		{"unsigned binary", 1, unsignedOutput, errUnsigned, exitUnsigned},
		{"unsigned wins even if verify exit is 0", 0, unsignedOutput, errUnsigned, exitUnsigned},
		{"ad-hoc signature", 0, adHocOutput, errAdHoc, exitAdHoc},
		{"linker-signed ad-hoc signature", 0, linkerSignedOutput, errAdHoc, exitAdHoc},
		{"missing TeamIdentifier line", 0, noTeamLineOutput, errNoTeamLine, exitNoTeamLine},
		{"retired individual signer is rejected", 0, developerIDOutput(retiredTeam), errWrongTeam, exitWrongTeam},
		{"any other team is rejected", 0, developerIDOutput("ABCDE12345"), errWrongTeam, exitWrongTeam},
		{"team-less platform signature", 0, platformOutput, errTeamNotSet, exitTeamNotSet},
		{"strict verify failure beats a matching team", 3, developerIDOutput(want), errVerifyFailed, exitVerifyFail},
		{"two TeamIdentifier lines are rejected", 0, developerIDOutput(want) + "TeamIdentifier=" + retiredTeam + "\n", errWrongTeam, exitWrongTeam},
		{"empty output is not a pass", 0, "", errNoTeamLine, exitNoTeamLine},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decide(tc.verifyExit, tc.dv, want)
			if tc.wantErr == nil {
				if got != nil {
					t.Fatalf("decide = %v, want PASS", got)
				}
			} else if !errors.Is(got, tc.wantErr) {
				t.Fatalf("decide = %v, want %v", got, tc.wantErr)
			}
			if code := exitCode(got); code != tc.wantExit {
				t.Fatalf("exitCode(%v) = %d, want %d", got, code, tc.wantExit)
			}
		})
	}
}

// TestExitCodesDistinct pins that every verdict has its own exit status and none
// collides with the pass, operational-error or usage codes.
func TestExitCodesDistinct(t *testing.T) {
	seen := map[int]error{exitOK: nil, exitError: nil, exitUsage: nil}
	for _, v := range []error{errUnsigned, errVerifyFailed, errAdHoc, errTeamNotSet, errNoTeamLine, errWrongTeam} {
		code := exitCode(v)
		if prev, dup := seen[code]; dup {
			t.Fatalf("verdict %v shares exit %d with %v", v, code, prev)
		}
		seen[code] = v
	}
	if code := exitCode(errors.New("other")); code != exitError {
		t.Fatalf("unknown error exit = %d, want %d", code, exitError)
	}
}

// TestPinnedTeamIDShape guards the constant itself: an Apple Team ID is ten
// uppercase alphanumerics, and the retired signer must never be the pin.
func TestPinnedTeamIDShape(t *testing.T) {
	id := builder.HostBuildxTeamID
	if len(id) != 10 {
		t.Fatalf("HostBuildxTeamID %q: want 10 characters", id)
	}
	for _, r := range id {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			t.Fatalf("HostBuildxTeamID %q: %q is not an uppercase alphanumeric", id, r)
		}
	}
	if id == retiredTeam {
		t.Fatalf("HostBuildxTeamID is the retired signer %s", retiredTeam)
	}
}
