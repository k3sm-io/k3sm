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
	"strings"
)

// The verdicts decide can return. Each is a distinct hard failure with its own
// exit code (see exitCode), so a caller can tell WHY a binary was rejected
// without parsing text. A nil verdict is the only PASS.
var (
	errUnsigned     = errors.New("code object is not signed at all")
	errVerifyFailed = errors.New("codesign --verify --strict rejected the signature")
	errAdHoc        = errors.New("ad-hoc signature (no Developer ID)")
	errTeamNotSet   = errors.New("signature carries no Team ID (TeamIdentifier=not set)")
	errNoTeamLine   = errors.New("codesign -dv reported no TeamIdentifier line")
	errWrongTeam    = errors.New("TeamIdentifier is not the pinned signer")
)

// decide is the pure verdict over codesign's answers about ONE file:
// verifyExit is the exit status of `codesign --verify --strict`, dvOut is the
// combined output of `codesign -dv`, and want is the expected Team ID.
//
// It returns nil only when the strict verify succeeded AND the one
// TeamIdentifier line names want. The checks run from the most specific
// diagnosis to the least, so an unsigned binary reports as unsigned rather than
// as a failed verify, and an ad-hoc one as ad-hoc rather than as team-less.
func decide(verifyExit int, dvOut, want string) error {
	if strings.Contains(dvOut, "code object is not signed at all") {
		return errUnsigned
	}
	if verifyExit != 0 {
		return fmt.Errorf("%w (exit %d)", errVerifyFailed, verifyExit)
	}
	if isAdHoc(dvOut) {
		return errAdHoc
	}
	teams := teamIdentifiers(dvOut)
	switch {
	case len(teams) == 0:
		return errNoTeamLine
	case len(teams) > 1:
		return fmt.Errorf("%w: %d TeamIdentifier lines %q", errWrongTeam, len(teams), teams)
	case teams[0] == "not set":
		return errTeamNotSet
	case teams[0] != want:
		return fmt.Errorf("%w: got %q, want %q", errWrongTeam, teams[0], want)
	}
	return nil
}

// isAdHoc reports whether codesign -dv describes an ad-hoc signature: either
// the "Signature=adhoc" line or "adhoc" among the CodeDirectory flags (which
// also covers the linker's own "adhoc,linker-signed" signature).
func isAdHoc(dvOut string) bool {
	for _, line := range strings.Split(dvOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "Signature=adhoc" {
			return true
		}
		if !strings.HasPrefix(line, "CodeDirectory ") {
			continue
		}
		_, flags, ok := strings.Cut(line, "flags=")
		if !ok {
			continue
		}
		open, cls := strings.IndexByte(flags, '('), strings.IndexByte(flags, ')')
		if open < 0 || cls < open {
			continue
		}
		for _, f := range strings.Split(flags[open+1:cls], ",") {
			if f == "adhoc" {
				return true
			}
		}
	}
	return false
}

// teamIdentifiers returns the value of every "TeamIdentifier=" line in dvOut.
func teamIdentifiers(dvOut string) []string {
	var out []string
	for _, line := range strings.Split(dvOut, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier="); ok {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// Exit codes. 0 is PASS; 1 is an operational failure (download, digest
// mismatch, codesign not runnable); 2 is a usage error; 3..8 name the verdict.
const (
	exitOK         = 0
	exitError      = 1
	exitUsage      = 2
	exitUnsigned   = 3
	exitVerifyFail = 4
	exitAdHoc      = 5
	exitTeamNotSet = 6
	exitNoTeamLine = 7
	exitWrongTeam  = 8
)

// exitCode maps a verdict from decide to the process exit status.
func exitCode(verdict error) int {
	switch {
	case verdict == nil:
		return exitOK
	case errors.Is(verdict, errUnsigned):
		return exitUnsigned
	case errors.Is(verdict, errVerifyFailed):
		return exitVerifyFail
	case errors.Is(verdict, errAdHoc):
		return exitAdHoc
	case errors.Is(verdict, errTeamNotSet):
		return exitTeamNotSet
	case errors.Is(verdict, errNoTeamLine):
		return exitNoTeamLine
	case errors.Is(verdict, errWrongTeam):
		return exitWrongTeam
	}
	return exitError
}
