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

// Package childreq names the module requirements k3sm raises above what a pinned
// child's own go.mod selects, and applies them to a module tree.
//
// kine and zot are built from pinned upstream module source, out of k3sm's go.mod.
// Their dependency graphs are the ones the upstream tags pin, except where a
// dependency carries a fix the tag predates: then the child is built with that one
// requirement raised, and nothing else moves. kine is built from a patched copy of
// its own module, so Apply raises the requirement in that copy's go.mod and adds
// the hashes to its go.sum; zot is built from a wrapper module
// (pkg/registrysvc/zotchild) whose go.mod requires zot at its pin and each raise
// below, which the registrysvc tests check against this list.
//
// A raise is a build-time requirement only. The go.sum hashes are the checksum
// database's, recorded here so the build runs -mod=readonly: every module is
// hash-checked against a lockfile this repo carries, never against what a proxy
// serves on the day.
package childreq

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// XNetVersion is the golang.org/x/net version kine and zot are built against.
// v0.60.0 fixes GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612 and
// GO-2026-6617 in its HTTP/2 code; both pinned tags select v0.59.0. Its own
// requirements (x/crypto, x/sys, x/term, x/text) are the versions both tags
// already select, so raising it moves no other module. hack/release/stage.sh
// reads this line as the floor a staged kine or zot must link.
const XNetVersion = "v0.60.0"

// Requirement is one raised module requirement and its go.sum hashes.
type Requirement struct {
	// Path is the module path.
	Path string
	// Version is the version the child is built against.
	Version string
	// Sum is the module zip's go.sum hash and GoModSum its go.mod's.
	Sum, GoModSum string
}

// Raises is the set of raised requirements both children are built with.
// Changing it changes what the children link, so it changes kine's patch-set id
// (pkg/executor kineBuildVariant) and zot's build variant (pkg/registrysvc
// zotBuildVariant) too; each package's tests hold that link.
var Raises = []Requirement{{
	Path:     "golang.org/x/net",
	Version:  XNetVersion,
	Sum:      "h1:79p50tfZlm0J9YfoDsSi639qSXNGVwEzOPLCxM2FsYU=",
	GoModSum: "h1:2DA/G1UfVbCpQPeWTmMPGY7Cs2PkBkwu743bVX5PIVg=",
}}

// ErrNotARaise marks a requirement the tree already meets or exceeds: the pin
// moved past the raise, which is then dropped (and the variants changed) rather
// than silently applied as a no-op or a downgrade.
var ErrNotARaise = errors.New("the module already requires this version or newer")

// Apply raises each requirement in the go.mod at root and adds its hashes to the
// go.sum there. The module must already be required on exactly one go.mod line at
// a version strictly below the raise; anything else is an error naming the module,
// never a silent skip, so a pin bump that already carries the fix stops the build
// and makes someone drop the raise.
func Apply(root string, reqs []Requirement) error {
	modPath := filepath.Join(root, "go.mod")
	mod, err := os.ReadFile(modPath)
	if err != nil {
		return fmt.Errorf("raise requirements: %w", err)
	}
	lines := strings.Split(string(mod), "\n")
	var sums strings.Builder
	for _, r := range reqs {
		if err := raiseLine(lines, r); err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s %s %s\n%s %s/go.mod %s\n", r.Path, r.Version, r.Sum, r.Path, r.Version, r.GoModSum)
	}
	if err := os.WriteFile(modPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("raise requirements: %w", err)
	}
	sumPath := filepath.Join(root, "go.sum")
	sum, err := os.ReadFile(sumPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("raise requirements: %w", err)
	}
	if len(sum) > 0 && sum[len(sum)-1] != '\n' {
		sum = append(sum, '\n')
	}
	if err := os.WriteFile(sumPath, append(sum, sums.String()...), 0o644); err != nil {
		return fmt.Errorf("raise requirements: %w", err)
	}
	return nil
}

// raiseLine rewrites, in place, the one go.mod line requiring r.Path, either a
// "require <path> <version>" line or a "<path> <version>" line in a require block.
func raiseLine(lines []string, r Requirement) error {
	at, block := -1, false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "require ("):
			block = true
			continue
		case block && t == ")":
			block = false
			continue
		}
		f := strings.Fields(t)
		if !block {
			if len(f) < 3 || f[0] != "require" {
				continue
			}
			f = f[1:]
		}
		if len(f) < 2 || f[0] != r.Path {
			continue
		}
		if at >= 0 {
			return fmt.Errorf("raise %s: go.mod requires it on more than one line", r.Path)
		}
		at = i
	}
	if at < 0 {
		return fmt.Errorf("raise %s: go.mod does not require it", r.Path)
	}
	f := strings.Fields(lines[at])
	old := f[1]
	if f[0] == "require" {
		old = f[2]
	}
	less, err := versionLess(old, r.Version)
	if err != nil {
		return fmt.Errorf("raise %s: %w", r.Path, err)
	}
	if !less {
		return fmt.Errorf("raise %s to %s: go.mod requires %s: %w", r.Path, r.Version, old, ErrNotARaise)
	}
	lines[at] = strings.Replace(lines[at], r.Path+" "+old, r.Path+" "+r.Version, 1)
	return nil
}

// versionLess reports whether release version a sorts before b. Both must be plain
// "vMAJOR.MINOR.PATCH" release versions, the only form a raise names.
func versionLess(a, b string) (bool, error) {
	pa, err := parseRelease(a)
	if err != nil {
		return false, err
	}
	pb, err := parseRelease(b)
	if err != nil {
		return false, err
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i], nil
		}
	}
	return false, nil
}

// parseRelease splits "vX.Y.Z" into its three numbers.
func parseRelease(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if !strings.HasPrefix(v, "v") || len(parts) != 3 {
		return out, fmt.Errorf("version %q is not a vX.Y.Z release", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strconv.Itoa(n) != p {
			return out, fmt.Errorf("version %q is not a vX.Y.Z release", v)
		}
		out[i] = n
	}
	return out, nil
}
