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
// kine is built from pinned upstream module source, out of k3sm's go.mod. Its
// dependency graph is the one the upstream tag pins, except where a dependency
// carries a fix the tag predates: then it is built with that requirement raised,
// together with each requirement the raised version itself needs above the tag's,
// and nothing else moves. kine is built from a patched copy of its own
// module, so Apply raises the requirement in that copy's go.mod and adds the hashes
// to its go.sum.
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

// XNetVersion is the golang.org/x/net version kine is built against.
// v0.60.0 fixed GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612 and
// GO-2026-6617 in its HTTP/2 code (kine's pinned tag selects v0.59.0). v0.62.0
// is the x/net the control-plane binaries and the bundled helm are built against,
// which fixes GO-2026-6860 and GO-2026-6866 in the HTML parser and renderer.
// v0.62.0 requires newer golang.org/x/crypto, x/sys, x/term and x/text than the
// tag selects, and that x/text requires a newer golang.org/x/sync, so raising
// x/net moves those five too; each is raised explicitly below so the build stays
// -mod=readonly with every hash recorded here. hack/release/stage.sh reads this
// line as the floor a staged kine must link.
const XNetVersion = "v0.62.0"

// XCryptoVersion, XSysVersion, XTermVersion and XTextVersion are the versions
// golang.org/x/net XNetVersion requires, and XSyncVersion the version
// golang.org/x/text XTextVersion requires; kine's pinned tag selects v0.57.0,
// v0.48.0, v0.46.0, v0.42.0 and v0.23.0. They are raised only because x/net
// needs them.
const (
	XCryptoVersion = "v0.58.0"
	XSysVersion    = "v0.49.0"
	XTermVersion   = "v0.47.0"
	XTextVersion   = "v0.43.0"
	XSyncVersion   = "v0.24.0"
)

// CompressVersion is the github.com/klauspost/compress version kine is
// built against. v1.20.2 fixes GO-2026-6865, a panic on two-block frames in its fse
// and huff0 packages; kine's tag selects v1.20.1. It requires no
// module of its own, so raising it moves no other module.
const CompressVersion = "v1.20.2"

// Requirement is one raised module requirement and its go.sum hashes.
type Requirement struct {
	// Path is the module path.
	Path string
	// Version is the version the child is built against.
	Version string
	// Sum is the module zip's go.sum hash and GoModSum its go.mod's.
	Sum, GoModSum string
}

// Raises is the set of raised requirements kine is built with. Changing it changes
// what kine links, so it changes kine's patch-set id (pkg/executor kineBuildVariant)
// too; that package's tests hold the link.
var Raises = []Requirement{{
	Path:     "golang.org/x/net",
	Version:  XNetVersion,
	Sum:      "h1:18ELalfM5+XNRwzM2nYqXsZQ9ByS1uhj2O/U7+5jqRY=",
	GoModSum: "h1:WgDCOTH8iwtB66T4/GfI94AHo/hhdb7Hah9NDseQfiI=",
}, {
	Path:     "golang.org/x/crypto",
	Version:  XCryptoVersion,
	Sum:      "h1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=",
	GoModSum: "h1:Xh+kl5A+M0gMiWDytH2Hhr5Z7WbNCpv/eB/EFgfSk+w=",
}, {
	Path:     "golang.org/x/sys",
	Version:  XSysVersion,
	Sum:      "h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=",
	GoModSum: "h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=",
}, {
	Path:     "golang.org/x/term",
	Version:  XTermVersion,
	Sum:      "h1:cpyOwQkr2Nzxe2p6KnrTG7Ei2wtzjsuSjhpXXepZ/BM=",
	GoModSum: "h1:efAfAuG6RKABvg1ArGebRkvX6LXul14SM67o2e4mUCY=",
}, {
	Path:     "golang.org/x/text",
	Version:  XTextVersion,
	Sum:      "h1:1QivrlhwAsnMOcqgOdl9my7s9OyZl8O5/UGUTJVXoWc=",
	GoModSum: "h1:hbSIYA/amXcRXTFSZqh8tWHEoqRvvbKPJ2uz/KU+a+s=",
}, {
	Path:     "golang.org/x/sync",
	Version:  XSyncVersion,
	Sum:      "h1:iqiDrGoDgyuvAKrhLQthUEzU/R378N78gXbBjxed7oA=",
	GoModSum: "h1:sUUOizhqBxiL6pEWpqNLUiaJn1ShEbZ6BBqskPbjZm0=",
}, {
	Path:     "github.com/klauspost/compress",
	Version:  CompressVersion,
	Sum:      "h1:v5tiZvm1KGLyg5d5oXdXe3lsSPrbEUiKoXGia//I7Qo=",
	GoModSum: "h1:LUdAzn7YLVvxLpc7y3V1m40wESHTgc1422pwwBSKYuI=",
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
