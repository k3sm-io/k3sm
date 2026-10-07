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

package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// stagedChild declares one control-plane child that is BUILT from source at a pinned
// version (rather than downloaded) and staged into a bin dir beside a version marker.
// The declaration names the child; ensureInto owns the staging choreography, so every
// such child gets the same guarantees without copying them:
//
//   - a no-op (re-sign only) when, and only when, the marker vouches for exactly
//     (version, variant) and the binary is present;
//   - the ErrNoGoToolchain preflight BEFORE anything is dropped, so a toolchain-less
//     park leaves the previously staged binary and its marker untouched;
//   - the stale marker dropped BEFORE the binary is touched;
//   - the binary installed through a temp name + rename, then ad-hoc signed;
//   - the marker written LAST, atomically, so "marker matches" implies "the binary
//     beside it is finished".
type stagedChild struct {
	// name is the staged binary's basename.
	name string
	// marker is the basename of the version marker written beside the binary.
	marker string
	// version and variant are the pin and build variant the marker records as
	// "<version> <variant>\n".
	version, variant string
	// build produces the binary inside scratch (a per-build temp dir the caller
	// removes) and returns its path. It is the only child-specific step, and the
	// seam a test fakes so nothing is fetched.
	build func(ctx context.Context, scratch string) (builtPath string, err error)
}

func (c stagedChild) binPath(bd string) string    { return filepath.Join(bd, c.name) }
func (c stagedChild) markerPath(bd string) string { return filepath.Join(bd, c.marker) }

// markerContent renders the marker: "<version> <variant>\n".
func (c stagedChild) markerContent() string { return c.version + " " + c.variant + "\n" }

// readChildMarker returns the (version, variant) recorded in the marker at path. A
// missing or unreadable marker yields ("", ""), which no target ever matches — so an
// unmarked binary always re-stages.
func readChildMarker(path string) (version, variant string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	f := strings.Fields(string(b))
	switch len(f) {
	case 0:
		return "", ""
	case 1:
		return f[0], ""
	default:
		return f[0], f[1]
	}
}

// staged reports whether bd holds the binary and a marker vouching for exactly
// (version, variant).
func (c stagedChild) staged(bd string) bool {
	if _, err := os.Stat(c.binPath(bd)); err != nil {
		return false
	}
	v, variant := readChildMarker(c.markerPath(bd))
	return v == c.version && variant == c.variant
}

// writeMarker writes the marker atomically (temp + rename) so a crashed or killed
// boot can never leave a half-written marker vouching for the wrong bytes.
func (c stagedChild) writeMarker(bd string) error {
	tmp := c.markerPath(bd) + ".tmp"
	if err := os.WriteFile(tmp, []byte(c.markerContent()), 0o644); err != nil {
		return fmt.Errorf("write %s version marker: %w", c.name, err)
	}
	if err := os.Rename(tmp, c.markerPath(bd)); err != nil {
		return fmt.Errorf("install %s version marker: %w", c.name, err)
	}
	return nil
}

// ensureInto stages the child into bd under the protocol described on stagedChild.
func (c stagedChild) ensureInto(ctx context.Context, bd string) error {
	if c.staged(bd) {
		return signBinaries(ctx, bd, []string{c.name})
	}
	// Preflight the toolchain BEFORE anything runs `go` (the module-cache probe is the
	// first). Its absence is the one build failure that is deterministic: a launchd
	// PATH without `go` is the same PATH on every respawn, so the daemon's breaker
	// parks on the first such failure instead of counting to its threshold. The
	// sentinel is the ONLY classification; build output is never string-matched.
	// It runs before the stale marker is dropped on purpose: a toolchain-less park
	// then leaves the previously staged binary AND its marker untouched, instead of
	// stranding good bytes unmarked until the operator's remedy rebuilds them.
	if _, err := lookPathGo(); err != nil {
		return fmt.Errorf("build %s %s: %w (%v); %s", c.name, c.version, ErrNoGoToolchain, err, NoGoToolchainRemedy)
	}
	// Drop any stale marker BEFORE touching the binary: from here until the marker is
	// rewritten, the correct answer to "what is staged?" is "nothing trustworthy", and
	// an interrupted re-stage must re-stage again rather than trust a marker that
	// describes bytes we did not finish writing.
	if err := os.Remove(c.markerPath(bd)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear %s version marker: %w", c.name, err)
	}
	scratch, err := os.MkdirTemp("", "k3sm-"+c.name+"-gopath")
	if err != nil {
		return fmt.Errorf("%s build scratch dir: %w", c.name, err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	built, err := c.build(ctx, scratch)
	if err != nil {
		return err
	}
	// Stage through a temp name + rename so an interrupted copy cannot leave a
	// truncated binary at the real path.
	bin := c.binPath(bd)
	if err := copyFile(built, bin+".tmp", 0o755); err != nil {
		return fmt.Errorf("stage %s binary: %w", c.name, err)
	}
	if err := os.Rename(bin+".tmp", bin); err != nil {
		return fmt.Errorf("install %s binary: %w", c.name, err)
	}
	if err := signBinaries(ctx, bd, []string{c.name}); err != nil {
		return err
	}
	// LAST: the marker vouches for a staged, signed binary.
	return c.writeMarker(bd)
}
