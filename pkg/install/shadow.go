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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/shadow"
)

// shadowOwnership is the owner and mode of every shadow-set file: root:wheel,
// never writable by the service user, executable by it. The manifest is the
// same owner, read-only for everyone else.
var shadowOwnership = struct {
	uid, gid     int
	mode         fs.FileMode
	manifestMode fs.FileMode
	dirMode      fs.FileMode
}{uid: 0, gid: 0, mode: 0o755, manifestMode: 0o644, dirMode: 0o755}

// stagedShadowDir is the shadow directory under the staging tree; its live
// counterpart is shadow.Dir(InstallDir).
func (c Config) stagedShadowDir() string { return c.stagedPath(shadow.Dir(c.InstallDir)) }

// shadowSetBudget bounds the whole set: one codesign run keeps its own
// timeout (shadowSignTimeout), and the set as a whole stops at this deadline,
// checked before each copy, so a wedged codesign cannot multiply by the number
// of copies. Making the full set takes a few seconds on a current Mac.
var shadowSetBudget = 5 * time.Minute

// makeShadowSet makes the shadow binary set in the staging tree: for each of
// shadow.Copies(), a clone of the host binary at <shadow>/<name>, root:wheel
// 0755 (an explicit mode, so a source mode bit such as setuid never survives),
// re-signed ad hoc, then verified, and the source's cdhash recorded; then the
// manifest, in the list's order.
//
// Why: dyld drops DYLD_INSERT_LIBRARIES for a platform binary, so a pod that
// starts through /bin/sh loses the DNS and path-rebase shims for everything it
// runs. runtimed execs these copies instead (runtime.Config.ShadowBinDir), and
// an ad-hoc re-signed copy is not restricted.
//
// The verification (System.VerifyShadowCopy) is what makes the copy safe to
// hand to every pod: a regular file, not SF_RESTRICTED, no setuid, setgid or
// group/world write bit, an ad-hoc signature with neither the hardened runtime
// nor the restrict flag and no entitlements. A copy that fails is an install
// error naming the copy and the property.
//
// A missing source (a host without /bin/dash) is a WARN and the set goes on
// without it: runtimed keeps the host exec for a copy that is not there. Any
// other failure fails the install, which has written nothing live yet.
func makeShadowSet(sys System, cfg Config) error {
	started := time.Now()
	dir := cfg.stagedShadowDir()
	if err := sys.EnsureRootDir(dir, shadowOwnership.dirMode); err != nil {
		return fmt.Errorf("install: create the shadow binary dir %s: %w", dir, err)
	}
	m := shadow.Manifest{Version: shadow.ManifestVersion}
	hashes := make(map[string]string)
	var total int64
	for _, c := range shadow.Copies() {
		if elapsed := time.Since(started); elapsed > shadowSetBudget {
			return fmt.Errorf("install: the shadow binary set took longer than %s (stopped before %s)", shadowSetBudget, c.Name)
		}
		dst := filepath.Join(dir, c.Name)
		if err := sys.CloneToOwned(c.Source, dst, shadowOwnership.uid, shadowOwnership.gid, shadowOwnership.mode); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				cfg.Logger.Warn("host binary not present; no shadow copy made (pods that exec it run the host binary)",
					"copy", c.Name, "source", c.Source)
				continue
			}
			return fmt.Errorf("install: clone %s to %s: %w", c.Source, dst, err)
		}
		if err := sys.AdHocSign(dst); err != nil {
			return fmt.Errorf("install: re-sign the shadow copy %s: %w", dst, err)
		}
		size, err := sys.VerifyShadowCopy(dst)
		if err != nil {
			return fmt.Errorf("install: verify the shadow copy %s: %w", c.Name, err)
		}
		total += size
		h, ok := hashes[c.Source]
		if !ok {
			if h, err = sys.CDHash(c.Source); err != nil {
				return fmt.Errorf("install: read the cdhash of %s: %w", c.Source, err)
			}
			hashes[c.Source] = h
		}
		m.Sources = append(m.Sources, shadow.Source{Name: c.Name, Path: c.Source, CDHash: h})
	}
	b, err := shadow.Encode(m)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	path := filepath.Join(dir, shadow.ManifestName)
	if err := sys.WriteRootOnlyFile(path, b, shadowOwnership.manifestMode); err != nil {
		return fmt.Errorf("install: write the shadow manifest %s: %w", path, err)
	}
	cfg.Logger.Info("made the shadow binary set", "dir", shadow.Dir(cfg.InstallDir), "copies", len(m.Sources),
		"bytes", total, "elapsed", time.Since(started).Round(time.Millisecond))
	return nil
}
