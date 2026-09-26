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

// makeShadowSet makes the shadow shell set in the staging tree: for each of
// shadow.Shells, a clone of the host binary at <shadow>/<name>, root:wheel
// 0755, re-signed ad hoc, and the source's cdhash recorded; then the manifest.
//
// Why: dyld drops DYLD_INSERT_LIBRARIES for a platform binary, so a pod that
// starts through /bin/sh loses the DNS and path-rebase shims for everything it
// runs. runtimed execs these copies instead (runtime.Config.ShadowBinDir), and
// an ad-hoc re-signed copy is not restricted.
//
// A missing source (a host without /bin/dash) is a WARN and the set goes on
// without it: runtimed keeps the host exec for a copy that is not there. Any
// other failure fails the install, which has written nothing live yet.
func makeShadowSet(sys System, cfg Config) error {
	dir := cfg.stagedShadowDir()
	if err := sys.EnsureRootDir(dir, shadowOwnership.dirMode); err != nil {
		return fmt.Errorf("install: create the shadow shell dir %s: %w", dir, err)
	}
	m := shadow.Manifest{Version: shadow.ManifestVersion}
	for _, sh := range shadow.Shells {
		dst := filepath.Join(dir, sh.Name)
		if err := sys.CloneToOwned(sh.Source, dst, shadowOwnership.uid, shadowOwnership.gid, shadowOwnership.mode); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				cfg.Logger.Warn("host shell not present; no shadow copy made (pods that exec it run the host binary)",
					"source", sh.Source)
				continue
			}
			return fmt.Errorf("install: clone %s to %s: %w", sh.Source, dst, err)
		}
		if err := sys.AdHocSign(dst); err != nil {
			return fmt.Errorf("install: re-sign the shadow copy %s: %w", dst, err)
		}
		h, err := sys.CDHash(sh.Source)
		if err != nil {
			return fmt.Errorf("install: read the cdhash of %s: %w", sh.Source, err)
		}
		m.Sources = append(m.Sources, shadow.Source{Name: sh.Name, Path: sh.Source, CDHash: h})
	}
	b, err := shadow.Encode(m)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	path := filepath.Join(dir, shadow.ManifestName)
	if err := sys.WriteRootOnlyFile(path, b, shadowOwnership.manifestMode); err != nil {
		return fmt.Errorf("install: write the shadow manifest %s: %w", path, err)
	}
	cfg.Logger.Info("made the shadow shell set", "dir", shadow.Dir(cfg.InstallDir), "copies", len(m.Sources))
	return nil
}
