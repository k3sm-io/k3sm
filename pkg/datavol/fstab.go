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

package datavol

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
)

// fstabBackupSuffix is appended to /etc/fstab before k3sm rewrites it, so the
// operator's own lines are recoverable from a file beside the original.
const fstabBackupSuffix = ".k3sm-bak"

// EnsureFstabLine appends the k3sm data-volume line to the fstab at path
// unless a line already claims mountpoint, and reports whether it added one.
//
// The line is the SECOND declaration of the volume (see the package comment):
// diskarbitrationd mounts from it at boot, and a k3sm binary too old to read
// the record still perceives the volume through it and still refuses an
// unmounted data root. An existing line for the mountpoint is left exactly as
// the operator wrote it -- adoption keeps what it finds.
func EnsureFstabLine(fsys dataroot.FS, path, uuid, mountpoint string) (bool, error) {
	content, err := readFstab(fsys, path)
	if err != nil {
		return false, err
	}
	if _, ok := findFstabSpec(content, mountpoint); ok {
		return false, nil
	}
	next := content
	if next != "" && !strings.HasSuffix(next, "\n") {
		next += "\n"
	}
	next += fmt.Sprintf("UUID=%s %s apfs rw,%s\n", uuid, mountpoint, MountOptions)
	if err := rewriteFstab(path, content, next); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveFstabLine removes every line whose mount point is mountpoint from the
// fstab at path, and reports whether it removed any. It matches the mount
// point exactly, so an unrelated line for another volume is never touched.
func RemoveFstabLine(fsys dataroot.FS, path, mountpoint string) (bool, error) {
	content, err := readFstab(fsys, path)
	if err != nil {
		return false, err
	}
	if content == "" {
		return false, nil
	}
	lines := strings.Split(content, "\n")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if _, dir, ok := fstabFields(line); ok && filepath.Clean(dir) == filepath.Clean(mountpoint) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return false, nil
	}
	if err := rewriteFstab(path, content, strings.Join(kept, "\n")); err != nil {
		return false, err
	}
	return true, nil
}

// fstabSpecFor reports the device specification of the fstab line that
// declares mountpoint, if there is one.
func fstabSpecFor(fsys dataroot.FS, path, mountpoint string) (string, bool) {
	content, err := readFstab(fsys, path)
	if err != nil {
		return "", false
	}
	return findFstabSpec(content, mountpoint)
}

// fstabTarget turns an fstab device specification into something diskutil
// accepts: a UUID= or LABEL= spec carries its argument after the '=', and a
// device node is already a target.
func fstabTarget(spec string) string {
	for _, prefix := range []string{"UUID=", "LABEL="} {
		if strings.HasPrefix(spec, prefix) {
			return strings.TrimPrefix(spec, prefix)
		}
	}
	return spec
}

// findFstabSpec scans fstab content for a line whose mount point is
// mountpoint.
func findFstabSpec(content, mountpoint string) (string, bool) {
	want := filepath.Clean(mountpoint)
	for _, line := range strings.Split(content, "\n") {
		spec, dir, ok := fstabFields(line)
		if ok && filepath.Clean(dir) == want {
			return spec, true
		}
	}
	return "", false
}

// fstabFields splits one fstab(5) line into its specification and mount point.
// A blank line, a comment, or a line with fewer than two fields declares
// nothing.
func fstabFields(line string) (spec, dir string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", "", false
	}
	fields := strings.Fields(t)
	if len(fields) < 2 {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// readFstab returns the fstab content at path. An absent file reads as empty:
// a Mac with no /etc/fstab has simply declared nothing.
func readFstab(fsys dataroot.FS, path string) (string, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

// rewriteFstab writes next to path atomically, keeping a copy of the previous
// content beside it first. Both the backup and the new file are 0644, the mode
// vifs(8) leaves /etc/fstab in.
func rewriteFstab(path, previous, next string) error {
	if previous != "" {
		if err := os.WriteFile(path+fstabBackupSuffix, []byte(previous), 0o644); err != nil {
			return fmt.Errorf("back up %s: %w", path, err)
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".fstab-k3sm-*")
	if err != nil {
		return fmt.Errorf("create a temp fstab in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename succeeded

	if _, err := tmp.WriteString(next); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
