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
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/internal/oslog"
)

// LaunchctlDisable sets the label's disabled bit in the system domain.
// launchctl disable succeeds on an already-disabled label and on one launchd
// has never seen.
func (darwinSystem) LaunchctlDisable(label string) error {
	if out, err := exec.Command("launchctl", "disable", "system/"+label).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl disable %s: %w: %s", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchctlDisabled reads the label's override back from launchctl
// print-disabled system (parsePrintDisabled).
func (darwinSystem) LaunchctlDisabled(label string) (bool, error) {
	out, err := exec.Command("launchctl", "print-disabled", "system").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("launchctl print-disabled system: %w: %s", err, strings.TrimSpace(firstLine(string(out))))
	}
	return parsePrintDisabled(string(out), label)
}

// ReadStopMarker reads the marker through the O_NOFOLLOW regular-file read.
func (darwinSystem) ReadStopMarker(path string) ([]byte, error) {
	return readRegularFile(path)
}

// WriteStopMarker installs the marker 0644 after checking its parent
// (checkStopMarkerDir), through atomicfile.Replace: a temp file beside it,
// fsync, rename over the old marker (never following a link there), and a
// directory fsync.
func (darwinSystem) WriteStopMarker(path string, data []byte) error {
	return writeStopMarkerFile(path, data)
}

// writeStopMarkerFile is WriteStopMarker, split out for the on-disk test.
func writeStopMarkerFile(path string, data []byte) error {
	if err := checkStopMarkerDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := atomicfile.Replace(path, data, 0o644); err != nil {
		return fmt.Errorf("write the stop marker: %w", err)
	}
	return nil
}

// checkStopMarkerDir refuses a marker directory that is a symlink, is not a
// directory, or that a less privileged user could write to or owns
// (atomicfile.CheckTrustedDir: owned by root or by this process, which for
// the root CLI is root, and no group or world write).
func checkStopMarkerDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stop marker directory %s: %w", dir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("stop marker directory %s is a symlink; refusing to write through it", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("stop marker directory %s is not a directory", dir)
	}
	if err := atomicfile.CheckTrustedDir(dir); err != nil {
		return fmt.Errorf("stop marker directory: %w", err)
	}
	return nil
}

// RemoveStopMarker unlinks the marker. Absent is success.
func (darwinSystem) RemoveStopMarker(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ReadVMHostRecords reads the runtime's vm reap store (readVMHostRecords).
func (darwinSystem) ReadVMHostRecords(dataRoot string) ([]VMHostRecord, error) {
	return readVMHostRecords(dataRoot)
}

// OSLog writes msg to the unified log, subsystem io.k3sm, category lifecycle.
func (darwinSystem) OSLog(level slog.Level, msg string) {
	l := oslog.Default
	if level >= slog.LevelError {
		l = oslog.Error
	}
	oslog.Write("lifecycle", l, msg)
}
