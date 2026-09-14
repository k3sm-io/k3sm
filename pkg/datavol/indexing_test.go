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
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestIndexingMarkers exercises the real Darwin implementation against a temp
// directory. Both mechanisms exist because the obvious tool does not work on a
// nobrowse volume: mdutil reports "unknown indexing state" because Spotlight
// does not track one, and tmutil is gated behind Full Disk Access and exits 80
// even as root. Neither replacement needs privilege, which is why this is a
// unit test and not a lab rung.
func TestIndexingMarkers(t *testing.T) {
	ctx := context.Background()

	t.Run("Spotlight is refused with a marker file at the volume root", func(t *testing.T) {
		dir := t.TempDir()
		if err := (Darwin{}).SpotlightOff(ctx, dir); err != nil {
			t.Fatalf("SpotlightOff: %v", err)
		}
		marker := filepath.Join(dir, ".metadata_never_index")
		fi, err := os.Stat(marker)
		if err != nil {
			t.Fatalf("the marker was not written: %v", err)
		}
		if fi.Size() != 0 {
			t.Fatalf("marker is %d bytes, want empty", fi.Size())
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("marker mode = %v, want 0644", fi.Mode().Perm())
		}
		// mdutil's answer for a directory it does not track must not turn a
		// successful exclusion into a failure, and a second run is a no-op.
		if err := (Darwin{}).SpotlightOff(ctx, dir); err != nil {
			t.Fatalf("SpotlightOff (second): %v", err)
		}
	})

	t.Run("Time Machine is refused with the exclusion xattr", func(t *testing.T) {
		dir := t.TempDir()
		if err := (Darwin{}).TimeMachineExclude(ctx, dir); err != nil {
			t.Fatalf("TimeMachineExclude: %v", err)
		}
		buf := make([]byte, 256)
		n, err := unix.Getxattr(dir, timeMachineExcludeAttr, buf)
		if err != nil {
			t.Fatalf("the exclusion xattr was not set: %v", err)
		}
		if got := string(buf[:n]); got != timeMachineExcludeValue {
			t.Fatalf("xattr = %q, want %q", got, timeMachineExcludeValue)
		}
		if err := (Darwin{}).TimeMachineExclude(ctx, dir); err != nil {
			t.Fatalf("TimeMachineExclude (second): %v", err)
		}
	})

	t.Run("a mount point that is not there is an error, not a silent pass", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent")
		if err := (Darwin{}).SpotlightOff(ctx, missing); err == nil {
			t.Fatal("SpotlightOff reported success with nowhere to write the marker")
		}
		if err := (Darwin{}).TimeMachineExclude(ctx, missing); err == nil {
			t.Fatal("TimeMachineExclude reported success with nothing to exclude")
		}
	})
}
