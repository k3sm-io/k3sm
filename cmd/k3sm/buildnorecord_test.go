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
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildNoRecordNeverDialsStore pins the --no-record contract: the build
// delivers to --output and/or --push and never reaches the store recorder (the
// seam that dials the runtime daemon), so a user who cannot reach the daemon's
// socket can build; and a --no-record build with neither sink is refused at
// parse time, before any work.
func TestBuildNoRecordNeverDialsStore(t *testing.T) {
	cases := []struct {
		name       string
		output     string
		format     string
		push       bool
		wantOutput bool
		// wantHint is the root step the summary must name, with %s standing for
		// the --output path.
		wantHint string
	}{
		{name: "docker output only", output: "img.tar", format: "docker", wantOutput: true, wantHint: "sudo k3sm image load %s"},
		{name: "oci output only", output: "layout", format: "oci", wantOutput: true, wantHint: "tar -cf %[1]s.tar -C %[1]s . && sudo k3sm image import %[1]s.tar"},
		{name: "push only", format: "docker", push: true, wantHint: "write an artifact with --output"},
		{name: "oci output and push", output: "layout", format: "oci", push: true, wantOutput: true, wantHint: "sudo k3sm image import %[1]s.tar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--no-record", "-t", "example.com/app:v1", "--format", tc.format}
			out := ""
			if tc.output != "" {
				out = filepath.Join(t.TempDir(), tc.output)
				args = append(args, "--output", out)
			}
			if tc.push {
				args = append(args, "--push")
			}
			ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
			o, err := parseBuildArgs(append(args, ctxDir), io.Discard)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !o.noRecord {
				t.Fatal("--no-record did not set noRecord")
			}

			// Both entry points: buildWith proves deliver skips the store, and
			// buildRecorded (the production wrapper) proves the seam it hands down
			// is never the caller's recorder either.
			for _, entry := range []string{"buildWith", "buildRecorded"} {
				if out != "" {
					// Each entry point writes the artifact afresh.
					if err := os.RemoveAll(out); err != nil {
						t.Fatal(err)
					}
				}
				store := &recordingStore{}
				var log []string
				pusher := &recordingPush{log: &log}
				var summary bytes.Buffer
				if entry == "buildWith" {
					err = buildWith(t.Context(), o, &summary, engineBuildWith(recordInStore), store.record, pusher.push)
				} else {
					err = buildRecorded(t.Context(), nil, o, &summary, engineBuildWith, store.record, pusher.push)
				}
				if err != nil {
					t.Fatalf("%s: build: %v", entry, err)
				}
				if len(store.calls) != 0 {
					t.Fatalf("%s: the store was recorded under --no-record: %v", entry, store.calls)
				}
				if tc.push != (len(pusher.targets) == 1) {
					t.Errorf("%s: push targets = %v, want a push iff --push", entry, pusher.targets)
				}
				if tc.wantOutput {
					if _, statErr := os.Stat(out); statErr != nil {
						t.Errorf("%s: --output wrote no artifact: %v", entry, statErr)
					}
				}
				s := summary.String()
				if !strings.Contains(s, "not recorded (--no-record)") {
					t.Errorf("%s: the summary does not say the image was not recorded:\n%s", entry, s)
				}
				hint := tc.wantHint
				if strings.Contains(hint, "%") {
					hint = fmt.Sprintf(hint, out)
				}
				if !strings.Contains(s, hint) {
					t.Errorf("%s: the summary does not name the root step %q:\n%s", entry, hint, s)
				}
				if strings.Contains(s, "recorded in this node's image store") {
					t.Errorf("%s: the summary claims a store recording:\n%s", entry, s)
				}
			}
		})
	}

	t.Run("neither output nor push is refused", func(t *testing.T) {
		_, err := parseBuildArgs([]string{"--no-record", "-t", "app:dev", "."}, io.Discard)
		if err == nil {
			t.Fatal("expected --no-record without --output or --push to be refused")
		}
		for _, want := range []string{"--no-record", "--output", "--push"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %s", err, want)
			}
		}
	})

	t.Run("without the flag the store is still recorded", func(t *testing.T) {
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		o, err := parseBuildArgs([]string{"-t", "example.com/app:v1", ctxDir}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		store := &recordingStore{}
		if err := buildRecorded(t.Context(), nil, o, io.Discard, engineBuildWith, store.record, noPush); err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(store.calls) != 1 {
			t.Fatalf("store recordings = %v, want exactly one", store.calls)
		}
	})
}
