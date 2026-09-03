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
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// noStore is the storeRecorder for tests that are not about the store: it
// records nothing and cannot fail, so a build test never needs a daemon.
func noStore(context.Context, name.Tag, ggcrv1.Image) error { return nil }

// recordingStore is a storeRecorder that remembers what it was handed.
type recordingStore struct {
	calls []string
	err   error
}

func (r *recordingStore) record(_ context.Context, ref name.Tag, img ggcrv1.Image) error {
	if img == nil {
		return errors.New("the store was handed a nil image")
	}
	r.calls = append(r.calls, ref.String())
	return r.err
}

// TestBuildSinkMatrix pins the terminal state of a build.
//
// The node's image store is the DEFAULT and is written in every successful
// build; --output ADDITIONALLY writes the portable artifact. This is the whole
// docker-parity contract — `k3sm build -t app:dev .` is followed by naming
// app:dev in a Pod, with nothing in between.
func TestBuildSinkMatrix(t *testing.T) {
	cases := []struct {
		name         string
		output       string
		format       string
		wantArtifact bool
	}{
		{name: "no output records only in the store", wantArtifact: false},
		{name: "output records in the store AND writes the artifact", output: "img.tar", format: "docker", wantArtifact: true},
		{name: "an oci output records in the store too", output: "layout", format: "oci", wantArtifact: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
			out := ""
			if tc.output != "" {
				out = filepath.Join(t.TempDir(), tc.output)
			}
			store := &recordingStore{}
			var log bytes.Buffer

			err := buildWith(t.Context(), buildOptions{
				dockerfile: filepath.Join(ctxDir, "Dockerfile"),
				tag:        "example.com/app:v1",
				output:     out,
				format:     tc.format,
				contextDir: ctxDir,
			}, &log, engineBuild, store.record, noPush)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			if len(store.calls) != 1 || store.calls[0] != "example.com/app:v1" {
				t.Fatalf("store recordings = %v, want exactly [example.com/app:v1]", store.calls)
			}
			if !strings.Contains(log.String(), "store:") {
				t.Errorf("the summary does not report the store recording:\n%s", log.String())
			}

			if !tc.wantArtifact {
				if strings.Contains(log.String(), "output:") {
					t.Errorf("a build with no --output reported one:\n%s", log.String())
				}
				return
			}
			if _, statErr := os.Stat(out); statErr != nil {
				t.Errorf("--output wrote no artifact: %v", statErr)
			}
			if !strings.Contains(log.String(), "output:") {
				t.Errorf("the summary does not report the artifact:\n%s", log.String())
			}
		})
	}

	t.Run("a store failure fails the build", func(t *testing.T) {
		// The store is the terminal state, so a build that could not record is
		// not a build that succeeded — exiting 0 here would leave the operator
		// naming a tag no Pod can resolve.
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		store := &recordingStore{err: errors.New("cannot reach runtimed")}
		err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "example.com/app:v1",
			format:     "docker",
			contextDir: ctxDir,
		}, io.Discard, engineBuild, store.record, noPush)
		if err == nil {
			t.Fatal("expected the store failure to fail the build")
		}
		if !strings.Contains(err.Error(), "runtimed") {
			t.Errorf("error lost the store cause: %v", err)
		}
	})

	t.Run("the artifact is written before the store is dialed", func(t *testing.T) {
		// A bad --output path must fail before a multi-gigabyte stream reaches
		// the daemon.
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		store := &recordingStore{}
		err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "example.com/app:v1",
			output:     filepath.Join(t.TempDir(), "no-such-dir", "img.tar"),
			format:     "docker",
			contextDir: ctxDir,
		}, io.Discard, engineBuild, store.record, noPush)
		if err == nil {
			t.Fatal("expected an error for an unwritable --output")
		}
		if len(store.calls) != 0 {
			t.Errorf("the store was written for a build that could not write its artifact: %v", store.calls)
		}
	})
}

// TestBuildTagRequiredWithoutOutput pins that --tag stays required with or
// without --output: it names the store entry every build creates, and the error
// register is unchanged.
func TestBuildTagRequiredWithoutOutput(t *testing.T) {
	t.Run("no tag and no output", func(t *testing.T) {
		_, err := parseBuildArgs([]string{"."}, io.Discard)
		if err == nil {
			t.Fatal("expected an error for a build with no --tag")
		}
		if !strings.Contains(err.Error(), "--tag") {
			t.Errorf("error %q does not name --tag", err)
		}
	})
	t.Run("no output is now accepted", func(t *testing.T) {
		o, err := parseBuildArgs([]string{"-t", "app:dev", "."}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if o.output != "" {
			t.Errorf("output = %q, want empty (the store is the default sink)", o.output)
		}
	})
	t.Run("output is still honoured", func(t *testing.T) {
		o, err := parseBuildArgs([]string{"-t", "app:dev", "--output", "img.tar", "."}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if o.output != "img.tar" {
			t.Errorf("output = %q", o.output)
		}
	})
}
