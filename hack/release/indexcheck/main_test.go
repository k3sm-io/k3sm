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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/update"
)

func TestRun(t *testing.T) {
	testdata := filepath.Join("..", "..", "..", "pkg", "update", "testdata")
	golden := filepath.Join(testdata, "release-index", "index.json")
	candidate := filepath.Join(testdata, "release-index-rc", "index.json")
	dir := t.TempDir()
	over := filepath.Join(dir, "over.json")
	if err := os.WriteFile(over, bytes.Repeat([]byte(" "), update.MaxReleaseIndexBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr error
	}{
		{
			name: "the golden index prints its release fields in order",
			args: []string{"final", golden},
			want: "tag=v0.2.0\n" +
				"minimum_supported_tag=v0.1.0\n" +
				"image_name=k3sm_0.2.0_darwin_arm64.dmg\n" +
				"image_sha256=6105d6cc76af400325e94d588ce511be5bfdbb73b437dc51eca43917d7a43e3d\n" +
				"image_size=123456789\n" +
				"archive=k3sm_0.2.0_darwin_arm64.tar.gz\n" +
				"archive_sha256=0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3\n" +
				"payload_manifest_sha256=05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f\n",
		},
		{
			name: "the candidate golden prints its release fields in order",
			args: []string{"candidate", "v0.3.0-rc.2", candidate},
			want: "tag=v0.3.0-rc.2\n" +
				"minimum_supported_tag=v0.2.0\n" +
				"image_name=k3sm_0.3.0-rc.2_darwin_arm64.dmg\n" +
				"image_sha256=7c1f0a55d3b84e96a2c07f1e68bd4093e5a17c26f08db3946ea15c70b28d4f61\n" +
				"image_size=123456789\n" +
				"archive=k3sm_0.3.0-rc.2_darwin_arm64.tar.gz\n" +
				"archive_sha256=2be94d07a6f1c3585d10e7b2946fa83c17d5e06b4f92ca3780b1d6e54a39c028\n" +
				"payload_manifest_sha256=93a6d1e47f0b285cc4e87a1036f5bd92e0c74d18a35b6f09d2e1847c6ba05f13\n",
		},
		{
			name:    "a document the decoder refuses is an error",
			args:    []string{"final", filepath.Join(testdata, "release-index", "red-duplicate-key.json")},
			wantErr: update.ErrReleaseIndex,
		},
		{
			name:    "final refuses the candidate document",
			args:    []string{"final", candidate},
			wantErr: update.ErrReleaseIndex,
		},
		{
			name:    "candidate refuses the stable document",
			args:    []string{"candidate", "v0.2.0", golden},
			wantErr: update.ErrReleaseIndex,
		},
		{
			name:    "candidate refuses a document for another candidate",
			args:    []string{"candidate", "v0.3.0-rc.3", candidate},
			wantErr: update.ErrReleaseIndex,
		},
		{
			name:    "a document over the cap is refused",
			args:    []string{"final", over},
			wantErr: update.ErrReleaseIndex,
		},
		{name: "no argument is an error", args: nil},
		{name: "a path with no kind is an error", args: []string{golden}},
		{name: "another kind is an error", args: []string{"stable", golden}},
		{name: "candidate with no tag is an error", args: []string{"candidate", candidate}},
		{name: "a missing file is an error", args: []string{"final", filepath.Join(dir, "missing.json")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			err := run(tt.args, &out)
			if tt.want != "" {
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				if out.String() != tt.want {
					t.Fatalf("output:\n%s\nwant:\n%s", out.String(), tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("run accepted it and printed %q", out.String())
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("error %v is not %v", err, tt.wantErr)
			}
			if out.Len() != 0 {
				t.Fatalf("printed %q on a refusal", out.String())
			}
		})
	}
}
