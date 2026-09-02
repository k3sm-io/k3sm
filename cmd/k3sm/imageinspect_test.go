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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestImageInspectVerb is the gate for `k3sm image inspect`: the target is
// addressed as a reference or a digest by SHAPE, the table reports the facts an
// operator came for, an absent fact is omitted rather than invented, and -o json
// prints the daemon's own response.
func TestImageInspectVerb(t *testing.T) {
	digest := "sha256:" + strings.Repeat("3c", 32)
	created := time.Date(2026, 5, 4, 3, 2, 1, 0, time.UTC)

	full := func() *runtimev1.InspectImageResponse {
		return &runtimev1.InspectImageResponse{
			Image: storeImage("example.test/app:v1", digest, "darwin", "arm64"),
			Config: &runtimev1.ImageConfig{
				Platform:   &runtimev1.Platform{Os: "darwin", Architecture: "arm64"},
				Created:    timestamppb.New(created),
				Entrypoint: []string{"/bin/app", "--serve"},
				Cmd:        []string{"--port", "8080"},
				Env:        []string{"PATH=/bin"},
				User:       "1000:1000",
				WorkingDir: "/srv",
			},
			TotalSizeBytes: 3 << 20,
		}
	}

	t.Run("addresses a reference by name and a digest by digest", func(t *testing.T) {
		tests := []struct {
			name          string
			arg           string
			wantReference string
			wantDigest    string
		}{
			{name: "a reference", arg: "example.test/app:v1", wantReference: "example.test/app:v1"},
			{name: "a digest", arg: digest, wantDigest: digest},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				fake := &fakeImagesDaemon{inspectResp: full()}
				sock := serveFakeImages(t, fake)
				if _, err := runImageCmd(t, []string{"--socket", sock, "inspect", tc.arg}); err != nil {
					t.Fatalf("image inspect: %v", err)
				}
				got := fake.gotInspect[0]
				if got.GetReference() != tc.wantReference || got.GetDigest() != tc.wantDigest {
					t.Errorf("request reference=%q digest=%q, want %q/%q",
						got.GetReference(), got.GetDigest(), tc.wantReference, tc.wantDigest)
				}
			})
		}
	})

	t.Run("the table carries the facts an operator came for", func(t *testing.T) {
		fake := &fakeImagesDaemon{inspectResp: full()}
		sock := serveFakeImages(t, fake)
		out, err := runImageCmd(t, []string{"--socket", sock, "inspect", "example.test/app:v1"})
		if err != nil {
			t.Fatalf("image inspect: %v", err)
		}
		for _, want := range []string{
			"example.test/app:v1", digest, "darwin/arm64", "2026-05-04T03:02:01Z",
			"1000:1000", "/srv", "/bin/app", "--port",
			"sha256:layer1", "1.0 MiB", "sha256:layer2", "2.0 MiB",
			"LAYERS      2", "TOTAL", "3.0 MiB",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the table omits %q\ngot:\n%s", want, out)
			}
		}
		// The total measures the image; it is not what a prune would give back,
		// and the table must not let that be inferred.
		if !strings.Contains(out, "survive a prune") {
			t.Errorf("the table omits the shared-layer caveat\ngot:\n%s", out)
		}
	})

	// The wire makes every field independently optional so a later daemon can
	// report more without a wire change. An absent field is an absent FACT — the
	// ordinary state after a prune reclaimed an unrooted image's config — and the
	// table must omit the row rather than print an empty or invented one.
	t.Run("an absent fact is omitted, not invented", func(t *testing.T) {
		fake := &fakeImagesDaemon{inspectResp: &runtimev1.InspectImageResponse{
			Image:          storeImage("example.test/app:v1", digest, "", ""),
			TotalSizeBytes: 1 << 20,
		}}
		sock := serveFakeImages(t, fake)
		out, err := runImageCmd(t, []string{"--socket", sock, "inspect", "example.test/app:v1"})
		if err != nil {
			t.Fatalf("image inspect: %v", err)
		}
		for _, absent := range []string{"CREATED", "USER", "WORKDIR", "ENTRYPOINT", "CMD", "PLATFORM"} {
			if strings.Contains(out, absent) {
				t.Errorf("the table printed a %s row for a fact the daemon did not report\ngot:\n%s", absent, out)
			}
		}
		if !strings.Contains(out, digest) {
			t.Errorf("the table omits the digest\ngot:\n%s", out)
		}
	})

	t.Run("-o json prints the daemon's response", func(t *testing.T) {
		fake := &fakeImagesDaemon{inspectResp: full()}
		sock := serveFakeImages(t, fake)
		out, err := runImageCmd(t, []string{"--socket", sock, "inspect", "example.test/app:v1", "-o", "json"})
		if err != nil {
			t.Fatalf("image inspect -o json: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("the -o json output is not JSON: %v\ngot:\n%s", err, out)
		}
		// protojson field names, not Go ones: the response is a proto message
		// and its JSON is the wire's, so another tool can read it.
		image, ok := doc["image"].(map[string]any)
		if !ok {
			t.Fatalf("no image object in the JSON\ngot:\n%s", out)
		}
		desc, ok := image["manifestDescriptor"].(map[string]any)
		if !ok {
			t.Fatalf("no manifestDescriptor in the JSON\ngot:\n%s", out)
		}
		if desc["digest"] != digest {
			t.Errorf("JSON digest = %v, want %s", desc["digest"], digest)
		}
		// The env the table deliberately leaves out is still on the JSON path,
		// which is why the JSON rendering exists at all.
		cfg, ok := doc["config"].(map[string]any)
		if !ok {
			t.Fatalf("no config object in the JSON\ngot:\n%s", out)
		}
		if _, ok := cfg["env"]; !ok {
			t.Errorf("the JSON omits the config env\ngot:\n%s", out)
		}
	})

	t.Run("surfaces the daemon's refusal", func(t *testing.T) {
		fake := &fakeImagesDaemon{inspectErr: status.Error(codes.NotFound,
			"InspectImage: example.test/app:v1 is not in the local index")}
		sock := serveFakeImages(t, fake)
		out, err := runImageCmd(t, []string{"--socket", sock, "inspect", "example.test/app:v1"})
		if err == nil {
			t.Fatalf("inspect of an absent image succeeded: %s", out)
		}
		if !strings.Contains(err.Error(), "is not in the local index") {
			t.Errorf("error = %v", err)
		}
	})
}
