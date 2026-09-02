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
	"io"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestImageSelectorParsing pins the three argv-level decisions the store verbs
// rest on: an unset platform stays UNSET on the wire (it is not "every
// platform"), a policy is the corev1 enum in either spelling, and a digest is
// told from a reference by shape alone.
func TestImageSelectorParsing(t *testing.T) {
	t.Run("platform", func(t *testing.T) {
		tests := []struct {
			name    string
			spec    string
			want    *runtimev1.Platform
			wantErr string
		}{
			{
				// Unset must reach the daemon as nil: the wire reads an unset
				// platform as the host's own for a pull and as "the reference's
				// single entry" elsewhere, neither of which an empty Platform says.
				name: "unset stays nil", spec: "", want: nil,
			},
			{name: "os and arch", spec: "darwin/arm64", want: &runtimev1.Platform{Os: "darwin", Architecture: "arm64"}},
			{name: "with a variant", spec: "linux/arm/v7", want: &runtimev1.Platform{Os: "linux", Architecture: "arm", Variant: "v7"}},
			{name: "os alone is refused", spec: "darwin", wantErr: "os/arch"},
			{name: "four components are refused", spec: "a/b/c/d", wantErr: "os/arch"},
			{name: "an empty component is refused", spec: "darwin/", wantErr: "non-empty"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := parsePlatform(tc.spec)
				if tc.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("parsePlatform(%q) err = %v, want one containing %q", tc.spec, err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("parsePlatform(%q): %v", tc.spec, err)
				}
				if tc.want == nil {
					if got != nil {
						t.Fatalf("parsePlatform(%q) = %v, want nil", tc.spec, got)
					}
					return
				}
				if got.GetOs() != tc.want.GetOs() || got.GetArchitecture() != tc.want.GetArchitecture() || got.GetVariant() != tc.want.GetVariant() {
					t.Errorf("parsePlatform(%q) = %v, want %v", tc.spec, got, tc.want)
				}
			})
		}
	})

	t.Run("policy", func(t *testing.T) {
		tests := []struct {
			name    string
			spec    string
			want    runtimev1.ImagePullPolicy
			wantErr string
		}{
			{name: "unset is the pull-through default", spec: "", want: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED},
			{name: "always", spec: "always", want: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS},
			{name: "if-not-present", spec: "if-not-present", want: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT},
			// The corev1 spelling is accepted because an operator reading a Pod
			// spec has that spelling in front of them and it is not wrong.
			{name: "the corev1 spelling", spec: "IfNotPresent", want: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT},
			{name: "never", spec: "Never", want: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER},
			{name: "an invented policy is refused", spec: "sometimes", wantErr: "want always"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := parsePullPolicy(tc.spec)
				if tc.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("parsePullPolicy(%q) err = %v, want one containing %q", tc.spec, err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("parsePullPolicy(%q): %v", tc.spec, err)
				}
				if got != tc.want {
					t.Errorf("parsePullPolicy(%q) = %v, want %v", tc.spec, got, tc.want)
				}
			})
		}
	})

	t.Run("digest-or-reference", func(t *testing.T) {
		digest := "sha256:" + strings.Repeat("ab", 32)
		tests := []struct {
			name string
			in   string
			want bool
		}{
			{name: "a sha256 digest", in: digest, want: true},
			{name: "a tag is not a digest", in: "alpine:3.20", want: false},
			{name: "a registry port is not an algorithm", in: "localhost:5000/app:v1", want: false},
			{name: "a pinned reference is a reference", in: "example.com/app@" + digest, want: false},
			{name: "a bare name", in: "alpine", want: false},
			{name: "a short hex tail is not a digest", in: "sha256:abcd", want: false},
			{name: "a non-hex tail is not a digest", in: "sha256:" + strings.Repeat("zz", 32), want: false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := looksLikeDigest(tc.in); got != tc.want {
					t.Errorf("looksLikeDigest(%q) = %v, want %v", tc.in, got, tc.want)
				}
				ref, dgst := imageTarget(tc.in)
				// Exactly one of the pair, always: the wire answers
				// INVALID_ARGUMENT when both are set.
				if (ref == "") == (dgst == "") {
					t.Errorf("imageTarget(%q) = (%q, %q); exactly one must be set", tc.in, ref, dgst)
				}
			})
		}
	})
}

// TestImageVerbArgGrammar is the argv contract for the store verbs: each takes
// exactly the positionals it needs, a flag reaches only the verbs that can
// honour it, and every verb that moves image bytes inherits the streaming
// deadline rather than the one sized for a metadata call.
func TestImageVerbArgGrammar(t *testing.T) {
	digest := "sha256:" + strings.Repeat("cd", 32)
	tests := []struct {
		name    string
		args    []string
		wantErr string
		check   func(t *testing.T, o imageOptions)
	}{
		{
			name: "pull takes a reference and defaults to the streaming deadline",
			args: []string{"pull", "example.com/app:v1"},
			check: func(t *testing.T, o imageOptions) {
				if o.source != "example.com/app:v1" {
					t.Errorf("source = %q", o.source)
				}
				if o.platform != nil {
					t.Errorf("platform = %v, want nil (unset must stay unset on the wire)", o.platform)
				}
				if o.timeout != streamingTimeout {
					t.Errorf("timeout = %v, want %v", o.timeout, streamingTimeout)
				}
			},
		},
		{
			name: "pull carries the platform and the policy",
			args: []string{"pull", "example.com/app:v1", "--platform", "linux/amd64", "--policy", "if-not-present"},
			check: func(t *testing.T, o imageOptions) {
				if o.platform.GetOs() != "linux" || o.platform.GetArchitecture() != "amd64" {
					t.Errorf("platform = %v", o.platform)
				}
				if o.policy != runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT {
					t.Errorf("policy = %v", o.policy)
				}
			},
		},
		{name: "pull needs a reference", args: []string{"pull"}, wantErr: "requires the reference"},
		{name: "pull takes one reference", args: []string{"pull", "a:1", "b:2"}, wantErr: "exactly one reference"},
		{
			name: "tag takes a source and a new reference",
			args: []string{"tag", digest, "example.com/app:v2"},
			check: func(t *testing.T, o imageOptions) {
				if o.source != digest || o.target != "example.com/app:v2" {
					t.Errorf("source = %q target = %q", o.source, o.target)
				}
			},
		},
		{name: "tag needs both", args: []string{"tag", digest}, wantErr: "new reference"},
		{
			name: "untag takes the digest pin",
			args: []string{"untag", "example.com/app:v1", "--digest", digest},
			check: func(t *testing.T, o imageOptions) {
				if o.digest != digest {
					t.Errorf("digest = %q", o.digest)
				}
			},
		},
		{
			name: "inspect renders a table by default",
			args: []string{"inspect", "example.com/app:v1"},
			check: func(t *testing.T, o imageOptions) {
				if o.output != "" {
					t.Errorf("output = %q, want the empty (table) rendering", o.output)
				}
				// inspect reads metadata only, so it keeps the metadata deadline.
				if o.timeout != metadataTimeout {
					t.Errorf("timeout = %v, want %v", o.timeout, metadataTimeout)
				}
			},
		},
		{
			name: "inspect takes -o json",
			args: []string{"inspect", digest, "-o", "json"},
			check: func(t *testing.T, o imageOptions) {
				if o.output != "json" {
					t.Errorf("output = %q", o.output)
				}
			},
		},
		{name: "inspect refuses another rendering", args: []string{"inspect", "a:1", "-o", "yaml"}, wantErr: "renders a table by default"},
		{
			name: "save needs a file and streams",
			args: []string{"save", "example.com/app:v1", "-o", "/tmp/app.tar"},
			check: func(t *testing.T, o imageOptions) {
				if o.output != "/tmp/app.tar" {
					t.Errorf("output = %q", o.output)
				}
				if o.timeout != streamingTimeout {
					t.Errorf("timeout = %v, want %v", o.timeout, streamingTimeout)
				}
			},
		},
		// An archive written to a terminal is a mistake nobody recovers from
		// gracefully, so the file is required rather than defaulted.
		{name: "save refuses to write to the terminal", args: []string{"save", "example.com/app:v1"}, wantErr: "requires -o"},
		// A flag a verb cannot honour is refused, not ignored: an ignored
		// --platform on a prune reads as "that platform was pruned".
		{name: "prune refuses --platform", args: []string{"prune", "--platform", "darwin/arm64"}, wantErr: "prune does not take --platform"},
		{name: "ls refuses --policy", args: []string{"ls", "--policy", "always"}, wantErr: "ls does not take --policy"},
		{name: "inspect refuses --digest", args: []string{"inspect", "a:1", "--digest", digest}, wantErr: "inspect does not take --digest"},
		{name: "load refuses -o", args: []string{"load", "a.tar", "-o", "x"}, wantErr: "load does not take -o"},
		{name: "a bad platform fails before anything is dialled", args: []string{"pull", "a:1", "--platform", "darwin"}, wantErr: "os/arch"},
		{
			name: "push accepts a store reference as its source",
			args: []string{"push", "example.com/app:v1", "localhost:5000/app:v1"},
			check: func(t *testing.T, o imageOptions) {
				if o.layoutDir != "example.com/app:v1" || o.target != "localhost:5000/app:v1" {
					t.Errorf("layoutDir = %q target = %q", o.layoutDir, o.target)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseImageArgs(tc.args, io.Discard)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseImageArgs(%v): %v", tc.args, err)
			}
			tc.check(t, o)
		})
	}
}

// TestImageUsageNamesEveryVerb keeps the help and the argument errors honest
// about the same set of verbs — a verb advertised in one and missing from the
// other is how a CLI grows a command nobody can discover.
func TestImageUsageNamesEveryVerb(t *testing.T) {
	for _, verb := range strings.Split(imageSubcommands, ", ") {
		if !strings.Contains(imageUsage, "k3sm image "+verb+" ") {
			t.Errorf("the usage does not show a synopsis for %q", verb)
		}
	}
}
