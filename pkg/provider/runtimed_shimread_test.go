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

package provider

import (
	"context"
	"slices"
	"testing"
)

// TestPodProfileCarriesTheStagedShimReadPaths proves the two pod-support DYLD
// shims reach every pod's Seatbelt read allow, not only its DYLD insert env.
//
// dyld loads an inserted library INSIDE the confined pod, so the pod profile has
// to be able to read the file. The profile's read baseline is /System, /usr,
// /bin and /Library; a shim staged anywhere else (a rootless dev instance stages
// beside its runtime root, under /private/var/tmp) is unreadable unless the
// provider names it in SandboxProfile.ExtraReadPaths, and dyld then fails closed
// and the pod dies at exec. The grant is exactly the two FILES: naming their
// directory would hand the pod whatever else lands there.
func TestPodProfileCarriesTheStagedShimReadPaths(t *testing.T) {
	const (
		dyld = "/private/var/tmp/k3sm-dev-501/dev/shims/libk3smdns.dylib"
		path = "/private/var/tmp/k3sm-dev-501/dev/shims/libk3smpath.dylib"
	)
	cases := []struct {
		name           string
		dyldShim, path string
		want           []string
	}{
		{"both shims staged", dyld, path, []string{dyld, path}},
		{"only the path shim (no datapath, no DNS shim)", "", path, []string{path}},
		{"only the DNS shim", dyld, "", []string{dyld}},
		{"no shims staged grants nothing", "", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRuntimeServer()
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName:   "n",
				NodeIP:     "192.168.1.10",
				Root:       t.TempDir(),
				PodLogsDir: t.TempDir(),
				DyldShim:   tc.dyldShim,
				PathShim:   tc.path,
			}, nil, nil)
			if err := r.CreatePod(context.Background(), runtimedPod("default", "web")); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			box := f.created["uid-web"]
			if box == nil {
				t.Fatal("no PodBox reached the runtime")
			}
			got := slices.Clone(box.GetSandboxProfile().GetExtraReadPaths())
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("SandboxProfile.ExtraReadPaths = %v, want exactly %v", got, want)
			}
		})
	}
}
