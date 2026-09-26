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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/shadow"
)

// TestShadowSetIsMadeAtInstall is B243's install gate: `sudo k3sm install`
// makes the shadow shell set in the staged install root, in this order per
// shell, clone (owner and mode from shadowOwnership: root:wheel 0755, never
// writable by the service user) then ad-hoc re-sign then read the SOURCE's
// cdhash, and finally writes the manifest root:wheel 0644 recording every
// source and its cdhash. A host without /bin/dash is a WARN and the set is made
// without it; the install still succeeds.
func TestShadowSetIsMadeAtInstall(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing string
	}{
		{name: "every shell present"},
		{name: "no /bin/dash on this host", missing: "/bin/dash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := &fakeSystem{}
			if tc.missing != "" {
				f.missingPaths = map[string]bool{tc.missing: true}
			}
			var logs bytes.Buffer
			cfg := serverCfg()
			cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}

			dir := "/Library/k3sm.staging/shadow"
			var want []string
			want = append(want, "EnsureRootDir:"+dir)
			var wantSources []shadow.Source
			for _, sh := range shadow.Shells {
				dst := dir + "/" + sh.Name
				want = append(want, fmt.Sprintf("CloneToOwned:%s->%s:%d:%d:%#o", sh.Source, dst,
					shadowOwnership.uid, shadowOwnership.gid, shadowOwnership.mode))
				if sh.Source == tc.missing {
					continue
				}
				want = append(want, "AdHocSign:"+dst, "CDHash:"+sh.Source)
				wantSources = append(wantSources, shadow.Source{Name: sh.Name, Path: sh.Source, CDHash: "cdhash-of-" + sh.Name})
			}
			want = append(want, fmt.Sprintf("WriteRootOnlyFile:%s/%s:%#o", dir, shadow.ManifestName, 0o644))

			start := idx(f.calls, want[0])
			if start < 0 || start+len(want) > len(f.calls) {
				t.Fatalf("no shadow set in the call sequence %v", f.calls)
			}
			for i, w := range want {
				if got := f.calls[start+i]; got != w {
					t.Errorf("shadow call %d = %q, want %q", i, got, w)
				}
			}
			if shadowOwnership.uid != 0 || shadowOwnership.gid != 0 || shadowOwnership.mode != 0o755 {
				t.Errorf("shadowOwnership = %+v, want root:wheel 0755", shadowOwnership)
			}
			// Staged, then published with the rest of the tree.
			if idx(f.calls, want[len(want)-1]) > idx(f.calls, "SwapInstallRoot:/Library/k3sm.staging<->/Library/k3sm:rename") {
				t.Errorf("the manifest was written after the publish")
			}

			m, err := shadow.Decode(f.files[dir+"/"+shadow.ManifestName])
			if err != nil {
				t.Fatalf("decode the manifest: %v", err)
			}
			if fmt.Sprint(m.Sources) != fmt.Sprint(wantSources) {
				t.Errorf("manifest sources = %+v, want %+v", m.Sources, wantSources)
			}

			warned := strings.Contains(logs.String(), "level=WARN") && strings.Contains(logs.String(), "/bin/dash")
			if tc.missing != "" && !warned {
				t.Errorf("a missing %s was not warned about; log:\n%s", tc.missing, logs.String())
			}
			if tc.missing == "" && strings.Contains(logs.String(), "host shell not present") {
				t.Errorf("warned about a missing shell on a host that has all four")
			}
		})
	}
}
