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
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/shadow"
	"k3sm.io/runtimed/pkg/shadowset"
)

// shadowSetCalls is the call sequence makeShadowSet issues under dir for the
// shared list, skipping the clone's follow-ups for a missing source: per copy,
// clone (root:wheel 0755) then ad-hoc re-sign then verify, then the SOURCE's
// cdhash, read once per distinct source.
func shadowSetCalls(dir string, missing map[string]bool) []string {
	var out []string
	read := map[string]bool{}
	for _, c := range shadow.Copies() {
		dst := dir + "/" + c.Name
		out = append(out, fmt.Sprintf("CloneToOwned:%s->%s:%d:%d:%#o", c.Source, dst,
			shadowOwnership.uid, shadowOwnership.gid, shadowOwnership.mode))
		if missing[c.Source] {
			continue
		}
		out = append(out, "AdHocSign:"+dst, "VerifyShadowCopy:"+dst)
		if !read[c.Source] {
			out = append(out, "CDHash:"+c.Source)
			read[c.Source] = true
		}
	}
	return out
}

// TestShadowSetIsMadeAtInstall is the install gate for the shadow binary set:
// `sudo k3sm install` makes it in the staged install root, one copy per entry
// of the shared list in list order, each cloned (owner and mode from
// shadowOwnership: root:wheel 0755, never writable by the service user), then
// re-signed ad hoc, then verified, then its SOURCE's cdhash read, and finally
// writes the manifest root:wheel 0644 recording every copy and its source's
// cdhash. A host without /bin/dash is a WARN and the set is made without it;
// the install still succeeds. The total size and the elapsed time are logged.
func TestShadowSetIsMadeAtInstall(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing string
	}{
		{name: "every source present"},
		{name: "no /bin/dash on this host", missing: "/bin/dash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := &fakeSystem{}
			missing := map[string]bool{}
			if tc.missing != "" {
				f.missingPaths = map[string]bool{tc.missing: true}
				missing[tc.missing] = true
			}
			var logs bytes.Buffer
			cfg := serverCfg()
			cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}

			dir := "/Library/k3sm.staging/shadow"
			want := []string{"EnsureRootDir:" + dir}
			want = append(want, shadowSetCalls(dir, missing)...)
			want = append(want, fmt.Sprintf("WriteRootOnlyFile:%s/%s:%#o", dir, shadow.ManifestName, 0o644))
			var wantSources []shadow.Source
			for _, c := range shadow.Copies() {
				if !missing[c.Source] {
					wantSources = append(wantSources, shadow.Source{Name: c.Name, Path: c.Source, CDHash: "cdhash-of-" + filepath.Base(c.Source)})
				}
			}

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
			if tc.missing == "" && strings.Contains(logs.String(), "host binary not present") {
				t.Errorf("warned about a missing source on a host that has every one")
			}
			wantBytes := fmt.Sprintf("bytes=%d", fakeShadowCopySize*len(wantSources))
			if !strings.Contains(logs.String(), "made the shadow binary set") || !strings.Contains(logs.String(), wantBytes) ||
				!strings.Contains(logs.String(), "elapsed=") {
				t.Errorf("no summary line with %s and the elapsed time; log:\n%s", wantBytes, logs.String())
			}
		})
	}
}

// TestShadowSetSharesTheOneList pins that the installer's set IS the shared
// shadowset list: exactly one copy per declared Copy name, cloned from that
// entry's Source, in declaration order, with the manifest listing the same
// pairs. (The status row's expected set is checked against the same list in
// pkg/status.)
func TestShadowSetSharesTheOneList(t *testing.T) {
	shrinkRestartBudgets(t)
	f := &fakeSystem{}
	cfg := serverCfg()
	cfg.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	const dir = "/Library/k3sm.staging/shadow"
	var clones []string
	for _, c := range recorded(f.calls, "CloneToOwned:") {
		clones = append(clones, strings.SplitN(c, ":", 2)[0])
	}
	m, err := shadow.Decode(f.files[dir+"/"+shadow.ManifestName])
	if err != nil {
		t.Fatalf("decode the manifest: %v", err)
	}
	entries := shadowset.Entries()
	if len(clones) != len(entries) || len(m.Sources) != len(entries) {
		t.Fatalf("clones %d, manifest %d, list %d: want one per list entry", len(clones), len(m.Sources), len(entries))
	}
	for i, e := range entries {
		if want := e.Source + "->" + dir + "/" + e.Copy; clones[i] != want {
			t.Errorf("clone %d = %q, want %q", i, clones[i], want)
		}
		if m.Sources[i].Name != e.Copy || m.Sources[i].Path != e.Source {
			t.Errorf("manifest %d = %+v, want %s from %s", i, m.Sources[i], e.Copy, e.Source)
		}
	}
}

// TestShadowCopyVerificationFailsTheInstall pins that a made copy failing the
// post-sign verification fails the install with an error naming the copy and
// the property, before anything is published.
func TestShadowCopyVerificationFailsTheInstall(t *testing.T) {
	shrinkRestartBudgets(t)
	const dir = "/Library/k3sm.staging/shadow"
	bad := fmt.Errorf("%w: signature carries entitlements", shadow.ErrUnsafeCopy)
	f := &fakeSystem{verifyErrs: map[string]error{dir + "/tar": bad}}
	cfg := serverCfg()
	cfg.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	err := Install(context.Background(), f, cfg)
	if !errors.Is(err, shadow.ErrUnsafeCopy) || !strings.Contains(err.Error(), "tar") || !strings.Contains(err.Error(), "entitlements") {
		t.Fatalf("Install err = %v, want the unsafe-copy error naming tar and the property", err)
	}
	if idx(f.calls, "SwapInstallRoot:/Library/k3sm.staging<->/Library/k3sm:rename") >= 0 {
		t.Errorf("the tree was published after a failed verification")
	}
	if idx(f.calls, "WriteRootOnlyFile:"+dir+"/"+shadow.ManifestName+":0644") >= 0 {
		t.Errorf("the manifest was written after a failed verification")
	}
}

// TestShadowSetBudget pins the overall deadline: a set that runs past
// shadowSetBudget stops before the next copy and fails the install.
func TestShadowSetBudget(t *testing.T) {
	shrinkRestartBudgets(t)
	prev := shadowSetBudget
	shadowSetBudget = -1
	t.Cleanup(func() { shadowSetBudget = prev })
	f := &fakeSystem{}
	cfg := serverCfg()
	cfg.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	err := Install(context.Background(), f, cfg)
	if err == nil || !strings.Contains(err.Error(), "took longer than") {
		t.Fatalf("Install err = %v, want the shadow set budget error", err)
	}
	if len(recorded(f.calls, "CloneToOwned:")) != 0 {
		t.Errorf("a copy was made past the budget")
	}
}
