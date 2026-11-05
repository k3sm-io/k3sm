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

package layout

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

func TestValidateVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"0.3.0", true},
		{"v0.3.0", true},
		{"0.2.0-rc.1", true},
		{"1.2.3+build.5", true},
		{"unknown-0123456789ab", true},
		{"", false},
		{".", false},
		{"..", false},
		{"current", false},
		{"previous", false},
		{"0.3.0.tmp", false},
		{"0.3", false},
		{"01.2.3", false},
		{"0.3.0/..", false},
		{"../0.3.0", false},
		{"0.3.0\x00", false},
		{"dev", false},
		{"unknown-0123456789AB", false},
		{"unknown-0123", false},
		{"1.2.3-" + strings.Repeat("a", 130), false},
	} {
		t.Run(fmt.Sprintf("%q", tc.name), func(t *testing.T) {
			err := ValidateVersion(tc.name)
			if (err == nil) != tc.ok {
				t.Errorf("ValidateVersion(%q) = %v, want ok=%v", tc.name, err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrBadVersion) {
				t.Errorf("err %v is not ErrBadVersion", err)
			}
		})
	}
	if !IsUnknownVersion("unknown-0123456789ab") || IsUnknownVersion("0.3.0") {
		t.Error("IsUnknownVersion misclassifies")
	}
}

func TestPaths(t *testing.T) {
	l := New("/tmp/root/")
	v, err := l.VersionDir("0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	bin, _ := l.Binary("k3sm")
	compat, _ := l.CompatLink("k3sm")
	for _, tc := range []struct{ name, got, want string }{
		{"root", l.Root(), "/tmp/root"},
		{"versions", l.VersionsDir(), "/tmp/root/versions"},
		{"version", v, "/tmp/root/versions/0.3.0"},
		{"current", l.Current(), "/tmp/root/current"},
		{"previous", l.Previous(), "/tmp/root/previous"},
		{"binary", bin, "/tmp/root/current/k3sm"},
		{"compat", compat, "/tmp/root/k3sm"},
		{"updater dir", l.UpdaterDir(), "/tmp/root/updater"},
		{"updater current", l.UpdaterCurrent(), "/tmp/root/updater/current"},
		{"updater current binary", l.UpdaterCurrentBinary(), "/tmp/root/updater/current/k3sm-updater"},
		{"updater guard", l.UpdaterGuard(), "/tmp/root/updater/guard"},
		{"updater guard binary", l.UpdaterGuardBinary(), "/tmp/root/updater/guard/k3sm-updater"},
		{"state", l.StateDir(), "/tmp/root/updater-state"},
		{"work", l.WorkDir(), "/tmp/root/updater-work"},
		{"run", l.RunDir(), "/tmp/root/run"},
		{"socket", l.Socket(), "/tmp/root/run/updater.sock"},
		{"trust", l.TrustCA(), "/tmp/root/trust/cluster-ca.crt"},
		{"status", l.StatusFile(), "/tmp/root/status/update.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %s, want %s", tc.got, tc.want)
			}
		})
	}
	t.Run("production root", func(t *testing.T) {
		p := New(DefaultRoot)
		if p.Current() != "/Library/k3sm/current" || p.RunDir() != "/Library/k3sm/run" || p.TrustCA() != "/Library/k3sm/trust/cluster-ca.crt" {
			t.Errorf("production paths: %s %s %s", p.Current(), p.RunDir(), p.TrustCA())
		}
	})
	t.Run("bad names refused", func(t *testing.T) {
		if _, err := l.VersionDir("../x"); !errors.Is(err, ErrBadVersion) {
			t.Errorf("VersionDir: %v", err)
		}
		for _, b := range []string{"", ".", "..", "a/b", "/k3sm"} {
			if _, err := l.Binary(b); !errors.Is(err, ErrBadName) {
				t.Errorf("Binary(%q): %v", b, err)
			}
			if _, err := l.CompatLink(b); !errors.Is(err, ErrBadName) {
				t.Errorf("CompatLink(%q): %v", b, err)
			}
		}
	})
}

// TestVersionedBinary pins which recorded executable paths count as one of the
// tree's binaries: exactly root/versions/<ver>/<bin>, cleaned, with a valid
// version, and nothing else.
func TestVersionedBinary(t *testing.T) {
	l := New("/tmp/root")
	for _, tc := range []struct {
		name, path, bin, ver string
		ok                   bool
	}{
		{"release version", "/tmp/root/versions/0.3.0/k3sm-vmhost", "k3sm-vmhost", "0.3.0", true},
		{"migrated unknown version", "/tmp/root/versions/unknown-0123456789ab/k3sm-vmhost", "k3sm-vmhost", "unknown-0123456789ab", true},
		{"uncleaned path", "/tmp/root/versions/./0.3.0//k3sm-vmhost", "k3sm-vmhost", "0.3.0", true},
		{"other basename", "/tmp/root/versions/0.3.0/k3sm", "k3sm-vmhost", "", false},
		{"flat path", "/tmp/root/k3sm-vmhost", "k3sm-vmhost", "", false},
		{"through current", "/tmp/root/current/k3sm-vmhost", "k3sm-vmhost", "", false},
		{"deeper", "/tmp/root/versions/0.3.0/bin/k3sm-vmhost", "k3sm-vmhost", "", false},
		{"partial version", "/tmp/root/versions/0.3.0.partial/k3sm-vmhost", "k3sm-vmhost", "", false},
		{"dot-dot escape", "/tmp/root/versions/../k3sm-vmhost", "k3sm-vmhost", "", false},
		{"outside the root", "/tmp/other/versions/0.3.0/k3sm-vmhost", "k3sm-vmhost", "", false},
		{"relative", "versions/0.3.0/k3sm-vmhost", "k3sm-vmhost", "", false},
		{"bad bin", "/tmp/root/versions/0.3.0/k3sm-vmhost", "a/b", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ver, ok := l.VersionedBinary(tc.path, tc.bin)
			if ok != tc.ok || ver != tc.ver {
				t.Errorf("VersionedBinary(%q, %q) = %q, %v; want %q, %v", tc.path, tc.bin, ver, ok, tc.ver, tc.ok)
			}
		})
	}
}

// links is a Readlink over a fixed map.
func links(m map[string]string) Readlink {
	return func(name string) (string, error) {
		if t, ok := m[name]; ok {
			return t, nil
		}
		return "", fs.ErrNotExist
	}
}

func TestResolveActive(t *testing.T) {
	l := New("/r")
	for _, tc := range []struct {
		name    string
		target  string
		want    string
		wantErr error
	}{
		{"release", "versions/0.3.0", "0.3.0", nil},
		{"unknown", "versions/unknown-0123456789ab", "unknown-0123456789ab", nil},
		{"absolute", "/r/versions/0.3.0", "", ErrBadLink},
		{"escapes", "versions/../../etc", "", ErrBadLink},
		{"nested", "versions/0.3.0/k3sm", "", ErrBadLink},
		{"bad version", "versions/dev", "", ErrBadLink},
		{"elsewhere", "other/0.3.0", "", ErrBadLink},
		{"empty", "", "", ErrBadLink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := l.ResolveActive(links(map[string]string{"/r/current": tc.target}))
			if got != tc.want || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("ResolveActive -> %q = %q, %v; want %q, %v", tc.target, got, err, tc.want, tc.wantErr)
			}
		})
	}
	t.Run("missing link", func(t *testing.T) {
		if _, err := l.ResolveActive(links(nil)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("previous", func(t *testing.T) {
		got, err := l.ResolvePrevious(links(map[string]string{"/r/previous": "versions/0.2.3"}))
		if got != "0.2.3" || err != nil {
			t.Errorf("ResolvePrevious = %q, %v", got, err)
		}
	})
	t.Run("updater is one level down", func(t *testing.T) {
		got, err := l.ResolveUpdater(links(map[string]string{"/r/updater/current": "../versions/0.3.0"}))
		if got != "0.3.0" || err != nil {
			t.Errorf("ResolveUpdater = %q, %v", got, err)
		}
		if _, err := l.ResolveUpdater(links(map[string]string{"/r/updater/current": "versions/0.3.0"})); !errors.Is(err, ErrBadLink) {
			t.Errorf("same-level target: err = %v, want ErrBadLink", err)
		}
	})
}

func TestPlanFlip(t *testing.T) {
	l := New("/r")
	t.Run("upgrade flips current then previous", func(t *testing.T) {
		got, err := l.PlanFlip("0.2.3", "0.3.0")
		if err != nil {
			t.Fatal(err)
		}
		want := []Step{
			{OpRemoveStale, "/r/current.tmp", ""},
			{OpSymlink, "/r/current.tmp", "versions/0.3.0"},
			{OpRename, "/r/current.tmp", "/r/current"},
			{OpRemoveStale, "/r/previous.tmp", ""},
			{OpSymlink, "/r/previous.tmp", "versions/0.2.3"},
			{OpRename, "/r/previous.tmp", "/r/previous"},
		}
		if !slices.Equal(got, want) {
			t.Errorf("PlanFlip = %v\nwant %v", got, want)
		}
	})
	t.Run("first activation has no previous", func(t *testing.T) {
		got, err := l.PlanFlip("", "0.3.0")
		if err != nil || len(got) != 3 || got[2].Target != "/r/current" {
			t.Errorf("PlanFlip(\"\", 0.3.0) = %v, %v", got, err)
		}
	})
	t.Run("every link replaced by rename, never written in place", func(t *testing.T) {
		got, _ := l.PlanFlip("0.2.3", "0.3.0")
		for _, s := range got {
			if s.Op == OpSymlink && (s.Path == l.Current() || s.Path == l.Previous()) {
				t.Errorf("step %v creates a live link directly", s)
			}
		}
	})
	for _, tc := range []struct {
		name, from, to string
		want           error
	}{
		{"no change", "0.3.0", "0.3.0", ErrNoChange},
		{"bad to", "0.2.3", "../x", ErrBadVersion},
		{"bad from", "dev", "0.3.0", ErrBadVersion},
		{"empty to", "0.2.3", "", ErrBadVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := l.PlanFlip(tc.from, tc.to); !errors.Is(err, tc.want) {
				t.Errorf("PlanFlip(%q, %q) err = %v, want %v", tc.from, tc.to, err, tc.want)
			}
		})
	}
	if OpRename.String() != "rename" || Op(9).String() != "Op(9)" {
		t.Error("Op.String")
	}
}
