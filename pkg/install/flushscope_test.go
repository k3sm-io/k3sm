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
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// TestRecordedFlushScopeIsValidated is the B1492 gate: the Service range read
// back from the installed netd plist (or, on uninstall with no plist, from the
// configuration) bounds a root `ifconfig lo0 -alias` sweep, so a value no
// working Service range could have (too wide, IPv6, over loopback or the mesh)
// is refused: only the pinned pod aggregate is flushed, with a Warn and a
// LeftoverLo0 item. A non-default range an earlier release wrote, and the
// default, still flush; uninstall falls through to its configured range.
func TestRecordedFlushScopeIsValidated(t *testing.T) {
	cases := []struct {
		name    string
		cidr    string
		flushed string // the Service range flushed; "" when refused
	}{
		{"the whole IPv4 space", "0.0.0.0/0", ""},
		{"loopback", "127.0.0.0/8", ""},
		{"link-local", "169.254.0.0/16", ""},
		{"multicast", "224.0.0.0/4", ""},
		{"wider than a /12", "10.0.0.0/8", ""},
		{"a /11", "10.96.0.0/11", ""},
		{"an exact /12", "10.96.0.0/12", "10.96.0.0/12"},
		{"IPv6", "fd00:10:96::/112", ""},
		{"4in6", "::ffff:10.96.0.0/112", ""},
		{"overlaps the mesh", "100.64.0.0/16", ""},
		// No range of /12 or narrower contains the /10 mesh aggregate (that is
		// refused for width); these are /12s inside it, at both of its ends,
		// and the /12 just below it, which does not overlap and is accepted.
		{"a /12 at the start of the mesh", "100.64.0.0/12", ""},
		{"a /12 at the end of the mesh", "100.112.0.0/12", ""},
		{"a /12 just below the mesh", "100.0.0.0/12", "100.0.0.0/12"},
		{"host bits are masked", "10.96.0.5/16", "10.96.0.0/16"},
		{"a non-default range an earlier release wrote", "10.96.0.0/16", "10.96.0.0/16"},
		{"the default", DefaultServiceCIDR, DefaultServiceCIDR},
	}
	check := func(t *testing.T, f *fakeSystem, cfg Config, logs *bytes.Buffer, fp flushPrefixes, cidr, flushed string) {
		t.Helper()
		f.calls = nil
		left, _ := flushHostNetwork(f, cfg, fp, -1)
		var flushes []string
		for _, c := range f.calls {
			if strings.HasPrefix(c, "FlushLo0Aliases:") {
				flushes = append(flushes, c)
			}
		}
		lo0Left := slices.ContainsFunc(left, func(l LeftoverItem) bool { return l.Kind == LeftoverLo0 })
		if flushed != "" {
			want := []string{"FlushLo0Aliases:100.64.0.0/10," + flushed}
			if !slices.Equal(flushes, want) || lo0Left {
				t.Errorf("flushes = %q, lo0 leftover = %v; want %q and no leftover", flushes, lo0Left, want)
			}
			return
		}
		if want := []string{"FlushLo0Aliases:100.64.0.0/10"}; !slices.Equal(flushes, want) {
			t.Errorf("a refused Service range %s: flushes = %q, want the pinned pod aggregate alone %q", cidr, flushes, want)
		}
		if !lo0Left {
			t.Errorf("a refused Service range %s reported no %s leftover: %v", cidr, LeftoverLo0, left)
		}
		if !strings.Contains(logs.String(), "lo0 aliases not flushed") {
			t.Errorf("a refused Service range %s logged no Warn; logs:\n%s", cidr, logs.String())
		}
	}
	for _, tc := range cases {
		t.Run("recorded/"+tc.name, func(t *testing.T) {
			f := newFakeSystem(t)
			var logs bytes.Buffer
			cfg := Config{
				InstallDir:   testInstallDir(t),
				BinarySource: "/tmp/k3sm", TargetUser: "alice",
				Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}
			recordServiceCIDR(t, f, cfg, tc.cidr)
			cfg = cfg.withDefaults()
			check(t, f, cfg, &logs, recordedFlushPrefixes(f, cfg), tc.cidr, tc.flushed)
		})
		t.Run("config/"+tc.name, func(t *testing.T) {
			f := newFakeSystem(t)
			var logs bytes.Buffer
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil)), ServiceCIDR: tc.cidr}
			check(t, f, cfg, &logs, configFlushPrefixes(cfg), tc.cidr, tc.flushed)
		})
	}
	// Uninstall over a plist that records a refused range warns, naming it, and
	// flushes the uninstall configuration's (default) range instead.
	t.Run("uninstall falls through to the configured range", func(t *testing.T) {
		f := newFakeSystem(t)
		var logs bytes.Buffer
		cfg := Config{
			InstallDir:   testInstallDir(t),
			BinarySource: "/tmp/k3sm", TargetUser: "alice",
			Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		recordServiceCIDR(t, f, cfg, "0.0.0.0/0")
		f.calls = nil
		logs.Reset()
		if err := Uninstall(context.Background(), f, cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		var warned bool
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "records a refused Service range") && strings.Contains(line, "refused=0.0.0.0/0") && strings.Contains(line, "err=") {
				warned = true
			}
		}
		if !warned {
			t.Errorf("uninstall logged no Warn naming the refused recorded range 0.0.0.0/0; logs:\n%s", logs.String())
		}
		var flushes []string
		for _, c := range f.calls {
			if strings.HasPrefix(c, "FlushLo0Aliases:") {
				flushes = append(flushes, c)
			}
		}
		if want := []string{"FlushLo0Aliases:100.64.0.0/10," + DefaultServiceCIDR}; !slices.Equal(flushes, want) {
			t.Errorf("uninstall flushed %q, want %q", flushes, want)
		}
	})
	// An empty configured range keeps flushing the pod aggregate alone.
	t.Run("config/empty", func(t *testing.T) {
		f := newFakeSystem(t)
		cfg := Config{Logger: slog.New(slog.DiscardHandler)}
		f.calls = nil
		if left, _ := flushHostNetwork(f, cfg, configFlushPrefixes(cfg), -1); slices.ContainsFunc(left, func(l LeftoverItem) bool { return l.Kind == LeftoverLo0 }) {
			t.Errorf("an empty configured Service range reported a %s leftover: %v", LeftoverLo0, left)
		}
		if !slices.Contains(f.calls, "FlushLo0Aliases:100.64.0.0/10") {
			t.Errorf("calls = %q, want the pod aggregate flushed alone", f.calls)
		}
	})
}
