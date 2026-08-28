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
	"log/slog"
	"testing"
)

// providerConfiguredMessage is the one startup line the provider constructor
// emits with its shim wiring. Matched exactly so the gate pins THAT record and
// not some other line that happens to carry a shim attribute.
const providerConfiguredMessage = "runtimed provider configured"

// TestProviderLogsBothShimPaths pins the B159 observability contract: the
// provider's startup line reports BOTH pod-support shims — the getaddrinfo DNS
// shim (dyld_shim) and the path-rebase shim (path_shim) — and reports them
// UNCONDITIONALLY, empty value included.
//
// Fails-before: the line logged dyld_shim only. A node running with an EMPTY
// path shim therefore looked identical in the log to one with the shim staged,
// while in-pod every ABSOLUTE volume-mount path ENOENTed (runtimed injects no
// path rebase when PathShimPath is empty). The missing key is what made that
// condition invisible and cost a full mis-diagnosis against another subsystem —
// so an ABSENT shim MUST appear as an empty value, never as an omitted key.
//
// No privilege, no network: the constructor is driven over the package fake.
func TestProviderLogsBothShimPaths(t *testing.T) {
	t.Parallel()

	// configuredRecord runs the provider constructor under a capture handler and
	// returns its startup record.
	configuredRecord := func(t *testing.T, cfg RuntimedConfig) capturedRecord {
		t.Helper()
		h := newCaptureHandler()
		newRuntimedWith(newFakeRuntimeServer(), cfg, nil, slog.New(h))
		for _, rec := range h.captured() {
			if rec.message == providerConfiguredMessage {
				return rec
			}
		}
		t.Fatalf("no %q record logged by the provider constructor (records: %v)", providerConfiguredMessage, h.captured())
		return capturedRecord{}
	}

	cases := []struct {
		name         string
		cfg          RuntimedConfig
		wantDyldShim string
		wantPathShim string
	}{
		{
			name:         "both shims staged",
			cfg:          RuntimedConfig{NodeName: "n", Root: t.TempDir(), DyldShim: "/Library/k3sm/libk3sm_getaddrinfo_shim.dylib", PathShim: "/Library/k3sm/libk3sm_pathrebase_shim.dylib"},
			wantDyldShim: "/Library/k3sm/libk3sm_getaddrinfo_shim.dylib",
			wantPathShim: "/Library/k3sm/libk3sm_pathrebase_shim.dylib",
		},
		{
			// THE regression case: the DNS shim resolved, the path shim did not.
			// Pre-B159 this logged one shim and silently dropped the other — the
			// unstaged one being exactly the fault to diagnose.
			name:         "path shim absent, dns shim staged",
			cfg:          RuntimedConfig{NodeName: "n", Root: t.TempDir(), DyldShim: "/Library/k3sm/libk3sm_getaddrinfo_shim.dylib"},
			wantDyldShim: "/Library/k3sm/libk3sm_getaddrinfo_shim.dylib",
			wantPathShim: "",
		},
		{
			name: "neither shim staged (a from-source run)",
			cfg:  RuntimedConfig{NodeName: "n", Root: t.TempDir()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := configuredRecord(t, tc.cfg)
			for _, key := range []string{"dyld_shim", "path_shim"} {
				if _, ok := rec.attrs[key]; !ok {
					t.Errorf("%q attr is MISSING from the startup line (attrs: %v) — an unset shim must be visible as empty, not omitted", key, rec.attrs)
				}
			}
			if got := rec.attrs["dyld_shim"]; got != tc.wantDyldShim {
				t.Errorf("dyld_shim = %q, want %q", got, tc.wantDyldShim)
			}
			if got := rec.attrs["path_shim"]; got != tc.wantPathShim {
				t.Errorf("path_shim = %q, want %q", got, tc.wantPathShim)
			}
		})
	}
}
