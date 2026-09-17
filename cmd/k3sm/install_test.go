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
	"strings"
	"testing"
)

// TestParseInstallFlagsMeshIP pins the --mesh-ip flag contract: a valid address
// is accepted and stored, and the shapes that can never be a server's own bind
// address are refused AT PARSE TIME, before `sudo` and the rest of a (possibly
// slow) install has run.
func TestParseInstallFlagsMeshIP(t *testing.T) {
	t.Run("absent leaves meshIP empty", func(t *testing.T) {
		opts, err := parseInstallFlags(nil)
		if err != nil {
			t.Fatalf("parseInstallFlags(nil) = %v, want nil", err)
		}
		if opts.meshIP != "" {
			t.Errorf("meshIP = %q, want empty", opts.meshIP)
		}
	})

	t.Run("a valid address is accepted and stored", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--mesh-ip", "100.64.0.1"})
		if err != nil {
			t.Fatalf("parseInstallFlags: %v", err)
		}
		if opts.meshIP != "100.64.0.1" {
			t.Errorf("meshIP = %q, want 100.64.0.1", opts.meshIP)
		}
	})

	for _, tc := range []struct {
		name string
		addr string
		want string
	}{
		{name: "not an IP address at all", addr: "300.1.1.1", want: "is not an IP address"},
		{name: "the unspecified IPv6 address", addr: "::", want: "not an IPv4"},
		{name: "the unspecified IPv4 address", addr: "0.0.0.0", want: "unspecified"},
		{name: "IPv4 loopback", addr: "127.0.0.1", want: "loopback"},
		{name: "IPv6 loopback", addr: "::1", want: "not an IPv4"},
		{name: "a global IPv6 address", addr: "2001:db8::1", want: "not an IPv4"},
		{name: "IPv6 link-local", addr: "fe80::1", want: "not an IPv4"},
		{name: "IPv4 link-local", addr: "169.254.1.5", want: "link-local"},
		{name: "multicast", addr: "224.0.0.1", want: "multicast"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseInstallFlags([]string{"--mesh-ip", tc.addr})
			if err == nil {
				t.Fatalf("parseInstallFlags(--mesh-ip %s) = nil, want an error naming %q", tc.addr, tc.want)
			}
			if !strings.Contains(err.Error(), tc.addr) {
				t.Errorf("error %q must name the offending value %q", err, tc.addr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q must explain the reason (%q)", err, tc.want)
			}
		})
	}
}
