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
	"fmt"
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

	t.Run("a second server's own range is accepted", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--mesh-ip", "100.64.1.1"})
		if err != nil {
			t.Fatalf("parseInstallFlags: %v", err)
		}
		if opts.meshIP != "100.64.1.1" {
			t.Errorf("meshIP = %q, want 100.64.1.1", opts.meshIP)
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
		{name: "a host that is not its node range's mesh-egress address", addr: "100.64.1.5", want: "mesh-egress address 100.64.1.1"},
		{name: "outside the cluster pod range", addr: "10.0.0.1", want: "outside the cluster pod range"},
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

// TestUninstallConfigSplitsResultsFromDiagnostics pins the uninstall's output
// wiring: the purge's result lines (what it removed, the account it could not
// delete and how to finish by hand) are stdout, and the progress and
// diagnostics the logger carries are stderr.
func TestUninstallConfigSplitsResultsFromDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		write      func(t *testing.T, stdout, stderr *bytes.Buffer)
		wantStdout string
		wantStderr string
	}{
		{name: "a result line is stdout", wantStdout: "k3sm purged; removed: x\n", write: func(t *testing.T, stdout, stderr *bytes.Buffer) {
			cfg := uninstallConfig(stdout, stderr)
			if _, err := fmt.Fprintln(cfg.Out, "k3sm purged; removed: x"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a log line is stderr", wantStderr: "level=WARN msg=diagnostic", write: func(t *testing.T, stdout, stderr *bytes.Buffer) {
			uninstallConfig(stdout, stderr).Logger.Warn("diagnostic")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			tc.write(t, &stdout, &stderr)
			if tc.wantStdout != stdout.String() {
				t.Errorf("stdout = %q, want %q", stdout.String(), tc.wantStdout)
			}
			if tc.wantStderr == "" && stderr.Len() != 0 || !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to hold %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}
