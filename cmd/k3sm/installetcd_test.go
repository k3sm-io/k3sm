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
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestInstallRecordsEmbeddedEtcdServerFlags pins the embedded-etcd HA surface
// of `k3sm install`: --cluster-init forms a cluster, --server-join with --server
// and --token-file joins one, and either takes the --node-ip the etcd peer
// listener binds. Every accepted combination must reach BOTH the server
// daemon's argv and the server-arguments record, because the record is what a
// later plain reinstall (or an uninstall-then-install) carries forward; every
// refused combination must say why, before any privilege is taken.
func TestInstallRecordsEmbeddedEtcdServerFlags(t *testing.T) {
	dataRoot := install.DefaultDataRoot
	adminToken := filepath.Join(dataRoot, "server", "token")
	joinToken := filepath.Join(dataRoot, "server", "join-token")
	const operatorToken = "/var/root/k3sm-server-token"

	accepted := []struct {
		name      string
		args      []string
		wantArgs  []string // the operator arguments, in the plist and in the record
		tokenFile string   // the --token-file the daemon is pointed at
	}{
		{
			name:      "a single-node install renders no HA flag",
			args:      nil,
			wantArgs:  nil,
			tokenFile: adminToken,
		},
		{
			name:      "--cluster-init forms a cluster on the LAN peer address",
			args:      []string{"--cluster-init", "--node-ip", "192.0.2.10"},
			wantArgs:  []string{"--cluster-init", "--etcd-peer-ip", "192.0.2.10"},
			tokenFile: adminToken,
		},
		{
			name:      "--cluster-init beside the mesh address",
			args:      []string{"--cluster-init", "--node-ip", "192.0.2.10", "--mesh-ip", "100.64.0.1"},
			wantArgs:  []string{"--mesh-ip", "100.64.0.1", "--cluster-init", "--etcd-peer-ip", "192.0.2.10"},
			tokenFile: adminToken,
		},
		{
			name:      "--server-join through an existing server, its token staged off the argv",
			args:      []string{"--server-join", "--server", "192.0.2.10", "--token-file", operatorToken, "--node-ip", "192.0.2.20", "--mesh-ip", "100.64.0.2"},
			wantArgs:  []string{"--mesh-ip", "100.64.0.2", "--server-join", "--server", "192.0.2.10", "--etcd-peer-ip", "192.0.2.20"},
			tokenFile: joinToken,
		},
		{
			name:      "--server-join takes a DNS name for the existing server",
			args:      []string{"--server-join", "--server", "server-a.lan", "--token-file", operatorToken, "--node-ip", "192.0.2.20"},
			wantArgs:  []string{"--server-join", "--server", "server-a.lan", "--etcd-peer-ip", "192.0.2.20"},
			tokenFile: joinToken,
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseInstallFlags(append([]string{"--user", "alice"}, tc.args...))
			if err != nil {
				t.Fatalf("parseInstallFlags(%v): %v", tc.args, err)
			}
			if opts.role() != install.RoleServer {
				t.Fatalf("role = %q, want the control plane", opts.role())
			}
			cfg := opts.installConfig("/tmp/k3sm", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

			// The record: what a later reinstall carries forward.
			if got := install.RecordedServerArgs(cfg); !slices.Equal(got, tc.wantArgs) {
				t.Errorf("recorded server arguments = %q, want %q", got, tc.wantArgs)
			}

			// The plist: what launchd runs now, through the real parse.
			plist := install.ServerPlist(cfg)
			got, err := install.OperatorServerArgs(plist)
			if err != nil {
				t.Fatalf("parse the rendered server plist: %v", err)
			}
			if !slices.Equal(got, tc.wantArgs) {
				t.Errorf("server plist operator arguments = %q, want %q", got, tc.wantArgs)
			}
			wantTokenFile := "<string>--token-file</string>\n    <string>" + tc.tokenFile + "</string>"
			if !strings.Contains(string(plist), wantTokenFile) {
				t.Errorf("the server plist does not point --token-file at %s:\n%s", tc.tokenFile, plist)
			}
			// The operator's own token file is read once by the install and is
			// never what the daemon is told to read.
			if strings.Contains(string(plist), operatorToken) {
				t.Errorf("the server plist names the operator's token file %s", operatorToken)
			}
		})
	}

	refused := []struct {
		name string
		args []string
		want string
	}{
		{"--cluster-init with --server-join", []string{"--cluster-init", "--server-join", "--server", "192.0.2.10", "--token-file", operatorToken, "--node-ip", "192.0.2.20"}, "mutually exclusive"},
		{"--server-join without --server", []string{"--server-join", "--token-file", operatorToken, "--node-ip", "192.0.2.20"}, "--server-join needs --server"},
		{"--server-join without --token-file", []string{"--server-join", "--server", "192.0.2.10", "--node-ip", "192.0.2.20"}, "--server-join needs --token-file"},
		{"--cluster-init without --node-ip", []string{"--cluster-init"}, "need --node-ip"},
		{"--server-join without --node-ip", []string{"--server-join", "--server", "192.0.2.10", "--token-file", operatorToken}, "need --node-ip"},
		{"a loopback --node-ip", []string{"--cluster-init", "--node-ip", "127.0.0.1"}, "cannot be loopback"},
		{"an unspecified --node-ip", []string{"--server-join", "--server", "192.0.2.10", "--token-file", operatorToken, "--node-ip", "0.0.0.0"}, "unspecified"},
		{"a --node-ip that is not an address", []string{"--cluster-init", "--node-ip", "server-a"}, "LAN address"},
		{"--server with --cluster-init", []string{"--cluster-init", "--node-ip", "192.0.2.10", "--server", "192.0.2.11"}, "--server cannot be combined with --cluster-init"},
		{"--token-file with --cluster-init", []string{"--cluster-init", "--node-ip", "192.0.2.10", "--token-file", operatorToken}, "--token-file cannot be combined with --cluster-init"},
		{"--server on a single-node server", []string{"--server", "192.0.2.10"}, "--server needs --agent or --server-join"},
		{"--token-file on a single-node server", []string{"--token-file", operatorToken}, "--token-file needs --agent or --server-join"},
		{"--node-ip on a single-node server", []string{"--node-ip", "192.0.2.10"}, "--node-ip needs --agent, --cluster-init or --server-join"},
		{"--agent with --cluster-init", []string{"--agent", "--server", "192.0.2.10", "--cluster-init"}, "--cluster-init cannot be combined with --agent"},
		{"--agent with --server-join", []string{"--agent", "--server", "192.0.2.10", "--server-join"}, "--server-join cannot be combined with --agent"},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			_, err := parseInstallFlags(append([]string{"--user", "alice"}, tc.args...))
			if err == nil {
				t.Fatalf("parseInstallFlags(%v) was accepted, want a refusal naming %q", tc.args, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal %q must name the reason %q", err, tc.want)
			}
		})
	}
}
