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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// plistDisk is a read-only fake of the one disk read the role probe makes. It
// has no write method, which is the point: the refusal is handed nothing it
// could rewrite a plist, config or identity file through.
type plistDisk struct {
	files map[string]bool
	err   error
}

func (d plistDisk) ReadFile(path string) ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	if d.files[path] {
		return []byte("<plist/>"), nil
	}
	return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

// TestAgentRefusesWhenServerRoleInstalled proves a hand-run `k3sm agent` on a
// Mac still installed as a server stops before it joins, and names both the
// cause and the two commands that change the role. On such a Mac the netd
// helper is handed the server's admin kubeconfig, so a worker started beside it
// would have its privileged Service binds refused.
func TestAgentRefusesWhenServerRoleInstalled(t *testing.T) {
	serverPlist := filepath.Join(install.DefaultLaunchDaemonDir, install.ServerLabel+".plist")
	agentPlist := filepath.Join(install.DefaultLaunchDaemonDir, install.AgentLabel+".plist")
	denied := errors.New("permission denied")

	for _, tc := range []struct {
		name    string
		disk    plistDisk
		wantErr bool
		want    []string
	}{
		{
			name:    "server plist on disk: refused with the remedy",
			disk:    plistDisk{files: map[string]bool{serverPlist: true}},
			wantErr: true,
			want:    []string{serverPlist, "server admin kubeconfig", "sudo k3sm uninstall", "sudo k3sm install --agent"},
		},
		{
			name: "no server plist: proceeds",
			disk: plistDisk{},
		},
		{
			name: "an installed agent is not a reason to refuse",
			disk: plistDisk{files: map[string]bool{agentPlist: true}},
		},
		{
			name:    "an unreadable plist is reported, not read as absent",
			disk:    plistDisk{err: denied},
			wantErr: true,
			want:    []string{serverPlist},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseAgentOnServerMac(tc.disk)
			if (err != nil) != tc.wantErr {
				t.Fatalf("refuseAgentOnServerMac() error = %v, wantErr %v", err, tc.wantErr)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err, w)
				}
			}
		})
	}
}
