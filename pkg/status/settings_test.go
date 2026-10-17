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

package status

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// nodeArgs is a NodeArgs seam answering args (or err) for every role.
func nodeArgs(args []string, err error) func(install.Role) ([]string, error) {
	return func(install.Role) ([]string, error) { return args, err }
}

// TestSettingsRow pins the settings row: its shape on each role, the defaults
// an absent flag reads as, the restricted masking of a root-only source, that
// no credential reaches it, and that the goldens carry exactly the row Collect
// builds.
func TestSettingsRow(t *testing.T) {
	t.Parallel()
	okRoot := Row{Name: RowDataRoot, State: StateOK}
	lanOff := &Network{LAN: string(install.LANOff), Recorded: true}
	volume := &dataroot.Record{Name: "k3sm", QuotaBytes: 100 << 30, Encrypted: true}

	for _, tc := range []struct {
		name       string
		role       dataroot.Role
		args       []string
		argsErr    error
		dataRoot   Row
		volume     *dataroot.Record
		network    *Network
		wantState  RowState
		wantSev    Severity
		wantRemedy string
		wantWide   map[string]string
		wantDetail string
	}{
		{
			name: "a stock server reads every default",
			role: dataroot.RoleServer, dataRoot: okRoot, network: lanOff,
			wantState: StateOK, wantSev: SeverityOK,
			wantWide: map[string]string{
				SettingNodePortAddresses: "every interface",
				SettingRegistryPort:      "off",
				SettingTLSSANs:           "none",
				SettingMeshIP:            "none",
				SettingKubeconfigName:    install.DefaultKubeconfigName,
				SettingReleaseBase:       "default",
				SettingDataVolume:        "none",
				SettingLANAccess:         "off",
			},
			wantDetail: "NodePort addresses every interface · registry port off · TLS SANs none · mesh IP none · kubeconfig name " +
				install.DefaultKubeconfigName + " · release base default · data volume none · LAN access off",
		},
		{
			name: "a configured server reads its recorded flags, either spelling, and masks a URL password",
			role: dataroot.RoleServer, dataRoot: okRoot, volume: volume,
			network: &Network{LAN: string(install.LANOn), Recorded: true},
			args: []string{
				"--nodeport-addresses", "local", "-registry-port=5000",
				"--tls-san=k3sm.example.test", "--tls-san", "192.0.2.20",
				"--mesh-ip", "100.64.0.1", "--kubeconfig-name", "lab",
				"--update-release-base=https://mirror:hunter2@releases.example.test/k3sm",
			},
			wantState: StateOK, wantSev: SeverityOK,
			wantWide: map[string]string{
				SettingNodePortAddresses: "local",
				SettingRegistryPort:      "5000",
				SettingTLSSANs:           "k3sm.example.test,192.0.2.20",
				SettingMeshIP:            "100.64.0.1",
				SettingKubeconfigName:    "lab",
				SettingReleaseBase:       "https://mirror:***@releases.example.test/k3sm",
				SettingDataVolume:        "k3sm (quota 100G, encrypted)",
				SettingLANAccess:         "on",
			},
			wantDetail: "NodePort addresses local · registry port 5000 · TLS SANs k3sm.example.test,192.0.2.20 · mesh IP 100.64.0.1 · kubeconfig name lab · release base https://mirror:***@releases.example.test/k3sm · data volume k3sm (quota 100G, encrypted) · LAN access on",
		},
		{
			name: "a worker carries only the settings its daemon takes",
			role: dataroot.RoleAgent, dataRoot: okRoot, network: lanOff,
			args:      []string{"--nodeport-addresses", "192.0.2.0/24", "--registry-port", "5000"},
			wantState: StateOK, wantSev: SeverityOK,
			wantWide: map[string]string{
				SettingNodePortAddresses: "192.0.2.0/24",
				SettingReleaseBase:       "default",
				SettingDataVolume:        "none",
				SettingLANAccess:         "off",
			},
			wantDetail: "NodePort addresses 192.0.2.0/24 · release base default · data volume none · LAN access off",
		},
		{
			name: "a root-only arguments source is restricted, and what this account can read still reads",
			role: dataroot.RoleServer, dataRoot: okRoot, volume: volume, network: lanOff,
			argsErr:   fmt.Errorf("read the installed server plist /Library/LaunchDaemons/io.k3sm.server.plist: %w", fs.ErrPermission),
			wantState: StateNeedsAdmin, wantSev: SeveritySkip, wantRemedy: needsAdminRemedy,
			wantWide: map[string]string{
				SettingNodePortAddresses: SettingRestricted,
				SettingRegistryPort:      SettingRestricted,
				SettingTLSSANs:           SettingRestricted,
				SettingMeshIP:            SettingRestricted,
				SettingKubeconfigName:    SettingRestricted,
				SettingReleaseBase:       SettingRestricted,
				SettingDataVolume:        "k3sm (quota 100G, encrypted)",
				SettingLANAccess:         "off",
			},
			wantDetail: "NodePort addresses restricted · registry port restricted · TLS SANs restricted · mesh IP restricted · kubeconfig name restricted · release base restricted · data volume k3sm (quota 100G, encrypted) · LAN access off",
		},
		{
			name: "an unparsable source, an unprobed data root and no LAN reader are unknown",
			role: dataroot.RoleAgent, dataRoot: Row{Name: RowDataRoot, State: StateUnknown},
			argsErr:   errors.New("no ProgramArguments array"),
			wantState: StateUnknown, wantSev: SeverityUnknown,
			wantWide: map[string]string{
				SettingNodePortAddresses: "unknown",
				SettingReleaseBase:       "unknown",
				SettingDataVolume:        "unknown",
				SettingLANAccess:         "unknown",
			},
			wantDetail: "NodePort addresses unknown · release base unknown · data volume unknown · LAN access unknown",
		},
		{
			name: "an unusable LAN record says so",
			role: dataroot.RoleAgent, dataRoot: okRoot,
			network:   &Network{LAN: string(install.LANOff), Recorded: true, RecordState: NetworkRecordUnreadable},
			wantState: StateOK, wantSev: SeverityOK,
			wantWide: map[string]string{
				SettingNodePortAddresses: "every interface",
				SettingReleaseBase:       "default",
				SettingDataVolume:        "none",
				SettingLANAccess:         NetworkRecordUnreadable,
			},
			wantDetail: "NodePort addresses every interface · release base default · data volume none · LAN access unreadable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{NodeArgs: nodeArgs(tc.args, tc.argsErr)}
			row, ok := c.settingsRow(tc.role, true, tc.dataRoot, tc.volume, tc.network)
			if !ok {
				t.Fatal("no settings row on an installed Mac with a reader")
			}
			if row.Name != RowSettings || row.State != tc.wantState || row.Severity != tc.wantSev || row.Remedy != tc.wantRemedy {
				t.Errorf("row = %s %s/%s remedy %q, want %s %s/%s remedy %q",
					row.Name, row.State, row.Severity, row.Remedy, RowSettings, tc.wantState, tc.wantSev, tc.wantRemedy)
			}
			if !reflect.DeepEqual(row.Wide, tc.wantWide) {
				t.Errorf("wide = %v\nwant   %v", row.Wide, tc.wantWide)
			}
			if row.Detail != tc.wantDetail {
				t.Errorf("detail = %q\nwant     %q", row.Detail, tc.wantDetail)
			}
			for k, v := range row.Wide {
				if strings.Contains(v, "hunter2") || strings.Contains(row.Detail, "hunter2") {
					t.Errorf("wide %s = %q carries the URL password", k, v)
				}
			}
		})
	}

	t.Run("no install or no reader leaves the row out", func(t *testing.T) {
		t.Parallel()
		if _, ok := (Collector{NodeArgs: nodeArgs(nil, nil)}).settingsRow(dataroot.RoleServer, false, Row{}, nil, nil); ok {
			t.Error("a Mac with no install got a settings row")
		}
		if _, ok := (Collector{}).settingsRow(dataroot.RoleServer, true, Row{}, nil, nil); ok {
			t.Error("a report with no arguments reader got a settings row")
		}
	})

	t.Run("a restricted row never moves the verdict", func(t *testing.T) {
		t.Parallel()
		c := Collector{NodeArgs: nodeArgs(nil, fs.ErrPermission)}
		row, _ := c.settingsRow(dataroot.RoleServer, true, Row{Name: RowDataRoot, State: StateOK}, nil, nil)
		if v, _, _ := Aggregate(append(healthyRows(), row), true, dataroot.RoleServer); v != VerdictRunning {
			t.Errorf("verdict = %v with a restricted settings row, want running", v)
		}
	})

	t.Run("the goldens carry exactly the row Collect builds", func(t *testing.T) {
		seen := 0
		for name, sc := range contractScenarios() {
			fullPath, _ := goldenPaths(name)
			var golden Report
			decodeStrict(t, fullPath, &golden)
			got, gotOK := sc.collector(t).Collect(context.Background()).Row(RowSettings)
			want, wantOK := golden.Row(RowSettings)
			if gotOK != wantOK || !reflect.DeepEqual(got, want) {
				t.Errorf("%s: collected settings row (%v) %+v, golden (%v) %+v", name, gotOK, got, wantOK, want)
			}
			if gotOK {
				seen++
				if got.State == StateNeedsAdmin && got.Wide[SettingNodePortAddresses] != SettingRestricted {
					t.Errorf("%s: a needs-admin settings row does not mark its values restricted", name)
				}
			}
		}
		if seen == 0 {
			t.Error("no golden carries a settings row")
		}
	})
}
