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
	"errors"
	"io/fs"
	"strconv"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// RowSettings is the node's install settings: the values `k3sm install`
// recorded in the node daemon's arguments, the data volume, and LAN access.
// The row exists on an installed Mac whose report wired the arguments reader.
const RowSettings = "settings"

// SettingRestricted is a settings value only root may read: the arguments
// source is closed to this account. It is a value, not a guess, so a client
// can show it as "needs sudo" rather than as unset.
const SettingRestricted = "restricted"

// settingUnknown is a settings value whose source could not be read for a
// reason other than permission (an unparsable plist, a data root this report
// could not probe, no reader wired).
const settingUnknown = "unknown"

// The settings row's wide keys. They are the machine contract: a reader keys on
// them, so they change like an API (docs/user/status-json.md lists them).
const (
	SettingNodePortAddresses = "nodeport-addresses"
	SettingRegistryPort      = "registry-port"
	SettingTLSSANs           = "tls-sans"
	SettingMeshIP            = "mesh-ip"
	SettingKubeconfigName    = "kubeconfig-name"
	SettingReleaseBase       = "release-base"
	SettingDataVolume        = "data-volume"
	SettingLANAccess         = "lan-access"
)

// setting is one entry of the row: its wide key and the label the human line
// gives it, in display order.
type setting struct {
	key, label string
	// serverOnly entries are flags only `k3sm server` takes, so a worker's row
	// does not carry them.
	serverOnly bool
}

// settingsOrder is the row's entries, in the order the human line reads them.
var settingsOrder = []setting{
	{key: SettingNodePortAddresses, label: "NodePort addresses"},
	{key: SettingRegistryPort, label: "registry port", serverOnly: true},
	{key: SettingTLSSANs, label: "TLS SANs", serverOnly: true},
	{key: SettingMeshIP, label: "mesh IP", serverOnly: true},
	{key: SettingKubeconfigName, label: "kubeconfig name", serverOnly: true},
	{key: SettingReleaseBase, label: "release base"},
	{key: SettingDataVolume, label: "data volume"},
	{key: SettingLANAccess, label: "LAN access"},
}

// settingsRow reports the install settings of this Mac's node: what an
// operator chose at `k3sm install` (or left at the default), read back from the
// same sources a reinstall carries over. It reports ok=false when there is no
// install or no arguments reader.
//
// It is read-only and never moves the verdict. Every value is one the
// installer wrote in the open (the daemon's argv, the data-volume record, the
// LAN record): the flags it names are a fixed list, none of which carries a
// credential, and each value still goes through Redact, so a release base URL
// with a password in it reaches the row with the password masked. A source
// this account may not read yields SettingRestricted for the values it holds
// and the row says needs-admin, the way every other root-only check does.
func (c Collector) settingsRow(role dataroot.Role, installed bool, dataRoot Row, volume *dataroot.Record, network *Network) (Row, bool) {
	if !installed || c.NodeArgs == nil {
		return Row{}, false
	}
	row := Row{Name: RowSettings, State: StateOK, Severity: SeverityOK, Wide: map[string]string{}}
	args, err := c.NodeArgs(role)
	argsValue := ""
	switch {
	case errors.Is(err, fs.ErrPermission):
		argsValue = SettingRestricted
		row.State, row.Severity, row.Remedy = StateNeedsAdmin, SeveritySkip, needsAdminRemedy
	case err != nil:
		argsValue = settingUnknown
		row.State, row.Severity = StateUnknown, SeverityUnknown
	}
	for _, s := range settingsOrder {
		if s.serverOnly && role == dataroot.RoleAgent {
			continue
		}
		switch {
		case s.key == SettingDataVolume:
			row.Wide[s.key] = dataVolumeSetting(dataRoot, volume)
		case s.key == SettingLANAccess:
			row.Wide[s.key] = lanSetting(network)
		case argsValue != "":
			row.Wide[s.key] = argsValue
		default:
			row.Wide[s.key] = Redact(argSetting(args, s.key))
		}
	}
	parts := make([]string, 0, len(row.Wide))
	for _, s := range settingsOrder {
		if v, ok := row.Wide[s.key]; ok {
			parts = append(parts, s.label+" "+v)
		}
	}
	row.Detail = strings.Join(parts, " · ")
	return row, true
}

// argSetting is the value one recorded flag sets, or the word for the default
// the daemon takes when the flag is absent.
func argSetting(args []string, key string) string {
	switch key {
	case SettingNodePortAddresses:
		// Absent (or empty) is every interface: install drops the flag for "".
		if v, ok := argValue(args, "nodeport-addresses"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return "every interface"
	case SettingRegistryPort:
		// The registry runs by default; only an explicit 0 turns it off.
		v, ok := argValue(args, "registry-port")
		switch {
		case !ok || v == "":
			return strconv.Itoa(executor.DefaultRegistryPort)
		case v == "0":
			return "off"
		}
		return v
	case SettingTLSSANs:
		if sans := install.ServerArgValues(args, install.TLSSANFlag); len(sans) > 0 {
			return strings.Join(sans, ",")
		}
		return "none"
	case SettingMeshIP:
		if v, ok := argValue(args, "mesh-ip"); ok && v != "" {
			return v
		}
		return "none"
	case SettingKubeconfigName:
		if v, ok := argValue(args, "kubeconfig-name"); ok && v != "" {
			return v
		}
		return install.DefaultKubeconfigName
	case SettingReleaseBase:
		if v, ok := argValue(args, install.UpdateReleaseBaseFlag); ok && v != "" {
			return v
		}
		return "default"
	}
	return settingUnknown
}

// dataVolumeSetting is the data-volume entry: "none" for a data root that is a
// plain directory, else the volume's name, quota and encryption, read from the
// record the data-root row read.
func dataVolumeSetting(dataRoot Row, volume *dataroot.Record) string {
	if dataRoot.State == StateUnknown {
		return settingUnknown
	}
	if volume == nil {
		return "none"
	}
	enc := "not encrypted"
	if volume.Encrypted {
		enc = "encrypted"
	}
	return volume.Name + " (quota " + quotaText(volume.QuotaBytes) + ", " + enc + ")"
}

// lanSetting is the LAN access entry, from the report's network block: the
// value the node daemon serves, "unreadable" when the record cannot be used,
// or unknown when the report read no record.
func lanSetting(n *Network) string {
	switch {
	case n == nil:
		return settingUnknown
	case n.RecordState == NetworkRecordUnreadable:
		return NetworkRecordUnreadable
	}
	return n.LAN
}
