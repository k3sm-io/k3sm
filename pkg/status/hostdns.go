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
	"fmt"
	"io/fs"
	"strings"

	"k3sm.io/k3sm/pkg/shadow"
)

// nodeResolverKickstart restarts netd, which republishes the node resolver
// entry on every start.
const nodeResolverKickstart = "sudo launchctl kickstart -k system/io.k3sm.netd"

// shadowRemedy re-makes the shadow shell set from the live host binaries.
const shadowRemedy = "sudo k3sm install"

// nodeResolverRow reports whether netd's node resolver entry (svc and the
// cluster domain routed to the node DNS VIP) is in the host resolver
// configuration, and whether netd is alive to own it. configd keeps a State:
// key after its writer exits, so a present entry alone does not say the
// daemon that republishes and removes it is running. netd is the netd row
// just collected; ok is false when no reader was wired in.
func (c Collector) nodeResolverRow(netd Row) (Row, bool) {
	if c.NodeResolverPresent == nil {
		return Row{}, false
	}
	row := Row{Name: RowNodeResolver}
	present, err := c.NodeResolverPresent()
	switch {
	case err != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not read the host resolver configuration: " + errText(err)
	case !present:
		row.State, row.Severity = StateMissing, SeverityWarn
		row.Detail = "netd has not published the node resolver entry: host processes and pods whose shell lost the shim cannot resolve cluster names"
		row.Remedy = nodeResolverKickstart
	case !c.netdAlive(netd):
		row.State, row.Severity = StateDown, SeverityWarn
		row.Detail = "entry published, but netd is not running to maintain it; svc and the cluster domain route to a node DNS that may not answer"
		row.Remedy = nodeResolverKickstart
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "entry published; svc and the cluster domain route to the node DNS"
	}
	return row, true
}

// netdAlive reports whether netd is up, by the netd row's own verdict and the
// existing rendezvous-socket probe (socketClause's Stat). A socket this
// account cannot see (the run dir is not readable) defers to the row.
func (c Collector) netdAlive(netd Row) bool {
	if netd.Severity != SeverityOK {
		return false
	}
	if c.FS == nil || c.Paths.NetdSocket == "" {
		return true
	}
	_, err := c.FS.Stat(c.Paths.NetdSocket)
	return err == nil || errors.Is(err, fs.ErrPermission)
}

// shadowShellsRow compares the shadow shell manifest's source cdhashes with
// the live host binaries. A macOS update replaces /bin/bash and friends; the
// copies then lag until the next install, which is what the remedy does. ok is
// false when no cdhash reader was wired in.
func (c Collector) shadowShellsRow() (Row, bool) {
	if c.CDHash == nil || c.FS == nil || c.Paths.ShadowManifest == "" {
		return Row{}, false
	}
	row := Row{Name: RowShadowShells, Remedy: shadowRemedy}
	b, err := c.FS.ReadFile(c.Paths.ShadowManifest)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			row.State, row.Severity = StateMissing, SeverityWarn
			row.Detail = "no shadow shell set: pods that start through /bin/sh lose the DNS and path shims"
			return row, true
		}
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not read " + c.Paths.ShadowManifest + ": " + errText(err)
		row.Remedy = ""
		return row, true
	}
	m, err := shadow.Decode(b)
	if err != nil {
		row.State, row.Severity = StateCorrupt, SeverityWarn
		row.Detail = errText(err)
		return row, true
	}
	drifted := shadow.Drift(m, c.CDHash)
	if len(drifted) == 0 {
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("%d re-signed host shells match their sources", len(m.Sources))
		row.Remedy = ""
		return row, true
	}
	var paths []string
	for _, d := range drifted {
		paths = append(paths, d.Source.Path)
	}
	row.State, row.Severity = StateDrift, SeverityWarn
	row.Detail = fmt.Sprintf("%s changed since the last install (a macOS update); pods keep running the older copies: run sudo k3sm install",
		strings.Join(paths, ", "))
	return row, true
}
