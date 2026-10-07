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
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// SchemaVersion is the version of the `k3sm status` JSON contract, carried by
// both shapes (Report and DaemonsReport) as "schemaVersion". It is defined
// here, once, and bumps ONLY on a breaking change: a field removed or renamed,
// a field whose type changes, or a field or enum word whose meaning changes. An
// added field or an added enum word does not bump it, so a reader must ignore
// keys it does not know and treat an enum word it does not know as unknown.
// docs/user/status-json.md is the reader-facing statement of the contract.
const SchemaVersion = 1

// DaemonsReport is the machine interface of `k3sm status daemons -o json`: the
// cheap probe. It answers "are this Mac's k3sm daemons up" from launchd and the
// local disk alone; it never builds an apiserver client, never dials the
// runtime socket and never lists a workload, so it is safe to poll.
//
// Daemons holds the netd row and this Mac's node-daemon row (server or agent),
// built by the same builders as the full report's rows of the same names. The
// verdict is Aggregate's, the same function the full report's verdict comes
// from, fed the rows this probe read (the install row and the two daemons). A
// report that did not probe the apiserver carries no apiserver row, and
// Aggregate reads the daemons alone in that case, so the probe's verdict is the
// full report's on every cause it can see; a cause only the apiserver or the
// disk rows can see (a pod stuck pending, an unmounted data root) shows in the
// full report and not here.
type DaemonsReport struct {
	SchemaVersion int           `json:"schemaVersion"`
	Verdict       Verdict       `json:"verdict"`
	Role          dataroot.Role `json:"role"`
	Summary       string        `json:"summary"`
	Daemons       []Row         `json:"daemons"`
}

// CollectDaemons is the cheap probe behind DaemonsReport. It reads launchd
// (through the Launchd seam), the install's files, the crash-loop record and
// the node credential store (through the FS seam) and the data-volume record
// (through the DataRoot seam). It never touches Kube, Runtimed, Volumes,
// ServerArgs, NodeResolverPresent, CDHash or EtcdMetrics, so a caller may leave
// them nil, and a test pins that a wired one is never reached.
func (c Collector) CollectDaemons() DaemonsReport {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	role, _, bothRoles := c.installedRole()
	ld := c.launchdRows(now(), role, bothRoles, c.dataVolume() != nil)
	verdict, summary, _ := Aggregate([]Row{ld.install, ld.netd, ld.node}, ld.installed, role)
	return DaemonsReport{
		SchemaVersion: SchemaVersion,
		Verdict:       verdict,
		Role:          role,
		Summary:       summary,
		Daemons:       []Row{ld.netd, ld.node},
	}
}

// dataVolume is the data-volume record this Mac's data root is declared by, or
// nil when it has none or it could not be read. It is the same read
// dataRootRow makes (dataroot.ReadWithRecord), without the usage figures that
// row adds, so the probe's install row demands the mount job's plist exactly
// when the full report's does.
func (c Collector) dataVolume() *dataroot.Record {
	if c.DataRoot == nil {
		return nil
	}
	st, err := dataroot.ReadWithRecord(c.DataRoot, c.Paths.DataRoot, c.datavolRecordPath())
	if err != nil {
		return nil
	}
	return st.Volume
}

// datavolRecordPath is the data-volume record this report reads: the scoped
// one when Paths names it, else the one production record.
func (c Collector) datavolRecordPath() string {
	if c.Paths.DatavolRecord != "" {
		return c.Paths.DatavolRecord
	}
	return dataroot.DefaultRecordPath
}
