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

import "strconv"

// The scheduled etcd snapshot flags of `k3sm install`.
//
// `k3sm install` accepts k3s's three snapshot flags and renders the ones the operator
// passed into the server daemon's arguments, where they are recorded and carried
// forward like every other server argument: a later plain reinstall keeps them, and
// a reinstall that passes one again replaces the carried value instead of rendering
// the flag twice. A flag the operator did not pass is not rendered, so the daemon
// takes k3s's default for it.

const (
	etcdSnapshotCronFlag      = "etcd-snapshot-schedule-cron"
	etcdSnapshotRetentionFlag = "etcd-snapshot-retention"
	etcdDisableSnapshotsFlag  = "etcd-disable-snapshots"
)

// EtcdSnapshotFlags are the scheduled-snapshot flags THIS install was given. A zero
// field was not given: Cron "" and Retention 0 are never valid values, and Disable
// is a pointer so an explicit --etcd-disable-snapshots=false can turn a carried
// true back off.
type EtcdSnapshotFlags struct {
	Cron      string
	Retention int
	Disable   *bool
}

// args renders the given flags as `k3sm server` arguments.
func (f EtcdSnapshotFlags) args() []string {
	var out []string
	if f.Cron != "" {
		out = append(out, "--"+etcdSnapshotCronFlag, f.Cron)
	}
	if f.Retention != 0 {
		out = append(out, "--"+etcdSnapshotRetentionFlag, strconv.Itoa(f.Retention))
	}
	if f.Disable != nil {
		out = append(out, "--"+etcdDisableSnapshotsFlag+"="+strconv.FormatBool(*f.Disable))
	}
	return out
}

// names are the flags f sets.
func (f EtcdSnapshotFlags) names() map[string]bool {
	m := map[string]bool{}
	if f.Cron != "" {
		m[etcdSnapshotCronFlag] = true
	}
	if f.Retention != 0 {
		m[etcdSnapshotRetentionFlag] = true
	}
	if f.Disable != nil {
		m[etcdDisableSnapshotsFlag] = true
	}
	return m
}

// setEtcdSnapshotArgs returns args with every carried occurrence of a flag f sets
// removed (either spelling, inline or separate value) and f's flags appended. The
// boolean flag never takes a separate value, matching Go's flag package.
func setEtcdSnapshotArgs(args []string, f EtcdSnapshotFlags) []string {
	set := f.names()
	if len(set) == 0 {
		return args
	}
	out := make([]string, 0, len(args)+5)
	for i := 0; i < len(args); i++ {
		name, _, inline := splitFlag(args[i])
		if !set[name] {
			out = append(out, args[i])
			continue
		}
		if !inline && name != etcdDisableSnapshotsFlag {
			i++ // drop the separate value too
		}
	}
	return append(out, f.args()...)
}
