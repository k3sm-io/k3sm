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

import (
	"slices"
	"testing"
)

// TestSetEtcdSnapshotArgs: each snapshot flag this install was given replaces every
// carried spelling of it (single or double dash, inline or separate value), the
// boolean never swallows the next argument, other arguments keep their order, and
// an install that passed none returns the carried arguments untouched.
func TestSetEtcdSnapshotArgs(t *testing.T) {
	t.Parallel()
	off, on := false, true
	for _, tc := range []struct {
		name    string
		carried []string
		flags   EtcdSnapshotFlags
		want    []string
	}{
		{"none passed", []string{"--mesh-ip", "100.64.0.1", "--etcd-snapshot-retention", "9"}, EtcdSnapshotFlags{},
			[]string{"--mesh-ip", "100.64.0.1", "--etcd-snapshot-retention", "9"}},
		{"separate values replaced", []string{"--etcd-snapshot-schedule-cron", "0 1 * * *", "--mesh-ip", "100.64.0.1", "-etcd-snapshot-retention", "9"},
			EtcdSnapshotFlags{Cron: "0 2 * * *", Retention: 4},
			[]string{"--mesh-ip", "100.64.0.1", "--etcd-snapshot-schedule-cron", "0 2 * * *", "--etcd-snapshot-retention", "4"}},
		{"inline values replaced", []string{"--etcd-snapshot-retention=9", "--cluster-init"}, EtcdSnapshotFlags{Retention: 4},
			[]string{"--cluster-init", "--etcd-snapshot-retention", "4"}},
		{"the boolean takes no separate value", []string{"--etcd-disable-snapshots", "--cluster-init"}, EtcdSnapshotFlags{Disable: &off},
			[]string{"--cluster-init", "--etcd-disable-snapshots=false"}},
		{"an explicit disable", nil, EtcdSnapshotFlags{Disable: &on}, []string{"--etcd-disable-snapshots=true"}},
		{"an unpassed flag is carried", []string{"--etcd-snapshot-schedule-cron", "0 1 * * *"}, EtcdSnapshotFlags{Retention: 2},
			[]string{"--etcd-snapshot-schedule-cron", "0 1 * * *", "--etcd-snapshot-retention", "2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := setEtcdSnapshotArgs(slices.Clone(tc.carried), tc.flags); !slices.Equal(got, tc.want) {
				t.Fatalf("setEtcdSnapshotArgs = %q, want %q", got, tc.want)
			}
		})
	}
}
