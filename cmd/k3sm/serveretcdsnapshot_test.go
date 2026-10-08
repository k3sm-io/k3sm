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
	"errors"
	"flag"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// TestServerEtcdSnapshotFlags pins the scheduled-snapshot flags of `k3sm server`:
// k3s's names and defaults, the schedule they render into the etcd block (none when
// disabled), the refusals of a schedule that cannot run, and the one Info line when
// they are not read (the kine posture, or the schedule turned off).
func TestServerEtcdSnapshotFlags(t *testing.T) {
	parse := func(t *testing.T, args ...string) serverOptions {
		t.Helper()
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		opts := serverOptions{}
		_ = registerServerFlags(fs, &opts)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		opts.nodeName = "server-a"
		return opts
	}

	t.Run("k3s defaults", func(t *testing.T) {
		opts := parse(t, "--cluster-init", "--etcd-peer-ip", "192.0.2.10")
		if opts.etcdSnapshotCron != "0 */12 * * *" || opts.etcdSnapshotRetention != 5 || opts.etcdDisableSnapshots {
			t.Fatalf("defaults = %q %d %v", opts.etcdSnapshotCron, opts.etcdSnapshotRetention, opts.etcdDisableSnapshots)
		}
		snap := opts.etcdConfig().Snapshots
		if snap == nil || snap.Cron.String() != executor.DefaultEtcdSnapshotCron || snap.Retention != executor.DefaultEtcdSnapshotRetention {
			t.Fatalf("etcd block snapshots = %+v", snap)
		}
		if err := opts.executorConfig(nil).Validate(); err != nil {
			t.Fatalf("Validate = %v", err)
		}
	})

	t.Run("operator values reach the etcd block", func(t *testing.T) {
		opts := parse(t, "--server-join", "--etcd-peer-ip", "192.0.2.11", "--etcd-snapshot-schedule-cron", "30 3 * * *", "--etcd-snapshot-retention", "9")
		snap := opts.etcdConfig().Snapshots
		if snap == nil || snap.Cron.String() != "30 3 * * *" || snap.Retention != 9 {
			t.Fatalf("etcd block snapshots = %+v", snap)
		}
	})

	t.Run("disabled renders no schedule", func(t *testing.T) {
		opts := parse(t, "--cluster-init", "--etcd-peer-ip", "192.0.2.10", "--etcd-disable-snapshots")
		if snap := opts.etcdConfig().Snapshots; snap != nil {
			t.Fatalf("etcd block snapshots = %+v, want none", snap)
		}
	})

	for _, tc := range []struct {
		name string
		args []string
		want error
	}{
		{"a malformed cron", []string{"--etcd-snapshot-schedule-cron", "every 12 hours"}, executor.ErrCronSpec},
		{"a cron that never fires", []string{"--etcd-snapshot-schedule-cron", "0 0 31 2 *"}, executor.ErrCronSpec},
		{"retention zero", []string{"--etcd-snapshot-retention", "0"}, executor.ErrEtcdSnapshotRetention},
		{"a malformed cron on a single-server control plane", []string{"--etcd-snapshot-schedule-cron", "*/x * * * *"}, executor.ErrCronSpec},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			opts := parse(t, tc.args...)
			if err := opts.validateEtcdSnapshotFlags(); !errors.Is(err, tc.want) {
				t.Fatalf("validateEtcdSnapshotFlags = %v, want %v", err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name string
		args []string
		want string // "" = no line
	}{
		{"kine posture, defaults: silent", nil, ""},
		{"kine posture, a flag changed: one Info line", []string{"--etcd-snapshot-retention", "3"}, "the etcd snapshot flags are ignored"},
		{"kine posture, disabled: one Info line", []string{"--etcd-disable-snapshots"}, "the etcd snapshot flags are ignored"},
		{"etcd posture, defaults: silent here (the executor logs the schedule)", []string{"--cluster-init", "--etcd-peer-ip", "192.0.2.10"}, ""},
		{"etcd posture, disabled: one Info line", []string{"--cluster-init", "--etcd-peer-ip", "192.0.2.10", "--etcd-disable-snapshots"}, "scheduled etcd snapshots are off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			parse(t, tc.args...).logEtcdSnapshotPosture(slog.New(slog.NewTextHandler(&buf, nil)))
			out := buf.String()
			switch {
			case tc.want == "" && out != "":
				t.Fatalf("logged %q, want nothing", out)
			case tc.want != "" && (strings.Count(out, "\n") != 1 || !strings.Contains(out, tc.want) || !strings.Contains(out, "level=INFO")):
				t.Fatalf("logged %q, want one Info line carrying %q", out, tc.want)
			}
		})
	}
}

// TestInstallRecordsEtcdSnapshotFlags pins `k3sm install`'s snapshot flags: a
// passed flag reaches the daemon's argv and the server-arguments record (and the
// daemon parses it back to the same schedule), it replaces a carried value rather
// than rendering a second one, an unpassed flag leaves the carried value alone, and
// a worker install or a schedule the daemon would refuse is refused before anything
// is written.
func TestInstallRecordsEtcdSnapshotFlags(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := []string{"--user", "alice", "--cluster-init", "--node-ip", "192.0.2.10"}

	t.Run("passed flags are recorded and parse back", func(t *testing.T) {
		opts, err := parseInstallFlags(append(base, "--etcd-snapshot-schedule-cron", " 15  2 * * * ", "--etcd-snapshot-retention", "7", "--etcd-disable-snapshots=false"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := opts.installConfig("/tmp/k3sm", nil, logger)
		want := []string{"--cluster-init", "--etcd-peer-ip", "192.0.2.10",
			"--etcd-snapshot-schedule-cron", "15 2 * * *", "--etcd-snapshot-retention", "7", "--etcd-disable-snapshots=false"}
		got := install.RecordedServerArgs(cfg)
		if !slices.Equal(got, want) {
			t.Fatalf("recorded = %q, want %q", got, want)
		}
		plistArgs, err := install.OperatorServerArgs(install.ServerPlist(cfg))
		if err != nil || !slices.Equal(plistArgs, want) {
			t.Fatalf("plist operator args = %q (%v), want %q", plistArgs, err, want)
		}
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		so := serverOptions{}
		_ = registerServerFlags(fs, &so)
		if err := fs.Parse(got); err != nil {
			t.Fatalf("the daemon cannot parse the recorded arguments: %v", err)
		}
		so.nodeName = "server-a"
		if snap := so.etcdConfig().Snapshots; snap == nil || snap.Cron.String() != "15 2 * * *" || snap.Retention != 7 {
			t.Fatalf("the daemon reads the schedule as %+v", snap)
		}
	})

	t.Run("a passed flag replaces the carried one; an unpassed one is carried", func(t *testing.T) {
		opts, err := parseInstallFlags(append(base, "--etcd-snapshot-retention", "2"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := opts.installConfig("/tmp/k3sm", nil, logger)
		cfg.ExtraServerArgs = []string{"--etcd-snapshot-retention=9", "--etcd-snapshot-schedule-cron", "0 1 * * *", "--etcd-disable-snapshots"}
		want := []string{"--etcd-snapshot-schedule-cron", "0 1 * * *", "--etcd-disable-snapshots",
			"--cluster-init", "--etcd-peer-ip", "192.0.2.10", "--etcd-snapshot-retention", "2"}
		if got := install.RecordedServerArgs(cfg); !slices.Equal(got, want) {
			t.Fatalf("recorded = %q, want %q", got, want)
		}
	})

	t.Run("no snapshot flag passed renders none", func(t *testing.T) {
		opts, err := parseInstallFlags(base)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range install.RecordedServerArgs(opts.installConfig("/tmp/k3sm", nil, logger)) {
			if strings.Contains(a, "snapshot") {
				t.Fatalf("an install with no snapshot flag rendered %q", a)
			}
		}
	})

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"on a worker", []string{"--user", "alice", "--agent", "--server", "192.0.2.10", "--etcd-snapshot-retention", "3"}},
		{"a malformed cron", append(slices.Clone(base), "--etcd-snapshot-schedule-cron", "0 */12 * *")},
		{"retention zero", append(slices.Clone(base), "--etcd-snapshot-retention", "0")},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			if _, err := parseInstallFlags(tc.args); err == nil {
				t.Fatalf("parseInstallFlags(%v) accepted it", tc.args)
			}
		})
	}
}
