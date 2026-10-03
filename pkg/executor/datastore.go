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

package executor

import (
	"strconv"
)

// sqliteEndpoint is the single-node kine->SQLite WAL DSN. The path segment composes
// on StateDBPath so the writer and the `k3sm doctor` probe share one source of the
// state.db layout.
//
// _kine_disable_startup_vacuum turns OFF the full-database VACUUM kine >=0.16 runs on
// EVERY startup (kine pkg/drivers/sqlite/sqlite.go: noStartupVacuum). k3sm DELIBERATELY
// disables it. A VACUUM rewrites the entire database — it needs room for a second full
// copy on the same APFS volume that also holds the image store, pod dirs, and PV data
// (DESIGN's ENOSPC hazard), and it lengthens every boot of a laptop-class node in
// proportion to cluster size, on the critical path before the apiserver can start.
// Reclaiming post-compaction free pages is worth doing occasionally, not once per
// `launchctl kickstart`; if it is ever wanted it becomes a deliberate maintenance
// operation, not a boot-time surprise. The old pin (v1.14.2) never vacuumed at startup,
// so leaving the flag off would have made "same datastore, new kine pin" silently
// change what a boot does to the disk.
//
// The parameter is valueless by kine's own contract (a strings.Contains probe on the
// DSN); the no-cgo driver passes unknown parameters through to modernc.org/sqlite,
// which ignores it. Verified live against the pinned build: kine logs
// "Startup VACUUM is disabled" and serves normally.
func sqliteEndpoint(workDir string) string {
	return "sqlite://" + StateDBPath(workDir) + "?_journal=WAL&_busy_timeout=30000&_kine_disable_startup_vacuum"
}

// kineArgs renders kine's argv from cfg. It is a pure function (no I/O) so the
// datastore posture is table-tested without spawning kine. kine runs only in the
// single-node posture (the etcd posture runs an etcd child instead), so its argv is
// always the SQLite WAL shape, byte-identical across releases
// (TestKineArgsUnchangedAfterRetirement). The error return is kept so a future
// endpoint that can fail to render does not change every caller.
func kineArgs(cfg Config) ([]string, error) {
	// Disable kine's Prometheus metrics endpoint. It defaults to :8080 on ALL
	// interfaces (kine v1.14.2 app.go: "set 0 to disable metrics serving"), and
	// because k3sm pods share the host network (no netns), that listener collides
	// with any workload binding :8080 — e.g. a readiness probe server — failing it
	// with "bind: address already in use". k3sm does not scrape kine's metrics; a
	// later need would bind them to a chosen localhost port, never all-interfaces :8080.
	return []string{
		"--listen-address", "127.0.0.1:" + strconv.Itoa(cfg.KinePort),
		"--metrics-bind-address", "0",
		"--endpoint", sqliteEndpoint(cfg.WorkDir),
	}, nil
}

// datastorePosture names the datastore backing this server for logging: "sqlite" for
// the single-node kine WAL default, "etcd" for an embedded etcd member.
func datastorePosture(cfg Config) string {
	if cfg.Etcd != nil {
		return "etcd"
	}
	return "sqlite"
}
