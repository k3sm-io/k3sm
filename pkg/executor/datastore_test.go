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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestDatastoreEndpointSQLiteDefault proves the single-node path renders kine's argv
// as exactly [--listen-address 127.0.0.1:<port> --metrics-bind-address 0 --endpoint
// sqlite://…WAL…], with NO connection-pool flags and NO out-of-band secret env. The
// --metrics-bind-address 0 DISABLES kine's Prometheus endpoint (kine's default is
// :8080 on ALL interfaces); pods share the host network, so that listener would
// collide with any workload binding :8080 (a readiness server) — "address already
// in use". k3sm does not scrape kine's metrics.
func TestDatastoreEndpointSQLiteDefault(t *testing.T) {
	cfg := Config{WorkDir: "/var/lib/k3sm/server", KinePort: 2379}
	args, err := kineArgs(cfg)
	if err != nil {
		t.Fatalf("kineArgs: %v", err)
	}
	// The _kine_disable_startup_vacuum opt-out is part of the shipped DSN — see
	// TestSQLiteEndpointDisablesStartupVacuum for why it is not optional.
	wantEndpoint := "sqlite:///var/lib/k3sm/server/db/state.db?_journal=WAL&_busy_timeout=30000&_kine_disable_startup_vacuum"
	want := []string{"--listen-address", "127.0.0.1:2379", "--metrics-bind-address", "0", "--endpoint", wantEndpoint}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("SQLite kine argv mismatch.\n got %v\nwant %v", args, want)
	}
	// kine's :8080 metrics endpoint must be disabled so it can't squat a pod's port.
	if got := flagValue(args, "--metrics-bind-address"); got != "0" {
		t.Errorf("--metrics-bind-address = %q, want \"0\" (disabled — else kine binds *:8080 and collides with pods)", got)
	}
	// No connection-pool flags leak onto the single-node path.
	for _, absent := range []string{"--datastore-max-open-connections", "--datastore-max-idle-connections", "--datastore-connection-max-lifetime"} {
		if hasArg(args, absent) || flagValue(args, absent) != "" {
			t.Errorf("single-node SQLite path must not carry %s, args=%v", absent, args)
		}
	}
}

// TestKineVersionSinglePin proves there is ONE kine pin, filled regardless of posture,
// and that it is a >=0.16 release (the floor that carries the kine#577
// watch-progress-notify fix and a real pure-Go SQLite backend).
func TestKineVersionSinglePin(t *testing.T) {
	if !strings.HasPrefix(DefaultKineVersion, "v0.") {
		t.Fatalf("DefaultKineVersion = %q, want a v0.x release (the two-pin collapse targets kine >=0.16.x; the orphan v1.14.2 line is retired)", DefaultKineVersion)
	}
	minor := 0
	if _, err := fmt.Sscanf(DefaultKineVersion, "v0.%d.", &minor); err != nil {
		t.Fatalf("DefaultKineVersion = %q: cannot parse a minor version: %v", DefaultKineVersion, err)
	}
	if minor < 16 {
		t.Errorf("DefaultKineVersion = %q, want >= v0.16.x (the kine#577 watch-progress floor)", DefaultKineVersion)
	}

	// withDefaults fills the SAME pin regardless of datastore posture.
	if got := (Config{}).withDefaults().KineVersion; got != DefaultKineVersion {
		t.Errorf("withDefaults SQLite KineVersion = %q, want %q", got, DefaultKineVersion)
	}
	if got := (Config{KineVersion: "v0.99.0"}).withDefaults().KineVersion; got != "v0.99.0" {
		t.Errorf("explicit KineVersion must be honored, got %q", got)
	}
}

// TestDefaultKineVersionIsPinned asserts the exact kine pin. The literal is
// deliberate: every pin bump must touch this test, which is what makes a bump's
// gate red on the old pin and green on the new one. TestKineVersionSinglePin
// checks the pin's shape; this test checks its value.
func TestDefaultKineVersionIsPinned(t *testing.T) {
	const want = "v0.17.2"
	if DefaultKineVersion != want {
		t.Errorf("DefaultKineVersion = %q, want %q", DefaultKineVersion, want)
	}
}

// TestSQLiteEndpointDisablesStartupVacuum pins the DSN opt-out. kine >=0.16 VACUUMs the
// WHOLE database on EVERY startup unless the DSN carries _kine_disable_startup_vacuum;
// the pin k3sm left behind never did. Losing this parameter would put a full-database
// rewrite on the critical path of every `launchctl kickstart`, on the shared APFS volume
// that also holds images, pod dirs, and PV data — silently, and only on real clusters
// large enough to notice.
func TestSQLiteEndpointDisablesStartupVacuum(t *testing.T) {
	dsn := sqliteEndpoint("/var/lib/k3sm/server")
	if !strings.Contains(dsn, "_kine_disable_startup_vacuum") {
		t.Errorf("sqliteEndpoint() = %q, want it to carry _kine_disable_startup_vacuum", dsn)
	}
	// kine detects the flag with strings.Contains over the DSN, so it must survive
	// whole into the rendered argv, not just into this helper.
	args, err := kineArgs(Config{WorkDir: "/var/lib/k3sm/server"}.withDefaults())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "_kine_disable_startup_vacuum") {
		t.Errorf("kineArgs = %v, want the SQLite endpoint to carry _kine_disable_startup_vacuum", args)
	}
	// The WAL + busy-timeout posture is unchanged by the opt-out.
	for _, want := range []string{"_journal=WAL", "_busy_timeout=30000"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("sqliteEndpoint() = %q, want it to keep %s", dsn, want)
		}
	}
}

// TestEtcdRoleMakesIllegalStatesUnrepresentable proves the HA role lives only inside
// Config.Etcd: there is no Config value that asks to join an HA control plane without
// the etcd posture (so no second server can fall back to its own SQLite), the zero
// Config is single-node, and an Etcd block without a valid role is refused.
func TestEtcdRoleMakesIllegalStatesUnrepresentable(t *testing.T) {
	ct := reflect.TypeOf(Config{})
	for _, retired := range []string{"ServerJoin", "DatastoreEndpoint"} {
		if _, ok := ct.FieldByName(retired); ok {
			t.Errorf("Config.%s exists: an HA role or datastore outside Config.Etcd makes join-without-etcd representable", retired)
		}
	}
	if (Config{}).isHA() {
		t.Error("the zero Config must be the single-node posture, not HA")
	}
	if err := (Config{}).Validate(); err != nil {
		t.Errorf("the zero Config must validate, got %v", err)
	}
	cases := []struct {
		name string
		etcd EtcdConfig
		want error
	}{
		{"missing role", EtcdConfig{Name: "n", PeerIP: "192.0.2.10"}, ErrEtcdRole},
		{"unknown role", EtcdConfig{Role: EtcdRole(99), Name: "n", PeerIP: "192.0.2.10"}, ErrEtcdRole},
		{"missing name", EtcdConfig{Role: EtcdJoin, PeerIP: "192.0.2.10"}, ErrEtcdRole},
		{"init", EtcdConfig{Role: EtcdInit, Name: "n", PeerIP: "192.0.2.10"}, nil},
		{"join", EtcdConfig{Role: EtcdJoin, Name: "n", PeerIP: "192.0.2.10"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			etcd := tc.etcd
			cfg := Config{Etcd: &etcd}
			if !cfg.isHA() {
				t.Error("a Config carrying Etcd must be HA")
			}
			err := cfg.Validate()
			if tc.want == nil && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestLeaderElectHAvsSingleNode proves the leader-election posture: --leader-elect is
// false single-node (unchanged) and true in HA (the etcd posture) for BOTH the scheduler and
// the controller-manager, so two servers never both run active schedulers/KCMs. An
// explicit Config.LeaderElect overrides the derivation.
func TestLeaderElectHAvsSingleNode(t *testing.T) {
	single := Config{WorkDir: "/wd"}
	if single.leaderElect() {
		t.Error("single-node leaderElect() must be false")
	}
	if !hasArg(schedulerArgs(single), "--leader-elect=false") {
		t.Errorf("single-node scheduler must carry --leader-elect=false, args=%v", schedulerArgs(single))
	}
	if !hasArg(controllerManagerArgs(single), "--leader-elect=false") {
		t.Errorf("single-node KCM must carry --leader-elect=false, args=%v", controllerManagerArgs(single))
	}

	// The etcd posture is HA in both roles: one active scheduler/KCM across servers.
	for _, role := range []EtcdRole{EtcdInit, EtcdJoin} {
		etcd := Config{WorkDir: "/wd", Etcd: &EtcdConfig{Role: role, Name: "n", PeerIP: "192.0.2.10"}}
		if !etcd.leaderElect() {
			t.Errorf("etcd posture (%v) leaderElect() must be true", role)
		}
		if !hasArg(schedulerArgs(etcd), "--leader-elect=true") || !hasArg(controllerManagerArgs(etcd), "--leader-elect=true") {
			t.Errorf("etcd posture (%v) scheduler and KCM must carry --leader-elect=true", role)
		}
	}

	// An explicit pointer overrides the derivation in both directions.
	on, off := true, false
	if !(Config{LeaderElect: &on}).leaderElect() {
		t.Error("explicit LeaderElect=true must win")
	}
	if (Config{Etcd: &EtcdConfig{Role: EtcdInit, Name: "n", PeerIP: "192.0.2.10"}, LeaderElect: &off}).leaderElect() {
		t.Error("explicit LeaderElect=false must win even in HA")
	}
}
