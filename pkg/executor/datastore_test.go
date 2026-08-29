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
	"fmt"
	"strconv"
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
	// No Postgres pool flags leak onto the single-node path.
	for _, absent := range []string{"--datastore-max-open-connections", "--datastore-max-idle-connections", "--datastore-connection-max-lifetime"} {
		if hasArg(args, absent) || flagValue(args, absent) != "" {
			t.Errorf("single-node SQLite path must not carry %s, args=%v", absent, args)
		}
	}
	// No password file is produced for the SQLite path.
	if _, pw, err := splitDatastorePassword(""); err != nil || pw != "" {
		t.Errorf("splitDatastorePassword(\"\") = (_, %q, %v), want empty", pw, err)
	}
}

// TestDatastoreEndpointPostgres proves the HA path: a Postgres DSN reaches kine's
// --endpoint with the host/user/db intact but the PASSWORD STRIPPED (no secret on
// argv), and the pinned pgx connection-pool bounds are present.
func TestDatastoreEndpointPostgres(t *testing.T) {
	const (
		password = "s3cr3t-p@ss"
		dsn      = "postgres://k3sm:s3cr3t-p%40ss@db.internal:5432/k3sm?sslmode=verify-full"
	)
	cfg := Config{WorkDir: "/wd", KinePort: 2379, DatastoreEndpoint: dsn}
	args, err := kineArgs(cfg)
	if err != nil {
		t.Fatalf("kineArgs: %v", err)
	}
	joined := strings.Join(args, " ")

	// The secret must NOT appear anywhere on argv (neither the literal nor the
	// percent-encoded form).
	if strings.Contains(joined, password) || strings.Contains(joined, "s3cr3t-p%40ss") {
		t.Fatalf("Postgres password leaked onto kine argv: %v", args)
	}
	endpoint := flagValue(args, "--endpoint")
	if !strings.Contains(endpoint, "db.internal:5432") {
		t.Errorf("--endpoint = %q, want it to carry the Postgres host", endpoint)
	}
	if !strings.Contains(endpoint, "k3sm@") || strings.Contains(endpoint, ":s3cr3t") {
		t.Errorf("--endpoint = %q, want the username kept but the password removed", endpoint)
	}
	if !strings.Contains(endpoint, "sslmode=verify-full") {
		t.Errorf("--endpoint = %q, want the sslmode query parameter preserved", endpoint)
	}

	// The pgx connection-pool bounds are pinned (kine's own default is UNLIMITED).
	if got := flagValue(args, "--datastore-max-open-connections"); got != strconv.Itoa(datastoreMaxOpenConns) {
		t.Errorf("--datastore-max-open-connections = %q, want %d", got, datastoreMaxOpenConns)
	}
	if got := flagValue(args, "--datastore-max-idle-connections"); got != strconv.Itoa(datastoreMaxIdleConns) {
		t.Errorf("--datastore-max-idle-connections = %q, want %d", got, datastoreMaxIdleConns)
	}
	if got := flagValue(args, "--datastore-connection-max-lifetime"); got != datastoreConnMaxLifetime {
		t.Errorf("--datastore-connection-max-lifetime = %q, want %q", got, datastoreConnMaxLifetime)
	}
	// The HA path disables kine's :8080 metrics endpoint too (same pod-port-collision reason).
	if got := flagValue(args, "--metrics-bind-address"); got != "0" {
		t.Errorf("--metrics-bind-address = %q, want \"0\" (disabled)", got)
	}
	// 2*maxOpen must fit a documented Postgres max_connections (default 100) so two HA
	// servers do not exhaust it.
	if 2*datastoreMaxOpenConns > 100 {
		t.Errorf("2*datastoreMaxOpenConns = %d exceeds the Postgres default max_connections (100)", 2*datastoreMaxOpenConns)
	}
}

// TestDatastorePasswordRelocation proves the secret-handling primitive end-to-end:
// the password is extracted from the DSN, the sanitized DSN keeps the username but
// not the password, and the .pgpass line escapes the pgpass metacharacters so pgx
// reads the literal password back.
func TestDatastorePasswordRelocation(t *testing.T) {
	cases := []struct {
		name     string
		dsn      string
		wantPass string
		wantUser bool // sanitized DSN keeps a username
	}{
		{"user+password", "postgres://k3sm:hunter2@h:5432/db", "hunter2", true},
		{"password with metachars", "postgres://u:a%3Ab%5Cc@h/db", "a:b\\c", true},
		{"no password (env-supplied)", "postgres://k3sm@h/db", "", true},
		{"no userinfo", "postgres://h/db", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized, pass, err := splitDatastorePassword(tc.dsn)
			if err != nil {
				t.Fatalf("splitDatastorePassword(%q): %v", tc.dsn, err)
			}
			if pass != tc.wantPass {
				t.Errorf("password = %q, want %q", pass, tc.wantPass)
			}
			if pass != "" && strings.Contains(sanitized, pass) {
				t.Errorf("sanitized DSN %q must not contain the password", sanitized)
			}
			if tc.wantUser && !strings.Contains(sanitized, "@") {
				t.Errorf("sanitized DSN %q must keep the username", sanitized)
			}
			// The .pgpass line escapes ':' and '\' and wildcards the match fields.
			if tc.wantPass != "" {
				line := pgPassLine(pass)
				if !strings.HasPrefix(line, "*:*:*:*:") || !strings.HasSuffix(line, "\n") {
					t.Errorf("pgPassLine = %q, want *:*:*:*:<escaped>\\n", line)
				}
				if strings.Contains(tc.wantPass, ":") && !strings.Contains(line, `\:`) {
					t.Errorf("pgPassLine = %q must escape ':' in the password", line)
				}
			}
		})
	}
}

// TestKineVersionSinglePin proves the collapse: there is ONE kine pin, it serves both
// datastore postures, and it is a >=0.16 release (the floor that carries the kine#577
// watch-progress-notify fix and a real pure-Go SQLite backend). The old two-pin split
// — v1.14.2 for SQLite, a separate HA-only constant for Postgres — is gone, so a
// re-introduced second pin cannot compile past this test.
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
	if got := (Config{DatastoreEndpoint: "postgres://k3sm@db/k3sm"}).withDefaults().KineVersion; got != DefaultKineVersion {
		t.Errorf("withDefaults Postgres KineVersion = %q, want %q (one pin, both postures)", got, DefaultKineVersion)
	}
	if got := (Config{KineVersion: "v0.99.0", DatastoreEndpoint: "postgres://k3sm@db/k3sm"}).withDefaults().KineVersion; got != "v0.99.0" {
		t.Errorf("explicit KineVersion must be honored, got %q", got)
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

// TestHARequiresDatastoreEndpoint proves the split-brain guard is fail-closed: a
// server that declares HA intent (ServerJoin) WITHOUT a datastore endpoint is
// REJECTED (ErrHARequiresDatastore) rather than silently falling back to its own
// SQLite — two servers each on their own SQLite is split-brain. The single-node path
// (no HA intent) and the HA-with-endpoint path both validate clean.
func TestHARequiresDatastoreEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"single-node (no HA intent)", Config{}, false},
		{"HA intent, no datastore -> SPLIT-BRAIN", Config{ServerJoin: true}, true},
		{"HA intent + datastore", Config{ServerJoin: true, DatastoreEndpoint: "postgres://k3sm@db/k3sm"}, false},
		{"datastore only (single server on Postgres)", Config{DatastoreEndpoint: "postgres://k3sm@db/k3sm"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatal("Validate must REJECT HA intent without a datastore endpoint (split-brain)")
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: unexpected error %v", err)
			}
		})
	}
}

// TestLeaderElectHAvsSingleNode proves the leader-election posture: --leader-elect is
// false single-node (unchanged) and true in HA (Postgres) for BOTH the scheduler and
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

	ha := Config{WorkDir: "/wd", DatastoreEndpoint: "postgres://k3sm@db/k3sm"}
	if !ha.leaderElect() {
		t.Error("HA (Postgres) leaderElect() must be true")
	}
	if !hasArg(schedulerArgs(ha), "--leader-elect=true") {
		t.Errorf("HA scheduler must carry --leader-elect=true, args=%v", schedulerArgs(ha))
	}
	if !hasArg(controllerManagerArgs(ha), "--leader-elect=true") {
		t.Errorf("HA KCM must carry --leader-elect=true, args=%v", controllerManagerArgs(ha))
	}

	// ServerJoin (HA intent) also turns it on.
	if !(Config{ServerJoin: true, DatastoreEndpoint: "postgres://k3sm@db/k3sm"}).leaderElect() {
		t.Error("ServerJoin HA leaderElect() must be true")
	}

	// An explicit pointer overrides the derivation in both directions.
	on, off := true, false
	if !(Config{LeaderElect: &on}).leaderElect() {
		t.Error("explicit LeaderElect=true must win")
	}
	if (Config{DatastoreEndpoint: "postgres://k3sm@db/k3sm", LeaderElect: &off}).leaderElect() {
		t.Error("explicit LeaderElect=false must win even in HA")
	}
}
