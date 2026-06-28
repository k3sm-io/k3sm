package executor

import (
	"strconv"
	"strings"
	"testing"
)

// TestDatastoreEndpointSQLiteDefault proves the single-node path is BYTE-UNCHANGED
// (the M1–M5 golden behavior): an empty Config.DatastoreEndpoint renders kine's argv
// as exactly [--listen-address 127.0.0.1:<port> --endpoint sqlite://…WAL…], with NO
// connection-pool flags and NO out-of-band secret env.
func TestDatastoreEndpointSQLiteDefault(t *testing.T) {
	cfg := Config{WorkDir: "/var/lib/k3sm/server", KinePort: 2379}
	args, err := kineArgs(cfg)
	if err != nil {
		t.Fatalf("kineArgs: %v", err)
	}
	wantEndpoint := "sqlite:///var/lib/k3sm/server/db/state.db?_journal=WAL&_busy_timeout=30000"
	want := []string{"--listen-address", "127.0.0.1:2379", "--endpoint", wantEndpoint}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("SQLite kine argv must be byte-unchanged.\n got %v\nwant %v", args, want)
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

// TestKineVersionPostureAware proves the deferred bump-vs-soak decision: the SQLite
// single-node path stays on v1.14.2 (unchanged), while a Postgres datastore endpoint
// moves kine to the pinned >=0.15 release (DefaultKineVersionHA, with the kine#577
// watch-progress fix). An explicit KineVersion is honored either way.
func TestKineVersionPostureAware(t *testing.T) {
	if got := defaultKineVersion(""); got != DefaultKineVersion {
		t.Errorf("SQLite path kine version = %q, want %q", got, DefaultKineVersion)
	}
	if got := defaultKineVersion("postgres://k3sm@db/k3sm"); got != DefaultKineVersionHA {
		t.Errorf("Postgres path kine version = %q, want %q", got, DefaultKineVersionHA)
	}
	// The single-node default const must NOT have drifted off the M0-validated pin.
	if DefaultKineVersion != "v1.14.2" {
		t.Errorf("DefaultKineVersion = %q, want v1.14.2 (single-node installed base must not migrate)", DefaultKineVersion)
	}
	// The HA pin must be a real, distinct version (a >=0.15 release per the DESIGN
	// floor — the exact value is go-install-verified and documented on the const).
	if !strings.HasPrefix(DefaultKineVersionHA, "v") || DefaultKineVersionHA == DefaultKineVersion {
		t.Errorf("DefaultKineVersionHA = %q, want a real version distinct from the SQLite pin %q", DefaultKineVersionHA, DefaultKineVersion)
	}

	// withDefaults wires the posture: an empty KineVersion fills from the datastore.
	if got := (Config{}).withDefaults().KineVersion; got != DefaultKineVersion {
		t.Errorf("withDefaults SQLite KineVersion = %q, want %q", got, DefaultKineVersion)
	}
	if got := (Config{DatastoreEndpoint: "postgres://k3sm@db/k3sm"}).withDefaults().KineVersion; got != DefaultKineVersionHA {
		t.Errorf("withDefaults Postgres KineVersion = %q, want %q", got, DefaultKineVersionHA)
	}
	if got := (Config{KineVersion: "v0.99.0", DatastoreEndpoint: "postgres://k3sm@db/k3sm"}).withDefaults().KineVersion; got != "v0.99.0" {
		t.Errorf("explicit KineVersion must be honored, got %q", got)
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
