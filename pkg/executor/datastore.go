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
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// Postgres connection-pool bounds for the HA datastore path (kine's pgx pool).
// kine's OWN defaults are dangerous for a multi-writer cluster: --datastore-max-
// open-connections defaults to 0 (UNLIMITED), so N control-plane servers sharing one
// Postgres can exhaust its max_connections. We pin per-server bounds so the cluster
// total stays within a documented Postgres max_connections. See the package doc
// ("HA datastore") for the SPOF + sizing rationale.
const (
	// datastoreMaxOpenConns bounds kine's Postgres connections PER SERVER. With 2 HA
	// servers that is 2*32 = 64 <= 100 (the Postgres default max_connections), leaving
	// headroom for the operator's psql/pg_dump/monitoring sessions. For >2 servers the
	// operator must raise Postgres max_connections (or lower this) so 2*pool still fits.
	datastoreMaxOpenConns = 32
	// datastoreMaxIdleConns keeps a warm subset (<= max-open) so steady watch/list
	// load does not pay a reconnect per request.
	datastoreMaxIdleConns = 8
	// datastoreConnMaxLifetime recycles a connection after this long so a failed-over
	// Postgres / connection-pooler (pgbouncer) endpoint is picked up and no connection
	// is pinned indefinitely. Rendered as a Go duration (kine's flag is a DurationFlag).
	datastoreConnMaxLifetime = "30m"
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
// datastore posture is table-tested without spawning kine.
//
// Empty Config.DatastoreEndpoint -> the single-node SQLite WAL default, argv
// byte-identical to the pre-HA shape (no connection-pool flags, no out-of-band
// env). A non-empty
// endpoint -> the operator's Postgres DSN with the PASSWORD STRIPPED (the password
// is relocated out-of-band to PGPASSFILE by kineSecretEnv; it must never reach argv
// or a log) plus the pinned pgx connection-pool bounds.
//
// kine's own datastore flag is --endpoint (k3s wraps it as --datastore-endpoint and
// translates); the scheme of the DSN selects the driver (sqlite:// vs postgres://,
// the latter via jackc/pgx/v5).
func kineArgs(cfg Config) ([]string, error) {
	// Disable kine's Prometheus metrics endpoint. It defaults to :8080 on ALL
	// interfaces (kine v1.14.2 app.go: "set 0 to disable metrics serving"), and
	// because k3sm pods share the host network (no netns), that listener collides
	// with any workload binding :8080 — e.g. a readiness probe server — failing it
	// with "bind: address already in use". k3sm does not scrape kine's metrics; a
	// later need would bind them to a chosen localhost port, never all-interfaces :8080.
	args := []string{
		"--listen-address", "127.0.0.1:" + strconv.Itoa(cfg.KinePort),
		"--metrics-bind-address", "0",
	}
	if cfg.DatastoreEndpoint == "" {
		return append(args, "--endpoint", sqliteEndpoint(cfg.WorkDir)), nil
	}
	onArgv, _, err := splitDatastorePassword(cfg.DatastoreEndpoint)
	if err != nil {
		return nil, err
	}
	args = append(args,
		"--endpoint", onArgv,
		"--datastore-max-open-connections", strconv.Itoa(datastoreMaxOpenConns),
		"--datastore-max-idle-connections", strconv.Itoa(datastoreMaxIdleConns),
		"--datastore-connection-max-lifetime", datastoreConnMaxLifetime,
	)
	return args, nil
}

// splitDatastorePassword parses a datastore DSN (the URL form kine expects:
// scheme://user[:password]@host[:port]/db?params) and returns (a) the DSN with the
// password removed (safe to place on argv or in a log) and (b) the extracted
// password (relocated out-of-band to PGPASSFILE). A DSN with no userinfo, or no
// password in the userinfo, is returned unchanged with an empty password (the
// operator is supplying the password by another means — PGPASSWORD/PGPASSFILE/trust).
func splitDatastorePassword(dsn string) (sanitized, password string, err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", "", fmt.Errorf("parse datastore endpoint: %w", err)
	}
	if u.User == nil {
		return dsn, "", nil
	}
	pw, ok := u.User.Password()
	if !ok {
		return dsn, "", nil
	}
	// Keep the username on argv (pgx needs it to know which Postgres role to
	// authenticate, and the PGPASSFILE wildcard matches any user); drop the password.
	u.User = url.User(u.User.Username())
	return u.String(), pw, nil
}

// pgPassPath is the 0600 libpq/pgx password file the kine child reads via the
// PGPASSFILE env var. It lives in the work-dir alongside the other 0600 secrets.
func pgPassPath(workDir string) string { return filepath.Join(workDir, ".pgpass") }

// pgPassLine renders a libpq/pgx .pgpass entry that supplies password for ANY
// host/port/database/user (wildcards in the first four fields), escaping the two
// pgpass metacharacters ('\' and ':'). pgx (jackc/pgpassfile) and libpq both
// un-escape these. A trailing newline terminates the single-line file.
func pgPassLine(password string) string {
	esc := strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(password)
	return "*:*:*:*:" + esc + "\n"
}

// datastorePosture names the datastore backing this server for logging: "sqlite" for
// the single-node WAL default, "postgres" for the HA multi-writer endpoint. It reads
// only the posture, never the DSN (which carries a password).
func datastorePosture(cfg Config) string {
	if cfg.DatastoreEndpoint == "" {
		return "sqlite"
	}
	return "postgres"
}
