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
// ("HA datastore (M6)") for the SPOF + sizing rationale.
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

// sqliteEndpoint is the single-node kine->SQLite WAL DSN. It is BYTE-UNCHANGED from
// M1 (the single-node installed base depends on this exact string); do not reorder
// or reformat the query parameters. The path segment composes on StateDBPath so the
// writer and the `k3sm doctor` probe share one source of the state.db layout — the
// emitted string is byte-identical to the prior hand-joined form.
func sqliteEndpoint(workDir string) string {
	return "sqlite://" + StateDBPath(workDir) + "?_journal=WAL&_busy_timeout=30000"
}

// kineArgs renders kine's argv from cfg. It is a pure function (no I/O) so the
// datastore posture is table-tested without spawning kine.
//
// Empty Config.DatastoreEndpoint -> the single-node SQLite WAL default, argv
// byte-identical to M1 (no connection-pool flags, no out-of-band env). A non-empty
// endpoint -> the operator's Postgres DSN with the PASSWORD STRIPPED (the password
// is relocated out-of-band to PGPASSFILE by kineSecretEnv; it must never reach argv
// or a log) plus the pinned pgx connection-pool bounds.
//
// kine's own datastore flag is --endpoint (k3s wraps it as --datastore-endpoint and
// translates); the scheme of the DSN selects the driver (sqlite:// vs postgres://,
// the latter via jackc/pgx/v5).
func kineArgs(cfg Config) ([]string, error) {
	args := []string{"--listen-address", "127.0.0.1:" + strconv.Itoa(cfg.KinePort)}
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
