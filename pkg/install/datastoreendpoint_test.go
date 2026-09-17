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
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The datastore DSN a test plants where a password must never appear. It is a
// realistic value rather than a placeholder, so a renderer that put it back on
// the argv is caught by its own spelling, and its password is a distinct string
// so a partial leak is caught too.
const (
	theDatastoreDSN      = "postgres://k3sm:sup3r-s3cret-pw@db.example.internal:5432/k3sm?sslmode=require"
	theDatastorePassword = "sup3r-s3cret-pw"
	// A DSN with no password at all: the control case. Nothing here is a
	// credential, so the flag must be left exactly where the operator put it.
	thePasswordlessDSN = "postgres://k3sm@db.example.internal:5432/k3sm?sslmode=require"
)

// stagedEndpointPath spells the staged file's path LITERALLY rather than
// calling the accessor under test, so the test pins the on-disk contract (the
// leaf name inside the server work dir) instead of agreeing with whatever the
// code happens to compute.
func stagedEndpointPath(cfg Config) string {
	return filepath.Join(cfg.withDefaults().serverWorkDir(), "datastore-endpoint")
}

// endpointStagings returns the WriteServiceUserFile calls the install made
// against the staged endpoint path, so a test can assert both that a staging
// happened with the right owner and mode and that one did NOT happen.
func endpointStagings(f *fakeSystem, path string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "WriteServiceUserFile:"+path+":") {
			out = append(out, c)
		}
	}
	return out
}

// TestServerPlistCarriesNoDatastorePassword is the gate for B295: the HA
// datastore DSN must not be on the server LaunchDaemon's argv.
//
// B249 already moved the admin token off that argv and narrowed the plist to
// 0600, but the DSN stayed a VALUE on it — and the plist's mode is only one of
// the three ways an argv is published. `ps` shows a running job's arguments to
// every account on the Mac for the whole life of the daemon, and launchd echoes
// them back from its own job description; neither is affected by the file's
// permissions. So a Postgres password an operator configured was readable by
// any local process. It now reaches the daemon the way the admin token does:
// `k3sm install` stages the DSN in the server work dir, owned by the service
// user at 0600, and renders --datastore-endpoint-file naming that path.
func TestServerPlistCarriesNoDatastorePassword(t *testing.T) {
	t.Run("a credentialed DSN is staged and the argv names only the file", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		dc := cfg.withDefaults()
		path := stagedEndpointPath(cfg)

		// The operator's own edit to the installed plist, the way `PlistBuddy`
		// would make it: the DSN inline, which is the only shape earlier builds
		// could render.
		configureServerArgs(f, cfg, "--mesh-ip", "100.64.0.1", "--datastore-endpoint", theDatastoreDSN)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}

		plist := string(f.files[dc.plistPath(ServerLabel)])
		if plist == "" {
			t.Fatal("no server plist was written")
		}
		if strings.Contains(plist, theDatastorePassword) {
			t.Errorf("the rendered server plist carries the datastore password:\n%s", plist)
		}
		if strings.Contains(plist, theDatastoreDSN) {
			t.Errorf("the rendered server plist carries the inline DSN:\n%s", plist)
		}
		args := serverArgsOf(t, f, cfg)
		if got, want := flagValue(args, "datastore-endpoint-file"), path; got != want {
			t.Errorf("--datastore-endpoint-file = %q, want the staged path %q (argv: %v)", got, want, args)
		}
		if got := flagValue(args, "datastore-endpoint"); got != "" {
			t.Errorf("--datastore-endpoint is still rendered (= %q); the DSN must never reach the argv", got)
		}
		// Everything else the operator configured survives the rewrite.
		if got := flagValue(args, "mesh-ip"); got != "100.64.0.1" {
			t.Errorf("--mesh-ip = %q after the rewrite, want 100.64.0.1 (argv: %v)", got, args)
		}

		// The file itself: service-user-owned 0600 in a 0700 directory, holding
		// the DSN the argv no longer carries.
		want := "WriteServiceUserFile:" + path + ":0600:0700:271"
		if !containsCall(f.calls, want) {
			t.Errorf("install did not stage the DSN as %q (stagings: %v)", want, endpointStagings(f, path))
		}
		if got := strings.TrimSpace(string(f.files[path])); got != theDatastoreDSN {
			t.Errorf("staged DSN = %q, want %q", got, theDatastoreDSN)
		}
		// Staged BEFORE the plist that names it: a daemon pointed at a file
		// nobody has written yet comes up with no datastore at all.
		if idx(f.calls, want) >= idx(f.calls, "WriteLaunchDaemon:"+dc.plistPath(ServerLabel)) {
			t.Error("the DSN must be staged before the plist that names it is written")
		}

		// The record is the OTHER on-disk copy of the argv, and it is what the
		// next install re-renders from, so it must carry the rewritten form.
		rec, ok := f.serverArgs[dc.ServerArgsRecord]
		if !ok {
			t.Fatal("install wrote no server-arguments record")
		}
		if joined := strings.Join(rec.Args, " "); strings.Contains(joined, theDatastorePassword) {
			t.Errorf("the server-arguments record carries the datastore password: %q", joined)
		}
		if got, want := flagValue(rec.Args, "datastore-endpoint-file"), path; got != want {
			t.Errorf("recorded --datastore-endpoint-file = %q, want %q (record: %v)", got, want, rec.Args)
		}
	})

	t.Run("a passwordless DSN is left inline", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		path := stagedEndpointPath(cfg)

		configureServerArgs(f, cfg, "--datastore-endpoint", thePasswordlessDSN)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}

		args := serverArgsOf(t, f, cfg)
		if got := flagValue(args, "datastore-endpoint"); got != thePasswordlessDSN {
			t.Errorf("--datastore-endpoint = %q, want the operator's own %q left alone (argv: %v)", got, thePasswordlessDSN, args)
		}
		if got := flagValue(args, "datastore-endpoint-file"); got != "" {
			t.Errorf("--datastore-endpoint-file = %q; a DSN with no credential in it is not staged", got)
		}
		if calls := endpointStagings(f, path); len(calls) != 0 {
			t.Errorf("install staged a file for a passwordless DSN: %v", calls)
		}
		if _, ok := f.files[path]; ok {
			t.Errorf("install wrote %s for a passwordless DSN", path)
		}
	})

	t.Run("a reinstall carries the file flag and never rewrites the file", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		path := stagedEndpointPath(cfg)

		// The Mac as THIS feature leaves it: the flag names the staged file and
		// the file is there. The DSN is the operator's and k3sm never re-mints
		// it, so a reinstall must carry the flag and leave the bytes alone.
		configureServerArgs(f, cfg, "--datastore-endpoint-file", path)
		f.putFile(path, []byte(theDatastoreDSN+"\n"))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("reinstall: %v", err)
		}

		args := serverArgsOf(t, f, cfg)
		if got := flagValue(args, "datastore-endpoint-file"); got != path {
			t.Errorf("--datastore-endpoint-file = %q, want the carried %q (argv: %v)", got, path, args)
		}
		if calls := endpointStagings(f, path); len(calls) != 0 {
			t.Errorf("the reinstall rewrote the operator's DSN file: %v", calls)
		}
		if got := strings.TrimSpace(string(f.files[path])); got != theDatastoreDSN {
			t.Errorf("staged DSN after the reinstall = %q, want it untouched (%q)", got, theDatastoreDSN)
		}
	})

	t.Run("a carried file flag whose file is gone refuses the install", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		path := stagedEndpointPath(cfg)

		// The flag is carried, the file is not there. Rendering the plist anyway
		// would hand an HA control plane a daemon that falls back to its own
		// single-node SQLite, which is a split datastore nobody is told about.
		configureServerArgs(f, cfg, "--datastore-endpoint-file", path)
		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install succeeded with a --datastore-endpoint-file naming a file that is not there")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the refusal does not name the missing file: %v", err)
		}
	})

	t.Run("a carried file flag naming something that is not a file refuses", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		path := stagedEndpointPath(cfg)

		// A directory (or a fifo, or a device) at the path. The server work dir
		// belongs to the service user, so what wears this name is not
		// automatically what an install put there, and blessing it would render a
		// daemon that reads whatever the path resolves to at start.
		configureServerArgs(f, cfg, "--datastore-endpoint-file", path)
		f.putFile(path, []byte(theDatastoreDSN+"\n"))
		f.putIrregular(path)

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install accepted a --datastore-endpoint-file naming something that is not a regular file")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the refusal does not name the path: %v", err)
		}
	})

	t.Run("an install with no datastore flag stages nothing", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		path := stagedEndpointPath(cfg)

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if calls := endpointStagings(f, path); len(calls) != 0 {
			t.Errorf("a single-node install staged a datastore endpoint file: %v", calls)
		}
		if _, ok := f.files[path]; ok {
			t.Errorf("a single-node install wrote %s", path)
		}
		args := serverArgsOf(t, f, cfg)
		if slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "datastore") }) {
			t.Errorf("a single-node install rendered a datastore flag: %v", args)
		}
	})
}
