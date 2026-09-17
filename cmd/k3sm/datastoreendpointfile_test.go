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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestServerDatastoreEndpointFile pins how `k3sm server` is given its HA
// datastore DSN by file — the datastore half of TestServerTokenFile, and the
// daemon's side of the installer staging that keeps a Postgres password off the
// argv `ps` publishes to every account on the Mac.
//
// The one place its contract deliberately differs from the token file's is
// absence: a missing token file is a posture (the executor mints one), while a
// missing DSN file is TERMINAL, because an empty endpoint means the single-node
// SQLite datastore and an HA server that quietly came up on its own datastore
// is a split cluster nobody is told about.
func TestServerDatastoreEndpointFile(t *testing.T) {
	const dsn = "postgres://k3sm:sup3r-s3cret-pw@db.example.internal:5432/k3sm?sslmode=require"

	writeMode := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "datastore-endpoint")
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		// WriteFile applies the umask, so the mode is set explicitly.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
		return path
	}
	write := func(t *testing.T, content string) string {
		t.Helper()
		return writeMode(t, content, 0o600)
	}

	t.Run("the flag is registered", func(t *testing.T) {
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		var opts serverOptions
		_ = registerServerFlags(fs, &opts)
		if fs.Lookup("datastore-endpoint-file") == nil {
			t.Fatal("`k3sm server` has no --datastore-endpoint-file flag")
		}
		if err := fs.Parse([]string{"--datastore-endpoint-file", "/var/lib/k3sm/server/datastore-endpoint"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.datastoreEndpointFile != "/var/lib/k3sm/server/datastore-endpoint" {
			t.Errorf("datastoreEndpointFile = %q, want the path", opts.datastoreEndpointFile)
		}
	})

	t.Run("the file supplies the DSN", func(t *testing.T) {
		// The trailing newline is what the installer writes; the reader trims it,
		// exactly as the token reader does.
		got, err := resolveDatastoreEndpoint("", write(t, dsn+"\n"))
		if err != nil {
			t.Fatalf("resolveDatastoreEndpoint: %v", err)
		}
		if got != dsn {
			t.Errorf("DSN = %q, want %q", got, dsn)
		}
	})

	t.Run("no file leaves the inline flag alone", func(t *testing.T) {
		got, err := resolveDatastoreEndpoint(dsn, "")
		if err != nil {
			t.Fatalf("resolveDatastoreEndpoint: %v", err)
		}
		if got != dsn {
			t.Errorf("DSN = %q, want the inline %q (direct invocation still takes it)", got, dsn)
		}
		// And neither flag is the single-node default, which must stay empty.
		if got, err := resolveDatastoreEndpoint("", ""); err != nil || got != "" {
			t.Errorf("resolveDatastoreEndpoint(\"\", \"\") = (%q, %v), want (\"\", nil) — the single-node default", got, err)
		}
	})

	t.Run("a missing file is a start error naming the path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "datastore-endpoint")
		_, err := resolveDatastoreEndpoint("", path)
		if err == nil {
			t.Fatal("a --datastore-endpoint-file that is not there was accepted; an HA server must never fall back to the single-node datastore")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the error does not name the file: %v", err)
		}
	})

	t.Run("an empty file is a start error", func(t *testing.T) {
		path := write(t, "  \n")
		if _, err := resolveDatastoreEndpoint("", path); err == nil {
			t.Fatal("an empty --datastore-endpoint-file was accepted as an empty DSN")
		}
	})

	// The mode refusal is what makes "the DSN is in a file" an improvement over
	// the argv rather than a relocation: a file the group or other accounts can
	// read is the same password shared with the same people, just from a
	// different place. It is the mask the join token file is judged by.
	t.Run("a file others can read is refused", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o640, 0o644} {
			t.Run(mode.String(), func(t *testing.T) {
				path := writeMode(t, dsn+"\n", mode)
				_, err := resolveDatastoreEndpoint("", path)
				if err == nil {
					t.Fatalf("a mode %#o datastore endpoint file was accepted", mode)
				}
				if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "chmod 600") {
					t.Errorf("the refusal must name the file and the mode to put it at: %v", err)
				}
			})
		}
	})

	t.Run("a 0600 file is accepted", func(t *testing.T) {
		got, err := resolveDatastoreEndpoint("", writeMode(t, dsn+"\n", 0o600))
		if err != nil {
			t.Fatalf("a mode 0600 datastore endpoint file was refused: %v", err)
		}
		if got != dsn {
			t.Errorf("DSN = %q, want %q", got, dsn)
		}
	})

	t.Run("both flags are refused", func(t *testing.T) {
		path := write(t, dsn+"\n")
		_, err := resolveDatastoreEndpoint(dsn, path)
		if err == nil {
			t.Fatal("--datastore-endpoint and --datastore-endpoint-file were accepted together")
		}
		// The env variable fills --datastore-endpoint by default, so the refusal
		// has to say so or an operator reads it as impossible.
		if !strings.Contains(err.Error(), "K3SM_DATASTORE_ENDPOINT") {
			t.Errorf("the refusal does not mention the environment default: %v", err)
		}
	})
}
