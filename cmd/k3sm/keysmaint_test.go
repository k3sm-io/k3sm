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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// keysAttrRecorder is a file-attribute writer that records each call.
type keysAttrRecorder struct{ calls []string }

func (r *keysAttrRecorder) Fchown(int, int, int) error {
	r.calls = append(r.calls, "fchown")
	return nil
}

func (r *keysAttrRecorder) Fchmod(int, uint32) error {
	r.calls = append(r.calls, "fchmod")
	return nil
}

func (r *keysAttrRecorder) Fchflags(int, int) error {
	r.calls = append(r.calls, "fchflags")
	return nil
}

// floor --rebuild and rm-scope: usage and a non-root caller are refused
// before the store opens; floor --rebuild acts through the file-attribute
// writer the verb is given and writes its audit line as floor-rebuild, via
// root; rm-scope refuses an absent scope, audited as refused.
func TestKeysMaintenanceVerbs(t *testing.T) {
	h := newKeysHarness(t)
	var lines []string
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	rec := &keysAttrRecorder{}
	h.attrs = rec
	h.stdin = bytes.NewReader([]byte("tok"))
	h.mustRun(keysOK, "put", "system/api-token", "--in", "-")

	for _, tc := range []struct {
		args []string
		euid int
		code int
	}{
		{[]string{"floor"}, 0, keysBadUsage},
		{[]string{"floor", "--rebuild", "extra"}, 0, keysBadUsage},
		{[]string{"floor", "--rebuild"}, 501, keysRefused},
		{[]string{"rm-scope", "user/1001"}, 0, keysBadUsage},
		{[]string{"rm-scope", "user/01001", "--yes"}, 0, keysBadUsage},
		{[]string{"rm-scope", "system/x", "--yes"}, 0, keysBadUsage},
		{[]string{"rm-scope", "user/1001", "--yes"}, 501, keysRefused},
	} {
		lines = nil
		h.euid = tc.euid
		h.mustRun(tc.code, tc.args...)
		if len(lines) != 0 {
			t.Errorf("keys %v asked for audit lines %q before opening the store", tc.args, lines)
		}
	}

	h.euid = 0
	floor := filepath.Join(h.cfg.DataRoot, "keystore-user-floor.log")
	if err := os.WriteFile(floor, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lines = nil
	h.mustRun(keysOK, "floor", "--rebuild")
	if !strings.Contains(h.stdout.String(), "rebuilt the user-scope floor: 0 scopes, 0 keys") {
		t.Errorf("floor --rebuild printed %q", h.stdout.String())
	}
	if !slices.Equal(lines, []string{"floor-rebuild  ok"}) {
		t.Errorf("floor --rebuild audit lines %q", lines)
	}
	if !slices.Contains(rec.calls, "fchflags") {
		t.Errorf("floor --rebuild did not act through the writer it was given: %q", rec.calls)
	}
	lines = nil
	h.mustRun(keysRefused, "rm-scope", "user/1001", "--yes")
	if !slices.Equal(lines, []string{"rm-scope  refused"}) {
		t.Errorf("rm-scope audit lines %q", lines)
	}
}
