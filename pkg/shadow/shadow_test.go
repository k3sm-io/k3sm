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

package shadow

import (
	"errors"
	"reflect"
	"testing"
)

// TestManifestRoundTripAndDrift pins the manifest the installer writes and the
// status row reads: it round-trips, refuses an unknown version, parses the
// CDHash line out of real codesign output, and reports a changed or unreadable
// source as drift.
func TestManifestRoundTripAndDrift(t *testing.T) {
	t.Parallel()
	m := Manifest{Version: ManifestVersion, Sources: []Source{
		{Name: "bash", Path: "/bin/bash", CDHash: "aa"},
		{Name: "env", Path: "/usr/bin/env", CDHash: "bb"},
	}}
	b, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(b)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("Decode = %+v, %v, want %+v", got, err, m)
	}
	if _, err := Decode([]byte(`{"version":9,"sources":[]}`)); err == nil {
		t.Fatalf("Decode accepted an unknown version")
	}

	out := []byte("Identifier=com.apple.bash\nCandidateCDHash sha256=e71e\nCDHash=E71EBF5018702DD8CED80C32718437B6A4D8F9D5\nTeamIdentifier=not set\n")
	if h, err := ParseCDHash(out); err != nil || h != "e71ebf5018702dd8ced80c32718437b6a4d8f9d5" {
		t.Fatalf("ParseCDHash = %q, %v", h, err)
	}
	if _, err := ParseCDHash([]byte("code object is not signed at all\n")); !errors.Is(err, ErrNoCDHash) {
		t.Fatalf("ParseCDHash(unsigned) err = %v, want ErrNoCDHash", err)
	}

	live := map[string]string{"/bin/bash": "aa", "/usr/bin/env": "cc"}
	d := Drift(m, func(p string) (string, error) { return live[p], nil })
	if len(d) != 1 || d[0].Source.Name != "env" || d[0].Live != "cc" {
		t.Fatalf("Drift = %+v, want env only", d)
	}
	gone := errors.New("no such file")
	d = Drift(m, func(string) (string, error) { return "", gone })
	if len(d) != 2 || !errors.Is(d[0].Err, gone) {
		t.Fatalf("Drift(unreadable) = %+v, want both with the read error", d)
	}
}
