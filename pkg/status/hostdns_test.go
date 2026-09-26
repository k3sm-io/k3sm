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

package status

import (
	"errors"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/shadow"
)

// TestHostDNSRows pins the two B243 rows: node-resolver reports whether netd's
// entry is in the host resolver configuration, and shadow-shells compares the
// manifest's source cdhashes with the live host binaries and names the remedy
// (sudo k3sm install) on drift or when the set is missing. Neither row exists
// without its reader, and both are advisory.
func TestHostDNSRows(t *testing.T) {
	t.Parallel()
	const manifest = "/Library/k3sm/shadow/sources.json"
	b, err := shadow.Encode(shadow.Manifest{Version: shadow.ManifestVersion, Sources: []shadow.Source{
		{Name: "bash", Path: "/bin/bash", CDHash: "aa"},
		{Name: "env", Path: "/usr/bin/env", CDHash: "bb"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]string{"/bin/bash": "aa", "/usr/bin/env": "bb"}
	cdhash := func(p string) (string, error) { return live[p], nil }

	const sock = "/var/lib/k3sm/run/netd.sock"
	netdUp := Row{Name: RowNetd, State: StateRunning, Severity: SeverityOK}
	c := Collector{
		FS:    fakeFS{contents: map[string][]byte{manifest: b}, present: map[string]bool{sock: true}},
		Paths: Paths{ShadowManifest: manifest, NetdSocket: sock},
	}
	if _, ok := c.nodeResolverRow(netdUp); ok {
		t.Fatalf("node-resolver row without a reader")
	}
	if _, ok := c.shadowShellsRow(); ok {
		t.Fatalf("shadow-shells row without a cdhash reader")
	}

	c.NodeResolverPresent = func() (bool, error) { return true, nil }
	if r, _ := c.nodeResolverRow(netdUp); r.Severity != SeverityOK || !strings.Contains(r.Detail, "entry published") {
		t.Errorf("present entry row = %+v, want ok", r)
	}
	// The entry outlives its writer in configd: a present entry with netd
	// stopped, or with its socket gone, is a warning, not ok.
	netdDown := Row{Name: RowNetd, State: StateStopped, Severity: SeverityFail}
	if r, _ := c.nodeResolverRow(netdDown); r.Severity != SeverityWarn || r.Remedy != nodeResolverKickstart {
		t.Errorf("present entry, netd stopped row = %+v, want a warn naming the netd kickstart", r)
	}
	noSock := c
	noSock.FS = fakeFS{contents: map[string][]byte{manifest: b}}
	if r, _ := noSock.nodeResolverRow(netdUp); r.Severity != SeverityWarn {
		t.Errorf("present entry, netd socket absent row = %+v, want a warn", r)
	}
	c.NodeResolverPresent = func() (bool, error) { return false, nil }
	if r, _ := c.nodeResolverRow(netdUp); r.Severity != SeverityWarn || r.Remedy != nodeResolverKickstart {
		t.Errorf("absent entry row = %+v, want a warn naming the netd kickstart", r)
	}
	c.NodeResolverPresent = func() (bool, error) { return false, errors.New("configd down") }
	if r, _ := c.nodeResolverRow(netdUp); r.Severity != SeverityUnknown {
		t.Errorf("unreadable entry row = %+v, want unknown", r)
	}

	c.CDHash = cdhash
	if r, _ := c.shadowShellsRow(); r.Severity != SeverityOK || r.Remedy != "" {
		t.Errorf("matching set row = %+v, want ok and no remedy", r)
	}
	live["/bin/bash"] = "cc"
	r, _ := c.shadowShellsRow()
	if r.State != StateDrift || r.Remedy != "sudo k3sm install" || !strings.Contains(r.Detail, "/bin/bash") || strings.Contains(r.Detail, "/usr/bin/env") {
		t.Errorf("drifted set row = %+v, want drift naming /bin/bash only, remedy sudo k3sm install", r)
	}
	c.FS = fakeFS{}
	if r, _ := c.shadowShellsRow(); r.State != StateMissing || r.Remedy != "sudo k3sm install" {
		t.Errorf("missing manifest row = %+v, want missing with the install remedy", r)
	}
	for _, name := range []string{RowNodeResolver, RowShadowShells} {
		if !advisory("", name) {
			t.Errorf("%s is not advisory", name)
		}
	}
}
