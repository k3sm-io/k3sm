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
	"fmt"
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

// TestShadowShellsRowAgainstTheList pins the shadow-shells row against the
// shared list: each source's cdhash is read once however many copies share
// it; drift names at most three paths and counts the rest; a manifest missing
// copies of the current list (an older install) is drift with the install
// remedy; and a source this host lacks is never expected.
func TestShadowShellsRowAgainstTheList(t *testing.T) {
	t.Parallel()
	const manifest = "/Library/k3sm/shadow/sources.json"
	all := shadow.Copies()
	full := make([]shadow.Source, 0, len(all))
	present := map[string]bool{}
	paths := map[string]bool{}
	for _, c := range all {
		full = append(full, shadow.Source{Name: c.Name, Path: c.Source, CDHash: "h"})
		present[c.Source] = true
		paths[c.Source] = true
	}
	encode := func(src []shadow.Source) []byte {
		b, err := shadow.Encode(shadow.Manifest{Version: shadow.ManifestVersion, Sources: src})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	collector := func(src []shadow.Source, present map[string]bool, cdhash func(string) (string, error)) Collector {
		return Collector{
			FS:     fakeFS{contents: map[string][]byte{manifest: encode(src)}, present: present},
			Paths:  Paths{ShadowManifest: manifest},
			CDHash: cdhash,
		}
	}

	t.Run("a current set is ok and reads each source once", func(t *testing.T) {
		t.Parallel()
		dup := append(append([]shadow.Source(nil), full...), shadow.Source{Name: "extra", Path: full[0].Path, CDHash: "h"})
		reads := map[string]int{}
		r, _ := collector(dup, present, func(p string) (string, error) { reads[p]++; return "h", nil }).shadowShellsRow()
		if r.State != StateOK || r.Remedy != "" {
			t.Errorf("row = %+v, want ok", r)
		}
		for p, n := range reads {
			if n != 1 {
				t.Errorf("%s read %d times, want once", p, n)
			}
		}
		if len(reads) != len(paths) {
			t.Errorf("read %d sources, want %d", len(reads), len(paths))
		}
	})

	t.Run("drift names three paths and counts the rest", func(t *testing.T) {
		t.Parallel()
		r, _ := collector(full, present, func(string) (string, error) { return "new", nil }).shadowShellsRow()
		want := fmt.Sprintf("%d of %d host binaries changed since the last install", len(paths), len(paths))
		more := fmt.Sprintf("and %d more", len(paths)-3)
		if r.State != StateDrift || r.Remedy != "sudo k3sm install" || !strings.Contains(r.Detail, want) ||
			!strings.Contains(r.Detail, more) || !strings.Contains(r.Detail, full[2].Path) || strings.Contains(r.Detail, full[3].Path+",") {
			t.Errorf("row = %+v, want drift %q listing three paths %q", r, want, more)
		}
	})

	t.Run("a set from an older install is drift", func(t *testing.T) {
		t.Parallel()
		r, _ := collector(full[:4], present, func(string) (string, error) { return "h", nil }).shadowShellsRow()
		want := fmt.Sprintf("the shadow set is from an older install (4 of %d copies)", len(all))
		if r.State != StateDrift || r.Severity != SeverityWarn || r.Remedy != "sudo k3sm install" || !strings.Contains(r.Detail, want) {
			t.Errorf("row = %+v, want drift %q", r, want)
		}
	})

	t.Run("a source this host lacks is not expected", func(t *testing.T) {
		t.Parallel()
		var kept []shadow.Source
		lacking := map[string]bool{}
		for p := range present {
			lacking[p] = true
		}
		delete(lacking, "/bin/dash")
		for _, s := range full {
			if s.Path != "/bin/dash" {
				kept = append(kept, s)
			}
		}
		r, _ := collector(kept, lacking, func(string) (string, error) { return "h", nil }).shadowShellsRow()
		if r.State != StateOK {
			t.Errorf("row = %+v, want ok (the installer skipped the absent source)", r)
		}
	})
}
