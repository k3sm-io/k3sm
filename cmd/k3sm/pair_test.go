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
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/bootstrap/pairing"
)

func TestParsePairFlags(t *testing.T) {
	rows := []struct {
		args    []string
		wantErr bool
	}{
		{[]string{"--for", "10m"}, false},
		{[]string{"--for", "10m", "--max-joins", "2"}, false},
		{[]string{"--close"}, false},
		{nil, false},
		{[]string{"--listen", "10m", "--cluster", "abc"}, false},
		{[]string{"--for", "10m", "--close"}, true},
		{[]string{"--cluster", "abc"}, true},
		{[]string{"--for", "10m", "--max-joins", "0"}, true},
	}
	for _, r := range rows {
		if _, err := parsePairFlags(r.args, io.Discard); (err != nil) != r.wantErr {
			t.Errorf("parsePairFlags(%v) err = %v, wantErr %v", r.args, err, r.wantErr)
		}
	}
	if !strings.Contains(pairInstallLine("abc123"), "sudo k3sm install --auto-join --cluster abc123") {
		t.Errorf("install line = %q", pairInstallLine("abc123"))
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	if got := describeWindow(pairing.Window{Until: now.Add(time.Minute), MaxJoins: 1}, true, now); !strings.Contains(got, "open until") {
		t.Errorf("open window = %q", got)
	}
	if got := describeWindow(pairing.Window{Until: now.Add(time.Minute), MaxJoins: 1, Completed: 1}, true, now); !strings.Contains(got, "closed") {
		t.Errorf("full window = %q", got)
	}
}

func TestInstallFlagsAutoJoin(t *testing.T) {
	o, err := parseInstallFlags([]string{"--user", "alice", "--auto-join", "--cluster", "abc"})
	if err != nil {
		t.Fatalf("--auto-join: %v", err)
	}
	if !o.agent || !o.autoJoin || o.arm != pairing.DefaultArm || o.cluster != "abc" {
		t.Fatalf("parsed = %+v", o)
	}
	for _, bad := range [][]string{
		{"--user", "alice", "--auto-join", "--server", "192.0.2.1"},
		{"--user", "alice", "--auto-join", "--token-file", "/tmp/t"},
		{"--user", "alice", "--agent", "--server", "192.0.2.1", "--cluster", "abc"},
		{"--user", "alice", "--auto-join", "--pairing", "10m"},
		{"--user", "alice", "--auto-join", "--arm", "0s"},
	} {
		if _, err := parseInstallFlags(bad); err == nil {
			t.Errorf("parseInstallFlags(%v) accepted", bad)
		}
	}
	if o, err := parseInstallFlags([]string{"--user", "alice", "--pairing", "10m"}); err != nil || o.pairing != 10*time.Minute || o.agent {
		t.Errorf("--pairing on a server = %+v, %v", o, err)
	}
}

type fakeRemover struct {
	removed []string
	version wire.Version
	err     error
}

func (f *fakeRemover) RemoveLink(_ context.Context, iface string) error {
	f.removed = append(f.removed, iface)
	return f.err
}

func (f *fakeRemover) HelperVersion() (wire.Version, bool) { return f.version, true }

func TestReleaseLinks(t *testing.T) {
	hw := func(context.Context) (map[string]int, error) { return map[string]int{"en3": 2, "en2": 1}, nil }
	f := &fakeRemover{version: wire.Version{Major: wire.ProtocolVersionMajor, Minor: wire.MinorDirectLinks}}
	var out strings.Builder
	if err := releaseLinks(context.Background(), f, hw, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.removed, ",") != "en2,en3" {
		t.Fatalf("removed %v, want every Thunderbolt port in order", f.removed)
	}
	old := &fakeRemover{version: wire.Version{Major: wire.ProtocolVersionMajor}}
	out.Reset()
	if err := releaseLinks(context.Background(), old, hw, &out); err != nil || !strings.Contains(out.String(), "predates direct links") {
		t.Fatalf("an old helper: err %v out %q", err, out.String())
	}
	failing := &fakeRemover{version: f.version, err: errors.New("boom")}
	if err := releaseLinks(context.Background(), failing, hw, io.Discard); err == nil || len(failing.removed) != 2 {
		t.Fatalf("a failing release = %v after %v; want the error and every port attempted", err, failing.removed)
	}
}
