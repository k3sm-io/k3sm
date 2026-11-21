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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/netdsvc"
)

// removeFailingSystem refuses to remove one path, as a read-only or wedged key
// dir would, and leaves every other removal to the fake.
type removeFailingSystem struct {
	*fakeSystem
	path string
}

func (s removeFailingSystem) RemoveAll(path string) error {
	if path == s.path {
		s.calls = append(s.calls, "RemoveAll:"+path)
		return fmt.Errorf("remove %s: operation not permitted", path)
	}
	return s.fakeSystem.RemoveAll(path)
}

// TestInstallRetiresARecordedPodRangeTheSeedNoLongerNames pins the one place an
// install touches the identity file netd records.
//
// A restarting netd believes that file over its --node-pod-cidr flag, so a server
// reinstalled with a new --mesh-ip would come back on the old /24 and be refused
// the alias of its new address, at every start. The file has to go when it names
// another range than the one this install seeds, and only then: on an ordinary
// reinstall it is the record of the range the node is on, and a worker's file is
// the only place its range is written down at all.
func TestInstallRetiresARecordedPodRangeTheSeedNoLongerNames(t *testing.T) {
	identity := netdsvc.NodeIdentityPath(MeshKeyDir)
	sweep := func(index int) string {
		return fmt.Sprintf("FlushInterconnectAliases:%s:%d", netdsvc.InterconnectStatePath(MeshKeyDir), index)
	}

	for _, tc := range []struct {
		name string
		// file is the identity file's content, or "" for none.
		file string
		// flagMeshIP is this install's --mesh-ip, carriedMeshIP the one the
		// server-arguments record carries from the previous install.
		flagMeshIP, carriedMeshIP string
		worker                    bool
		wantRemoved               bool
		// wantSweep is the node index swept, meaningful with wantRemoved.
		wantSweep int
	}{
		{
			name: "a new --mesh-ip retires the old range", file: "100.64.2.0/24\n",
			flagMeshIP: "100.64.1.1", carriedMeshIP: "100.64.2.1",
			wantRemoved: true, wantSweep: 2,
		},
		{
			// The plist already seeds the new range after an install that failed
			// between the two, or after an uninstall that kept the file to finish a
			// failed sweep. Only the file itself still says what it holds.
			name: "a carried --mesh-ip the file disagrees with retires it", file: "100.64.2.0/24\n",
			carriedMeshIP: "100.64.1.1",
			wantRemoved:   true, wantSweep: 2,
		},
		{
			name: "a reinstall with the same --mesh-ip keeps the file", file: "100.64.1.0/24\n",
			flagMeshIP: "100.64.1.1", carriedMeshIP: "100.64.1.1",
		},
		{
			name: "a reinstall carrying its --mesh-ip keeps the file", file: "100.64.1.0/24\n",
			carriedMeshIP: "100.64.1.1",
		},
		{name: "a first install has nothing to retire", flagMeshIP: "100.64.1.1"},
		{
			name: "a server without a --mesh-ip keeps a record of the default range", file: "100.64.0.0/24\n",
		},
		{
			// The default is what netd's flag falls back to and what this server's
			// pods are addressed from, so the file would strand them the same way.
			name: "a server without a --mesh-ip retires any other range", file: "100.64.2.0/24\n",
			wantRemoved: true, wantSweep: 2,
		},
		{
			// netd ignores such a file and starts on its flag, and rewrites it at the
			// next confirmation, so it strands nothing and there is no index to sweep.
			name: "a malformed record is left to netd", file: "not a prefix\n",
			flagMeshIP: "100.64.1.1",
		},
		{
			name: "a record outside the cluster range is left to netd", file: "10.0.0.0/24\n",
			flagMeshIP: "100.64.1.1",
		},
		{
			name: "a worker keeps the range its join gave it", file: "100.64.7.0/24\n",
			worker: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := reinstallFake(t)
			cfg := testConfig(t)
			cfg.MeshIP = tc.flagMeshIP
			if tc.worker {
				cfg = agentCfg(t)
				f = newFakeSystem(t)
				f.putLoaded(NetdLabel, AgentLabel)
				seedJoinedAgent(t, f)
			}
			if tc.carriedMeshIP != "" {
				putServerArgsRecord(t, f, cfg.withDefaults().ServerArgsRecord, "--mesh-ip", tc.carriedMeshIP)
			}
			if tc.file != "" {
				f.putFile(identity, []byte(tc.file))
			}

			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}

			_, kept := f.files[identity]
			if tc.wantRemoved && kept {
				t.Errorf("the identity file survived, so netd restores %q over the seed and refuses the new address", tc.file)
			}
			if !tc.wantRemoved {
				if tc.file != "" && !kept {
					t.Errorf("the identity file %q was removed, but the seeded range did not change", tc.file)
				}
				if n := callIndex(f.calls, "FlushInterconnectAliases:"); n >= 0 {
					t.Errorf("interconnect aliases were swept with no range change: %s", f.calls[n])
				}
				return
			}
			// netd must be down, or its next confirmation writes the file straight
			// back. The sweep needs the index only the file holds, so it comes first.
			// Both come before the plist that seeds the new range, so an install that
			// fails here rolls back to a plist and a file that still agree.
			order := []string{"Bootout:" + NetdLabel, sweep(tc.wantSweep), "RemoveAll:" + identity, "WriteLaunchDaemon:" + cfg.withDefaults().plistPath(NetdLabel), "Bootstrap:" + NetdLabel}
			prev := -1
			for _, want := range order {
				at := callIndex(f.calls, want)
				if at < 0 {
					t.Fatalf("no %s call: %v", want, f.calls)
				}
				if at < prev {
					t.Errorf("%s ran too early; want the order %v, got %v", want, order, f.calls)
				}
				prev = at
			}
		})
	}

	t.Run("a failed sweep does not hold the new address hostage", func(t *testing.T) {
		// macOS can refuse to delete an alias for good, so refusing the install here
		// could never clear. The leftover is named, with its remedy.
		var logs bytes.Buffer
		f := reinstallFake(t)
		f.failOn("FlushInterconnectAliases", errors.New("ifconfig bridge0 -alias: not in table"))
		f.putFile(identity, []byte("100.64.2.0/24\n"))
		cfg := testConfig(t)
		cfg.MeshIP = "100.64.1.1"
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if _, kept := f.files[identity]; kept {
			t.Error("the identity file survived a failed sweep, so the new address stays refused")
		}
		out := logs.String()
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "not in table") || !strings.Contains(out, InterconnectBridge) {
			t.Errorf("no WARN names the failed sweep and the bridge:\n%s", out)
		}
	})

	t.Run("a file that cannot be removed fails the install before the plist changes", func(t *testing.T) {
		f := reinstallFake(t)
		f.putFile(identity, []byte("100.64.2.0/24\n"))
		cfg := testConfig(t)
		cfg.MeshIP = "100.64.1.1"
		sys := removeFailingSystem{fakeSystem: f, path: identity}

		err := Install(context.Background(), sys, cfg)
		if err == nil || !strings.Contains(err.Error(), identity) {
			t.Fatalf("Install = %v, want a failure naming %s", err, identity)
		}
		if at := callIndex(f.calls, "WriteLaunchDaemon:"+cfg.withDefaults().plistPath(NetdLabel)); at >= 0 {
			t.Errorf("the netd plist was rewritten beside a file naming the old range: %v", f.calls)
		}
	})

	t.Run("a file that cannot be read fails the install rather than guess", func(t *testing.T) {
		f := reinstallFake(t)
		f.putFile(identity, []byte("100.64.2.0/24\n"))
		f.putKind(identity, fakeSymlink)
		cfg := testConfig(t)
		cfg.MeshIP = "100.64.1.1"

		err := Install(context.Background(), f, cfg)
		if !errors.Is(err, ErrNotRegularFile) {
			t.Fatalf("Install = %v, want ErrNotRegularFile", err)
		}
	})
}
