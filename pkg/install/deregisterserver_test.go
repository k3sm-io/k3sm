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
	"slices"
	"strings"
	"testing"
)

// deregisterServerCall is the marker a fake DeregisterServer appends to the fake
// system's call log, so its order against the preflight and the bootouts is read
// off one sequence.
const deregisterServerCall = "DeregisterServer"

func recordingDeregisterServer(f *fakeSystem, err error) func(context.Context) error {
	return func(context.Context) error {
		f.calls = append(f.calls, deregisterServerCall)
		return err
	}
}

// TestUninstallServerMemberRemoveOrder pins when an etcd server leaves its cluster
// on uninstall: exactly once, after a purge's preflight and before any daemon is
// booted out (its local member must still be running to remove itself), for a plain
// uninstall and a purge alike; never on a purge the preflight refuses; never on a
// server whose plist does not select the etcd posture; and a failure is a warning
// naming the --cluster-reset remedy that never stops the teardown.
func TestUninstallServerMemberRemoveOrder(t *testing.T) {
	etcdArgs := map[string][]string{
		"--cluster-init": {"--cluster-init", "--etcd-peer-ip", "192.0.2.10"},
		"--server-join":  {"--server-join", "--server", "192.0.2.10", "--etcd-peer-ip", "192.0.2.11"},
	}
	for name, args := range etcdArgs {
		t.Run("plain uninstall, "+name, func(t *testing.T) {
			f := &fakeSystem{}
			cfg := Config{Role: RoleServer, Logger: testLogger(&bytes.Buffer{}), DeregisterServer: recordingDeregisterServer(f, nil)}
			configureServerArgs(f, cfg, args...)
			if err := Uninstall(context.Background(), f, cfg); err != nil {
				t.Fatalf("Uninstall: %v", err)
			}
			assertDeregisteredBeforeBootout(t, f.calls)
		})
	}

	t.Run("purge: after the preflight, before the bootouts", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		r.cfg.DeregisterServer = recordingDeregisterServer(r.f, nil)
		configureServerArgs(r.f, r.cfg, etcdArgs["--cluster-init"]...)
		if err := r.run(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		assertDeregisteredBeforeBootout(t, r.f.calls)
		preflight := callIndex(r.f.calls, "ResolvePath:")
		if preflight < 0 || preflight > slices.Index(r.f.calls, deregisterServerCall) {
			t.Errorf("the member was removed before the purge preflight ran (calls: %v)", r.f.calls)
		}
	})

	t.Run("a refused purge makes no call", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		r.cfg.DeregisterServer = recordingDeregisterServer(r.f, nil)
		configureServerArgs(r.f, r.cfg, etcdArgs["--cluster-init"]...)
		r.cfg.DataRoot = "/"
		r.f.seedPurgeable("/")
		if err := r.run(); !errors.Is(err, ErrPurgeRefused) {
			t.Fatalf("purge = %v, want ErrPurgeRefused", err)
		}
		if slices.Contains(r.f.calls, deregisterServerCall) {
			t.Errorf("a refused purge removed the etcd member (calls: %v)", r.f.calls)
		}
	})

	for name, args := range map[string][]string{
		"single-node":           nil,
		"mesh, not etcd":        {"--mesh-ip", "198.51.100.10"},
		"--cluster-init=false":  {"--cluster-init=false"},
		"agent-role uninstall":  nil,
		"no plist on this disk": nil,
	} {
		t.Run("no call: "+name, func(t *testing.T) {
			f := &fakeSystem{}
			cfg := Config{Role: RoleServer, Logger: testLogger(&bytes.Buffer{}), DeregisterServer: recordingDeregisterServer(f, nil)}
			switch name {
			case "agent-role uninstall":
				cfg.Role = RoleAgent
			case "no plist on this disk":
			default:
				configureServerArgs(f, cfg, args...)
			}
			if err := Uninstall(context.Background(), f, cfg); err != nil {
				t.Fatalf("Uninstall: %v", err)
			}
			if slices.Contains(f.calls, deregisterServerCall) {
				t.Errorf("DeregisterServer was called (calls: %v)", f.calls)
			}
		})
	}

	t.Run("a failure warns with the reset remedy and the teardown completes", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		cfg := Config{Role: RoleServer, Logger: testLogger(&log),
			DeregisterServer: recordingDeregisterServer(f, errors.New("etcdserver: no leader"))}
		configureServerArgs(f, cfg, etcdArgs["--cluster-init"]...)
		if err := Uninstall(context.Background(), f, cfg); err != nil {
			t.Fatalf("a failed member removal must not fail the uninstall: %v", err)
		}
		for _, want := range []string{"Bootout:" + ServerLabel, "RemoveAll:" + DefaultInstallDir} {
			if !slices.Contains(f.calls, want) {
				t.Errorf("the teardown did not reach %s (calls: %v)", want, f.calls)
			}
		}
		for _, want := range []string{"--cluster-reset", "etcdserver: no leader"} {
			if !strings.Contains(log.String(), want) {
				t.Errorf("the warning does not carry %q:\n%s", want, log.String())
			}
		}
	})
}

func assertDeregisteredBeforeBootout(t *testing.T, calls []string) {
	t.Helper()
	at := slices.Index(calls, deregisterServerCall)
	if at < 0 {
		t.Fatalf("the etcd member was never removed (calls: %v)", calls)
	}
	if n := strings.Count(strings.Join(calls, ","), deregisterServerCall); n != 1 {
		t.Errorf("DeregisterServer called %d times, want 1", n)
	}
	for i, c := range calls {
		if strings.HasPrefix(c, "Bootout:") && i < at {
			t.Fatalf("%s ran before the member removal (calls: %v); the local member must still be up", c, calls)
		}
	}
}
