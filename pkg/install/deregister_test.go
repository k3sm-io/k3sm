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
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// deregisterCall is the marker a fake Deregister appends to the fake system's
// own call log, so the ORDER of the deregistration against the daemon bootouts
// is asserted on one recorded sequence rather than on two clocks.
const deregisterCall = "Deregister"

// recordingDeregister returns a Deregister closure that records itself in f's
// call log and then returns err.
func recordingDeregister(f *fakeSystem, err error) func(context.Context) error {
	return func(context.Context) error {
		f.calls = append(f.calls, deregisterCall)
		return err
	}
}

// TestUninstallDeregistersTheNode is the gate for B311: an uninstalled worker
// must leave the cluster, not linger in it.
//
// Until this existed, `sudo k3sm uninstall` on a worker removed the Mac and
// nothing else. The node's MeshPeer stayed in the datastore, so every remaining
// peer kept a wireguard entry and a route for a machine that would never answer
// again, and its Node object kept showing up as NotReady. Nothing reaps either
// one: the node is gone, and no controller owns a MeshPeer.
//
// Four properties, each of which is a way to get this wrong:
//
//   - the call happens, exactly once, and BEFORE the agent daemon is booted out
//     — after the bootout the mesh is coming down and the node may no longer be
//     able to reach the control plane at all;
//   - a failure does not block the teardown, and says how to finish the job by
//     hand (an operator who never learns the delete did not happen leaves a dead
//     peer in a live cluster);
//   - a SERVER uninstall never calls it, whatever the Config carries — a control
//     plane does not deregister itself from itself;
//   - a nil closure is simply skipped, which is what every caller with no usable
//     credential passes.
func TestUninstallDeregistersTheNode(t *testing.T) {
	t.Run("an agent uninstall deregisters before the daemon is booted out", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		err := Uninstall(context.Background(), f, Config{
			Role:       RoleAgent,
			Logger:     testLogger(&log),
			Deregister: recordingDeregister(f, nil),
		})
		if err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		deregisters := slices.Index(f.calls, deregisterCall)
		if deregisters < 0 {
			t.Fatalf("the uninstall never deregistered the node (calls: %v)", f.calls)
		}
		if n := strings.Count(strings.Join(f.calls, ","), deregisterCall); n != 1 {
			t.Errorf("Deregister called %d times, want exactly 1", n)
		}
		bootout := slices.Index(f.calls, "Bootout:"+AgentLabel)
		if bootout < 0 {
			t.Fatalf("the agent daemon was never booted out (calls: %v)", f.calls)
		}
		if deregisters > bootout {
			t.Errorf("the node was deregistered AFTER the agent daemon was booted out (calls: %v); by then the mesh is coming down and the control plane may be unreachable", f.calls)
		}
		// The local teardown still completed in full.
		for _, want := range []string{"RemoveAll:" + DefaultInstallDir, "FlushMeshPFAnchor"} {
			if !slices.Contains(f.calls, want) {
				t.Errorf("the teardown did not reach %s (calls: %v)", want, f.calls)
			}
		}
	})

	t.Run("a failing deregistration is logged with the remedy and does not stop the teardown", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		err := Uninstall(context.Background(), f, Config{
			Role:       RoleAgent,
			Logger:     testLogger(&log),
			Deregister: recordingDeregister(f, errors.New("no route to the control plane for node worker-1")),
		})
		if err != nil {
			t.Fatalf("a failed deregistration must not fail the uninstall: %v", err)
		}
		for _, want := range []string{"Bootout:" + AgentLabel, "RemoveAll:" + DefaultInstallDir, "FlushLo0Aliases:100.64.0.0/10,10.43.0.0/16"} {
			if !slices.Contains(f.calls, want) {
				t.Errorf("the teardown did not reach %s after a failed deregistration (calls: %v)", want, f.calls)
			}
		}
		text := log.String()
		if !strings.Contains(text, "kubectl delete meshpeer/") {
			t.Errorf("the log does not carry the manual remedy, so the operator never learns the node is still in the cluster:\n%s", text)
		}
		if !strings.Contains(text, "no route to the control plane for node worker-1") {
			t.Errorf("the log does not carry the underlying error (which is what names the node):\n%s", text)
		}
	})

	t.Run("a server uninstall never deregisters", func(t *testing.T) {
		f := &fakeSystem{}
		err := Uninstall(context.Background(), f, Config{
			Role:       RoleServer,
			Deregister: recordingDeregister(f, nil),
		})
		if err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if slices.Contains(f.calls, deregisterCall) {
			t.Errorf("a control-plane uninstall deregistered a node (calls: %v)", f.calls)
		}
	})

	t.Run("a server uninstall on a Mac that also carries the agent daemon does deregister", func(t *testing.T) {
		// The CLI passes a Config that says nothing about the role, so the
		// worker verdict has to come off the DISK. A Mac with the agent plist
		// on it is a worker whatever the Config claims.
		f := &fakeSystem{}
		f.putFile(Config{}.withDefaults().plistPath(AgentLabel), AgentPlist(agentCfg(t)))
		err := Uninstall(context.Background(), f, Config{
			Role:       RoleServer,
			Deregister: recordingDeregister(f, nil),
		})
		if err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if !slices.Contains(f.calls, deregisterCall) {
			t.Errorf("the agent daemon is on disk but the uninstall did not deregister the node (calls: %v)", f.calls)
		}
	})

	t.Run("a nil Deregister is skipped", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, Config{Role: RoleAgent}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if slices.Contains(f.calls, deregisterCall) {
			t.Fatalf("impossible: a nil closure cannot have recorded a call (calls: %v)", f.calls)
		}
	})
}

// TestAgentJoinServerReadsTheInstalledPlist pins the one place the installed
// join target is written down.
//
// The agent-arguments record deliberately does NOT carry --server (the renderer
// owns that flag and re-derives it on every install), so the plist is the only
// source, and an uninstall that cannot read it has nowhere to send a
// deregistration. The absent-plist arm must stay an fs.ErrNotExist all the way
// out: that is how the caller tells "this Mac is not a worker" (say nothing)
// from "the join target is unreadable" (say so).
func TestAgentJoinServerReadsTheInstalledPlist(t *testing.T) {
	t.Run("the installed plist names the control plane", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := agentCfg(t)
		f.putFile(cfg.withDefaults().plistPath(AgentLabel), AgentPlist(cfg))
		got, err := AgentJoinServer(f, Config{})
		if err != nil {
			t.Fatalf("AgentJoinServer: %v", err)
		}
		if got != cfg.JoinServer {
			t.Errorf("join server = %q, want %q", got, cfg.JoinServer)
		}
	})

	t.Run("no agent plist is fs.ErrNotExist", func(t *testing.T) {
		_, err := AgentJoinServer(&fakeSystem{}, Config{})
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want it to wrap fs.ErrNotExist so a control plane is distinguishable from an unreadable plist", err)
		}
	})

	t.Run("a plist with no --server is an error", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := agentCfg(t)
		cfg.JoinServer = ""
		f.putFile(cfg.withDefaults().plistPath(AgentLabel), AgentPlist(cfg))
		if got, err := AgentJoinServer(f, Config{}); err == nil {
			t.Errorf("AgentJoinServer returned %q for a plist that names no control plane, want an error", got)
		}
	})
}
