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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/nodecred"
	"k3sm.io/k3sm/pkg/version"
)

// The status JSON contract (docs/user/status-json.md), as data. Each set is
// what a reader of schemaVersion 1 may rely on; a change to one of them is a
// change to the contract, and the doc changes with it.
var (
	// reportRequired and reportOptional are the top-level keys of `k3sm status
	// -o json`. The optional ones are omitted when empty.
	reportRequired = []string{"schemaVersion", "capabilities", "verdict", "role", "summary", "rows", "version", "host", "timestamp"}
	reportOptional = []string{"next", "peers", "interconnect", "stoppedBy", "network", "workers", "joinTarget"}
	// workerRequired and workerOptional are the keys of each entry of the
	// optional workers list; version is omitted while a kubelet has reported
	// none.
	workerRequired = []string{"name", "role"}
	workerOptional = []string{"version"}
	// networkRequired are the keys of the optional network object.
	networkRequired = []string{"lan", "recorded", "covers", "alwaysOn"}
	// networkOptional are the optional keys of the network object.
	networkOptional = []string{"recordState", "applied", "appliedReadable"}
	// networkAppliedRequired / Optional are the keys of network.applied.
	networkAppliedRequired = []string{"lan", "serial"}
	networkAppliedOptional = []string{"error"}
	// stoppedByRequired are the keys of the optional stoppedBy object.
	stoppedByRequired = []string{"actor", "reason", "at", "phase"}
	// interconnectRequired and interconnectOptional are the keys of the
	// report's interconnect block, and interconnectPodRequired those of each
	// attached pod in it.
	interconnectRequired    = []string{"name", "armed", "plaintext", "members", "up", "segments"}
	interconnectOptional    = []string{"armedBy", "outOfRange", "pods"}
	interconnectPodRequired = []string{"namespace", "pod", "node", "address"}
	// daemonsRequired is the whole of `k3sm status daemons -o json`.
	daemonsRequired = []string{"schemaVersion", "verdict", "role", "summary", "daemons"}
	daemonsOptional = []string{"stoppedBy", "network"}
	rowRequired     = []string{"name", "state", "severity", "detail"}
	rowOptional     = []string{"remedy", "wide", "alert"}
	// alertRequired and alertOptional are the keys of a row's alert, and
	// fixStepRequired / fixStepOptional those of each of its fix steps.
	alertRequired   = []string{"cause", "evidence", "fix", "docs"}
	alertOptional   = []string{"since"}
	fixStepRequired = []string{"step", "needsAdmin", "confirm"}
	fixStepOptional = []string{"command"}
	versionRequired = []string{"version", "commit", "dirty", "date", "goVersion", "platform", "kubeVersion", "kineVersion"}
	versionOptional = []string{"modules"}
	moduleRequired  = []string{"path", "sha"}
	peerRequired    = []string{"name", "state", "detail"}

	// contractVerdicts maps every verdict word to the exit code `k3sm status`
	// (either shape) exits with alongside it.
	contractVerdicts = map[string]int{"running": 0, "stopped": 3, "degraded": 4, "not-installed": 5, "unknown": 6}
	contractRoles    = []string{"server", "agent"}
	// contractDaemonRows are the row names the probe carries: netd, and the
	// node daemon of the role.
	contractDaemonRows = []string{RowNetd, RowServer, RowAgent}
	// contractDaemonStates is every state a daemon row can carry today: the
	// launchd classes (ClassifyDaemon), the crash-loop record's word, and the
	// agent's credential words. Each one appears in at least one golden.
	contractDaemonStates = []RowState{
		StateRunning, StateStopped, StateNotLoaded, StateDisabled, StateFailed, StateCrashLoop, StateUnknown,
		StateWaiting, StateExpired, StateCorrupt, StateAddressMismatch,
	}
	// contractRowStates is the whole shipped row-state vocabulary (report.go),
	// which every row of the full report draws from.
	contractRowStates = []RowState{
		StateOK, StateRunning, StateReady, StateCrashLoop, StateFailed, StateStopped, StateNotLoaded,
		StateDisabled, StateDown, StateNotReady, StateWrongOwner, StateNotMounted, StateAbsent, StatePartial,
		StateMissing, StateSkip, StateWaiting, StateExpired, StateCorrupt, StateAddressMismatch, StateDrift,
		StateUnknown, StateHealthy, StateUnhealthy, StateStale, StateNeedsAdmin, StateBehind, StateAhead, StateRefused,
		StateOn, StateInvalid,
	}
)

// contractVersion is a fully populated build provenance, so the goldens carry
// every key of the embedded version object.
var contractVersion = version.Info{
	Version:     "v0.1.7",
	Commit:      "0123456789abcdef0123456789abcdef01234567",
	Date:        "2026-10-01T00:00:00Z",
	GoVersion:   "go1.26.1",
	Platform:    "darwin/arm64",
	KubeVersion: "v1.36.2",
	KineVersion: "v1.14.2",
	Modules: []version.ModuleRef{
		{Path: "k3sm.io/apis", SHA: "v0.1.7"},
		{Path: "k3sm.io/darwin-net", SHA: "v0.1.7"},
		{Path: "k3sm.io/runtimed", SHA: "v0.1.7"},
		{Path: "k3sm.io/k3sm", SHA: "v0.1.7"},
	},
}

// contractWorkDir is a work dir that exists on no machine, so the datastore
// row (which reads the real filesystem) says the same thing everywhere.
const contractWorkDir = "/nonexistent/k3sm-status-contract/server"

// contractScenario is one machine posture, collected into both shapes.
type contractScenario struct {
	collector func(t *testing.T) Collector
	verdict   Verdict
}

// downKube is an apiserver that refuses the readiness probe.
func downKube() fakeKube {
	return fakeKube{
		rawErr: map[string]error{"/readyz": errors.New("connection refused")},
		server: "https://127.0.0.1:6444",
		tls:    "ca pinned",
	}
}

// contractServer is a control-plane Mac whose two daemons launchd describes
// with the named fixtures.
func contractServer(t *testing.T, netd, server string, kube Kube, kubeErr error) Collector {
	t.Helper()
	p := testPaths(contractWorkDir)
	fsys := installedFS(p)
	fsys.tail = map[string][]string{p.ServerLog: {
		`time=2026-09-05T09:30:00Z level=ERROR msg="control plane exited" err="bind: address already in use"`,
	}}
	return Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, netd),
			p.ServerLabel: fixture(t, server),
		}},
		FS:         fsys,
		Kube:       kube,
		KubeErr:    kubeErr,
		KubeSource: `~/.kube/config context "k3sm"`,
		Procs:      fakeProcs{live: LivenessRunning},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o755, uid: 0, mounted: true},
		DNS:        answeringDNS(),
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Now:        func() time.Time { return goldenTime },
		Version:    contractVersion,
		Host:       goldenHost,
		Hostname:   "my-mac",
	}
}

// contractDeveloperMode is the running control plane with a developer-mode
// marker in state and an installed k3sm whose signature reads as team, err.
func contractDeveloperMode(t *testing.T, state install.DeveloperModeState, team string, err error) Collector {
	t.Helper()
	c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
	c.DeveloperMode = func() install.DeveloperModeState { return state }
	c.SigningTeamID = func(context.Context, string) (string, error) { return team, err }
	return c
}

// contractRecordOff is a readable LAN record that says off.
func contractRecordOff() (install.NetworkRecord, bool, error) {
	return install.NetworkRecord{Version: install.NetworkRecordVersion, LAN: install.LANOff, Serial: "4f0c2a9e1b7d3c55"}, true, nil
}

// contractNetwork is the running control plane with the LAN record and the
// node daemon's applied report read through the given seams.
func contractNetwork(t *testing.T, record func() (install.NetworkRecord, bool, error), applied func(install.Role) ([]byte, error)) Collector {
	t.Helper()
	c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
	c.Network, c.NetworkApplied = record, applied
	return c
}

// contractAgent is a worker Mac with both daemons running and the credential
// store stage leaves.
func contractAgent(t *testing.T, stage func(*testing.T, Paths, fakeFS) fakeFS) Collector {
	t.Helper()
	p := agentPaths(contractWorkDir)
	c := agentCollector(t, p, stage(t, p, agentInstalledFS(p)))
	c.KubeErr = errors.New("no k3sm context in ~/.kube/config")
	c.DNS = answeringDNS()
	c.Version = contractVersion
	c.Hostname = "my-mac"
	return c
}

// contractInterconnect is the running control plane with an armed
// interconnect: two cabled members up in one segment, one cabled node beyond
// the index ceiling, and two pods attached. The Interconnect is served at its
// apiserver path and read through ReadInterconnect, the production reader.
func contractInterconnect(t *testing.T) Collector {
	t.Helper()
	kube := heartbeatingKube(goldenTime)
	armedAt := metav1.NewTime(goldenTime.Add(-time.Hour))
	ic := netv1alpha1.Interconnect{
		ObjectMeta: metav1.ObjectMeta{Name: netv1alpha1.MediumThunderbolt},
		Spec:       netv1alpha1.InterconnectSpec{Medium: netv1alpha1.MediumThunderbolt, Enabled: true},
		Status: netv1alpha1.InterconnectStatus{
			Members: []netv1alpha1.InterconnectMember{
				{Node: "my-mac", Index: 0, Address: "169.254.0.1", State: netv1alpha1.InterconnectMemberUp, Segment: "s0"},
				{Node: "node-a", Index: 1, Address: "169.254.0.9", State: netv1alpha1.InterconnectMemberUp, Segment: "s0"},
				{Node: "far", Index: 40, State: netv1alpha1.InterconnectMemberDown},
			},
			Segments: []netv1alpha1.InterconnectSegment{{ID: "s0", Nodes: []string{"my-mac", "node-a"}}},
			ArmedBy:  "kubernetes-admin",
			ArmedAt:  &armedAt,
		},
	}
	raw, err := json.Marshal(ic)
	if err != nil {
		t.Fatal(err)
	}
	kube.raw[interconnectPath] = raw
	kube.pods = append(kube.pods,
		attachedPod("mlx", "llama-0", "my-mac", "169.254.0.2"),
		attachedPod("default", "bench", "node-a", "169.254.0.11"))
	c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", kube, nil)
	c.Interconnect = func(ctx context.Context) (*netv1alpha1.Interconnect, error) { return ReadInterconnect(ctx, kube) }
	return c
}

// attachedPod is a running pod on node whose k3sm.io/InterconnectAttached
// condition is True with addr, the way the provider records it.
func attachedPod(ns, name, node, addr string) corev1.Pod {
	p := podIn(corev1.PodRunning)
	p.Namespace, p.Name, p.Spec.NodeName = ns, name, node
	p.Status.Conditions = []corev1.PodCondition{{
		Type:    corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached),
		Status:  corev1.ConditionTrue,
		Reason:  netv1alpha1.MediumThunderbolt,
		Message: addr,
	}}
	return p
}

// contractScenarios are the postures the goldens record. Every verdict is
// here, and every daemon-row state appears in at least one of them. Each
// cause is one the probe can see, so the two shapes agree on the verdict.
func contractScenarios() map[string]contractScenario {
	return map[string]contractScenario{
		"running": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			return contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
		}},
		"degraded": {verdict: VerdictDegraded, collector: func(t *testing.T) Collector {
			c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", healthyKube(), nil)
			c.Procs = fakeProcs{live: LivenessDead} // launchd says running; the pid is gone
			return c
		}},
		"stopped-crashloop": {verdict: VerdictStopped, collector: func(t *testing.T) Collector {
			return contractServer(t, "launchctl_netd_running.txt", "launchctl_server_crashloop.txt", downKube(), nil)
		}},
		"stopped-clean": {verdict: VerdictStopped, collector: func(t *testing.T) Collector {
			return contractServer(t, "launchctl_failed_once.txt", "launchctl_stopped_clean.txt", downKube(), nil)
		}},
		"stopped-disabled": {verdict: VerdictStopped, collector: func(t *testing.T) Collector {
			c := contractServer(t, "launchctl_not_loaded.txt", "launchctl_stopped_clean.txt", downKube(), nil)
			c.Launchd = fakeLaunchd{
				out: map[string][]byte{c.Paths.ServerLabel: fixture(t, "launchctl_stopped_clean.txt")},
				err: map[string]error{c.Paths.NetdLabel: errors.New("exit status 113")},
				// print-disabled output naming the server as disabled.
				disabled: fixture(t, "launchctl_disabled.txt"),
			}
			return c
		}},
		"stopped-by-user": {verdict: VerdictStopped, collector: func(t *testing.T) Collector {
			c := contractServer(t, "launchctl_failed_once.txt", "launchctl_stopped_clean.txt", downKube(), nil)
			c.StopMarker = fakeStopMarker(userStopMarker(goldenTime.Add(-90*time.Second), install.StopPhaseStopped))
			return c
		}},
		"not-installed": {verdict: VerdictNotInstalled, collector: func(t *testing.T) Collector {
			c := contractServer(t, "launchctl_not_loaded.txt", "launchctl_not_loaded.txt", nil, errors.New("no k3sm context in ~/.kube/config"))
			notLoaded := errors.New("exit status 113")
			c.Launchd = fakeLaunchd{err: map[string]error{c.Paths.NetdLabel: notLoaded, c.Paths.ServerLabel: notLoaded}}
			c.FS = fakeFS{}
			c.DataRoot = fakeDataRootFS{dir: c.Paths.DataRoot, missing: true}
			return c
		}},
		"unknown": {verdict: VerdictUnknown, collector: func(t *testing.T) Collector {
			c := contractServer(t, "launchctl_format_drift.txt", "launchctl_format_drift.txt", nil, errors.New("no k3sm context in ~/.kube/config"))
			// The arguments source is root's: the settings it holds are restricted.
			c.NodeArgs = func(install.Role) ([]string, error) { return nil, os.ErrPermission }
			return c
		}},
		"running-interconnect": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			return contractInterconnect(t)
		}},
		"server-with-workers": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			kube := heartbeatingKube(goldenTime)
			older := workerNode("node-b", "v1.36.2+k3sm.0.1.6")
			peer := workerNode("node-a", "v1.36.2+k3sm.0.1.7")
			peer.Labels = map[string]string{controlPlaneNodeLabel: ""}
			kube.nodes = append(kube.nodes, older, peer)
			return contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", kube, nil)
		}},
		"network-recorded": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			c := contractNetwork(t, contractRecordOff, func(install.Role) ([]byte, error) {
				return []byte(`{"lan":"off","serial":"4f0c2a9e1b7d3c55"}`), nil
			})
			// An operator-configured server: the settings row reads each flag.
			c.NodeArgs = func(install.Role) ([]string, error) {
				return []string{
					"--nodeport-addresses", "local", "--registry-port", "5000",
					"--tls-san=k3sm.example.test", "--tls-san=192.0.2.20", "--mesh-ip", "100.64.0.1",
					"--update-release-base=https://releases.example.test/k3sm",
				}, nil
			}
			return c
		}},
		"network-absent": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			c := contractNetwork(t, func() (install.NetworkRecord, bool, error) {
				return install.NetworkRecord{Version: install.NetworkRecordVersion, LAN: install.LANOn}, false, nil
			}, nil)
			// A stock install: no recorded flag, so every setting is its default.
			c.NodeArgs = func(install.Role) ([]string, error) { return nil, nil }
			return c
		}},
		"network-unreadable": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			return contractNetwork(t, func() (install.NetworkRecord, bool, error) {
				return install.NetworkRecord{}, true, fmt.Errorf("network record /Library/k3sm/network.json: %w: owned by uid 501, not root", install.ErrNetworkRecord)
			}, func(install.Role) ([]byte, error) {
				return []byte(`{"lan":"off","serial":"","error":"read the network record: network record unusable"}`), nil
			})
		}},
		"network-applied-unreadable": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			return contractNetwork(t, contractRecordOff, func(install.Role) ([]byte, error) { return nil, os.ErrPermission })
		}},
		"agent-join-target": {verdict: VerdictDegraded, collector: func(t *testing.T) Collector {
			c := contractAgent(t, func(_ *testing.T, _ Paths, fsys fakeFS) fakeFS { return fsys })
			sys := agentPlistSystem("192.0.2.10")
			c.AgentJoinServer = func() (string, error) { return install.AgentJoinServer(sys, install.Config{}) }
			c.NodeArgs = func(install.Role) ([]string, error) {
				return []string{"--nodeport-addresses", "192.0.2.0/24"}, nil
			}
			return c
		}},
		// Developer mode on, over an ad-hoc signed k3sm: the row warns and the
		// verdict stays running.
		"developer_mode": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			return contractDeveloperMode(t, install.DeveloperModeMarkerOn, "", install.ErrNoTeamID)
		}},
		// A marker that fails the checks, over a team-signed k3sm: ignored, and
		// the verdict stays running.
		"developer_mode_invalid": {verdict: VerdictRunning, collector: func(t *testing.T) Collector {
			return contractDeveloperMode(t, install.DeveloperModeInvalid, "ABCDE12345", nil)
		}},
		"agent-waiting": {verdict: VerdictDegraded, collector: func(t *testing.T) Collector {
			return contractAgent(t, func(_ *testing.T, _ Paths, fsys fakeFS) fakeFS { return fsys })
		}},
		"agent-expired": {verdict: VerdictDegraded, collector: func(t *testing.T) Collector {
			return contractAgent(t, func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
				return withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(-24*time.Hour))
			})
		}},
		"agent-corrupt": {verdict: VerdictDegraded, collector: func(t *testing.T) Collector {
			return contractAgent(t, func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
				fsys = withCredential(t, fsys, p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour))
				fsys.contents[filepath.Join(p.AgentCredentialDir, nodecred.KubeconfigFile)] = []byte("not a kubeconfig")
				return fsys
			})
		}},
		"agent-address-mismatch": {verdict: VerdictDegraded, collector: func(t *testing.T) Collector {
			return contractAgent(t, func(t *testing.T, p Paths, fsys fakeFS) fakeFS {
				return withCredentialFor(t, fsys, p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour), "100.64.9.9")
			})
		}},
	}
}

// goldenPaths names a scenario's two golden files.
func goldenPaths(name string) (full, daemons string) {
	return filepath.Join("testdata", "status_json_"+name+".json"),
		filepath.Join("testdata", "status_daemons_json_"+name+".json")
}

// decodeStrict decodes a golden into its typed struct, refusing any key the
// struct does not define, and returns its generic form as well.
func decodeStrict(t *testing.T, path string, into any) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s does not decode into %T: %v", path, into, err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return generic
}

// checkKeys asserts obj carries every required key and nothing outside
// required+optional, and records which keys it carried in seen.
func checkKeys(t *testing.T, where string, obj any, required, optional []string, seen map[string]bool) {
	t.Helper()
	m, ok := obj.(map[string]any)
	if !ok {
		t.Errorf("%s is %T, want a JSON object", where, obj)
		return
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			t.Errorf("%s is missing the required key %q", where, k)
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("%s carries %q, which the contract does not define", where, k)
		}
		if seen != nil {
			seen[k] = true
		}
	}
}

// checkRows asserts the key set of every row in a rows array.
func checkRows(t *testing.T, where string, rows any, seen map[string]bool) {
	t.Helper()
	list, ok := rows.([]any)
	if !ok {
		t.Errorf("%s is %T, want an array", where, rows)
		return
	}
	for i, r := range list {
		at := fmt.Sprintf("%s[%d]", where, i)
		checkKeys(t, at, r, rowRequired, rowOptional, seen)
		checkAlert(t, at, r, seen)
	}
}

// checkAlert asserts a row's alert is present exactly when its severity is
// warn, fail or unknown or its state is needs-admin, and checks its keys and
// those of each fix step.
func checkAlert(t *testing.T, where string, row any, seen map[string]bool) {
	t.Helper()
	m, _ := row.(map[string]any)
	sev, state := m["severity"], m["state"]
	want := sev == "warn" || sev == "fail" || sev == "unknown" || state == string(StateNeedsAdmin)
	a, has := m["alert"]
	if has != want {
		t.Errorf("%s (%v/%v) carries an alert: %v, want %v", where, state, sev, has, want)
	}
	if !has {
		return
	}
	checkKeys(t, where+" alert", a, alertRequired, alertOptional, seen)
	am, _ := a.(map[string]any)
	fix, _ := am["fix"].([]any)
	if len(fix) == 0 {
		t.Errorf("%s alert has no fix step", where)
	}
	for j, f := range fix {
		checkKeys(t, fmt.Sprintf("%s alert fix[%d]", where, j), f, fixStepRequired, fixStepOptional, seen)
	}
}

// jsonKeys is the set of JSON keys a struct type encodes.
func jsonKeys(typ reflect.Type) []string {
	var keys []string
	for i := 0; i < typ.NumField(); i++ {
		if !typ.Field(i).IsExported() {
			continue // never encoded
		}
		tag := typ.Field(i).Tag.Get("json")
		if tag == "-" {
			continue // never encoded (a text-only field)
		}
		name, _, _ := strings.Cut(tag, ",")
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}

func sortedUnion(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	sort.Strings(out)
	return out
}

// TestStatusJSONContractGolden is the gate on the versioned status JSON. The
// goldens under testdata are samples of both shapes, one pair per posture; the
// test reads them as a consumer would and pins what a consumer may rely on:
// the key sets, the closed enums, schemaVersion 1, that the probe's daemon
// rows are the full report's rows, and the exit code each verdict maps to. It
// also re-collects every posture and checks the goldens still describe what
// the collectors produce.
func TestStatusJSONContractGolden(t *testing.T) {
	t.Parallel()

	t.Run("the structs encode exactly the contract's keys", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			typ  reflect.Type
			want []string
		}{
			{reflect.TypeOf(Report{}), sortedUnion(reportRequired, reportOptional)},
			{reflect.TypeOf(DaemonsReport{}), sortedUnion(daemonsRequired, daemonsOptional)},
			{reflect.TypeOf(StoppedBy{}), sortedUnion(stoppedByRequired)},
			{reflect.TypeOf(Network{}), sortedUnion(networkRequired, networkOptional)},
			{reflect.TypeOf(NetworkApplied{}), sortedUnion(networkAppliedRequired, networkAppliedOptional)},
			{reflect.TypeOf(Row{}), sortedUnion(rowRequired, rowOptional)},
			{reflect.TypeOf(Alert{}), sortedUnion(alertRequired, alertOptional)},
			{reflect.TypeOf(FixStep{}), sortedUnion(fixStepRequired, fixStepOptional)},
			{reflect.TypeOf(PeerStatus{}), sortedUnion(peerRequired)},
			{reflect.TypeOf(Worker{}), sortedUnion(workerRequired, workerOptional)},
			{reflect.TypeOf(Interconnect{}), sortedUnion(interconnectRequired, interconnectOptional)},
			{reflect.TypeOf(InterconnectPod{}), sortedUnion(interconnectPodRequired)},
			{reflect.TypeOf(version.Info{}), sortedUnion(versionRequired, versionOptional)},
			{reflect.TypeOf(version.ModuleRef{}), sortedUnion(moduleRequired)},
		} {
			if got := jsonKeys(tc.typ); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s encodes %v, the contract says %v", tc.typ, got, tc.want)
			}
		}
	})

	t.Run("schemaVersion is defined once, as 1", func(t *testing.T) {
		t.Parallel()
		if SchemaVersion != 1 {
			t.Fatalf("SchemaVersion = %d; a bump is a breaking change and moves the goldens and the doc with it", SchemaVersion)
		}
	})

	daemonStatesSeen := map[RowState]bool{}
	verdictsSeen := map[string]bool{}
	optionalSeen := map[string]bool{}
	for name, sc := range contractScenarios() {
		fullPath, daemonsPath := goldenPaths(name)
		var full Report
		fullGeneric := decodeStrict(t, fullPath, &full)
		var probe DaemonsReport
		probeGeneric := decodeStrict(t, daemonsPath, &probe)

		t.Run(name+"/keys", func(t *testing.T) {
			checkKeys(t, fullPath, fullGeneric, reportRequired, reportOptional, optionalSeen)
			checkRows(t, fullPath+" rows", fullGeneric["rows"], optionalSeen)
			checkKeys(t, fullPath+" version", fullGeneric["version"], versionRequired, versionOptional, optionalSeen)
			if mods, ok := fullGeneric["version"].(map[string]any)["modules"].([]any); ok {
				for _, m := range mods {
					checkKeys(t, fullPath+" version.modules", m, moduleRequired, nil, nil)
				}
			}
			if ic, ok := fullGeneric["interconnect"]; ok {
				checkKeys(t, fullPath+" interconnect", ic, interconnectRequired, interconnectOptional, optionalSeen)
				if pods, ok := ic.(map[string]any)["pods"].([]any); ok {
					for i, p := range pods {
						checkKeys(t, fmt.Sprintf("%s interconnect.pods[%d]", fullPath, i), p, interconnectPodRequired, nil, nil)
					}
				}
			}
			if ws, ok := fullGeneric["workers"]; ok {
				list, isList := ws.([]any)
				if !isList {
					t.Errorf("%s workers is %T, want an array", fullPath, ws)
				}
				for i, w := range list {
					checkKeys(t, fmt.Sprintf("%s workers[%d]", fullPath, i), w, workerRequired, workerOptional, nil)
					if role, _ := w.(map[string]any)["role"].(string); !contains(contractRoles, role) {
						t.Errorf("%s workers[%d] role %q is outside the contract", fullPath, i, role)
					}
				}
			}
			if jt, ok := fullGeneric["joinTarget"]; ok && full.Role != "agent" {
				t.Errorf("%s carries joinTarget %v on a %s", fullPath, jt, full.Role)
			}
			if nw, ok := fullGeneric["network"]; ok {
				checkKeys(t, fullPath+" network", nw, networkRequired, networkOptional, optionalSeen)
			}
			if nw, ok := probeGeneric["network"]; ok {
				checkKeys(t, daemonsPath+" network", nw, networkRequired, networkOptional, optionalSeen)
				for _, k := range []string{"applied", "appliedReadable"} {
					if _, has := nw.(map[string]any)[k]; has {
						t.Errorf("%s network carries %q, which the probe never reads", daemonsPath, k)
					}
				}
			}
			for _, g := range []map[string]any{fullGeneric, probeGeneric} {
				nw, _ := g["network"].(map[string]any)
				if rs, ok := nw["recordState"]; ok && rs != NetworkRecordUnreadable {
					t.Errorf("%s network.recordState %v is outside the contract", name, rs)
				}
			}
			checkKeys(t, daemonsPath, probeGeneric, daemonsRequired, daemonsOptional, optionalSeen)
			for _, g := range []map[string]any{fullGeneric, probeGeneric} {
				if sb, ok := g["stoppedBy"]; ok {
					checkKeys(t, name+" stoppedBy", sb, stoppedByRequired, nil, nil)
				}
			}
			checkRows(t, daemonsPath+" daemons", probeGeneric["daemons"], optionalSeen)
		})

		t.Run(name+"/enums", func(t *testing.T) {
			for _, g := range []map[string]any{fullGeneric, probeGeneric} {
				if v, ok := g["schemaVersion"].(float64); !ok || v != 1 {
					t.Errorf("schemaVersion = %v, want 1", g["schemaVersion"])
				}
				verdict, _ := g["verdict"].(string)
				if _, ok := contractVerdicts[verdict]; !ok {
					t.Errorf("verdict %q is outside the contract", verdict)
				}
				verdictsSeen[verdict] = true
				if role, _ := g["role"].(string); !contains(contractRoles, role) {
					t.Errorf("role %q is outside the contract", role)
				}
			}
			for _, r := range full.Rows {
				if !containsState(contractRowStates, r.State) {
					t.Errorf("row %s carries state %q, outside the shipped vocabulary", r.Name, r.State)
				}
			}
			if len(probe.Daemons) != 2 || probe.Daemons[0].Name != RowNetd {
				t.Fatalf("daemons = %+v, want netd and the node daemon", probe.Daemons)
			}
			if want := nodeRowName(probe.Role); probe.Daemons[1].Name != want {
				t.Errorf("node daemon row = %q, want %q for role %s", probe.Daemons[1].Name, want, probe.Role)
			}
			for _, d := range probe.Daemons {
				if !contains(contractDaemonRows, d.Name) {
					t.Errorf("daemon row %q is outside the contract", d.Name)
				}
				if !containsState(contractDaemonStates, d.State) {
					t.Errorf("daemon row %s carries state %q, outside the contract", d.Name, d.State)
				}
				daemonStatesSeen[d.State] = true
			}
		})

		t.Run(name+"/daemons are the full report's rows", func(t *testing.T) {
			for _, d := range probe.Daemons {
				r, ok := full.Row(d.Name)
				if !ok {
					t.Errorf("daemon row %q is not in the full report", d.Name)
					continue
				}
				if !reflect.DeepEqual(r, d) {
					t.Errorf("daemon row %q differs from the full report's:\nprobe %+v\nfull  %+v", d.Name, d, r)
				}
			}
			if probe.Role != full.Role {
				t.Errorf("role: probe %s, full %s", probe.Role, full.Role)
			}
			if probe.Verdict != full.Verdict {
				t.Errorf("verdict: probe %v, full %v; this posture's cause is a daemon, which both read", probe.Verdict, full.Verdict)
			}
			var want *Network
			if full.Network != nil {
				n := *full.Network
				n.Applied, n.AppliedReadable = nil, nil
				want = &n
			}
			if !reflect.DeepEqual(probe.Network, want) {
				t.Errorf("network: probe %+v, want the full report's without applied %+v", networkOf(probe.Network), networkOf(want))
			}
		})

		t.Run(name+"/exit code", func(t *testing.T) {
			if got, want := probe.Verdict.ExitCode(), contractVerdicts[probe.Verdict.String()]; got != want {
				t.Errorf("probe verdict %v exits %d, the contract says %d", probe.Verdict, got, want)
			}
			if got, want := full.Verdict.ExitCode(), contractVerdicts[full.Verdict.String()]; got != want {
				t.Errorf("full verdict %v exits %d, the contract says %d", full.Verdict, got, want)
			}
		})

		t.Run(name+"/the goldens describe what the collectors produce", func(t *testing.T) {
			c := sc.collector(t)
			gotFull := c.Collect(context.Background())
			gotProbe := c.CollectDaemons()
			if gotFull.Verdict != sc.verdict || gotProbe.Verdict != sc.verdict {
				t.Fatalf("collected verdicts full=%v probe=%v, scenario says %v\n%s", gotFull.Verdict, gotProbe.Verdict, sc.verdict, Render(gotFull, Style{}))
			}
			if gotFull.SchemaVersion != SchemaVersion || gotProbe.SchemaVersion != SchemaVersion {
				t.Errorf("collected schemaVersion full=%d probe=%d, want %d", gotFull.SchemaVersion, gotProbe.SchemaVersion, SchemaVersion)
			}
			if gotFull.Verdict != full.Verdict || gotFull.Role != full.Role || gotProbe.Verdict != probe.Verdict || gotProbe.Role != probe.Role {
				t.Errorf("golden pair %s no longer matches the collectors' verdict/role", name)
			}
			if got, want := stateTable(gotProbe.Daemons), stateTable(probe.Daemons); got != want {
				t.Errorf("probe daemons: collected %s, golden %s", got, want)
			}
			if got, want := stateTable(gotFull.Rows), stateTable(full.Rows); got != want {
				t.Errorf("full rows: collected %s, golden %s", got, want)
			}
			for _, pair := range [][2][]Row{{gotFull.Rows, full.Rows}, {gotProbe.Daemons, probe.Daemons}} {
				for i := range pair[0] {
					if i < len(pair[1]) && !reflect.DeepEqual(pair[0][i].Alert, pair[1][i].Alert) {
						t.Errorf("%s alert: collected %+v, golden %+v", pair[0][i].Name, pair[0][i].Alert, pair[1][i].Alert)
					}
				}
			}
			if !reflect.DeepEqual(gotFull.Interconnect, full.Interconnect) {
				t.Errorf("interconnect block: collected %+v, golden %+v", gotFull.Interconnect, full.Interconnect)
			}
			if !reflect.DeepEqual(gotFull.Workers, full.Workers) {
				t.Errorf("workers: collected %v, golden %v", deref(gotFull.Workers), deref(full.Workers))
			}
			if !reflect.DeepEqual(gotFull.Network, full.Network) {
				t.Errorf("network: collected %+v, golden %+v", networkOf(gotFull.Network), networkOf(full.Network))
			}
			if !reflect.DeepEqual(gotProbe.Network, probe.Network) {
				t.Errorf("probe network: collected %+v, golden %+v", networkOf(gotProbe.Network), networkOf(probe.Network))
			}
			if !reflect.DeepEqual(gotFull.Capabilities, full.Capabilities) || !reflect.DeepEqual(full.Capabilities, []string{CapabilityWatchJSON}) {
				t.Errorf("capabilities: collected %v, golden %v, want [%s]", gotFull.Capabilities, full.Capabilities, CapabilityWatchJSON)
			}
			if gotFull.JoinTarget != full.JoinTarget {
				t.Errorf("joinTarget: collected %q, golden %q", gotFull.JoinTarget, full.JoinTarget)
			}
		})
	}

	t.Run("coverage", func(t *testing.T) {
		for v := range contractVerdicts {
			if !verdictsSeen[v] {
				t.Errorf("no golden carries the verdict %q", v)
			}
		}
		for _, s := range contractDaemonStates {
			if !daemonStatesSeen[s] {
				t.Errorf("no golden carries a daemon row in state %q", s)
			}
		}
		// Every optional key appears in some golden, so a rename of a key that
		// one fixture omits still fails in another. peers is the exception: it
		// is reserved, and no posture emits it yet (the struct check covers it).
		for _, k := range append(append(append(append([]string{"next", "interconnect", "stoppedBy", "workers", "joinTarget", "network"}, rowOptional...), versionOptional...), interconnectOptional...), append(networkOptional, append(alertOptional, fixStepOptional...)...)...) {
			if !optionalSeen[k] {
				t.Errorf("no golden carries the optional key %q", k)
			}
		}
	})
}

// stateTable renders rows as name=state/severity, the contract-level facts a
// golden pins without pinning prose.
func stateTable(rows []Row) string {
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, r.Name+"="+string(r.State)+"/"+r.Severity.String())
	}
	return strings.Join(parts, " ")
}

func contains(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func containsState(set []RowState, s RowState) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// countingKube counts every apiserver call, so a test can prove a path made
// none and that the same collector's full report did make some.
type countingKube struct{ calls *atomic.Int32 }

func (k countingKube) RawGet(context.Context, string) ([]byte, error) {
	k.calls.Add(1)
	return []byte("ok"), nil
}

func (k countingKube) Nodes(context.Context) ([]corev1.Node, error) {
	k.calls.Add(1)
	return nil, nil
}

func (k countingKube) Pods(context.Context) ([]corev1.Pod, error) {
	k.calls.Add(1)
	return nil, nil
}

func (k countingKube) Server() string     { return "https://127.0.0.1:6444" }
func (k countingKube) TLSPosture() string { return "ca pinned" }

// countingRuntimed counts runtime-socket calls.
type countingRuntimed struct{ calls *atomic.Int32 }

func (r countingRuntimed) Info(context.Context) (*runtimev1.GetRuntimeInfoResponse, error) {
	r.calls.Add(1)
	return &runtimev1.GetRuntimeInfoResponse{Healthy: true}, nil
}

// fatalVolumes fails the test if diskutil is ever consulted. The embedded nil
// interface makes any other method panic, which fails the test as loudly.
type fatalVolumes struct {
	datavol.Volumes
	t *testing.T
}

func (v fatalVolumes) Info(context.Context, string) (datavol.Info, error) {
	v.t.Error("the daemons probe consulted diskutil")
	return datavol.Info{}, errors.New("not reached")
}

// TestDaemonsProbeNeverReachesTheAPIServer pins what makes the probe cheap:
// with every remote seam wired (an apiserver client, the runtime socket, as
// root so the socket is reachable, and the optional readers), CollectDaemons
// calls none of them. The same collector's full report is run as the control,
// so the test cannot pass because the seams were unreachable anyway.
func TestDaemonsProbeNeverReachesTheAPIServer(t *testing.T) {
	t.Parallel()
	var kubeCalls, runtimedCalls, optionalCalls atomic.Int32
	c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", countingKube{&kubeCalls}, nil)
	c.EUID = 0
	c.Runtimed = countingRuntimed{&runtimedCalls}
	c.ServerArgs = func([]byte) ([]string, error) { optionalCalls.Add(1); return nil, nil }
	c.NodeResolverPresent = func() (bool, error) { optionalCalls.Add(1); return true, nil }
	c.CDHash = func(string) (string, error) { optionalCalls.Add(1); return "", nil }
	c.EtcdMetrics = func(context.Context, string) ([]byte, error) { optionalCalls.Add(1); return nil, nil }
	c.Network = contractRecordOff // so a reached NetworkApplied would be called
	c.NetworkApplied = func(install.Role) ([]byte, error) { optionalCalls.Add(1); return nil, nil }

	probe := c
	probe.Volumes = fatalVolumes{t: t}
	rep := probe.CollectDaemons()
	if rep.Verdict != VerdictRunning {
		t.Fatalf("probe verdict = %v (%s), want running", rep.Verdict, rep.Summary)
	}
	if n := kubeCalls.Load(); n != 0 {
		t.Errorf("the daemons probe made %d apiserver calls, want 0", n)
	}
	if n := runtimedCalls.Load(); n != 0 {
		t.Errorf("the daemons probe made %d runtime-socket calls, want 0", n)
	}
	if n := optionalCalls.Load(); n != 0 {
		t.Errorf("the daemons probe called %d optional readers, want 0", n)
	}

	t.Run("a nil client is never needed", func(t *testing.T) {
		bare := Collector{Launchd: c.Launchd, FS: c.FS, Procs: c.Procs, DataRoot: c.DataRoot, Paths: c.Paths, EUID: c.EUID, ServiceUID: c.ServiceUID, Now: c.Now}
		if got := bare.CollectDaemons(); got.Verdict != VerdictRunning || got.SchemaVersion != SchemaVersion {
			t.Errorf("probe with no apiserver seam = %v (schemaVersion %d), want running", got.Verdict, got.SchemaVersion)
		}
	})

	t.Run("control: the full report does reach them", func(t *testing.T) {
		c.Collect(context.Background())
		if kubeCalls.Load() == 0 || runtimedCalls.Load() == 0 {
			t.Fatalf("the full report made %d apiserver and %d runtime calls; the probe's zero proves nothing", kubeCalls.Load(), runtimedCalls.Load())
		}
	})
}
