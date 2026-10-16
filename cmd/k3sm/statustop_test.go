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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k3sm.io/k3sm/pkg/status"
)

// topFixtureNow is the clock the top fixtures are written against: the node
// sample is 9 seconds old at this instant.
var topFixtureNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// fixtureKube is the apiserver seam answered from testdata/top: the core lists
// decode into the typed objects, and every raw path maps onto a fixture file.
// A path with no file answers NotFound, as the apiserver does.
type fixtureKube struct {
	t     *testing.T
	files map[string]string
	// gets counts the raw reads per path.
	gets map[string]int
}

func (f *fixtureKube) read(name string) []byte {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "top", name))
	if err != nil {
		f.t.Fatalf("read fixture: %v", err)
	}
	return b
}

func (f *fixtureKube) RawGet(_ context.Context, path string) ([]byte, error) {
	if f.gets == nil {
		f.gets = map[string]int{}
	}
	f.gets[path]++
	name, ok := f.files[path]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "apiregistration.k8s.io", Resource: "apiservices"}, filepath.Base(path))
	}
	return f.read(name), nil
}

func (f *fixtureKube) Nodes(context.Context) ([]corev1.Node, error) {
	var l corev1.NodeList
	if err := json.Unmarshal(f.read("nodes.json"), &l); err != nil {
		f.t.Fatalf("decode nodes: %v", err)
	}
	return l.Items, nil
}

func (f *fixtureKube) Pods(context.Context) ([]corev1.Pod, error) {
	var l corev1.PodList
	if err := json.Unmarshal(f.read("pods.json"), &l); err != nil {
		f.t.Fatalf("decode pods: %v", err)
	}
	return l.Items, nil
}

func (f *fixtureKube) Server() string     { return "https://127.0.0.1:6443" }
func (f *fixtureKube) TLSPosture() string { return "ca pinned" }

// topFiles is the fixture set of a cluster whose metrics API serves.
func topFiles(apiservice string) map[string]string {
	return map[string]string{
		"/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io": apiservice,
		"/apis/metrics.k8s.io/v1beta1/nodes":                                 "node-metrics.json",
		"/apis/metrics.k8s.io/v1beta1/pods":                                  "pod-metrics.json",
	}
}

// topRun runs `k3sm status <args>` against the fixture cluster and returns the
// exit code and stdout.
func topRun(t *testing.T, kube *fixtureKube, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	o, err := parseStatusArgs(args, &errOut)
	if err != nil {
		t.Fatalf("parse %q: %v", args, err)
	}
	r := testRunner(&out, &errOut, func(context.Context) status.Report {
		t.Fatal("the full report was collected for the top view")
		return status.Report{}
	})
	r.top = lazyTop(func(context.Context) *status.TopCollector {
		return &status.TopCollector{Kube: kube, Now: func() time.Time { return topFixtureNow }}
	})
	code := r.run(context.Background(), o)
	return code, out.String(), errOut.String()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", "top", name))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// TestStatusTopRendersNodesAndPods is the gate on `k3sm status top`: fixture
// nodes, pods and metrics in, the hand-reviewed screen out. It pins the node
// table (usage over allocatable with whole percentages, a node with no sample
// saying so, the sample's age), the pod table (terminated pods left out, an
// unscheduled pod kept, sorted by cpu then memory, sidecar restarts counted,
// an init container's not) and the header line.
func TestStatusTopRendersNodesAndPods(t *testing.T) {
	t.Parallel()
	code, out, errOut := topRun(t, &fixtureKube{t: t, files: topFiles("apiservice-available.json")}, "top", "--no-color")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	golden(t, "render.txt", out)
}

// TestStatusTopUnavailableMetrics pins the screen when the metrics API is not
// there: the header carries the APIService's own reason and message, and the
// tables show what the core API has.
func TestStatusTopUnavailableMetrics(t *testing.T) {
	t.Parallel()
	t.Run("Available False", func(t *testing.T) {
		t.Parallel()
		code, out, _ := topRun(t, &fixtureKube{t: t, files: topFiles("apiservice-unavailable.json")}, "top")
		if code != 0 {
			t.Fatalf("exit = %d, want 0: the cluster was read", code)
		}
		golden(t, "render_unavailable.txt", out)
	})
	t.Run("not registered", func(t *testing.T) {
		t.Parallel()
		code, out, _ := topRun(t, &fixtureKube{t: t, files: map[string]string{}}, "top")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		first, _, _ := strings.Cut(out, "\n")
		want := "metrics: unavailable (NotRegistered: the APIService v1beta1.metrics.k8s.io does not exist; metrics-server is not installed); showing nodes and pods without usage"
		if first != want {
			t.Errorf("header = %q, want %q", first, want)
		}
	})
}

// TestStatusTopJSON pins the -o json shape: the same rows as the screen, with
// null usage where there is no sample.
func TestStatusTopJSON(t *testing.T) {
	t.Parallel()
	code, out, _ := topRun(t, &fixtureKube{t: t, files: topFiles("apiservice-available.json")}, "top", "-o", "json", "--limit", "3")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	golden(t, "top.json", out)
}

// TestStatusTopClusterUnreadable: with no apiserver client the view says why
// and exits with the unknown code, never 0.
func TestStatusTopClusterUnreadable(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, nil)
	r.top = lazyTop(func(context.Context) *status.TopCollector {
		return &status.TopCollector{KubeErr: os.ErrPermission}
	})
	o, err := parseStatusArgs([]string{"top"}, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if code := r.run(context.Background(), o); code != status.VerdictUnknown.ExitCode() {
		t.Fatalf("exit = %d, want %d", code, status.VerdictUnknown.ExitCode())
	}
	if want := "cluster: unreachable, permission denied\n"; out.String() != want {
		t.Errorf("screen = %q, want %q", out.String(), want)
	}
}

// TestStatusTopWatchPollsMetricsAtMostEvery5s drives the watch loop at 2s
// frames on a moving clock: the nodes, pods and APIService are read every
// frame, the metrics API only when 5 seconds have passed since its last read.
func TestStatusTopWatchPollsMetricsAtMostEvery5s(t *testing.T) {
	t.Parallel()
	kube := &fixtureKube{t: t, files: topFiles("apiservice-available.json")}
	now := topFixtureNow
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, nil)
	r.stdoutTTY = true
	frames := 0
	r.sleep = func(_ context.Context, d time.Duration) bool {
		now = now.Add(d)
		frames++
		return frames < 6
	}
	r.top = lazyTop(func(context.Context) *status.TopCollector {
		return &status.TopCollector{Kube: kube, Now: func() time.Time { return now }}
	})
	o, err := parseStatusArgs([]string{"top", "--watch=2s"}, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if code := r.run(context.Background(), o); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr %s", code, errOut.String())
	}
	// Six frames at t = 0, 2, 4, 6, 8, 10 s: metrics are read at 0 and 6 only
	// (10 s is 4 s after the last read).
	if got := kube.gets["/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io"]; got != 6 {
		t.Errorf("APIService reads = %d, want one per frame (6)", got)
	}
	if got := kube.gets["/apis/metrics.k8s.io/v1beta1/nodes"]; got != 2 {
		t.Errorf("node metrics reads = %d, want 2", got)
	}
	if got := kube.gets["/apis/metrics.k8s.io/v1beta1/pods"]; got != 2 {
		t.Errorf("pod metrics reads = %d, want 2", got)
	}
	// The node sample is stamped 9 s before the first frame, so the last frame
	// shows it 19 s old: the age column carries the lag.
	if !strings.Contains(out.String(), "19s") {
		t.Errorf("the last frame does not show the sample aging:\n%s", out.String())
	}
}

// TestStatusTopArgs pins the flag rules: the top flags parse for top and are
// refused elsewhere, bad values are usage errors, and `status top --help`
// answers 0, which is how the app learns the view exists.
func TestStatusTopArgs(t *testing.T) {
	t.Parallel()
	o, err := parseStatusArgs([]string{"top", "--sort", "memory", "-n", "default", "--limit", "5"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := o.topOptions(), (status.TopOptions{Sort: status.TopSortMemory, Namespace: "default", Limit: 5}); got != want {
		t.Errorf("top options = %+v, want %+v", got, want)
	}
	o, err = parseStatusArgs([]string{"top"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := o.topOptions(), (status.TopOptions{Sort: status.TopSortCPU, Limit: status.DefaultTopLimit}); got != want {
		t.Errorf("default top options = %+v, want %+v", got, want)
	}

	for _, args := range [][]string{
		{"--sort", "cpu"},
		{"cluster", "-n", "default"},
		{"--limit", "3"},
		{"top", "--sort", "disk"},
		{"top", "--limit", "-1"},
		{"top", "-o", "wide"},
		{"top", "--wait"},
	} {
		if _, err := parseStatusArgs(args, &bytes.Buffer{}); err == nil {
			t.Errorf("parse %q: want a usage error", args)
		}
	}

	if !strings.Contains(statusUsage, "  top ") {
		t.Error("statusUsage does not list the top view")
	}
	for _, flag := range []string{"--sort", "-n <namespace>", "--limit"} {
		if !strings.Contains(statusUsage, flag) {
			t.Errorf("statusUsage does not document %s", flag)
		}
	}
}

// TestStatusViewHelp: --help on a real view prints the usage to stdout and
// exits 0; on an unknown view it is a usage error. The app shows its live top
// item only when `k3sm status top --help` exits 0.
func TestStatusViewHelp(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"top", "--help"}, 0},
		{[]string{"daemons", "--help"}, 0},
		{[]string{"logs", "server", "-h"}, 0},
		{[]string{"-o", "json", "--help"}, 0},
		{[]string{"bogus", "--help"}, exitUsage},
	} {
		var out, errOut bytes.Buffer
		_, err := parseStatusArgs(tc.args, &errOut)
		if err == nil {
			t.Fatalf("parse %q: want an error to answer", tc.args)
		}
		if got := statusArgsExit(err, &out, &errOut); got != tc.want {
			t.Errorf("%q exit = %d, want %d", tc.args, got, tc.want)
		}
		if tc.want == 0 && out.String() != statusUsage {
			t.Errorf("%q did not print the usage to stdout", tc.args)
		}
		if tc.want != 0 && out.Len() != 0 {
			t.Errorf("%q wrote to stdout: %q", tc.args, out.String())
		}
	}
	if got := runStatus([]string{"bogus", "--help"}); got != exitUsage {
		t.Errorf("runStatus bogus --help = %d, want %d", got, exitUsage)
	}
}
