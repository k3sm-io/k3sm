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
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/install"
)

// TestLifecycleVerbsRefuseWithoutRoot pins the named not-root exit code: the
// refusal comes before anything is read or changed.
func TestLifecycleVerbsRefuseWithoutRoot(t *testing.T) {
	orig := lifecycleGeteuid
	lifecycleGeteuid = func() int { return 501 }
	t.Cleanup(func() { lifecycleGeteuid = orig })
	for verb, run := range map[string]func([]string, *bytes.Buffer) int{
		"stop":    func(a []string, w *bytes.Buffer) int { return runStop(a, w) },
		"start":   func(a []string, w *bytes.Buffer) int { return runStart(a, w) },
		"restart": func(a []string, w *bytes.Buffer) int { return runRestart(a, w) },
	} {
		var stderr bytes.Buffer
		if code := run(nil, &stderr); code != exitNeedsRoot {
			t.Errorf("%s without root exited %d, want %d", verb, code, exitNeedsRoot)
		}
		if !strings.Contains(stderr.String(), "sudo k3sm "+verb) {
			t.Errorf("%s refusal does not name the remedy: %q", verb, stderr.String())
		}
		var usage bytes.Buffer
		if code := run([]string{"--no-such-flag"}, &usage); code != exitLifecycleUsage {
			t.Errorf("%s with a bad flag exited %d, want %d", verb, code, exitLifecycleUsage)
		}
	}
}

// TestStopHelpStatesTheTimeBound pins that the help carries the computed
// server stop bound and the exit-code table.
func TestStopHelpStatesTheTimeBound(t *testing.T) {
	help := stopUsage()
	for _, want := range []string{install.StopTimeBound().String(), "32+N", "exit codes"} {
		if !strings.Contains(strings.ToLower(help), strings.ToLower(want)) {
			t.Errorf("stop help lacks %q:\n%s", want, help)
		}
	}
	if got := install.StopTimeBound(); got != 150*time.Second {
		t.Errorf("StopTimeBound = %s; the help text's breakdown (15+60+15+15+10+5+30) sums to 150s", got)
	}
}

// TestLifecycleExitMapsLeftovers pins the exit code of a partial stop.
func TestLifecycleExitMapsLeftovers(t *testing.T) {
	var stderr bytes.Buffer
	err := &install.StopIncompleteError{Left: []install.LeftoverItem{
		{Kind: install.LeftoverMesh, Err: errors.New("netd refused")},
		{Kind: install.LeftoverLo0, Err: errors.New("ifconfig failed")},
	}}
	if code := lifecycleExit("stop", err, &stderr); code != install.StopExitLeftoverBase+4+8 {
		t.Errorf("exit = %d, want %d", code, install.StopExitLeftoverBase+4+8)
	}
	// Every class at once stays below the shell's reserved 126 and 127.
	var all []install.LeftoverItem
	for _, k := range []install.Leftover{install.LeftoverNodeDaemon, install.LeftoverPods, install.LeftoverMesh, install.LeftoverLo0, install.LeftoverNetd, install.LeftoverMarker} {
		all = append(all, install.LeftoverItem{Kind: k, Err: errors.New("x")})
	}
	if code := (&install.StopIncompleteError{Left: all}).ExitCode(); code != 95 {
		t.Errorf("every leftover class exits %d, want 95 (never 126 or 127)", code)
	}
	if !strings.Contains(stderr.String(), "mesh") || !strings.Contains(stderr.String(), "lo0-aliases") {
		t.Errorf("stderr does not name the leftovers: %q", stderr.String())
	}
	if code := lifecycleExit("stop", errors.New("boom"), &stderr); code != exitLifecycleFailed {
		t.Errorf("plain failure exit = %d, want %d", code, exitLifecycleFailed)
	}
}

// TestMarkNodeObject pins the cordon contract: a stop cordons and annotates,
// a start undoes only the cordon the stop made, and a start on a node with no
// annotation changes nothing.
func TestMarkNodeObject(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	get := func(t *testing.T, cs *fake.Clientset) *corev1.Node {
		t.Helper()
		n, err := cs.CoreV1().Nodes().Get(ctx, "k3sm-mac", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("stop then start on a schedulable node", func(t *testing.T) {
		cs := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-mac"}})
		if err := markNodeObject(ctx, cs, "k3sm-mac", true, "user", "plane", now); err != nil {
			t.Fatal(err)
		}
		n := get(t, cs)
		var a stopAnnotation
		if err := json.Unmarshal([]byte(n.Annotations[StoppedByUserAnnotation]), &a); err != nil || !n.Spec.Unschedulable || !a.Cordoned || a.Actor != "user" || a.Reason != "plane" {
			t.Fatalf("after stop: unschedulable %v, annotation %+v (%v)", n.Spec.Unschedulable, a, err)
		}
		if err := markNodeObject(ctx, cs, "k3sm-mac", false, "user", "home", now); err != nil {
			t.Fatal(err)
		}
		n = get(t, cs)
		if _, ok := n.Annotations[StoppedByUserAnnotation]; ok || n.Spec.Unschedulable {
			t.Errorf("after start: unschedulable %v, annotations %v", n.Spec.Unschedulable, n.Annotations)
		}
	})
	t.Run("a node an administrator cordoned stays cordoned after start", func(t *testing.T) {
		cs := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-mac"}, Spec: corev1.NodeSpec{Unschedulable: true}})
		if err := markNodeObject(ctx, cs, "k3sm-mac", true, "user", "plane", now); err != nil {
			t.Fatal(err)
		}
		if err := markNodeObject(ctx, cs, "k3sm-mac", false, "user", "home", now); err != nil {
			t.Fatal(err)
		}
		if n := get(t, cs); !n.Spec.Unschedulable {
			t.Error("start uncordoned a node the stop did not cordon")
		}
	})
	t.Run("start with no annotation changes nothing", func(t *testing.T) {
		cs := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-mac"}, Spec: corev1.NodeSpec{Unschedulable: true}})
		if err := markNodeObject(ctx, cs, "k3sm-mac", false, "user", "home", now); err != nil {
			t.Fatal(err)
		}
		for _, a := range cs.Actions() {
			if a.GetVerb() == "patch" {
				t.Errorf("start patched a node with no stop annotation: %v", a)
			}
		}
	})
}

// TestServiceCredentialDropsRootGroups pins the RemoveMesh child's identity:
// the service uid and gid, and a supplementary list of only that gid, set
// explicitly so none of root's groups is inherited.
func TestServiceCredentialDropsRootGroups(t *testing.T) {
	c := serviceCredential(271, 20)
	if c.Uid != 271 || c.Gid != 20 || c.NoSetGroups || len(c.Groups) != 1 || c.Groups[0] != 20 {
		t.Errorf("credential = %+v, want uid 271, gid 20, Groups [20], NoSetGroups false", c)
	}
	for _, g := range c.Groups {
		if g == 0 {
			t.Errorf("credential carries root's group 0: %+v", c)
		}
	}
}

// TestCountJoinedWorkers counts every Node but the server's own.
func TestCountJoinedWorkers(t *testing.T) {
	cs := fake.NewClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-studio"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-book"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "k3sm-mini"}},
	)
	if n, err := countJoinedWorkers(context.Background(), cs, "k3sm-studio"); err != nil || n != 2 {
		t.Errorf("countJoinedWorkers = %d, %v; want 2", n, err)
	}
}

// TestLifecycleContextIsBounded pins that a stop or start runs under a
// deadline of its bound plus the margin.
func TestLifecycleContextIsBounded(t *testing.T) {
	ctx, cancel := lifecycleContext(time.Minute)
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("the lifecycle context has no deadline")
	}
	if left := time.Until(dl); left > time.Minute+lifecycleMargin || left < time.Minute {
		t.Errorf("deadline in %s, want about %s", left, time.Minute+lifecycleMargin)
	}
}
