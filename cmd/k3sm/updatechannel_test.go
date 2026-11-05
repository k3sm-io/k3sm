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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/updatectl"
)

// channelIndex is a fake release index that counts what it is asked: stable is
// behind the latest redirect, and listed is the releases listing the rc channel
// reads.
type channelIndex struct {
	stable string
	listed []string
	// listFails makes the listing answer 500.
	listFails bool
	// redirects and lists count the two kinds of read.
	redirects, lists atomic.Int32
}

func (x *channelIndex) client() *http.Client {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		x.redirects.Add(1)
		http.Redirect(w, r, "/releases/tag/"+x.stable, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": strings.TrimPrefix(r.URL.Path, "/releases/tags/"), "published_at": "2026-10-01T00:00:00Z"})
	})
	mux.HandleFunc("/releases", func(w http.ResponseWriter, _ *http.Request) {
		x.lists.Add(1)
		if x.listFails {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		list := []map[string]any{}
		for _, tag := range x.listed {
			list = append(list, map[string]any{"tag_name": tag, "draft": false, "published_at": "2026-10-01T00:00:00Z"})
		}
		_ = json.NewEncoder(w).Encode(list)
	})
	return &http.Client{Transport: handlerTransport{mux}}
}

// setPolicy stores the UpdatePolicy with channel, as the apiserver serves it.
func (c updateCluster) setPolicy(t *testing.T, channel string) {
	t.Helper()
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": updatesv1alpha1.SchemeGroupVersion.String(),
		"kind":       "UpdatePolicy",
		"metadata":   map[string]any{"name": updatesv1alpha1.UpdatePolicyName},
		"spec":       map[string]any{"channel": channel},
	}}
	if _, err := c.dyn.Resource(updatePolicyGVR).Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// policyAnswers makes every read of the UpdatePolicy answer err.
func (c updateCluster) policyAnswers(err error) {
	c.dyn.PrependReactor("get", updatePolicyGVR.Resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
}

// policyReads counts the reads of the UpdatePolicy so far.
func (c updateCluster) policyReads() int {
	n := 0
	for _, a := range c.dyn.Actions() {
		if a.GetResource().Resource == updatePolicyGVR.Resource {
			n++
		}
	}
	return n
}

// publishingServer is a control-plane Node carrying a published pair; an empty
// channel is an older server's pair, with no channel annotation.
func publishingServer(name, latest, channel string) *corev1.Node {
	n := kubeletNode(name, "v1.37.1+k3sm.0.2.0")
	n.Labels = map[string]string{"node-role.kubernetes.io/control-plane": "true"}
	n.Annotations = map[string]string{
		status.NodeReleaseLatestAnnotation:  latest,
		status.NodeReleaseCheckedAnnotation: "2026-10-15T11:00:00Z",
	}
	if channel != "" {
		n.Annotations[updatesv1alpha1.AnnotationReleaseChannel] = channel
	}
	return n
}

// checkReport runs `k3sm update check -o json` and returns the report, the
// stderr and the record it left.
func checkReport(t *testing.T, c updateCluster, x *channelIndex, mutate func(*updateEnv)) (int, update.Report, string, status.UpdateRecord) {
	t.Helper()
	wd := installedWorkDir(t)
	code, out, errOut := c.runWith(t, func(env *updateEnv) {
		env.inputs.HTTP = x.client()
		env.workDir = wd
		if mutate != nil {
			mutate(env)
		}
	}, "check", "-o", "json")
	var rep update.Report
	if code == 0 {
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("report %q: %v", out, err)
		}
	}
	return code, rep, errOut, readUpdateRecord(wd)
}

// TestUpdateCheckReadsTheChannelFromItsSource is the channel's one reading rule
// as the verbs and the recorder see it: an identity that may read the UpdatePolicy
// reads it, any other reads the pair a server publishes, and a node with no
// setting anywhere stays on stable with no new failure.
func TestUpdateCheckReadsTheChannelFromItsSource(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: updatesv1alpha1.GroupName, Resource: updatePolicyGVR.Resource}, updatesv1alpha1.UpdatePolicyName, errors.New("no rule"))
	const stable, rc = updatesv1alpha1.UpdateChannelStable, updatesv1alpha1.UpdateChannelRC

	t.Run("NotFound is stable", func(t *testing.T) {
		x := &channelIndex{stable: "v0.2.3", listed: []string{"v0.2.3", "v0.3.0-rc.1"}}
		code, rep, errOut, rec := checkReport(t, newUpdateCluster(), x, nil)
		if code != 0 || rep.Channel != stable || rep.Latest.Tag != "v0.2.3" || errOut != "" {
			t.Fatalf("exit %d, report %+v, stderr %q", code, rep, errOut)
		}
		if x.lists.Load() != 0 || x.redirects.Load() != 1 {
			t.Errorf("stable read %d redirects and %d listings, want the one redirect", x.redirects.Load(), x.lists.Load())
		}
		if rec.Channel != stable || rec.Error != "" {
			t.Errorf("record = %+v", rec)
		}
	})

	t.Run("a server with no CRD is stable", func(t *testing.T) {
		c := newUpdateCluster()
		c.policyAnswers(apierrors.NewGenericServerResponse(http.StatusNotFound, "get", schema.GroupResource{Group: updatesv1alpha1.GroupName, Resource: updatePolicyGVR.Resource}, "", "the server could not find the requested resource", 0, true))
		code, rep, errOut, _ := checkReport(t, c, &channelIndex{stable: "v0.2.3"}, nil)
		if code != 0 || rep.Channel != stable || errOut != "" {
			t.Errorf("exit %d, report %+v, stderr %q", code, rep, errOut)
		}
	})

	t.Run("no cluster is stable and says so", func(t *testing.T) {
		x := &channelIndex{stable: "v0.2.3"}
		code, rep, errOut, _ := checkReport(t, newUpdateCluster(), x, func(env *updateEnv) {
			env.dyn, env.inputs.Kube, env.kubeErr = nil, nil, errors.New("no kubeconfig")
		})
		if code != 0 || rep.Channel != stable || rep.Latest.Tag != "v0.2.3" {
			t.Fatalf("exit %d, report %+v", code, rep)
		}
		if !strings.Contains(errOut, "no cluster to read the update channel from; checking as stable") {
			t.Errorf("stderr %q does not say so", errOut)
		}
	})

	t.Run("an empty channel is stable", func(t *testing.T) {
		c := newUpdateCluster()
		c.setPolicy(t, "")
		code, rep, _, _ := checkReport(t, c, &channelIndex{stable: "v0.2.3"}, nil)
		if code != 0 || rep.Channel != stable {
			t.Errorf("exit %d, report %+v", code, rep)
		}
	})

	t.Run("the object on rc lists and offers the highest", func(t *testing.T) {
		c := newUpdateCluster()
		c.setPolicy(t, "rc")
		x := &channelIndex{stable: "v0.2.3", listed: []string{"v0.3.0-rc.9", "v0.2.3", "v0.3.0-rc.10"}}
		code, rep, _, rec := checkReport(t, c, x, nil)
		if code != 0 || rep.Channel != rc || rep.Latest.Tag != "v0.3.0-rc.10" || x.lists.Load() != 1 {
			t.Fatalf("exit %d, report %+v, %d listings", code, rep, x.lists.Load())
		}
		if rec.Channel != rc || rec.Latest != "v0.3.0-rc.10" {
			t.Errorf("record = %+v", rec)
		}
	})

	t.Run("text names the channel first", func(t *testing.T) {
		c := newUpdateCluster()
		c.setPolicy(t, "rc")
		x := &channelIndex{listed: []string{"v0.3.0-rc.1"}}
		code, out, errOut := c.runWith(t, func(env *updateEnv) { env.inputs.HTTP = x.client() }, "check")
		if code != 0 || !strings.HasPrefix(out, "channel ") || !strings.Contains(strings.SplitN(out, "\n", 2)[0], "rc") {
			t.Errorf("exit %d, stderr %q, output:\n%s", code, errOut, out)
		}
	})

	t.Run("another error fails", func(t *testing.T) {
		c := newUpdateCluster()
		c.policyAnswers(apierrors.NewInternalError(errors.New("etcd away")))
		x := &channelIndex{stable: "v0.2.3"}
		code, _, errOut, rec := checkReport(t, c, x, nil)
		if code != exitInternalError || !strings.Contains(errOut, errChannelUnreadable.Error()) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if x.redirects.Load()+x.lists.Load() != 0 {
			t.Error("a channel it could not read still asked the release index")
		}
		if !strings.Contains(rec.Error, errChannelUnreadable.Error()) || rec.Latest != "" {
			t.Errorf("record = %+v", rec)
		}
		row := status.UpdateRowFrom(rec, rec.CheckedAt)
		if row.State != status.StateUnknown || !strings.Contains(row.Detail, errChannelUnreadable.Error()) {
			t.Errorf("row = %+v", row)
		}
	})

	t.Run("Forbidden reads the pair", func(t *testing.T) {
		c := newUpdateCluster(publishingServer("studio", "v0.3.0-rc.2", "rc"))
		c.policyAnswers(forbidden)
		x := &channelIndex{stable: "v0.2.3", listed: []string{"v9.9.9"}}
		code, rep, errOut, _ := checkReport(t, c, x, nil)
		if code != 0 || rep.Channel != rc || rep.Latest.Tag != "v0.3.0-rc.2" || errOut != "" {
			t.Fatalf("exit %d, report %+v, stderr %q", code, rep, errOut)
		}
		if x.lists.Load()+x.redirects.Load() != 0 {
			t.Errorf("a reader of the pair on rc asked the index %d times; only a server lists", x.lists.Load()+x.redirects.Load())
		}
	})

	t.Run("the newest checked server's pair wins, as one pair", func(t *testing.T) {
		older := publishingServer("a-old", "v0.3.0-rc.1", "rc")
		newer := publishingServer("z-new", "v0.2.3", "stable")
		newer.Annotations[status.NodeReleaseCheckedAnnotation] = "2026-10-15T11:30:00Z"
		c := newUpdateCluster(older, newer)
		c.policyAnswers(forbidden)
		x := &channelIndex{stable: "v0.2.3"}
		code, rep, _, _ := checkReport(t, c, x, nil)
		if code != 0 || rep.Channel != stable {
			t.Errorf("exit %d, report %+v", code, rep)
		}
	})

	t.Run("a pair with no channel is an older server's, stable", func(t *testing.T) {
		c := newUpdateCluster(publishingServer("studio", "v0.2.3", ""))
		c.policyAnswers(forbidden)
		code, rep, errOut, _ := checkReport(t, c, &channelIndex{stable: "v0.2.3"}, nil)
		if code != 0 || rep.Channel != stable || errOut != "" {
			t.Errorf("exit %d, report %+v, stderr %q", code, rep, errOut)
		}
	})

	t.Run("Forbidden with no pair is stable and says so", func(t *testing.T) {
		c := newUpdateCluster(kubeletNode("studio", "v1.37.1+k3sm.0.2.0"))
		c.policyAnswers(forbidden)
		code, rep, errOut, _ := checkReport(t, c, &channelIndex{stable: "v0.2.3"}, nil)
		if code != 0 || rep.Channel != stable || !strings.Contains(errOut, "no server has published a channel") {
			t.Errorf("exit %d, report %+v, stderr %q", code, rep, errOut)
		}
	})

	t.Run("a worker reads only the pair", func(t *testing.T) {
		c := newUpdateCluster(publishingServer("studio", "v0.3.0-rc.2", "rc"))
		c.setPolicy(t, "stable")
		before := c.policyReads()
		x := &channelIndex{stable: "v0.2.3"}
		code, rep, _, _ := checkReport(t, c, x, func(env *updateEnv) { env.worker = true })
		if code != 0 || rep.Channel != rc || rep.Latest.Tag != "v0.3.0-rc.2" {
			t.Fatalf("exit %d, report %+v", code, rep)
		}
		if got := c.policyReads(); got != before || x.lists.Load() != 0 {
			t.Errorf("a worker read the object %d times and listed %d times", got-before, x.lists.Load())
		}
	})

	t.Run("a worker that cannot list Nodes is stable and says so", func(t *testing.T) {
		c := newUpdateCluster()
		c.cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver away")
		})
		src := channelSource{dyn: c.dyn, kube: c.cs, pairOnly: true}
		got, err := src.read(context.Background())
		if err != nil || got.channel != stable || !got.degraded || !strings.Contains(got.note, "the server's channel could not be read") {
			t.Errorf("reading = %+v, err %v", got, err)
		}
	})

	t.Run("an unknown value fails on a server", func(t *testing.T) {
		c := newUpdateCluster()
		c.setPolicy(t, "beta\x1b[2J")
		x := &channelIndex{stable: "v0.2.3"}
		code, _, errOut, rec := checkReport(t, c, x, nil)
		if code != exitInternalError || !strings.Contains(errOut, update.ErrUnknownChannel.Error()) || strings.Contains(errOut, "\x1b") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if x.redirects.Load()+x.lists.Load() != 0 || rec.Channel != "" {
			t.Errorf("an unknown value decoded as a channel: %d reads, record %+v", x.redirects.Load()+x.lists.Load(), rec)
		}
		_, err := channelSource{dyn: c.dyn, kube: c.cs}.read(context.Background())
		if !errors.Is(err, errChannelUnreadable) || !errors.Is(err, update.ErrUnknownChannel) {
			t.Errorf("err = %v, want both sentinels", err)
		}
	})

	t.Run("an unknown value degrades to stable on a worker and says why", func(t *testing.T) {
		c := newUpdateCluster(publishingServer("studio", "v0.3.0-rc.2", "beta"))
		x := &channelIndex{stable: "v0.2.3"}
		code, rep, errOut, _ := checkReport(t, c, x, func(env *updateEnv) { env.worker = true })
		if code != 0 || rep.Channel != stable || rep.Latest.Tag != "v0.2.3" {
			t.Fatalf("exit %d, report %+v", code, rep)
		}
		if !strings.Contains(errOut, "the server's channel could not be read") || !strings.Contains(errOut, `"beta"`) {
			t.Errorf("stderr %q does not say why", errOut)
		}
	})

	t.Run("a pair on rc whose latest is no release tag degrades", func(t *testing.T) {
		c := newUpdateCluster(publishingServer("studio", "v0.3.0-dev", "rc"))
		code, rep, errOut, _ := checkReport(t, c, &channelIndex{stable: "v0.2.3"}, func(env *updateEnv) { env.worker = true })
		if code != 0 || rep.Channel != stable || !strings.Contains(errOut, "could not be read") {
			t.Errorf("exit %d, report %+v, stderr %q", code, rep, errOut)
		}
	})

	// The recorder: a fixed clock inside the hour of a recorded check, a poll every
	// millisecond, and a counter of each read and check.
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	type recorderRun struct {
		polls, checks atomic.Int32
		channel       atomic.Value
		readErr       atomic.Pointer[error]
	}
	start := func(t *testing.T, live updatesv1alpha1.UpdateChannel, wd string, sink *syncBuffer, checkErr func() error, unreadable ...error) *recorderRun {
		t.Helper()
		run := &recorderRun{}
		run.channel.Store(live)
		if len(unreadable) == 1 {
			run.readErr.Store(&unreadable[0])
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		t.Cleanup(func() { cancel(); <-done })
		handler := slog.DiscardHandler
		if sink != nil {
			handler = slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo})
		}
		r := updateRecorder{
			workDir: wd,
			check: func(context.Context) (update.Report, error) {
				run.checks.Add(1)
				ch := run.channel.Load().(updatesv1alpha1.UpdateChannel)
				if checkErr != nil {
					if err := checkErr(); err != nil {
						if errors.Is(err, errChannelUnreadable) {
							return update.Report{CheckedAt: now}, err
						}
						return update.Report{CheckedAt: now, Channel: ch}, err
					}
				}
				return update.Report{CheckedAt: now, Channel: ch, Latest: update.Release{Tag: "v0.2.3"}, Nodes: []update.Node{}}, nil
			},
			readChannel: func(context.Context) (channelReading, error) {
				defer run.polls.Add(1)
				if e := run.readErr.Load(); e != nil {
					return channelReading{}, *e
				}
				return channelReading{channel: run.channel.Load().(updatesv1alpha1.UpdateChannel)}, nil
			},
			interval:  time.Hour,
			rollEvery: time.Millisecond,
			now:       func() time.Time { return now },
			logger:    slog.New(handler),
		}
		go func() {
			defer close(done)
			r.run(ctx)
		}()
		return run
	}
	waitFor := func(t *testing.T, what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(time.Millisecond)
		}
	}
	// settle waits for n more polls, so "no further check" means something.
	settle := func(t *testing.T, run *recorderRun, n int32) {
		t.Helper()
		from := run.polls.Load()
		waitFor(t, "polls", func() bool { return run.polls.Load() >= from+n })
	}
	freshRecord := func(t *testing.T, ch updatesv1alpha1.UpdateChannel) string {
		t.Helper()
		wd := installedWorkDir(t)
		if err := writeUpdateRecord(wd, status.UpdateRecord{CheckedAt: now.Add(-10 * time.Minute), Channel: ch, Latest: "v0.2.3"}); err != nil {
			t.Fatal(err)
		}
		return wd
	}

	t.Run("a recheck on a channel change", func(t *testing.T) {
		wd := freshRecord(t, stable)
		run := start(t, stable, wd, nil, nil)
		settle(t, run, 5)
		if got := run.checks.Load(); got != 0 {
			t.Fatalf("%d checks inside the hour with no change", got)
		}
		run.channel.Store(rc)
		waitFor(t, "the recheck", func() bool { return readUpdateRecord(wd).Channel == rc })
		settle(t, run, 20)
		if got := run.checks.Load(); got != 1 {
			t.Errorf("%d checks after one change, want 1", got)
		}
	})

	t.Run("a recheck after a restart inside the hour", func(t *testing.T) {
		for _, tc := range []struct{ recorded, live updatesv1alpha1.UpdateChannel }{{stable, rc}, {rc, stable}} {
			t.Run(fmt.Sprintf("%s to %s", tc.recorded, tc.live), func(t *testing.T) {
				wd := freshRecord(t, tc.recorded)
				run := start(t, tc.live, wd, nil, nil)
				waitFor(t, "the recheck", func() bool { return run.checks.Load() >= 1 })
				settle(t, run, 20)
				if got := run.checks.Load(); got != 1 {
					t.Errorf("%d checks, want 1", got)
				}
				if got := readUpdateRecord(wd).Channel; got != tc.live {
					t.Errorf("record channel = %q, want %q", got, tc.live)
				}
			})
		}
	})

	t.Run("a poll that beats the forced check asks for it once", func(t *testing.T) {
		live := rc
		r := updateRecorder{
			readChannel: func(context.Context) (channelReading, error) { return channelReading{channel: live}, nil },
			logger:      slog.New(slog.DiscardHandler),
		}
		w := channelWatch{attempted: stable}
		if !r.pollChannel(context.Background(), &w) {
			t.Fatal("a change asked for no check")
		}
		if r.pollChannel(context.Background(), &w) {
			t.Error("the same change asked for a second check")
		}
	})

	t.Run("an older record with no channel is stable, with no recheck", func(t *testing.T) {
		run := start(t, stable, freshRecord(t, ""), nil, nil)
		settle(t, run, 20)
		if got := run.checks.Load(); got != 0 {
			t.Errorf("%d checks; a record from before channels forced one", got)
		}
	})

	t.Run("a failed recheck waits for the interval", func(t *testing.T) {
		wd := freshRecord(t, stable)
		run := start(t, rc, wd, nil, func() error { return fmt.Errorf("resolve: %w", update.ErrChannelList) })
		waitFor(t, "the recheck", func() bool { return run.checks.Load() >= 1 })
		settle(t, run, 20)
		if got := run.checks.Load(); got != 1 {
			t.Errorf("%d checks; a failed listing is retried on every poll", got)
		}
		if rec := readUpdateRecord(wd); rec.Error == "" || rec.Channel != rc {
			t.Errorf("record = %+v", rec)
		}
		if status.UpdateAnnotations(readUpdateRecord(wd)) != nil {
			t.Error("a failed check publishes a pair")
		}
	})

	t.Run("a server with nowhere to record does not recheck on every poll", func(t *testing.T) {
		wd := t.TempDir() + "/server"
		r := start(t, rc, wd, nil, nil)
		waitFor(t, "the check", func() bool { return r.checks.Load() >= 1 })
		settle(t, r, 20)
		if got := r.checks.Load(); got != 1 {
			t.Errorf("%d checks with no record to compare with, want 1", got)
		}
	})

	t.Run("a channel readable again rechecks", func(t *testing.T) {
		var failing atomic.Bool
		failing.Store(true)
		wd := installedWorkDir(t)
		run := start(t, stable, wd, nil, func() error {
			if failing.Load() {
				return fmt.Errorf("%w: etcd away", errChannelUnreadable)
			}
			return nil
		}, fmt.Errorf("%w: etcd away", errChannelUnreadable))
		waitFor(t, "the failed check", func() bool { return strings.Contains(readUpdateRecord(wd).Error, "etcd away") })
		settle(t, run, 5)
		if got := run.checks.Load(); got != 1 {
			t.Fatalf("%d checks while the channel stays unreadable, want 1", got)
		}
		failing.Store(false)
		run.readErr.Store(nil)
		waitFor(t, "the recheck", func() bool { return readUpdateRecord(wd).Error == "" && run.checks.Load() >= 2 })
		settle(t, run, 20)
		if got := run.checks.Load(); got != 2 {
			t.Errorf("%d checks after the channel came back, want 2", got)
		}
	})

	t.Run("Warn logging", func(t *testing.T) {
		warns := func(sink *syncBuffer, msg string) int {
			n := 0
			for _, l := range strings.Split(sink.String(), "\n") {
				if strings.Contains(l, "level=WARN") && strings.Contains(l, msg) {
					n++
				}
			}
			return n
		}
		t.Run("a channel change", func(t *testing.T) {
			sink := &syncBuffer{}
			run := start(t, rc, freshRecord(t, stable), sink, nil)
			waitFor(t, "the recheck", func() bool { return run.checks.Load() >= 1 })
			settle(t, run, 10)
			if got := warns(sink, "the update channel changed"); got != 1 {
				t.Errorf("%d Warn lines, want 1:\n%s", got, sink.String())
			}
			if !strings.Contains(sink.String(), "from=stable to=rc") {
				t.Errorf("log does not name the change:\n%s", sink.String())
			}
		})
		t.Run("an unreadable policy, once", func(t *testing.T) {
			sink := &syncBuffer{}
			run := start(t, stable, freshRecord(t, stable), sink, nil, fmt.Errorf("%w: etcd away", errChannelUnreadable))
			settle(t, run, 20)
			if got := warns(sink, "could not read the update channel"); got != 1 {
				t.Errorf("%d Warn lines, want 1:\n%s", got, sink.String())
			}
		})
		t.Run("a failed listing", func(t *testing.T) {
			for _, sentinel := range []error{update.ErrChannelList, update.ErrChannelPageCap, update.ErrNoChannelRelease} {
				sink := &syncBuffer{}
				run := start(t, stable, installedWorkDir(t), sink, func() error { return fmt.Errorf("resolve: %w", sentinel) })
				waitFor(t, "the check", func() bool { return run.checks.Load() >= 1 })
				settle(t, run, 2)
				if got := warns(sink, "could not check for a k3sm update"); got != 1 {
					t.Errorf("%v: %d Warn lines, want 1:\n%s", sentinel, got, sink.String())
				}
			}
		})
		t.Run("an unreachable release host stays at Info", func(t *testing.T) {
			sink := &syncBuffer{}
			run := start(t, stable, installedWorkDir(t), sink, func() error { return errors.New("connection refused") })
			waitFor(t, "the check", func() bool { return run.checks.Load() >= 1 })
			settle(t, run, 2)
			if strings.Contains(sink.String(), "level=WARN") || !strings.Contains(sink.String(), "level=INFO") {
				t.Errorf("log:\n%s", sink.String())
			}
		})
	})

	t.Run("the server's recorder reads the object in its check and its poll", func(t *testing.T) {
		c := newUpdateCluster()
		c.setPolicy(t, "rc")
		r := newUpdateRecorder(t.TempDir(), "studio", fakeIndexURL, fake.NewClientset(), c.dyn, slog.New(slog.DiscardHandler))
		got, err := r.readChannel(context.Background())
		if err != nil || got.channel != rc {
			t.Fatalf("poll read %+v, %v", got, err)
		}
		c = newUpdateCluster()
		c.setPolicy(t, "beta")
		r = newUpdateRecorder(t.TempDir(), "studio", fakeIndexURL, fake.NewClientset(), c.dyn, slog.New(slog.DiscardHandler))
		if _, err := r.check(context.Background()); !errors.Is(err, update.ErrUnknownChannel) {
			t.Errorf("check err = %v, want the unknown channel", err)
		}
	})

	// apply reads the same setting, and prints the signature policy and the pin.
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	applyOn := func(t *testing.T, c updateCluster, x *channelIndex, mutate func(*updateEnv), args ...string) (int, string, string) {
		t.Helper()
		return c.runWith(t, func(env *updateEnv) {
			env.inputs.HTTP = x.client()
			if mutate != nil {
				mutate(env)
			}
		}, append([]string{"apply", "--yes"}, args...)...)
	}
	hasLine := func(t *testing.T, out, want string) {
		t.Helper()
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}

	t.Run("apply with no setting targets stable", func(t *testing.T) {
		c := newUpdateCluster(kubeletNode("studio", "v1.36.2+k3sm.0.1.7"))
		code, out, errOut := applyOn(t, c, &channelIndex{stable: "v0.2.3", listed: []string{"v0.3.0-rc.1"}}, nil)
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		hasLine(t, out, "target            v0.2.3\n")
		hasLine(t, out, "channel           stable\n")
		hasLine(t, out, "signature         if-signed\n")
		hasLine(t, out, "pin               not known on this Mac\n")
		if strings.Contains(out, "No pin is known") {
			t.Errorf("a final roll warns of a candidate's pin:\n%s", out)
		}
		if got := c.get(t).Spec.Version; got != "v0.2.3" {
			t.Errorf("spec.version = %q", got)
		}
	})

	t.Run("apply on rc targets the channel and says a candidate carries no pin", func(t *testing.T) {
		c := newUpdateCluster(kubeletNode("studio", "v1.36.2+k3sm.0.1.7"))
		c.setPolicy(t, "rc")
		code, out, errOut := applyOn(t, c, &channelIndex{stable: "v0.2.3", listed: []string{"v0.2.3", "v0.3.0-rc.1"}}, func(env *updateEnv) {
			env.workDir = "/nonexistent"
			env.readPin = func(string) (*updatectl.ReleasePin, error) { return nil, nil }
		}, "--signature", "required")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		hasLine(t, out, "target            v0.3.0-rc.1 (release candidate)\n")
		hasLine(t, out, "channel           rc\n")
		hasLine(t, out, "signature         required\n")
		hasLine(t, out, "pin               none on this Mac\n")
		hasLine(t, out, "No pin is known to bind this release candidate roll.")
		if got := c.get(t).Spec.Version; got != "v0.3.0-rc.1" {
			t.Errorf("spec.version = %q", got)
		}
	})

	t.Run("apply names a pin given and a pin set", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			args []string
			read func(string) (*updatectl.ReleasePin, error)
			want string
			note bool
		}{
			{"given", []string{"--version", "v0.3.0-rc.1", "--pin-sha256", sum}, nil, "sha256:" + sum + ", from --pin-sha256", false},
			{"set for this release", []string{"--version", "v0.3.0-rc.1"}, func(string) (*updatectl.ReleasePin, error) {
				return &updatectl.ReleasePin{Version: "v0.3.0-rc.1", SHA256: sum}, nil
			}, "sha256:" + sum + ", set on this Mac", false},
			{"set for another release", []string{"--version", "v0.3.0-rc.1"}, func(string) (*updatectl.ReleasePin, error) {
				return &updatectl.ReleasePin{Version: "v0.2.0", SHA256: sum}, nil
			}, "none for this release; the pin on this Mac names v0.2.0", true},
			{"needs sudo", []string{"--version", "v0.3.0-rc.1"}, func(string) (*updatectl.ReleasePin, error) {
				return nil, fmt.Errorf("open: %w", fs.ErrPermission)
			}, "not known without sudo", true},
			{"untrusted", []string{"--version", "v0.3.0-rc.1"}, func(string) (*updatectl.ReleasePin, error) {
				return nil, errors.New("group writable")
			}, "cannot be trusted", true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := newUpdateCluster(kubeletNode("studio", "v1.36.2+k3sm.0.1.7"))
				code, out, errOut := applyOn(t, c, &channelIndex{stable: "v0.2.3"}, func(env *updateEnv) {
					env.root, env.workDir, env.readPin = true, t.TempDir(), tc.read
					env.writePin = func(string, updatectl.ReleasePin) error { return nil }
				}, tc.args...)
				if code != 0 {
					t.Fatalf("exit %d, stderr %q", code, errOut)
				}
				hasLine(t, out, "pin               "+tc.want)
				if got := strings.Contains(out, "No pin is known"); got != tc.note {
					t.Errorf("no-pin note = %v, want %v:\n%s", got, tc.note, out)
				}
			})
		}
	})

	t.Run("apply refuses a channel it cannot read unless a release is named", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			set  func(c updateCluster)
		}{
			{"another error", func(c updateCluster) { c.policyAnswers(apierrors.NewInternalError(errors.New("etcd away"))) }},
			{"an unknown value", func(c updateCluster) { c.setPolicy(t, "beta") }},
			{"Forbidden with an unknown pair", func(c updateCluster) {
				c.policyAnswers(forbidden)
				if _, err := c.cs.CoreV1().Nodes().Create(context.Background(), publishingServer("studio", "v0.3.0-rc.2", "beta"), metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := newUpdateCluster()
				tc.set(c)
				x := &channelIndex{stable: "v0.2.3", listed: []string{"v0.3.0-rc.1"}}
				code, _, errOut := applyOn(t, c, x, nil)
				if code != exitInternalError || !strings.Contains(errOut, "--version") {
					t.Fatalf("exit %d, stderr %q", code, errOut)
				}
				if u, _ := getUpdate(context.Background(), c.dyn); u != nil {
					t.Errorf("created %+v on a channel it could not read", u)
				}
				if x.redirects.Load()+x.lists.Load() != 0 {
					t.Error("resolved a release on a channel it could not read")
				}
				code, out, errOut := applyOn(t, c, x, nil, "--version", "v0.3.0-rc.1")
				if code != 0 {
					t.Fatalf("--version: exit %d, stderr %q", code, errOut)
				}
				if got := c.get(t).Spec.Version; got != "v0.3.0-rc.1" {
					t.Errorf("spec.version = %q", got)
				}
				if !strings.Contains(out, "could not be read") {
					t.Errorf("plan does not say the channel was not read:\n%s", out)
				}
			})
		}
	})

	t.Run("apply on rc refuses a failed listing, never the stable answer", func(t *testing.T) {
		c := newUpdateCluster(kubeletNode("studio", "v1.36.2+k3sm.0.1.7"))
		c.setPolicy(t, "rc")
		code, _, errOut := applyOn(t, c, &channelIndex{stable: "v0.2.3", listFails: true}, nil)
		if code != exitInternalError || !strings.Contains(errOut, update.ErrChannelList.Error()) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if u, _ := getUpdate(context.Background(), c.dyn); u != nil {
			t.Errorf("created %+v", u)
		}
	})
}
