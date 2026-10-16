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

package builder

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// routedExecer answers the readiness probe and buildctl du/prune by command.
type routedExecer struct {
	du, prune string
	pruneErr  error
	commands  [][]string
}

func (r *routedExecer) Exec(_ context.Context, _, _, _ string, cmd []string) (string, string, error) {
	r.commands = append(r.commands, cmd)
	joined := strings.Join(cmd, " ")
	switch {
	case strings.Contains(joined, "debug workers"):
		return oneWorker, "", nil
	case strings.Contains(joined, " du "):
		return r.du, "", nil
	case strings.Contains(joined, " prune"):
		return r.prune, "failed to prune", r.pruneErr
	}
	return "", "", errors.New("unexpected command " + joined)
}

const duJSON = `[
 {"id":"a","inUse":false,"size":100,"recordType":"regular","shared":false},
 {"id":"b","inUse":true,"size":200,"recordType":"regular","shared":false},
 {"id":"c","inUse":false,"size":400,"recordType":"frontend","shared":false},
 {"id":"d","inUse":false,"size":800,"recordType":"internal","shared":false},
 {"id":"e","inUse":false,"size":1600,"recordType":"regular","shared":true},
 {"id":"f","inUse":false,"size":0,"recordType":"exec.cachemount","shared":false}
]`

func readyManager(ex Execer) *Manager {
	cs := fake.NewSimpleClientset(builderPod(corev1.PodRunning), builderService("10.43.0.9"))
	return NewManager(cs, ex, Config{}, nil)
}

func TestPlanPruneFollowsBuildkitSelection(t *testing.T) {
	for _, tc := range []struct {
		all     bool
		records int
		bytes   int64
	}{
		{all: false, records: 1, bytes: 100},
		{all: true, records: 4, bytes: 100 + 400 + 800 + 1600},
	} {
		ex := &routedExecer{du: duJSON}
		rep, err := readyManager(ex).PlanPrune(t.Context(), tc.all)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Records != tc.records || rep.Bytes != tc.bytes {
			t.Errorf("all=%v: plan = %+v, want %d records, %d bytes", tc.all, rep, tc.records, tc.bytes)
		}
		for _, c := range ex.commands {
			if strings.Contains(strings.Join(c, " "), "prune") {
				t.Errorf("a dry run ran %v", c)
			}
		}
	}
}

func TestPruneCacheReportsReclaimedBytes(t *testing.T) {
	ex := &routedExecer{prune: `{"id":"a","size":100}` + "\n" + `{"id":"c","size":400}` + "\n"}
	rep, err := readyManager(ex).PruneCache(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Records != 2 || rep.Bytes != 500 {
		t.Errorf("reclaimed = %+v, want 2 records, 500 bytes", rep)
	}
	last := strings.Join(ex.commands[len(ex.commands)-1], " ")
	want := "buildctl --addr unix:///run/buildkit/buildkitd.sock prune --all --format {{json .}}"
	if last != want {
		t.Errorf("prune ran %q, want %q", last, want)
	}
	ex = &routedExecer{prune: ""}
	if _, err := readyManager(ex).PruneCache(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if last := strings.Join(ex.commands[len(ex.commands)-1], " "); strings.Contains(last, "--all") {
		t.Errorf("a default prune passed --all: %q", last)
	}
}

func TestPruneCacheErrors(t *testing.T) {
	m := NewManager(fake.NewSimpleClientset(), &routedExecer{}, Config{}, nil)
	if _, err := m.PruneCache(t.Context(), false); !errors.Is(err, ErrAbsent) {
		t.Errorf("an absent engine = %v, want ErrAbsent", err)
	}
	ex := &routedExecer{pruneErr: errors.New("exit 1")}
	if _, err := readyManager(ex).PruneCache(t.Context(), false); err == nil || !strings.Contains(err.Error(), "failed to prune") {
		t.Errorf("a failed prune = %v, want buildctl's stderr in the error", err)
	}
	ex = &routedExecer{du: "not json"}
	if _, err := readyManager(ex).PlanPrune(t.Context(), false); err == nil {
		t.Error("unreadable du output was accepted")
	}
}
