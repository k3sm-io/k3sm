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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"

	"k3sm.io/k3sm/pkg/status"
)

// fakeBudget is a budgetSource with a fixed answer.
type fakeBudget struct {
	obs budgetv1alpha1.NodeBudgetObservation
	ok  bool
}

func (f fakeBudget) Budget() (budgetv1alpha1.NodeBudgetObservation, bool) { return f.obs, f.ok }

func TestRecordBudget(t *testing.T) {
	t.Parallel()
	level := int64(1)
	obs := budgetv1alpha1.NodeBudgetObservation{
		ObservedAt: metav1.NewTime(time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)),
		Platform:   budgetv1alpha1.PlatformDarwin,
		Level:      budgetv1alpha1.LevelOK,
		Admit:      true,
		Darwin:     &budgetv1alpha1.DarwinSignals{VMPressureLevel: &level},
	}

	t.Run("a sample is written world-readable and parses back", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := recordBudget(fakeBudget{obs: obs, ok: true}, dir); err != nil {
			t.Fatal(err)
		}
		path := status.BudgetPath(dir)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("record mode %v, want 0644", fi.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := status.ParseBudgetRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got.Level != budgetv1alpha1.LevelOK || !got.ObservedAt.Equal(&obs.ObservedAt) {
			t.Errorf("record level=%s observedAt=%v, want ok at %v", got.Level, got.ObservedAt, obs.ObservedAt)
		}
		left, err := filepath.Glob(filepath.Join(dir, "*.json.*"))
		if err != nil || len(left) != 0 {
			t.Errorf("temporary files left behind: %v (%v)", left, err)
		}
	})

	t.Run("nothing is written before the first sample", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := recordBudget(fakeBudget{}, dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(status.BudgetPath(dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("record exists before a sample: %v", err)
		}
	})

	t.Run("no status directory writes nothing", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "absent")
		if err := recordBudget(fakeBudget{obs: obs, ok: true}, dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("status directory created: %v", err)
		}
	})

	t.Run("an invalid observation is refused, not written", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := recordBudget(fakeBudget{obs: budgetv1alpha1.NodeBudgetObservation{}, ok: true}, dir); err == nil {
			t.Fatal("recordBudget accepted an observation with no observedAt")
		}
		if _, err := os.Stat(status.BudgetPath(dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("record written for an invalid observation: %v", err)
		}
	})
}

func TestStatusBudgetForReadsOnlyARegularFile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		stage   func(t *testing.T, dir, path string)
		wantErr bool
	}{
		{"a regular file is read", func(t *testing.T, _, path string) {
			if err := os.WriteFile(path, []byte(`{"schema":1}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"no record", func(*testing.T, string, string) {}, true},
		{"a symlink is not followed", func(t *testing.T, dir, path string) {
			target := filepath.Join(dir, "elsewhere.json")
			if err := os.WriteFile(target, []byte(`{"schema":1}`), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a FIFO is refused without blocking", func(t *testing.T, _, path string) {
			if err := syscall.Mkfifo(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a directory is refused", func(t *testing.T, _, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tc.stage(t, dir, status.BudgetPath(dir))
			type result struct {
				raw []byte
				err error
			}
			done := make(chan result, 1)
			go func() {
				raw, err := statusBudgetFor(dir)()
				done <- result{raw, err}
			}()
			// A bound on a failure, not a wait for a condition: a read that
			// blocks (a FIFO opened without O_NONBLOCK) never sends.
			bound := time.NewTimer(5 * time.Second)
			defer bound.Stop()
			var r result
			select {
			case r = <-done:
			case <-bound.C:
				t.Fatal("the read blocked")
			}
			if (r.err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", r.err, tc.wantErr)
			}
			if tc.wantErr && r.raw != nil {
				t.Errorf("read %q alongside the error", r.raw)
			}
		})
	}
}
