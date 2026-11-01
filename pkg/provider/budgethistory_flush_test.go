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

package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// TestFlushWithoutWriterDoesNotStall: an emergency stop's flush with no writer
// running (never started, stopped, or exited on its context's end) writes the
// intent inline instead of waiting out budgetIntentWriteBound for a writer that
// is not there. A history with no path returns at once. Time is the bubble's
// virtual clock, so the elapsed time is exact.
//
// Fails-before: flush only signalled the writer and waited, so each case with a
// path took the full 250 ms and returned false with the intent not on disk.
func TestFlushWithoutWriterDoesNotStall(t *testing.T) {
	cases := []struct {
		name   string
		open   func(t *testing.T) (*BudgetHistory, string)
		onDisk bool
	}{
		{
			name: "never started",
			open: func(t *testing.T) (*BudgetHistory, string) {
				dir := t.TempDir()
				return OpenBudgetHistory(dir, "fp", discardLog()), dir
			},
			onDisk: true,
		},
		{
			name: "stopped",
			open: func(t *testing.T) (*BudgetHistory, string) {
				dir := t.TempDir()
				h := OpenBudgetHistory(dir, "fp", discardLog())
				h.start(context.Background())
				if !h.stop(BudgetHistoryStopBound) {
					t.Fatal("stop did not finish in its bound")
				}
				return h, dir
			},
			onDisk: true,
		},
		{
			name: "writer exited on its context's end",
			open: func(t *testing.T) (*BudgetHistory, string) {
				dir := t.TempDir()
				h := OpenBudgetHistory(dir, "fp", discardLog())
				ctx, cancel := context.WithCancel(context.Background())
				h.start(ctx)
				cancel()
				<-h.stopped
				return h, dir
			},
			onDisk: true,
		},
		{
			name: "in memory only",
			open: func(t *testing.T) (*BudgetHistory, string) {
				// A regular file where the dir should be leaves the history
				// with no path.
				dir := filepath.Join(t.TempDir(), "budget")
				if err := os.WriteFile(dir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				h := OpenBudgetHistory(dir, "fp", discardLog())
				if h.path != "" {
					t.Fatalf("want an in-memory history, got path %q", h.path)
				}
				return h, ""
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, dir := tc.open(t)
				h.recordIntent(types.UID("pod-1"), "app")
				start := time.Now()
				ok := h.flush(budgetIntentWriteBound)
				if elapsed := time.Since(start); elapsed >= 50*time.Millisecond {
					t.Fatalf("flush took %v with no writer running, want well under %v", elapsed, budgetIntentWriteBound)
				}
				if !ok {
					t.Fatal("flush reported the intent did not reach disk")
				}
				if !tc.onDisk {
					return
				}
				st, err := readHistory(filepath.Join(dir, budgetHistoryFile))
				if err != nil {
					t.Fatal(err)
				}
				if len(st.Intents) != 1 || st.Intents[0].Pod != "pod-1" {
					t.Fatalf("the file holds intents %+v, want the one for pod-1", st.Intents)
				}
			})
		})
	}
}

// TestReadHistoryRefusesNonRegular: readHistory opens with O_NOFOLLOW and
// checks the opened file, so a symlink at the history path (to a valid history
// or anywhere else) and a directory are refused as unrecognised, never read
// through.
func TestReadHistoryRefusesNonRegular(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, path string)
	}{
		{
			name: "symlink to a valid history",
			plant: func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "real")
				h := OpenBudgetHistory(filepath.Dir(target), "fp", discardLog())
				if err := os.Rename(h.path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "dangling symlink",
			plant: func(t *testing.T, path string) {
				if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			plant: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), budgetHistoryFile)
			tc.plant(t, path)
			_, err := readHistory(path)
			if !errors.Is(err, errBudgetHistoryFormat) {
				t.Fatalf("readHistory = %v, want errBudgetHistoryFormat", err)
			}
		})
	}
}
