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
	"io/fs"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
)

// fakeServicesSource is a servicesSource with a switchable Synced and a count
// of the table reads, which is how a test sees each record being taken.
type fakeServicesSource struct {
	synced atomic.Bool
	reads  atomic.Int64
}

func (f *fakeServicesSource) VIPStates() []proxy.VIPState {
	f.reads.Add(1)
	return []proxy.VIPState{{ClusterIP: "10.43.0.20", Port: 80, Protocol: "TCP", Namespace: "web", Name: "front", Backends: []string{"100.64.0.7:8080"}}}
}
func (f *fakeServicesSource) PinnedBackends() map[string][]string {
	return map[string][]string{"default/kubernetes": {"127.0.0.1:6444"}}
}
func (f *fakeServicesSource) UnproxiedClusterIPs() []string { return []string{"10.43.0.10"} }
func (f *fakeServicesSource) Synced() bool                  { return f.synced.Load() }

// readServicesRecord parses the record at path, or reports false.
func readServicesRecord(path string) (status.ServicesRecord, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return status.ServicesRecord{}, false
	}
	var rec status.ServicesRecord
	return rec, json.Unmarshal(raw, &rec) == nil
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestServicesRecorderLifecycle pins the recorder end to end under -race: the
// stale record is removed before the datapath decision; nothing is recorded
// until the proxy reports Synced; then a record lands (0600, parseable, carrying
// the pinned backends); and cancelling ctx returns the goroutine and stops the
// ticker, so no record is taken afterwards.
func TestServicesRecorderLifecycle(t *testing.T) {
	wd := t.TempDir()
	path := status.ServicesPath(wd)
	if err := os.WriteFile(path, []byte(`{"updatedAt":"2020-01-01T00:00:00Z","vips":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	removeServicesRecord(wd, logger)
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the stale record survived: %v", err)
	}
	removeServicesRecord(wd, logger) // an absent record is not an error

	src := &fakeServicesSource{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runServicesRecorder(ctx, src, wd, 10*time.Millisecond, time.Millisecond, logger)
	}()

	time.Sleep(50 * time.Millisecond)
	if n := src.reads.Load(); n != 0 {
		t.Fatalf("the recorder read the table %d times before the proxy synced", n)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a record was written before the proxy synced: %v", err)
	}
	src.synced.Store(true)
	waitFor(t, "a record", func() bool { _, ok := readServicesRecord(path); return ok })
	rec, _ := readServicesRecord(path)
	if len(rec.VIPs) != 1 || len(rec.Pinned) != 1 || rec.Pinned[0].Backends[0] != "127.0.0.1:6444" {
		t.Errorf("record = %+v", rec)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %v, err %v, want 0600", info.Mode().Perm(), err)
	}
	waitFor(t, "a second record from the ticker", func() bool { return src.reads.Load() >= 2 })

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the recorder did not return after ctx was cancelled")
	}
	after := src.reads.Load()
	time.Sleep(50 * time.Millisecond)
	if n := src.reads.Load(); n != after {
		t.Errorf("the recorder took %d records after it returned", n-after)
	}
}

// TestServicesRecorderStopsBeforeSync pins that a ctx cancelled while the proxy
// has not synced returns the recorder without a record.
func TestServicesRecorderStopsBeforeSync(t *testing.T) {
	wd := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runServicesRecorder(ctx, &fakeServicesSource{}, wd, time.Hour, time.Millisecond, slog.New(slog.DiscardHandler))
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the recorder did not return after ctx was cancelled")
	}
	if _, err := os.Stat(status.ServicesPath(wd)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a record was written for an unsynced proxy: %v", err)
	}
}
