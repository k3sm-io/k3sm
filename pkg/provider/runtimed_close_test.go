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
	"log/slog"
	"testing"
	"time"

	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// closeTestLockWait is the root-lock wait these runtimes run under: short, so a
// runtime that was not released fails the next NewRuntimed at once, named by
// runtimed.ErrRootInUse, instead of after runtimed's 15 s default.
const closeTestLockWait = 300 * time.Millisecond

// TestRuntimedRuntimeCloseReleasesRoot: the provider's Close lets go of the
// embedded runtime's root, so a second provider on the same root starts, as a
// restarted node does. Close is idempotent, and a repeated Close does not take
// the root back from the successor.
func TestRuntimedRuntimeCloseReleasesRoot(t *testing.T) {
	stageExecShim(t)
	root := t.TempDir()
	cfg := RuntimedConfig{
		NodeName: "n1", Root: root, PodLogsDir: root,
		Logger: slog.New(slog.DiscardHandler), rootLockWait: closeTestLockWait,
	}
	first, err := NewRuntimed(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewRuntimed: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() }) // a no-op once the test has closed it

	// While the first holds the root, a second is refused, which is also what
	// proves the short wait reaches runtimed.
	if r, err := NewRuntimed(context.Background(), cfg); !errors.Is(err, runtimed.ErrRootInUse) {
		if err == nil {
			_ = r.Close()
		}
		t.Fatalf("NewRuntimed on a held root: err = %v, want runtimed.ErrRootInUse", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second Close: %v, want Close to be idempotent", err)
	}

	second, err := NewRuntimed(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewRuntimed after Close: %v (a Close that kept the root reads as runtimed.ErrRootInUse)", err)
	}
	t.Cleanup(func() { _ = second.Close() }) // the test is done with it; a close error proves nothing here

	// A third Close of the first provider must not release the successor's lock.
	if err := first.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
	if r, err := NewRuntimed(context.Background(), cfg); !errors.Is(err, runtimed.ErrRootInUse) {
		if err == nil {
			_ = r.Close()
		}
		t.Fatalf("NewRuntimed while the successor holds the root: err = %v, want runtimed.ErrRootInUse", err)
	}
}
