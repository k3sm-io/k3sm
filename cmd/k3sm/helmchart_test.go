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
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestAwaitHelm: a failing EnsureHelm is retried, not a one-shot disable, and a
// repeated error is logged once.
func TestAwaitHelm(t *testing.T) {
	t.Run("retries until staged, logging each distinct error once", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		calls := 0
		ensure := func(context.Context) (string, error) {
			calls++
			if calls <= 2 {
				return "", errors.New("helm is not staged")
			}
			return "/bin/helm-v4", nil
		}
		path, err := awaitHelm(t.Context(), ensure, time.Millisecond, logger)
		if err != nil || path != "/bin/helm-v4" {
			t.Fatalf("awaitHelm = %q, %v, want the staged path", path, err)
		}
		if calls != 3 {
			t.Errorf("ensure calls = %d, want 3 (two failures, then success)", calls)
		}
		if n := strings.Count(buf.String(), "helm controller waiting"); n != 1 {
			t.Errorf("waiting lines = %d, want 1 (a repeated error is logged once):\n%s", n, buf.String())
		}
	})

	t.Run("a new error is logged again", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		errs := []string{"a", "a", "b"}
		calls := 0
		ensure := func(context.Context) (string, error) {
			calls++
			if calls <= len(errs) {
				return "", errors.New(errs[calls-1])
			}
			return "/bin/helm", nil
		}
		if _, err := awaitHelm(t.Context(), ensure, time.Millisecond, logger); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(buf.String(), "helm controller waiting"); n != 2 {
			t.Errorf("waiting lines = %d, want 2 (one per distinct error)", n)
		}
	})

	t.Run("ctx done ends the wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		ensure := func(context.Context) (string, error) {
			cancel()
			return "", errors.New("helm is not staged")
		}
		if _, err := awaitHelm(ctx, ensure, time.Hour, slog.New(slog.DiscardHandler)); !errors.Is(err, context.Canceled) {
			t.Fatalf("awaitHelm = %v, want context.Canceled", err)
		}
	})
}
