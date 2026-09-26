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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// levelCounter is a slog handler that keeps every record's level and its
// rendered text, so a test can count WARNs and grep what was logged.
type levelCounter struct {
	levels []slog.Level
	text   bytes.Buffer
}

func (h *levelCounter) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCounter) Handle(_ context.Context, r slog.Record) error {
	h.levels = append(h.levels, r.Level)
	fmt.Fprintf(&h.text, "%s %s", r.Level, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&h.text, " %s=%v", a.Key, a.Value)
		return true
	})
	h.text.WriteString("\n")
	return nil
}
func (h *levelCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelCounter) WithGroup(string) slog.Handler      { return h }

func (h *levelCounter) count(l slog.Level) int {
	n := 0
	for _, got := range h.levels {
		if got == l {
			n++
		}
	}
	return n
}

// TestNetdAuthorizerFailureReasonAtWarn proves the two failures that keep the
// privileged-port authorizer down for the daemon's whole life are visible at
// the default log level, once, with the kubeconfig path and a remedy, and
// without any byte of the credential; and that the ordinary boot-race failure
// stays at Debug.
func TestNetdAuthorizerFailureReasonAtWarn(t *testing.T) {
	const token = "k3sm-secret-token-bytes-0123456789"
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "k3sm.kubeconfig")
	// A kubeconfig that holds a token and does not parse. The loader's error
	// happens not to quote the token for this input, but nothing promises that
	// for every input, so the WARN must carry none of the loader's error text
	// at all (forbid below), and the token must appear nowhere.
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nusers: [{name: x, user: {token: "+token+"}\nclusters: {{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, loadErr := startServiceInformer(context.Background(), kubeconfig)
	if loadErr == nil {
		t.Fatal("startServiceInformer accepted an unparseable kubeconfig")
	}

	_, missingErr := startServiceInformer(context.Background(), filepath.Join(dir, "absent.kubeconfig"))
	if missingErr == nil {
		t.Fatal("startServiceInformer accepted a missing kubeconfig")
	}

	unauthorized := fmt.Errorf("service cache did not sync within 10s: %w", apierrors.NewUnauthorized("Unauthorized"))
	forbidden := fmt.Errorf("service cache did not sync within 10s: %w", apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", errors.New("denied")))
	dial := errors.New("service cache did not sync within 10s: dial tcp 10.43.0.1:443: connect: connection refused")

	for _, tc := range []struct {
		name      string
		errs      []error
		wantWarns int
		wantDebug int
		want      []string
		forbid    []string
	}{
		{
			name:      "a 401 warns once with the path and the remedy; a repeat is Debug",
			errs:      []error{unauthorized, unauthorized},
			wantWarns: 1,
			wantDebug: 1,
			want:      []string{kubeconfig, "401", "sudo k3sm uninstall"},
		},
		{
			name:      "a 403 warns",
			errs:      []error{forbidden},
			wantWarns: 1,
			want:      []string{"403"},
		},
		{
			name:      "an unparseable kubeconfig warns without its contents",
			errs:      []error{loadErr, loadErr},
			wantWarns: 1,
			wantDebug: 1,
			want:      []string{kubeconfig, "not a valid kubeconfig"},
			forbid:    []string{"yaml:", "error loading config file"},
		},
		{
			name:      "a 401 warns on its first sighting",
			errs:      []error{unauthorized},
			wantWarns: 1,
		},
		{
			name:      "a kubeconfig missing for fewer attempts than the threshold is the boot race: Debug only",
			errs:      repeatErr(missingErr, missingKubeconfigWarnAfter-1),
			wantDebug: missingKubeconfigWarnAfter - 1,
		},
		{
			name:      "a kubeconfig missing for the threshold warns exactly once, path only",
			errs:      repeatErr(missingErr, missingKubeconfigWarnAfter+5),
			wantWarns: 1,
			wantDebug: missingKubeconfigWarnAfter + 4,
			want:      []string{kubeconfig, "does not exist", "sudo k3sm uninstall"},
		},
		{
			name:      "a missing streak broken by another failure starts over",
			errs:      append(append(repeatErr(missingErr, missingKubeconfigWarnAfter-1), dial), repeatErr(missingErr, missingKubeconfigWarnAfter-1)...),
			wantDebug: 2*(missingKubeconfigWarnAfter-1) + 1,
		},
		{
			name:      "a dial error is the boot race: Debug only",
			errs:      []error{dial, dial},
			wantDebug: 2,
		},
		{
			name:      "a different credential error warns again",
			errs:      []error{unauthorized, forbidden},
			wantWarns: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &levelCounter{}
			logger := slog.New(h)
			var l authorizerFailureLog
			for _, err := range tc.errs {
				l.note(logger, kubeconfig, err)
			}
			if got := h.count(slog.LevelWarn); got != tc.wantWarns {
				t.Errorf("WARN records = %d, want %d\n%s", got, tc.wantWarns, h.text.String())
			}
			if got := h.count(slog.LevelDebug); got != tc.wantDebug {
				t.Errorf("Debug records = %d, want %d\n%s", got, tc.wantDebug, h.text.String())
			}
			out := h.text.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("log does not name %q:\n%s", w, out)
				}
			}
			for _, f := range tc.forbid {
				if strings.Contains(out, f) {
					t.Errorf("log carries the loader's error text %q:\n%s", f, out)
				}
			}
			if strings.Contains(out, token) {
				t.Errorf("the log carries token bytes:\n%s", out)
			}
		})
	}
}

// repeatErr returns n copies of err, one per consecutive failed attempt.
func repeatErr(err error, n int) []error {
	out := make([]error, n)
	for i := range out {
		out[i] = err
	}
	return out
}
