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

// authorizerFixture is the set of failures the authorizer tests feed note():
// real startServiceInformer errors for an unparseable and a missing
// kubeconfig, and synthetic apiserver/dial errors.
type authorizerFixture struct {
	kubeconfig   string
	loadErr      error
	missingErr   error
	unauthorized error
	forbidden    error
	dial         error
}

// authorizerFixtureToken is the credential written into the unparseable
// kubeconfig; no log line may carry it.
const authorizerFixtureToken = "k3sm-secret-token-bytes-0123456789"

func newAuthorizerFixture(t *testing.T) authorizerFixture {
	t.Helper()
	dir := t.TempDir()
	f := authorizerFixture{kubeconfig: filepath.Join(dir, "k3sm.kubeconfig")}
	// A kubeconfig that holds a token and does not parse. The loader's error
	// happens not to quote the token for this input, but nothing promises that
	// for every input, so the WARN must carry none of the loader's error text
	// at all (forbid below), and the token must appear nowhere.
	if err := os.WriteFile(f.kubeconfig, []byte("apiVersion: v1\nusers: [{name: x, user: {token: "+authorizerFixtureToken+"}\nclusters: {{{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, f.loadErr = startServiceInformer(context.Background(), f.kubeconfig); f.loadErr == nil {
		t.Fatal("startServiceInformer accepted an unparseable kubeconfig")
	}
	if _, f.missingErr = startServiceInformer(context.Background(), filepath.Join(dir, "absent.kubeconfig")); f.missingErr == nil {
		t.Fatal("startServiceInformer accepted a missing kubeconfig")
	}
	f.unauthorized = fmt.Errorf("service cache did not sync within 10s: %w", apierrors.NewUnauthorized("Unauthorized"))
	f.forbidden = fmt.Errorf("service cache did not sync within 10s: %w", apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", errors.New("denied")))
	f.dial = errors.New("service cache did not sync within 10s: dial tcp 10.43.0.1:443: connect: connection refused")
	return f
}

// authorizerCase is one sequence of consecutive failed attempts and what the
// log must hold after it.
type authorizerCase struct {
	name      string
	errs      []error
	wantWarns int
	// wantDebug < 0 skips the Debug count.
	wantDebug int
	want      []string
	forbid    []string
}

// runAuthorizerCases feeds each case's attempts to a fresh
// authorizerFailureLog and checks the WARN/Debug counts, the required and
// forbidden text, and that no token byte was logged.
func runAuthorizerCases(t *testing.T, kubeconfig string, cases []authorizerCase) {
	t.Helper()
	for _, tc := range cases {
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
			if got := h.count(slog.LevelDebug); tc.wantDebug >= 0 && got != tc.wantDebug {
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
			if strings.Contains(out, authorizerFixtureToken) {
				t.Errorf("the log carries token bytes:\n%s", out)
			}
		})
	}
}

// TestNetdAuthorizerFailureReasonAtWarn proves the failures that keep the
// privileged-port authorizer down for the daemon's whole life are visible at
// the default log level, once, with the kubeconfig path and a remedy, and
// without any byte of the credential; and that the ordinary boot-race failure
// stays at Debug.
func TestNetdAuthorizerFailureReasonAtWarn(t *testing.T) {
	f := newAuthorizerFixture(t)
	w := credentialRejectedWarnAfter
	runAuthorizerCases(t, f.kubeconfig, []authorizerCase{
		{
			name:      "a 401 held for the window warns once with the path and the remedy; a repeat is Debug",
			errs:      repeatErr(f.unauthorized, w+1),
			wantWarns: 1,
			wantDebug: w,
			want:      []string{f.kubeconfig, "401", "sudo k3sm uninstall"},
		},
		{
			name:      "a 403 warns",
			errs:      []error{f.forbidden},
			wantWarns: 1,
			want:      []string{"403"},
		},
		{
			name:      "an unparseable kubeconfig warns without its contents",
			errs:      []error{f.loadErr, f.loadErr},
			wantWarns: 1,
			wantDebug: 1,
			want:      []string{f.kubeconfig, "not a valid kubeconfig"},
			forbid:    []string{"yaml:", "error loading config file"},
		},
		{
			name:      "a 401 warns on the last attempt of its window",
			errs:      repeatErr(f.unauthorized, w),
			wantWarns: 1,
			wantDebug: w - 1,
		},
		{
			name:      "the same 401 for 149 further attempts past the window is not warned again",
			errs:      repeatErr(f.unauthorized, w+authorizerRewarnEvery-1),
			wantWarns: 1,
			wantDebug: w - 1 + authorizerRewarnEvery - 1,
		},
		{
			name:      "the same 401 is warned again at the re-warn interval",
			errs:      repeatErr(f.unauthorized, w+authorizerRewarnEvery),
			wantWarns: 2,
			wantDebug: w - 1 + authorizerRewarnEvery - 1,
			want:      []string{f.kubeconfig, "401", "sudo k3sm uninstall"},
		},
		{
			name:      "a different error resets the cadence",
			errs:      append(append(repeatErr(f.unauthorized, 100), f.forbidden), repeatErr(f.forbidden, authorizerRewarnEvery-1)...),
			wantWarns: 2,
			wantDebug: 99 + authorizerRewarnEvery - 1,
		},
		{
			name:      "a kubeconfig still missing is reminded at the re-warn interval",
			errs:      repeatErr(f.missingErr, missingKubeconfigWarnAfter+authorizerRewarnEvery),
			wantWarns: 2,
			wantDebug: missingKubeconfigWarnAfter - 1 + authorizerRewarnEvery - 1,
		},
		{
			name:      "a kubeconfig missing for fewer attempts than the threshold is the boot race: Debug only",
			errs:      repeatErr(f.missingErr, missingKubeconfigWarnAfter-1),
			wantDebug: missingKubeconfigWarnAfter - 1,
		},
		{
			name:      "a kubeconfig missing for the threshold warns exactly once, path only",
			errs:      repeatErr(f.missingErr, missingKubeconfigWarnAfter+5),
			wantWarns: 1,
			wantDebug: missingKubeconfigWarnAfter + 4,
			want:      []string{f.kubeconfig, "does not exist", "sudo k3sm uninstall"},
		},
		{
			name:      "a missing streak broken by another failure starts over",
			errs:      append(append(repeatErr(f.missingErr, missingKubeconfigWarnAfter-1), f.dial), repeatErr(f.missingErr, missingKubeconfigWarnAfter-1)...),
			wantDebug: 2*(missingKubeconfigWarnAfter-1) + 1,
		},
		{
			name:      "a missing streak that turns into a 401 streak starts the 401 window over",
			errs:      append(repeatErr(f.missingErr, missingKubeconfigWarnAfter-1), repeatErr(f.unauthorized, w-1)...),
			wantDebug: missingKubeconfigWarnAfter - 1 + w - 1,
		},
		{
			name:      "a dial error is the boot race: Debug only",
			errs:      []error{f.dial, f.dial},
			wantDebug: 2,
		},
		{
			name:      "a different credential error warns again",
			errs:      append(repeatErr(f.unauthorized, w), f.forbidden),
			wantWarns: 2,
			wantDebug: w - 1,
		},
	})
}

// TestNetdAuthorizerBootWindowCovers401 proves a 401 is given a boot window:
// the apiserver rejects even netd's valid credential for the first seconds of
// a server boot, so a 401 that clears within credentialRejectedWarnAfter
// attempts never WARNs, while one that holds warns once (path and remedy, no
// token) and then on the unchanged re-warn cadence. A 403 and an unparseable
// kubeconfig are never the boot race and still WARN on first sighting.
func TestNetdAuthorizerBootWindowCovers401(t *testing.T) {
	f := newAuthorizerFixture(t)
	w := credentialRejectedWarnAfter
	runAuthorizerCases(t, f.kubeconfig, []authorizerCase{
		{
			// The attempt after these succeeds, which ends the retry loop:
			// nothing further is noted.
			name:      "(a) a 401 for 9 attempts then success is the boot race: no WARN",
			errs:      repeatErr(f.unauthorized, w-1),
			wantDebug: w - 1,
		},
		{
			name:      "(b) a 401 for 10 consecutive attempts warns exactly once with the path and the remedy",
			errs:      repeatErr(f.unauthorized, w),
			wantWarns: 1,
			wantDebug: w - 1,
			want:      []string{f.kubeconfig, "401", "sudo k3sm uninstall"},
		},
		{
			name:      "(c) a 403 warns on its first sighting",
			errs:      []error{f.forbidden},
			wantWarns: 1,
			want:      []string{f.kubeconfig, "403", "sudo k3sm uninstall"},
		},
		{
			name:      "(d) an unparseable kubeconfig warns on its first sighting without its contents",
			errs:      []error{f.loadErr},
			wantWarns: 1,
			want:      []string{f.kubeconfig, "not a valid kubeconfig"},
			forbid:    []string{"yaml:", "error loading config file"},
		},
		{
			name:      "(e) past the window the same 401 for 149 more attempts does not warn again",
			errs:      repeatErr(f.unauthorized, w+authorizerRewarnEvery-1),
			wantWarns: 1,
			wantDebug: -1,
		},
		{
			name:      "(e) past the window the same 401 warns again at 150 more attempts",
			errs:      repeatErr(f.unauthorized, w+authorizerRewarnEvery),
			wantWarns: 2,
			wantDebug: -1,
		},
		{
			name:      "(f) a 401 streak broken by a dial error restarts: 9 more 401s do not warn",
			errs:      append(append(repeatErr(f.unauthorized, w-1), f.dial), repeatErr(f.unauthorized, w-1)...),
			wantDebug: 2*(w-1) + 1,
		},
	})
}

// repeatErr returns n copies of err, one per consecutive failed attempt.
func repeatErr(err error, n int) []error {
	out := make([]error, n)
	for i := range out {
		out[i] = err
	}
	return out
}
