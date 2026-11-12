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

package install

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"k3sm.io/k3sm/pkg/executor"
)

// rawTextHandler is a slog.Handler that writes the message and every attribute
// value as it is, with no quoting: the shape of a sink (a terminal, os_log)
// that does not escape what it is handed. slog's own TextHandler quotes a value
// holding a control byte, which would hide the defect this test is about.
type rawTextHandler struct {
	mu    *sync.Mutex
	lines *[]string
}

func (h rawTextHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h rawTextHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h rawTextHandler) WithGroup(string) slog.Handler            { return h }
func (h rawTextHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.lines = append(*h.lines, b.String())
	return nil
}

// controlRunes lists every rune of s a terminal could act on rather than show.
func controlRunes(s string) []rune {
	var bad []rune
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			bad = append(bad, r)
		}
	}
	return bad
}

// TestHostileCrashRecordRendersAsDataOnInstall plants a crash-loop record whose
// component, origin and detail carry ESC, CR and newline bytes — the record's
// directory is writable by the service uid — and drives it through every
// install/start reader that renders it: the parked and not-coming-up server
// errors, and the agent's tripped and did-not-recover errors and its log line.
// None of those bytes may reach the error text or the log of an operator
// running `sudo k3sm install` or `start`.
func TestHostileCrashRecordRendersAsDataOnInstall(t *testing.T) {
	const hostile = "kine\x1b]0;owned\x07\x1b[2J\rFAKE: install succeeded\nnext line‮"
	installStart := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	at := installStart.Add(time.Minute)

	check := func(t *testing.T, what, s string) {
		t.Helper()
		if bad := controlRunes(s); len(bad) > 0 {
			t.Errorf("%s carries control runes %q (ESC, CR, newline and the like) from the record: %q", what, bad, s)
		}
	}

	t.Run("server parked", func(t *testing.T) {
		f := reinstallFake(t)
		cfg := installCfg(t).withDefaults()
		seedCrashRecord(t, f, cfg, executor.CrashRecord{TrippedAt: &at, Crashes: []executor.Crash{
			{At: at, Origin: hostile, Component: hostile, Detail: hostile, Permanent: true},
		}})
		err := verifyServerNotParked(f, cfg, artifactManifest(cfg), installStart)
		if err == nil {
			t.Fatal("verifyServerNotParked passed over a tripped record")
		}
		check(t, "the parked error", err.Error())
		if strings.Contains(err.Error(), "FAKE: install succeeded") {
			t.Errorf("the parked error carries text from the record's origin: %q", err)
		}
	})

	// An origin with no control rune in it is still not one the executor
	// writes: it is data, and the parked error names it "unknown".
	t.Run("server parked, printable unknown origin", func(t *testing.T) {
		const fake = "FAKE: install succeeded"
		f := reinstallFake(t)
		cfg := installCfg(t).withDefaults()
		seedCrashRecord(t, f, cfg, executor.CrashRecord{TrippedAt: &at, Crashes: []executor.Crash{
			{At: at, Origin: fake, Component: "kine", Detail: "x", Permanent: true},
		}})
		err := verifyServerNotParked(f, cfg, artifactManifest(cfg), installStart)
		if err == nil {
			t.Fatal("verifyServerNotParked passed over a tripped record")
		}
		if strings.Contains(err.Error(), fake) {
			t.Errorf("the parked error carries the record's unknown origin %q: %q", fake, err)
		}
		if !strings.Contains(err.Error(), "unknown: kine") {
			t.Errorf("the parked error does not name the unknown origin \"unknown\": %q", err)
		}
	})

	t.Run("server not coming up", func(t *testing.T) {
		f := reinstallFake(t)
		cfg := installCfg(t).withDefaults()
		seedCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
			{At: at, Origin: executor.CrashOriginBringUp, Component: hostile, Detail: hostile},
		}})
		err := verifyServerNotParked(f, cfg, artifactManifest(cfg), installStart)
		if err == nil {
			t.Fatal("verifyServerNotParked passed over a fresh bring-up failure")
		}
		check(t, "the not-coming-up error", err.Error())
	})

	dir := Config{}.withDefaults().agentWorkDir()
	agentRun := func(t *testing.T, rec executor.CrashRecord) ([]string, error) {
		t.Helper()
		clk := &steppedClock{at: installStart.Add(5 * time.Second), step: time.Second}
		f := &fakeSystem{}
		cfg := agentCfg(t).withDefaults()
		var logged []string
		cfg.Logger = slog.New(rawTextHandler{mu: &sync.Mutex{}, lines: &logged})
		cred := mintNodeCredential(t, dir)
		cred.seed(f)
		seedAgentCrashRecord(t, f, cfg, rec)
		f.putFile(cfg.agentTokenPath(), []byte(cred.token+"\n"))
		err := verifyAgentJoinedOn(context.Background(), f, cfg, installStart, clk.clock())
		return logged, err
	}

	t.Run("agent tripped", func(t *testing.T) {
		logged, err := agentRun(t, executor.CrashRecord{TrippedAt: &at, Crashes: []executor.Crash{
			{At: at, Origin: hostile, Component: hostile, Detail: hostile},
		}})
		if err == nil {
			t.Fatal("verifyAgentJoined passed over a tripped record")
		}
		check(t, "the agent's tripped error", err.Error())
		for _, line := range logged {
			check(t, "the agent's log line", line)
		}
	})

	t.Run("agent did not recover", func(t *testing.T) {
		logged, err := agentRun(t, executor.CrashRecord{Crashes: []executor.Crash{
			{At: installStart.Add(2 * time.Second), Origin: executor.CrashOriginBringUp, Component: hostile, Detail: hostile},
		}})
		if err == nil {
			t.Fatal("verifyAgentJoined passed over a fresh start failure with no live daemon")
		}
		if !strings.Contains(strings.Join(logged, "\n"), "the agent recorded a start failure during this install") {
			t.Fatalf("the run never logged the recorded failure, so the log path was not exercised: %q", logged)
		}
		check(t, "the agent's did-not-recover error", err.Error())
		for _, line := range logged {
			check(t, "the agent's log line", line)
		}
	})
}

// TestAgentFailureDetailKeepsLineBreaksAsSpaces pins that a multi-line detail
// (a log tail) renders with its CR, LF and TAB runs as single spaces rather
// than fused away, still carries no control rune, and that a detail of nothing
// but control characters still reads as no detail.
func TestAgentFailureDetailKeepsLineBreaksAsSpaces(t *testing.T) {
	for _, tc := range []struct{ detail, want string }{
		{"line one\nline two\tend", "line one line two end"},
		{"a\r\n\r\nb", "a b"},
		{"\r\n\t", "no detail recorded"},
		{"\x1b\r\n", "no detail recorded"},
	} {
		got := agentFailureDetail(executor.Crash{Detail: tc.detail})
		if got != tc.want {
			t.Errorf("agentFailureDetail(%q) = %q, want %q", tc.detail, got, tc.want)
		}
		if bad := controlRunes(got); len(bad) > 0 {
			t.Errorf("agentFailureDetail(%q) carries control runes %q", tc.detail, bad)
		}
	}
}
