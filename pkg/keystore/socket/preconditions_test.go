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

package socket

import (
	"context"
	"errors"
	"testing"
)

// passing returns Preconditions under which every check passes.
func passing() Preconditions {
	return Preconditions{
		EUID:              func() int { return 260 },
		ServiceUID:        260,
		MaintenanceMarked: func() (bool, error) { return false, nil },
		OpenLogs:          func(context.Context) error { return nil },
		IgnoresOwnership:  func() (bool, error) { return false, nil },
		CheckInstall:      func(context.Context) error { return nil },
		ServerCount:       func(context.Context) (int, error) { return 1, nil },
	}
}

// TestPreconditionsCheck checks each start check maps to its reason, that
// the first failing check in the design's order wins, and that only the
// install reason names a remedy. The Supervisor and doctor both run this
// evaluator.
func TestPreconditionsCheck(t *testing.T) {
	boom := errors.New("boom")
	for _, tt := range []struct {
		name string
		mut  func(*Preconditions)
		want OffReason
	}{
		{"all pass", func(*Preconditions) {}, ""},
		{"rootless", func(p *Preconditions) { p.EUID = func() int { return 501 } }, OffNotInstalledServer},
		{"marker", func(p *Preconditions) { p.MaintenanceMarked = func() (bool, error) { return true, nil } }, OffMaintenance},
		{"marker unreadable", func(p *Preconditions) { p.MaintenanceMarked = func() (bool, error) { return false, boom } }, OffMaintenanceUnknown},
		{"ignore ownership", func(p *Preconditions) { p.IgnoresOwnership = func() (bool, error) { return true, nil } }, OffIgnoresOwnership},
		{"mount unreadable", func(p *Preconditions) { p.IgnoresOwnership = func() (bool, error) { return false, boom } }, OffMountUnknown},
		{"install", func(p *Preconditions) { p.CheckInstall = func(context.Context) error { return boom } }, OffInstall},
		{"logs unavailable", func(p *Preconditions) { p.OpenLogs = func(context.Context) error { return boom } }, OffLogsUnavailable},
		{"logs panic", func(p *Preconditions) { p.OpenLogs = func(context.Context) error { panic("fake") } }, OffLogsUnavailable},
		{"two servers", func(p *Preconditions) { p.ServerCount = func(context.Context) (int, error) { return 2, nil } }, OffServers},
		{"no server", func(p *Preconditions) { p.ServerCount = func(context.Context) (int, error) { return 0, nil } }, OffServersUnknown},
		{"count error", func(p *Preconditions) { p.ServerCount = func(context.Context) (int, error) { return 0, boom } }, OffServersUnknown},
		{"sandbox check unusable", func(p *Preconditions) { p.SandboxCheck = func() error { return boom } }, OffSandboxCheckUnusable},
		{"sandbox check panics", func(p *Preconditions) { p.SandboxCheck = func() error { panic("fake") } }, OffSandboxCheckUnusable},
		{"sandbox check usable", func(p *Preconditions) { p.SandboxCheck = func() error { return nil } }, ""},
		{"euid before mount", func(p *Preconditions) {
			p.EUID = func() int { return 0 }
			p.IgnoresOwnership = func() (bool, error) { return true, nil }
		}, OffNotInstalledServer},
		{"mount before install", func(p *Preconditions) {
			p.IgnoresOwnership = func() (bool, error) { return true, nil }
			p.CheckInstall = func(context.Context) error { return boom }
		}, OffIgnoresOwnership},
		{"install before marker", func(p *Preconditions) {
			p.CheckInstall = func(context.Context) error { return boom }
			p.MaintenanceMarked = func() (bool, error) { return false, boom }
		}, OffInstall},
		{"marker before logs", func(p *Preconditions) {
			p.MaintenanceMarked = func() (bool, error) { return true, nil }
			p.OpenLogs = func(context.Context) error { return boom }
		}, OffMaintenance},
		{"logs before sandbox check", func(p *Preconditions) {
			p.OpenLogs = func(context.Context) error { return boom }
			p.SandboxCheck = func() error { return boom }
		}, OffLogsUnavailable},
		{"sandbox check before servers", func(p *Preconditions) {
			p.SandboxCheck = func() error { return boom }
			p.ServerCount = func(context.Context) (int, error) { return 2, nil }
		}, OffSandboxCheckUnusable},
		{"install before servers", func(p *Preconditions) {
			p.CheckInstall = func(context.Context) error { return boom }
			p.ServerCount = func(context.Context) (int, error) { return 2, nil }
		}, OffInstall},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := passing()
			tt.mut(&p)
			if got, detail := p.Check(context.Background()); got != tt.want {
				t.Fatalf("Check = %q (%s), want %q", got, detail, tt.want)
			}
		})
	}
	for _, r := range []OffReason{OffNotInstalledServer, OffMaintenance, OffMaintenanceUnknown, OffIgnoresOwnership, OffMountUnknown, OffLogsUnavailable, OffServers, OffServersUnknown, OffListenerUnavailable, OffListenerFailed, OffSandboxCheckUnusable} {
		if got := r.Remedy(); got != "" {
			t.Errorf("%q names the remedy %q, want none", r, got)
		}
	}
	if got := OffInstall.Remedy(); got != "run `sudo k3sm install`" {
		t.Errorf("the install reason names %q", got)
	}
}
