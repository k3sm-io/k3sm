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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/proxy"
)

// kern.maxfilesperproc scales with installed RAM. These are the values measured
// on 2026-09-26 on macOS 26: the 64 GB studio and the 8 GB laptop.
const (
	maxFilesPerProc64GB = 245760
	maxFilesPerProc8GB  = 10240
)

// TestServerFileLimitDeploymentUX is the B405 gate: the operator-visible side of
// serverFileLimit. The kernel allocates a process at most kern.maxfilesperproc
// descriptors whatever launchd granted it, and launchd binds a changed limit
// only on bootout→bootstrap; install has to say both out loud, for both node
// roles. The number itself is coupled to darwin-net's UDP flow budget, which
// the last subtest pins through darwin-net's own exported rule.
func TestServerFileLimitDeploymentUX(t *testing.T) {
	shrinkRestartBudgets(t)

	roles := []struct {
		name  string
		label string
		cfg   func(t *testing.T) Config
		seed  func(t *testing.T, f *fakeSystem)
	}{
		{name: "server", label: ServerLabel, cfg: func(*testing.T) Config { return installCfg() }, seed: func(*testing.T, *fakeSystem) {}},
		{name: "agent", label: AgentLabel, cfg: agentCfg, seed: func(t *testing.T, f *fakeSystem) { seedJoinedAgent(t, f) }},
	}
	install := func(t *testing.T, f *fakeSystem, cfg Config, level slog.Level) string {
		t.Helper()
		var buf bytes.Buffer
		cfg.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level}))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v (a file-limit check must never fail an install)", err)
		}
		return buf.String()
	}
	capWarned := func(log string) bool {
		for _, line := range strings.Split(log, "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "kern.maxfilesperproc") {
				return true
			}
		}
		return false
	}
	const reloadMark = "launchctl kickstart -k alone would NOT"

	for _, role := range roles {
		t.Run(role.name+"/kernel fd cap", func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				kmax       uint64
				probeErr   error
				wantWarn   bool
				wantBudget int64
			}{
				{name: "ceiling below the limit (8 GB Mac) warns", kmax: maxFilesPerProc8GB, wantWarn: true, wantBudget: proxy.MaxUDPFlows},
				{name: "ceiling below the limit, above twice the floor, warns", kmax: serverFileLimit / 2, wantWarn: true, wantBudget: serverFileLimit / 4},
				{name: "ceiling equal to the limit is silent", kmax: serverFileLimit},
				{name: "ceiling above the limit (64 GB Mac) is silent", kmax: maxFilesPerProc64GB},
				{name: "probe error is skipped at DEBUG", probeErr: errors.New("sysctl: boom")},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := &fakeSystem{maxFilesPerProc: tc.kmax, maxFilesPerProcErr: tc.probeErr}
					role.seed(t, f)
					log := install(t, f, role.cfg(t), slog.LevelDebug)
					if got := capWarned(log); got != tc.wantWarn {
						t.Fatalf("fd-cap WARN present = %v, want %v; log =\n%s", got, tc.wantWarn, log)
					}
					if tc.wantWarn {
						remedy := fmt.Sprintf("sudo sysctl -w kern.maxfiles=%d kern.maxfilesperproc=%d", serverFileLimit, serverFileLimit)
						for _, want := range []string{
							"label=" + role.label,
							fmt.Sprintf("requested=%d", serverFileLimit),
							fmt.Sprintf("kern.maxfilesperproc=%d", tc.kmax),
							fmt.Sprintf("udp-flow-budget=%d", tc.wantBudget),
							"keeps its requested open-file soft limit",
							"scales with installed RAM",
							remedy,
							"does not survive a reboot",
						} {
							if !strings.Contains(log, want) {
								t.Errorf("the fd-cap WARN must carry %q; log =\n%s", want, log)
							}
						}
					}
					if tc.probeErr != nil && !(strings.Contains(log, "level=DEBUG") && strings.Contains(log, "skipping the open-file cap check")) {
						t.Errorf("a probe error must be logged at DEBUG and skipped; log =\n%s", log)
					}
				})
			}
		})

		t.Run(role.name+"/reload notice", func(t *testing.T) {
			stock := string(renderFor(t, role.label, role.cfg(t)))
			limitXML := fmt.Sprintf("<integer>%d</integer>", serverFileLimit)
			if !strings.Contains(stock, limitXML) {
				t.Fatalf("the stock %s plist does not carry %s", role.label, limitXML)
			}
			for _, tc := range []struct {
				name       string
				onDisk     string // "" = no plist on disk (fresh install)
				wantNotice bool
				wantOld    int
			}{
				{name: "fresh install: no notice"},
				{name: "same limit on disk: no notice", onDisk: stock},
				{name: "changed limit on disk: notice", onDisk: strings.ReplaceAll(stock, limitXML, "<integer>256</integer>"), wantNotice: true, wantOld: 256},
				{name: "pre-limit plist on disk: notice", onDisk: stripResourceLimits(t, stock), wantNotice: true, wantOld: 0},
				{name: "malformed limit on disk: no notice, no failure", onDisk: strings.Replace(stock, limitXML, "<integer>lots</integer>", 1)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := &fakeSystem{}
					role.seed(t, f)
					cfg := role.cfg(t)
					if tc.onDisk != "" {
						f.putFile(cfg.withDefaults().plistPath(role.label), []byte(tc.onDisk))
					}
					log := install(t, f, cfg, slog.LevelInfo)
					at := strings.Index(log, reloadMark)
					if got := at >= 0; got != tc.wantNotice {
						t.Fatalf("reload notice present = %v, want %v; log =\n%s", got, tc.wantNotice, log)
					}
					if !tc.wantNotice {
						return
					}
					for _, want := range []string{
						"label=" + role.label,
						fmt.Sprintf("old=%d", tc.wantOld),
						fmt.Sprintf("new=%d", serverFileLimit),
					} {
						if !strings.Contains(log[at:], want) {
							t.Errorf("the reload notice must carry %q; log =\n%s", want, log)
						}
					}
					// Reported only once the bootout→bootstrap it describes has happened.
					restarted := strings.Index(log, `msg="daemon restarted on the freshly installed binary" label=`+role.label)
					if restarted < 0 || restarted > at {
						t.Errorf("the reload notice must follow the %s restart; log =\n%s", role.label, log)
					}
				})
			}
		})
	}

	// An installed plist that exists but cannot be read. Through Install the
	// argument carry-over reads the same file first and refuses the install on
	// such an error, so the file-limit check is exercised directly: it must
	// neither report a change nor fail.
	t.Run("unreadable installed plist: no notice, no failure", func(t *testing.T) {
		cfg := installCfg().withDefaults()
		path := cfg.plistPath(ServerLabel)
		f := &fakeSystem{readErrs: map[string]error{path: errors.New("read: input/output error")}}
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		if n, ok := checkFileLimit(f, log, ServerLabel, path, ServerPlist(cfg)); ok {
			t.Errorf("an unreadable installed plist reported a limit change %+v", n)
		}
		if !strings.Contains(buf.String(), "skipping the reload notice") {
			t.Errorf("the unreadable plist must be logged at DEBUG and skipped; log =\n%s", buf.String())
		}
	})

	t.Run("coupling to darwin-net's UDP flow budget", func(t *testing.T) {
		const wantBudget = 65536
		for _, tc := range []struct {
			name string
			kmax uint64
			want int64
		}{
			{name: "unknown kernel cap", kmax: 0, want: wantBudget},
			{name: "64 GB Mac", kmax: maxFilesPerProc64GB, want: wantBudget},
			{name: "8 GB Mac", kmax: maxFilesPerProc8GB, want: proxy.MaxUDPFlows},
		} {
			if got := proxy.UDPFlowBudgetFor(serverFileLimit, tc.kmax); got != tc.want {
				t.Errorf("%s: proxy.UDPFlowBudgetFor(%d, %d) = %d, want %d", tc.name, serverFileLimit, tc.kmax, got, tc.want)
			}
		}
		if serverFileLimit/2 < proxy.MaxUDPFlows {
			t.Errorf("serverFileLimit/2 = %d must clear darwin-net's %d floor, or the half-for-UDP split is void",
				serverFileLimit/2, proxy.MaxUDPFlows)
		}
		// Both node plists request exactly this limit, as the parser reads it back.
		for name, p := range map[string][]byte{"server": ServerPlist(Config{}), "agent": AgentPlist(Config{})} {
			got, err := plistSoftFileLimit(p)
			if err != nil || got != serverFileLimit {
				t.Errorf("%s plist SoftResourceLimits NumberOfFiles = %d, %v; want %d", name, got, err, serverFileLimit)
			}
		}
	})
}

// renderFor renders label's plist the way Install would for cfg.
func renderFor(t *testing.T, label string, cfg Config) []byte {
	t.Helper()
	p, err := plistContent(label, cfg.withDefaults())
	if err != nil {
		t.Fatalf("render %s: %v", label, err)
	}
	return p
}

// stripResourceLimits removes both *ResourceLimits dicts, rendering the plist an
// install from before the limit existed left on disk.
func stripResourceLimits(t *testing.T, plist string) string {
	t.Helper()
	for _, key := range []string{"SoftResourceLimits", "HardResourceLimits"} {
		start := strings.Index(plist, "  <key>"+key+"</key>")
		if start < 0 {
			t.Fatalf("no %s key to strip", key)
		}
		end := strings.Index(plist[start:], "</dict>\n")
		if end < 0 {
			t.Fatalf("no %s dict to strip", key)
		}
		plist = plist[:start] + plist[start+end+len("</dict>\n"):]
	}
	if n, err := plistSoftFileLimit([]byte(plist)); err != nil || n != 0 {
		t.Fatalf("stripped plist still reads NumberOfFiles %d (%v)", n, err)
	}
	return plist
}
