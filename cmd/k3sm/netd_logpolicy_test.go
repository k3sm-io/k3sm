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
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// logEnsureCall is one call the fake log-policy System recorded.
type logEnsureCall struct {
	method string
	dir    string
	uid    uint32
}

// fakeLogPolicySystem records the installer ensure calls netd makes, and fails
// the ones named in fail.
type fakeLogPolicySystem struct {
	calls []logEnsureCall
	fail  map[string]error // keyed by dir
}

func (f *fakeLogPolicySystem) EnsureLogDir(dir string, uid uint32) error {
	f.calls = append(f.calls, logEnsureCall{"EnsureLogDir", dir, uid})
	return f.fail[dir]
}

func (f *fakeLogPolicySystem) EnsureContainerLogDir(dir string, uid uint32) error {
	f.calls = append(f.calls, logEnsureCall{"EnsureContainerLogDir", dir, uid})
	return f.fail[dir]
}

// TestNetdStartReappliesLogPolicy pins that a netd start re-applies the log
// ownership policy `k3sm install` lays down, through the installer's own ensure
// functions with the service uid, to every path the installer ensures: the
// daemon log dir (whose EnsureLogDir pre-creates the server, agent, netd and
// datavol logs) and each container-log directory. A macOS upgrade replaced
// /var/log on a worker and left the agent unable to start until someone re-ran
// the install; netd, root and started first, is what repairs it now.
//
// An ensure error is logged and is never fatal: the remaining paths are still
// repaired and the start goes on.
func TestNetdStartReappliesLogPolicy(t *testing.T) {
	const uid uint32 = 263

	want := []logEnsureCall{{"EnsureLogDir", install.LogDir, uid}}
	for _, dir := range install.ContainerLogDirs() {
		want = append(want, logEnsureCall{"EnsureContainerLogDir", dir, uid})
	}
	// The list netd walks must be the installer's whole container-log tree.
	for _, dir := range []string{install.PodLogsDir, install.ContainerLogsDir} {
		if !slices.Contains(install.ContainerLogDirs(), dir) {
			t.Fatalf("install.ContainerLogDirs() = %v, missing %s", install.ContainerLogDirs(), dir)
		}
	}

	tests := []struct {
		name     string
		fail     map[string]error
		wantWarn []string // dirs a Warn line must name
	}{
		{name: "every installer-ensured path is re-applied with the service uid"},
		{
			name:     "a log dir error is logged and the container log dirs are still repaired",
			fail:     map[string]error{install.LogDir: errors.New("chown denied")},
			wantWarn: []string{install.LogDir},
		},
		{
			name:     "a container log dir error is logged and the next one is still repaired",
			fail:     map[string]error{install.PodLogsDir: errors.New("read-only file system")},
			wantWarn: []string{install.PodLogsDir},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := &fakeLogPolicySystem{fail: tt.fail}
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			// reapplyLogPolicy returns nothing: an error cannot fail the start.
			reapplyLogPolicy(sys, uid, logger)

			if !slices.Equal(sys.calls, want) {
				t.Errorf("ensure calls = %+v, want %+v", sys.calls, want)
			}
			out := buf.String()
			warns := 0
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				if strings.Contains(line, "level=WARN") {
					warns++
				}
			}
			if warns != len(tt.wantWarn) {
				t.Errorf("got %d Warn lines, want %d:\n%s", warns, len(tt.wantWarn), out)
			}
			for _, dir := range tt.wantWarn {
				if !hasLogLine(out, "level=WARN", "dir="+dir+" ") {
					t.Errorf("no Warn line names %s:\n%s", dir, out)
				}
			}
			for _, c := range want {
				if _, failed := tt.fail[c.dir]; failed {
					continue
				}
				if !hasLogLine(out, "level=INFO", "dir="+c.dir+" ") {
					t.Errorf("no Info line names the repaired %s:\n%s", c.dir, out)
				}
			}
		})
	}
}

// hasLogLine reports whether one line of out contains every one of parts.
func hasLogLine(out string, parts ...string) bool {
	for _, line := range strings.Split(out, "\n") {
		if !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(line, p) }) {
			return true
		}
	}
	return false
}
