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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestContainerLogFlagsMatchKubeletDefaults pins the container-log flag surface:
// the NAMES are the kubelet's KubeletConfiguration fields and the DEFAULTS are
// the kubelet's defaults, on every command that brings a node up.
//
// This is a compatibility contract, not a style preference. k3s sets none of
// these, so upstream's defaults are what a k3s user has experienced, and an
// operator who knows what --container-log-max-size does elsewhere must not have
// to find out that it means something else here. A renamed flag or a changed
// default is a silent behaviour change for every existing runbook.
func TestContainerLogFlagsMatchKubeletDefaults(t *testing.T) {
	want := map[string]string{
		"pod-logs-dir":                   "/var/log/pods",
		"container-log-max-size":         "10Mi",
		"container-log-max-files":        "5",
		"container-log-max-workers":      "1",
		"container-log-monitor-interval": "10s",
	}

	registrars := map[string]func(fs *flag.FlagSet){
		"node":   func(fs *flag.FlagSet) { registerNodeFlags(fs, &nodeOptions{}) },
		"server": func(fs *flag.FlagSet) { registerServerFlags(fs, &serverOptions{}) },
		"agent":  func(fs *flag.FlagSet) { registerAgentFlags(fs, &agentOptions{}) },
	}
	for cmd, register := range registrars {
		t.Run(cmd, func(t *testing.T) {
			fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
			register(fs)
			for name, def := range want {
				f := fs.Lookup(name)
				if f == nil {
					t.Errorf("`k3sm %s` does not register --%s", cmd, name)
					continue
				}
				if f.DefValue != def {
					t.Errorf("`k3sm %s --%s` default = %q, want the kubelet's %q", cmd, name, f.DefValue, def)
				}
			}
		})
	}

	// The two refusals the flag layer owns. They are refusals rather than
	// clamps because the rotation manager degrades on a bad policy: without
	// these an operator's typo shows up as a line in server.log an hour later
	// and a full system volume a week later.
	t.Run("validate refuses a policy that cannot work", func(t *testing.T) {
		good := containerLogOptions{
			dir: "/var/log/pods", maxSize: "10Mi", maxFiles: 5, maxWorkers: 1,
			monitorInterval: 10 * time.Second,
		}
		if err := good.validate(); err != nil {
			t.Fatalf("the kubelet defaults were rejected: %v", err)
		}
		cases := []struct {
			name string
			opts containerLogOptions
			want string
		}{
			{name: "maxFiles 1 rotates and immediately discards", opts: withFiles(good, 1), want: "must be > 1"},
			{name: "maxFiles 0", opts: withFiles(good, 0), want: "must be > 1"},
			{name: "a max size that is not a quantity", opts: withSize(good, "10 megabytes"), want: "resource quantity"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.opts.validate()
				if err == nil {
					t.Fatal("validate accepted it")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("err = %v, want it to mention %q", err, tc.want)
				}
			})
		}
		// A NEGATIVE size is valid: it is upstream's documented way to turn
		// rotation off, and refusing it would remove a knob operators have.
		if err := withSize(good, "-1").validate(); err != nil {
			t.Errorf("a negative max size was rejected: %v (it is upstream's rotation opt-out)", err)
		}
	})

	// The node REFUSES to start when the tree is missing or unwritable, and the
	// refusal names the command that creates it. It never creates the directory
	// itself: on a real install only root can, at a mode that keeps pod output
	// off every local account.
	t.Run("a missing or unwritable pod-logs dir is a refusal naming k3sm install", func(t *testing.T) {
		missing := containerLogOptions{dir: filepath.Join(t.TempDir(), "absent")}
		err := missing.ensureWritable()
		if err == nil {
			t.Fatal("ensureWritable accepted a missing directory")
		}
		if !strings.Contains(err.Error(), "k3sm install") {
			t.Errorf("err = %v, want it to name `k3sm install`", err)
		}
		if _, statErr := os.Stat(missing.dir); statErr == nil {
			t.Error("ensureWritable CREATED the directory; it must refuse instead")
		}

		ok := containerLogOptions{dir: t.TempDir()}
		if err := ok.ensureWritable(); err != nil {
			t.Errorf("ensureWritable on a writable directory: %v", err)
		}
		// The probe leaves nothing behind.
		entries, rerr := os.ReadDir(ok.dir)
		if rerr != nil {
			t.Fatalf("read dir: %v", rerr)
		}
		if len(entries) != 0 {
			t.Errorf("the write probe left %d entries behind", len(entries))
		}

		unwritable := filepath.Join(t.TempDir(), "readonly")
		if err := os.Mkdir(unwritable, 0o500); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := (containerLogOptions{dir: unwritable}).ensureWritable(); err == nil {
			t.Error("ensureWritable accepted a directory it cannot write in")
		}
	})
}

// withFiles returns o with a different maxFiles.
func withFiles(o containerLogOptions, n int) containerLogOptions {
	o.maxFiles = n
	return o
}

// withSize returns o with a different maxSize.
func withSize(o containerLogOptions, s string) containerLogOptions {
	o.maxSize = s
	return o
}
