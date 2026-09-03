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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/builder"
)

// TestBuilderConfigMapping pins the flag-to-spec mapping.
func TestBuilderConfigMapping(t *testing.T) {
	opts := builderOptions{
		namespace:  "ns",
		node:       "mac-2",
		image:      "example/buildkit@sha256:abc",
		pullSecret: "ghcr",
		cacheSize:  "80Gi",
		port:       2000,
		mirror:     true,
	}
	cfg := builderConfig(opts)
	if cfg.Namespace != "ns" || cfg.NodeName != "mac-2" || cfg.Image != "example/buildkit@sha256:abc" {
		t.Errorf("mapping lost a field: %+v", cfg)
	}
	if !cfg.UseMirror || cfg.PullSecret != "ghcr" || cfg.CacheSize != "80Gi" || cfg.TCPPort != 2000 {
		t.Errorf("mapping lost a field: %+v", cfg)
	}
}

// TestParseBuilderArgsDefaults pins the default flag values.
func TestParseBuilderArgsDefaults(t *testing.T) {
	opts, err := parseBuilderArgs("up", nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.namespace != builder.DefaultNamespace {
		t.Errorf("namespace default = %q", opts.namespace)
	}
	if opts.port != builder.DefaultTCPPort {
		t.Errorf("port default = %d", opts.port)
	}
	if opts.mirror {
		t.Errorf("mirror should default false (upstream-direct pull needs no token)")
	}
	if opts.workDir == "" {
		t.Errorf("work dir should be resolved from the environment default")
	}
}

// TestBuilderAcceptsDelete pins that `delete` is a wired subcommand: it parses
// like the other verbs, and runBuilder dispatches it past the accept list rather
// than rejecting it as unknown. With a temp work dir (no kubeconfig) it reaches
// the legible control-plane error — proof it was accepted, not refused. A missing
// accept-list entry would instead surface the "unknown subcommand" error.
func TestBuilderAcceptsDelete(t *testing.T) {
	if _, err := parseBuilderArgs("delete", nil); err != nil {
		t.Fatalf("parse delete: %v", err)
	}
	err := runBuilder([]string{"delete", "--work-dir", t.TempDir()})
	if err == nil {
		t.Fatal("expected the legible control-plane error for a missing kubeconfig")
	}
	if strings.Contains(err.Error(), "unknown") {
		t.Errorf("delete was refused as unknown, not accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "k3sm server") {
		t.Errorf("expected the legible kubeconfig error, got: %v", err)
	}
}

// TestBuilderUsageListsDelete pins that the usage string advertises delete and
// distinguishes it from down (full reset vs keep-cache stop).
func TestBuilderUsageListsDelete(t *testing.T) {
	if !strings.Contains(builderUsage, "up|down|delete|status") {
		t.Errorf("usage does not list delete in the subcommand line")
	}
	if !strings.Contains(builderUsage, "full reset") {
		t.Errorf("usage does not describe delete as a full reset")
	}
}

// TestBuilderAbsentControlPlaneIsLegible pins that a missing kubeconfig names the
// fix (`k3sm server`) rather than surfacing a bare file-not-found.
func TestBuilderAbsentControlPlaneIsLegible(t *testing.T) {
	opts := builderOptions{workDir: t.TempDir()}
	_, err := newBuilderManager(opts)
	if err == nil {
		t.Fatal("expected an error for a missing kubeconfig")
	}
	if !strings.Contains(err.Error(), "k3sm server") {
		t.Errorf("error does not name the fix: %v", err)
	}
}
