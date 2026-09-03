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

// TestBuilderAcceptsBuildx pins that `buildx` is a wired subcommand: it is
// dispatched past the accept list rather than refused as unknown. With a temp
// work dir (no kubeconfig) it reaches the legible control-plane error, which is
// proof of acceptance — a missing accept-list entry would say "unknown" instead.
func TestBuilderAcceptsBuildx(t *testing.T) {
	t.Setenv("K3SM_WORK_DIR", t.TempDir())
	err := runBuilder([]string{"buildx", "build", "-t", "myapp:dev", "."})
	if err == nil {
		t.Fatal("expected the legible control-plane error for a missing kubeconfig")
	}
	if strings.Contains(err.Error(), "unknown") {
		t.Errorf("buildx was refused as unknown, not accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "k3sm server") {
		t.Errorf("expected the legible kubeconfig error, got: %v", err)
	}
}

// TestBuilderBuildxNeedsACommand pins that a bare `k3sm builder buildx` explains
// itself instead of running buildx with only the injected --builder.
func TestBuilderBuildxNeedsACommand(t *testing.T) {
	err := runBuilder([]string{"buildx"})
	if err == nil {
		t.Fatal("expected an error for a buildx invocation with no command")
	}
	if !strings.Contains(err.Error(), "buildx build") {
		t.Errorf("error does not show a usable example: %v", err)
	}
}

// TestBuilderUsageListsBuildx pins that both usage strings advertise the
// passthrough and describe it as the driver setup the operator no longer does.
func TestBuilderUsageListsBuildx(t *testing.T) {
	if !strings.Contains(builderUsage, "buildx  run the bundled buildx against the engine") {
		t.Errorf("the builder usage does not list the buildx subcommand")
	}
	if !strings.Contains(builderUsage, "k3sm builder buildx build -t myapp:dev .") {
		t.Errorf("the builder usage shows no worked buildx example")
	}
	for _, want := range []string{"passed to buildx unchanged", builder.BuilderInstanceName, "k3sm builder up"} {
		if !strings.Contains(builderBuildxUsage, want) {
			t.Errorf("the buildx usage does not mention %q", want)
		}
	}
}

// TestBuilderUnknownSubcommandNamesBuildx pins that the refusal for a typo lists
// buildx among the verbs — a discoverability contract, since the passthrough has
// no flags of its own to stumble into.
func TestBuilderUnknownSubcommandNamesBuildx(t *testing.T) {
	err := runBuilder([]string{"buildxx"})
	if err == nil {
		t.Fatal("expected an unknown-subcommand error")
	}
	if !strings.Contains(err.Error(), "buildx") {
		t.Errorf("the unknown-subcommand error does not list buildx: %v", err)
	}
}
