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
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

// TestRegistryServeVerb pins the hidden verb's command line and that it stays
// hidden: the usage and the unknown-verb hint never name it.
func TestRegistryServeVerb(t *testing.T) {
	const config = "/var/lib/k3sm/server/registry-state/serve.json"
	t.Run("passes the config to the server", func(t *testing.T) {
		var got string
		want := errors.New("served")
		err := runRegistryServe([]string{"--config", config}, io.Discard, func(ctx context.Context, path string) error {
			if err := ctx.Err(); err != nil {
				t.Errorf("the server got a dead context: %v", err)
			}
			got = path
			return want
		})
		if !errors.Is(err, want) || got != config {
			t.Errorf("got path %q, err %v", got, err)
		}
	})
	refused := map[string][]string{
		"no config":       nil,
		"empty config":    {"--config", ""},
		"a stray arg":     {"--config", config, "extra"},
		"an unknown flag": {"--listen", "127.0.0.1:1"},
	}
	for name, args := range refused {
		t.Run(name, func(t *testing.T) {
			err := runRegistryServe(args, io.Discard, func(context.Context, string) error {
				t.Error("the server ran")
				return nil
			})
			if err == nil {
				t.Error("the command line was accepted")
			}
		})
	}
	t.Run("a bad command line never reaches the server through the dispatcher", func(t *testing.T) {
		if err := runRegistry([]string{"serve"}, io.Discard, io.Discard); err == nil {
			t.Error("registry serve with no config succeeded")
		}
	})
	t.Run("it is hidden", func(t *testing.T) {
		var b strings.Builder
		if err := runRegistry([]string{"--help"}, &b, io.Discard); err != nil {
			t.Fatal(err)
		}
		// "server" and "--server" are ordinary words of the usage.
		if regexp.MustCompile(`\bserve\b`).MatchString(b.String()) {
			t.Errorf("the usage names the verb:\n%s", b.String())
		}
		err := runRegistry([]string{"nonsense"}, io.Discard, io.Discard)
		if err == nil || regexp.MustCompile(`\bserve\b`).MatchString(err.Error()) {
			t.Errorf("the unknown-verb error names it: %v", err)
		}
	})
}
