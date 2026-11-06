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
	"io"
	"log/slog"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestLauncherConfigStarts proves the launcher's configuration builds a
// server: api.New refuses a config it cannot run (a missing GC grace was one).
func TestLauncherConfigStarts(t *testing.T) {
	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := api.New(serverConfig(st, log, api.AllowAll, 64<<20)); err != nil {
		t.Fatalf("the launcher's config does not build a server: %v", err)
	}
}
