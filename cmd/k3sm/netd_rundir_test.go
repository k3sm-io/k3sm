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

/*
Copyright 2026 The k3sm Authors

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
	"os"
	"strings"
	"testing"
)

// TestListenNetdNeverTakesTheSharedDirForRoot pins the 2026-09-02 boot-order
// fix: the run directory is shared with the service user's own control socket,
// its ownership policy belongs to `k3sm install`, and netd must never chown it
// root:wheel. The old behavior locked _k3sm out of its own socket dir on every
// boot. This is a source-shape pin (the unit tier cannot chown as non-root):
// the root:wheel chown is gone, and the service-user alignment is present.
func TestListenNetdNeverTakesTheSharedDirForRoot(t *testing.T) {
	src, err := os.ReadFile("netd.go")
	if err != nil {
		t.Fatalf("read netd.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, "Chown(dir, 0, 0)") {
		t.Fatalf("listenNetd chowns the shared run dir root:wheel again — that re-introduces the boot-order lockout the 2026-09-02 fix removed")
	}
	for _, want := range []string{"install.DefaultServiceUser", "Chmod(dir, 0o700)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("listenNetd lost the service-user alignment (%q missing)", want)
		}
	}
	// listenNetd still creates the socket root-owned with the 0660 group gate.
	for _, want := range []string{"Chown(socket, 0, gid)", "Chmod(socket, 0o660)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("netd socket posture changed (%q missing) — the SCM_CREDS + 0660 group gate is load-bearing", want)
		}
	}
}
