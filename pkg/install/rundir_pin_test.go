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

// This file is deliberately in the EXTERNAL test package. pkg/provider imports
// pkg/install, so the package under test cannot import the provider back — but an
// external test package may, and that is the only place the two halves of this
// invariant can be compared at all.
package install_test

import (
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/provider"
)

// TestRunDirIsTheSocketsDirectory is the invariant behind the first reinstall
// defect: the directory the ROOT installer prepares for the service user must be
// the directory the UNPRIVILEGED node then binds its runtimed control socket in.
//
// The two were never one string. The installer knew only /var/lib/k3sm/run/vm and
// left run/ itself to whichever daemon created it first — root netd — so the
// server's bind of runtimed.sock failed EACCES and the control socket was
// disabled after a bounded retry, on an install that reported success. A second
// literal is exactly how that happens again, so the derivations are compared
// here rather than trusted to stay in step.
func TestRunDirIsTheSocketsDirectory(t *testing.T) {
	for _, root := range []string{"", "/var/lib/k3sm", "/opt/k3sm-lab", "/Users/_k3sm/dev-cluster"} {
		socket := provider.RuntimedSocketPath(root)
		if got, want := install.RunDir(root), filepath.Dir(socket); got != want {
			t.Errorf("install.RunDir(%q) = %q, but the node binds its control socket in %q (socket %q)", root, got, want, socket)
		}
	}
}
