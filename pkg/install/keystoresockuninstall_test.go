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
	"context"
	"errors"
	"slices"
	"testing"
)

// A server bootout that fails leaves the job loaded, its plist in place
// and keystore-sock/ with it: the directory is removed only when the
// server's bootout succeeded in the same uninstall pass.
func TestUninstallKeepsKeystoreSockDirWhenServerBootoutFails(t *testing.T) {
	const dir = "RemoveAll:/var/lib/k3sm/keystore-sock"
	f := &fakeSystem{}
	f.purge.bootoutErrs = map[string]error{ServerLabel: errors.New("Boot-out failed: 5: Input/output error")}
	if err := Uninstall(context.Background(), f, Config{}); err == nil {
		t.Fatal("Uninstall succeeded over a failed server bootout")
	}
	if !slices.Contains(f.calls, "Bootout:"+ServerLabel) {
		t.Fatalf("no server bootout: %v", f.calls)
	}
	if slices.Contains(f.calls, dir) {
		t.Fatalf("keystore-sock/ removed while the server job may still be loaded: %v", f.calls)
	}
	ok := &fakeSystem{}
	if err := Uninstall(context.Background(), ok, Config{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ok.calls, dir) {
		t.Fatalf("keystore-sock/ not removed after a clean bootout: %v", ok.calls)
	}
}
