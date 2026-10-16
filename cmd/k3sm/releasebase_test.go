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

	"k3sm.io/k3sm/pkg/update"
	"k3sm.io/k3sm/pkg/updatectl"
)

// TestUpdateReleaseBaseWiring pins --update-release-base outside the node: the
// controller's resolver and the update check read the recorded base when one
// is set and GitHub's index otherwise, the install flag refuses plain http on
// a public host, and an accepted value reaches the install Config.
func TestUpdateReleaseBaseWiring(t *testing.T) {
	t.Parallel()
	const base = "http://192.168.0.50:8080/releases"
	got, err := updateResolver(base + "/").AssetURL("v0.2.0")
	if err != nil || got != base+"/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz" {
		t.Errorf("resolver with a base: AssetURL = %q, %v", got, err)
	}
	if r := updateResolver(""); r.Base != "" {
		t.Errorf("resolver with no base = %q, want GitHub's default", r.Base)
	}
	if def, _ := updateResolver("").AssetURL("v0.2.0"); !strings.HasPrefix(def, updatectl.DefaultReleaseBase+"/download/") {
		t.Errorf("default resolver AssetURL = %q", def)
	}
	if got := checkBase(releaseBaseURL(base)); got != base {
		t.Errorf("check base = %q, want %q", got, base)
	}
	if got := checkBase(releaseBaseURL("")); got != update.DefaultBaseURL {
		t.Errorf("check base with none = %q, want %q", got, update.DefaultBaseURL)
	}
	if got := releaseBaseURL("http://example.com/releases"); got != "" {
		t.Errorf("an invalid recorded base reached the check as %q", got)
	}
	o, err := parseInstallFlags([]string{"--user", "admin", "--update-release-base", base + "/"})
	if err != nil {
		t.Fatalf("parseInstallFlags = %v", err)
	}
	if cfg := o.installConfig("/tmp/k3sm", nil, nil); cfg.UpdateReleaseBase != base {
		t.Errorf("install Config UpdateReleaseBase = %q, want %q", cfg.UpdateReleaseBase, base)
	}
	if _, err := parseInstallFlags([]string{"--user", "admin", "--update-release-base", "http://example.com/releases"}); err == nil || !strings.Contains(err.Error(), "RFC 1918") {
		t.Errorf("parseInstallFlags with http on a public host = %v, want refused", err)
	}
	if _, err := parseInstallFlags([]string{"--user", "admin", "--agent", "--server", "192.0.2.10", "--update-release-base", "https://mirror.example.com/r"}); err != nil {
		t.Errorf("an agent install with an https mirror = %v, want accepted", err)
	}
}
