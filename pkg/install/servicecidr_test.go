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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/defaults"
)

// TestServiceCIDRFlagAgreesWithTheAPIServer pins the one Service range netd
// and the apiserver share. --service-cidr reaches only netd's plist; the
// apiserver's --service-cluster-ip-range (and the DNS VIP, the API VIP and the
// serving SANs) are fixed to defaults.ServiceCIDR, which pkg/executor's
// TestAPIServerServiceRangeIsTheDefault pins. A different value would leave
// the two disagreeing, so install refuses it before anything is written.
func TestServiceCIDRFlagAgreesWithTheAPIServer(t *testing.T) {
	base := func() Config { return Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"} }

	t.Run("a non-default range is refused before anything is written", func(t *testing.T) {
		for _, role := range []Role{RoleServer, RoleAgent} {
			f := &fakeSystem{}
			cfg := base()
			cfg.Role = role
			if role == RoleAgent {
				cfg.JoinServer = "192.168.1.10"
			}
			cfg.ServiceCIDR = "10.44.0.0/16"
			err := Install(context.Background(), f, cfg)
			if err == nil {
				t.Fatalf("%s: Install succeeded with --service-cidr 10.44.0.0/16, want a refusal", role)
			}
			for _, want := range []string{"--service-cidr", "10.44.0.0/16", defaults.ServiceCIDR} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: refusal does not name %q: %v", role, want, err)
				}
			}
			// Only the read-only role probe runs first; nothing is written.
			for _, c := range f.calls {
				if !strings.HasPrefix(c, "ReadFile:") {
					t.Errorf("%s: Install made a non-read system call before refusing: %s", role, c)
				}
			}
			if len(f.files) != 0 {
				t.Errorf("%s: Install wrote files before refusing: %v", role, f.files)
			}
		}
	})

	t.Run("the default range is accepted and reaches netd", func(t *testing.T) {
		for _, svc := range []string{"", defaults.ServiceCIDR} {
			f := &fakeSystem{}
			cfg := base()
			cfg.ServiceCIDR = svc
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install with --service-cidr %q: %v", svc, err)
			}
			path := cfg.withDefaults().plistPath(NetdLabel)
			args, err := parseProgramArguments(f.files[path])
			if err != nil {
				t.Fatalf("netd plist %s: %v", path, err)
			}
			if got := flagValue(args, "service-cidr"); got != defaults.ServiceCIDR {
				t.Errorf("netd --service-cidr = %q, want %q", got, defaults.ServiceCIDR)
			}
		}
	})

	t.Run("a worker still refuses the control-plane flags", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := base()
		cfg.Role = RoleAgent
		cfg.JoinServer = "192.168.1.10"
		cfg.ClusterInit = true
		err := Install(context.Background(), f, cfg)
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with --agent") {
			t.Fatalf("Install(agent, --cluster-init) = %v, want the agent-role refusal", err)
		}
	})
}
