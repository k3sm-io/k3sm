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

// TestNodePortAddressesPostureAndNormalisation pins the install side of
// --nodeport-addresses: a non-empty value beside --network none is refused by
// name, and the value is trimmed so whitespace-only clears a carried setting.
func TestNodePortAddressesPostureAndNormalisation(t *testing.T) {
	str := func(s string) *string { return &s }

	t.Run("the posture predicate", func(t *testing.T) {
		cases := []struct {
			network, spec string
			refused       bool
		}{
			{"none", "local", true},
			{" none ", "127.0.0.0/8", true},
			{"none", "", false},
			{"none", "   ", false},
			{"", "local", false},
			{"auto", "local", false},
			{"direct", "local", false},
		}
		for _, tc := range cases {
			err := CheckNodePortPosture(tc.network, tc.spec)
			if got := errors.Is(err, ErrNodePortAddressesWithoutDatapath); got != tc.refused {
				t.Errorf("CheckNodePortPosture(%q, %q) = %v, want refused=%v", tc.network, tc.spec, err, tc.refused)
			}
		}
	})

	t.Run("a server install with a carried --network none is refused", func(t *testing.T) {
		cfg := Config{NodePortAddresses: str("local")}
		if err := checkNodePortPosture(nil, cfg, []string{"--network", "none"}); !errors.Is(err, ErrNodePortAddressesWithoutDatapath) {
			t.Errorf("got %v, want ErrNodePortAddressesWithoutDatapath", err)
		}
		if err := checkNodePortPosture(nil, cfg, []string{"--network", "helper"}); err != nil {
			t.Errorf("a datapath backend was refused: %v", err)
		}
		carried := Config{}
		if err := checkNodePortPosture(nil, carried, []string{"--network", "none", "--nodeport-addresses", "local"}); !errors.Is(err, ErrNodePortAddressesWithoutDatapath) {
			t.Errorf("a carried pair was not refused: %v", err)
		}
	})

	t.Run("an agent install with a carried --network none is refused", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		seeded := cfg
		seeded.ExtraAgentArgs = []string{"--network", "none"}
		f.putFile(cfg.withDefaults().plistPath(AgentLabel), AgentPlist(seeded))
		cfg.NodePortAddresses = str("local")
		if err := Install(context.Background(), f, cfg); !errors.Is(err, ErrNodePortAddressesWithoutDatapath) {
			t.Fatalf("Install = %v, want ErrNodePortAddressesWithoutDatapath", err)
		}
	})

	t.Run("whitespace is trimmed and whitespace-only clears", func(t *testing.T) {
		carried := []string{"--nodeport-addresses", "local", "--mesh-port", "51821"}
		for _, v := range []string{"", "   ", "\t"} {
			got := Config{NodePortAddresses: str(v)}.setNodePortAddressesArg(carried)
			if slices.Contains(got, "--nodeport-addresses") || !slices.Contains(got, "--mesh-port") {
				t.Errorf("value %q: args = %q, want only the carried setting dropped", v, got)
			}
		}
		got := Config{NodePortAddresses: str("  local , 10.0.0.0/8 ")}.setNodePortAddressesArg(nil)
		if want := []string{"--nodeport-addresses", "local , 10.0.0.0/8"}; !slices.Equal(got, want) {
			t.Errorf("args = %q, want %q", got, want)
		}
		if got := (Config{}).setNodePortAddressesArg(carried); !slices.Equal(got, carried) {
			t.Errorf("an unset value changed the carried args: %q", got)
		}
	})
}
