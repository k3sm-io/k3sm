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

package executor

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

// TestAPIServerArgsCarryNoMutatingAdmissionPolicyBetaFlags owns the "no MAP flags"
// posture of the kube-apiserver argv. MutatingAdmissionPolicy is GA at the pin and
// served at admissionregistration.k8s.io/v1 by default, so the argv carries no
// runtime-config and no MAP feature gate: either is a flag a later kube minor can
// reject at boot. The scan is a substring match over every argv element, so the
// `--flag value` and `--flag=value` spellings and a gate joined into a comma list
// are all caught. The second half proves the premise hermetically: the pinned
// apiserver's feature-gate registry defaults MutatingAdmissionPolicy to true at
// DefaultKubeVersion, so dropping the gate flag does not turn MAP off.
func TestAPIServerArgsCarryNoMutatingAdmissionPolicyBetaFlags(t *testing.T) {
	anon := false
	single := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	const meshIP = "100.64.0.1"
	ha := Config{
		WorkDir:       "/var/lib/k3sm/server",
		KinePort:      2379,
		APIServerPort: 6444,
		NodeIP:        meshIP,
		BindAddress:   meshIP,
		ClientCAFile:  "/var/lib/k3sm/server/tls/signing-ca.crt",
		KubeletCAFile: "/var/lib/k3sm/server/tls/cluster-ca.crt",
		AnonymousAuth: &anon,
		Etcd:          &EtcdConfig{Role: EtcdInit, Name: "s1", PeerIP: "192.0.2.10", PeerPort: 2380, MetricsPort: 2381},
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{"raw single-node", single},
		{"single-node through withDefaults", single.withDefaults()},
		{"mesh-bound HA server", ha},
	}
	forbidden := []string{
		"MutatingAdmissionPolicy",
		"admissionregistration.k8s.io/v1beta1",
		"--runtime-config",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := apiServerArgs(tc.cfg)
			// Guard against a vacuous pass on an empty or truncated argv.
			if !hasArg(args, "--enable-admission-plugins=NodeRestriction") {
				t.Fatalf("--enable-admission-plugins=NodeRestriction missing, args=%v", args)
			}
			if flagValue(args, "--authorization-mode") == "" {
				t.Fatalf("--authorization-mode missing, args=%v", args)
			}
			for _, a := range args {
				for _, bad := range forbidden {
					if strings.Contains(a, bad) {
						t.Errorf("argv element %q contains %q: the apiserver must carry no MutatingAdmissionPolicy flag (v1 is served by default at the pin)", a, bad)
					}
				}
			}
		})
	}

	t.Run("MutatingAdmissionPolicy defaults to true at the pin", func(t *testing.T) {
		pin, err := version.ParseGeneric(DefaultKubeVersion)
		if err != nil {
			t.Fatalf("parse DefaultKubeVersion %q: %v", DefaultKubeVersion, err)
		}
		specs, ok := utilfeature.DefaultMutableFeatureGate.GetAllVersioned()[features.MutatingAdmissionPolicy]
		if !ok {
			t.Fatalf("feature gate %q is not registered in the pinned k8s.io/apiserver", features.MutatingAdmissionPolicy)
		}
		// The spec in force at the pin is the one with the greatest version that is
		// not after the pin. Compare versions explicitly rather than trusting the
		// registry's ordering.
		at := -1
		for i := range specs {
			if specs[i].Version == nil || pin.LessThan(specs[i].Version) {
				continue
			}
			if at < 0 || specs[at].Version.LessThan(specs[i].Version) {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("no %s spec at or before %s: %v", features.MutatingAdmissionPolicy, DefaultKubeVersion, specs)
		}
		if !specs[at].Default {
			t.Errorf("%s default at %s = false (spec %+v); the argv relies on it being on by default", features.MutatingAdmissionPolicy, DefaultKubeVersion, specs[at])
		}
	})
}
