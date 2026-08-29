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

package provider

import (
	"errors"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestPodExecutionUID pins the derivation of the uid the foreign-user admission
// ceiling is parameterised with (B153 sub-decision 1). The lookup is INJECTED so
// the table is hermetic: whether `_k3sm` exists on the machine running the test
// must not decide the verdict.
func TestPodExecutionUID(t *testing.T) {
	const serviceUID = 271
	found := func(name string) (int, error) {
		if name != install.DefaultServiceUser {
			t.Fatalf("looked up %q, want the service user %q", name, install.DefaultServiceUser)
		}
		return serviceUID, nil
	}
	missing := func(string) (int, error) { return 0, errors.New("unknown user") }
	zero := func(string) (int, error) { return 0, nil }

	tests := []struct {
		name   string
		euid   int
		lookup func(string) (int, error)
		want   int64
	}{
		// The SHIPPED posture: the io.k3sm.server LaunchDaemon runs UserName=_k3sm,
		// runtimed is embedded in that process, and a pod that requests no drop keeps
		// the daemon's identity — so the euid IS the pod-execution uid.
		{"unprivileged server: the daemon euid pods inherit", serviceUID, found, serviceUID},
		// `k3sm dev` runs as the developer; pods run as the developer too, and the
		// service user is irrelevant even if it happens to exist.
		{"unprivileged dev server: the developer uid, not the service user", 501, found, 501},
		// A ROOT server: a no-drop pod literally runs as uid 0, but pinning the
		// ceiling to 0 names root as the k3sm pod identity and admits only root.
		// Root CAN setuid, so the service user is both the honest ceiling and an
		// identity this posture genuinely honours.
		{"root server: the service user, never 0", 0, found, serviceUID},
		// An uninstalled host running the server under sudo. There is no honest
		// non-zero answer; a phantom uid would make the rejection message a lie.
		{"root server with no service user: falls back to the euid", 0, missing, 0},
		{"root server whose service user resolves to 0: falls back to the euid", 0, zero, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := podExecutionUID(tt.euid, tt.lookup)
			if got != tt.want {
				t.Errorf("podExecutionUID(%d) = %d, want %d (%s)", tt.euid, got, tt.want, why)
			}
			if strings.TrimSpace(why) == "" {
				t.Error("the derivation must report WHY: it is logged at bring-up and is the only trace of this decision")
			}
		})
	}
}

// TestPodExecutionUIDNeverConsultsTheServiceUserWhenUnprivileged pins the
// direction of the fallback. An unprivileged server cannot setuid to anything, so
// resolving `_k3sm` there would name an identity pods can never have — the
// mirror-image of the root inversion.
func TestPodExecutionUIDNeverConsultsTheServiceUserWhenUnprivileged(t *testing.T) {
	got, _ := podExecutionUID(501, func(string) (int, error) {
		t.Fatal("the service user was looked up for an UNPRIVILEGED server: pods there run at the daemon euid, which cannot setuid away from itself")
		return 0, nil
	})
	if got != 501 {
		t.Errorf("podExecutionUID(501) = %d, want 501", got)
	}
}
