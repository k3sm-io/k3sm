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

package interconnect

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newArmClients(t *testing.T, user string, existing bool) (*fake.Clientset, Store) {
	t.Helper()
	cs := fake.NewClientset()
	cs.PrependReactor("create", "selfsubjectreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		if user == "" {
			return true, nil, errors.New("forbidden")
		}
		return true, &authenticationv1.SelfSubjectReview{Status: authenticationv1.SelfSubjectReviewStatus{
			UserInfo: authenticationv1.UserInfo{Username: user},
		}}, nil
	})
	var objs []runtime.Object
	if existing {
		u, err := toUnstructured(interconnect(false))
		if err != nil {
			t.Fatal(err)
		}
		objs = append(objs, u)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{GVR: "InterconnectList"}, objs...)
	return cs, Store{Client: dyn}
}

// TestSetEnabledRecordsTheAuthenticatedIdentity pins the arming verb: spec
// patched, armedBy from the SelfSubjectReview (never the OS user), "unknown"
// when the review is unavailable, an Event on the object, and disarming
// clearing the record.
func TestSetEnabledRecordsTheAuthenticatedIdentity(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		name, user, want string
		existing         bool
	}{
		{"existing object, known user", "system:admin", "system:admin", true},
		{"missing object is created", "kitsumiko", "kitsumiko", false},
		{"review unavailable", "", UnknownIdentity, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, store := newArmClients(t, tc.user, tc.existing)
			res, err := SetEnabled(ctx, cs, store, Name, true, t0, log)
			if err != nil {
				t.Fatalf("SetEnabled: %v", err)
			}
			if res.ArmedBy != tc.want || res.Created == tc.existing {
				t.Errorf("result = %+v, want armedBy %q created=%v", res, tc.want, !tc.existing)
			}
			ic, err := store.Get(ctx, Name)
			if err != nil {
				t.Fatal(err)
			}
			if !ic.Spec.Enabled || ic.Status.ArmedBy != tc.want || ic.Status.ArmedAt == nil || !ic.Status.ArmedAt.Time.Equal(t0) {
				t.Errorf("object = spec %+v status armedBy=%q armedAt=%v", ic.Spec, ic.Status.ArmedBy, ic.Status.ArmedAt)
			}
			evs, err := cs.CoreV1().Events(metav1.NamespaceDefault).List(ctx, metav1.ListOptions{})
			if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != EventArmed || evs.Items[0].Type != corev1.EventTypeWarning ||
				evs.Items[0].InvolvedObject.Kind != "Interconnect" {
				t.Errorf("events = %+v, %v; want one Warning %s on the Interconnect", evs, err, EventArmed)
			}

			if _, err := SetEnabled(ctx, cs, store, Name, false, t0.Add(time.Hour), log); err != nil {
				t.Fatalf("disable: %v", err)
			}
			ic, _ = store.Get(ctx, Name)
			if ic.Spec.Enabled || ic.Status.ArmedBy != "" || ic.Status.ArmedAt != nil {
				t.Errorf("after disable: spec %+v armedBy=%q armedAt=%v, want disarmed and cleared", ic.Spec, ic.Status.ArmedBy, ic.Status.ArmedAt)
			}
		})
	}
	cs, store := newArmClients(t, "system:admin", true)
	if _, err := SetEnabled(ctx, cs, store, "usb4", true, t0, log); err == nil {
		t.Error("an interconnect other than thunderbolt was accepted")
	}
}

// TestMeshLivenessKeysOnBridge0 pins the adapter over darwin-net's prober: a
// new target reads unreachable, and a removed one stays so.
func TestMeshLivenessKeysOnBridge0(t *testing.T) {
	a := netip.MustParseAddr("169.254.0.9")
	var l Liveness = NewMeshLiveness(nil)
	l.SetTargets([]netip.Addr{a})
	if l.Probe(a).Alive {
		t.Fatal("a new target must start unreachable")
	}
	l.SetTargets(nil)
	if l.Probe(a).Alive {
		t.Fatal("a removed target must read unreachable")
	}
}
