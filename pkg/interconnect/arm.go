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
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// UnknownIdentity is armedBy when the caller's identity cannot be read.
const UnknownIdentity = "unknown"

// Event reasons of the arming verbs.
const (
	EventArmed    = "InterconnectArmed"
	EventDisarmed = "InterconnectDisarmed"
)

// eventNamespace is where Events about the cluster-scoped Interconnect go.
const eventNamespace = metav1.NamespaceDefault

// Identity returns the username the apiserver authenticated client as, read
// through a SelfSubjectReview. It is informational: it records who armed the
// cable, from the credential that did it, and never from the OS user or a flag.
// Any failure reads as UnknownIdentity.
func Identity(ctx context.Context, client kubernetes.Interface) string {
	rev, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || rev.Status.UserInfo.Username == "" {
		return UnknownIdentity
	}
	return rev.Status.UserInfo.Username
}

// ArmResult is what SetEnabled did.
type ArmResult struct {
	// ArmedBy is the identity recorded (enable) or "" (disable).
	ArmedBy string
	// Created reports that the object did not exist and was created.
	Created bool
}

// SetEnabled arms (enabled true) or disarms the named Interconnect: it patches
// spec.enabled, records status.armedBy and armedAt on arming (and clears them on
// disarming), emits an Event on the object and a Warn line. A missing object is
// created, so an admin may arm the cable before the first report arrives.
func SetEnabled(ctx context.Context, client kubernetes.Interface, store Store, name string, enabled bool, now time.Time, log *slog.Logger) (ArmResult, error) {
	if log == nil {
		log = slog.Default()
	}
	if name != netv1alpha1.MediumThunderbolt {
		return ArmResult{}, fmt.Errorf("interconnect %q: the only interconnect is %q", name, netv1alpha1.MediumThunderbolt)
	}
	var res ArmResult
	if enabled {
		res.ArmedBy = Identity(ctx, client)
	}
	specPatch, err := json.Marshal(map[string]any{"spec": map[string]any{"enabled": enabled}})
	if err != nil {
		return ArmResult{}, err
	}
	_, err = store.Patch(ctx, name, specPatch)
	if apierrors.IsNotFound(err) {
		_, err = store.Create(ctx, &netv1alpha1.Interconnect{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: netv1alpha1.InterconnectSpec{
				Medium:   name,
				Fallback: netv1alpha1.InterconnectFallbackNetwork,
				Enabled:  enabled,
			},
		})
		if apierrors.IsAlreadyExists(err) {
			_, err = store.Patch(ctx, name, specPatch)
		} else if err == nil {
			res.Created = true
		}
	}
	if err != nil {
		return ArmResult{}, fmt.Errorf("set interconnect %s enabled=%v: %w", name, enabled, err)
	}

	status := map[string]any{"armedBy": nil, "armedAt": nil}
	if enabled {
		status = map[string]any{"armedBy": res.ArmedBy, "armedAt": now.UTC().Format(time.RFC3339)}
	}
	statusPatch, err := json.Marshal(map[string]any{"status": status})
	if err != nil {
		return ArmResult{}, err
	}
	ic, err := store.Patch(ctx, name, statusPatch, "status")
	if err != nil {
		return ArmResult{}, fmt.Errorf("record who armed interconnect %s: %w", name, err)
	}

	reason, typ, msg := EventDisarmed, corev1.EventTypeNormal,
		"interconnect disarmed: the server removes every node's interconnect address"
	if enabled {
		reason, typ = EventArmed, corev1.EventTypeWarning
		msg = fmt.Sprintf("interconnect armed by %s: opted-in pod traffic crosses the cable in plaintext, and any device on a cabled port can reach and spoof interconnect addresses", res.ArmedBy)
	}
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{GenerateName: name + ".", Namespace: eventNamespace},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: netv1alpha1.SchemeGroupVersion.String(),
			Kind:       "Interconnect",
			Name:       name,
			UID:        ic.UID,
		},
		Reason:              reason,
		Message:             msg,
		Type:                typ,
		Source:              corev1.EventSource{Component: eventComponent},
		FirstTimestamp:      metav1.NewTime(now),
		LastTimestamp:       metav1.NewTime(now),
		Count:               1,
		ReportingController: eventComponent,
	}
	if _, err := client.CoreV1().Events(eventNamespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		log.Warn("interconnect: could not record the arming Event", "interconnect", name, "err", err)
	}
	verb := "disarmed"
	if enabled {
		verb = "armed"
	}
	log.Warn("interconnect "+verb, "interconnect", name, "armedBy", res.ArmedBy, "created", res.Created)
	return res, nil
}
