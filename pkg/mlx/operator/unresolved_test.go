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

package operator

import (
	"context"
	"errors"
	"net/http"
	"syscall"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/registryclient"
)

// roundTripFunc is an http.RoundTripper from a function: the registry the
// real client talks to in these tests, with no socket opened.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// registryAnswering is RegistryResolver over a real registry client whose
// every request gets rt's answer.
func registryAnswering(t *testing.T, rt roundTripFunc) ArtifactResolver {
	t.Helper()
	c, err := registryclient.New("http://"+testRegistryHost, registryclient.Options{Transport: rt})
	if err != nil {
		t.Fatal(err)
	}
	return RegistryResolver(c)
}

// answering is a registry that answers every request with code.
func answering(code int) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Status: http.StatusText(code), Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	}
}

// TestResolutionFailureConditionReason pins the Ready reason of an artifact
// resolution failure: a transient registry failure (a transport error, a 5xx,
// a 429) reports the non-terminal ArtifactUnresolved and is requeued; a 404,
// a 401, a malformed reference and an unclassified error keep InvalidSpec.
// The Event reason is ArtifactUnresolved for every resolution failure, and
// the Ready reason returns to the model's normal one once the reference
// resolves.
func TestResolutionFailureConditionReason(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		resolver  func(t *testing.T) ArtifactResolver
		want      string
		requeue   bool
	}{
		{"connection refused", testRegistryHost + "/models/qwen3:v1", func(t *testing.T) ArtifactResolver {
			return registryAnswering(t, func(*http.Request) (*http.Response, error) { return nil, syscall.ECONNREFUSED })
		}, ReasonArtifactUnresolved, true},
		{"503", testRegistryHost + "/models/qwen3:v1", func(t *testing.T) ArtifactResolver {
			return registryAnswering(t, answering(http.StatusServiceUnavailable))
		}, ReasonArtifactUnresolved, true},
		{"429", testRegistryHost + "/models/qwen3:v1", func(t *testing.T) ArtifactResolver {
			return registryAnswering(t, answering(http.StatusTooManyRequests))
		}, ReasonArtifactUnresolved, true},
		{"404", testRegistryHost + "/models/qwen3:v1", func(t *testing.T) ArtifactResolver {
			return registryAnswering(t, answering(http.StatusNotFound))
		}, ReasonInvalidSpec, false},
		{"401", testRegistryHost + "/models/qwen3:v1", func(t *testing.T) ArtifactResolver {
			return registryAnswering(t, answering(http.StatusUnauthorized))
		}, ReasonInvalidSpec, false},
		{"malformed reference", testRegistryHost + "/models/Qwen3::v1", func(t *testing.T) ArtifactResolver {
			return &countingResolver{digest: testDigestA}
		}, ReasonInvalidSpec, false},
		{"unclassified error", testRegistryHost + "/models/qwen3:v1", func(*testing.T) ArtifactResolver {
			return ArtifactResolverFunc(func(context.Context, string, string, string) (string, error) {
				return "", errors.New("registry-k3sm:6450: connection refused")
			})
		}, ReasonInvalidSpec, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			h := artifactHarness(t, tc.reference, tc.resolver(t))
			h.ctrl.recorder = rec
			err := h.ctrl.Reconcile(context.Background(), key())
			if tc.requeue && err == nil {
				t.Error("Reconcile returned nil for a transient failure, want the error so it is requeued")
			}
			ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
			if ready == nil || ready.Reason != tc.want {
				t.Fatalf("Ready = %+v, want reason %s", ready, tc.want)
			}
			if h.statefulSet(t) != nil {
				t.Error("a StatefulSet was applied for an unresolved artifact")
			}
			if len(rec.events) != 1 {
				t.Fatalf("%d events, want 1: %+v", len(rec.events), rec.events)
			}
			// A malformed reference is refused by the render and never
			// resolved, so its Event is the render's.
			wantEvent := eventReasonArtifactUnresolved
			if tc.want == ReasonInvalidSpec && tc.reference != testRegistryHost+"/models/qwen3:v1" {
				wantEvent = ReasonInvalidSpec
			}
			if got := rec.events[0].reason; got != wantEvent {
				t.Errorf("event reason = %s, want %s", got, wantEvent)
			}
		})
	}

	t.Run("recovers once resolution succeeds", func(t *testing.T) {
		healthy := newHealthyArtifactHarness(t)
		healthy.reconcile(t)
		normal := meta.FindStatusCondition(healthy.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
		if normal == nil {
			t.Fatal("no Ready condition on a model that resolves")
		}

		down := true
		flaky := ArtifactResolverFunc(func(context.Context, string, string, string) (string, error) {
			if down {
				return "", registryclient.ErrTransient
			}
			return testDigestA, nil
		})
		h := artifactHarness(t, testRegistryHost+"/models/qwen3:v1", flaky)
		if err := h.ctrl.Reconcile(context.Background(), key()); err == nil {
			t.Fatal("Reconcile returned nil during the outage")
		}
		if r := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady); r == nil || r.Reason != ReasonArtifactUnresolved {
			t.Fatalf("Ready = %+v during the outage, want %s", r, ReasonArtifactUnresolved)
		}
		down = false
		h.reconcile(t)
		ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
		if ready == nil || ready.Reason != normal.Reason {
			t.Fatalf("Ready = %+v after the registry recovered, want reason %s", ready, normal.Reason)
		}
		if got := h.status(t).ResolvedArtifact; got != testDigestA {
			t.Errorf("status.resolvedArtifact = %q, want %q", got, testDigestA)
		}
		if h.statefulSet(t) == nil {
			t.Error("no StatefulSet applied once the artifact resolved")
		}
	})
}

// newHealthyArtifactHarness is a model whose artifact resolves at once, for
// the Ready reason a resolved model reports.
func newHealthyArtifactHarness(t *testing.T) *harness {
	t.Helper()
	return artifactHarness(t, testRegistryHost+"/models/qwen3:v1", &countingResolver{digest: testDigestA})
}
