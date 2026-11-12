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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/runtimed/pkg/artifact"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// timeoutError is a net.Error that reports a timeout, as a transport's
// deadline does.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// failingBody returns part of a body and then fails, as a connection closed
// mid-response does.
type failingBody struct{ sent bool }

func (b *failingBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, `{"schemaVersion":`), nil
}

func (b *failingBody) Close() error { return nil }

// statusTransport answers every request with one HTTP status.
func statusTransport(code int) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: code,
			Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
}

// clientResolver is RegistryResolver over a client whose transport is rt, so
// the error the operator classifies is the one registryclient really returns.
func clientResolver(t *testing.T, rt http.RoundTripper) ArtifactResolver {
	t.Helper()
	c, err := registryclient.New("https://"+testRegistryHost, registryclient.Options{Transport: rt})
	if err != nil {
		t.Fatal(err)
	}
	return RegistryResolver(c)
}

// failingResolver returns err for every reference.
func failingResolver(err error) ArtifactResolver {
	return ArtifactResolverFunc(func(context.Context, string, string, string) (string, error) {
		return "", err
	})
}

// TestResolutionFailureConditionReason pins the Ready reason of a failed
// artifact resolution: a cause outside the spec (the registry cannot be
// reached, is slow, fails, throttles, has not been pushed to yet, refuses the
// read, or the operator has no registry client) is ArtifactUnavailable, and
// everything else, including an error that cannot be classified, stays
// InvalidSpec. The Event is ArtifactUnresolved for both.
func TestResolutionFailureConditionReason(t *testing.T) {
	cases := []struct {
		name     string
		resolver func(t *testing.T) ArtifactResolver
		want     string
	}{
		{"registry unreachable", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
			}))
		}, "ArtifactUnavailable"},
		{"transport timeout", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, timeoutError{}
			}))
		}, "ArtifactUnavailable"},
		{"context deadline", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, context.DeadlineExceeded
			}))
		}, "ArtifactUnavailable"},
		{"http 500", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusInternalServerError))
		}, "ArtifactUnavailable"},
		{"http 503", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusServiceUnavailable))
		}, "ArtifactUnavailable"},
		{"http 429", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusTooManyRequests))
		}, "ArtifactUnavailable"},
		{"short read", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}, Body: &failingBody{}, Request: req}, nil
			}))
		}, "ArtifactUnavailable"},
		{"http 404", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusNotFound))
		}, "ArtifactUnavailable"},
		{"http 401", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusUnauthorized))
		}, "ArtifactUnavailable"},
		{"http 403", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusForbidden))
		}, "ArtifactUnavailable"},
		{"no registry client", func(*testing.T) ArtifactResolver { return nil }, "ArtifactUnavailable"},
		{"http 400", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, statusTransport(http.StatusBadRequest))
		}, ReasonInvalidSpec},
		{"digest mismatch", func(*testing.T) ArtifactResolver {
			return failingResolver(fmt.Errorf("manifest models/qwen3@sha256:00 hashes to sha256:11: %w", registryclient.ErrDigestMismatch))
		}, ReasonInvalidSpec},
		{"spec fault", func(*testing.T) ArtifactResolver {
			return failingResolver(fmt.Errorf("models/qwen3:v1 is an index: %w", artifact.ErrVariantRequired))
		}, ReasonInvalidSpec},
		{"unclassified", func(*testing.T) ArtifactResolver {
			return failingResolver(errors.New("something nobody anticipated"))
		}, ReasonInvalidSpec},
		{"cancelled", func(*testing.T) ArtifactResolver {
			return failingResolver(context.Canceled)
		}, ReasonInvalidSpec},
		{"tls alert from the peer", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, &net.OpError{Op: "remote error", Err: tls.AlertError(42)}
			}))
		}, ReasonInvalidSpec},
		{"certificate verification", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
			}))
		}, ReasonInvalidSpec},
		{"cancelled dial", func(t *testing.T) ArtifactResolver {
			return clientResolver(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}
			}))
		}, ReasonInvalidSpec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			h := artifactHarness(t, testRegistryHost+"/models/qwen3:v1", tc.resolver(t))
			h.ctrl.recorder = rec
			_ = h.ctrl.Reconcile(context.Background(), key())

			ready := meta.FindStatusCondition(h.status(t).Conditions, mlxv1alpha1.MLXModelConditionReady)
			if ready == nil || ready.Status != "False" || ready.Reason != tc.want {
				t.Errorf("Ready = %+v, want False/%s", ready, tc.want)
			}
			if len(rec.events) != 1 {
				t.Fatalf("%d events, want 1: %+v", len(rec.events), rec.events)
			}
			if got := rec.events[0]; got.reason != eventReasonArtifactUnresolved || got.eventType != corev1.EventTypeWarning {
				t.Errorf("event = %s/%s, want %s/%s", got.eventType, got.reason, corev1.EventTypeWarning, eventReasonArtifactUnresolved)
			}
		})
	}
}
