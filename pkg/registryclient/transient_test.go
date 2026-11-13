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

package registryclient_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/registryclient"
)

// funcTransport is a RoundTripper from a function, for a transport that fails
// or answers with a body that cannot be read.
type funcTransport func(*http.Request) (*http.Response, error)

func (f funcTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// failingBody is a response body whose read fails partway.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, syscall.ECONNRESET }
func (failingBody) Close() error             { return nil }

// TestTransientFailures pins ErrTransient: a request that did not complete, a
// 5xx or 429, and a failed body read wrap it (and keep their cause); a 404,
// 401/403, another 4xx, a refused redirect and a refused certificate do not,
// and the existing sentinels are unchanged.
func TestTransientFailures(t *testing.T) {
	status := func(code int) registryclient.Options {
		return registryclient.Options{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		})}}
	}
	fail := func(err error) registryclient.Options {
		return registryclient.Options{Transport: funcTransport(func(*http.Request) (*http.Response, error) { return nil, err })}
	}
	never := registryclient.Options{Timeout: 50 * time.Millisecond, Transport: handlerTransport{http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})}}
	badBody := registryclient.Options{Transport: funcTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{}, Body: failingBody{}, Request: r}, nil
	})}
	redirect := registryclient.Options{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://elsewhere.test/v2/_catalog")
		w.WriteHeader(http.StatusFound)
	})}}

	tests := []struct {
		name      string
		opts      registryclient.Options
		transient bool
		alsoIs    error
	}{
		{"connection refused", fail(syscall.ECONNREFUSED), true, syscall.ECONNREFUSED},
		{"request timeout", never, true, nil},
		{"500", status(http.StatusInternalServerError), true, nil},
		{"503", status(http.StatusServiceUnavailable), true, nil},
		{"429", status(http.StatusTooManyRequests), true, nil},
		{"a failed body read", badBody, true, syscall.ECONNRESET},
		{"404", status(http.StatusNotFound), false, registryclient.ErrNotFound},
		{"401", status(http.StatusUnauthorized), false, registryclient.ErrUnauthorized},
		{"403", status(http.StatusForbidden), false, registryclient.ErrUnauthorized},
		{"400", status(http.StatusBadRequest), false, nil},
		{"a redirect to another host", redirect, false, nil},
		{"a certificate the trust store refuses", fail(x509.UnknownAuthorityError{}), false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := registryclient.New("http://registry.test", tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Catalog(context.Background())
			if err == nil {
				t.Fatal("Catalog succeeded")
			}
			if got := errors.Is(err, registryclient.ErrTransient); got != tc.transient {
				t.Errorf("errors.Is(%v, ErrTransient) = %v, want %v", err, got, tc.transient)
			}
			if tc.alsoIs != nil && !errors.Is(err, tc.alsoIs) {
				t.Errorf("err = %v; want errors.Is %v as well", err, tc.alsoIs)
			}
		})
	}
}

// TestTransientFailureOnManifest pins the sentinel on the manifest read the
// mlx operator's resolver uses, not only on a listing.
func TestTransientFailureOnManifest(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}), registryclient.Options{})
	_, err := c.Manifest(context.Background(), "app", "v1")
	if !errors.Is(err, registryclient.ErrTransient) || !strings.Contains(err.Error(), "502") {
		t.Errorf("Manifest err = %v; want ErrTransient naming the 502", err)
	}
	_, err = c.ManifestIndexBounded(context.Background(), "app", "v1", 1<<20)
	if !errors.Is(err, registryclient.ErrTransient) {
		t.Errorf("ManifestIndexBounded err = %v; want ErrTransient", err)
	}
}
