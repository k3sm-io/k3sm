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

	"k3sm.io/k3sm/pkg/registryclient"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (brokenBody) Close() error             { return nil }

func answer(code int, body io.ReadCloser) rtFunc {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)), Header: http.Header{}, Body: body, Request: req}, nil
	}
}

// TestTypedErrors pins the typed surface a caller classifies a failed read
// by: a sentinel per transport cause, *StatusError for an unmapped status,
// and nothing typed for a failure outside those.
func TestTypedErrors(t *testing.T) {
	empty := func() io.ReadCloser { return io.NopCloser(strings.NewReader("")) }
	cases := []struct {
		name   string
		rt     rtFunc
		is     error
		status int
	}{
		{"dial refused", func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}, registryclient.ErrUnreachable, 0},
		{"connection reset", func(*http.Request) (*http.Response, error) { return nil, syscall.ECONNRESET }, registryclient.ErrUnreachable, 0},
		{"closed before the answer", func(*http.Request) (*http.Response, error) { return nil, io.EOF }, registryclient.ErrUnreachable, 0},
		{"transport timeout", func(*http.Request) (*http.Response, error) { return nil, timeoutErr{} }, registryclient.ErrTimeout, 0},
		{"context deadline", func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded }, registryclient.ErrTimeout, 0},
		{"short read", answer(http.StatusOK, brokenBody{}), registryclient.ErrShortRead, 0},
		{"404", answer(http.StatusNotFound, empty()), registryclient.ErrNotFound, 0},
		{"401", answer(http.StatusUnauthorized, empty()), registryclient.ErrUnauthorized, 0},
		{"403", answer(http.StatusForbidden, empty()), registryclient.ErrUnauthorized, 0},
		{"429", answer(http.StatusTooManyRequests, empty()), nil, http.StatusTooManyRequests},
		{"502", answer(http.StatusBadGateway, empty()), nil, http.StatusBadGateway},
		{"400", answer(http.StatusBadRequest, empty()), nil, http.StatusBadRequest},
		{"other transport failure", func(*http.Request) (*http.Response, error) { return nil, errors.New("tls: bad certificate") }, nil, 0},
		{"tls alert from the peer", func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "remote error", Err: tls.AlertError(42)}
		}, nil, 0},
		{"certificate verification", func(*http.Request) (*http.Response, error) {
			return nil, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
		}, nil, 0},
		{"cancelled dial", func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}
		}, nil, 0},
	}
	sentinels := []error{registryclient.ErrUnreachable, registryclient.ErrTimeout, registryclient.ErrShortRead, registryclient.ErrNotFound, registryclient.ErrUnauthorized}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := registryclient.New("http://registry.test", registryclient.Options{Transport: tc.rt})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Manifest(context.Background(), "models/qwen3", "v1")
			if err == nil {
				t.Fatal("Manifest returned nil")
			}
			for _, s := range sentinels {
				if got, want := errors.Is(err, s), s == tc.is; got != want {
					t.Errorf("errors.Is(%v, %v) = %t, want %t", err, s, got, want)
				}
			}
			var se *registryclient.StatusError
			if got := errors.As(err, &se); got != (tc.status != 0) {
				t.Fatalf("errors.As(%v, *StatusError) = %t, want %t", err, got, tc.status != 0)
			}
			if se != nil && se.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", se.StatusCode, tc.status)
			}
		})
	}
}
