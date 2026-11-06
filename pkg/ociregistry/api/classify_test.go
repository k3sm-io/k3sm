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

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestClassifyStoreLimits pins the answers to the store's size refusals: a full
// index is a client refusal that says how to make room, not a 500.
func TestClassifyStoreLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		code    string
		message string
	}{
		{
			name:    "a full index, as a manifest PUT wraps it",
			err:     fmt.Errorf("put manifest in app: %w: 9 rows would take index.json to 2100 bytes, past 2048", store.ErrIndexFull),
			status:  http.StatusForbidden,
			code:    codeDenied,
			message: "delete tags",
		},
		{
			name:   "an upload over the limit",
			err:    fmt.Errorf("append: %w", store.ErrUploadTooLarge),
			status: http.StatusRequestEntityTooLarge,
			code:   codeSizeInvalid,
		},
		{
			name:   "an error nothing maps",
			err:    errors.New("disk on fire"),
			status: http.StatusInternalServerError,
			code:   codeUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)
			if got.status != tc.status || got.code != tc.code {
				t.Fatalf("classify: %d %s, want %d %s", got.status, got.code, tc.status, tc.code)
			}
			if !strings.Contains(got.msg, tc.message) {
				t.Errorf("message %q does not say %q", got.msg, tc.message)
			}
			if !errors.Is(got.cause, tc.err) {
				t.Errorf("cause %v, want %v", got.cause, tc.err)
			}
		})
	}
}
