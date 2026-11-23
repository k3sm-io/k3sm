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

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// TestDoctorKeystorePreFrameDropped: the keystore-logs row reads the
// persisted pre-frame refusal counts through its seam: none adds nothing;
// some is WARN "N pre-frame refusal(s) not recorded for M uid(s)"; a file
// that does not read is WARN saying the persisted count is unreadable; a
// file this user may not read adds nothing; a soft-cap WARN keeps both.
func TestDoctorKeystorePreFrameDropped(t *testing.T) {
	t.Parallel()
	counts := func(c keystore.PreFrameDroppedCounts, err error) func(context.Context) (keystore.PreFrameDroppedCounts, error) {
		return func(context.Context) (keystore.PreFrameDroppedCounts, error) { return c, err }
	}
	cases := []struct {
		name   string
		mut    func(*doctorEnv)
		want   doctorStatus
		detail string
	}{
		{"pass-none", func(e *doctorEnv) {
			e.keystorePreFrameDropped = counts(keystore.PreFrameDroppedCounts{}, nil)
		}, statusPass, "flagged SF_APPEND"},
		{"warn-counts", func(e *doctorEnv) {
			e.keystorePreFrameDropped = counts(keystore.PreFrameDroppedCounts{Refusals: 7, UIDs: 2}, nil)
		}, statusWarn, "7 pre-frame refusal(s) not recorded for 2 uid(s)"},
		{"warn-others", func(e *doctorEnv) {
			e.keystorePreFrameDropped = counts(keystore.PreFrameDroppedCounts{Refusals: 9, UIDs: 256, Others: 3}, nil)
		}, statusWarn, "9 pre-frame refusal(s) not recorded for 256 uid(s), 3 of them for further uids not named"},
		{"warn-unreadable", func(e *doctorEnv) {
			e.keystorePreFrameDropped = counts(keystore.PreFrameDroppedCounts{}, errors.New("does not parse"))
		}, statusWarn, "the persisted pre-frame refusal count is unreadable"},
		{"pass-permission", func(e *doctorEnv) {
			e.keystorePreFrameDropped = counts(keystore.PreFrameDroppedCounts{}, fmt.Errorf("open: %w", fs.ErrPermission))
		}, statusPass, "flagged SF_APPEND"},
		{"warn-with-soft-cap", func(e *doctorEnv) {
			e.keystoreLogSizes = func(context.Context) (keystore.LogSizes, error) {
				return keystore.LogSizes{Audit: 65, SoftCap: 64, HardCap: 256}, nil
			}
			e.keystorePreFrameDropped = counts(keystore.PreFrameDroppedCounts{Refusals: 1, UIDs: 1}, nil)
		}, statusWarn, "past its soft cap of 64; past the hard cap of 256 no user-scope change is recorded; 1 pre-frame refusal(s) not recorded for 1 uid(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := healthyDoctorEnv()
			e.keystoreLogs = func(context.Context) error { return nil }
			e.keystoreLogSizes = nil
			tc.mut(&e)
			r := checkKeystoreLogs(e)
			if r.name != "keystore-logs" || r.status != tc.want || !strings.Contains(r.detail, tc.detail) {
				t.Fatalf("row = %s %v %q, want %v containing %q", r.name, r.status, r.detail, tc.want, tc.detail)
			}
			if r.status == statusWarn && !strings.Contains(r.remedy, "audit --rotate") {
				t.Fatalf("a WARN row with no rotate remedy: %q", r.remedy)
			}
		})
	}
}
