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
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fakeExit is a process exit status as the lsof runner sees one.
type fakeExit int

func (e fakeExit) Error() string { return "exit status " + strconv.Itoa(int(e)) }
func (e fakeExit) ExitCode() int { return int(e) }

// fakeLsof is an lsofExec that writes stdout and stderr and returns err, and
// records the arguments it was run with.
func fakeLsof(stdout, stderr string, err error, gotArgs *[]string) lsofExec {
	return func(_ context.Context, o, e io.Writer, args ...string) error {
		*gotArgs = args
		_, _ = io.WriteString(o, stdout)
		_, _ = io.WriteString(e, stderr)
		return err
	}
}

// TestLanVerifyUsesHardenedLsofReader proves the post-apply socket proof reads
// the node daemon's listeners through the same hardened, fail-closed lsof
// runner and parser as the exposure check, per pid.
func TestLanVerifyUsesHardenedLsofReader(t *testing.T) {
	const pid = 4242
	ap := netip.MustParseAddrPort
	table := strings.Join([]string{
		"p4242", "R1", "ck3sm",
		"f7", "PTCP", "n*:30090",
		"f8", "PTCP", "n127.0.0.1:8080",
		"f9", "PTCP", "n[::1]:6060",
		"f10", "PTCP", "n[2001:db8::5]:443",
		"f11", "PTCP", "n[::]:7000",
		"f12", "PUDP", "n*:5353",
		"p4300", "R4242", "chelper",
		"f3", "PTCP", "n*:9999",
	}, "\n") + "\n"

	cases := []struct {
		name           string
		stdout, stderr string
		err            error
		want           []netip.AddrPort
		wantErr        bool
		wantTooLarge   bool
	}{
		{
			name:   "only the pid's own TCP listeners, wildcard and bracketed IPv6 parsed",
			stdout: table,
			want: []netip.AddrPort{
				ap("0.0.0.0:30090"), ap("127.0.0.1:8080"), ap("[::1]:6060"), ap("[2001:db8::5]:443"), ap("[::]:7000"),
			},
		},
		{name: "silent exit 1 is no listeners", err: fakeExit(1)},
		{name: "stderr text with exit 1 is an error", stderr: "lsof: WARNING: can't stat()", err: fakeExit(1), wantErr: true},
		{name: "an unknown field line is an error", stdout: "p4242\nf7\nPTCP\nn*:80\nZsurprise\n", wantErr: true},
		{
			name:         "a table over the line cap is an error",
			stdout:       "p4242\n" + strings.Repeat("f3\nPTCP\nn*:80\n", lsofMaxLines/3+1),
			wantErr:      true,
			wantTooLarge: true,
		},
		{
			name:         "output over the byte cap is an error",
			stdout:       "p4242\n" + strings.Repeat("c", lsofMaxBytes),
			wantErr:      true,
			wantTooLarge: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			got, err := lsofListenersWith(context.Background(), fakeLsof(tc.stdout, tc.stderr, tc.err, &args), pid)
			wantArgs := []string{"-nP", "-a", "-p", strconv.Itoa(pid), "-iTCP", "-sTCP:LISTEN", "-F", "pRcPn"}
			if !slices.Equal(args, wantArgs) {
				t.Errorf("lsof args = %q, want %q", args, wantArgs)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantTooLarge && !errors.Is(err, errLsofTooLarge) {
				t.Errorf("err = %v, want %v", err, errLsofTooLarge)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("listeners = %v, want %v", got, tc.want)
			}
		})
	}

}
