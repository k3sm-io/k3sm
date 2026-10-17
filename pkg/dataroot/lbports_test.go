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

package dataroot

import (
	"errors"
	"slices"
	"testing"
)

// TestParseLBPrivilegedPorts pins the list grammar the server, the agent, the
// installer and netd share.
func TestParseLBPrivilegedPorts(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    []uint16
		wantErr bool
	}{
		{in: "80,443", want: []uint16{80, 443}},
		{in: " 443 , 80,80 ", want: []uint16{80, 443}},
		{in: "", want: nil},
		{in: "  ", want: nil},
		{in: "1,1023", want: []uint16{1, 1023}},
		{in: "0", wantErr: true},
		{in: "1024", wantErr: true},
		{in: "80,", wantErr: true},
		{in: "http", wantErr: true},
		{in: "-80", wantErr: true},
	} {
		got, err := ParseLBPrivilegedPorts(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseLBPrivilegedPorts(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("ParseLBPrivilegedPorts(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestRecordsRefuseABadLBPortList proves both argument records refuse an
// --lb-privileged-ports value netd would refuse at start, in either spelling,
// judged on the last occurrence (the one the flag package keeps).
func TestRecordsRefuseABadLBPortList(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		ok   bool
	}{
		{name: "absent", args: []string{"--kubelet-port", "10250"}, ok: true},
		{name: "valid", args: []string{"--lb-privileged-ports", "80,443"}, ok: true},
		{name: "valid inline", args: []string{"--lb-privileged-ports=22"}, ok: true},
		{name: "empty allows none", args: []string{"--lb-privileged-ports="}, ok: true},
		{name: "out of range", args: []string{"--lb-privileged-ports", "80,8080"}},
		{name: "not a number", args: []string{"-lb-privileged-ports=http"}},
		{name: "a bad last occurrence", args: []string{"--lb-privileged-ports=80", "--lb-privileged-ports=0"}},
		{name: "a bare trailing flag has no value", args: []string{"--kubelet-port", "10250", "--lb-privileged-ports"}},
		{name: "a bare trailing single-dash flag has no value", args: []string{"-lb-privileged-ports"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range []struct {
				name     string
				validate func([]string) error
				sentinel error
			}{
				{"server", ValidateServerArgs, ErrServerArgsRejected},
				{"agent", ValidateAgentArgs, ErrAgentArgsRejected},
			} {
				err := v.validate(tc.args)
				if tc.ok && err != nil {
					t.Errorf("%s: %v refused: %v", v.name, tc.args, err)
				}
				if !tc.ok && !errors.Is(err, v.sentinel) {
					t.Errorf("%s: %v = %v, want %v", v.name, tc.args, err, v.sentinel)
				}
			}
		})
	}
}
