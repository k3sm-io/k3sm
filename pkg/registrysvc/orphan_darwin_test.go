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

package registrysvc

import (
	"strings"
	"testing"
)

// TestProcargsArgv pins the kern.procargs2 layout the reclaim reads argv from.
func TestProcargsArgv(t *testing.T) {
	buf := func(argc int32, body string) []byte {
		b := []byte{byte(argc), byte(argc >> 8), byte(argc >> 16), byte(argc >> 24)}
		return append(b, body...)
	}
	cases := []struct {
		name    string
		raw     []byte
		want    []string
		wantErr bool
	}{
		{name: "path, padding, argv, env", raw: buf(3, "/b/zot\x00\x00\x00/b/zot\x00serve\x00/w/config.json\x00HOME=/\x00"), want: []string{"/b/zot", "serve", "/w/config.json"}},
		{name: "no padding", raw: buf(1, "/b/zot\x00/b/zot\x00"), want: []string{"/b/zot"}},
		{name: "too short", raw: []byte{1, 0}, wantErr: true},
		{name: "argv truncated", raw: buf(2, "/b/zot\x00/b/zot\x00ser"), wantErr: true},
		{name: "negative argc", raw: buf(-1, "/b/zot\x00"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := procargsArgv(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("procargsArgv = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("procargsArgv: %v", err)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("procargsArgv = %q, want %q", got, tc.want)
			}
		})
	}
}
