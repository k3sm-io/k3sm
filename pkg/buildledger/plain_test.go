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

package buildledger

import (
	"bytes"
	"testing"
)

func TestPlainWriterStripsTerminalControl(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks []string
		want   string
	}{
		{"plain text passes", []string{"#1 [internal] load build definition\n\tdone\n"}, "#1 [internal] load build definition\n\tdone\n"},
		{"colours", []string{"\x1b[32m=> [2/3] RUN make\x1b[0m\n"}, "=> [2/3] RUN make\n"},
		{"cursor up and line clear redraw", []string{"[+] Building 1.0s\n\x1b[1A\x1b[K[+] Building 2.0s\n"}, "[+] Building 1.0s\n[+] Building 2.0s\n"},
		{"private mode set and reset", []string{"\x1b[?25lstep\x1b[?25h\n"}, "step\n"},
		{"carriage returns from the pty", []string{"line\r\n"}, "line\n"},
		{"OSC title ended by BEL", []string{"\x1b]0;buildx\x07ok\n"}, "ok\n"},
		{"OSC ended by ST", []string{"\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\\n"}, "link\n"},
		{"two-byte escape", []string{"\x1b7saved\x1b8\n"}, "saved\n"},
		{"other control bytes", []string{"a\x00b\x07c\x08d\x7fe\n"}, "abcde\n"},
		{"utf-8 kept", []string{"✔ done — é\n"}, "✔ done — é\n"},
		{"sequence split across writes", []string{"x\x1b", "[3", "1mred\x1b[", "0m\n"}, "xred\n"},
		{"string split across writes", []string{"\x1b]0;ti", "tle\x1b", "\\after\n"}, "after\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewPlainWriter(&buf)
			for _, c := range tc.chunks {
				if n, err := w.Write([]byte(c)); err != nil || n != len(c) {
					t.Fatalf("write %q = %d, %v", c, n, err)
				}
			}
			if buf.String() != tc.want {
				t.Errorf("got %q, want %q", buf.String(), tc.want)
			}
		})
	}
}
