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
	"reflect"
	"testing"
)

func TestParseFstab(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []fstabEntry
	}{
		{name: "empty", in: "", want: nil},
		{
			name: "comments and blank lines only",
			in:   "#\n# Warning - this file should only be modified with vifs(8)\n#\n\n   \n",
			want: nil,
		},
		{
			name: "a UUID line separated by spaces",
			in:   "UUID=DEADBEEF-0000-1111-2222-333344445555 /var/lib/k3sm apfs rw\n",
			want: []fstabEntry{{Spec: "UUID=DEADBEEF-0000-1111-2222-333344445555", Dir: "/var/lib/k3sm"}},
		},
		{
			name: "a LABEL line separated by tabs",
			in:   "LABEL=Backup\t/Volumes/Backup\thfs\trw\n",
			want: []fstabEntry{{Spec: "LABEL=Backup", Dir: "/Volumes/Backup"}},
		},
		{
			name: "leading whitespace and a trailing line without a newline",
			in:   "   UUID=AAAA /var/lib/k3sm apfs rw\n\t# indented comment\n/dev/disk4 /Volumes/Scratch apfs rw",
			want: []fstabEntry{
				{Spec: "UUID=AAAA", Dir: "/var/lib/k3sm"},
				{Spec: "/dev/disk4", Dir: "/Volumes/Scratch"},
			},
		},
		{
			name: "a malformed one-field line is skipped, not guessed at",
			in:   "UUID=AAAA\nUUID=BBBB /var/lib/k3sm apfs rw\n",
			want: []fstabEntry{{Spec: "UUID=BBBB", Dir: "/var/lib/k3sm"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFstab([]byte(tc.in))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseFstab\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
