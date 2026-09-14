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

package datavol

import "testing"

// TestParseSize pins the flag grammar: the suffixes are binary units, so what
// the operator asks for is what diskutil reports back and what FormatSize
// prints, with no factor-of-1.07 surprise between the three.
func TestParseSize(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    uint64
		wantErr bool
	}{
		{name: "the default size", in: "100g", want: 100 << 30},
		{name: "the floor", in: "32g", want: MinQuotaBytes},
		{name: "an upper-case suffix", in: "2G", want: 2 << 30},
		{name: "megabytes", in: "512m", want: 512 << 20},
		{name: "terabytes", in: "1t", want: 1 << 40},
		{name: "a bare byte count", in: "1048576", want: 1 << 20},
		{name: "surrounding whitespace", in: "  8g\n", want: 8 << 30},
		{name: "zero parses; the floor is enforced elsewhere", in: "0", want: 0},
		{name: "empty", in: "", wantErr: true},
		{name: "an unknown unit", in: "100k", wantErr: true},
		{name: "a fraction", in: "1.5g", wantErr: true},
		{name: "not a number", in: "lots", wantErr: true},
		{name: "a negative count", in: "-1g", wantErr: true},
		{name: "an overflowing count", in: "99999999999t", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSize(%q) = %d, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestFormatSize pins the two shapes the docs and the status row quote.
func TestFormatSize(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{100 << 30, "100G"},
		{32105000000, "29.9G"},
		{512 << 20, "512M"},
		{1 << 40, "1T"},
		{4096, "4K"},
		{512, "512B"},
		{0, "0B"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := FormatSize(tc.in); got != tc.want {
				t.Fatalf("FormatSize(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
