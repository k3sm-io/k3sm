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

package hf

import (
	"errors"
	"strings"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// FuzzHubTreeListing: the tree listing is internet input. Whatever the bytes,
// parseTree returns or refuses without panicking, never more entries than
// its limit, and every entry it accepts passes checkEntry: a known type, a
// valid path, a 40-hex git id, and sizes and LFS hashes in bounds. The seed
// corpus is committed under testdata/fuzz/FuzzHubTreeListing.
func FuzzHubTreeListing(f *testing.F) {
	f.Add([]byte(`[]`), 3)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if limit < 0 || limit > MaxTreeEntries {
			limit = MaxTreeEntries
		}
		entries, err := parseTree(data, limit)
		if err != nil {
			if !errors.Is(err, ErrBadListing) {
				t.Fatalf("parseTree error %v is not ErrBadListing", err)
			}
			return
		}
		if len(entries) > limit {
			t.Fatalf("%d entries, limit %d", len(entries), limit)
		}
		for _, e := range entries {
			if err := checkEntry(e); err != nil {
				t.Fatalf("accepted entry %+v fails checkEntry: %v", e, err)
			}
			if e.Type == entryFile && e.LFS == nil && e.Size > MaxSmallFileBytes {
				t.Fatalf("accepted small file of %d bytes", e.Size)
			}
			if e.Size < 0 || e.Size > MaxFileBytes {
				t.Fatalf("accepted size %d", e.Size)
			}
		}
	})
}

const (
	blob40 = "ce013625030ba8dba906f756967f9e9ca394464a"
	sum64  = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
)

func TestParseTreeRefusesUnrecognised(t *testing.T) {
	file := `{"type":"file","oid":"` + blob40 + `","size":6,"path":"hello.txt"}`
	lfs := `{"type":"file","oid":"` + blob40 + `","size":10,"path":"model.safetensors","lfs":{"oid":"` + sum64 + `","size":10,"pointerSize":134}}`
	for _, tc := range []struct {
		name, in string
		ok       bool
	}{
		{"empty array", `[]`, true},
		{"a file, an LFS file and a directory, with unknown keys", `[` + file + `,` + lfs + `,{"type":"directory","oid":"` + blob40 + `","size":0,"path":"sub","lastCommit":{}}]`, true},
		{"not an array", `{"type":"file"}`, false},
		{"trailing data", `[]x`, false},
		{"two arrays", `[][]`, false},
		{"truncated", `[` + file, false},
		{"null entry", `[null]`, false},
		{"submodule", `[{"type":"submodule","oid":"` + blob40 + `","size":0,"path":"x"}]`, false},
		{"symlink type", `[{"type":"symlink","oid":"` + blob40 + `","size":0,"path":"x"}]`, false},
		{"short git id", `[{"type":"file","oid":"abc","size":1,"path":"x"}]`, false},
		{"uppercase git id", `[{"type":"file","oid":"` + strings.ToUpper(blob40) + `","size":1,"path":"x"}]`, false},
		{"negative size", `[{"type":"file","oid":"` + blob40 + `","size":-1,"path":"x"}]`, false},
		{"small file over the bound", `[{"type":"file","oid":"` + blob40 + `","size":67108865,"path":"x"}]`, false},
		{"LFS file over the bound", `[{"type":"file","oid":"` + blob40 + `","size":274877906945,"path":"x","lfs":{"oid":"` + sum64 + `","size":274877906945}}]`, false},
		{"LFS size disagrees", `[{"type":"file","oid":"` + blob40 + `","size":10,"path":"x","lfs":{"oid":"` + sum64 + `","size":11}}]`, false},
		{"LFS hash not sha256", `[{"type":"file","oid":"` + blob40 + `","size":10,"path":"x","lfs":{"oid":"` + blob40 + `","size":10}}]`, false},
		{"directory with a size", `[{"type":"directory","oid":"` + blob40 + `","size":3,"path":"x"}]`, false},
		{"path escapes", `[{"type":"file","oid":"` + blob40 + `","size":1,"path":"../x"}]`, false},
		{"absolute path", `[{"type":"file","oid":"` + blob40 + `","size":1,"path":"/etc/x"}]`, false},
		{"path outside the charset", `[{"type":"file","oid":"` + blob40 + `","size":1,"path":"a b"}]`, false},
		{"size as a string", `[{"type":"file","oid":"` + blob40 + `","size":"1","path":"x"}]`, false},
		{"size beyond int64", `[{"type":"file","oid":"` + blob40 + `","size":99999999999999999999,"path":"x"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTree([]byte(tc.in), MaxTreeEntries)
			if tc.ok && err != nil {
				t.Fatalf("parseTree = %v, want accepted", err)
			}
			if !tc.ok && !errors.Is(err, ErrBadListing) {
				t.Fatalf("parseTree = %v, want ErrBadListing", err)
			}
		})
	}
	t.Run("more entries than the limit", func(t *testing.T) {
		if _, err := parseTree([]byte(`[`+file+`,`+lfs+`]`), 1); !errors.Is(err, ErrBadListing) {
			t.Fatalf("parseTree over the limit = %v, want ErrBadListing", err)
		}
	})
	t.Run("a path longer than the path rules allow", func(t *testing.T) {
		long := strings.Repeat("a", artifactv1.MaxPathBytes+1)
		if _, err := parseTree([]byte(`[{"type":"file","oid":"`+blob40+`","size":1,"path":"`+long+`"}]`), 10); !errors.Is(err, ErrBadListing) {
			t.Fatalf("parseTree = %v, want ErrBadListing", err)
		}
	})
}

func TestNextLink(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		err      bool
	}{
		{"", "", false},
		{`<https://h/api/x?cursor=a>; rel="next"`, "https://h/api/x?cursor=a", false},
		{`<https://h/p1>; rel="prev", <https://h/p3>; rel="next"`, "https://h/p3", false},
		{`<https://h/p1>; rel=last`, "", false},
		{`https://h/p1; rel="next"`, "", true},
		{`<https://h/p1; rel="next"`, "", true},
	} {
		got, err := nextLink(tc.in)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("nextLink(%q) = %q, %v; want %q, error %v", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestParseRef(t *testing.T) {
	for _, tc := range []struct {
		in       string
		repo     string
		revision string
	}{
		{"hf://acme/tiny-model", "acme/tiny-model", "main"},
		{"hf://mlx-community/Qwen3-0.6B-4bit@" + blob40, "mlx-community/Qwen3-0.6B-4bit", blob40},
		{"hf://acme/m@refs/pr/1", "acme/m", "refs/pr/1"},
		{"hf://acme/m@v1.0", "acme/m", "v1.0"},
	} {
		got, err := ParseRef(tc.in)
		if err != nil || got.Repo != tc.repo || got.Revision != tc.revision {
			t.Errorf("ParseRef(%q) = %+v, %v; want %s@%s", tc.in, got, err, tc.repo, tc.revision)
		}
	}
	for _, in := range []string{
		"acme/m", "https://huggingface.co/acme/m", "hf://m", "hf://acme/m/x", "hf:///m", "hf://acme/",
		"hf://acme/-m", "hf://acme/m.", "hf://acme/a--b", "hf://acme/a..b", "hf://acme/m@", "hf://acme/m@a/../b",
		"hf://acme/m@a b", "hf://acme/m@/x", "hf://ac%2Fme/m", "hf://acme/" + strings.Repeat("m", 97),
		"hf://acme/m@" + strings.Repeat("r", 256),
	} {
		if _, err := ParseRef(in); !errors.Is(err, ErrBadReference) {
			t.Errorf("ParseRef(%q) = %v, want ErrBadReference", in, err)
		}
	}
}
