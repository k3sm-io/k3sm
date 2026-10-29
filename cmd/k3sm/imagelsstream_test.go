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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// timedLine is one Write a stream made, and when.
type timedLine struct {
	at   time.Time
	line string
}

// lineRecorder records every Write with its time, so a test can tell a line
// written as the listing ran from one held back until it ended.
type lineRecorder struct {
	mu    sync.Mutex
	lines []timedLine
}

func (r *lineRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, timedLine{time.Now(), string(p)})
	return len(p), nil
}

// streamLine is the union of the -o ndjson line shapes.
type streamLine struct {
	Type string `json:"type"`
	imageRow
	listProgress
	SchemaVersion      int             `json:"schemaVersion"`
	Registry           *registryReport `json:"registry"`
	Images             int             `json:"images"`
	CachedOnIncomplete []string        `json:"cachedOnIncomplete"`
	Error              string          `json:"error"`
	Migration          any             `json:"migration"`
}

// runImageStream runs `ls -o ndjson` and returns its writes and its error.
func runImageStream(t *testing.T, env imageRegistryEnv) ([]timedLine, error) {
	t.Helper()
	o, err := parseImageArgs([]string{"ls", "-o", "ndjson"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var rec lineRecorder
	err = imageRegistryCommand(context.Background(), o, &rec, env)
	return rec.lines, err
}

// decodeStream checks that every write is exactly one JSON line with a type,
// and decodes them.
func decodeStream(t *testing.T, writes []timedLine) []streamLine {
	t.Helper()
	var out []streamLine
	for i, w := range writes {
		if !strings.HasSuffix(w.line, "\n") || strings.Count(w.line, "\n") != 1 {
			t.Fatalf("write %d is not one line: %q", i, w.line)
		}
		var l streamLine
		dec := json.NewDecoder(strings.NewReader(w.line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil || l.Type == "" {
			t.Fatalf("write %d %q: not a typed JSON object: %v", i, w.line, err)
		}
		out = append(out, l)
	}
	return out
}

// TestImageLsStream: -o ndjson writes start, progress and one image line per
// tag as its describe completes, then end; each line is written on its own as
// the listing runs, and the image lines carry the -o json document's rows.
func TestImageLsStream(t *testing.T) {
	t.Run("a large registry streams as it is read", func(t *testing.T) {
		env, _ := largeRegistryEnv(t, 10, 20, 20*time.Millisecond)
		start := time.Now()
		writes, err := runImageStream(t, env)
		if err != nil {
			t.Fatal(err)
		}
		lines := decodeStream(t, writes)
		if lines[0].Type != "start" || lines[0].SchemaVersion != 1 || lines[0].Registry == nil || !lines[0].Registry.Reachable {
			t.Fatalf("first line = %+v; want a reachable start", lines[0])
		}
		last := lines[len(lines)-1]
		if last.Type != "end" || last.Images != 200 {
			t.Fatalf("last line = %+v; want end with 200 images", last)
		}
		images, firstImage := 0, -1
		var prev listProgress
		for i, l := range lines[1 : len(lines)-1] {
			switch l.Type {
			case "image":
				images++
				if firstImage < 0 {
					firstImage = i + 1
				}
			case "progress":
				p := l.listProgress
				if p.Repositories != 10 || p.RepositoriesRead < prev.RepositoriesRead || p.Tags < prev.Tags ||
					p.TagsRead < prev.TagsRead || p.TagsRead > p.Tags || p.RepositoriesRead > p.Repositories {
					t.Errorf("progress went backwards or past its totals: %+v after %+v", p, prev)
				}
				prev = p
			default:
				t.Errorf("unexpected line %+v between start and end", l)
			}
		}
		if images != 200 {
			t.Errorf("%d image lines; want 200", images)
		}
		if want := (listProgress{Repositories: 10, RepositoriesRead: 10, Tags: 200, TagsRead: 200}); prev != want {
			t.Errorf("the last progress = %+v; want %+v", prev, want)
		}
		firstAt, endAt := writes[firstImage].at.Sub(start), writes[len(writes)-1].at.Sub(start)
		t.Logf("first image line at %v, end at %v", firstAt, endAt)
		if firstAt > endAt/2 {
			t.Errorf("the first image line was written at %v of %v: the stream is not written as the listing runs", firstAt, endAt)
		}
	})

	t.Run("image lines are the json document's rows", func(t *testing.T) {
		f := newImageFixture(t, true)
		var rep imageListReport
		if err := json.Unmarshal([]byte(runImageReport(t, f.env, "ls", "-o", "json")), &rep); err != nil {
			t.Fatal(err)
		}
		writes, err := runImageStream(t, f.env)
		if err != nil {
			t.Fatal(err)
		}
		var rows []imageRow
		lines := decodeStream(t, writes)
		for _, l := range lines {
			if l.Type == "image" {
				rows = append(rows, l.imageRow)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Reference < rows[j].Reference })
		if !reflect.DeepEqual(rows, rep.Images) {
			t.Errorf("stream rows = %+v\njson rows = %+v", rows, rep.Images)
		}
		end := lines[len(lines)-1]
		if end.Type != "end" || end.Images != len(rep.Images) || !reflect.DeepEqual(end.CachedOnIncomplete, rep.CachedOnIncomplete) {
			t.Errorf("end = %+v; want %d images and cachedOnIncomplete %v", end, len(rep.Images), rep.CachedOnIncomplete)
		}
		if !strings.Contains(writes[len(writes)-1].line, `"migration":null`) {
			t.Errorf("end line %q must carry migration: null", writes[len(writes)-1].line)
		}
	})

	t.Run("an unreachable registry is start then end, exit 0", func(t *testing.T) {
		writes, err := runImageStream(t, newImageFixture(t, false).env)
		if err != nil {
			t.Fatalf("err = %v; want exit 0", err)
		}
		lines := decodeStream(t, writes)
		if len(lines) != 2 || lines[0].Type != "start" || lines[0].Registry.Reachable || lines[0].Registry.Error == "" ||
			lines[1].Type != "end" || lines[1].Images != 0 {
			t.Errorf("lines = %+v; want an unreachable start with its error, then end", lines)
		}
	})

	t.Run("a failure mid-listing is an error line and a non-zero exit", func(t *testing.T) {
		f := newImageFixture(t, true)
		f.env.transport = failManifests{f.env.transport}
		writes, err := runImageStream(t, f.env)
		if err == nil {
			t.Fatal("err = nil; want the manifest read's failure")
		}
		lines := decodeStream(t, writes)
		if lines[0].Type != "start" || !lines[0].Registry.Reachable {
			t.Errorf("first line = %+v; want a reachable start", lines[0])
		}
		last := lines[len(lines)-1]
		if last.Type != "error" || !strings.Contains(last.Error, "503") || !strings.Contains(err.Error(), "503") {
			t.Errorf("last line = %+v, err = %v; want an error line naming the 503", last, err)
		}
		for _, l := range lines {
			if l.Type == "end" {
				t.Error("a failed listing wrote an end line")
			}
		}
	})
}

// failManifests answers every manifest read with a 503.
type failManifests struct{ next http.RoundTripper }

func (f failManifests) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "/manifests/") {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable",
			Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	}
	return f.next.RoundTrip(r)
}

func TestImageLsStreamArgs(t *testing.T) {
	if o, err := parseImageArgs([]string{"ls", "-o", "ndjson"}, io.Discard); err != nil || o.output != "ndjson" {
		t.Errorf("ls -o ndjson = %+v, %v", o, err)
	}
	if _, err := parseImageArgs([]string{"df", "-o", "ndjson"}, io.Discard); err == nil {
		t.Error("df -o ndjson was accepted; only ls streams")
	}
}
