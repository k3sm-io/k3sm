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
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	imagestorev1 "k3sm.io/apis/imagestore/v1"
)

// TestImageDFClassesColumnAndMissingAnnotation pins how df reads each node's
// class report: the JSON fields, the IMAGE/ARTIFACT/OTHER cells and the
// trailing note, for a valid report, no report, an unreadable one, a newer
// schema, a stale one, one ahead of the clock, and a valid empty store.
func TestImageDFClassesColumnAndMissingAnnotation(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	encode := func(at time.Time, store uint64, classes map[string]uint64) string {
		t.Helper()
		r := imagestorev1.ClassReport{Schema: imagestorev1.ClassReportSchema, ObservedAt: at, StoreBytes: store, BytesByClass: classes}
		v, err := r.Encode()
		if err != nil {
			t.Fatalf("encode %+v: %v", r, err)
		}
		return v
	}
	node := func(name string, annotation *string) corev1.Node {
		n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if annotation != nil {
			n.Annotations = map[string]string{imagestorev1.AnnotationClassReport: *annotation}
		}
		return n
	}
	ptr := func(s string) *string { return &s }

	nodes := []corev1.Node{
		// Listed out of order: the report sorts by name.
		node("n7-empty", ptr(encode(now.Add(-time.Minute), 0, map[string]uint64{}))),
		node("n1-valid", ptr(encode(now.Add(-2*time.Minute), 3148800, map[string]uint64{
			imagestorev1.ClassImage:        3145728,
			imagestorev1.ClassArtifact:     1024,
			"application/x-foo":            1536,
			imagestorev1.ClassUnattributed: 512,
		}))),
		node("n2-missing", nil),
		node("n3-unreadable", ptr("{not json")),
		node("n4-newer", ptr(`{"schema":2,"observedAt":"2026-11-13T12:00:00Z"}`)),
		node("n5-stale", ptr(encode(now.Add(-25*time.Minute-30*time.Second), 100, map[string]uint64{imagestorev1.ClassImage: 100}))),
		node("n6-ahead", ptr(encode(now.Add(11*time.Minute), 2048, map[string]uint64{imagestorev1.ClassArtifact: 2048}))),
	}

	rep := buildImageDF(registryReport{Name: "registry-k3sm:6450", Reachable: true}, registryListing{}, nodes)

	const base = `"cacheBytes":0,"images":0,"incomplete":false`
	wantJSON := []string{
		`{"node":"n1-valid",` + base + `,"classes":{"application/x-foo":1536,"artifact":1024,"image":3145728,"unattributed":512},"classesObservedAt":"2026-11-13T11:58:00Z","storeBytes":3148800}`,
		`{"node":"n2-missing",` + base + `}`,
		`{"node":"n3-unreadable",` + base + `,"classesNote":"unreadable"}`,
		`{"node":"n4-newer",` + base + `,"classesNote":"newer schema"}`,
		`{"node":"n5-stale",` + base + `,"classes":{"image":100},"classesObservedAt":"2026-11-13T11:34:30Z","storeBytes":100}`,
		`{"node":"n6-ahead",` + base + `,"classes":{"artifact":2048},"classesObservedAt":"2026-11-13T12:11:00Z","storeBytes":2048}`,
		// A valid empty store keeps "classes": {} and "storeBytes": 0, so it
		// is never mistaken for a node with no report.
		`{"node":"n7-empty",` + base + `,"classes":{},"classesObservedAt":"2026-11-13T11:59:00Z","storeBytes":0}`,
	}
	if len(rep.Nodes) != len(wantJSON) {
		t.Fatalf("got %d node rows, want %d: %+v", len(rep.Nodes), len(wantJSON), rep.Nodes)
	}
	for i, row := range rep.Nodes {
		got, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal %+v: %v", row, err)
		}
		if string(got) != wantJSON[i] {
			t.Errorf("row %d JSON:\n got %s\nwant %s", i, got, wantJSON[i])
		}
	}

	var out bytes.Buffer
	if err := renderImageDF(&out, rep, now); err != nil {
		t.Fatalf("renderImageDF: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if lines[0] != "registry registry-k3sm:6450: 0 B" {
		t.Errorf("first line = %q", lines[0])
	}
	// tabwriter pads with at least two spaces and no cell holds two in a
	// row, so splitting on runs of two or more recovers the cells exactly.
	sep := regexp.MustCompile(`  +`)
	wantCells := [][]string{
		{"NODE", "CACHED", "IMAGES", "IMAGE", "ARTIFACT", "OTHER"},
		{"n1-valid", "0 B", "0", "3.0 MiB", "1.0 KiB", "2.0 KiB"},
		{"n2-missing", "0 B", "0", "-", "-", "-"},
		{"n3-unreadable", "0 B", "0", "-", "-", "-", "(class report unreadable)"},
		{"n4-newer", "0 B", "0", "-", "-", "-", "(class report newer schema)"},
		{"n5-stale", "0 B", "0", "100 B", "0 B", "0 B", "(class report 25m0s old)"},
		{"n6-ahead", "0 B", "0", "0 B", "2.0 KiB", "0 B", "(class report ahead of this clock)"},
		{"n7-empty", "0 B", "0", "0 B", "0 B", "0 B"},
	}
	table := lines[1:]
	if len(table) != len(wantCells) {
		t.Fatalf("table has %d lines, want %d:\n%s", len(table), len(wantCells), out.String())
	}
	for i, line := range table {
		got := sep.Split(strings.TrimRight(line, " "), -1)
		if strings.Join(got, "|") != strings.Join(wantCells[i], "|") {
			t.Errorf("table line %d cells:\n got %q\nwant %q", i, got, wantCells[i])
		}
	}
}
