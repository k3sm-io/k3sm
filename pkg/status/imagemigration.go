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

package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
)

// ImageMigrationRow names the row that reports the one-time copy of this
// node's user images into the cluster registry, read from the journal the
// copy keeps under the work dir.
//
// The row is for the text screen only: Report carries it in ImageMigration,
// which the JSON encoding leaves out, so `k3sm status -o json` is unchanged
// and the verdict never turns on it. That is also why it is not a Row*
// constant: those name the -o json row vocabulary. A pending copy loses
// nothing, because it never deletes from the node store.
const ImageMigrationRow = "img-migrate"

// ImageMigrationJournalPath is the journal the image migration keeps under
// workDir. cmd/k3sm writes it; a test there pins that both agree.
func ImageMigrationJournalPath(workDir string) string {
	return filepath.Join(workDir, "image-migration", "journal.json")
}

// imageMigrationSchema is the journal schema this reader knows.
const imageMigrationSchema = 1

// ImageMigrationSummaryName is the basename of the summary the migration
// publishes, world-readable, in the status directory (Dir).
const ImageMigrationSummaryName = "image-migration.json"

// ImageMigrationSummaryPath is the published summary for workDir, beside the
// other records the server publishes for `k3sm status`.
func ImageMigrationSummaryPath(workDir string) string {
	return filepath.Join(Dir(workDir), ImageMigrationSummaryName)
}

// ImageMigrationSummarySchema is the summary's format version.
const ImageMigrationSummarySchema = 1

// The summary's states.
const (
	// ImageMigrationComplete: a run reached every node-store entry.
	ImageMigrationComplete = "complete"
	// ImageMigrationPending: no run has yet reached every entry.
	ImageMigrationPending = "pending"
)

// ImageMigrationSummary is what the image migration publishes for an account
// that cannot read its root-only journal: the state, the counts and why the
// last run stopped, and no image name. cmd/k3sm writes it beside every journal
// write; a test there pins the two together.
type ImageMigrationSummary struct {
	Schema int `json:"schema"`
	// State is ImageMigrationComplete or ImageMigrationPending.
	State string `json:"state"`
	// InRegistry counts the images the registry holds (migrated, present and
	// renamed), CacheEntries the pull-cache entries left as they were, and
	// Held the images the node store could not export.
	InRegistry   int `json:"inRegistry"`
	CacheEntries int `json:"cacheEntries"`
	Held         int `json:"held"`
	// LastError is why the last run stopped short, said without naming any
	// image; empty after a run that reached every entry.
	LastError string `json:"lastError,omitempty"`
}

// imageMigrationJournal is the slice of the journal the row reads.
type imageMigrationJournal struct {
	Schema    int    `json:"schema"`
	Started   string `json:"started"`
	Complete  bool   `json:"complete"`
	LastError string `json:"lastError"`
	Images    []struct {
		Outcome string `json:"outcome"`
	} `json:"images"`
}

// imageMigrationRow renders the row, or false when there is no work dir to
// read it from. It reads the published summary first, as any account can,
// and the root-only journal only when there is no summary. A status directory
// with no summary in it means no run of this release has written a journal,
// since one publishes the summary beside every journal write, so a journal
// this account cannot read is reported as not started there.
func (c Collector) imageMigrationRow() (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	summary := ImageMigrationSummaryPath(wd)
	raw, err := c.FS.ReadFile(summary)
	switch {
	case err == nil:
		return imageMigrationSummaryRowFrom(summary, raw), true
	case !errors.Is(err, fs.ErrNotExist):
		return imageMigrationRowFrom(summary, nil, err), true
	}
	path := ImageMigrationJournalPath(wd)
	raw, err = c.FS.ReadFile(path)
	if errors.Is(err, fs.ErrPermission) {
		if _, serr := c.FS.Stat(Dir(wd)); serr == nil {
			err = fs.ErrNotExist
		}
	}
	return imageMigrationRowFrom(path, raw, err), true
}

// imageMigrationSummaryRowFrom renders the row from the published summary's
// bytes. Pure.
func imageMigrationSummaryRowFrom(path string, raw []byte) Row {
	row := Row{Name: ImageMigrationRow, Wide: map[string]string{"summary": path}}
	var s ImageMigrationSummary
	if err := json.Unmarshal(raw, &s); err != nil || s.Schema != ImageMigrationSummarySchema ||
		(s.State != ImageMigrationComplete && s.State != ImageMigrationPending) {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the image migration summary does not parse: " + path
		row.Remedy = "sudo k3sm image migrate --report"
		return row
	}
	renderImageMigration(&row, s.State == ImageMigrationComplete, s.LastError, s.InRegistry, s.CacheEntries, s.Held)
	return row
}

// imageMigrationRowFrom renders the row from the journal's bytes and the
// error reading them. Pure.
func imageMigrationRowFrom(path string, raw []byte, readErr error) Row {
	row := Row{Name: ImageMigrationRow, Wide: map[string]string{"journal": path}}
	switch {
	case errors.Is(readErr, fs.ErrNotExist):
		row.State, row.Severity = StateWaiting, SeveritySkip
		row.Detail = "not started: this node's images have not been copied into the cluster registry yet"
		row.Remedy = "sudo k3sm image migrate"
		return row
	case errors.Is(readErr, fs.ErrPermission):
		needsAdmin(&row, "needs sudo: "+path+" is readable by root only")
		return row
	case readErr != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not read " + path + ": " + errText(readErr)
		return row
	}
	var j imageMigrationJournal
	if err := json.Unmarshal(raw, &j); err != nil || j.Schema != imageMigrationSchema {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the image migration journal does not parse: " + path
		row.Remedy = "sudo k3sm image migrate --report"
		return row
	}
	var inRegistry, cached, held int
	for _, img := range j.Images {
		switch img.Outcome {
		case "migrated", "present", "renamed":
			inRegistry++
		case "cached":
			cached++
		case "unexportable":
			held++
		}
	}
	renderImageMigration(&row, j.Complete, j.LastError, inRegistry, cached, held)
	return row
}

// renderImageMigration fills row from a migration's state and counts.
func renderImageMigration(row *Row, complete bool, lastError string, inRegistry, cached, held int) {
	row.Wide["in_registry"] = strconv.Itoa(inRegistry)
	row.Wide["cache_entries"] = strconv.Itoa(cached)
	row.Wide["held"] = strconv.Itoa(held)
	counts := plural(inRegistry, "image") + " in the cluster registry, " + plural(cached, "pull-cache image") + " left as cached"
	if held > 0 {
		counts += fmt.Sprintf(", %d held in the node store (unexportable)", held)
	}
	switch {
	case complete:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "done: " + counts
		if held > 0 {
			row.Severity = SeverityWarn
			row.Remedy = "sudo k3sm image migrate --report"
		}
	case lastError != "":
		row.State, row.Severity = StateFailed, SeverityWarn
		row.Detail = "pending: " + Redact(firstLine(lastError)) + " (so far " + counts + "; nothing was removed from the node store)"
		row.Remedy = "sudo k3sm image migrate"
	default:
		row.State, row.Severity = StateWaiting, SeverityWarn
		row.Detail = "pending: the copy has not finished (so far " + counts + "; nothing was removed from the node store)"
		row.Remedy = "sudo k3sm image migrate"
	}
}
