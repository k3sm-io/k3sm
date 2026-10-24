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

// imageMigrationRow reads the journal and renders the row, or false when
// there is no work dir to read it from.
func (c Collector) imageMigrationRow() (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	path := ImageMigrationJournalPath(wd)
	raw, err := c.FS.ReadFile(path)
	return imageMigrationRowFrom(path, raw, err), true
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
	row.Wide["in_registry"] = strconv.Itoa(inRegistry)
	row.Wide["cache_entries"] = strconv.Itoa(cached)
	row.Wide["held"] = strconv.Itoa(held)
	counts := plural(inRegistry, "image") + " in the cluster registry, " + plural(cached, "pull-cache image") + " left as cached"
	if held > 0 {
		counts += fmt.Sprintf(", %d held in the node store (unexportable)", held)
	}
	switch {
	case j.Complete:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "done: " + counts
		if held > 0 {
			row.Severity = SeverityWarn
			row.Remedy = "sudo k3sm image migrate --report"
		}
	case j.LastError != "":
		row.State, row.Severity = StateFailed, SeverityWarn
		row.Detail = "pending: " + Redact(firstLine(j.LastError)) + " (so far " + counts + "; nothing was removed from the node store)"
		row.Remedy = "sudo k3sm image migrate"
	default:
		row.State, row.Severity = StateWaiting, SeverityWarn
		row.Detail = "pending: the copy has not finished (so far " + counts + "; nothing was removed from the node store)"
		row.Remedy = "sudo k3sm image migrate"
	}
	return row
}
