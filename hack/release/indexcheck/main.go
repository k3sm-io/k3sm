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

// Command indexcheck decodes one release index document with
// k3sm.io/k3sm/pkg/update.ParseReleaseIndex and prints the fields a release
// must match, one key=value line each, in a fixed order. hack/release/publish.sh
// runs it on the content it extracts from the signed index, so the document a
// release uploads passes the same decoder the schema is pinned to, and then
// compares the printed fields with the release's own assets.
//
// It decodes content only: it never verifies a signature.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"k3sm.io/k3sm/pkg/update"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "indexcheck: %v\n", err)
		os.Exit(1)
	}
}

// run decodes the document at args[0] and writes its fields to w.
func run(args []string, w io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: indexcheck <release-index.json>")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing
	// One byte over the cap is enough for ParseReleaseIndex to refuse it.
	raw, err := io.ReadAll(io.LimitReader(f, update.MaxReleaseIndexBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	ix, err := update.ParseReleaseIndex(raw)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, fields(ix))
	return err
}

// fields is the key=value form publish.sh compares, in its order.
func fields(ix update.ReleaseIndex) string {
	return "tag=" + ix.Tag + "\n" +
		"image_name=" + ix.App.Image.Name + "\n" +
		"image_sha256=" + ix.App.Image.SHA256 + "\n" +
		"image_size=" + strconv.FormatInt(ix.App.Image.Size, 10) + "\n" +
		"archive=" + ix.K3sm.Archive + "\n" +
		"archive_sha256=" + ix.K3sm.ArchiveSHA256 + "\n" +
		"payload_manifest_sha256=" + ix.K3sm.PayloadManifestSHA256 + "\n"
}
