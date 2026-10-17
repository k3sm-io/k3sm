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
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/updatectl"
)

// adminTokenReportBackoff and adminTokenReportMaxBackoff are the retry
// schedule of a failed Node patch of the rotation mark: 5 s, doubling, at most
// 60 s apart, for as long as the daemon runs. The marker is removed only once a
// patch lands, so a daemon that stops first publishes on its next start.
const (
	adminTokenReportBackoff    = 5 * time.Second
	adminTokenReportMaxBackoff = 60 * time.Second
)

// maxAdminTokenMarker bounds the marker read: it holds a time and a version.
const maxAdminTokenMarker = 256

// markerVersion is the shape of a release version the marker may carry. It
// rides into a Node annotation, so nothing else is accepted.
var markerVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)

// startAdminTokenRotationReport publishes the install's admin token rotation
// on this control plane's own Node, once, and returns its stop. It runs once
// the node is Ready, like the update watcher, at the point the update
// controller reads the mark from. A node with no marker path (a worker, the
// standalone `k3sm node`) does nothing.
func startAdminTokenRotationReport(ctx context.Context, opts nodeOptions, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	if opts.adminTokenMarker == "" || cs == nil {
		return noStop
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reportAdminTokenRotation(rctx, cs, opts.nodeName, opts.adminTokenMarker, adminTokenReportBackoff, adminTokenReportMaxBackoff, logger)
	}()
	return func() {
		cancel()
		<-done
	}
}

// reportAdminTokenRotation reads the marker the install left at path and, when
// there is one, sets updatectl.AdminTokenRotatedAnnotation on node to
// "<version> <RFC3339>". A failed patch is retried with backoff (from backoff,
// doubling, capped at maxBackoff) until it lands or ctx ends. Once it lands the
// marker is removed, but only if it still holds what was published: a marker
// a newer install wrote meanwhile is left for the next start. A marker that is
// not a time and a version is removed, since it reports nothing. Only the
// version and the time are ever published, and the marker's content is never
// logged.
func reportAdminTokenRotation(ctx context.Context, cs kubernetes.Interface, node, path string, backoff, maxBackoff time.Duration, logger *slog.Logger) {
	raw, err := readAdminTokenMarker(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var value string
	if err == nil {
		value, err = adminTokenMark(raw)
	}
	if err != nil {
		logger.Warn("the admin token rotation marker is unreadable or malformed; removing it", "path", path)
		removeAdminTokenMarker(path, raw, logger)
		return
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		updatectl.AdminTokenRotatedAnnotation: value,
	}}})
	if err != nil {
		logger.Error("encode the admin token rotation annotation", "err", err)
		return
	}
	wait := backoff
	for attempt := 1; ; attempt++ {
		_, err := cs.CoreV1().Nodes().Patch(ctx, node, types.MergePatchType, patch, metav1.PatchOptions{})
		if err == nil {
			break
		}
		logger.Warn("could not publish the admin token rotation on this node; retrying", "node", node, "attempt", attempt, "retry_in", wait, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, maxBackoff)
	}
	logger.Warn("this control plane's admin credential was re-minted by its last install: every copy of the admin kubeconfig taken before it is refused until it is copied again",
		"node", node, "annotation", updatectl.AdminTokenRotatedAnnotation, "mark", value)
	removeAdminTokenMarker(path, raw, logger)
}

// adminTokenMark is the annotation value for a marker's content: its two
// lines, the install's time and the release version, as "<version> <time>".
func adminTokenMark(raw []byte) (string, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		return "", errors.New("the marker is not two lines")
	}
	at, err := time.Parse(time.RFC3339, lines[0])
	if err != nil {
		return "", errors.New("the marker's first line is not a time")
	}
	if !markerVersion.MatchString(lines[1]) {
		return "", errors.New("the marker's second line is not a release version")
	}
	return lines[1] + " " + at.UTC().Format(time.RFC3339), nil
}

// readAdminTokenMarker reads the marker, at most maxAdminTokenMarker bytes. A
// missing marker keeps fs.ErrNotExist.
func readAdminTokenMarker(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxAdminTokenMarker+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAdminTokenMarker {
		return nil, errors.New("the marker is larger than a time and a version")
	}
	return raw, nil
}

// removeAdminTokenMarker removes the marker if it still holds read (nil: an
// unreadable marker, removed as found); a marker already gone is not a
// failure.
func removeAdminTokenMarker(path string, read []byte, logger *slog.Logger) {
	if read != nil {
		now, err := readAdminTokenMarker(path)
		if err != nil || !bytes.Equal(now, read) {
			if err == nil {
				logger.Info("the admin token rotation marker changed since it was published; leaving it for the next start", "path", path)
			}
			return
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logger.Warn("remove the admin token rotation marker", "path", path, "err", err)
	}
}
