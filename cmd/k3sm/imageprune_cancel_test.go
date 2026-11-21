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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// decodeOnlyPrune decodes stdout as the prune -o json document and fails
// unless it is exactly one valid JSON value with nothing but whitespace after
// it: a note on stdout, before or after the document, breaks every consumer
// that parses stdout as JSON.
func decodeOnlyPrune(t *testing.T, stdout string) pruneJSON {
	t.Helper()
	if !json.Valid([]byte(stdout)) {
		t.Fatalf("stdout is not one valid JSON document:\n%s", stdout)
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	var doc pruneJSON
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("prune -o json is not the documented shape: %v\n%s", err, stdout)
	}
	if rest := strings.TrimSpace(stdout[dec.InputOffset():]); rest != "" {
		t.Fatalf("stdout carries %q after the JSON document", rest)
	}
	return doc
}

// expiringCtx is a context whose deadline is simulated: it is done, with
// context.DeadlineExceeded, from the moment expire is first called and never
// before, so a test of what a deadline does mid-run waits on no wall clock.
type expiringCtx struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newExpiringCtx(parent context.Context) *expiringCtx {
	return &expiringCtx{Context: parent, done: make(chan struct{})}
}

// expire ends the context by its simulated deadline; later calls do nothing.
func (c *expiringCtx) expire() { c.once.Do(func() { close(c.done) }) }

func (c *expiringCtx) Done() <-chan struct{} { return c.done }

func (c *expiringCtx) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// unattemptedList is the report's unattempted manifests as repo@digest.
func unattemptedList(doc pruneJSON) []string {
	var got []string
	for _, m := range doc.Registry.Unattempted {
		got = append(got, m.Repository+"@"+m.Digest)
	}
	return got
}

// TestImagePruneForceJSONInterruptedStdoutIsOneDocument proves an interrupted
// `image prune --force -o json` keeps stdout a single JSON document: the
// report carries interrupted and the manifests it did not send, every
// interruption note is on stderr and none on stdout, and the command still
// returns the cancellation. The deleter cancels the context on its first
// call, as a Ctrl+C during the first DELETE would, and that DELETE succeeds.
func TestImagePruneForceJSONInterruptedStdoutIsOneDocument(t *testing.T) {
	workDir := t.TempDir()
	reg := serveFakePruneRegistry(t, workDir)
	f := buildPruneFixture(t, workDir)
	sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
	var stderr bytes.Buffer
	opts, err := parseImageArgs([]string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	del := func(ctx context.Context, rf name.Digest, state string, auth authn.Authenticator) error {
		cancel()
		return reg.delete(ctx, rf, state, auth)
	}
	var stdout bytes.Buffer
	err = imageCommandWith(ctx, opts, &stdout, dialRuntimed, del, reg.collect)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want the cancellation", err)
	}
	if errors.Is(err, errPruneIncomplete) {
		t.Errorf("err = %v; an unattempted delete is not a failed one", err)
	}

	doc := decodeOnlyPrune(t, stdout.String())
	if !doc.Registry.Interrupted {
		t.Errorf("report interrupted = false")
	}
	if want := []string{"multi@" + f.oldIndex, "multi@" + f.oldLeaf}; strings.Join(unattemptedList(doc), ",") != strings.Join(want, ",") {
		t.Errorf("report unattempted = %v; want %v", unattemptedList(doc), want)
	}
	if got := manifestList(doc); strings.Join(got, ",") != "app@"+f.overwritten {
		t.Errorf("report manifests = %v; want only app@%s", got, f.overwritten)
	}
	if len(doc.Registry.Failed) != 0 {
		t.Errorf("report failed = %+v; want none", doc.Registry.Failed)
	}
	if strings.Contains(stdout.String(), "prune interrupted") {
		t.Errorf("an interruption note is on stdout:\n%s", stdout.String())
	}
	for _, w := range []string{
		"prune interrupted: sweeping the 1 deleted manifest(s)",
		"prune interrupted: 2 planned manifest(s) not attempted or not confirmed",
	} {
		if !strings.Contains(stderr.String(), w) {
			t.Errorf("stderr lacks %q: %q", w, stderr.String())
		}
	}
}

// TestImagePruneForceTimeoutIsAnInterruption proves the --timeout deadline
// expiring during a forced prune stops it exactly as a Ctrl+C does: the same
// report shape (interrupted, the rest unattempted, nothing failed), the notes
// on stderr only, stdout one JSON document, and the deadline returned as the
// error. --timeout parses and imageContext turns it into a deadline; the
// deadline's expiry is simulated by an expiringCtx over that context, which
// the first DELETE expires, so nothing waits on the wall clock. In
// "confirmed" the registry still answers that DELETE, so it is deleted and
// swept; in "cut-off" the deadline cuts it off in flight, so it is
// unattempted too and nothing is swept.
func TestImagePruneForceTimeoutIsAnInterruption(t *testing.T) {
	for _, tc := range []struct {
		name           string
		confirm        bool
		wantDeleted    func(pruneFixture) []string
		wantUnattempt  func(pruneFixture) []string
		wantSweepNotes bool
	}{
		{
			name:           "confirmed",
			confirm:        true,
			wantDeleted:    func(f pruneFixture) []string { return []string{"app@" + f.overwritten} },
			wantUnattempt:  func(f pruneFixture) []string { return []string{"multi@" + f.oldIndex, "multi@" + f.oldLeaf} },
			wantSweepNotes: true,
		},
		{
			name:        "cut-off",
			wantDeleted: func(pruneFixture) []string { return nil },
			wantUnattempt: func(f pruneFixture) []string {
				return []string{"app@" + f.overwritten, "multi@" + f.oldIndex, "multi@" + f.oldLeaf}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			reg := serveFakePruneRegistry(t, workDir)
			f := buildPruneFixture(t, workDir)
			sock := serveFakeImages(t, &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{}})
			var stderr bytes.Buffer
			opts, err := parseImageArgs([]string{"--socket", sock, "--work-dir", workDir, "prune", "--force", "-o", "json", "--timeout", "1h"}, &stderr)
			if err != nil {
				t.Fatal(err)
			}
			if opts.timeout != time.Hour {
				t.Fatalf("parsed timeout = %v; want 1h", opts.timeout)
			}
			deadlineCtx, cancel := imageContext(t.Context(), opts)
			defer cancel()
			if _, ok := deadlineCtx.Deadline(); !ok {
				t.Fatal("imageContext set no deadline for prune --timeout")
			}
			ctx := newExpiringCtx(deadlineCtx)
			var calls int
			del := func(dctx context.Context, rf name.Digest, state string, auth authn.Authenticator) error {
				calls++
				if calls == 1 {
					ctx.expire()
				}
				if !tc.confirm {
					return dctx.Err()
				}
				return reg.delete(context.WithoutCancel(dctx), rf, state, auth)
			}
			var sweepCtxErr error
			collect := func(ctx context.Context, authority string, deleted []registrysvc.StoredManifest, cred registrysvc.Credential) (registrysvc.CollectResult, error) {
				sweepCtxErr = ctx.Err()
				return reg.collect(ctx, authority, deleted, cred)
			}
			var stdout bytes.Buffer
			err = imageCommandWith(ctx, opts, &stdout, dialRuntimed, del, collect)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v; want the --timeout deadline", err)
			}
			if errors.Is(err, errPruneIncomplete) {
				t.Errorf("err = %v; an unattempted delete is not a failed one", err)
			}
			if calls != 1 {
				t.Errorf("deleter called %d times; want 1, nothing after the deadline", calls)
			}

			doc := decodeOnlyPrune(t, stdout.String())
			if !doc.Registry.Interrupted {
				t.Errorf("report interrupted = false")
			}
			if len(doc.Registry.Failed) != 0 {
				t.Errorf("report failed = %+v; want none", doc.Registry.Failed)
			}
			if want := tc.wantUnattempt(f); strings.Join(unattemptedList(doc), ",") != strings.Join(want, ",") {
				t.Errorf("report unattempted = %v; want %v", unattemptedList(doc), want)
			}
			if want := tc.wantDeleted(f); strings.Join(manifestList(doc), ",") != strings.Join(want, ",") {
				t.Errorf("report manifests = %v; want %v", manifestList(doc), want)
			}

			unattemptedNote := fmt.Sprintf("prune interrupted: %d planned manifest(s) not attempted or not confirmed; run prune again to delete them\n", len(tc.wantUnattempt(f)))
			wantNotes := unattemptedNote
			if tc.wantSweepNotes {
				wantNotes = "prune interrupted: sweeping the 1 deleted manifest(s) for up to " + pruneSweepGrace.String() + "\n" + unattemptedNote
				if doc.Registry.Sweep == nil {
					t.Errorf("report has no sweep of the confirmed delete")
				}
				if sweepCtxErr != nil {
					t.Errorf("the sweep ran under the expired deadline: %v", sweepCtxErr)
				}
				if len(reg.collects) != 1 {
					t.Errorf("collects %v; want one sweep", reg.collects)
				}
			} else {
				if doc.Registry.Sweep != nil || len(reg.collects) != 0 {
					t.Errorf("swept with nothing confirmed deleted: sweep %+v, collects %v", doc.Registry.Sweep, reg.collects)
				}
			}
			if stderr.String() != wantNotes {
				t.Errorf("stderr = %q\nwant     %q", stderr.String(), wantNotes)
			}
		})
	}
}
