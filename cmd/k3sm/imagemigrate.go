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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/pkg/status"
)

// The image-store migration moves every user image out of this node's store
// and into the cluster registry, the one image store. It is one-time and
// resumable: a journal under the work dir records each image's outcome as it
// is reached, so an interrupted run picks up where it stopped and a finished
// run does nothing.
//
// IT NEVER DELETES. The migration reads the node store through its two read
// verbs (list and export) and writes only to the registry and its own journal.
// Every node-store entry, and the operator record that roots the pulled and
// tagged ones, is left exactly as it was, so rolling back to a release that
// reads the node store finds everything where it left it. Retiring the node
// store's user entries is a later, separate step, and it can only follow a
// journal that says the registry holds each digest.

// migrationSchema is the journal's on-disk format version. A journal written
// under a version this binary does not know is an error, never an empty
// journal: an empty one would re-run the migration over a registry the newer
// release has since changed.
const migrationSchema = 1

// migratedTagInfix is the suffix stem a migrated image is pushed under when
// the registry already holds its tag at a different digest. The registry's
// image is the newer one (a build or load since the upgrade wrote it), so it
// keeps the tag and the node's older image lands beside it.
const migratedTagInfix = "-k3sm-migrated-"

// The outcomes a journal records for one image.
const (
	// migrationMigrated: pushed to the registry under its own tag.
	migrationMigrated = "migrated"
	// migrationPresent: the registry already held this digest at the tag.
	migrationPresent = "present"
	// migrationRenamed: the tag was held at another digest, so this image was
	// pushed under the -k3sm-migrated-<12hex> suffix.
	migrationRenamed = "renamed"
	// migrationCached: the registry the reference names serves this digest,
	// so the entry is a pull cache entry and not a user image.
	migrationCached = "cached"
	// migrationUnexportable: the node store could not export it. It stays held
	// and runnable in the node store until it is loaded again.
	migrationUnexportable = "unexportable"
)

// migrationDone reports whether an outcome is final: the image is in the
// registry or is not a user image. An unexportable image is retried.
func migrationDone(outcome string) bool {
	switch outcome {
	case migrationMigrated, migrationPresent, migrationRenamed, migrationCached:
		return true
	}
	return false
}

// migrationInRegistry reports whether an outcome means the registry holds the
// image at the record's target.
func migrationInRegistry(outcome string) bool {
	return outcome == migrationMigrated || outcome == migrationPresent || outcome == migrationRenamed
}

// storeEntry is one node-store entry as the migration reads it: one
// (reference x platform) with its manifest digest and, when the reference
// resolved through a multi-platform index, that index's digest.
type storeEntry struct {
	Reference   string
	Platform    string
	Digest      string
	IndexDigest string
}

// migrationSource is the node store, read-only. It is a seam so the
// migration is provable without a daemon, and it has no method that writes:
// the migration cannot delete what it has no verb for.
type migrationSource interface {
	// List returns every entry of the node store.
	List(ctx context.Context) ([]storeEntry, error)
	// Export returns one entry's image, read back from the store and verified
	// against its digest. cleanup removes any staging the export used.
	Export(ctx context.Context, img storeEntry) (ggcrv1.Image, func(), error)
}

// registryDigester answers which digest the registry holds at a reference,
// asked the way dest writes to it. found is false, with a nil error, when the
// registry has no such tag.
type registryDigester func(ctx context.Context, ref name.Tag, dest pushDest) (digest string, found bool, err error)

// migrationWriter is where one migration run writes into the cluster
// registry from this Mac: the authority it dials and how it authenticates.
type migrationWriter struct {
	// authority is the host:port a registry-k3sm:6450 reference is rewritten
	// to for the upload.
	authority string
	// dest carries the credential: the builder token for a run a user started,
	// this server's own push credential for the run its daemon starts.
	dest pushDest
}

// target is where this Mac sends the cluster-registry reference flat.
func (w migrationWriter) target(flat string) (name.Tag, error) {
	t, err := name.NewTag(flat)
	if err != nil {
		return name.Tag{}, fmt.Errorf("parse %s: %w", flat, err)
	}
	out, err := name.NewTag(w.authority + "/" + t.RepositoryStr() + ":" + t.TagStr())
	if err != nil {
		return name.Tag{}, fmt.Errorf("%s at %s: %w", flat, w.authority, err)
	}
	return out, nil
}

// migrationRoute resolves the writer once per run, and only for a run that
// has an image to ask the registry about.
type migrationRoute func(ctx context.Context) (migrationWriter, error)

// upstreamServes reports whether the registry ref names serves digest there.
// It answers false on any failure to ask: a reference whose registry cannot
// be reached is migrated, because a migrated cache entry costs a little space
// and a skipped user image is lost.
type upstreamServes func(ctx context.Context, ref, digest string) bool

// migrationRecord is one image's line in the journal and the report.
type migrationRecord struct {
	// Reference is the node-store reference.
	Reference string `json:"reference"`
	// Platforms are the platforms the node store holds the reference for.
	Platforms []string `json:"platforms"`
	// Sources are the node-store manifest digests, sorted. A re-run that finds
	// different ones treats the image as new.
	Sources []string `json:"sources"`
	// Outcome is one of the migration outcomes.
	Outcome string `json:"outcome"`
	// Target is the registry reference the image is recorded under, empty for
	// a cache entry and an unexportable one.
	Target string `json:"target,omitempty"`
	// Digest is the digest the registry holds at Target.
	Digest string `json:"digest,omitempty"`
	// Detail says why, for a rename, a cache entry and an unexportable image.
	Detail string `json:"detail,omitempty"`
}

// migrationJournal is the journal file, which is also the report.
type migrationJournal struct {
	Schema   int    `json:"schema"`
	Started  string `json:"started,omitempty"`
	Finished string `json:"finished,omitempty"`
	// Complete is set when a run reached every node-store entry. Only the
	// on-upgrade trigger reads it; `k3sm image migrate` always re-checks.
	Complete bool `json:"complete"`
	// LastError is why the last run stopped short, empty after a run that
	// reached every entry. `k3sm image migrate --report` shows it.
	LastError string `json:"lastError,omitempty"`
	// PendingReason is LastError said without naming any image, for the
	// world-readable summary `k3sm status` reads. It is set and cleared with
	// LastError.
	PendingReason string            `json:"pendingReason,omitempty"`
	Images        []migrationRecord `json:"images"`
}

// migrationSummary counts a journal's outcomes, for the report line.
type migrationSummary struct {
	Migrated, Present, Renamed, Cached, Unexportable int
}

func (j migrationJournal) summary() migrationSummary {
	var s migrationSummary
	for _, r := range j.Images {
		switch r.Outcome {
		case migrationMigrated:
			s.Migrated++
		case migrationPresent:
			s.Present++
		case migrationRenamed:
			s.Renamed++
		case migrationCached:
			s.Cached++
		case migrationUnexportable:
			s.Unexportable++
		}
	}
	return s
}

// record returns the journal's record for reference, if any.
func (j *migrationJournal) record(reference string) (migrationRecord, bool) {
	for _, r := range j.Images {
		if r.Reference == reference {
			return r, true
		}
	}
	return migrationRecord{}, false
}

// put replaces or adds the record for r.Reference, keeping the list sorted.
func (j *migrationJournal) put(r migrationRecord) {
	for i := range j.Images {
		if j.Images[i].Reference == r.Reference {
			j.Images[i] = r
			return
		}
	}
	j.Images = append(j.Images, r)
	sort.Slice(j.Images, func(a, b int) bool { return j.Images[a].Reference < j.Images[b].Reference })
}

// migrationDir is where the journal lives: beside, not inside, the registry's
// own state, so resetting the registry does not forget what was migrated.
func migrationDir(workDir string) string { return filepath.Join(workDir, "image-migration") }

// migrationJournalPath is the journal file.
func migrationJournalPath(workDir string) string {
	return filepath.Join(migrationDir(workDir), "journal.json")
}

// readMigrationJournal reads the journal. A missing journal is an empty one;
// an unreadable or unknown-schema one is an error.
func readMigrationJournal(workDir string) (migrationJournal, error) {
	b, err := os.ReadFile(migrationJournalPath(workDir))
	if errors.Is(err, fs.ErrNotExist) {
		return migrationJournal{Schema: migrationSchema}, nil
	}
	if err != nil {
		return migrationJournal{}, fmt.Errorf("read the image migration journal: %w", err)
	}
	var j migrationJournal
	if err := json.Unmarshal(b, &j); err != nil {
		return migrationJournal{}, fmt.Errorf("parse the image migration journal %s: %w", migrationJournalPath(workDir), err)
	}
	if j.Schema != migrationSchema {
		return migrationJournal{}, fmt.Errorf("the image migration journal %s has schema %d; this binary reads %d", migrationJournalPath(workDir), j.Schema, migrationSchema)
	}
	return j, nil
}

// writeMigrationJournal replaces the journal atomically, so a crash leaves
// the previous journal or the new one, never half of either.
func writeMigrationJournal(workDir string, j migrationJournal) error {
	if err := os.MkdirAll(migrationDir(workDir), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", migrationDir(workDir), err)
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the image migration journal: %w", err)
	}
	if err := atomicfile.Replace(migrationJournalPath(workDir), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write the image migration journal: %w", err)
	}
	return publishMigrationSummary(workDir, j)
}

// migrationSummaryOf is the journal's world-readable summary: its state, its
// counts and its pending reason, never an image name.
func migrationSummaryOf(j migrationJournal) status.ImageMigrationSummary {
	s := j.summary()
	out := status.ImageMigrationSummary{
		Schema:       status.ImageMigrationSummarySchema,
		State:        status.ImageMigrationPending,
		InRegistry:   s.Migrated + s.Present + s.Renamed,
		CacheEntries: s.Cached,
		Held:         s.Unexportable,
	}
	if j.Complete {
		out.State = status.ImageMigrationComplete
	}
	if j.LastError != "" {
		out.LastError = j.PendingReason
		if out.LastError == "" {
			out.LastError = "the last run stopped short; sudo k3sm image migrate --report says why"
		}
	}
	return out
}

// publishMigrationSummary writes the journal's summary, 0644, into the status
// directory beside workDir, where the server publishes every record `k3sm
// status` reads (as registrysvc.WriteState publishes the registry's state),
// so an account that cannot read the 0600 journal still sees the copy's
// progress. A Mac with no status directory (a hand-run server, a test) gets
// the journal only.
func publishMigrationSummary(workDir string, j migrationJournal) error {
	path := status.ImageMigrationSummaryPath(workDir)
	if _, err := os.Stat(filepath.Dir(path)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	b, err := json.Marshal(migrationSummaryOf(j))
	if err != nil {
		return fmt.Errorf("encode the image migration summary: %w", err)
	}
	if err := atomicfile.Replace(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("publish the image migration summary: %w", err)
	}
	return nil
}

// imageMigrator runs the migration. Every collaborator is a seam.
type imageMigrator struct {
	workDir  string
	source   migrationSource
	route    migrationRoute
	digestAt registryDigester
	push     imagePusher
	upstream upstreamServes
	// isLocal reports whether a reference already names the cluster registry,
	// so its upstream is the registry being migrated into.
	isLocal func(reference string) bool
	now     func() time.Time
}

// run migrates every user image and returns the journal it left. A failure to
// reach the node store or the registry stops the run with the journal written
// up to that image, so the next run resumes there.
func (m imageMigrator) run(ctx context.Context) (migrationJournal, error) {
	j, err := readMigrationJournal(m.workDir)
	if err != nil {
		return migrationJournal{}, err
	}
	j.Schema = migrationSchema
	j.Complete = false
	j.Started = m.now().UTC().Format(time.RFC3339)
	j.Finished = ""

	// stop records why the run stopped short and leaves the journal pending,
	// so the next run resumes and `k3sm status` can say why.
	stop := func(err error) (migrationJournal, error) {
		j.LastError = err.Error()
		j.PendingReason = pendingReason(err)
		if werr := writeMigrationJournal(m.workDir, j); werr != nil {
			return j, errors.Join(err, werr)
		}
		return j, err
	}
	entries, err := m.source.List(ctx)
	if err != nil {
		return stop(&migrationStop{public: "this node's image store could not be listed",
			err: fmt.Errorf("list this node's image store: %w", err)})
	}
	groups := groupStoreImages(entries)
	var w migrationWriter
	if len(groups) > 0 {
		if w, err = m.route(ctx); err != nil {
			return stop(&migrationStop{public: "the cluster registry cannot be reached from this Mac: " + err.Error(),
				err: fmt.Errorf("reach the cluster registry: %w", err)})
		}
	}
	for _, group := range groups {
		rec, err := m.migrate(ctx, &j, group, w)
		if err != nil {
			return stop(imageStepStop(err))
		}
		j.put(rec)
		if err := writeMigrationJournal(m.workDir, j); err != nil {
			return j, err
		}
	}
	j.Complete = true
	j.LastError = ""
	j.PendingReason = ""
	j.Finished = m.now().UTC().Format(time.RFC3339)
	return j, writeMigrationJournal(m.workDir, j)
}

// recordMigrationFailure notes in the journal why a run could not start, so
// `k3sm status` shows a pending migration with its reason. The caller holds
// the migration lock. A journal that cannot be read is left alone.
func recordMigrationFailure(workDir string, cause error) error {
	j, err := readMigrationJournal(workDir)
	if err != nil {
		return err
	}
	j.Schema = migrationSchema
	j.Complete = false
	j.LastError = cause.Error()
	j.PendingReason = pendingReason(cause)
	return writeMigrationJournal(workDir, j)
}

// migrationStop is why a run stopped short, with the same reason said without
// naming any image, for the world-readable summary.
type migrationStop struct {
	public string
	err    error
}

func (e *migrationStop) Error() string { return e.err.Error() }

func (e *migrationStop) Unwrap() error { return e.err }

// imageStepStop is the stop of a run whose registry question or upload of one
// image failed. The full error names the image; the public reason names only
// the kind of failure.
func imageStepStop(err error) error {
	public := "an image could not be copied into the cluster registry"
	switch {
	case errors.Is(err, errPushAuth):
		public += ": the registry refused the credential"
	case errors.Is(err, errPushNetwork):
		public += ": the registry could not be reached"
	}
	return &migrationStop{public: public + "; sudo k3sm image migrate --report names it", err: err}
}

// pendingReason is the public form of why a run stopped: a migrationStop's
// own, else the error itself, which the callers that pass one (the start-up
// run's "the runtime is not reachable") never let name an image.
func pendingReason(err error) string {
	var stop *migrationStop
	if errors.As(err, &stop) {
		return stop.public
	}
	return err.Error()
}

// groupStoreImages groups the node store's entries by reference, sorted, so
// the platforms of one multi-platform reference migrate as one index and the
// run's order is the same every time.
func groupStoreImages(entries []storeEntry) [][]storeEntry {
	by := make(map[string][]storeEntry)
	for _, e := range entries {
		by[e.Reference] = append(by[e.Reference], e)
	}
	refs := make([]string, 0, len(by))
	for r := range by {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	out := make([][]storeEntry, 0, len(refs))
	for _, r := range refs {
		g := by[r]
		sort.Slice(g, func(a, b int) bool { return g[a].Platform < g[b].Platform })
		out = append(out, g)
	}
	return out
}

// sourcesOf is a group's sorted manifest digests: the identity of what the
// node store holds for the reference.
func sourcesOf(group []storeEntry) []string {
	s := make([]string, 0, len(group))
	for _, e := range group {
		s = append(s, e.Digest)
	}
	sort.Strings(s)
	return s
}

// migrate decides and carries out one reference.
func (m imageMigrator) migrate(ctx context.Context, j *migrationJournal, group []storeEntry, w migrationWriter) (migrationRecord, error) {
	ref := group[0].Reference
	rec := migrationRecord{Reference: ref, Sources: sourcesOf(group)}
	for _, e := range group {
		rec.Platforms = append(rec.Platforms, e.Platform)
	}

	// Resume: an image the journal already finished is skipped, after asking
	// the registry it still holds the digest, without exporting anything.
	if prev, ok := j.record(ref); ok && migrationDone(prev.Outcome) && slices.Equal(prev.Sources, rec.Sources) {
		if !migrationInRegistry(prev.Outcome) {
			return prev, nil
		}
		target, err := w.target(prev.Target)
		if err != nil {
			return rec, err
		}
		got, found, err := m.digestAt(ctx, target, w.dest)
		if err != nil {
			return rec, fmt.Errorf("ask the cluster registry for %s: %w", prev.Target, err)
		}
		if found && got == prev.Digest {
			return prev, nil
		}
	}

	if !m.isLocal(ref) && m.isCached(ctx, group) {
		rec.Outcome = migrationCached
		rec.Detail = "its registry serves this digest; it stays a pull cache entry"
		return rec, nil
	}

	flat, err := migrationTarget(ref)
	if err != nil {
		rec.Outcome = migrationUnexportable
		rec.Detail = fmt.Sprintf("it stays held in this node's store: it has no registry name: %v", err)
		return rec, nil
	}
	b, cleanup, err := m.export(ctx, group)
	if err != nil {
		rec.Outcome = migrationUnexportable
		rec.Detail = fmt.Sprintf("it stays held in this node's store until it is loaded again: %v", err)
		return rec, nil
	}
	defer cleanup()
	h, err := b.digest()
	if err != nil {
		return rec, fmt.Errorf("compute the digest of %s: %w", ref, err)
	}
	digest := h.String()
	rec.Digest = digest

	target, err := w.target(flat.String())
	if err != nil {
		return rec, err
	}
	held, found, err := m.digestAt(ctx, target, w.dest)
	if err != nil {
		return rec, fmt.Errorf("ask the cluster registry for %s: %w", flat, err)
	}
	rec.Outcome = migrationMigrated
	switch {
	case found && held == digest:
		rec.Outcome = migrationPresent
		rec.Target = flat.String()
		return rec, nil
	case found:
		renamed, err := name.NewTag(flat.Context().String() + ":" + renamedTag(flat.TagStr(), h))
		if err != nil {
			return rec, fmt.Errorf("name the migrated copy of %s: %w", ref, err)
		}
		rec.Outcome = migrationRenamed
		rec.Detail = fmt.Sprintf("%s holds %s in the registry", flat, held)
		flat = renamed
		if target, err = w.target(flat.String()); err != nil {
			return rec, err
		}
		if held, found, err = m.digestAt(ctx, target, w.dest); err != nil {
			return rec, fmt.Errorf("ask the cluster registry for %s: %w", flat, err)
		}
	}
	rec.Target = flat.String()
	if found && held == digest {
		return rec, nil
	}
	if err := m.push(ctx, target, b, w.dest); err != nil {
		return rec, fmt.Errorf("migrate %s to the cluster registry as %s: %w", ref, flat, err)
	}
	return rec, nil
}

// isCached reports whether every entry of the group is served, at its digest,
// by the registry its reference names. A multi-platform reference is compared
// by its index digest.
func (m imageMigrator) isCached(ctx context.Context, group []storeEntry) bool {
	for _, e := range group {
		want := e.Digest
		if e.IndexDigest != "" {
			want = e.IndexDigest
		}
		if !m.upstream(ctx, e.Reference, want) {
			return false
		}
	}
	return true
}

// export reads a group back out of the node store: a single entry as its
// image, several platforms as one index of them.
func (m imageMigrator) export(ctx context.Context, group []storeEntry) (built, func(), error) {
	var cleanups []func()
	cleanup := func() {
		for _, c := range cleanups {
			c()
		}
	}
	var adds []mutate.IndexAddendum
	var first ggcrv1.Image
	for _, e := range group {
		img, c, err := m.source.Export(ctx, e)
		if err != nil {
			cleanup()
			return built{}, nil, fmt.Errorf("export %s (%s): %w", e.Reference, e.Platform, err)
		}
		cleanups = append(cleanups, c)
		got, err := img.Digest()
		if err != nil {
			cleanup()
			return built{}, nil, fmt.Errorf("digest the export of %s: %w", e.Reference, err)
		}
		if got.String() != e.Digest {
			cleanup()
			return built{}, nil, fmt.Errorf("the export of %s is %s, not the store's %s", e.Reference, got, e.Digest)
		}
		if first == nil {
			first = img
		}
		if len(group) == 1 {
			break
		}
		p, err := ggcrv1.ParsePlatform(e.Platform)
		if err != nil {
			cleanup()
			return built{}, nil, fmt.Errorf("platform %q of %s: %w", e.Platform, e.Reference, err)
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: ggcrv1.Descriptor{Platform: p}})
	}
	if len(group) == 1 {
		return built{image: first}, cleanup, nil
	}
	return built{image: first, index: mutate.AppendManifests(empty.Index, adds...)}, cleanup, nil
}

// renamedTag is the tag a migrated image takes when its own tag is held at
// another digest: <tag>-k3sm-migrated-<first 12 hex of its digest>, cut so
// the whole stays within the 128-character tag limit.
func renamedTag(tag string, h ggcrv1.Hash) string {
	suffix := migratedTagInfix + h.Hex[:12]
	if max := 128 - len(suffix); len(tag) > max {
		tag = tag[:max]
	}
	return tag + suffix
}

// migrationTarget is the cluster-registry reference a node-store reference
// migrates to: registry-k3sm:6450/<repository>:<tag>.
//
// A Docker Hub official-image spelling (docker.io/library/app) loses its
// library/ element, because the node store recorded `k3sm build -t app:dev`
// under that spelling and the operator wrote app. A digest-only reference has
// no tag to keep and takes k3sm-migrated-<12hex>.
func migrationTarget(reference string) (name.Tag, error) {
	// Parsed the way the node store validated it when it was recorded, so
	// every recorded reference parses here too.
	ref, err := name.ParseReference(reference)
	if err != nil {
		return name.Tag{}, fmt.Errorf("reference %q: %w", reference, err)
	}
	repo := ref.Context().RepositoryStr()
	if ref.Context().RegistryStr() == name.DefaultRegistry {
		if rest, ok := strings.CutPrefix(repo, "library/"); ok && !strings.Contains(rest, "/") {
			repo = rest
		}
	}
	tag := ""
	switch r := ref.(type) {
	case name.Tag:
		tag = r.TagStr()
	case name.Digest:
		h, err := ggcrv1.NewHash(r.DigestStr())
		if err != nil {
			return name.Tag{}, fmt.Errorf("reference %q: %w", reference, err)
		}
		tag = strings.TrimPrefix(migratedTagInfix, "-") + h.Hex[:12]
	}
	t, err := name.NewTag(flatRegistryHost + "/" + repo + ":" + tag)
	if err != nil {
		return name.Tag{}, fmt.Errorf("name %q in the cluster registry: %w", reference, err)
	}
	return t, nil
}

// renderMigrationReport writes the human report of a journal.
func renderMigrationReport(out io.Writer, j migrationJournal) {
	for _, r := range j.Images {
		switch r.Outcome {
		case migrationMigrated, migrationPresent:
			fmt.Fprintf(out, "%-12s %s -> %s\n", r.Outcome, r.Reference, r.Target)
		case migrationRenamed:
			fmt.Fprintf(out, "%-12s %s -> %s (%s)\n", r.Outcome, r.Reference, r.Target, r.Detail)
		default:
			fmt.Fprintf(out, "%-12s %s (%s)\n", r.Outcome, r.Reference, r.Detail)
		}
	}
	fmt.Fprintln(out, migrationSummaryLine(j))
}

// migrationSummaryLine is the one-line summary the report ends with.
func migrationSummaryLine(j migrationJournal) string {
	s := j.summary()
	state := "incomplete, re-run k3sm image migrate"
	if j.Complete {
		state = "complete"
	}
	return fmt.Sprintf("image migration %s: %d migrated, %d already present, %d renamed, %d cache entries left, %d held (unexportable)",
		state, s.Migrated, s.Present, s.Renamed, s.Cached, s.Unexportable)
}
