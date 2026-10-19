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

package updatectl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"
)

// The release pin is a server-local record of the archive digest a release
// must have, written by root (`k3sm update apply --pin-sha256`) before it
// creates the Update. It binds a roll to bytes vouched for outside the
// release host: the controller refuses a release whose checksums file
// disagrees with the pin before any node is touched, and on a match the
// pinned digest is what the cluster CA signs into every node's payload.
//
// The pin lives at <server work dir>/update/release-pin, a root-owned 0644
// file in a root-owned 0755 directory. Only root can write it; the server
// reads it. A pin can only constrain a roll, never loosen one: it is
// consulted only for its own version, and a pin the controller cannot trust
// (a wrong owner, a group- or world-writable file or directory, a symlink, a
// malformed record) refuses the roll rather than being skipped.
const (
	// releasePinDirName is the directory under the server work dir.
	releasePinDirName = "update"
	// releasePinFileName is the pin file in that directory.
	releasePinFileName = "release-pin"
	// maxReleasePinBytes bounds the pin read; a record is under 200 bytes.
	maxReleasePinBytes = 4096
)

// ReleasePinRequiredAnnotation, on an Update, names the release tag root
// pinned when it created the Update (`k3sm update apply --pin-sha256`). The
// controller then refuses to resolve the Update unless a trusted pin for
// exactly that tag matched, so a pin that is missing by the time the
// controller resolves fails the roll instead of letting it run unpinned.
// No RBAC rule k3sm ships names updates.k3sm.io, so only a cluster-admin
// identity can write an Update; removing this annotation therefore needs an
// identity that can already change spec.version, and the requirement adds no
// weaker way around the pin. pkg/rbac's TestNoProvisionedRuleGrantsUpdates
// fails if a provisioned rule ever grants the group.
const ReleasePinRequiredAnnotation = "k3sm.io/release-pin-required"

// The condition reasons the release pin adds.
const (
	// ReasonReleasePinMismatch is the Failed (and Resolved) condition reason
	// when the release disagrees with the release pin, or the pin cannot be
	// trusted.
	ReasonReleasePinMismatch = "ReleasePinMismatch"
	// ReasonResolvedPinned is the Resolved condition reason when the release
	// matched the release pin for its version.
	ReasonResolvedPinned = "ResolvedPinned"
)

// ErrReleasePinMismatch marks a release the release pin refuses: its
// checksums file has no entry for the archive, its digest differs from the
// pin, or the pin itself cannot be trusted. Every such error also wraps
// ErrRelease, so the roll fails definitively instead of retrying.
var ErrReleasePinMismatch = errors.New("the release does not match the release pin")

// pinError is a definitive failure carrying ErrReleasePinMismatch.
func pinError(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrRelease, ErrReleasePinMismatch, fmt.Sprintf(format, args...))
}

// ReleasePin is the pin record, stored as JSON.
type ReleasePin struct {
	// Version is the release tag the pin binds, exactly as the Update names it.
	Version string `json:"version"`
	// SHA256 is the darwin/arm64 archive's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// At is when the pin was written.
	At time.Time `json:"at"`
}

// Validate refuses a record with an unusable tag or a digest that is not 64
// lowercase hex digits.
func (p ReleasePin) Validate() error {
	if !validTag(p.Version) {
		return fmt.Errorf("the pinned version %q is not a release tag", p.Version)
	}
	if !isSHA256Hex(p.SHA256) {
		return errors.New("the pinned sha256 is not 64 lowercase hex digits")
	}
	return nil
}

// ReleasePinDir is the directory holding the release pin under workDir.
func ReleasePinDir(workDir string) string { return filepath.Join(workDir, releasePinDirName) }

// ReleasePinPath is the release pin file under workDir.
func ReleasePinPath(workDir string) string {
	return filepath.Join(ReleasePinDir(workDir), releasePinFileName)
}

// PinnedResolver wraps a Resolver with the release pin under WorkDir. With no
// pin, or a pin for another version (logged), it is Resolver. With a pin for
// exactly the tag being resolved, the release's checksums digest must equal
// the pin: a match is returned with Pinned set; a mismatch, a checksums file
// with no entry for the archive, or any other definitive resolve failure is
// ErrReleasePinMismatch. A pin it cannot trust refuses every resolve until
// root fixes or removes it (`k3sm update apply --clear-pin`). A transient
// resolve error passes through, to be retried.
type PinnedResolver struct {
	// Resolver reads the release index. Required.
	Resolver Resolver
	// WorkDir is the server work dir the pin lives under. Required.
	WorkDir string
	// Log is the structured logger. nil means slog.Default().
	Log *slog.Logger
	// owner is the uid the pin and its directory must be owned by. The zero
	// value is root, the only owner outside tests.
	owner uint32
}

// AssetURL implements Resolver.
func (r PinnedResolver) AssetURL(tag string) (string, error) { return r.Resolver.AssetURL(tag) }

// Resolve implements Resolver.
func (r PinnedResolver) Resolve(ctx context.Context, tag string) (Release, error) {
	if r.Resolver == nil || r.WorkDir == "" {
		return Release{}, pinError("the pinned resolver has no resolver or work dir")
	}
	pin, err := readReleasePin(r.WorkDir, r.owner)
	if err != nil {
		return Release{}, pinError("the release pin cannot be trusted: %v", err)
	}
	if pin == nil {
		return r.Resolver.Resolve(ctx, tag)
	}
	if pin.Version != tag {
		r.log().Info("update controller: ignoring the release pin for another version",
			"pinned", pin.Version, "target", tag, "path", ReleasePinPath(r.WorkDir))
		return r.Resolver.Resolve(ctx, tag)
	}
	rel, err := r.Resolver.Resolve(ctx, tag)
	if err != nil {
		if errors.Is(err, ErrRelease) {
			return Release{}, pinError("%s is pinned to sha256:%s, and the release did not resolve: %v", tag, pin.SHA256, err)
		}
		return Release{}, err
	}
	if rel.SHA256 != pin.SHA256 {
		return Release{}, pinError("%s is pinned to sha256:%s, the release's checksums file says sha256:%s", tag, pin.SHA256, rel.SHA256)
	}
	rel.Pinned = true
	return rel, nil
}

func (r PinnedResolver) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}
