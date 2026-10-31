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

package layout

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultRoot is the production root of the versioned tree.
const DefaultRoot = "/Library/k3sm"

// Names inside the root. They are relative names, joined to a Layout's root.
const (
	// VersionsName is the directory holding one subdirectory per release.
	VersionsName = "versions"
	// CurrentName is the symlink to the active version.
	CurrentName = "current"
	// PreviousName is the symlink to the rollback version.
	PreviousName = "previous"
	// UpdaterName is the directory holding the updater's own pointers.
	UpdaterName = "updater"
	// UpdaterStateName is the root-only directory of the updater's state.
	UpdaterStateName = "updater-state"
	// UpdaterWorkName is the root-only directory archives are staged in.
	UpdaterWorkName = "updater-work"
	// RunName is the directory holding the updater's socket.
	RunName = "run"
	// SocketName is the updater's socket inside RunName.
	SocketName = "updater.sock"
	// TrustName is the directory holding the trust copy.
	TrustName = "trust"
	// ClusterCAName is the cluster CA certificate inside TrustName.
	ClusterCAName = "cluster-ca.crt"
	// StatusName is the directory holding the user-readable status.
	StatusName = "status"
	// UpdateStatusName is the update status file inside StatusName.
	UpdateStatusName = "update.json"
	// UpdaterBinary is the updater's executable name inside a version.
	UpdaterBinary = "k3sm-updater"
	// K3smBinary is the k3sm executable name inside a version.
	K3smBinary = "k3sm"
	// TempSuffix names the temporary symlink a flip creates before renaming it.
	TempSuffix = ".tmp"
)

// Launchd labels of the updater's own jobs. The node jobs' labels live in
// pkg/install/order.
const (
	// UpdaterLabel is the resident root updater LaunchDaemon.
	UpdaterLabel = "io.k3sm.updater"
	// GuardLabel is the periodic job that reverts a failed updater take-over.
	GuardLabel = "io.k3sm.updater-guard"
)

var (
	// ErrBadVersion reports a version directory name that is not a release
	// version or a migrated unknown version.
	ErrBadVersion = errors.New("not a valid version directory name")
	// ErrBadLink reports a layout symlink whose target is not a version
	// directory in the expected relative form.
	ErrBadLink = errors.New("layout symlink does not point at a version directory")
	// ErrNoChange reports a flip to the version that is already current.
	ErrNoChange = errors.New("the version is already current")
	// ErrRequiresInstaller reports a release that declares it needs the
	// installer (a plist or hard-limit change), which the updater refuses.
	ErrRequiresInstaller = errors.New("the release requires the installer; run sudo k3sm install")
	// ErrNotRootOwned reports a directory, or one of its ancestors, not owned
	// by root.
	ErrNotRootOwned = errors.New("not owned by root")
	// ErrWritableByOthers reports a directory, or one of its ancestors,
	// writable by its group or by other users.
	ErrWritableByOthers = errors.New("writable by group or other")
	// ErrNotDirectory reports a path component that is not a real directory,
	// a symlink included.
	ErrNotDirectory = errors.New("not a directory")
	// ErrBadName reports a binary name or launchd label that is not a plain,
	// well-formed name.
	ErrBadName = errors.New("not a valid name")
)

// Layout is the versioned tree under one root. The zero value is not usable;
// build one with New.
type Layout struct {
	root string
}

// New returns the layout rooted at root, cleaned. Production passes
// DefaultRoot; tests pass a temporary directory.
func New(root string) Layout { return Layout{root: filepath.Clean(root)} }

// Root returns the layout's root directory.
func (l Layout) Root() string { return l.root }

// VersionsDir returns the directory holding every version.
func (l Layout) VersionsDir() string { return filepath.Join(l.root, VersionsName) }

// VersionDir returns the directory of version ver, after validating the name.
func (l Layout) VersionDir(ver string) (string, error) {
	if err := ValidateVersion(ver); err != nil {
		return "", err
	}
	return filepath.Join(l.root, VersionsName, ver), nil
}

// Current returns the path of the current symlink.
func (l Layout) Current() string { return filepath.Join(l.root, CurrentName) }

// Previous returns the path of the previous symlink.
func (l Layout) Previous() string { return filepath.Join(l.root, PreviousName) }

// Binary returns the path a launchd job runs bin from: through current, never
// a version directory, so a flip changes what runs without touching a plist.
func (l Layout) Binary(bin string) (string, error) {
	if err := validBinary(bin); err != nil {
		return "", err
	}
	return filepath.Join(l.root, CurrentName, bin), nil
}

// CompatLink returns the flat compatibility path of bin (root/<bin>), the
// symlink to current/<bin> kept for the shell, the app and the docs.
func (l Layout) CompatLink(bin string) (string, error) {
	if err := validBinary(bin); err != nil {
		return "", err
	}
	return filepath.Join(l.root, bin), nil
}

// UpdaterDir returns the directory of the updater's own pointers.
func (l Layout) UpdaterDir() string { return filepath.Join(l.root, UpdaterName) }

// UpdaterCurrent returns the path of the updater's own current symlink, which
// points at a version directory independently of current.
func (l Layout) UpdaterCurrent() string { return filepath.Join(l.root, UpdaterName, CurrentName) }

// UpdaterCurrentBinary returns the updater executable the updater job runs.
func (l Layout) UpdaterCurrentBinary() string {
	return filepath.Join(l.UpdaterCurrent(), UpdaterBinary)
}

// UpdaterGuard returns the directory of the pinned known-good updater copy the
// guard job runs.
func (l Layout) UpdaterGuard() string { return filepath.Join(l.root, UpdaterName, "guard") }

// UpdaterGuardBinary returns the updater executable the guard job runs.
func (l Layout) UpdaterGuardBinary() string { return filepath.Join(l.UpdaterGuard(), UpdaterBinary) }

// StateDir returns the root-only directory of the updater's state.
func (l Layout) StateDir() string { return filepath.Join(l.root, UpdaterStateName) }

// WorkDir returns the root-only directory archives are staged in.
func (l Layout) WorkDir() string { return filepath.Join(l.root, UpdaterWorkName) }

// RunDir returns the directory holding the updater's socket.
func (l Layout) RunDir() string { return filepath.Join(l.root, RunName) }

// Socket returns the path of the updater's socket.
func (l Layout) Socket() string { return filepath.Join(l.root, RunName, SocketName) }

// TrustCA returns the path of the cluster CA copy the updater trusts.
func (l Layout) TrustCA() string { return filepath.Join(l.root, TrustName, ClusterCAName) }

// StatusFile returns the path of the user-readable update status.
func (l Layout) StatusFile() string { return filepath.Join(l.root, StatusName, UpdateStatusName) }

// releaseVersion is MAJOR.MINOR.PATCH with an optional leading v, an optional
// pre-release and optional build metadata: the release versions the installer
// accepts.
var releaseVersion = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// unknownVersion is the name the flat-layout migration gives a set whose
// version does not parse: unknown- and a 12-character sha256 prefix.
var unknownVersion = regexp.MustCompile(`^unknown-[0-9a-f]{12}$`)

// maxVersionLen bounds a version directory name.
const maxVersionLen = 128

// ValidateVersion reports whether name may be a version directory: a release
// version or an unknown-<sha256 prefix> name the migration made. Anything else,
// a path separator, a dot entry or a temporary name included, is ErrBadVersion.
func ValidateVersion(name string) error {
	if len(name) == 0 || len(name) > maxVersionLen || !(releaseVersion.MatchString(name) || unknownVersion.MatchString(name)) {
		return fmt.Errorf("%w: %q", ErrBadVersion, name)
	}
	return nil
}

// IsUnknownVersion reports whether name is a migrated unknown version, which
// is never a downgrade target.
func IsUnknownVersion(name string) bool { return unknownVersion.MatchString(name) }

// CheckActivatable refuses a release whose manifest declares requiresInstaller:
// plists never change in an update, so a release that needs a different plist
// or hard limit is the installer's to apply. It also validates the version.
func CheckActivatable(ver string, requiresInstaller bool) error {
	if err := ValidateVersion(ver); err != nil {
		return err
	}
	if requiresInstaller {
		return fmt.Errorf("version %s: %w", ver, ErrRequiresInstaller)
	}
	return nil
}

// Readlink reads a symlink's target, as os.Readlink does. It is the seam the
// resolution functions read the tree through.
type Readlink func(name string) (string, error)

// ResolveActive returns the version current points at. The link must read
// exactly versions/<ver> with a valid ver; anything else, an absolute target
// included, is ErrBadLink.
func (l Layout) ResolveActive(readlink Readlink) (string, error) {
	return resolve(readlink, l.Current(), VersionsName)
}

// ResolvePrevious returns the version previous points at, on the same terms as
// ResolveActive.
func (l Layout) ResolvePrevious(readlink Readlink) (string, error) {
	return resolve(readlink, l.Previous(), VersionsName)
}

// ResolveUpdater returns the version the updater's own current points at. Its
// link sits one level down, so it must read ../versions/<ver>.
func (l Layout) ResolveUpdater(readlink Readlink) (string, error) {
	return resolve(readlink, l.UpdaterCurrent(), filepath.Join("..", VersionsName))
}

// resolve reads link and returns the version it names, requiring the target
// to be exactly dir/<ver>.
func resolve(readlink Readlink, link, dir string) (string, error) {
	target, err := readlink(link)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", link, err)
	}
	ver, ok := strings.CutPrefix(target, dir+"/")
	if !ok || ValidateVersion(ver) != nil {
		return "", fmt.Errorf("%s -> %q: %w", link, target, ErrBadLink)
	}
	return ver, nil
}

// validBinary refuses a binary name that is not one plain path element.
func validBinary(bin string) error {
	if bin == "" || bin == "." || bin == ".." || strings.ContainsAny(bin, "/\x00") || bin != filepath.Base(bin) {
		return fmt.Errorf("binary %q: %w", bin, ErrBadName)
	}
	return nil
}
