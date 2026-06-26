package install

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// darwinSystem is the production System: it performs the privileged operations
// via the macOS tools (dscl for the service user, ditto for the root-owned copy,
// launchctl for the daemons) and os.Chown for ownership. It is exercised by the
// M2 acceptance gate (the one-time root install), NOT by unit tests — the
// standards forbid real privilege in unit tests, so install_test.go uses the
// fake instead.
type darwinSystem struct{}

// NewDarwinSystem returns the production darwin System.
func NewDarwinSystem() System { return darwinSystem{} }

// systemUIDFloor/Ceil bound the search for a free hidden service-user uid (the
// macOS daemon range below the 500 login-user floor).
const (
	systemUIDFloor = 250
	systemUIDCeil  = 400
)

// EnsureServiceUser idempotently creates name as a hidden, no-login system user
// whose home is DefaultDataRoot, and ensures that data root exists owned by it
// (so the _k3sm control plane can write its work-dir there). It returns the uid.
func (darwinSystem) EnsureServiceUser(name string) (uint32, error) {
	if u, err := user.Lookup(name); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		if err := ensureOwnedDir(DefaultDataRoot, uid); err != nil {
			return 0, err
		}
		return uint32(uid), nil
	}

	uid, err := freeSystemUID()
	if err != nil {
		return 0, err
	}
	record := "/Users/" + name
	steps := [][]string{
		{"dscl", ".", "-create", record},
		{"dscl", ".", "-create", record, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", record, "RealName", "k3sm service user"},
		{"dscl", ".", "-create", record, "UniqueID", strconv.Itoa(uid)},
		{"dscl", ".", "-create", record, "PrimaryGroupID", "20"}, // staff
		{"dscl", ".", "-create", record, "NFSHomeDirectory", DefaultDataRoot},
		{"dscl", ".", "-create", record, "IsHidden", "1"},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("create service user (%s): %w: %s", strings.Join(s, " "), err, out)
		}
	}
	if err := ensureOwnedDir(DefaultDataRoot, uid); err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

// freeSystemUID returns the first uid in [floor,ceil] not already assigned.
func freeSystemUID() (int, error) {
	for uid := systemUIDFloor; uid <= systemUIDCeil; uid++ {
		if _, err := user.LookupId(strconv.Itoa(uid)); err != nil {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no free system uid in [%d,%d]", systemUIDFloor, systemUIDCeil)
}

// ensureOwnedDir creates dir 0750 (idempotent) and chowns it to uid:staff so the
// service user owns its data root.
func ensureOwnedDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create data root %s: %w", dir, err)
	}
	if err := os.Chown(dir, uid, 20); err != nil {
		return fmt.Errorf("chown data root %s to %d: %w", dir, uid, err)
	}
	return nil
}

// CopyToRootOwned copies src into dstDir (created root:wheel 0755) using ditto
// (preserves the signature/extended attributes the notarized binary needs) and
// returns the installed path.
func (darwinSystem) CopyToRootOwned(src, dstDir string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("create install dir %s: %w", dstDir, err)
	}
	if err := os.Chown(dstDir, 0, 0); err != nil {
		return "", fmt.Errorf("chown install dir %s root:wheel: %w", dstDir, err)
	}
	dst := filepath.Join(dstDir, filepath.Base(src))
	if out, err := exec.Command("ditto", src, dst).CombinedOutput(); err != nil {
		return "", fmt.Errorf("ditto %s -> %s: %w: %s", src, dst, err, out)
	}
	if err := os.Chown(dst, 0, 0); err != nil {
		return "", fmt.Errorf("chown %s root:wheel: %w", dst, err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return "", fmt.Errorf("chmod %s 0755: %w", dst, err)
	}
	return dst, nil
}

// WriteLaunchDaemon writes the plist root:wheel 0644.
func (darwinSystem) WriteLaunchDaemon(plistPath string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return fmt.Errorf("create launchd dir: %w", err)
	}
	if err := os.WriteFile(plistPath, contents, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", plistPath, err)
	}
	if err := os.Chown(plistPath, 0, 0); err != nil {
		return fmt.Errorf("chown %s root:wheel: %w", plistPath, err)
	}
	return nil
}

// LaunchctlBootstrap loads the daemon into the system domain.
func (darwinSystem) LaunchctlBootstrap(label string) error {
	plist := filepath.Join(DefaultLaunchDaemonDir, label+".plist")
	if out, err := exec.Command("launchctl", "bootstrap", "system", plist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap %s: %w: %s", label, err, out)
	}
	return nil
}

// LaunchctlBootout unloads the daemon. A not-loaded label (exit 113/3) is treated
// as success so uninstall is idempotent.
func (darwinSystem) LaunchctlBootout(label string) error {
	out, err := exec.Command("launchctl", "bootout", "system/"+label).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Could not find") || strings.Contains(string(out), "No such process") {
			return nil
		}
		return fmt.Errorf("launchctl bootout %s: %w: %s", label, err, out)
	}
	return nil
}

// LaunchctlKickstart force-restarts the daemon.
func (darwinSystem) LaunchctlKickstart(label string) error {
	if out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+label).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w: %s", label, err, out)
	}
	return nil
}

// WriteUserKubeconfig writes contents to targetUser's ~/.kube/config, owned by
// targetUser (NOT root) so the human can kubectl without sudo.
func (darwinSystem) WriteUserKubeconfig(targetUser string, contents []byte) error {
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("lookup target user %s: %w", targetUser, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	kubeDir := filepath.Join(u.HomeDir, ".kube")
	if err := os.MkdirAll(kubeDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", kubeDir, err)
	}
	_ = os.Chown(kubeDir, uid, gid)
	path := filepath.Join(kubeDir, "config")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %s: %w", path, targetUser, err)
	}
	return nil
}

// RemoveAll removes a path tree.
func (darwinSystem) RemoveAll(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
