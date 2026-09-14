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

package datavol

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// systemKeychain is the keychain an encrypted data volume's passphrase lives
// in: the System keychain, so a boot-time root daemon can read it with no user
// session.
const systemKeychain = "/Library/Keychains/System.keychain"

// keychainAccount is the account every k3sm keychain item is filed under; the
// service is the volume UUID. Every lookup and delete names it too, so they
// select exactly the item Store wrote rather than whatever else in the System
// keychain happens to share the service.
const keychainAccount = "k3sm"

// keychainLabel is what the item shows as in Keychain Access.
const keychainLabel = "k3sm data volume"

// spotlightMarkerName is the file whose presence at the root of a volume tells
// Spotlight never to index it.
const spotlightMarkerName = ".metadata_never_index"

// timeMachineExcludeAttr and timeMachineExcludeValue are the extended
// attribute Time Machine reads to skip a path, and the value tmutil writes.
const (
	timeMachineExcludeAttr  = "com.apple.metadata:com_apple_backup_excludeItem"
	timeMachineExcludeValue = "com.apple.backupd"
)

// Darwin is the production implementation of all three seams: it runs the real
// diskutil, security, mdutil and tmutil. Its zero value is usable.
//
// Every method assumes the caller is already root -- the installer and the
// io.k3sm.datavol daemon both are -- so nothing here ever invokes sudo.
type Darwin struct{}

// NewDarwin returns Deps wired to the real macOS tools.
func NewDarwin() Deps { return Deps{Volumes: Darwin{}, Keychain: Darwin{}, Indexing: Darwin{}} }

// Info implements Volumes.
func (Darwin) Info(ctx context.Context, target string) (Info, error) {
	out, err := run(ctx, "", "diskutil", "info", "-plist", target)
	if err != nil {
		return Info{}, fmt.Errorf("diskutil info %s: %w", target, err)
	}
	info, err := parseInfoPlist([]byte(out))
	if err != nil {
		return Info{}, fmt.Errorf("diskutil info %s: %w", target, err)
	}
	return info, nil
}

// Capacity implements Volumes.
func (Darwin) Capacity(ctx context.Context, container, uuid string) (Capacity, error) {
	out, err := run(ctx, "", "diskutil", "apfs", "list", "-plist", container)
	if err != nil {
		return Capacity{}, fmt.Errorf("diskutil apfs list %s: %w", container, err)
	}
	c, err := parseCapacityPlist([]byte(out), container, uuid)
	if err != nil {
		return Capacity{}, fmt.Errorf("diskutil apfs list %s: %w", container, err)
	}
	return c, nil
}

// AddVolume implements Volumes.
//
// APFSX is the case-sensitive personality; -nomount leaves the new volume for
// MountRecorded to mount with MountOptions, rather than letting diskutil put it
// under /Volumes first. -quota is the only chance to bound the volume: no
// diskutil verb changes a quota afterwards.
func (Darwin) AddVolume(ctx context.Context, container, name string, quotaBytes uint64, passphrase string) error {
	args := []string{"apfs", "addVolume", container, "APFSX", name}
	if quotaBytes > 0 {
		args = append(args, "-quota", strconv.FormatUint(quotaBytes, 10))
	}
	args = append(args, "-nomount")
	stdin := ""
	if passphrase != "" {
		args = append(args, "-stdinpassphrase")
		stdin = passphrase + "\n"
	}
	if _, err := run(ctx, stdin, "diskutil", args...); err != nil {
		return fmt.Errorf("diskutil apfs addVolume %s %s: %w", container, name, err)
	}
	return nil
}

// Mount implements Volumes.
func (Darwin) Mount(ctx context.Context, uuid, mountpoint string) error {
	if _, err := run(ctx, "", "diskutil", "mount", "-mountOptions", MountOptions, "-mountPoint", mountpoint, uuid); err != nil {
		return fmt.Errorf("diskutil mount %s at %s: %w", uuid, mountpoint, err)
	}
	return nil
}

// Unmount implements Volumes.
func (Darwin) Unmount(ctx context.Context, target string) error {
	if _, err := run(ctx, "", "diskutil", "unmount", target); err != nil {
		return fmt.Errorf("diskutil unmount %s: %w", target, err)
	}
	return nil
}

// DeleteVolume implements Volumes.
func (Darwin) DeleteVolume(ctx context.Context, uuid string) error {
	if _, err := run(ctx, "", "diskutil", "apfs", "deleteVolume", uuid); err != nil {
		return fmt.Errorf("diskutil apfs deleteVolume %s: %w", uuid, err)
	}
	return nil
}

// Unlock implements Volumes. The volume is left unmounted so the caller mounts
// it at the data root with MountOptions rather than wherever diskutil would.
func (Darwin) Unlock(ctx context.Context, uuid, passphrase string) error {
	if _, err := run(ctx, passphrase+"\n", "diskutil", "apfs", "unlockVolume", uuid, "-stdinpassphrase", "-nomount"); err != nil {
		return fmt.Errorf("diskutil apfs unlockVolume %s: %w", uuid, err)
	}
	return nil
}

// Store implements Keychain.
func (Darwin) Store(ctx context.Context, uuid, passphrase string) error {
	cmd := strings.Join([]string{
		"add-generic-password",
		"-a", securityQuote(keychainAccount),
		"-s", securityQuote(uuid),
		"-l", securityQuote(keychainLabel),
		"-w", securityQuote(passphrase),
		securityQuote(systemKeychain),
	}, " ")
	if _, err := security(ctx, cmd); err != nil {
		return fmt.Errorf("store the data volume passphrase for %s: %w", uuid, err)
	}
	return nil
}

// Lookup implements Keychain.
func (Darwin) Lookup(ctx context.Context, uuid string) (string, error) {
	cmd := strings.Join([]string{
		"find-generic-password",
		"-a", securityQuote(keychainAccount),
		"-s", securityQuote(uuid),
		"-w", securityQuote(systemKeychain),
	}, " ")
	out, err := security(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("read the data volume passphrase for %s: %w", uuid, err)
	}
	pw := strings.TrimSpace(lastLine(out))
	if pw == "" {
		return "", fmt.Errorf("read the data volume passphrase for %s: the keychain item is empty", uuid)
	}
	return pw, nil
}

// Delete implements Keychain. An item that is not there is not an error: the
// delete path may be re-run after a partial failure.
func (Darwin) Delete(ctx context.Context, uuid string) error {
	cmd := strings.Join([]string{
		"delete-generic-password",
		"-a", securityQuote(keychainAccount),
		"-s", securityQuote(uuid),
		securityQuote(systemKeychain),
	}, " ")
	out, err := security(ctx, cmd)
	if err != nil {
		if strings.Contains(out, "could not be found") || strings.Contains(err.Error(), "could not be found") {
			return nil
		}
		return fmt.Errorf("delete the data volume passphrase for %s: %w", uuid, err)
	}
	return nil
}

// SpotlightOff implements Indexing.
//
// The marker file is the primary mechanism, not a belt-and-braces addition:
// Spotlight does not track a nobrowse volume at all, so `mdutil -i off` on a
// freshly mounted k3sm data volume exits 1 with "Error: unknown indexing
// state." every time, whoever runs it. (A hand-configured volume answers
// "Indexing disabled" only because it was set while browsable.) An empty
// .metadata_never_index at the root of a volume is honoured on every volume
// regardless, so it is what actually holds.
//
// mdutil still runs afterwards, because a volume that later becomes browsable
// should carry the explicit setting too. Its "unknown indexing state" is the
// expected answer described above and counts as success; any other failure is
// returned, and the caller logs it without failing the mount.
func (Darwin) SpotlightOff(ctx context.Context, mountpoint string) error {
	marker := filepath.Join(mountpoint, spotlightMarkerName)
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", marker, err)
	}
	if _, err := run(ctx, "", "mdutil", "-i", "off", mountpoint); err != nil {
		if strings.Contains(err.Error(), "unknown indexing state") {
			return nil
		}
		return fmt.Errorf("mdutil -i off %s: %w", mountpoint, err)
	}
	return nil
}

// TimeMachineExclude implements Indexing.
//
// This sets the extended attribute directly rather than running tmutil:
// `tmutil addexclusion` is TCC-gated behind Full Disk Access and exits 80
// ("requires Full Disk Access privileges") even as root, so it is unusable
// from a LaunchDaemon. The xattr below is exactly what a non-`-p`
// `tmutil addexclusion` writes, and setting it makes `tmutil isexcluded`
// report [Excluded] with no TCC involvement.
func (Darwin) TimeMachineExclude(_ context.Context, mountpoint string) error {
	if err := unix.Setxattr(mountpoint, timeMachineExcludeAttr, []byte(timeMachineExcludeValue), 0); err != nil {
		return fmt.Errorf("set %s on %s: %w", timeMachineExcludeAttr, mountpoint, err)
	}
	return nil
}

// security runs one security(1) command line on STDIN under -i, so the argv of
// the process is only ["security", "-i"] and a passphrase never reaches any
// process listing or Endpoint Security exec log. It returns the command's
// stdout even on failure, because the caller distinguishes "no such item" from
// a real error by reading it.
func security(ctx context.Context, line string) (string, error) {
	return run(ctx, line+"\n", "security", "-i")
}

// securityQuote quotes one argument of a security(1) stdin command line.
// security tokenizes that line itself, honouring double quotes and backslash
// escapes, so a label with a space or a passphrase with a shell metacharacter
// must be quoted here. Nothing reaches a shell: run execs directly.
func securityQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// lastLine returns the last non-empty line of s, which is where security
// prints the password it was asked for.
func lastLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

// run executes name with args, feeding stdin to it, and returns stdout. On a
// non-zero exit the error carries the tool's stderr, which is the message an
// operator needs verbatim; stdout is returned alongside so a caller can read it
// too. Nothing is passed through a shell.
func run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg == "" {
			return out.String(), err
		}
		return out.String(), fmt.Errorf("%w: %s", err, msg)
	}
	return out.String(), nil
}
