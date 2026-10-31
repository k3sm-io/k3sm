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

package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"k3sm.io/k3sm/internal/binsign"
)

// consoleDevice is the device whose owner is the user logged in at the screen;
// loginwindow hands it to that user at login and back to root at logout.
const consoleDevice = "/dev/console"

// maxAppCommandOutput caps what a launch-path command may write back.
const maxAppCommandOutput = 64 << 10

// appToolEnv is the environment of the read-only tools the checks run as root.
var appToolEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}

// NewAppLauncher returns the AppLauncher the CLI wires into Install, Start and
// Restart: it opens AppBundlePath hidden for the console user, after checking
// the bundle against executable, the running k3sm binary. Logger receives the
// result and every reason to skip.
func NewAppLauncher(logger *slog.Logger, executable string) AppLauncher {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return hiddenAppLauncher{host: darwinAppHost{}, executable: executable, bundle: AppBundlePath, logger: logger}
}

// darwinAppHost is the real appHost.
type darwinAppHost struct{}

// DeveloperMode reads the developer-mode marker through the installer's own
// System.
func (darwinAppHost) DeveloperMode() bool {
	return ReadDeveloperModeState(NewDarwinSystem(), DeveloperModeMarkerPath) == DeveloperModeMarkerOn
}

// ConsoleUser reads /dev/console's owner and looks the account up. A console
// owned by root (the login window, or no GUI session at all) is reported as
// uid 0, which the caller refuses; a missing device is ErrNoConsoleUser.
func (darwinAppHost) ConsoleUser() (ConsoleUser, error) {
	fi, err := os.Stat(consoleDevice)
	if errors.Is(err, fs.ErrNotExist) {
		return ConsoleUser{}, ErrNoConsoleUser
	}
	if err != nil {
		return ConsoleUser{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ConsoleUser{}, fmt.Errorf("stat %s: no ownership information", consoleDevice)
	}
	if st.Uid == 0 {
		return ConsoleUser{UID: 0, Name: "root"}, nil
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		return ConsoleUser{}, fmt.Errorf("look up the console owner uid %d: %w", st.Uid, err)
	}
	return ConsoleUser{UID: st.Uid, Name: u.Username, Home: u.HomeDir}, nil
}

// LstatBundle describes path without following a symlink.
func (darwinAppHost) LstatBundle(path string) (fs.FileMode, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

// BundleInfo reads the two keys with the system plutil, which parses both the
// XML and the binary plist forms.
func (h darwinAppHost) BundleInfo(ctx context.Context, bundle string) (string, string, error) {
	plist := filepath.Join(bundle, "Contents", "Info.plist")
	read := func(key string) (string, error) {
		out, err := h.Run(ctx, []string{"/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist}, appToolEnv)
		if err != nil {
			return "", fmt.Errorf("read %s from %s: %w", key, plist, err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	id, err := read("CFBundleIdentifier")
	if err != nil {
		return "", "", err
	}
	exe, err := read("CFBundleExecutable")
	if err != nil {
		return "", "", err
	}
	return id, exe, nil
}

// Signature runs the system codesign through internal/binsign. Its commands
// carry no WaitDelay; the hard bound in launchApp covers them.
func (darwinAppHost) Signature(ctx context.Context, path string) (binsign.Signature, error) {
	return binsign.CodesignInspector{}.Inspect(ctx, path)
}

// Running asks pgrep for a process of exactly that name owned by uid: exit 0
// is a match, exit 1 none, anything else an error.
func (darwinAppHost) Running(ctx context.Context, uid uint32, name string) (bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/pgrep", "-U", strconv.FormatUint(uint64(uid), 10), "-x", name)
	cmd.Env = appToolEnv
	cmd.Dir = "/"
	cmd.WaitDelay = appCommandWaitDelay
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("pgrep -U %d -x %s: %w", uid, name, err)
}

// Run runs argv with exactly env in /, its stdout and stderr captured
// together and capped. WaitDelay bounds the wait for a child that keeps the
// output pipe open after the command exits.
func (darwinAppHost) Run(ctx context.Context, argv, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = "/"
	out := &cappedBuffer{max: maxAppCommandOutput}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = appCommandWaitDelay
	err := cmd.Run()
	return out.buf.Bytes(), err
}
