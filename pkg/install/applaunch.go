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
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/internal/binsign"
)

// AppBundlePath is where the k3sm menu bar app is installed.
const AppBundlePath = "/Applications/k3sm.app"

// AppBundleID is the CFBundleIdentifier the app must carry before k3sm
// launches it.
const AppBundleID = "io.k3sm.app"

// AppBackgroundArg is the launch argument that tells the app to start with its
// window hidden: the status item appears, and the window stays closed.
const AppBackgroundArg = "--background"

// appLaunchBound is the one hard bound over the whole best-effort path, the
// checks and the launch together, measured from the start of launchApp: a
// step that hangs past it is abandoned (see launchApp), so the app adds at
// most this much to the command that brought the node up. A var so a test can
// shorten it.
var appLaunchBound = 15 * time.Second

// appCommandWaitDelay bounds the wait for a launch-path command's output
// after it exits or is killed, for a child that keeps the pipe open.
const appCommandWaitDelay = 2 * time.Second

// minHumanUID is the first uid macOS gives a human account; below it are root
// and the system and service accounts. The app is never opened for those.
const minHumanUID = 501

// maxProcessNameLen is MAXCOMLEN: the kernel keeps this many bytes of a
// process name, and `pgrep -x` matches against that truncated name.
const maxProcessNameLen = 16

// AppLaunchRequest names the command that asks for the app.
type AppLaunchRequest struct {
	// Command is the k3sm verb that brought the node up: install, start or
	// restart. It is logged, nothing else.
	Command string
}

// AppLauncher opens the menu bar app for the console user once a command has
// brought the node up. Install, Start and Restart (with Start) call it, best
// effort: an error is logged and never fails the command. Nil in Config
// launches nothing.
type AppLauncher interface {
	Launch(ctx context.Context, req AppLaunchRequest) error
}

// ErrNoConsoleUser reports that no human is logged in at the screen.
var ErrNoConsoleUser = errors.New("no user is logged in at the console")

// ConsoleUser is the human logged in at the screen: the owner of /dev/console.
type ConsoleUser struct {
	UID  uint32
	Name string
	Home string
}

// appHost is the set of host facts and the command runner the launch decision
// reads through. The darwin implementation is darwinAppHost; tests fake it.
type appHost interface {
	// ConsoleUser is /dev/console's owner and its account; ErrNoConsoleUser
	// when there is none.
	ConsoleUser() (ConsoleUser, error)
	// LstatBundle describes path without following a symlink.
	LstatBundle(path string) (fs.FileMode, error)
	// BundleInfo reads CFBundleIdentifier and CFBundleExecutable from the
	// bundle's Contents/Info.plist.
	BundleInfo(ctx context.Context, bundle string) (id, executable string, err error)
	// Signature runs `codesign --verify --strict` on path and reports its
	// kind and Team ID (binsign.Signature; the zero value when it fails).
	Signature(ctx context.Context, path string) (binsign.Signature, error)
	// Running reports whether a process named name runs as uid.
	Running(ctx context.Context, uid uint32, name string) (bool, error)
	// Run runs argv with exactly env and returns its combined output.
	Run(ctx context.Context, argv, env []string) ([]byte, error)
}

// hiddenAppLauncher is the AppLauncher k3sm uses: it opens AppBundlePath for
// the console user, with its window hidden, after checking that the bundle is
// the k3sm app and is signed the way the running k3sm is.
type hiddenAppLauncher struct {
	host appHost
	// executable is the running k3sm binary, whose signature sets the posture
	// the app's must match.
	executable string
	bundle     string
	logger     *slog.Logger
}

// Launch opens the app hidden for the console user, or logs why it did not.
// A skip is not an error: only a launch that was attempted and failed is.
func (l hiddenAppLauncher) Launch(ctx context.Context, req AppLaunchRequest) error {
	argv, env, skip := l.plan(ctx)
	if skip != "" {
		l.logger.Info("not opening the k3sm app: "+skip, "command", req.Command, "app", l.bundle)
		return nil
	}
	// Checks that ran out the bound decided nothing: never open after it.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("checks ran past the launch bound: %w", err)
	}
	// Accepted residual at this verify-then-open seam: /Applications is
	// admin-writable, so an admin console user can swap the bundle between
	// the checks above and `open` below. What then runs is that user's own
	// code under their own uid (never root), which they could already run, so
	// it is an accepted risk, not an escalation.
	out, err := l.host.Run(ctx, argv, env)
	if err != nil {
		return fmt.Errorf("open %s for uid %s: %w (output: %q)", l.bundle, argv[2], err, strings.TrimSpace(string(out)))
	}
	l.logger.Info("opened the k3sm app with its window hidden", "command", req.Command, "app", l.bundle, "uid", argv[2], "output", strings.TrimSpace(string(out)))
	return nil
}

// plan decides the launch. It returns the argv and environment to run, or a
// reason to skip. A skip that points at something wrong with the bundle or the
// host is also logged at Warn; one that is simply the normal state of the Mac
// (no app installed, nobody at the screen, the app already running) is not.
func (l hiddenAppLauncher) plan(ctx context.Context) (argv, env []string, skip string) {
	warn := func(why string) ([]string, []string, string) {
		l.logger.Warn("not opening the k3sm app: "+why, "app", l.bundle)
		return nil, nil, why
	}
	u, err := l.host.ConsoleUser()
	switch {
	case errors.Is(err, ErrNoConsoleUser):
		return nil, nil, "no user is logged in at the screen (an SSH-only or headless session)"
	case err != nil:
		return warn(fmt.Sprintf("the console user could not be read: %v", err))
	case u.UID < minHumanUID || u.Name == "" || u.Name == "root" || strings.HasPrefix(u.Name, "_"):
		return nil, nil, fmt.Sprintf("the console is owned by uid %d, which is not a human account", u.UID)
	case !validAccountName(u.Name):
		return warn(fmt.Sprintf("the console user's name %q is not a plain account name", u.Name))
	}
	mode, err := l.host.LstatBundle(l.bundle)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, "the app is not installed"
	case err != nil:
		return warn(fmt.Sprintf("the app bundle could not be read: %v", err))
	case mode&fs.ModeSymlink != 0:
		return warn("the app bundle is a symbolic link, not the installed app")
	case !mode.IsDir():
		return warn("the app bundle is not a directory")
	}
	// The signature first: it seals Info.plist, which is read only once the
	// seal verifies.
	app, err := l.host.Signature(ctx, l.bundle)
	switch {
	case err != nil:
		return warn(fmt.Sprintf("its code signature could not be checked: %v", err))
	case !app.Valid:
		return warn("its code signature does not verify (codesign --verify --strict)")
	case app.Identifier != AppBundleID:
		return warn(fmt.Sprintf("its signing identifier is %q, not %q", app.Identifier, AppBundleID))
	}
	id, exe, err := l.host.BundleInfo(ctx, l.bundle)
	switch {
	case err != nil:
		return warn(fmt.Sprintf("its Info.plist could not be read: %v", err))
	case id != AppBundleID:
		return warn(fmt.Sprintf("its bundle identifier is %q, not %q", id, AppBundleID))
	case !validProcessName(exe):
		return warn(fmt.Sprintf("its CFBundleExecutable %q is not a plain file name", exe))
	}
	cli, err := l.host.Signature(ctx, l.executable)
	switch {
	case err != nil:
		return warn(fmt.Sprintf("the running k3sm's code signature could not be checked: %v", err))
	case !cli.Valid:
		return warn("the running k3sm's code signature does not verify")
	}
	if why := signingMismatch(cli, app); why != "" {
		return warn(why)
	}
	name := exe
	if len(name) > maxProcessNameLen {
		name = name[:maxProcessNameLen]
	}
	running, err := l.host.Running(ctx, u.UID, name)
	switch {
	case err != nil:
		return warn(fmt.Sprintf("whether it already runs could not be checked: %v", err))
	case running:
		return nil, nil, fmt.Sprintf("it already runs for %s", u.Name)
	}
	return appLaunchArgv(u, l.bundle), appLaunchEnv(u), ""
}

// signingMismatch compares the app's signature with the running k3sm's: an
// ad-hoc k3sm (a local build) opens only an ad-hoc app, and a team-signed
// k3sm only an app signed by the same team. Every other pairing is a
// mismatch. Empty means they match.
func signingMismatch(cli, app binsign.Signature) string {
	switch {
	case cli.AdHoc && app.AdHoc:
		return ""
	case cli.AdHoc:
		return fmt.Sprintf("k3sm is ad-hoc signed but the app is signed by team %q", app.TeamID)
	case cli.TeamID == "":
		return "k3sm is signed by neither a team nor ad hoc"
	case app.AdHoc:
		return fmt.Sprintf("k3sm is signed by team %s but the app is ad-hoc signed", cli.TeamID)
	case app.TeamID != cli.TeamID:
		return fmt.Sprintf("k3sm is signed by team %s but the app by team %q", cli.TeamID, app.TeamID)
	}
	return ""
}

// appLaunchArgv is the fixed launch command: launchctl asuser puts the command
// in the console user's login session (the GUI bootstrap namespace, where
// Launch Services runs), and sudo drops root to that user (with -H, also to
// their home) before open runs. -g keeps the app in the background, -j
// launches it hidden, and the background argument keeps its window closed.
func appLaunchArgv(u ConsoleUser, bundle string) []string {
	uid := strconv.FormatUint(uint64(u.UID), 10)
	return []string{
		"/bin/launchctl", "asuser", uid,
		"/usr/bin/sudo", "-n", "-H", "-u", "#" + uid,
		"/usr/bin/open", "-g", "-j", "-a", bundle, "--args", AppBackgroundArg,
	}
}

// appLaunchEnv is the whole environment of the launch command: a system PATH
// and the console user's identity, nothing inherited from the root process.
func appLaunchEnv(u ConsoleUser) []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "USER=" + u.Name, "LOGNAME=" + u.Name}
	if u.Home != "" {
		env = append(env, "HOME="+u.Home)
	}
	return env
}

// validAccountName reports a short account name of the characters macOS
// allows in one: letters, digits, '.', '_' and '-', not starting with '-'.
func validAccountName(s string) bool {
	if s == "" || len(s) > 255 || s[0] == '-' {
		return false
	}
	return plainChars(s)
}

// validProcessName reports a file name with no path separator, of plain
// characters, that is not "." or "..".
func validProcessName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 || s[0] == '-' {
		return false
	}
	return plainChars(s)
}

func plainChars(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// InstallWithResult is Install, also returning the Result. A successful
// install that left the node up opens the menu bar app (launchAppAfterInstall).
func InstallWithResult(ctx context.Context, sys System, cfg Config) (Result, error) {
	var res Result
	if err := install(ctx, sys, cfg, &res); err != nil {
		return res, err
	}
	launchAppAfterInstall(ctx, sys, cfg)
	return res, nil
}

// launchAppAfterInstall opens the app after a successful install, unless the
// install kept a stopped node stopped. That case is read from the stop
// marker: a successful install leaves it in place exactly when it brought
// nothing up, and removes it when --start started the node.
func launchAppAfterInstall(ctx context.Context, sys System, cfg Config) {
	cfg = cfg.withDefaults()
	if cfg.AppLauncher == nil {
		return
	}
	if _, stopped, _ := readStopMarker(sys, cfg); stopped {
		cfg.Logger.Info("not opening the k3sm app: the node stays stopped", "command", "install")
		return
	}
	launchApp(ctx, cfg, "install")
}

// launchApp asks cfg.AppLauncher, if any, to open the app after command
// brought the node up. It never fails the command: an error is one Warn line.
//
// The whole call is held to appLaunchBound. The launcher gets a context with
// that deadline (every command it runs is killed at it, with WaitDelay
// bounding the pipe wait), and launchApp also stops waiting at the deadline,
// so even a step that ignores its context cannot hold the command longer. An
// abandoned launcher goroutine ends when its killed command is reaped.
func launchApp(ctx context.Context, cfg Config, command string) {
	if cfg.AppLauncher == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, appLaunchBound)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cfg.AppLauncher.Launch(ctx, AppLaunchRequest{Command: command}) }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		err = fmt.Errorf("gave up after %s: %w", appLaunchBound, ctx.Err())
	}
	if err != nil {
		cfg.Logger.Warn("could not open the k3sm app; the node is up, and the app can be opened by hand", "command", command, "err", err)
	}
}
