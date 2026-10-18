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
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/internal/binsign"
)

// fakeAppHost is the appHost a test describes: the console user, the bundle,
// the two signatures and the process table, plus a runner that records what
// it would have run and never runs anything.
type fakeAppHost struct {
	console    ConsoleUser
	consoleErr error
	mode       fs.FileMode
	modeErr    error
	id, exe    string
	infoErr    error
	appSig     binsign.Signature
	cliSig     binsign.Signature
	running    bool
	runErr     error
	// block, when set, runs at the start of Signature: a check that hangs.
	block func(ctx context.Context)

	runs    [][]string
	envs    [][]string
	pgreps  []string
	sigsFor []string
}

func (h *fakeAppHost) ConsoleUser() (ConsoleUser, error) { return h.console, h.consoleErr }
func (h *fakeAppHost) LstatBundle(string) (fs.FileMode, error) {
	return h.mode, h.modeErr
}
func (h *fakeAppHost) BundleInfo(context.Context, string) (string, string, error) {
	return h.id, h.exe, h.infoErr
}
func (h *fakeAppHost) Signature(ctx context.Context, path string) (binsign.Signature, error) {
	if h.block != nil {
		h.block(ctx)
	}
	h.sigsFor = append(h.sigsFor, path)
	if path == testAppBundle {
		return h.appSig, nil
	}
	return h.cliSig, nil
}
func (h *fakeAppHost) Running(_ context.Context, uid uint32, name string) (bool, error) {
	h.pgreps = append(h.pgreps, name)
	return h.running, nil
}
func (h *fakeAppHost) Run(_ context.Context, argv, env []string) ([]byte, error) {
	h.runs = append(h.runs, argv)
	h.envs = append(h.envs, env)
	return nil, h.runErr
}

const (
	testAppBundle = "/Applications/k3sm.app"
	testCLI       = "/Library/k3sm/bin/k3sm"
	testTeam      = "ABCDE12345"
)

// recordingLauncher is an AppLauncher that records each request and returns err.
type recordingLauncher struct {
	reqs []AppLaunchRequest
	err  error
}

func (r *recordingLauncher) Launch(_ context.Context, req AppLaunchRequest) error {
	r.reqs = append(r.reqs, req)
	return r.err
}

// TestInstallLaunchesTheAppHidden is the gate for opening the menu bar app
// after a command brings the node up: the app opens for the console user
// only, never as root, with its window hidden, and only when the bundle is
// the k3sm app signed the way the running k3sm is and is not already running;
// Install, Start and Restart --start ask for it, Stop, Uninstall and a plain
// Restart do not; and a launch that fails never fails the command.
func TestInstallLaunchesTheAppHidden(t *testing.T) {
	adhoc := binsign.Signature{Valid: true, AdHoc: true, Identifier: AppBundleID}
	team := binsign.Signature{Valid: true, TeamID: testTeam, Identifier: AppBundleID}
	alice := ConsoleUser{UID: 501, Name: "alice", Home: "/Users/alice"}
	good := func() *fakeAppHost {
		return &fakeAppHost{console: alice, mode: fs.ModeDir | 0o755, id: AppBundleID, exe: "k3sm-app", appSig: adhoc, cliSig: adhoc}
	}
	wantArgv := []string{
		"/bin/launchctl", "asuser", "501",
		"/usr/bin/sudo", "-n", "-H", "-u", "#501",
		"/usr/bin/open", "-g", "-j", "-a", testAppBundle, "--args", "--background",
	}

	cases := []struct {
		name   string
		mutate func(h *fakeAppHost)
		launch bool
		// wantWarn is a substring of the Warn line a refused bundle logs; empty
		// means the skip is the normal state of the Mac and logs at Info.
		wantWarn string
	}{
		{name: "console user, app present, verified, not running: opened hidden as that uid", launch: true},
		{name: "team-signed k3sm and app of the same team: opened", launch: true, mutate: func(h *fakeAppHost) { h.cliSig, h.appSig = team, team }},
		{name: "ad-hoc k3sm, team-signed app", mutate: func(h *fakeAppHost) { h.appSig = team }, wantWarn: "ad-hoc signed but the app is signed by team"},
		{name: "signing identifier is not the app's", mutate: func(h *fakeAppHost) {
			h.appSig = binsign.Signature{Valid: true, AdHoc: true, Identifier: "com.example.other"}
		}, wantWarn: "signing identifier"},
		{name: "app absent", mutate: func(h *fakeAppHost) { h.modeErr = fs.ErrNotExist }},
		{name: "already running for the console user", mutate: func(h *fakeAppHost) { h.running = true }},
		{name: "console owned by root", mutate: func(h *fakeAppHost) { h.console = ConsoleUser{UID: 0, Name: "root"} }},
		{name: "console owned by a service uid below 501", mutate: func(h *fakeAppHost) { h.console = ConsoleUser{UID: 200, Name: "_k3sm"} }},
		{name: "no console user (SSH-only session)", mutate: func(h *fakeAppHost) { h.consoleErr = ErrNoConsoleUser }},
		{name: "symlinked bundle", mutate: func(h *fakeAppHost) { h.mode = fs.ModeSymlink | 0o755 }, wantWarn: "symbolic link"},
		{name: "bundle is a file", mutate: func(h *fakeAppHost) { h.mode = 0o644 }, wantWarn: "not a directory"},
		{name: "wrong bundle id", mutate: func(h *fakeAppHost) { h.id = "com.example.k3sm" }, wantWarn: "bundle identifier"},
		{name: "executable name with a path", mutate: func(h *fakeAppHost) { h.exe = "../evil" }, wantWarn: "CFBundleExecutable"},
		{name: "codesign verify fails on the app", mutate: func(h *fakeAppHost) { h.appSig = binsign.Signature{} }, wantWarn: "does not verify"},
		{name: "codesign verify fails on k3sm", mutate: func(h *fakeAppHost) { h.cliSig = binsign.Signature{} }, wantWarn: "running k3sm"},
		{name: "team-signed k3sm, ad-hoc app", mutate: func(h *fakeAppHost) { h.cliSig = team }, wantWarn: "ad-hoc"},
		{name: "team mismatch", mutate: func(h *fakeAppHost) {
			h.cliSig = team
			h.appSig = binsign.Signature{Valid: true, TeamID: "ZZZZZ99999", Identifier: AppBundleID}
		}, wantWarn: "ZZZZZ99999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := good()
			if tc.mutate != nil {
				tc.mutate(h)
			}
			var logs bytes.Buffer
			l := hiddenAppLauncher{host: h, executable: testCLI, bundle: testAppBundle,
				logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
			if err := l.Launch(context.Background(), AppLaunchRequest{Command: "install"}); err != nil {
				t.Fatalf("Launch: %v", err)
			}
			for i, argv := range h.runs {
				assertNeverRoot(t, argv, h.envs[i])
			}
			if !tc.launch {
				if len(h.runs) != 0 {
					t.Fatalf("launched %q, want no launch", h.runs)
				}
				if tc.wantWarn != "" && (!strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), tc.wantWarn)) {
					t.Errorf("want a Warn naming %q, logs:\n%s", tc.wantWarn, logs.String())
				}
				if tc.wantWarn == "" && strings.Contains(logs.String(), "level=WARN") {
					t.Errorf("a normal skip logged a Warn:\n%s", logs.String())
				}
				if !strings.Contains(logs.String(), "not opening the k3sm app") {
					t.Errorf("the skip is not logged:\n%s", logs.String())
				}
				return
			}
			if len(h.runs) != 1 || !slices.Equal(h.runs[0], wantArgv) {
				t.Fatalf("ran %q, want exactly %q", h.runs, wantArgv)
			}
			wantEnv := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "USER=alice", "LOGNAME=alice", "HOME=/Users/alice"}
			if !slices.Equal(h.envs[0], wantEnv) {
				t.Errorf("env %q, want exactly %q", h.envs[0], wantEnv)
			}
			if !slices.Equal(h.pgreps, []string{"k3sm-app"}) {
				t.Errorf("running check for %q, want the bundle's executable", h.pgreps)
			}
			if !slices.Equal(h.sigsFor, []string{testAppBundle, testCLI}) {
				t.Errorf("signatures checked for %q", h.sigsFor)
			}
			if !strings.Contains(logs.String(), "opened the k3sm app") {
				t.Errorf("the launch is not logged at Info:\n%s", logs.String())
			}
		})
	}

	t.Run("a long executable name is matched as the kernel truncates it", func(t *testing.T) {
		h := good()
		h.exe = "k3sm-app-with-a-long-name"
		l := hiddenAppLauncher{host: h, executable: testCLI, bundle: testAppBundle, logger: slog.New(slog.DiscardHandler)}
		if err := l.Launch(context.Background(), AppLaunchRequest{Command: "start"}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(h.pgreps, []string{"k3sm-app-with-a-"}) {
			t.Errorf("pgrep name %q", h.pgreps)
		}
	})

	t.Run("a failed launch is an error to the caller", func(t *testing.T) {
		h := good()
		h.runErr = errors.New("exit status 1")
		l := hiddenAppLauncher{host: h, executable: testCLI, bundle: testAppBundle, logger: slog.New(slog.DiscardHandler)}
		if err := l.Launch(context.Background(), AppLaunchRequest{Command: "install"}); err == nil {
			t.Fatal("Launch: nil error for a failed open")
		}
	})

	t.Run("a hung check costs at most the bound, and the command goes on", func(t *testing.T) {
		old := appLaunchBound
		appLaunchBound = 100 * time.Millisecond
		t.Cleanup(func() { appLaunchBound = old })
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		for _, bc := range []struct {
			name  string
			block func(ctx context.Context)
		}{
			{"blocks until its context is done", func(ctx context.Context) { <-ctx.Done() }},
			{"ignores its context", func(context.Context) { <-release }},
		} {
			t.Run(bc.name, func(t *testing.T) {
				h := good()
				h.block = bc.block
				var logs bytes.Buffer
				logger := slog.New(slog.NewTextHandler(&logs, nil))
				cfg := Config{Logger: logger, AppLauncher: hiddenAppLauncher{host: h, executable: testCLI, bundle: testAppBundle, logger: logger}}
				start := time.Now()
				launchApp(context.Background(), cfg, "start")
				if took := time.Since(start); took > appLaunchBound+time.Second {
					t.Fatalf("launchApp took %s, bound %s", took, appLaunchBound)
				}
				if !strings.Contains(logs.String(), "could not open the k3sm app") {
					t.Errorf("the abandoned launch is not logged:\n%s", logs.String())
				}
				if len(h.runs) != 0 {
					t.Errorf("launched after the bound: %q", h.runs)
				}
			})
		}
	})

	t.Run("launcher error: a server install still succeeds", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		var logs bytes.Buffer
		rec := &recordingLauncher{err: errors.New("open failed")}
		cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", AppLauncher: rec,
			Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !slices.Equal(rec.reqs, []AppLaunchRequest{{Command: "install"}}) {
			t.Fatalf("launch requests %v, want one for install", rec.reqs)
		}
		if !strings.Contains(logs.String(), "could not open the k3sm app") {
			t.Errorf("the launch error is not logged:\n%s", logs.String())
		}
	})

	t.Run("an agent install (a join) opens the app", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		rec := &recordingLauncher{}
		cfg := agentCfg(t)
		cfg.AppLauncher = rec
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !slices.Equal(rec.reqs, []AppLaunchRequest{{Command: "install"}}) {
			t.Fatalf("launch requests %v, want one for install", rec.reqs)
		}
	})

	t.Run("start and restart --start open it; stop, restart, a stays-stopped install and uninstall do not", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		rec := &recordingLauncher{}
		cfg.AppLauncher = rec
		ctx := context.Background()
		if err := Restart(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Restart: %v", err)
		}
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		// An install over the stopped node keeps it stopped: nothing came up.
		if err := Install(ctx, f, cfg); err != nil {
			t.Fatalf("Install over a stopped node: %v", err)
		}
		if len(rec.reqs) != 0 {
			t.Fatalf("restart, stop or a stays-stopped install opened the app: %v", rec.reqs)
		}
		if err := Start(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Start: %v", err)
		}
		withStart := cfg
		withStart.Start = true
		if err := Restart(ctx, f, withStart, ActorUser, "test"); err != nil {
			t.Fatalf("Restart --start: %v", err)
		}
		if err := Uninstall(ctx, f, cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		want := []AppLaunchRequest{{Command: "start"}, {Command: "restart"}}
		if !slices.Equal(rec.reqs, want) {
			t.Fatalf("launch requests %v, want %v", rec.reqs, want)
		}
	})
}

// assertNeverRoot fails when a launch would run as root: the uid passed to
// launchctl and sudo, and the environment's user, must never be root's.
func assertNeverRoot(t *testing.T, argv, env []string) {
	t.Helper()
	for i, a := range argv {
		if (a == "asuser" || a == "-u") && i+1 < len(argv) && (argv[i+1] == "0" || argv[i+1] == "#0" || argv[i+1] == "root") {
			t.Fatalf("launch as root: %q", argv)
		}
	}
	if slices.Contains(env, "USER=root") {
		t.Fatalf("launch env names root: %q", env)
	}
}
