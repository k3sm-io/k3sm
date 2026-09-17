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
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testConfig is an install pointed entirely at scratch: a data root and a
// server-arguments record that exist only for this test, so nothing reads or
// writes the running Mac's /var/lib/k3sm or /Library/Preferences.
func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		BinarySource:     "/tmp/k3sm",
		TargetUser:       "alice",
		DataRoot:         filepath.Join(dir, "data"),
		ServerArgsRecord: filepath.Join(dir, "io.k3sm.server-args.json"),
	}
}

// configureServerArgs is the operator's own edit to the installed plist: the
// two flags whose loss is the whole defect, applied the way `PlistBuddy` would.
func configureServerArgs(f *fakeSystem, cfg Config, token string, args ...string) {
	f.putFile(cfg.withDefaults().plistPath(ServerLabel), ServerPlist(Config{
		AdminToken:      token,
		ExtraServerArgs: args,
	}))
}

// serverArgsOf returns the operator-supplied arguments the fake's installed
// server plist currently carries, through the real render/parse round trip.
func serverArgsOf(t *testing.T, f *fakeSystem, cfg Config) []string {
	t.Helper()
	raw, ok := f.files[cfg.withDefaults().plistPath(ServerLabel)]
	if !ok {
		t.Fatal("no server plist was written")
	}
	args, err := parseProgramArguments(raw)
	if err != nil {
		t.Fatalf("parse the installed server plist: %v", err)
	}
	return preservedServerArgs(args)
}

// tokenOf returns the --token the fake's installed server plist carries.
func tokenOf(t *testing.T, f *fakeSystem, cfg Config) string {
	t.Helper()
	raw, ok := f.files[cfg.withDefaults().plistPath(ServerLabel)]
	if !ok {
		t.Fatal("no server plist was written")
	}
	args, err := parseProgramArguments(raw)
	if err != nil {
		t.Fatalf("parse the installed server plist: %v", err)
	}
	return flagValue(args, "token")
}

// TestUninstallThenInstallPreservesServerArgs is the gate.
//
// Carrying the operator's arguments over used to read ONLY the installed plist,
// and `k3sm uninstall` removes that plist — so uninstall-then-install (the
// clean-cutover sequence the install docs recommend between channels) silently
// re-rendered the stock template: --mesh-ip gone, --registry-port gone and
// therefore the registry disabled with no log line, and a cluster that came back
// single-node on loopback. An in-place reinstall was unaffected, which is why
// this survived every reinstall test.
func TestUninstallThenInstallPreservesServerArgs(t *testing.T) {
	f := &fakeSystem{}
	// A scratch data root: the record lives inside it, and nothing here may
	// touch the running Mac's /var/lib/k3sm.
	cfg := testConfig(t)
	plist := cfg.withDefaults().plistPath(ServerLabel)

	// (1) The first install renders the stock template; the operator then
	//     configures the node, and the next install carries that configuration
	//     into BOTH the plist it renders and the record inside the data root.
	//     The second install is what puts the arguments somewhere an uninstall
	//     does not reach: the record is written by `k3sm install`, so a hand-
	//     edited plist that has never been through one is still only in the
	//     plist (which is why the un-carried case warns — see
	//     TestInstallWarnsWhenNothingIsCarriedOverAUsedDataRoot).
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	firstToken := tokenOf(t, f, cfg)
	configureServerArgs(f, cfg, firstToken, "--mesh-ip", "100.64.0.1", "--registry-port", "5000")
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	firstToken = tokenOf(t, f, cfg)

	// (2) Uninstall. The plist really goes — the artifact manifest removes it,
	//     and the fake models that removal. The data root, and the record in it,
	//     are preserved.
	if err := Uninstall(context.Background(), f, cfg); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, ok := f.files[plist]; ok {
		t.Fatal("uninstall left the server plist behind; the fake must model the removal or this gate proves nothing")
	}
	if _, ok := f.files[cfg.withDefaults().ServerArgsRecord]; !ok {
		t.Fatal("uninstall removed the server-arguments record; it lives in the preserved data root")
	}

	// (3) Install again. There is no plist to read, so the carry-over must come
	//     from the record the previous install wrote into the data root.
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	got := serverArgsOf(t, f, cfg)
	want := []string{"--mesh-ip", "100.64.0.1", "--registry-port", "5000"}
	if !slices.Equal(got, want) {
		t.Errorf("after uninstall then install the server plist carries %v, want %v", got, want)
	}
	// --token stays install-managed: re-minted in lockstep with the kubeconfig,
	// never carried over from either source.
	newToken := tokenOf(t, f, cfg)
	if newToken == "" || newToken == firstToken {
		t.Errorf("--token must be re-minted (was %q, now %q)", firstToken, newToken)
	}
	if !strings.Contains(f.kubeContent, newToken) {
		t.Error("the admin kubeconfig must carry the re-minted token")
	}
}

// TestServerArgsRecordSources pins which source wins when both the plist and the
// record have an opinion, and what happens when one of them cannot be read.
func TestServerArgsRecordSources(t *testing.T) {
	recordPath := func(cfg Config) string { return cfg.withDefaults().ServerArgsRecord }

	t.Run("the plist wins over the record, and the record is rewritten from it", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		// A stale record from an earlier configuration, and a plist the operator
		// has since edited. The plist is what launchd actually runs.
		putServerArgsRecord(t, f, recordPath(cfg), "--registry-port", "5000")
		configureServerArgs(f, cfg, "k3sm-old-token", "--mesh-ip", "100.64.0.2")

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got, want := serverArgsOf(t, f, cfg), []string{"--mesh-ip", "100.64.0.2"}; !slices.Equal(got, want) {
			t.Errorf("rendered args = %v, want the PLIST's %v", got, want)
		}
		rec, ok := f.serverArgs[recordPath(cfg)]
		if !ok {
			t.Fatal("the record was not rewritten")
		}
		if got, want := rec.Args, []string{"--mesh-ip", "100.64.0.2"}; !slices.Equal(got, want) {
			t.Errorf("record args = %v, want the plist's %v", got, want)
		}
		if rec.CreatedAt.IsZero() || rec.CreatedBy == "" {
			t.Errorf("record = %+v, want a createdAt and a createdBy", rec)
		}
	})

	t.Run("an unreadable plist names the record and the arguments it holds", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		putServerArgsRecord(t, f, recordPath(cfg), "--mesh-ip", "100.64.0.1")
		f.putFile(cfg.withDefaults().plistPath(ServerLabel), []byte("<plist><dict></dict></plist>"))

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install must refuse a server plist whose arguments it cannot read")
		}
		for _, want := range []string{cfg.withDefaults().plistPath(ServerLabel), recordPath(cfg), "--mesh-ip 100.64.0.1"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must name %q", err, want)
			}
		}
	})

	t.Run("a record from a newer k3sm fails the install and names its path", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		f.putFile(recordPath(cfg), []byte(`{"version":99,"args":["--mesh-ip","100.64.0.1"]}`))

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install must refuse a server-arguments record it cannot understand")
		}
		if !strings.Contains(err.Error(), recordPath(cfg)) || !strings.Contains(err.Error(), "rm ") {
			t.Errorf("error %q must name the record path and the rm remedy", err)
		}
	})

	t.Run("a record that is not json fails the install and names its path", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		f.putFile(recordPath(cfg), []byte("{ this is not json"))

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install must refuse a server-arguments record it cannot parse")
		}
		if !strings.Contains(err.Error(), recordPath(cfg)) {
			t.Errorf("error %q must name the record path", err)
		}
	})
}

// TestInstallWarnsWhenNothingIsCarriedOverAUsedDataRoot pins the one warning
// that covers the Macs this fix cannot repair retroactively: an install that
// already lost its plist before records existed has no record either, so the
// stock template is genuinely all there is — and the operator has to be told,
// once, at the moment it happens.
func TestInstallWarnsWhenNothingIsCarriedOverAUsedDataRoot(t *testing.T) {
	warnKey := "no operator-supplied server arguments"

	t.Run("a used data root with neither source warns and names both flags", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		cfg := testConfig(t)
		cfg.Logger = testLogger(&log)
		// Prior cluster state: the datastore an earlier install left behind.
		writeFileForTest(t, cfg.DataRoot+"/server/db/state.db", "SQLite format 3\x00")

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		out := log.String()
		if !strings.Contains(out, warnKey) {
			t.Fatalf("no warning about the un-carried arguments; log =\n%s", out)
		}
		for _, want := range []string{"--mesh-ip", "--registry-port", cfg.DataRoot} {
			if !strings.Contains(out, want) {
				t.Errorf("the warning must name %q; log =\n%s", want, out)
			}
		}
	})

	t.Run("a first install on an empty data root says nothing", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		cfg := testConfig(t)
		cfg.Logger = testLogger(&log)

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if strings.Contains(log.String(), warnKey) {
			t.Errorf("a first install must not warn about arguments nobody configured; log =\n%s", log.String())
		}
	})

	t.Run("a record present on a used data root says nothing", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		cfg := testConfig(t)
		cfg.Logger = testLogger(&log)
		writeFileForTest(t, cfg.DataRoot+"/server/db/state.db", "SQLite format 3\x00")
		putServerArgsRecord(t, f, cfg.withDefaults().ServerArgsRecord, "--mesh-ip", "100.64.0.1")

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if strings.Contains(log.String(), warnKey) {
			t.Errorf("a carried-over record must not warn; log =\n%s", log.String())
		}
	})
}

// TestUninstallNamesWhatItKeeps proves the uninstall says, in one line, which
// artifacts it deliberately left on disk — the service user, the kubeconfig, the
// data root with its server-arguments record, and the daemon log dir. An
// operator who cannot see that list has no way to know a reinstall will pick up
// where they left off.
func TestUninstallNamesWhatItKeeps(t *testing.T) {
	var log bytes.Buffer
	cfg := testConfig(t)
	cfg.Logger = testLogger(&log)
	if err := Uninstall(context.Background(), &fakeSystem{}, cfg); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	out := log.String()
	for _, want := range []string{
		DefaultServiceUser,
		"kubeconfig",
		cfg.DataRoot,
		cfg.withDefaults().ServerArgsRecord,
		LogDir,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the uninstall must name the kept artifact %q; log =\n%s", want, out)
		}
	}
}

// testLogger writes structured records into buf at Info level, so a test can
// assert on what an operator would have seen on their terminal.
func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// TestRecordCanNeverSetAManagedFlag is the gate on the record as an INPUT: the
// file decides a root LaunchDaemon's argv, so a forged one must not be able to
// hand the daemon a credential of its own choosing.
//
// Two layers, both asserted, because either alone would be enough to pass a
// weaker test: pkg/dataroot refuses to read the record at all, and the carry-over
// filters managed flags even from arguments that did get through.
func TestRecordCanNeverSetAManagedFlag(t *testing.T) {
	t.Run("a forged record fails the install and nothing is rendered", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		plist := cfg.withDefaults().plistPath(ServerLabel)
		// Plausible, with one flag appended after the operator's own pair.
		f.putFile(cfg.withDefaults().ServerArgsRecord,
			[]byte(`{"version":1,"args":["--mesh-ip","100.64.0.1","--token=evil"],"createdBy":"k3sm 0.0.0","createdAt":"2026-09-14T12:00:00Z"}`))

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install accepted a record naming a managed flag")
		}
		if !strings.Contains(err.Error(), cfg.withDefaults().ServerArgsRecord) || !strings.Contains(err.Error(), "token") {
			t.Errorf("error %q must name the record and the offending flag", err)
		}
		if raw, ok := f.files[plist]; ok && strings.Contains(string(raw), "evil") {
			t.Fatal("the forged token reached the rendered server plist")
		}
	})

	t.Run("the carry-over filters a managed flag even if one got through", func(t *testing.T) {
		// The second layer, exercised directly: whatever the record holds, the
		// arguments handed to the renderer never name a managed flag.
		got := filterManagedServerArgs([]string{"--mesh-ip", "100.64.0.1", "--token=evil", "--registry-port", "5000"})
		want := []string{"--mesh-ip", "100.64.0.1", "--registry-port", "5000"}
		if !slices.Equal(got, want) {
			t.Fatalf("filterManagedServerArgs = %v, want %v", got, want)
		}
		// And the render carries only the token this install minted.
		argv, err := parseProgramArguments(ServerPlist(Config{AdminToken: "k3sm-minted", ExtraServerArgs: got}))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if tok := flagValue(argv, "token"); tok != "k3sm-minted" {
			t.Errorf("rendered --token = %q, want the re-minted one", tok)
		}
		if strings.Contains(strings.Join(argv, " "), "evil") {
			t.Errorf("the rendered argv carries the forged value: %v", argv)
		}
	})
}

// TestBothSourcesUnreadableNamesBothFiles covers the double fault: an unparsable
// plist AND a record that cannot be read. Naming only the plist would send the
// operator to remove it and walk straight into the record's refusal on the next
// run, having been told nothing about it.
func TestBothSourcesUnreadableNamesBothFiles(t *testing.T) {
	f := &fakeSystem{}
	cfg := testConfig(t)
	plist := cfg.withDefaults().plistPath(ServerLabel)
	record := cfg.withDefaults().ServerArgsRecord
	f.putFile(plist, []byte("<plist><dict></dict></plist>"))
	f.putFile(record, []byte("{ this is not json"))

	err := Install(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("Install must refuse when neither source can be read")
	}
	for _, want := range []string{plist, record} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q: the operator has to fix or remove both", err, want)
		}
	}
}

// TestServerArgsAreCarriedVerbatimAndPrintedRedacted is the credential gate on
// the whole path. --datastore-endpoint carries a DSN password, so the argument
// has to reach the daemon EXACTLY as the operator wrote it while never appearing
// intact in anything k3sm prints.
func TestServerArgsAreCarriedVerbatimAndPrintedRedacted(t *testing.T) {
	const (
		dsn    = "postgres://u:s3cret@h/db"
		secret = "s3cret"
	)
	var log bytes.Buffer
	f := &fakeSystem{}
	cfg := testConfig(t)
	cfg.Logger = testLogger(&log)

	// Install, configure the endpoint, reinstall: the second install is the one
	// that carries the DSN and records it.
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	configureServerArgs(f, cfg, tokenOf(t, f, cfg), "--datastore-endpoint", dsn)
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("reinstall: %v", err)
	}

	t.Run("verbatim where it has to work", func(t *testing.T) {
		if got, want := serverArgsOf(t, f, cfg), []string{"--datastore-endpoint", dsn}; !slices.Equal(got, want) {
			t.Errorf("rendered args = %v, want %v (a masked DSN would not connect)", got, want)
		}
		rec, ok := f.serverArgs[cfg.withDefaults().ServerArgsRecord]
		if !ok {
			t.Fatal("no record was written")
		}
		if !slices.Contains(rec.Args, dsn) {
			t.Errorf("record args = %v, want the DSN verbatim", rec.Args)
		}
	})

	t.Run("masked in every line the install printed", func(t *testing.T) {
		if strings.Contains(log.String(), secret) {
			t.Fatalf("the install log leaked the DSN password:\n%s", log.String())
		}
		if !strings.Contains(log.String(), "postgres://u:***@h/db") {
			t.Errorf("the log must still say which endpoint was configured:\n%s", log.String())
		}
	})

	t.Run("masked after an uninstall, on the record's own log line", func(t *testing.T) {
		log.Reset()
		if err := Uninstall(context.Background(), f, cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("install after uninstall: %v", err)
		}
		if strings.Contains(log.String(), secret) {
			t.Fatalf("the carried-from-record log line leaked the DSN password:\n%s", log.String())
		}
		// And it was really carried, from the record, verbatim.
		if got, want := serverArgsOf(t, f, cfg), []string{"--datastore-endpoint", dsn}; !slices.Equal(got, want) {
			t.Errorf("after uninstall then install the args are %v, want %v", got, want)
		}
	})

	t.Run("masked in the unparsable-plist error", func(t *testing.T) {
		g := &fakeSystem{}
		gcfg := testConfig(t)
		putServerArgsRecord(t, g, gcfg.withDefaults().ServerArgsRecord, "--datastore-endpoint", dsn)
		g.putFile(gcfg.withDefaults().plistPath(ServerLabel), []byte("<plist><dict></dict></plist>"))

		err := Install(context.Background(), g, gcfg)
		if err == nil {
			t.Fatal("Install must refuse an unparsable plist")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error leaked the DSN password: %v", err)
		}
		if !strings.Contains(err.Error(), "postgres://u:***@h/db") {
			t.Errorf("the error must still name the endpoint: %v", err)
		}
	})

	t.Run("the token is masked too, in either spelling", func(t *testing.T) {
		got := redactedServerArgsText([]string{"--agent-token", "k3sm-secret-value", "--token=k3sm-other", "--mesh-ip", "100.64.0.1"})
		for _, leaked := range []string{"k3sm-secret-value", "k3sm-other"} {
			if strings.Contains(got, leaked) {
				t.Errorf("redaction leaked %q: %s", leaked, got)
			}
		}
		if !strings.Contains(got, "--mesh-ip 100.64.0.1") {
			t.Errorf("redaction ate an ordinary flag: %s", got)
		}
	})
}
