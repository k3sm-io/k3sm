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
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/version"
)

// managedAgentFlags are the `k3sm agent` flags AgentPlist renders ITSELF, by
// flag name with the leading dashes stripped — the ones a carry-over must drop
// so the next render cannot end up with the same flag twice.
//
// It is deliberately WIDER than dataroot.ManagedAgentFlags, and the difference
// is what each list decides. dataroot's list is the REFUSAL set: a record that
// names --token is rejected outright, because a file trying to put a credential
// on a root daemon's argv is not a stale record. This list is the FILTER set:
// --server, --node-ip and --token-file are legitimate things for a plist to
// carry — this renderer put them there — but they are re-derived from the
// operator's flags on every install, so carrying the installed values over
// would re-render a join target the operator has just changed, or a token file
// they have already deleted.
var managedAgentFlags = func() map[string]bool {
	m := map[string]bool{"server": true, "node-ip": true, "token-file": true}
	for _, name := range dataroot.ManagedAgentFlags {
		m[name] = true
	}
	return m
}()

// installedAgentArgs returns the operator-supplied `k3sm agent` arguments the
// next render must carry over, or nil when there are none.
//
// It is installedServerArgs's contract for the other role, with the same two
// sources in the same precedence: the agent plist ALREADY INSTALLED (what
// launchd is running right now), and — only when there is no plist, which is
// every install that follows an uninstall — the agent-arguments record in
// root-owned /Library/Preferences. It reads neither of the server role's files.
func installedAgentArgs(sys System, cfg Config) ([]string, error) {
	path := cfg.plistPath(AgentLabel)
	raw, err := sys.ReadFile(path)
	switch {
	case err == nil:
		args, perr := parseProgramArguments(raw)
		if perr != nil {
			return nil, fmt.Errorf("install: cannot read the arguments of the installed agent plist %s: %w (remove the file to reinstall from the stock template — doing so discards any agent flags it carried)", path, perr)
		}
		return preservedAgentArgs(args), nil
	case errors.Is(err, fs.ErrNotExist):
		return recordedAgentArgs(sys, cfg)
	default:
		return nil, fmt.Errorf("install: read installed agent plist %s: %w", path, err)
	}
}

// AgentJoinServer returns the control-plane host the INSTALLED agent daemon
// joins: the --server value of the agent plist on disk.
//
// It reads the plist rather than the agent-arguments record on purpose. The
// record deliberately does not carry --server (managedAgentFlags filters it out,
// because the renderer re-derives it from the operator's flags on every
// install), so the plist is the only place the installed join target is written
// down. An uninstall needs it to reach the bootstrap listener at <host>:9345,
// which is the same address the join dialed and the same one the agent
// republishes its endpoint to.
//
// Every failure is an ERROR rather than an empty answer, including the absent
// plist: "this Mac does not carry the agent daemon" and "the join target could
// not be read" lead to the same skipped deregistration but mean different
// things, and only the caller can tell which one deserves a sentence.
func AgentJoinServer(sys System, cfg Config) (string, error) {
	cfg = cfg.withDefaults()
	path := cfg.plistPath(AgentLabel)
	raw, err := sys.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("install: read the installed agent plist %s: %w", path, err)
	}
	args, err := parseProgramArguments(raw)
	if err != nil {
		return "", fmt.Errorf("install: cannot read the arguments of the installed agent plist %s: %w", path, err)
	}
	host := flagValue(args, "server")
	if host == "" {
		return "", fmt.Errorf("install: the installed agent plist %s names no --server, so the control plane this node joined is unknown", path)
	}
	return host, nil
}

// recordedAgentArgs returns the arguments the agent-arguments record carries,
// or nil when there is no record. A record that cannot be read is an ERROR,
// never an empty answer — "no arguments" and "the arguments could not be read"
// render identically, and only one of them is safe to render.
func recordedAgentArgs(sys System, cfg Config) ([]string, error) {
	path := cfg.AgentArgsRecord
	rec, err := dataroot.ReadAgentArgsRecord(systemFiles{sys}, path)
	if err != nil {
		return nil, fmt.Errorf("install: %w (`sudo rm %s` to reinstall from the stock template, which discards the arguments it lists)", err, path)
	}
	if rec == nil {
		return nil, nil
	}
	// Through the SAME filter the plist path uses: dataroot already refuses a
	// record naming --token, and this drops the flags the renderer owns.
	args := filterManagedAgentArgs(rec.Args)
	if len(args) > 0 {
		cfg.Logger.Info("carried the operator-supplied agent arguments over from the recorded ones (the installed plist is gone, as after an uninstall)",
			"args", redactedServerArgsText(args), "record", path, "recorded-at", rec.CreatedAt.Format(time.RFC3339), "recorded-by", rec.CreatedBy)
	}
	return args, nil
}

// writeArgsRecord records the arguments this install rendered, in the record
// belonging to the role it installed. It is the one write point for both
// records, so a role can never write the other's file.
func writeArgsRecord(sys System, cfg Config) error {
	if cfg.Role == RoleAgent {
		return writeAgentArgsRecord(sys, cfg)
	}
	return writeServerArgsRecord(sys, cfg)
}

// writeAgentArgsRecord records the agent arguments this install rendered, so
// the next one can carry them over with no plist to read.
func writeAgentArgsRecord(sys System, cfg Config) error {
	path := cfg.AgentArgsRecord
	rec := dataroot.AgentArgsRecord{
		Args:      cfg.ExtraAgentArgs,
		CreatedBy: "k3sm " + version.Get().Version,
		CreatedAt: time.Now().UTC(),
	}
	if err := sys.WriteAgentArgsRecord(path, rec); err != nil {
		return fmt.Errorf("install: write the agent arguments record %s: %w", path, err)
	}
	return nil
}

// preservedAgentArgs returns the arguments of an installed agent plist the next
// render must carry over. The first two elements are dropped by position (the
// installed binary path and the `agent` subcommand, both re-derived from the
// Config); the rest is walked by flag NAME, so an operator who reordered the
// argv still gets the same answer.
func preservedAgentArgs(installed []string) []string {
	if len(installed) < 2 {
		return nil
	}
	return filterManagedAgentArgs(installed[2:])
}

// filterManagedAgentArgs drops the install-managed agent flags (and their
// separated values) from a bare argument list, keeping everything else in
// order.
func filterManagedAgentArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		name, _, inline := splitFlag(args[i])
		if name == "" || !managedAgentFlags[name] {
			out = append(out, args[i])
			continue
		}
		if !inline {
			i++ // the managed flag's value is a separate argument
		}
	}
	return out
}

// stageJoinToken copies the operator's join token to where the agent daemon can
// read it: agentTokenPath(), owned by the service uid at AgentTokenFileMode
// inside a directory at AgentTokenDirMode.
//
// The copy exists because of a privilege asymmetry that has no other fix. The
// operator writes the token as root, so their file is root-owned and, on the
// obvious choice of /var/root, sits under a directory the service user cannot
// even traverse. The daemon runs as that user. Pointing it at the operator's
// path would produce a worker that fails to read a token that is plainly there,
// reported as a permission error in a log nobody is watching yet.
//
// The token is validated before an operator leaves the terminal rather than at
// the daemon — a file anyone can read, an empty one, and one whose contents are
// not a K10 join token at all are mistakes worth one sentence now instead of a
// backoff loop later — but that validation happens in operatorJoinToken, at the
// join-endpoint preflight, which is where those refusals can still cost nothing.
// This function receives the bytes that reading produced and does one thing with
// them: write them where the daemon can read them.
//
// Nothing here logs or echoes the value — not the token, not a prefix of it.
func stageJoinToken(sys System, cfg Config, uid uint32, token string) error {
	// The BYTES come from the caller, not from a fresh read of the operator's
	// file: Install's join-endpoint preflight read that file once, judged its
	// mode, parsed it and pinned the control plane against it, all before the
	// first write. Re-reading here would put the service user, the log trees and
	// the run dir between the bytes that were checked and the bytes that are
	// staged, so a file replaced in that window would reach the daemon
	// unvalidated and pinned to nothing. An empty token is a programmer error —
	// this function is reached only on the path the preflight has already run.
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("install: no join token was read before staging (the join-endpoint preflight is what reads %s)", cfg.TokenFile)
	}
	dst := cfg.agentTokenPath()
	if err := stageTokenFile(sys, uid, token, dst, "join token", AgentTokenFileMode, AgentTokenDirMode); err != nil {
		return err
	}
	cfg.Logger.Info("staged the join token for the agent daemon (your own copy is untouched and yours to delete once the node is Ready)",
		"from", cfg.TokenFile, "to", dst)
	return nil
}

// operatorJoinToken reads the OPERATOR's join-token file and returns its text
// and the parsed token, refusing a file that is missing, readable by anyone but
// its owner, empty, or not a k3sm join token.
//
// It is one function rather than a check at each caller because both callers ask
// the identical question of the identical file — the join-endpoint preflight
// needs the token's cluster-CA pin before anything is written, and staging needs
// the bytes — and two readers of one credential file would eventually disagree
// about which files are acceptable.
func operatorJoinToken(sys System, cfg Config) (string, bootstrap.Token, error) {
	// The mode BEFORE the bytes: a credential this Mac should not have accepted
	// is refused without being read anywhere else first.
	switch perm, err := sys.FileMode(cfg.TokenFile); {
	case errors.Is(err, fs.ErrNotExist):
		return "", bootstrap.Token{}, fmt.Errorf("install: the join token file %s is not there: write the token `k3sm token create` printed on the server into it, or drop --token-file on a node that has already joined", cfg.TokenFile)
	case err != nil:
		return "", bootstrap.Token{}, fmt.Errorf("install: inspect the join token file %s: %w", cfg.TokenFile, err)
	case perm&tokenFileMask != 0:
		return "", bootstrap.Token{}, fmt.Errorf("install: the join token file %s is mode %#o: a join token is a credential, so the file must not be readable by its group or by other accounts — `chmod 600 %s`, and mint a fresh token if it has been exposed", cfg.TokenFile, perm, cfg.TokenFile)
	}
	raw, err := sys.ReadFile(cfg.TokenFile)
	if err != nil {
		return "", bootstrap.Token{}, fmt.Errorf("install: read the join token file %s: %w (it is read once, by root, and copied to %s for the agent daemon to present)", cfg.TokenFile, err, cfg.agentTokenPath())
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", bootstrap.Token{}, fmt.Errorf("install: the join token file %s is empty: write the token `k3sm token create` printed on the server into it", cfg.TokenFile)
	}
	// The shape, before a byte is written anywhere. The parse error is quoted
	// and the token is not: pkg/bootstrap's errors describe the STRUCTURE that
	// is missing (the K10 prefix, the `::`, the user:secret) and never the
	// value, which is what makes it safe to put in front of an operator.
	tok, err := bootstrap.ParseToken(token)
	if err != nil {
		return "", bootstrap.Token{}, fmt.Errorf("install: the contents of the join token file %s are not a k3sm join token (%v): a join token is `K10<cluster-CA hash>::<user>:<secret>`, exactly as `k3sm token create` prints it on the server — mint a fresh one rather than editing this file", cfg.TokenFile, err)
	}
	return token, tok, nil
}

// tokenFileMask is the permission bits a join-token file may not carry: any
// group or other access at all. It is ssh(1)'s rule for a private key, for the
// same reason — the file IS the credential for as long as it exists.
//
// The agent applies the identical mask to the file it is pointed at
// (cmd/k3sm's own tokenFileMask). The two are separate because the packages
// cannot import each other, and they are the same number because the question
// is the same one asked of the same kind of file.
const tokenFileMask fs.FileMode = 0o077
