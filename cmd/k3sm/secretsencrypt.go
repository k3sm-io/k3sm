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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

const secretsEncryptUsage = `Usage: k3sm secrets-encrypt status [flags]

Report whether Secrets are encrypted at rest on this control plane. Encryption
is enabled only by 'k3sm install --secrets-encryption' on a new cluster.

  status   print enabled, disabled, or refused (with the reason), the
           provider, the configuration path and its mode. The key is never
           printed. Exits non-zero when the state would stop the control
           plane from starting, or cannot be read (run it with sudo).

Flags:
  --work-dir <dir>            control-plane state root (default: this posture's work dir)
  --datastore-endpoint <dsn>  the server's datastore DSN, when it has one
                              (default: $K3SM_DATASTORE_ENDPOINT)
  --server-join               the server joins an HA control plane
`

// Exit codes of `k3sm secrets-encrypt`.
const (
	secretsEncryptOK       = 0
	secretsEncryptRefused  = 1
	secretsEncryptBadUsage = 2
)

// runSecretsEncrypt dispatches `k3sm secrets-encrypt`. Its only verb is
// status; it reads, and never writes, the credential pair.
func runSecretsEncrypt(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, secretsEncryptUsage)
		return secretsEncryptBadUsage
	}
	switch args[0] {
	case "status":
		return runSecretsEncryptStatus(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, secretsEncryptUsage)
		return secretsEncryptOK
	default:
		fmt.Fprintf(stderr, "k3sm secrets-encrypt: unknown subcommand %q (want: status)\n", args[0])
		return secretsEncryptBadUsage
	}
}

func runSecretsEncryptStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("secrets-encrypt status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, secretsEncryptUsage) }
	workDir := snapshotWorkDirFlag(fs)
	endpoint := fs.String("datastore-endpoint", os.Getenv("K3SM_DATASTORE_ENDPOINT"), "the server's datastore DSN, when it has one (or $K3SM_DATASTORE_ENDPOINT)")
	serverJoin := fs.Bool("server-join", false, "the server joins an HA control plane")
	if err := fs.Parse(args); err != nil {
		return secretsEncryptBadUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "k3sm secrets-encrypt status takes no positional arguments (got %q)\n", fs.Arg(0))
		return secretsEncryptBadUsage
	}
	return renderSecretsEncryptStatus(stdout, *workDir, *endpoint != "" || *serverJoin, daemonUID(*workDir))
}

// daemonUID is the uid the control plane runs as, which the key file must be
// owned by. Unprivileged, status runs as that user (the server's own check
// uses its euid). As root, the daemon is whoever owns its work dir: the
// service user on an installed Mac, root in the run-as-root posture.
func daemonUID(workDir string) uint32 {
	euid := uint32(os.Geteuid())
	if euid != 0 {
		return euid
	}
	if _, uid, err := (executor.OSEncryptionStore{}).Lstat(workDir); err == nil {
		return uid
	}
	return euid
}

// renderSecretsEncryptStatus prints the start verdict the server would reach
// for workDir, from the same predicate it uses, and returns the exit code.
func renderSecretsEncryptStatus(w io.Writer, workDir string, ha bool, expectedUID uint32) int {
	path := executor.EncryptionConfigPath(workDir)
	in, err := executor.ReadEncryptionStartInputs(executor.OSEncryptionStore{}, workDir, ha, expectedUID)
	var enabled bool
	if err == nil {
		enabled, err = executor.DecideEncryptionAtStart(in)
	}
	state := "disabled"
	code := secretsEncryptOK
	switch {
	case err != nil:
		state = "refused (" + err.Error() + ")"
		code = secretsEncryptRefused
	case enabled:
		state = "enabled"
	}
	mode := "absent"
	if fi, serr := os.Stat(path); serr == nil {
		mode = fmt.Sprintf("%#o", fi.Mode().Perm())
	} else if !os.IsNotExist(serr) {
		mode = "unknown (" + serr.Error() + ")"
	}
	provider := executor.EncryptionProviderName
	if !enabled {
		provider = "none"
	}
	fmt.Fprintf(w, "secrets encryption: %s\n", state)
	fmt.Fprintf(w, "provider:           %s\n", provider)
	fmt.Fprintf(w, "config:             %s\n", path)
	fmt.Fprintf(w, "mode:               %s\n", mode)
	return code
}

// parkWhileEncryptionRefused is the start refusal for secrets encryption. Like
// parkUntilCleared it keeps the daemon resident and idle instead of exiting,
// because the server plist's KeepAlive would respawn an exit straight back
// into the same refusal. It re-reads the credential pair every poll and
// returns nil once the start verdict no longer refuses (an operator restored
// the key file), so launchd starts a clean boot, or when ctx is done.
func parkWhileEncryptionRefused(ctx context.Context, workDir string, ha bool, expectedUID uint32, poll time.Duration, logger *slog.Logger) error {
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("parked control plane received a stop; exiting")
			return nil
		case <-t.C:
			if _, err := executor.EncryptionAtStart(executor.OSEncryptionStore{}, workDir, ha, expectedUID); err == nil {
				logger.Info("the secrets encryption refusal is resolved; exiting so launchd starts a clean boot")
				return nil
			}
		}
	}
}
