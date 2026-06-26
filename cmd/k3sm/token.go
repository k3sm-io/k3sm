package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

// runToken dispatches the `k3sm token` subcommands (currently only `create`).
func runToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: k3sm token create [--ttl <dur>] [--work-dir <dir>]")
	}
	switch args[0] {
	case "create":
		return runTokenCreate(args[1:])
	default:
		return fmt.Errorf("unknown token subcommand %q (want: create)", args[0])
	}
}

// runTokenCreate mints a TTL-bounded worker-join token of the form
// K10<sha256(cluster-CA)>::<user>:<secret>. The CA-hash prefix is what the joining
// node pins the server's TLS chain against (NOT insecure-skip), and the credential
// is distinct from — and far less privileged than — the system:masters admin token:
// it authorizes only submitting a node-password + CSR and receiving a node-scoped
// credential. It is stored hashed (bcrypt) in the work dir's bootstrap-token store.
func runTokenCreate(args []string) error {
	fs := flag.NewFlagSet("token create", flag.ExitOnError)
	workDir := fs.String("work-dir", executor.DefaultWorkDir, "control-plane state root (the cluster CA + token store live here)")
	ttl := fs.Duration("ttl", 24*time.Hour, "token time-to-live (must be positive)")
	_ = fs.Parse(args)

	if *ttl <= 0 {
		return fmt.Errorf("--ttl must be positive, got %s", *ttl)
	}

	// Ensure the CA hierarchy exists (idempotent — the server uses the same files).
	h, err := certs.EnsureHierarchy(*workDir)
	if err != nil {
		return fmt.Errorf("ensure CA hierarchy: %w", err)
	}

	store := bootstrap.NewFileTokenStore(bootstrap.TokensPath(*workDir), nil)
	user, secret, expiry, err := store.Create(*ttl)
	if err != nil {
		return fmt.Errorf("mint token: %w", err)
	}

	fmt.Println(bootstrap.FormatToken(h.Cluster.PinHash(), user, secret))
	fmt.Fprintf(os.Stderr, "# k3sm join token (expires %s) — pins the cluster CA; NOT the admin token\n", expiry.Format(time.RFC3339))
	return nil
}
