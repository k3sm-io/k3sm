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
	// Posture-aware default (the _k3sm control plane writes <home>/server, not the
	// root-only const); a resolve failure falls back to the const, overridable.
	defaultWorkDir, err := executor.ResolveWorkDir()
	if err != nil {
		defaultWorkDir = executor.DefaultWorkDir
	}
	workDir := fs.String("work-dir", defaultWorkDir, "control-plane state root (the cluster CA + token store live here)")
	ttl := fs.Duration("ttl", 24*time.Hour, "token time-to-live (must be positive; ignored for --server)")
	serverTok := fs.Bool("server", false, "mint a SERVER-class join token (to add an HA control-plane server, M6.1) instead of a worker token")
	_ = fs.Parse(args)

	if !*serverTok && *ttl <= 0 {
		return fmt.Errorf("--ttl must be positive, got %s", *ttl)
	}

	// Ensure the CA hierarchy exists (idempotent — the server uses the same files).
	h, err := certs.EnsureHierarchy(*workDir)
	if err != nil {
		return fmt.Errorf("ensure CA hierarchy: %w", err)
	}

	// M6.1: a SERVER token reconstructs the cluster CAs (it authorizes the CA-bundle
	// endpoint and its secret is the bundle's KDF passphrase). It is stable (not
	// TTL-bounded) and DISTINCT from a worker token — give it only to a trusted
	// control-plane Mac. A leaked WORKER token can never reconstruct the signing CA.
	if *serverTok {
		secret, err := bootstrap.LoadOrCreateServerSecret(serverSecretPath(*workDir))
		if err != nil {
			return fmt.Errorf("server-bootstrap secret: %w", err)
		}
		fmt.Println(bootstrap.FormatServerToken(h.Cluster.PinHash(), secret))
		fmt.Fprintln(os.Stderr, "# k3sm SERVER join token — authorizes reconstructing the cluster CAs; give ONLY to a trusted control-plane Mac")
		return nil
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
