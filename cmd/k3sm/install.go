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
	"log/slog"
	"os"

	"k3sm.io/k3sm/pkg/install"
)

// runInstall lays down k3sm's two root LaunchDaemons (io.k3sm.netd as root,
// io.k3sm.server as the _k3sm user) via the install package's system seam. It is
// the single root step (run as `sudo k3sm install`): it copies THIS binary into
// the root-owned install dir, writes the plists, bootstraps both daemons, and
// writes the admin kubeconfig to the invoking human's home ($SUDO_USER), owned by
// them. The Homebrew formula that invokes this and the notarize/signing pipeline
// are the packaging follow-up.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	targetUser := fs.String("user", os.Getenv("SUDO_USER"), "the human whose ~/.kube/config receives the admin kubeconfig (default $SUDO_USER)")
	serviceCIDR := fs.String("service-cidr", install.DefaultServiceCIDR, "cluster Service CIDR")
	printRequired := fs.Bool("print-required-artifacts", false, "print the artifacts that must sit beside this binary (one per line, relative) and exit; needs no privilege")
	_ = fs.Parse(args)

	// Read-only introspection of the layout contract, deliberately BEFORE the
	// root check: the release tooling asserts an extracted archive's member set
	// against this output, and must be able to do so unprivileged. Paths are
	// printed relative so the caller can join them onto any directory.
	if *printRequired {
		for _, p := range install.RequiredSiblings("") {
			fmt.Println(p)
		}
		return nil
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm install must run as root — use 'sudo k3sm install'")
	}
	if *targetUser == "" || *targetUser == "root" {
		return fmt.Errorf("--user (or $SUDO_USER) must be a non-root human so the kubeconfig is not root-owned; run via 'sudo k3sm install'")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own binary path: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()
	return install.Install(ctx, install.NewDarwinSystem(), install.Config{
		BinarySource: self,
		TargetUser:   *targetUser,
		ServiceCIDR:  *serviceCIDR,
		Logger:       logger,
	})
}

// runUninstall boots out both LaunchDaemons (the netd helper flushes lo0/pf/utun
// on SIGTERM) and removes the install dir. It requires root and is idempotent.
func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm uninstall must run as root — use 'sudo k3sm uninstall'")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return install.Uninstall(context.Background(), install.NewDarwinSystem(), install.Config{Logger: logger})
}
