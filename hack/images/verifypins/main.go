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

// Command verifypins is the implementation behind hack/verify-image-pins.sh.
//
// It is deliberately thin: every decision lives in k3sm.io/k3sm/pkg/images, so the
// release gate and the unit tests exercise the SAME code. Adding logic here — a second
// digest parser, a second platform comparison — would recreate the drift this tool
// exists to prevent.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/images"
)

func main() {
	var (
		live     = flag.Bool("live", false, "verify each pin against the registry (network; anonymous)")
		manifest = flag.String("manifest", "", "path to the mirror manifest (required)")
		registry = flag.String("registry", "", "override the registry host in every mirror ref (test seam)")
		insecure = flag.Bool("insecure", false, "allow plain HTTP (only with -registry, for a loopback fixture)")
		timeout  = flag.Duration("timeout", 2*time.Minute, "overall deadline for -live")
	)
	flag.Usage = usage
	flag.Parse()

	if *manifest == "" {
		fail("-manifest is required")
	}
	if *insecure && *registry == "" {
		fail("-insecure is only meaningful with -registry (it exists for a loopback fixture)")
	}

	// The constants<->manifest lockstep runs UNLESS the registry is overridden. The
	// condition is tied to its reason: a fixture registry serves fixture content, whose
	// digests are computed from that content and therefore cannot equal the shipped
	// constants. Overriding the manifest alone still runs lockstep — that is exactly how
	// a mutated manifest is proven to fail.
	if *registry == "" {
		if err := images.LockstepFile(*manifest); err != nil {
			fail("lockstep: %v", err)
		}
		fmt.Printf("ok  lockstep: %d pin(s) match %s\n", len(images.Pins()), *manifest)
	} else {
		fmt.Printf("--  lockstep skipped: registry overridden to %s (fixture content cannot match shipped pins)\n", *registry)
	}

	if !*live {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := images.VerifyLiveFile(ctx, *manifest, images.LiveOptions{
		Registry: *registry,
		Insecure: *insecure,
	}); err != nil {
		fail("live: %v", err)
	}
	m, err := images.LoadManifest(*manifest)
	if err != nil {
		fail("live: %v", err)
	}
	fmt.Printf("ok  live: %d entr(ies) present at their recorded digests, anonymously\n", len(m.Images))
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "verify-image-pins: "+format+"\n", a...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(flag.CommandLine.Output(), `verifypins — verify k3sm's digest-pinned image references.

Two orthogonal checks:
  lockstep   the pin constants match the committed mirror manifest (offline)
  live       each manifest entry exists in the registry at its recorded digest,
             with the platforms it claims, fetched ANONYMOUSLY (network)

Together they bind the constants to the registry. Lockstep also rides "go test ./...",
so drift between code and manifest reds every CI run without this tool being invoked.

Flags:
`)
	flag.PrintDefaults()
}
