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
	"os"
	"os/signal"
	"syscall"

	"k3sm.io/k3sm/pkg/executor"
)

// runPayload is `k3sm payload <dir>`: stage the control-plane payload
// (kube-apiserver/scheduler/controller-manager/kubectl + kine) into <dir> using
// the executor's own pinned versions and acquisition code. It is the
// packaging-side PRODUCER — run it in a shell that has `gh` and the Go toolchain
// (a dev Mac, goreleaser); `k3sm install` then stages <dir> beside the daemon so
// the launchd boot (which has neither tool) seeds from it.
func runPayload(args []string) error {
	fs := flag.NewFlagSet("payload", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: k3sm payload <dir>  — stage the control-plane payload (needs gh + go on PATH)")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("payload needs exactly one destination directory")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := executor.StagePayload(ctx, fs.Arg(0)); err != nil {
		return err
	}
	fmt.Printf("staged control-plane payload (%s + kine %s) -> %s\n",
		executor.DefaultKubeVersion, executor.DefaultKineVersion, fs.Arg(0))
	return nil
}
