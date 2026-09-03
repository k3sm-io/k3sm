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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/executor"
)

// buildxSetupTimeout bounds the SETUP a buildx run needs — resolving the
// endpoint, staging the pinned binary, registering the builder instance. The
// build itself is deliberately unbounded: a real RUN build legitimately takes
// longer than any timeout worth guessing, and killing one halfway is worse than
// letting the operator interrupt it.
const buildxSetupTimeout = 15 * time.Minute

// buildxSession is everything an exec of the bundled buildx needs to reach the
// k3sm engine: the verified binary, the k3sm-owned config dir, the endpoint the
// remote driver dials, and the environment that ties them together.
type buildxSession struct {
	bin      string
	cfgDir   string
	endpoint string
	env      []string
}

// newBuildxSession prepares a buildx run against the engine for workDir.
//
// bootstrap decides what an ABSENT engine means. `k3sm builder buildx` passes
// false: the operator is driving buildx directly, so the answer is the legible
// refusal that names `k3sm builder up`. `k3sm build` passes true: a Dockerfile
// that needs a real builder gets one, which is the whole point of there being a
// single build command.
func newBuildxSession(ctx context.Context, workDir string, bootstrap bool, out io.Writer) (buildxSession, error) {
	mgr, err := newBuilderManager(builderOptions{workDir: workDir})
	if err != nil {
		return buildxSession{}, err
	}

	var endpoint string
	if bootstrap {
		st, err := mgr.EnsureRunning(ctx, func(msg string) { fmt.Fprintln(out, msg) })
		if err != nil {
			return buildxSession{}, err
		}
		endpoint = st.Endpoint
		if endpoint == "" {
			// Ready without an endpoint would mean a Service with no ClusterIP;
			// ask the manager rather than guess, so the error is its own.
			if endpoint, err = mgr.Endpoint(ctx); err != nil {
				return buildxSession{}, err
			}
		}
	} else {
		if endpoint, err = mgr.Endpoint(ctx); err != nil {
			return buildxSession{}, err
		}
	}

	bin, err := builder.EnsureHostBuildx(ctx, executor.BinDir(workDir))
	if err != nil {
		return buildxSession{}, err
	}
	cfgDir := builder.HostConfigDir(workDir)
	if err := builder.EnsureBuilderInstance(ctx, bin, cfgDir, endpoint); err != nil {
		return buildxSession{}, err
	}
	return buildxSession{
		bin:      bin,
		cfgDir:   cfgDir,
		endpoint: endpoint,
		env:      builder.BuildxEnv(os.Environ(), cfgDir),
	}, nil
}

// runBuilderBuildx is `k3sm builder buildx <args...>`: the bundled buildx, wired
// to the k3sm engine, with the argv passed through VERBATIM.
//
// Nothing after `buildx` is parsed by k3sm — not even to look for --help. buildx
// owns that argv, and a wrapper that re-read it would break every flag it had
// not been taught. The work dir therefore comes from the environment
// (K3SM_WORK_DIR, else the posture default), never from a k3sm flag that could
// collide with one of buildx's own.
func runBuilderBuildx(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, builderBuildxUsage)
		return errors.New("k3sm builder buildx needs a buildx command, e.g. `k3sm builder buildx build -t myapp:dev .`")
	}

	setupCtx, cancel := context.WithTimeout(context.Background(), buildxSetupTimeout)
	defer cancel()
	sess, err := newBuildxSession(setupCtx, workDirFromEnv(), false, os.Stdout)
	if err != nil {
		return err
	}
	cancel()

	// The build runs on an uncancelled context: setup is bounded, the build is
	// the operator's to interrupt.
	if err := builder.RunBuildx(context.Background(), sess.bin, builder.BuildxArgs(args), sess.env); err != nil {
		// Forward buildx's own exit code so scripts and CI see the real status
		// (the `k3sm kubectl` passthrough precedent).
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

const builderBuildxUsage = `k3sm builder buildx — run the bundled buildx against the k3sm build engine

Usage: k3sm builder buildx <buildx command and flags>

  k3sm builder buildx build -t myapp:dev .
  k3sm builder buildx bake -f bake.hcl target
  k3sm builder buildx build -t myapp:dev -o type=oci,dest=out.oci .

Everything after "buildx" is passed to buildx unchanged. k3sm supplies the
pinned buildx binary, points it at the engine's endpoint with a remote driver,
and injects --builder ` + builder.BuilderInstanceName + `; nothing else is rewritten.

The engine must be running (` + "`k3sm builder up`" + `). Set K3SM_WORK_DIR if the
control plane uses a non-default --work-dir.

Most builds need none of this: ` + "`k3sm build`" + ` uses the same engine
automatically for a Dockerfile that RUNs commands.
`
