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
	"log/slog"
	"time"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/helmchart/controller"
)

// runHelmController runs the HelmChart controller (the k3s helm-controller
// analog) until ctx is done: it resolves the staged helm, ensures the two
// helm.k3sm.io CRDs, and reconciles HelmCharts while this server holds the
// k3sm-helm-controller Lease. It uses the admin client, as k3s's helm-controller
// runs with the server's own credentials; the Jobs it creates run as their own
// per-chart identity.
//
// Every failure is logged here and ends only this surface, exactly like
// runManifestDir: HelmChart support is optional, and nothing it does is
// returned to bring-up or to the control plane's tear-down.
//
// helm normally arrives in the payload and is seeded into the work dir's bin at
// boot. When it is absent, awaitHelm keeps re-checking every helmRetryInterval
// until it is staged: a daemon re-checks the work dir only (EnsureHelm never
// fetches without `gh`), a dev shell retries the verified download. This runs
// in its own goroutine, off the bring-up path.
func runHelmController(ctx context.Context, adminCfg *rest.Config, admin kubernetes.Interface, workDir, nodeName string, logger *slog.Logger) {
	bd := executor.BinDir(workDir)
	helmPath, err := awaitHelm(ctx, func(ctx context.Context) (string, error) {
		return executor.EnsureHelm(ctx, bd)
	}, helmRetryInterval, logger)
	if err != nil {
		return
	}
	dyn, err := dynamic.NewForConfig(adminCfg)
	if err != nil {
		logger.Error("helm controller disabled: build its dynamic client", "err", err)
		return
	}
	crd, err := apiextensionsclient.NewForConfig(adminCfg)
	if err != nil {
		logger.Error("helm controller disabled: build its apiextensions client", "err", err)
		return
	}
	ctrl, err := controller.New(controller.Config{
		Client:   admin,
		Dynamic:  dyn,
		CRD:      crd,
		HelmPath: helmPath,
		Identity: nodeName,
		Log:      logger,
	})
	if err != nil {
		logger.Error("helm controller disabled: build it", "err", err)
		return
	}
	if err := ctrl.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("helm controller", "err", err)
	}
}

// helmRetryInterval is how often awaitHelm re-checks for a staged helm.
const helmRetryInterval = 60 * time.Second

// awaitHelm calls ensure until it succeeds or ctx is done, waiting interval
// between tries. A one-shot failure would disable HelmCharts for the life of
// the process over a transient fault (a dropped download, a payload restaged
// after boot), so it retries. Each distinct error is logged once, not on every
// tick, so a daemon waiting on a reinstall does not flood its log. The error it
// returns is ctx's.
func awaitHelm(ctx context.Context, ensure func(context.Context) (string, error), interval time.Duration, logger *slog.Logger) (string, error) {
	var last string
	for {
		path, err := ensure(ctx)
		if err == nil {
			if last != "" {
				logger.Info("helm staged; starting the helm controller", "path", path)
			}
			return path, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if msg := err.Error(); msg != last {
			last = msg
			logger.Error("helm controller waiting: stage the pinned helm", "err", err, "retry", interval,
				"remedy", "re-run `sudo k3sm install` with a payload staged by `k3sm payload`, which carries helm")
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return "", ctx.Err()
		case <-t.C:
		}
	}
}
