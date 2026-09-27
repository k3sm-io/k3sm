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
// boot. When it is absent (a dev shell with no payload, or a payload staged by
// an older release) EnsureHelm downloads and verifies the pin, off the bring-up
// path because this runs in its own goroutine.
func runHelmController(ctx context.Context, adminCfg *rest.Config, admin kubernetes.Interface, workDir, nodeName string, logger *slog.Logger) {
	helmPath, err := executor.EnsureHelm(ctx, executor.BinDir(workDir))
	if err != nil {
		if ctx.Err() == nil {
			logger.Error("helm controller disabled: stage the pinned helm", "err", err,
				"remedy", "re-run `sudo k3sm install` with a payload staged by `k3sm payload`, which carries helm")
		}
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
