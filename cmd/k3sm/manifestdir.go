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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/rbac"
)

// runManifestDir provisions the bounded manifest identity with the admin client,
// builds the manifest-directory reconciler on that identity, and runs it until ctx
// is done. Every failure is logged here and ends only this surface: nothing it
// does is returned to bring-up or to the control plane's tear-down.
func runManifestDir(ctx context.Context, adminCfg *rest.Config, admin kubernetes.Interface, logger *slog.Logger) {
	if err := rbac.ProvisionManifestApplier(ctx, admin); err != nil {
		if ctx.Err() == nil {
			logger.Error("manifest dir disabled: provision its identity", "dir", install.ManifestDir, "err", err)
		}
		return
	}
	md, err := addons.NewManifestDirFromAdmin(install.ManifestDir, adminCfg, admin,
		rbac.ManifestApplierNamespace, rbac.ManifestApplierName, logger)
	if err != nil {
		logger.Error("manifest dir disabled: build its reconciler", "dir", install.ManifestDir, "err", err)
		return
	}
	md.Run(ctx)
}
