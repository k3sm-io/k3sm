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
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// The BUILDER TOKEN: the credential a user pushes to the cluster registry with,
// from any Mac. It is a TokenRequest for the k3sm-registry/builder
// ServiceAccount, audience registrysvc.RegistryAudience, minted through the
// caller's own kubeconfig, so who may push is exactly who the cluster's RBAC
// lets create that ServiceAccount's token: an admin kubeconfig, or a user an
// admin bound k3sm:registry-builder-token to.
//
// The token is short-lived and lives in this process's memory. It is never
// logged and never written to disk, except by `k3sm registry login` into the
// docker config file the user asked for.

// defaultBuilderTokenDuration is the lifetime `k3sm registry token` asks for
// when --duration is not given.
const defaultBuilderTokenDuration = time.Hour

// minBuilderTokenDuration is the shortest lifetime the apiserver issues a
// TokenRequest for (ten minutes); a shorter request is refused here rather than
// sent.
const minBuilderTokenDuration = 10 * time.Minute

// builderTokenUser is the username a builder token is presented with. The push
// gate ignores it: the token is the whole credential.
const builderTokenUser = "builder"

// errNoUserKubeconfig reports that this account has no kubeconfig to mint a
// builder token through.
var errNoUserKubeconfig = errors.New("no kubeconfig to mint a registry push token with")

// errBuilderTokenRefused reports that the cluster would not mint a builder
// token for this kubeconfig's identity.
var errBuilderTokenRefused = errors.New("the cluster refused to mint a registry push token")

// errBuilderTokenDuration reports a lifetime the apiserver will not issue.
var errBuilderTokenDuration = errors.New("the requested token lifetime is not one the cluster issues")

// builderTokenRemedy is the fix for a Mac with no kubeconfig: write one with
// the admin copy, as `k3sm kubeconfig` does on any Mac.
const builderTokenRemedy = "write one with `k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write`, run with the admin kubeconfig copied from the server (a worker writes no user kubeconfig); or have an admin bind the k3sm:registry-builder-token Role to you with a RoleBinding in " + registrysvc.BuilderNamespace

// serviceAccountTokens is the slice of the Kubernetes API a builder token is
// minted through. cs.CoreV1().ServiceAccounts(ns) satisfies it.
type serviceAccountTokens interface {
	CreateToken(ctx context.Context, serviceAccountName string, tr *authnv1.TokenRequest, opts metav1.CreateOptions) (*authnv1.TokenRequest, error)
}

// builderToken is a minted token and when it stops being valid. String never
// prints the token.
type builderToken struct {
	value   string
	expires time.Time
}

// String redacts the token, so a %v of one in an error or a log line carries
// only its expiry.
func (t builderToken) String() string {
	return "builder token (expires " + t.expires.UTC().Format(time.RFC3339) + ")"
}

// mintBuilderToken asks the cluster for a token for the builder ServiceAccount,
// audience registrysvc.RegistryAudience, valid for d. A token the apiserver
// issued for LESS than d means d is above its maximum, and is refused rather
// than handed back as if it were what was asked for.
func mintBuilderToken(ctx context.Context, sa serviceAccountTokens, d time.Duration, now func() time.Time) (builderToken, error) {
	if d < minBuilderTokenDuration {
		return builderToken{}, fmt.Errorf("%w: %s is below the minimum of %s", errBuilderTokenDuration, d, minBuilderTokenDuration)
	}
	secs := int64(d / time.Second)
	asked := now()
	resp, err := sa.CreateToken(ctx, registrysvc.BuilderServiceAccount, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences:         []string{registrysvc.RegistryAudience},
			ExpirationSeconds: &secs,
		},
	}, metav1.CreateOptions{})
	switch {
	case apierrors.IsForbidden(err):
		return builderToken{}, fmt.Errorf("%w: this kubeconfig may not create tokens for %s/%s; an admin can bind the k3sm:registry-builder-token Role to you with a RoleBinding in %s",
			errBuilderTokenRefused, registrysvc.BuilderNamespace, registrysvc.BuilderServiceAccount, registrysvc.BuilderNamespace)
	case apierrors.IsNotFound(err):
		return builderToken{}, fmt.Errorf("%w: the %s/%s ServiceAccount does not exist; a server creates it on start, so this cluster's server predates it",
			errBuilderTokenRefused, registrysvc.BuilderNamespace, registrysvc.BuilderServiceAccount)
	case err != nil:
		return builderToken{}, fmt.Errorf("mint a token for %s/%s: %w", registrysvc.BuilderNamespace, registrysvc.BuilderServiceAccount, err)
	case resp == nil || resp.Status.Token == "":
		return builderToken{}, fmt.Errorf("%w: the apiserver answered with no token", errBuilderTokenRefused)
	}
	exp := resp.Status.ExpirationTimestamp.Time
	// A minute of slack covers the round trip and clock skew between this Mac
	// and the server; a clamp to the apiserver's maximum is far larger.
	if exp.Before(asked.Add(d - time.Minute)) {
		return builderToken{}, fmt.Errorf("%w: %s is above the cluster's maximum (it issued a token valid until %s)",
			errBuilderTokenDuration, d, exp.UTC().Format(time.RFC3339))
	}
	return builderToken{value: resp.Status.Token, expires: exp}, nil
}
