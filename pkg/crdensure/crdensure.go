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

package crdensure

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

// DefaultFieldManager is the server-side-apply field manager an ensure writes
// under when Options names none: the bare "k3sm".
//
// It is deliberately distinct from the add-on reconciler's "k3sm-addons"
// (pkg/addons). Two independent appliers sharing one manager name each take
// ownership of the other's fields and fight over them on every boot, so the bare
// name is reserved for exactly this applier.
const DefaultFieldManager = "k3sm"

// Ensure defaults. The timeout is generous because establishment waits on the
// API server building a REST handler, which on a cold control plane trails the
// write by seconds; the interval is short because the transition is a single
// step and a long interval only adds latency to every boot.
const (
	defaultTimeout      = 60 * time.Second
	defaultPollInterval = 250 * time.Millisecond
)

// Ensure errors. They are sentinels so a caller can branch on the CLASS of
// failure — a malformed manifest is a build defect, a non-established CRD is an
// operational one — without matching on message text. Each is returned wrapped
// with the manifest's name where one could be read.
var (
	// ErrNoManifest is returned for empty manifest bytes. An empty manifest is
	// always a wiring mistake (a lost embed, a nil accessor result), and applying
	// nothing successfully would hide it until the first custom resource 404s.
	ErrNoManifest = errors.New("crd manifest is empty")
	// ErrNotCRD is returned when the manifest does not declare an
	// apiextensions.k8s.io/v1 CustomResourceDefinition. Applying some other kind
	// through this path would create an object nobody asked for under the CRD
	// applier's field manager.
	ErrNotCRD = errors.New("manifest is not an apiextensions.k8s.io/v1 CustomResourceDefinition")
	// ErrUnnamed is returned when the manifest declares no metadata.name.
	// Server-side apply is keyed by name, so an unnamed manifest has no identity
	// to converge onto.
	ErrUnnamed = errors.New("crd manifest declares no metadata.name")
	// ErrNamesRejected is returned when the API server refuses the CRD's names —
	// almost always because another CRD already owns the group/plural. It is
	// separate from ErrNotEstablished because it never resolves by waiting: the
	// conflicting CRD has to go first.
	ErrNamesRejected = errors.New("crd names were rejected by the api server")
	// ErrNotEstablished is returned when the CRD did not reach the Established
	// condition within the timeout. Returning rather than proceeding is the
	// point: the custom resource's REST handler does not exist yet, so an
	// informer started now 404s and retries forever.
	ErrNotEstablished = errors.New("crd did not become established")
)

// Options tunes one Ensure call. The zero value is usable and means the bare
// "k3sm" field manager with the default timings.
type Options struct {
	// FieldManager is the server-side-apply field manager. Empty means
	// DefaultFieldManager.
	FieldManager string
	// Timeout bounds the wait for the Established condition. Zero means 60s. It
	// bounds only the wait: a cancelled ctx aborts sooner.
	Timeout time.Duration
	// PollInterval is how often the Established condition is re-read. Zero means
	// 250ms.
	PollInterval time.Duration
	// Log is the structured logger. nil means slog.Default().
	Log *slog.Logger
}

// withDefaults returns o with every unset field replaced by its default, so the
// zero Options is usable and no call site has to restate the defaults.
func (o Options) withDefaults() Options {
	if o.FieldManager == "" {
		o.FieldManager = DefaultFieldManager
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.PollInterval <= 0 {
		o.PollInterval = defaultPollInterval
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return o
}

// Ensure server-side-applies the single CustomResourceDefinition in manifest and
// blocks until the API server reports it Established.
//
// manifest is one YAML document — the bytes a caller got from its embedded
// manifest accessor, applied verbatim (see the package doc). It is safe to call
// on every start: an apply of identical bytes under the same field manager is a
// no-op at the API server, and a CRD that is already established satisfies the
// wait on its first poll.
//
// It returns the established CRD as the API server stored it, so a caller that
// wants to log the served version or read back a condition does not need a
// second round trip.
func Ensure(ctx context.Context, c apiextensionsclient.Interface, manifest []byte, opts Options) (*apiextensionsv1.CustomResourceDefinition, error) {
	opts = opts.withDefaults()

	name, body, err := decode(manifest)
	if err != nil {
		return nil, err
	}

	// A raw apply-patch, not a typed Apply: the bytes on the wire are the
	// manifest's own JSON, so no field is lost to a compiled-in type that predates
	// it. Force is set because a field another manager has claimed would otherwise
	// wedge convergence forever, with a silently-stale schema as the only symptom.
	if _, err := c.ApiextensionsV1().CustomResourceDefinitions().Patch(ctx, name, types.ApplyPatchType, body,
		metav1.PatchOptions{FieldManager: opts.FieldManager, Force: ptr.To(true)}); err != nil {
		return nil, fmt.Errorf("apply crd %s: %w", name, err)
	}

	established, err := waitEstablished(ctx, c, name, opts)
	if err != nil {
		return nil, err
	}
	opts.Log.Debug("ensured customresourcedefinition",
		"crd", name, "fieldManager", opts.FieldManager, "resourceVersion", established.ResourceVersion)
	return established, nil
}

// decode converts one YAML manifest document to the JSON that will be applied and
// returns the object's name alongside it.
//
// The typed decode is a VALIDATION step only — its result is deliberately
// discarded. Applying a re-marshalling of the typed struct would drop any field
// the compiled-in apiextensions types do not know, which for a schema document
// means shipping a quietly smaller CRD than the manifest describes.
func decode(manifest []byte) (name string, body []byte, err error) {
	if len(manifest) == 0 {
		return "", nil, ErrNoManifest
	}
	body, err = yaml.YAMLToJSON(manifest)
	if err != nil {
		return "", nil, fmt.Errorf("convert crd manifest yaml to json: %w", err)
	}

	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(manifest, &crd); err != nil {
		return "", nil, fmt.Errorf("decode crd manifest: %w", err)
	}
	if crd.APIVersion != apiextensionsv1.SchemeGroupVersion.String() || crd.Kind != "CustomResourceDefinition" {
		return "", nil, fmt.Errorf("%w: got %s %s", ErrNotCRD, crd.APIVersion, crd.Kind)
	}
	if crd.Name == "" {
		return "", nil, ErrUnnamed
	}
	return crd.Name, body, nil
}

// waitEstablished polls the CRD until the API server has built its REST handler.
//
// NamesAccepted=False short-circuits the wait: a group/plural already owned by
// another CRD is a conflict that cannot resolve on its own, and burning the whole
// timeout on it turns a legible error into a slow, generic one.
func waitEstablished(ctx context.Context, c apiextensionsclient.Interface, name string, opts Options) (*apiextensionsv1.CustomResourceDefinition, error) {
	var (
		last   *apiextensionsv1.CustomResourceDefinition
		fatal  error
		client = c.ApiextensionsV1().CustomResourceDefinitions()
	)
	waitErr := wait.PollUntilContextTimeout(ctx, opts.PollInterval, opts.Timeout, true,
		func(ctx context.Context) (bool, error) {
			crd, err := client.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				// A transient read failure is retried: the object was just applied
				// successfully, so its absence here is a watch-cache or apiserver
				// hiccup rather than a verdict.
				return false, nil
			}
			last = crd
			for _, cond := range crd.Status.Conditions {
				switch {
				case cond.Type == apiextensionsv1.NamesAccepted && cond.Status == apiextensionsv1.ConditionFalse:
					fatal = fmt.Errorf("%w: crd %s: %s: %s", ErrNamesRejected, name, cond.Reason, cond.Message)
					return false, fatal
				case cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue:
					return true, nil
				}
			}
			return false, nil
		})
	if fatal != nil {
		return nil, fatal
	}
	if waitErr != nil {
		return nil, fmt.Errorf("%w: crd %s within %s: %w", ErrNotEstablished, name, opts.Timeout, waitErr)
	}
	return last, nil
}
