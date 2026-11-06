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

package updater

import (
	"context"
	"io"
	"time"
)

// MemberKind is what a manifest member is.
type MemberKind string

const (
	// MemberMachO is a Mach-O executable or library; the Apple check covers it.
	MemberMachO MemberKind = "mach-o"
	// MemberVersionMarker is a small text file copied as data.
	MemberVersionMarker MemberKind = "version-marker"
	// MemberData is any other declared non-code file.
	MemberData MemberKind = "data"
)

// Member is one file of a release as its signed manifest lists it.
type Member struct {
	// Path is the member's clean slash-separated path inside the release.
	Path string
	// SHA256 is the member's lowercase hex sha256.
	SHA256 string
	// Kind is the member's kind.
	Kind MemberKind
}

// Manifest is the signed description of a release, as the verifier returns it
// after the signature check.
type Manifest struct {
	// Version is the release version. It is a signed string, not yet a safe
	// path element: layout.ValidateVersion runs before any path is built.
	Version string
	// KubeMinor is the Kubernetes minor the release ships.
	KubeMinor string
	// CompatibleFrom is the oldest installed version the release may update.
	CompatibleFrom string
	// RequiresInstaller is true when only the installer may apply the release.
	RequiresInstaller bool
	// ArchiveSHA256 is the lowercase hex sha256 of the whole archive.
	ArchiveSHA256 string
	// Members lists every file the release carries.
	Members []Member
}

// SignedInput is what the k3sm leg checks a copied archive against. Every field
// comes from a root-only copy.
type SignedInput struct {
	// ClusterCAPEM is the root-owned CA copy.
	ClusterCAPEM []byte
	// SignerCertPEM is the update signer's certificate.
	SignerCertPEM []byte
	// Manifest is the manifest exactly as it was signed.
	Manifest []byte
	// Signature is the signature over Manifest.
	Signature []byte
	// Now is the time the signer's validity is checked at.
	Now time.Time
}

// PayloadVerifier is the k3sm leg: it verifies the signature, the archive's
// digest and every member, and extracts the archive into dst, an empty private
// directory. It returns the manifest only when every check passed. A refusal
// may leave a partial extraction in dst, which the caller discards.
type PayloadVerifier interface {
	VerifyPayload(ctx context.Context, in SignedInput, archive io.ReadSeeker, dst string) (*Manifest, error)
}

// CodeVerifier is the Apple leg for one Mach-O: its signature satisfies the
// compiled requirement with identifier io.k3sm.<binary>, its entitlements are
// allowed for binary, and the version in its signed section equals version.
type CodeVerifier interface {
	VerifyCode(ctx context.Context, path, binary, version string) error
}

// Restarter restarts one launchd job.
type Restarter interface {
	Kickstart(ctx context.Context, label string) error
}

// Probe is one health check after a swap.
type Probe string

// The health checks. A worker runs the first three, a server all five.
const (
	// ProbeJobs asks whether every k3sm launchd job is running.
	ProbeJobs Probe = "jobs"
	// ProbeNetd asks whether netd answers its status verb with the mesh up.
	ProbeNetd Probe = "netd"
	// ProbeAgentReady asks whether the restarted agent reported it registered
	// and wrote Ready.
	ProbeAgentReady Probe = "agent-ready"
	// ProbeReadyz asks whether the apiserver's /readyz answers healthy.
	ProbeReadyz Probe = "readyz"
	// ProbeKineRead asks whether one read through kine succeeds.
	ProbeKineRead Probe = "kine-read"
)

// NodeHealth is how the updater sees the node after a swap.
type NodeHealth interface {
	// DataRootMounted reports whether the data root is mounted.
	DataRootMounted(ctx context.Context) (bool, error)
	// Check runs one probe and returns nil when it is green.
	Check(ctx context.Context, p Probe) error
}

// PodUsage reports the versions running pods were started under, which a prune
// keeps and a stage may not overwrite.
type PodUsage interface {
	InUseVersions(ctx context.Context) ([]string, error)
}

// Clock drives every deadline.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// BootID names this boot of the machine; it changes across a reboot.
	BootID() (string, error)
}
