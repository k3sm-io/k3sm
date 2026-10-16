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

package status

import (
	"errors"
	"io/fs"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/install"
)

// ServicesRecord is what a running server records about its Service proxy: every
// Service port the proxy routes and the Ready backends it routes each one to,
// refreshed every ServicesRecordInterval. The services row compares it with the
// API's EndpointSlices.
type ServicesRecord struct {
	UpdatedAt time.Time  `json:"updatedAt"`
	VIPs      []VIPEntry `json:"vips"`
	// Unproxied are the ClusterIPs the proxy deliberately does not route because
	// another listener on the node owns them (the cluster DNS address). Their
	// Services have no entry in VIPs, and the row does not expect one.
	Unproxied []string `json:"unproxied,omitempty"`
	// Pinned are the Services whose backends the server pins rather than
	// derives from EndpointSlices (the kubernetes Service of a single-node
	// server, whose loopback endpoint no EndpointSlice may carry), with the
	// backends pinned. They are what the proxy must route those ports to, and no
	// API object can say so.
	Pinned []PinnedService `json:"pinned,omitempty"`
}

// PinnedService is one Service the server pins to fixed backends.
type PinnedService struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Backends are the pinned addresses ("ip:port"), sorted.
	Backends []string `json:"backends"`
}

// VIPEntry is one routed Service port as the proxy holds it.
type VIPEntry struct {
	ClusterIP string `json:"clusterIP"`
	Port      int32  `json:"port"`
	// Protocol is "TCP" or "UDP".
	Protocol string `json:"protocol"`
	// Namespace and Name identify the owning Service.
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Policy is the port's internalTrafficPolicy, "Cluster" or "Local".
	Policy string `json:"policy"`
	// Backends are the Ready backend addresses ("ip:port"), sorted; empty, never
	// nil, when the port has none.
	Backends []string `json:"backends"`
	// LocalBackends is how many of Backends run on this node.
	LocalBackends int `json:"localBackends"`
	// Generation numbers the distinct backend sets the proxy has installed for
	// the port.
	Generation uint64 `json:"generation"`
}

// ServicesRecordInterval is how often a server refreshes its ServicesRecord.
const ServicesRecordInterval = 30 * time.Second

// servicesName is the record's basename, beside the mesh claim record.
const servicesName = "services.json"

// ServicesPath is the record's path for a work dir.
func ServicesPath(workDir string) string { return filepath.Join(workDir, servicesName) }

// Dir is the user-readable status directory for a server work dir: the
// StatusSubdir sibling of the work dir, /var/lib/k3sm/status on an install. The
// server writes each record there 0644 as well as 0600 in its own work dir,
// because the records hold cluster-internal names and addresses, never a
// credential, and an ordinary account cannot see inside the 0700 work dir.
func Dir(workDir string) string {
	return filepath.Join(filepath.Dir(workDir), install.StatusSubdir)
}

// UserReadablePath is the user-readable copy, in Dir, of a record whose work-dir
// path is path.
func UserReadablePath(workDir, path string) string {
	return filepath.Join(Dir(workDir), filepath.Base(path))
}

// recordRead is one record read through readRecord.
type recordRead struct {
	raw []byte
	// path is the file that was read, or the one that failed.
	path string
	err  error
}

// readRecord reads a server record at its work-dir path through the FS seam.
// An account that may not read the work dir reads the user-readable copy in Dir
// instead; when Dir is there and holds no copy, the server has not written the
// record yet, which reads as absent. Only when neither answers is the error a
// permission error, the one case that truly needs root.
func (c Collector) readRecord(path string) recordRead {
	raw, err := c.FS.ReadFile(path)
	if !errors.Is(err, fs.ErrPermission) {
		return recordRead{raw: raw, path: path, err: err}
	}
	user := UserReadablePath(c.Paths.WorkDir, path)
	uraw, uerr := c.FS.ReadFile(user)
	switch {
	case uerr == nil:
		return recordRead{raw: uraw, path: user}
	case errors.Is(uerr, fs.ErrNotExist) && c.exists(Dir(c.Paths.WorkDir)):
		return recordRead{path: user, err: uerr}
	}
	return recordRead{path: path, err: err}
}

// recordNeedsAdminDetail is the detail of a record row whose record only root
// can read: the work-dir copy is root-only and the server publishes no
// user-readable one (a server older than the status directory).
func (c Collector) recordNeedsAdminDetail(path string) string {
	return "needs sudo: " + path + " is readable by root only, and no user-readable copy is in " + Dir(c.Paths.WorkDir)
}
