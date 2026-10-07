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

package defaults

const (
	// ServiceUser is the unprivileged, no-login system user the control
	// plane, node, runtimed, and Service proxy all run as.
	ServiceUser = "_k3sm"
	// ServiceCIDR is the cluster Service CIDR the netd daemon pins so the
	// proxy's ClusterIP VIP aliases are admitted.
	ServiceCIDR = "10.43.0.0/16"
	// PathShimName is the basename of the path-rebase DYLD shim (runtimed's
	// shim/pathrebase_shim.c) installed beside the binary. runtimed resolves it
	// next to the executable and injects it into a mounting pod so an absolute
	// volume mount resolves under the pod data volume (no chroot).
	PathShimName = "libk3sm_pathrebase_shim.dylib"
	// DNSShimName is the basename of the getaddrinfo DNS shim (darwin-net's
	// shim/getaddrinfo_shim.c) installed beside the binary. The provider resolves it
	// next to the executable and injects it into each pod (DYLD_INSERT_LIBRARIES) so
	// an in-pod cluster-name lookup goes to the per-node resolver on the DNS VIP;
	// without it a pod uses the system resolver and cluster names are NXDOMAIN.
	DNSShimName = "libk3sm_getaddrinfo_shim.dylib"
)
