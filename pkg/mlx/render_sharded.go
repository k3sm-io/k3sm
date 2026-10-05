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

package mlx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// Sharded render errors. Like the single-node ones, every one is returned
// wrapped with the model's namespace/name; branch with errors.Is.
var (
	// ErrNotDistributed is returned by RenderSharded for a spec that does not
	// set spec.distributed: there is nothing to shard.
	ErrNotDistributed = errors.New("spec.distributed is not set")
	// ErrInvalidRanks is returned for a rank count below two. One rank is a
	// single-node model, which the StatefulSet path serves.
	ErrInvalidRanks = errors.New("spec.distributed.ranks must be at least 2")
	// ErrShardedReplicas is returned for a sharded spec asking for more than one
	// replica. A sharded model is ONE logical replica spanning its ranks; two
	// would need two disjoint placements and a router between them, neither of
	// which exists.
	ErrShardedReplicas = errors.New("a sharded model is one logical replica: spec.replicas must be unset, 0 or 1")
	// ErrPlacementMismatch is returned when the placement handed to
	// RenderSharded does not describe exactly spec.distributed.ranks ranks on
	// distinct nodes with a resolved backend. It is a caller bug, never a spec
	// problem.
	ErrPlacementMismatch = errors.New("placement does not match spec.distributed")
	// ErrCollectivePortConflict is returned when the serving port equals the
	// rank-to-rank collective port, which rank 0 would then try to bind twice.
	ErrCollectivePortConflict = errors.New("spec.port collides with the sharded collective port")
)

// Sharded-render constants. Each is a contract with the k3sm-shard entrypoint
// in hack/images/mlx-serve, which reads the environment named here.
const (
	// LabelRank is the label every rank Pod and its cache claim carry, holding
	// the rank index ("0", "1", …). The ClusterIP Service selects rank 0 through
	// it, and the operator finds a model's rank Pods by its presence.
	LabelRank = "k3sm.io/mlx-rank"

	// AnnotationSpecHash records, on every rank Pod, the hash of the spec and
	// render options the Pod was rendered from. Pods are immutable, so a spec
	// change cannot be applied in place: a rank Pod whose hash differs from the
	// current one is stale, and the gang restarts.
	AnnotationSpecHash = "k3sm.io/mlx-spec-hash"
	// AnnotationBackend records the RESOLVED collective backend (ring or jaccl)
	// the gang was placed for. spec.distributed.backend may say auto; the Pods
	// say what auto became.
	AnnotationBackend = "k3sm.io/mlx-backend"
	// AnnotationPlacedLinks records the direct links the placement counted on,
	// as "nodeA/nodeB" pairs joined by commas. LinksHealthy re-checks exactly
	// these against the live link graph.
	AnnotationPlacedLinks = "k3sm.io/mlx-placed-links"

	// CollectivePort is the TCP port every rank listens on for the collective
	// backend: the ring backend's hostfile entries and the jaccl coordinator
	// side channel. It is fixed rather than derived from the serving port so
	// that rank 0 never has to bind the same port for two purposes. 29500 is the
	// de-facto distributed-rendezvous port, which makes it recognizable in a
	// connection table.
	CollectivePort int32 = 29500
	// collectivePortName names the collective container port. Declared for
	// legibility (kubectl describe, a connection table); no Service targets it,
	// because ranks dial each other's pod IPs directly.
	collectivePortName = "mlx-collective"

	// shardInterpreter is the serving image's interpreter Mach-O. A rank runs
	// the image's own interpreter, never a shell wrapper: argv[0] is what the
	// runtime verifies a signature on (see hack/images/mlx-serve/build.sh).
	shardInterpreter = "/bin/python3.12"
	// shardModule is the k3sm-shard entrypoint module the image carries.
	shardModule = "k3sm_shard"
	// shardProbeFlag runs the entrypoint as a liveness probe instead of a
	// server.
	shardProbeFlag = "--probe"
	// shardModelFlag is mlx_lm.server's model option. Unlike the single-node
	// engine, mlx_lm.server takes the model as an OPTION, not a positional.
	shardModelFlag = "--model"

	// shardReadinessPath is the rank-0 readiness endpoint. mlx_lm.server opens
	// its HTTP listener only after the sharded load has completed on every rank
	// (the load itself is collective), so an answer here means the whole gang
	// is serving.
	shardReadinessPath = "/v1/models"
)

// The environment the k3sm-shard entrypoint reads.
const (
	envMLXRank          = "MLX_RANK"
	envMLXWorldSize     = "MLX_WORLD_SIZE"
	envMLXFastSynch     = "MLX_METAL_FAST_SYNCH"
	envBackend          = "K3SM_MLX_BACKEND"
	envParallelism      = "K3SM_MLX_PARALLELISM"
	envRanks            = "K3SM_MLX_RANKS"
	envCollectivePort   = "K3SM_MLX_PORT"
	envServePort        = "K3SM_MLX_SERVE_PORT"
	envIBVDevicesJSON   = "K3SM_MLX_IBV_DEVICES_JSON"
	fastSynchEnabled    = "1"
	placedLinkSeparator = ","
)

// The rank-0 liveness probe: a one-token generation through the local server,
// on a 60-second cadence, to catch a hung collective — a gang whose rank 0
// still accepts connections while a peer has stopped answering all_sum, which
// readiness cannot see because the listener stays up.
//
// Its COST is a real one-token generation every minute: one forward pass of
// the whole sharded model across every rank, plus a collective round trip.
// M17-lab records that cost on the rig beside the tokens/s figure; if it is too
// costly the cadence is a recorded open question, not a silent gap. The timeout
// is generous because the forward pass runs behind whatever requests are
// already in flight. A server that has not opened its listener yet (still
// downloading or loading) answers the probe with success: the probe judges a
// serving gang, never a starting one, so it cannot turn a long first download
// into a kill loop.
const (
	livenessPeriodSeconds    = 60
	livenessTimeoutSeconds   = 30
	livenessFailureThreshold = 2
)

// RankPlacement is where one rank runs.
type RankPlacement struct {
	// Rank is the rank index, 0..ranks-1.
	Rank int
	// Node is the node the rank Pod is bound to (spec.nodeName).
	Node string
	// RDMADevices is, for the jaccl backend, the local RDMA device this rank
	// uses to reach each peer, indexed by PEER rank: entry j is the local
	// rdma_enX on the up link to rank j's node, and the rank's own entry is
	// empty. Nil for the ring backend.
	RDMADevices []string
}

// Placement is one decided placement of a sharded model: the resolved backend
// (never auto), one entry per rank in rank order, and the direct links the
// placement relies on.
type Placement struct {
	// Backend is ring or jaccl.
	Backend mlxv1alpha1.MLXDistributedBackend
	// Ranks are the rank placements, Ranks[i].Rank == i.
	Ranks []RankPlacement
	// Links are the direct links between placed nodes the backend's traffic
	// rides, each as a sorted node pair. For ring, the consecutive hops that
	// are direct links; for jaccl, every pair.
	Links [][2]string
}

// ShardedObjects are the API objects that serve one sharded MLXModel. Every one
// carries a controller ownerReference to the model.
type ShardedObjects struct {
	// HeadlessService is the same governing Service the single-node path
	// renders; with the rank Pods' hostname/subdomain it gives every rank its
	// per-pod DNS name.
	HeadlessService *corev1.Service
	// ClusterIPService is the stable client endpoint, selecting rank 0 only:
	// rank 0 is the only rank serving HTTP.
	ClusterIPService *corev1.Service
	// Claims are the cache claims, one per placed rank, or nil without
	// spec.cache.
	Claims []*corev1.PersistentVolumeClaim
	// Pods are the rank Pods, in rank order.
	Pods []*corev1.Pod
	// SpecHash is the value of AnnotationSpecHash on every Pod.
	SpecHash string
}

// RankPodName returns the name of rank i's Pod for the MLXModel called name.
// It is also the Pod's spec.hostname, so the per-pod DNS record under the
// headless Service has the same name as the Pod.
func RankPodName(name string, rank int) string {
	return name + "-rank-" + strconv.Itoa(rank)
}

// RankCacheClaimName returns the cache claim name for a rank of the MLXModel
// called name placed on node.
//
// It is keyed by NODE, not by rank index, deliberately. The cache class binds a
// claim to the node of its first consumer, and a gang restart can re-place
// rank i onto a different node when the link graph changed; a rank-keyed claim
// would then pin the new rank Pod to a node it is not bound to, and it would
// never start. Keyed by node, whichever rank lands on a node finds that node's
// weights. At any moment there is still exactly one claim per placed rank,
// because placement never puts two ranks on one node.
func RankCacheClaimName(name, node string) string {
	return cacheVolumeName + "-" + name + "-" + node
}

// RankDNSName returns rank i's per-pod DNS name under the model's headless
// Service, in the namespace-qualified form the cluster search path completes.
func RankDNSName(m *mlxv1alpha1.MLXModel, rank int) string {
	return fmt.Sprintf("%s.%s.%s.svc", RankPodName(m.Name, rank), HeadlessServiceName(m.Name), m.Namespace)
}

// ShardedSelector returns the labels that select every rank Pod of the
// MLXModel called name: the render's selector labels plus the presence of
// LabelRank, which no single-node replica carries.
func ShardedSelector(name string) string {
	return fmt.Sprintf("app.kubernetes.io/name=mlx-model,app.kubernetes.io/instance=%s,%s", name, LabelRank)
}

// RenderShardedServices renders the two Services a sharded model keeps
// whatever its placement: the unchanged headless governing Service, and the
// ClusterIP Service narrowed to rank 0. The operator applies these even while
// no placement exists, so a client's address is stable across gang restarts.
func RenderShardedServices(m *mlxv1alpha1.MLXModel, opts Options) (headless, clusterIP *corev1.Service, err error) {
	p, err := prepareSharded(m, opts)
	if err != nil {
		return nil, nil, err
	}
	headless, clusterIP = shardedServices(m, p)
	return headless, clusterIP, nil
}

// RenderSharded turns a sharded MLXModel and its decided placement into the
// objects that serve it: the two Services, a cache claim per rank when
// spec.cache is set, and one Pod per rank bound to its placed node.
//
// It is pure like Render. A spec that cannot be rendered, or a placement that
// does not match the spec, yields a wrapped sentinel error and no objects.
func RenderSharded(m *mlxv1alpha1.MLXModel, opts Options, placement Placement) (*ShardedObjects, error) {
	p, err := prepareSharded(m, opts)
	if err != nil {
		return nil, err
	}
	if err := checkPlacement(m, placement); err != nil {
		return nil, renderErr(m, err)
	}
	headless, clusterIP := shardedServices(m, p)
	perRank, err := PerRankMemory(m.Spec.Memory, m.Spec.Distributed.Ranks)
	if err != nil {
		return nil, renderErr(m, err)
	}
	hash, err := SpecHash(m, opts)
	if err != nil {
		return nil, renderErr(m, err)
	}

	objs := &ShardedObjects{HeadlessService: headless, ClusterIPService: clusterIP, SpecHash: hash}
	ibv, err := ibvDevicesJSON(placement)
	if err != nil {
		return nil, renderErr(m, err)
	}
	for _, r := range placement.Ranks {
		var claim *corev1.PersistentVolumeClaim
		if c := m.Spec.Cache; c != nil {
			claim = rankClaim(m, p.owner, r, *c)
			objs.Claims = append(objs.Claims, claim)
		}
		objs.Pods = append(objs.Pods, rankPod(m, p, placement, r, perRank, hash, ibv, claim))
	}
	return objs, nil
}

// prepareSharded runs the shared spec checks plus the sharded ones.
func prepareSharded(m *mlxv1alpha1.MLXModel, opts Options) (prepared, error) {
	p, err := prepare(m, opts)
	if err != nil {
		return prepared{}, err
	}
	d := m.Spec.Distributed
	if d == nil {
		return prepared{}, renderErr(m, ErrNotDistributed)
	}
	if d.Ranks < 2 {
		return prepared{}, renderErr(m, fmt.Errorf("%w: %d", ErrInvalidRanks, d.Ranks))
	}
	if p.replicas > 1 {
		return prepared{}, renderErr(m, fmt.Errorf("%w: spec.replicas=%d", ErrShardedReplicas, p.replicas))
	}
	if p.port == CollectivePort {
		return prepared{}, renderErr(m, fmt.Errorf("%w: %d", ErrCollectivePortConflict, p.port))
	}
	return p, nil
}

// checkPlacement verifies the placement describes exactly the spec's ranks.
func checkPlacement(m *mlxv1alpha1.MLXModel, placement Placement) error {
	n := int(m.Spec.Distributed.Ranks)
	if placement.Backend != mlxv1alpha1.MLXDistributedBackendRing && placement.Backend != mlxv1alpha1.MLXDistributedBackendJACCL {
		return fmt.Errorf("%w: backend %q is not resolved to ring or jaccl", ErrPlacementMismatch, placement.Backend)
	}
	if len(placement.Ranks) != n {
		return fmt.Errorf("%w: %d ranks placed, spec asks for %d", ErrPlacementMismatch, len(placement.Ranks), n)
	}
	seen := map[string]bool{}
	for i, r := range placement.Ranks {
		if r.Rank != i {
			return fmt.Errorf("%w: entry %d is rank %d", ErrPlacementMismatch, i, r.Rank)
		}
		if r.Node == "" || seen[r.Node] {
			return fmt.Errorf("%w: rank %d node %q is empty or already holds a rank", ErrPlacementMismatch, i, r.Node)
		}
		seen[r.Node] = true
		if placement.Backend == mlxv1alpha1.MLXDistributedBackendJACCL && len(r.RDMADevices) != n {
			return fmt.Errorf("%w: rank %d has %d rdma devices, want %d", ErrPlacementMismatch, i, len(r.RDMADevices), n)
		}
	}
	return nil
}

// shardedServices renders the headless Service unchanged and the ClusterIP
// Service with rank 0 added to its selector.
func shardedServices(m *mlxv1alpha1.MLXModel, p prepared) (headless, clusterIP *corev1.Service) {
	headless = headlessService(m, p.owner, p.port)
	clusterIP = clusterIPService(m, p.owner, p.port)
	clusterIP.Spec.Selector[LabelRank] = "0"
	return headless, clusterIP
}

// SpecHash is the hash recorded on every rank Pod (AnnotationSpecHash): the
// model spec and the render options that shape a Pod. The placement is NOT in
// it: a link going down must not by itself restart a gang that is still
// serving (the ring backend keeps serving over the mesh), and a gang restart
// that IS needed re-places anyway.
func SpecHash(m *mlxv1alpha1.MLXModel, opts Options) (string, error) {
	raw, err := json.Marshal(struct {
		Spec    mlxv1alpha1.MLXModelSpec `json:"spec"`
		Options Options                  `json:"options"`
	}{m.Spec, opts})
	if err != nil {
		return "", fmt.Errorf("hash spec: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8]), nil
}

// ibvDevicesJSON renders the jaccl device matrix: one row per rank, each row
// indexed by peer rank, null for the rank itself. It is the shape MLX's own
// launcher writes to the MLX_IBV_DEVICES file, and every rank receives the
// whole matrix (each reads its own row). Empty for ring.
func ibvDevicesJSON(placement Placement) (string, error) {
	if placement.Backend != mlxv1alpha1.MLXDistributedBackendJACCL {
		return "", nil
	}
	rows := make([][]*string, len(placement.Ranks))
	for i, r := range placement.Ranks {
		row := make([]*string, len(r.RDMADevices))
		for j, dev := range r.RDMADevices {
			if dev != "" {
				row[j] = ptr.To(dev)
			}
		}
		rows[i] = row
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", fmt.Errorf("encode rdma device matrix: %w", err)
	}
	return string(raw), nil
}

// FormatPlacedLinks renders placement links as the AnnotationPlacedLinks value.
func FormatPlacedLinks(links [][2]string) string {
	parts := make([]string, 0, len(links))
	for _, l := range links {
		parts = append(parts, l[0]+"/"+l[1])
	}
	return strings.Join(parts, placedLinkSeparator)
}

// ParsePlacedLinks is FormatPlacedLinks' inverse. Malformed entries are
// skipped: the annotation is the operator's own, and a hand-edited value can
// only shrink what LinksHealthy checks, never invent a link.
func ParsePlacedLinks(v string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(v, placedLinkSeparator) {
		a, b, ok := strings.Cut(part, "/")
		if !ok || a == "" || b == "" {
			continue
		}
		out = append(out, [2]string{a, b})
	}
	return out
}

// rankClaim renders one rank's cache claim in the single-node claim shape,
// named for its node and owned by the model (a bare Pod has no claim
// templates, so the claim is the operator's own object).
func rankClaim(m *mlxv1alpha1.MLXModel, owner metav1.OwnerReference, r RankPlacement, cache mlxv1alpha1.MLXCache) *corev1.PersistentVolumeClaim {
	claim := cacheClaim(m, cache)
	claim.TypeMeta = metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: "PersistentVolumeClaim"}
	claim.Name = RankCacheClaimName(m.Name, r.Node)
	claim.Namespace = m.Namespace
	claim.OwnerReferences = []metav1.OwnerReference{owner}
	return &claim
}

// rankPod renders one rank's Pod.
func rankPod(m *mlxv1alpha1.MLXModel, p prepared, placement Placement, r RankPlacement, perRank resource.Quantity, hash, ibv string, claim *corev1.PersistentVolumeClaim) *corev1.Pod {
	labels := Labels(m.Name)
	labels[LabelRank] = strconv.Itoa(r.Rank)

	container := corev1.Container{
		Name:    containerName,
		Image:   p.image,
		Command: []string{shardInterpreter, "-m", shardModule},
		// The model leads, then the caller's own arguments LAST: the override
		// seam the single-node engineArgs keeps. The entrypoint adds --host,
		// --port and --pipeline itself, from the environment.
		Args: append([]string{shardModelFlag, p.modelRef}, m.Spec.Runtime.Args...),
		Ports: []corev1.ContainerPort{{
			Name:          collectivePortName,
			ContainerPort: CollectivePort,
			Protocol:      corev1.ProtocolTCP,
		}},
		Env:       rankEnv(m, p, placement, r, ibv),
		Resources: podResources(perRank),
	}
	if r.Rank == 0 {
		container.Ports = append([]corev1.ContainerPort{{
			Name:          portName,
			ContainerPort: p.port,
			Protocol:      corev1.ProtocolTCP,
		}}, container.Ports...)
		container.ReadinessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: shardReadinessPath, Port: intstr.FromString(portName)},
			},
			PeriodSeconds:    readinessPeriodSeconds,
			TimeoutSeconds:   readinessTimeoutSeconds,
			FailureThreshold: readinessFailureThreshold,
			SuccessThreshold: readinessSuccessThreshold,
		}
		container.LivenessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{shardInterpreter, "-m", shardModule, shardProbeFlag}},
			},
			PeriodSeconds:    livenessPeriodSeconds,
			TimeoutSeconds:   livenessTimeoutSeconds,
			FailureThreshold: livenessFailureThreshold,
			SuccessThreshold: 1,
		}
	}

	var volumes []corev1.Volume
	if claim != nil {
		container.Env = append(container.Env, corev1.EnvVar{Name: hfHomeEnv, Value: hfHomePath})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: cacheVolumeName, MountPath: CacheMountPath})
		volumes = append(volumes, corev1.Volume{
			Name: cacheVolumeName,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name},
			},
		})
	}

	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RankPodName(m.Name, r.Rank),
			Namespace: m.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				AnnotationSpecHash:    hash,
				AnnotationBackend:     string(placement.Backend),
				AnnotationPlacedLinks: FormatPlacedLinks(placement.Links),
			},
			OwnerReferences: []metav1.OwnerReference{p.owner},
		},
		Spec: corev1.PodSpec{
			NodeName: r.Node,
			// The same guarded selector and toleration the StatefulSet template
			// carries: nodeName bypasses the scheduler, not admission, and the
			// admission policy checks both.
			NodeSelector: maps.Clone(p.nodeSelector),
			Tolerations:  providerTolerations(),
			Hostname:     RankPodName(m.Name, r.Rank),
			Subdomain:    HeadlessServiceName(m.Name),
			// Never, not Always: a rank restarted on its own cannot rejoin a
			// collective its peers are blocked in, so a lone restart is a hang.
			// A rank that exits ends its Pod, and the operator's gang semantics
			// restart every rank together.
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{container},
			Volumes:       volumes,
		},
	}
}

// rankEnv builds the per-rank environment the k3sm-shard entrypoint reads.
func rankEnv(m *mlxv1alpha1.MLXModel, p prepared, placement Placement, r RankPlacement, ibv string) []corev1.EnvVar {
	n := len(placement.Ranks)
	names := make([]string, n)
	for i := range names {
		names[i] = RankDNSName(m, i)
	}
	parallelism := m.Spec.Distributed.Parallelism
	if parallelism == "" {
		parallelism = mlxv1alpha1.MLXParallelismTensor
	}
	env := []corev1.EnvVar{
		{Name: envMLXRank, Value: strconv.Itoa(r.Rank)},
		{Name: envMLXWorldSize, Value: strconv.Itoa(n)},
		{Name: envMLXFastSynch, Value: fastSynchEnabled},
		{Name: envBackend, Value: string(placement.Backend)},
		{Name: envParallelism, Value: string(parallelism)},
		{Name: envRanks, Value: strings.Join(names, ",")},
		{Name: envCollectivePort, Value: strconv.Itoa(int(CollectivePort))},
		{Name: envServePort, Value: strconv.Itoa(int(p.port))},
	}
	if ibv != "" {
		env = append(env, corev1.EnvVar{Name: envIBVDevicesJSON, Value: ibv})
	}
	return env
}
