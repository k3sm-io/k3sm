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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// The registry listing's fixed facts.
const (
	// canonicalRegistry is the one name every image in the cluster's registry
	// is shown under, whichever address the CLI reached it at.
	canonicalRegistry = "registry-k3sm:6450"
	// imageReportSchemaVersion versions the -o json documents of ls and df. A
	// consumer (the app) refuses a version it does not know.
	imageReportSchemaVersion = 1
	// nodeStatusImageCap is how many images a node reports in status.images
	// (the kubelet's --node-status-max-images default, which k3sm's provider
	// applies). A node at the cap may hold an image it does not list, so its
	// absence from cachedOn proves nothing.
	nodeStatusImageCap = 50
	// describeParallelism bounds the manifest reads in flight at once.
	describeParallelism = 4
)

// registryReport says which registry a report is about and whether it answered.
type registryReport struct {
	Name      string `json:"name"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// imageRow is one tag in the registry.
type imageRow struct {
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	Reference  string   `json:"reference"`
	Digest     string   `json:"digest"`
	Platforms  []string `json:"platforms"`
	SizeBytes  int64    `json:"sizeBytes"`
	Pods       int      `json:"pods"`
	CachedOn   []string `json:"cachedOn"`
}

// imageListReport is `k3sm image ls -o json`.
type imageListReport struct {
	SchemaVersion      int            `json:"schemaVersion"`
	Registry           registryReport `json:"registry"`
	Images             []imageRow     `json:"images"`
	CachedOnIncomplete []string       `json:"cachedOnIncomplete"`
	// Migration summarises the move of node-store images into the registry.
	// Nothing fills it yet; the key is always present, null until then.
	Migration any `json:"migration"`
}

// nodeCacheRow is one node's image cache as its status.images reports it.
type nodeCacheRow struct {
	Node       string `json:"node"`
	CacheBytes int64  `json:"cacheBytes"`
	Images     int    `json:"images"`
	// Incomplete is a node at the status.images cap: it may cache more than it
	// reports, so CacheBytes is a lower bound.
	Incomplete bool `json:"incomplete"`
}

// imageDFReport is `k3sm image df -o json`.
type imageDFReport struct {
	SchemaVersion int            `json:"schemaVersion"`
	Registry      registryReport `json:"registry"`
	// RegistryBytes is the sum of the distinct blobs the registry's tags reach.
	RegistryBytes int64          `json:"registryBytes"`
	Nodes         []nodeCacheRow `json:"nodes"`
}

// imageRegistryEnv is what ls and df read: the cluster, and how to reach the
// registry the cluster publishes. Injected so the gate runs against a fake
// clientset and an in-process fake registry.
type imageRegistryEnv struct {
	kube kubernetes.Interface
	// apiHost is the host of the apiserver URL kube dials. The registry runs
	// on the server, so it is reached on the same host: loopback when the
	// apiserver is, the server's address otherwise (an agent, or a Mac whose
	// kubeconfig points at the server).
	apiHost string
	// rootCAs is the cluster CA, trusted for an https registry address.
	rootCAs *x509.CertPool
	// transport replaces the registry client's HTTP transport; nil in
	// production.
	transport http.RoundTripper
}

// newImageRegistryEnv resolves the cluster the way `k3sm status` does, over the
// invoking user's own credentials: no root, no daemon socket.
func newImageRegistryEnv() (imageRegistryEnv, error) {
	role, _ := installedRole()
	workDir := statusWorkDir(os.Geteuid(), lookupServiceUID())
	k, _, err := newStatusKube(statusKubeInputsFor(role, statusPaths(workDir)))
	if err != nil {
		return imageRegistryEnv{}, fmt.Errorf("find the cluster: %w", err)
	}
	rk, ok := k.(restKube)
	if !ok {
		return imageRegistryEnv{}, fmt.Errorf("the cluster client is a %T, not a clientset", k)
	}
	u, err := url.Parse(rk.cfg.Host)
	if err != nil {
		return imageRegistryEnv{}, fmt.Errorf("parse the apiserver URL %q: %w", rk.cfg.Host, err)
	}
	env := imageRegistryEnv{kube: rk.client, apiHost: u.Hostname()}
	ca := rk.cfg.TLSClientConfig.CAData
	if len(ca) == 0 && rk.cfg.TLSClientConfig.CAFile != "" {
		if ca, err = os.ReadFile(rk.cfg.TLSClientConfig.CAFile); err != nil {
			return imageRegistryEnv{}, fmt.Errorf("read the cluster CA: %w", err)
		}
	}
	if len(ca) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(ca) {
			env.rootCAs = pool
		}
	}
	return env, nil
}

// imageRegistryCommand runs ls or df.
func imageRegistryCommand(ctx context.Context, o imageOptions, out io.Writer, env imageRegistryEnv) error {
	nodes, err := env.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	listing, regErr := listRegistry(ctx, env)
	reg := registryReport{Name: canonicalRegistry, Reachable: regErr == nil}
	if regErr != nil {
		reg.Error = regErr.Error()
	}
	switch o.subcommand {
	case "ls":
		var pods []corev1.Pod
		if regErr == nil {
			pl, err := env.kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("list pods: %w", err)
			}
			pods = pl.Items
		}
		rep := buildImageList(reg, listing, nodes.Items, pods)
		if o.output == "json" {
			return writeImageReport(out, rep)
		}
		return renderImageList(out, rep)
	case "df":
		rep := buildImageDF(reg, listing, nodes.Items)
		if o.output == "json" {
			return writeImageReport(out, rep)
		}
		return renderImageDF(out, rep)
	}
	return fmt.Errorf("unknown subcommand %q", o.subcommand)
}

// registryListing is what the registry holds: every tag, described, and the
// aliases its references may be spelled with in a Pod spec.
type registryListing struct {
	images  []registryclient.Image
	aliases map[string]bool
}

// hostingDoc is the part of the KEP-1755 document the listing reads.
type hostingDoc struct {
	Host                     string `json:"host"`
	HostFromContainerRuntime string `json:"hostFromContainerRuntime"`
	HostFromClusterNetwork   string `json:"hostFromClusterNetwork"`
}

// readHosting reads the cluster's local-registry-hosting document.
func readHosting(ctx context.Context, kube kubernetes.Interface) (hostingDoc, error) {
	cm, err := kube.CoreV1().ConfigMaps(registrysvc.HostingNamespace).Get(ctx, registrysvc.HostingConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return hostingDoc{}, fmt.Errorf("the cluster publishes no registry (%s/%s is absent)", registrysvc.HostingNamespace, registrysvc.HostingConfigMapName)
	}
	if err != nil {
		return hostingDoc{}, fmt.Errorf("read %s/%s: %w", registrysvc.HostingNamespace, registrysvc.HostingConfigMapName, err)
	}
	var doc hostingDoc
	if err := yaml.Unmarshal([]byte(cm.Data[registrysvc.HostingDataKey]), &doc); err != nil {
		return hostingDoc{}, fmt.Errorf("decode %s: %w", registrysvc.HostingDataKey, err)
	}
	if doc.Host == "" {
		return hostingDoc{}, fmt.Errorf("%s names no host", registrysvc.HostingDataKey)
	}
	return doc, nil
}

// registryBases are the URLs the registry is tried at, in order. On loopback
// it is the registry's own plain-HTTP listener. Off loopback it is the
// server's address on the port the document names: https verified against
// the cluster CA first, plain HTTP only when the server answers HTTPS with
// HTTP (a registry that serves no TLS there), never on a certificate failure.
func registryBases(doc hostingDoc, apiHost string) ([]string, error) {
	_, port, err := net.SplitHostPort(doc.Host)
	if err != nil {
		return nil, fmt.Errorf("%s host %q: %w", registrysvc.HostingDataKey, doc.Host, err)
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		return nil, fmt.Errorf("%s host %q has no valid port", registrysvc.HostingDataKey, doc.Host)
	}
	if isLoopbackHost(apiHost) {
		return []string{"http://" + net.JoinHostPort("127.0.0.1", port)}, nil
	}
	hp := net.JoinHostPort(apiHost, port)
	return []string{"https://" + hp, "http://" + hp}, nil
}

// isLoopbackHost reports whether host names this Mac.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// registryAliases are the registry hosts a Pod's image reference may name and
// still mean this registry.
func registryAliases(doc hostingDoc) map[string]bool {
	aliases := map[string]bool{canonicalRegistry: true}
	for _, h := range []string{doc.Host, doc.HostFromContainerRuntime, doc.HostFromClusterNetwork} {
		if h == "" {
			continue
		}
		aliases[h] = true
		if _, port, err := net.SplitHostPort(h); err == nil {
			aliases["localhost:"+port] = true
			aliases["127.0.0.1:"+port] = true
		}
	}
	return aliases
}

// listRegistry reads every tag the registry holds. Any failure is the
// registry's: the caller reports it as unreachable and still exits 0.
func listRegistry(ctx context.Context, env imageRegistryEnv) (registryListing, error) {
	doc, err := readHosting(ctx, env.kube)
	if err != nil {
		return registryListing{}, err
	}
	bases, err := registryBases(doc, env.apiHost)
	if err != nil {
		return registryListing{}, err
	}
	var c *registryclient.Client
	var repos []string
	for _, base := range bases {
		c, err = registryclient.New(base, registryclient.Options{RootCAs: env.rootCAs, Transport: env.transport})
		if err != nil {
			return registryListing{}, err
		}
		repos, err = c.Catalog(ctx)
		if !errors.Is(err, http.ErrSchemeMismatch) {
			break
		}
	}
	if err != nil {
		return registryListing{}, fmt.Errorf("registry at %s: %w", c.Host(), err)
	}
	type job struct{ repo, tag string }
	var jobs []job
	for _, r := range repos {
		if !registryclient.ValidRepository(r) {
			continue
		}
		tags, err := c.Tags(ctx, r)
		if errors.Is(err, registryclient.ErrNotFound) {
			continue // deleted since the catalog was read
		}
		if err != nil {
			return registryListing{}, fmt.Errorf("registry at %s: %w", c.Host(), err)
		}
		for _, t := range tags {
			if registryclient.ValidTag(t) {
				jobs = append(jobs, job{r, t})
			}
		}
	}
	images := make([]registryclient.Image, len(jobs))
	errs := make([]error, len(jobs))
	sem := make(chan struct{}, describeParallelism)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			images[i], errs[i] = c.Describe(ctx, j.repo, j.tag)
		}()
	}
	wg.Wait()
	out := registryListing{aliases: registryAliases(doc)}
	for i, err := range errs {
		switch {
		case errors.Is(err, registryclient.ErrNotFound):
			// A tag deleted between the tag list and the read is no row.
		case err != nil:
			return registryListing{}, fmt.Errorf("registry at %s: %w", c.Host(), err)
		default:
			out.images = append(out.images, images[i])
		}
	}
	return out, nil
}

// buildImageList joins the registry's tags against where they are cached and
// which Pods use them.
func buildImageList(reg registryReport, l registryListing, nodes []corev1.Node, pods []corev1.Pod) imageListReport {
	rep := imageListReport{
		SchemaVersion:      imageReportSchemaVersion,
		Registry:           reg,
		Images:             []imageRow{},
		CachedOnIncomplete: incompleteNodes(nodes),
	}
	for _, img := range l.images {
		row := imageRow{
			Repository: img.Repository,
			Tag:        img.Tag,
			Reference:  canonicalRegistry + "/" + img.Repository + ":" + img.Tag,
			Digest:     img.Digest,
			Platforms:  append([]string{}, img.Platforms...),
			SizeBytes:  img.SizeBytes,
			CachedOn:   []string{},
		}
		for _, n := range nodes {
			if nodeCaches(n, img.Digest) {
				row.CachedOn = append(row.CachedOn, n.Name)
			}
		}
		sort.Strings(row.CachedOn)
		for i := range pods {
			if podUses(&pods[i], img, l.aliases) {
				row.Pods++
			}
		}
		rep.Images = append(rep.Images, row)
	}
	sort.Slice(rep.Images, func(i, j int) bool {
		a, b := rep.Images[i], rep.Images[j]
		if a.Repository != b.Repository {
			return a.Repository < b.Repository
		}
		return a.Tag < b.Tag
	})
	return rep
}

// buildImageDF sums the registry's distinct blobs and each node's reported
// cache.
func buildImageDF(reg registryReport, l registryListing, nodes []corev1.Node) imageDFReport {
	rep := imageDFReport{SchemaVersion: imageReportSchemaVersion, Registry: reg, Nodes: []nodeCacheRow{}}
	blobs := map[string]int64{}
	for _, img := range l.images {
		for d, s := range img.Blobs {
			blobs[d] = s
		}
	}
	for _, s := range blobs {
		rep.RegistryBytes += s
	}
	for _, n := range nodes {
		row := nodeCacheRow{Node: n.Name, Images: len(n.Status.Images), Incomplete: len(n.Status.Images) >= nodeStatusImageCap}
		for _, ci := range n.Status.Images {
			row.CacheBytes += ci.SizeBytes
		}
		rep.Nodes = append(rep.Nodes, row)
	}
	sort.Slice(rep.Nodes, func(i, j int) bool { return rep.Nodes[i].Node < rep.Nodes[j].Node })
	return rep
}

// incompleteNodes are the nodes whose status.images is at the cap, sorted.
func incompleteNodes(nodes []corev1.Node) []string {
	out := []string{}
	for _, n := range nodes {
		if len(n.Status.Images) >= nodeStatusImageCap {
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

// nodeCaches reports whether n's status.images names digest. The node lists
// each cached image by repository@digest, the digest being the index's for a
// multi-platform image, which is the digest the registry's tag points at.
func nodeCaches(n corev1.Node, digest string) bool {
	for _, ci := range n.Status.Images {
		for _, name := range ci.Names {
			if strings.HasSuffix(name, "@"+digest) {
				return true
			}
		}
	}
	return false
}

// podUses reports whether any of p's containers names img: by digest, by its
// reference under one of the registry's aliases, or by the image ID the node
// reported for a running container.
func podUses(p *corev1.Pod, img registryclient.Image, aliases map[string]bool) bool {
	var refs []string
	for _, c := range p.Spec.InitContainers {
		refs = append(refs, c.Image)
	}
	for _, c := range p.Spec.Containers {
		refs = append(refs, c.Image)
	}
	for _, c := range p.Spec.EphemeralContainers {
		refs = append(refs, c.Image)
	}
	for _, list := range [][]corev1.ContainerStatus{p.Status.InitContainerStatuses, p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses} {
		for _, cs := range list {
			if cs.ImageID == img.Digest || strings.HasSuffix(cs.ImageID, "@"+img.Digest) {
				return true
			}
		}
	}
	for _, ref := range refs {
		if referenceNames(ref, img, aliases) {
			return true
		}
	}
	return false
}

// referenceNames reports whether the image reference ref resolves to img.
// A reference with no registry host is Docker Hub's, never this registry's.
func referenceNames(ref string, img registryclient.Image, aliases map[string]bool) bool {
	name, digest, hasDigest := strings.Cut(ref, "@")
	if hasDigest && digest == img.Digest {
		return true
	}
	host, rest, ok := strings.Cut(name, "/")
	if !ok || !(strings.ContainsAny(host, ".:") || host == "localhost") || !aliases[host] {
		return false
	}
	repo, tag := rest, "latest"
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		repo, tag = rest[:i], rest[i+1:]
	}
	if hasDigest {
		return false // pinned to a different digest
	}
	return repo == img.Repository && tag == img.Tag
}

// writeImageReport writes v indented, with a trailing newline.
func writeImageReport(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// renderImageList is ls's table.
func renderImageList(out io.Writer, rep imageListReport) error {
	if !rep.Registry.Reachable {
		fmt.Fprintf(out, "registry %s is unreachable: %s\n", rep.Registry.Name, rep.Registry.Error)
		return nil
	}
	if len(rep.Images) == 0 {
		fmt.Fprintf(out, "no images in registry %s.\n", rep.Registry.Name)
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REFERENCE\tDIGEST\tPLATFORMS\tSIZE\tPODS\tCACHED ON")
		for _, r := range rep.Images {
			cached := strings.Join(r.CachedOn, ",")
			if cached == "" {
				cached = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", r.Reference, shortDigest(r.Digest),
				strings.Join(r.Platforms, ","), humanBytes(uint64(max(r.SizeBytes, 0))), r.Pods, cached)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(rep.CachedOnIncomplete) > 0 {
		fmt.Fprintf(out, "(%s report %d images, the status.images cap, so CACHED ON may omit them)\n",
			strings.Join(rep.CachedOnIncomplete, ", "), nodeStatusImageCap)
	}
	return nil
}

// renderImageDF is df's table.
func renderImageDF(out io.Writer, rep imageDFReport) error {
	if rep.Registry.Reachable {
		fmt.Fprintf(out, "registry %s: %s\n", rep.Registry.Name, humanBytes(uint64(max(rep.RegistryBytes, 0))))
	} else {
		fmt.Fprintf(out, "registry %s is unreachable: %s\n", rep.Registry.Name, rep.Registry.Error)
	}
	if len(rep.Nodes) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tCACHED\tIMAGES")
	for _, n := range rep.Nodes {
		count := strconv.Itoa(n.Images)
		if n.Incomplete {
			count += " (at the status.images cap; the cache may hold more)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", n.Node, humanBytes(uint64(max(n.CacheBytes, 0))), count)
	}
	return tw.Flush()
}

// shortDigest is a digest cut to the 12 hex characters a table shows.
func shortDigest(d string) string {
	if algo, hex, ok := strings.Cut(d, ":"); ok && len(hex) > 12 {
		return algo + ":" + hex[:12]
	}
	return d
}
