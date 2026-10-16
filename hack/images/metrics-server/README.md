# metrics-server image

k3sm's native darwin/arm64 build of upstream metrics-server, the image the embedded
add-on (`pkg/addons/manifests/metrics-server.yaml`) runs as a native pod on server
nodes. Upstream publishes Linux images only. A Linux image would need a `vm` pod, and
a `vm` pod cannot open connections to another node's kubelet, so it could not scrape
the workers.

| file | what it is |
|---|---|
| `build.sh` | the recipe: pinned module source, pinned toolchain, checks, `k3sm build` |
| `selftest.sh` | the recipe's hermetic checks; `hack/ci.sh` runs it |
| `image.yaml` | the one record of the image's digest; the manifest carries a checked copy |
| `go.mod`, `go.sum` | the build's module graph: upstream's, with `golang.org/x/net` moved to v0.60.0 |
| `buildinfo.lock` | `go version -m` of the pinned build; a differing rebuild is refused |
| `govulncheck.accepted` | govulncheck findings accepted one advisory at a time, each with a reason and an expiry |

## What the build does

1. Refuses a placeholder pin before touching the network.
2. Downloads `sigs.k8s.io/metrics-server` at the pinned version in a clean environment
   (private module cache, `GOTOOLCHAIN=local`, `GOENV=off`; the module proxy and the
   checksum database at their defaults) and refuses it unless its `Sum` is the pinned
   checksum database hash.
3. Checks that the committed `go.mod` and `go.sum` require that module at the pinned
   version and hash, and `golang.org/x/net` at v0.60.0, with no `replace`. Upstream
   v0.9.0 links x/net v0.56.0, whose HTTP/2 server advisories are reachable on
   metrics-server's serving port. Minimal version selection moves `x/crypto`,
   `x/sync`, `x/sys`, `x/term` and `x/text` with it, to the versions k3sm itself ships.
   `--regen-graph` regenerates the two files; review that diff as a dependency change.
4. Builds `cmd/metrics-server` from that graph (`go build -mod=readonly`) with the pinned Go (`PAYLOAD_GO_VERSION` in
   `hack/release/lib/gochild.sh`, the same pin the release payload uses):
   `CGO_ENABLED=0`, darwin/arm64, `-trimpath`, and upstream's ldflags with every
   stamp taken from a pin. The build date is the tag commit's time, never the clock.
5. Checks the build info with the same shared function the release staging uses, and
   compares it with `buildinfo.lock`.
6. Runs the 14-day cooldown and the malicious-package check over every module the
   binary links (`hack/verify-deps.sh --modules`), and `govulncheck -mode=binary` at
   the pin `hack/ci.sh` carries. A finding is refused unless `govulncheck.accepted`
   matches its advisory id, module and found version with an entry that has not expired
   (a date, or the next upstream release, whichever comes first). A network failure is
   a failure.
7. Packages the binary with `k3sm build --format oci`: `FROM scratch`, one `COPY`, the
   `ENTRYPOINT`. The image holds no shell and no CA bundle. The in-cluster CA comes
   from the projected `kube-root-ca.crt`. The image is unsigned. runtimed signs the
   binary before it runs it, as it does for every native image.

```sh
CGO_ENABLED=1 go build -o <dir>/k3sm ./cmd/k3sm
K3SM_BIN=<dir>/k3sm hack/images/metrics-server/build.sh --work <scratch dir>
```

`k3sm build` also records the image in the node's image store, so run it where
`k3sm build` can reach runtimed (an installed node, as root or as the runtimed
socket's owner). The build prints the binary's sha256, the darwin/arm64 manifest
digest and the reference to pin. `k3sm image push` publishes the single manifest as is,
so there is no image index. The pinned reference names the darwin/arm64 manifest.

## Reachability

`govulncheck -show verbose` in source mode over upstream v0.9.0's own graph
(darwin/arm64, `./cmd/metrics-server/...`) traced these advisories:

| advisory | module | reachable? | path |
|---|---|---|---|
| GO-2026-6617, 6612, 6611, 6603 | golang.org/x/net v0.56.0 | yes, on the serve path | `SecureServingInfo.Serve` calls `http2.ConfigureServer` for the secure port, and HTTP/2 framing runs before authentication. Fixed by the x/net v0.60.0 graph. |
| GO-2026-6610 | golang.org/x/net v0.56.0 | client side only | fixed by the same graph |
| GO-2026-5970 | golang.org/x/text v0.38.0 | not on attacker input | `idna` on the apiserver host name; fixed by the x/text the graph moves to |
| GO-2026-6505 | go.opentelemetry.io/otel and its exporters | package init only | no tracing is configured; accepted |
| GO-2026-6443 | google.golang.org/grpc | not reachable | package level only; no gRPC server runs; accepted |
| GO-2026-6348, 6061 | google.golang.org/grpc | client transport only | every trace is `http2Client`, used by an otel exporter that is not configured; accepted |

Over the patched graph, source mode reports only GO-2026-6505, 6348 and 6061 as
called, and every grpc trace is the client transport.

## Reproducibility

The binary and the image are reproducible: `-trimpath`, a pinned build date, and
`k3sm build` writes every tar header and config timestamp at a fixed epoch. The check is
a rebuild on a second Mac that yields the same image digest. A rebuild on the same
host shares its environment, so it proves less.

## Publish

Publishing is a human step. Nothing in this directory pushes.

1. Build, and record the digests from the build output.
2. Push the layout: `K3SM_REGISTRY_TOKEN=<token> k3sm image push <work>/oci ghcr.io/k3sm-io/metrics-server:v0.9.0`.
   The credential is read from the environment, never from argv.
3. Make the package public. GHCR creates new packages private, and every node pulls
   the image anonymously.
4. Re-derive the digest from the published artifact with an anonymous fetch, write it
   to `image.yaml` and to the manifest's image line, and mark the record published.
5. `hack/images/metrics-server/build.sh --live` resolves `image.yaml`'s reference
   anonymously and must succeed.

A manifest change never merges while `image.yaml` names a digest that is not published.
An unpublished pin leaves every upgraded cluster's add-on in `ImagePullBackOff` and its
APIService unavailable.

## Bumping

Change the pins at the top of `build.sh` together with the manifest header's vendored
version, rebuild with `--update-lock`, review the `buildinfo.lock` diff as a dependency
change, prune `govulncheck.accepted`, and publish as above.
