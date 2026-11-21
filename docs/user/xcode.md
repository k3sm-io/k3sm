# Building with Xcode in k3sm Pods

A native k3sm Pod can run `xcodebuild`: it can generate a project with XcodeGen, resolve Swift
packages, compile Swift and Objective-C, compile asset catalogs, and produce a `.app`. This page is
the one place that says what a node needs, what the `k3sm.io/xcode-toolchain` annotation changes,
how to keep builds warm, and what each failure you may meet means.

For the sandbox details behind each grant, see
[SwiftPM and `xcodebuild` builds in a Pod](limitations.md#swiftpm-and-xcodebuild-builds-in-a-pod)
and [the annotation's node classes](limitations.md#k3smioxcode-toolchain-grants-one-node-class-and-says-nothing-about-the-others)
in the limitations page.

## Prerequisites

- **Xcode at `/Applications/Xcode.app`**, selected with `xcode-select`:
  `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`. The node reads its developer
  directory once, when the node daemon starts, so restart the daemon after changing it. An Xcode
  at any other path (`Xcode-beta.app`, a versioned name) gets the read grant but no tool copies,
  and `xcodebuild` does not run there.
- **`sudo k3sm install` after every Xcode update** (and after every macOS update). It makes the
  node's re-signed copies of `xcodebuild`, `xcrun`, `actool`, `ibtool` and `ibtoold` (see
  [Signing and entitlements](#signing-and-entitlements)). `k3sm status` reports the copies as
  drifted until you run it again.
- **A node to schedule on.** k3sm has no node label for Xcode today. Pin a build Pod to a node you
  know has Xcode with `nodeName`, and keep `nodeSelector: {kubernetes.io/os: darwin}` so it never
  lands on a Linux node. Admission refuses a Pod without that selector, and every k3sm node carries
  the `k3sm.io/provider` NoSchedule taint, so a Pod also needs the toleration in the examples below.

## The Annotation and What It Changes

Add `k3sm.io/xcode-toolchain: "true"` to the Pod's annotations. On a node with a full Xcode
selected, the grant takes effect and k3sm sets up the Pod for Xcode:

| What | Value | Why |
|---|---|---|
| Read access | Xcode's compilers, linker, SDKs, `usr/bin`, the IDE plug-ins, Xcode's `git`, and the directories on the way to each | `xcodebuild` registers its plug-ins before it opens a project; `actool` finds `ibtoold` by walking `usr` |
| `DEVELOPER_DIR` | the node's developer directory | The shims' own lookup reads a path the sandbox denies |
| `HOME` | `<data volume>/home`, a directory made for the Pod (mode 0700) | A Pod has no writable home otherwise |
| `CFFIXED_USER_HOME` | the Pod's effective `HOME` | Xcode ignores `$HOME` and asks the user database, which names `/var/lib/k3sm`, a directory no Pod can write |
| `USER`, `LOGNAME` | the Pod's user name | XcodeGen stops with `Couldn't find current username` without them |
| `PATH` | `$DEVELOPER_DIR/usr/bin:$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin`, only when no `PATH` is set | Puts Xcode's own tools ahead of the `/usr/bin` trampolines |
| `~/.gitconfig` | `safe.directory = *`, written once into the Pod's home | Git refuses a repository another user owns, such as a host-shared checkout |
| `xcodebuild` arguments | `-IDEPackageSupportDisableManifestSandbox=YES`, `-IDEPackageSupportDisablePluginExecutionSandbox=YES` and the build setting `SWIFTC_DISABLE_SANDBOX=YES` | SwiftPM manifests, package plug-ins and Swift macros each start a sandbox of their own, and macOS refuses a sandbox inside the Pod's |

Each variable is set only when the image and the Pod spec do not set it already; a value you set
wins. The `xcodebuild` arguments are added when a Pod runs Xcode's `xcodebuild`
(`$DEVELOPER_DIR/usr/bin/xcodebuild`, or plain `xcodebuild` on the default `PATH`) and k3sm swaps in
its copy. Calling the copy directly, `/Library/k3sm/shadow/xcodebuild`, adds nothing. The build
setting is left out of the tool modes that take none (`-create-xcframework`, `-exportArchive`,
`-exportLocalizations`, `-importLocalizations`, `-exportNotarizedApp`), and a value you pass wins.

`safe.directory = *` turns git's ownership check off for the Pod's git, in every repository the Pod
can reach. A repository's own configuration then takes effect there, including hooks and settings
such as `core.fsmonitor` that run a command. Mount only checkouts you trust into a build Pod, or
replace `~/.gitconfig` in the Pod with the paths you mean.

Turning the nested sandboxes off means a dependency's manifest, package plug-ins and macros run
with the Pod's own reach, the same as `swift build --disable-sandbox`: whatever the Pod can read,
write or reach on the network, they can too. They are still confined by the Pod's sandbox, which is
why k3sm turns them off rather than failing every package build. This holds for every `xcodebuild`
run in a Pod with the annotation, so treat the Pod as the boundary: dependency code can use the
Pod's network, write its data volume and any writable volume or host share it mounts, and write the
build cache the Pod publishes (below). Pin dependencies, and do not give a Pod that builds
packages you do not trust a writable share or a cache key that trusted builds use. To keep a nested sandbox on, pass
`-IDEPackageSupportDisableManifestSandbox=NO`, `-IDEPackageSupportDisablePluginExecutionSandbox=NO`
or `SWIFTC_DISABLE_SANDBOX=NO` yourself; inside a Pod that step then fails with the
`sandbox_apply` error below. A preference file cannot change any of this in a Pod, because a Pod
reaches no `cfprefsd`.

`kubectl apply` prints an admission warning for a hand-set annotation
(`k3sm-warn-pod-hand-set-xcode-toolchain`). It is advice, not a refusal: the annotation is meant to
be stamped by a controller acting for the Pod, and hand-setting it still works.

Nothing else about the Pod changes. It runs as the same `_k3sm` user with the same sandbox, and the
grant is read access only.

A Pod that asks on a node that cannot honour it still starts. The Pod carries a Warning Event in
`kubectl describe pod`:

- `XcodeToolchainUngranted`: the node has no full Xcode selected.
- `XcodebuildCopyUnavailable`: the grant took effect, but one of the tool copies is missing, stale
  after an update, or was skipped by the installer. The message names which one, and the fix is
  `sudo k3sm install`. `clang`, `swiftc` and `swift build` still work in that Pod.

## A Minimal Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: xcode-shell
  annotations:
    k3sm.io/xcode-toolchain: "true"
spec:
  nodeName: my-mac            # a node with Xcode
  nodeSelector:
    kubernetes.io/os: darwin
  tolerations:
  - {key: k3sm.io/provider, operator: Exists, effect: NoSchedule}
  containers:
  - name: shell
    image: native             # a host binary; command[0] is its absolute path
    command: ["/bin/sh", "-c", "sleep 86400"]
    resources:
      requests: {cpu: "2", memory: 4Gi}
```

Then work in it:

```sh
kubectl exec -it xcode-shell -- /bin/sh
xcodebuild -version
cd "$K3SM_ROOTFS" && git clone https://github.com/example/app.git && cd app
xcodebuild -scheme App -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

## A Build Job

A Job runs one build to completion and reports its exit code. This one clones a repository, builds
it and lists the product:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: app-build
spec:
  backoffLimit: 0
  template:
    metadata:
      annotations:
        k3sm.io/xcode-toolchain: "true"
        k3sm.io/xcode-cache: "app-debug"    # optional: see DerivedData and Caching
    spec:
      restartPolicy: Never
      nodeName: my-mac
      nodeSelector:
        kubernetes.io/os: darwin
      tolerations:
      - {key: k3sm.io/provider, operator: Exists, effect: NoSchedule}
      containers:
      - name: build
        image: native
        command:
        - /bin/sh
        - -ec
        - |
          cd "$K3SM_ROOTFS"
          git clone --depth 1 https://github.com/example/app.git src
          cd src
          xcodebuild -project App.xcodeproj -scheme App -configuration Debug \
            CODE_SIGNING_ALLOWED=NO build
          ls -d "$HOME"/Library/Developer/Xcode/DerivedData/*/Build/Products/Debug/*.app
        resources:
          requests: {cpu: "4", memory: 8Gi}
```

To build a checkout that lives on the Mac instead, share it with a `hostPath` volume. The node's
host-share allowlist must name the path first (`sudo k3sm share`), and a share is read-only, so
clone it into the data volume before you build: `git clone /Users/me/src/app "$K3SM_ROOTFS/app"`.

## XcodeGen and SwiftPM

**XcodeGen.** A native Pod runs host binaries and has no toolchain image, so there is no XcodeGen
to install into. Build it from source in the Pod, pinned to a release commit, and keep the binary
in a cache you reuse:

```sh
cd "$K3SM_ROOTFS"
git clone https://github.com/yonaskolb/XcodeGen.git && cd XcodeGen
git checkout 8445e778        # 2.46.0; pin the commit you reviewed
swift build -c release --disable-sandbox
./.build/release/xcodegen generate --spec "$K3SM_ROOTFS/app/project.yml"
```

**SwiftPM inside `xcodebuild`** needs nothing from you: package resolution, package plug-ins and
macros work through k3sm's `xcodebuild` copy (see the table above). Dependencies are fetched with
Xcode's own `git`. A dependency over `https` that needs credentials fails, because a Pod reaches no
keychain; use a public URL or vendor the package.

**`swift build` and `swift test`** on their own still need `--disable-sandbox`, and the toolchain's
`bin` ahead of `/usr/bin` (the default `PATH` above does that). See
[the limitations page](limitations.md#swiftpm-and-xcodebuild-builds-in-a-pod).

## DerivedData and Caching

The default DerivedData is `$HOME/Library/Developer/Xcode/DerivedData`, inside the Pod's own data
volume. It is a real path, the same inside the Pod and on the node, which is what Xcode's build
database needs. Leave it at the default, or pass `-derivedDataPath` under `$K3SM_ROOTFS`. Do not
put it under a volume's mount path such as `/work`. k3sm rewrites mount paths for the Pod's
processes, the build database then opens a path that differs from the one it recorded, and the
build fails with `unable to attach DB`.

The data volume is removed with the Pod, so every new Pod builds cold. The build cache is opt-in:
a Pod without the annotation below neither reads nor writes one. It is also unbounded for now,
with no size limit and no eviction, so decide which Pods may use it. To keep builds warm, add
`k3sm.io/xcode-cache: "<key>"` beside the toolchain annotation. The key is lower case and matches
`^[a-z0-9][a-z0-9._-]{0,62}$`; name it after the project and configuration, such as `app-debug`.

- A cache is kept per node, per namespace, per key and per Xcode build. A cache made by one Xcode
  is never handed to another.
- When the Pod starts, it gets a copy-on-write clone (APFS `clonefile`) of the last published
  DerivedData and the SwiftPM cache (`~/Library/Caches/org.swift.swiftpm`). The clone takes moments
  whatever its size, and the Pod writes only its own clone, so concurrent builds with one key
  never touch each other's files.
- When the Pod is deleted, its DerivedData is published back, but only if every main container
  exited 0. A failed or interrupted build never replaces a good cache. When two successful
  builds finish, the later one wins.
- A Job fits this model: it builds once, exits 0, and publishes when it is cleaned up
  (`ttlSecondsAfterFinished`, or `kubectl delete job`).
- One namespace and key is one trust domain over time. Any Pod that may carry the annotation in
  that namespace, and exits 0, decides what the next build with that key starts from, including
  compiled modules and fetched packages. Builds of different trust, such as a fork's pull request
  and a release, need different keys or namespaces.
- Nothing evicts a cache and there is no size limit. A snapshot stays until an operator removes
  `xcode-cache/<namespace>/<key>` under the node's state directory (`/var/lib/k3sm` by default).

Not yet measured in a Pod. In a host simulation of the Pod profile on a Mac Studio (the Pod's
Seatbelt profile applied with `sandbox-exec`, Xcode 27.1), a cold Debug build of the Yureisha app,
with its SwiftPM packages, macros and asset catalog, took 78 s. The warm figure and the in-Pod
figures are added once they are measured on a node.

## Signing and Entitlements

Sign ad hoc or not at all: `CODE_SIGNING_ALLOWED=NO`, or `CODE_SIGN_IDENTITY=-`. A Developer ID
or Apple Development identity lives in a keychain, which a Pod cannot read. Simulators, devices,
`xcodebuild test` against anything but `platform=macOS`, and anything that talks to a running Xcode
are not available either.

**Why k3sm runs copies of Apple's tools.** Apple signs `xcodebuild` with private entitlements,
ships `xcrun` as a platform binary, and signs `actool`, `ibtool` and `ibtoold` with library
validation. macOS treats each of these as restricted, so they drop k3sm's path-rebase shim and the
per-Pod temp-directory setting. Without them, Xcode writes to directories the Pod does not own,
and an atomic save, such as an app icon's `.icns`, fails. `sudo k3sm install` therefore copies
each tool into the node's shadow directory, rewrites `xcodebuild`'s relative library paths, and
re-signs every copy ad hoc without the entitlements. k3sm then runs the copy whenever a Pod execs
the original. The installer makes the copies only when Xcode and every directory above it are
owned by root and writable by no one but root and the admin group, and only from binaries Apple
signed. A copy has no entitlements and no hardened runtime, so it honours `DYLD_*` variables from
the Pod's environment. That runs code inside the Pod's own sandbox and gains the Pod nothing.

If a shell or tool in a Pod execs Xcode's `xcodebuild`, `actool`, `ibtool` or `ibtoold` on a node
whose shadow set has no usable copy of it, the exec fails at once (`ENOEXEC`) with
`k3sm: refusing to run <path> in this pod: the node has no usable re-signed copy …`, naming
`sudo k3sm install`. When the install skipped the copy (an Xcode not owned by root, or not signed
by Apple), `k3sm doctor` names the reason. Earlier releases started the original, which never
finished. A container whose own `command` is Xcode's `xcodebuild` starts through the node daemon
instead, which logs a warning and falls back to Apple's binary; the Pod's
`XcodebuildCopyUnavailable` Event is the signal there.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `xcodebuild -list` or a build sits at 0% CPU and never finishes | An older node whose profile does not read Xcode's `Contents/PlugIns`, or a node without the `xcodebuild` copy | Upgrade the node and run `sudo k3sm install`; check `k3sm doctor` |
| `k3sm: refusing to run <path> in this pod: the node has no usable re-signed copy …` | No usable copy of that Xcode tool on the node | Run `sudo k3sm install`; if it skipped the copy, `k3sm doctor` says why |
| `XcodebuildCopyUnavailable` Event on the Pod | A tool copy is missing, stale after an Xcode or macOS update, or was skipped | Run `sudo k3sm install`; the Event names the copy |
| `You don't have permission to save the file "repositories" in the folder "SourcePackages"`, or another write under `Library` | Xcode used the node user's home, `/var/lib/k3sm`, because `CFFIXED_USER_HOME` was not set | Upgrade the node, or set `HOME` and `CFFIXED_USER_HOME` to a directory under `$K3SM_ROOTFS` |
| `You don't have permission to save the file` (Cocoa error 513) or `EXDEV` on an atomic save | The write was staged in a volume's shared `.TemporaryItems`: the file is on another disk, or a restricted tool lost the shim | Keep the build in the data volume; on an old node, run `sudo k3sm install` for the `actool` and `ibtool` copies |
| `Failed to write ICNS data for app icon` | `actool` running without its copy | Run `sudo k3sm install` |
| `unable to attach DB` | DerivedData under a rewritten mount path such as `/work` | Use the default DerivedData or a path under `$K3SM_ROOTFS` |
| `fatal: detected dubious ownership in repository` | The repository is owned by another user, such as a host-shared checkout | Upgrade the node (the Pod's `~/.gitconfig` then sets `safe.directory = *`), or `git -c safe.directory='*' …` |
| `could not read Username for 'https://…'`, or the keychain helper failing | A private dependency needs credentials, and a Pod has no keychain | Use a public URL, vendor the package, or fetch it outside the Pod |
| `sandbox-exec: sandbox_apply: Operation not permitted` while resolving packages | SwiftPM's nested manifest sandbox | Upgrade the node; for an old one, pass `-IDEPackageSupportDisableManifestSandbox=YES -IDEPackageSupportDisablePluginExecutionSandbox=YES` |
| `swift-plugin-server produced malformed response` on a macro | The compiler's nested macro sandbox | Upgrade the node; for an old one, pass `SWIFTC_DISABLE_SANDBOX=YES` |
| `Could not locate ibtoold.` | An old node: its profile cannot see `$DEVELOPER_DIR/usr` itself | Upgrade the node |
| `Could not locate ibtoold.` on an upgraded node | An `actool` copy with no `ibtoold` copy beside it | Run `sudo k3sm install` |
| `sandbox_extension_issue_file failed for … (Operation not permitted)` from `ibtoold` | Noise: `ibtoold` cannot hand out a sandbox extension | Not a failure; the output is written |
| `Couldn't find current username` from XcodeGen | `USER` and `LOGNAME` are unset | Upgrade the node, or set both in the Pod spec |
| `couldNotFindTmpDir` at the link step of `swift build` | The build started through `/usr/bin/swift`, Apple's shim | Put the toolchain's `bin` first on `PATH` |
| `xcodebuild` behaves as if the copy did not exist | It started as `/usr/bin/xcodebuild`, the system trampoline, with a `PATH` you set | Put `$DEVELOPER_DIR/usr/bin` before `/usr/bin`, or call `$DEVELOPER_DIR/usr/bin/xcodebuild` |
| `couldn't create cache file '/var/folders/…/xcrun_db-…'` | `xcrun`'s lookup cache, on a node installed before the `xcrun` copy | Not a failure; the command succeeds. `sudo k3sm install` removes it |

## Verify a Node

On the node, run `k3sm doctor` and read two rows. `toolchain` says whether the annotation grants
the node's Xcode. `shadow-shells` says whether the tool copies are present and current. When either
warns, its fix is repeated under `Next:`. `k3sm status` shows the same `shadow-shells` row.

Then run a build end to end. k3sm has no verify subcommand; this Job is the check. It prints the
Xcode version, builds a one-file app and runs it:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: xcode-verify
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      annotations:
        k3sm.io/xcode-toolchain: "true"
    spec:
      restartPolicy: Never
      nodeName: my-mac
      nodeSelector:
        kubernetes.io/os: darwin
      tolerations:
      - {key: k3sm.io/provider, operator: Exists, effect: NoSchedule}
      containers:
      - name: verify
        image: native
        command:
        - /bin/sh
        - -ec
        - |
          xcodebuild -version
          mkdir -p "$K3SM_ROOTFS/v/Sources" && cd "$K3SM_ROOTFS/v"
          printf 'print("hello from a pod")\n' > Sources/main.swift
          cat > Package.swift <<'EOF'
          // swift-tools-version:5.9
          import PackageDescription
          let package = Package(name: "Verify", targets: [.executableTarget(name: "Verify", path: "Sources")])
          EOF
          xcodebuild -scheme Verify -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
          "$(find "$HOME/Library/Developer/Xcode/DerivedData" -path '*Products/Debug/Verify' -type f | head -1)"
```

```sh
kubectl apply -f xcode-verify.yaml
kubectl wait --for=condition=complete job/xcode-verify --timeout=10m
kubectl logs job/xcode-verify | tail -1      # hello from a pod
```

If the Job fails, `kubectl describe pod -l job-name=xcode-verify` shows any
`XcodeToolchainUngranted` or `XcodebuildCopyUnavailable` Event, and the log's last lines match a row
in the table above.
