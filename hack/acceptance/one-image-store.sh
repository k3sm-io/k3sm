#!/usr/bin/env bash
#
# k3sm one-image-store lab gate: the cluster registry is the one place images are
# stored, every node reaches it by the one flat name registry-k3sm:6450, and the
# node stores are pull caches.
#
# It runs against the RUNNING two-Mac cluster in $KUBECONFIG and boots nothing. The
# driver has already installed the build under test on both Macs (agent first,
# server last), polled the join port before the agent rejoin, and re-copied the
# kubeconfig. Every Kubernetes object it creates lives in one namespace minted per
# run; every registry tag it creates is named under the run's own repositories. The
# exit trap brings the server back if a leg stopped it, deletes the namespace, untags
# every tag, prunes the registry and both node caches, and removes the build context
# it copied to the worker, green or red.
#
# Legs (`--plan` prints them; the first red leg ends the run, exit 1, naming the leg):
#   ois.1   build on the worker: `k3sm build --tag registry-k3sm:6450/<run>/app:v1 .`
#           as the operator's own user (the push carries the user identity, a
#           TokenRequest for k3sm-registry/builder) exits 0, and `k3sm image ls -o json`
#           on the server lists that reference with a sha256 digest
#   ois.2   run on both nodes by the flat name: four native pods, one per node per
#           imagePullPolicy (Always, IfNotPresent), all reach Ready, and each
#           container's imageID carries the registry's digest
#   ois.3   cached on both: `k3sm image ls -o json` lists both nodes in cachedOn for
#           the reference (a node over the 50-entry status cap is reported, not failed)
#   ois.4   push from a native pod: the worker builds the push client image
#           (hack/acceptance/testdata/ois-pusher, `k3sm build --tag
#           registry-k3sm:6450/<run>/pusher:v1 .`), then a pod on the worker running
#           that image pushes a one-layer image to
#           registry-k3sm:6450/<run>-pods/native:v1 over HTTPS (cluster CA) with its
#           projected k3sm-registry token, the registry answers the manifest PUT with
#           201 and the digest the pod computed, and `image ls` lists it at that digest.
#           The client ships in the image because a platform binary (/usr/bin/curl)
#           loses the path-rebase and DNS shims in a native pod
#           (docs/user/limitations.md)
#   ois.5   push from a vm pod: the same push from a runtimeClassName vm pod, to
#           .../<run>-pods/vm:v1
#   ois.6   tag: `k3sm image tag` gives app:v1 three more tags (second, control,
#           uncached), each listed at app:v1's digest
#   ois.7   untag: `k3sm image untag` of app:second removes that tag and leaves app:v1
#           at its digest; untagging native:v1 leaves its manifest untagged for ois.8
#   ois.8   prune: the run first makes its own aged seed (a native pod running the
#           ois.4 push client image pushes a one-layer image whose content carries the run id to <run>-pods/aged:v1,
#           the server untags it, and its manifest blob in the registry root is
#           backdated two hours as root, past the one-hour prune grace), and
#           confirms the seed is still there; then the dry run (`-o json`) lists
#           that aged untagged manifest for deletion, keeps the just-untagged native
#           manifest as younger than the grace period, and names no tagged digest;
#           `--force` deletes the aged manifest (inspect by digest then fails), keeps
#           the young one (inspect still answers) and reports no failed deletion;
#           every app pod is still Ready
#   ois.9   the upgrade migration: the server's own journal (`image migrate --report
#           -o json`) is complete; `sudo k3sm image migrate -o json` on the seeded node
#           records $K3SM_OIS_PREMIGRATE_REF as migrated, present or renamed with a
#           target, `image ls` lists the target at the record's digest, a re-run
#           records it present (resumable, nothing pushed twice), and the node still
#           reports the source digest in status.images (nothing was deleted)
#   ois.10  server down: with io.k3sm.server booted out, both worker app pods still
#           answer HTTP on their pod IPs, and a worker `image pull` of app:uncached
#           fails, while the same pull of app:control succeeded just before; the
#           server is bootstrapped again and the cluster serves with both nodes Ready
#
# Seeding, done by the driver before the run (the gate cannot do it):
#   - $K3SM_OIS_PREMIGRATE_REF: BEFORE upgrading to the build under test, on the node
#     named by K3SM_OIS_PREMIGRATE_NODE (default the worker), load or build one user
#     image with the PREVIOUS release (`k3sm build -t ois-premig:v1 .` or
#     `sudo k3sm image load <tar>`), so it lives only in that node's store. After the
#     upgrade the node store is a pull cache and no verb can put a user image there.
#   The aged prune seed is NOT seeded by the driver: ois.8 makes it inside the run.
#   The cluster registry runs its own garbage collection (zot: gc on, gcDelay 1h,
#   gcInterval 6h; pkg/registrysvc/config.go), which deletes untagged manifests older
#   than an hour on its own sweeps, so a seed untagged an hour before the run is
#   usually gone by ois.8. `k3sm image prune` judges age by the manifest blob's
#   mtime (pkg/registrysvc/prune.go, PruneGrace one hour), so backdating that blob
#   right before the dry run gives prune an aged manifest zot has not swept. If the
#   seed is absent anyway, ois.8 fails naming the registry's garbage collection.
#
# Pods follow the lab rules: nodeName AND the darwin nodeSelector; tolerations are
# k3sm.io/provider plus only the keys in K3SM_LAB_TOLERATE_KEYS
# (hack/lab/lib/tolerations.sh); the vm pod's in-pod script rides a ConfigMap, and
# the native pods' push client rides its own image. Events are selected by involvedObject.uid.
#
# Environment (required under K3SM_LAB=1):
#   KUBECONFIG                 the admin kubeconfig of the running cluster
#   K3SM_OIS_SERVER_NODE       the server's node name
#   K3SM_OIS_WORKER_NODE       the joined worker's node name
#   K3SM_OIS_SERVER_SSH        ssh destination of the server Mac (`local` runs here)
#   K3SM_OIS_WORKER_SSH        ssh destination of the worker Mac (`local` runs here)
#   K3SM_OIS_PREMIGRATE_REF    the node-store reference seeded before the upgrade
# Optional:
#   K3SM_OIS_PREMIGRATE_NODE   the node the migration seed lives on (default: worker)
#   K3SM_OIS_VM_NODE           the node the vm pusher runs on (default: worker)
#   K3SM_OIS_VM_IMAGE          a Linux image with sh and curl
#                              (default: docker.io/curlimages/curl:8.10.1)
#   K3SM_OIS_SERVER_PLIST      the server LaunchDaemon (default:
#                              /Library/LaunchDaemons/io.k3sm.server.plist)
#   KUBECTL                    kubectl binary (default: kubectl)
#   K3SM_LAB_TOLERATE_KEYS     extra taint keys every pod tolerates with Exists
#
# Exit: 0 every leg held; 1 a leg failed (the run log names it); 2 the run did not
# happen: K3SM_LAB unset (SKIP, never a pass), a bad argument, or a refused
# precondition, with nothing created.
#
# Usage:  hack/acceptance/one-image-store.sh --plan        # the legs; contacts nothing
#         hack/acceptance/one-image-store.sh --self-test   # offline checks of this script
#         K3SM_LAB=1 ... hack/acceptance/one-image-store.sh [<evidence-dir>]
#             (default evidence dir: a new mktemp directory)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/one-image-store.sh"
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/tolerations.sh
. "$REPO_ROOT/hack/lab/lib/tolerations.sh"

GATE_NAME="one-image-store"
MODE="lab"
REG="registry-k3sm:6450"
VM_IMAGE="${K3SM_OIS_VM_IMAGE:-docker.io/curlimages/curl:8.10.1}"
SERVER_PLIST="${K3SM_OIS_SERVER_PLIST:-/Library/LaunchDaemons/io.k3sm.server.plist}"
# REGISTRY_ROOT is the registry's storage root as `sudo -n k3sm image prune` reads it:
# registrysvc.StateDir(<work-dir>) = <work-dir>/registry, and a root k3sm resolves
# its work dir to executor.DefaultWorkDir (/var/lib/k3sm/server).
REGISTRY_ROOT="/var/lib/k3sm/server/registry"
REQUIRED_ENV="KUBECONFIG K3SM_OIS_SERVER_NODE K3SM_OIS_WORKER_NODE K3SM_OIS_SERVER_SSH K3SM_OIS_WORKER_SSH K3SM_OIS_PREMIGRATE_REF"

# The leg table: `name|statement`. --plan prints it, the run reports against it, and
# --self-test checks every name is unique and run.
LEGS=(
	"ois.1|build on the worker as the operator's user lands registry-k3sm:6450/<run>/app:v1 in the registry"
	"ois.2|four native pods (both nodes x Always, IfNotPresent) run the flat name and carry the registry digest"
	"ois.3|image ls lists both nodes in cachedOn for the reference"
	"ois.4|a native pod pushes by the flat name with its projected token; the registry holds the pod's digest"
	"ois.5|a vm pod pushes by the flat name with its projected token; the registry holds the pod's digest"
	"ois.6|image tag adds three tags at app:v1's digest"
	"ois.7|image untag removes app:second and keeps app:v1; native:v1 is left untagged"
	"ois.8|prune deletes the aged untagged manifest, keeps the young one and every tagged one"
	"ois.9|the upgrade migration copies the seeded node-store image into the registry, resumably, deleting nothing"
	"ois.10|server down: the worker's cached pods keep serving and a new pull fails; the server comes back"
)

# ---- pure helpers (the --self-test surface) -----------------------------------------

# OIS_PY reads one JSON document on stdin and answers one question about it. The
# documents are `k3sm image ls -o json`, `k3sm image prune -o json` and the
# `k3sm image migrate -o json` journal.
OIS_PY='
import json, sys
op, a = sys.argv[1], sys.argv[2:]
d = json.load(sys.stdin)
def image(ref):
    for i in d.get("images") or []:
        if i.get("reference") == ref:
            return i
    return None
if op == "ls-digest":
    i = image(a[0]); print(i.get("digest", "") if i else "")
elif op == "ls-cached":
    i = image(a[0]); print(" ".join(i.get("cachedOn") or []) if i else "")
elif op == "ls-incomplete":
    print(" ".join(d.get("cachedOnIncomplete") or []))
elif op == "ls-platforms":
    i = image(a[0]); print(" ".join(i.get("platforms") or []) if i else "")
elif op == "prune-dry":
    print("true" if d.get("dryRun") else "false")
elif op == "prune-in":
    for m in (d.get("registry") or {}).get(a[0]) or []:
        if m.get("repository") == a[1] and m.get("digest") == a[2]:
            print(m.get("reason") or "listed"); break
elif op == "prune-digests":
    r = d.get("registry") or {}
    print(" ".join(m.get("digest", "") for k in ("manifests", "kept") for m in (r.get(k) or [])))
elif op == "prune-failed":
    print(len((d.get("registry") or {}).get("failed") or []))
elif op == "mig-complete":
    print("true" if d.get("complete") else "false")
elif op == "mig-record":
    want = a[0]
    for r in d.get("images") or []:
        ref = r.get("reference", "")
        if ref == want or ref.endswith("/" + want):
            print("\t".join([r.get("outcome", ""), r.get("target", "") or "-", r.get("digest", "") or "-", ",".join(r.get("sources") or []) or "-"]))
            break
else:
    sys.exit("unknown op " + op)
'
# ojson <op> [args...] < document
ojson() { python3 -c "$OIS_PY" "$@"; }

# manifest_blob <registry-root> <repository> <sha256:hex>: the path zot stores the
# manifest blob at (<root>/<repository>/blobs/sha256/<hex>, as prune.go's blobPath);
# fails on a digest of any other shape.
manifest_blob() {
	local root="$1" repo="$2" dg="$3"
	[[ "$dg" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
	[ -n "$repo" ] && [ -n "$root" ] || return 1
	case "$repo" in /* | *..*) return 1 ;; esac
	echo "$root/$repo/blobs/sha256/${dg#sha256:}"
}

# probe_field <log> <key>: the last value a pod reported for key (`OIS key=value`).
probe_field() {
	printf '%s\n' "$1" | awk -v k="OIS $2=" 'index($0, k) == 1 { v = substr($0, length(k) + 1) } END { print v }'
}

# untolerated_keys <taint-lines>: the NoSchedule/NoExecute taint keys (lines of
# key:Effect) the provider entry and K3SM_LAB_TOLERATE_KEYS leave untolerated.
untolerated_keys() {
	local lines="$1" t key effect keys out=""
	keys=" $(lab_tol_keys) " || exit 2
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		key="${t%:*}"
		effect="${t##*:}"
		[ "$effect" = PreferNoSchedule ] && continue
		[ "$key" = k3sm.io/provider ] && continue
		case "$keys" in *" $key "*) continue ;; esac
		out="${out:+$out }$key"
	done <<<"$lines"
	printf '%s' "$out"
}

# ---- in-pod and build-context files -------------------------------------------------

# push_script: the vm pod's in-pod pusher (POSIX sh, curl, in a Linux image). The
# native pods run the same push from testdata/ois-pusher instead (see push_pod). It builds a one-layer image in the
# emptyDir at /ois-work and pushes it to registry-k3sm:6450 over HTTPS, trusting the
# service-account CA and presenting the projected k3sm-registry token as the Basic
# password (from a netrc file, so it never sits in a process argument). It reports
# `OIS key=value` lines between `OIS begin` and `OIS end` and exits 0 only when the
# manifest PUT answered 201 with the digest it computed.
push_script() {
	cat <<'PUSH'
#!/bin/sh
set -u
emit() { printf 'OIS %s\n' "$*"; }
REG=registry-k3sm:6450
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
W=/ois-work
emit begin
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
size() { wc -c <"$1" | tr -d ' '; }
fail() { emit "error=$1"; emit end; exit 1; }
[ -r "$CA" ] || fail no-ca
[ -r /var/run/secrets/registry/token ] || fail no-token
umask 077
printf 'machine registry-k3sm login pod password %s\n' "$(cat /var/run/secrets/registry/token)" >"$W/netrc"
cr() { curl -sS --cacert "$CA" --netrc-file "$W/netrc" -m 60 "$@"; }
printf 'one-image-store %s %s\n' "$OIS_RUN" "$OIS_REPO" >"$W/payload.txt"
(cd "$W" && tar -cf layer.tar payload.txt) || fail tar
L="$(sha "$W/layer.tar")"
LS="$(size "$W/layer.tar")"
printf '{"architecture":"%s","os":"%s","rootfs":{"type":"layers","diff_ids":["sha256:%s"]},"config":{}}' "$OIS_ARCH" "$OIS_OS" "$L" >"$W/config.json"
C="$(sha "$W/config.json")"
CS="$(size "$W/config.json")"
upload() {
	hdr="$(cr -o /dev/null -D - -X POST "https://$REG/v2/$OIS_REPO/blobs/uploads/" | tr -d '\r')" || return 1
	emit "post_status_$2=$(printf '%s\n' "$hdr" | awk 'NR == 1 { print $2 }')"
	loc="$(printf '%s\n' "$hdr" | awk 'tolower($1) == "location:" { print $2 }')"
	[ -n "$loc" ] || return 1
	case "$loc" in http*) ;; *) loc="https://$REG$loc" ;; esac
	case "$loc" in *\?*) sep='&' ;; *) sep='?' ;; esac
	code="$(cr -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/octet-stream' --data-binary "@$1" "${loc}${sep}digest=sha256:$2")" || return 1
	emit "put_status_$2=$code"
	[ "$code" = 201 ]
}
upload "$W/layer.tar" "$L" || fail layer-upload
upload "$W/config.json" "$C" || fail config-upload
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:%s","size":%s}]}' "$C" "$CS" "$L" "$LS" >"$W/manifest.json"
M="sha256:$(sha "$W/manifest.json")"
emit "manifest_digest=$M"
hdr="$(cr -o /dev/null -D - -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$W/manifest.json" "https://$REG/v2/$OIS_REPO/manifests/$OIS_TAG" | tr -d '\r')" || fail manifest-put
emit "manifest_status=$(printf '%s\n' "$hdr" | awk 'NR == 1 { print $2 }')"
emit "registry_digest=$(printf '%s\n' "$hdr" | awk 'tolower($1) == "docker-content-digest:" { print $2 }')"
rm -f "$W/netrc"
emit end
[ "$(printf '%s\n' "$hdr" | awk 'NR == 1 { print $2 }')" = 201 ]
PUSH
}

# build_context <dir>: the native app image the worker builds, the hello-http fixture
# (darwin/arm64, built here) serving its id on :8080.
build_context() {
	local dir="$1"
	mkdir -p "$dir"
	(cd "$REPO_ROOT" && env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$dir/hello-http" ./e2e/testdata/cmd/hello-http) || return 1
	cat >"$dir/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY hello-http /bin/hello-http
ENTRYPOINT ["/bin/hello-http", "--id", "ois-app", "--addr", ":8080"]
DOCKERFILE
}

# pusher_context <dir>: the push client image the native pods run, built by the
# worker in ois.4: the ois-pusher fixture (darwin/arm64, built here), the same
# client and report grammar as push_script with no platform binary in the pod.
pusher_context() {
	local dir="$1"
	mkdir -p "$dir"
	(cd "$REPO_ROOT" && env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$dir/ois-pusher" ./hack/acceptance/testdata/ois-pusher) || return 1
	cat >"$dir/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY ois-pusher /bin/ois-pusher
ENTRYPOINT ["/bin/ois-pusher"]
DOCKERFILE
}

# ---- manifests ------------------------------------------------------------------------

# scripts_configmap <ns>
scripts_configmap() {
	echo "apiVersion: v1"
	echo "kind: ConfigMap"
	echo "metadata: {name: ois-scripts, namespace: $1}"
	echo "data:"
	echo "  push.sh: |"
	push_script | sed 's/^/    /'
}

# push_rbac <ns> <prefix>: the pusher ServiceAccount and its RoleBinding to the
# shipped k3sm:registry-pusher ClusterRole. The namespace label is applied apart.
push_rbac() {
	cat <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: ois-pusher, namespace: $1}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ois-registry-pusher, namespace: $1}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: "k3sm:registry-pusher"}
subjects: [{kind: ServiceAccount, name: ois-pusher, namespace: $1}]
EOF
}

# app_pod <ns> <name> <node> <image> <pull-policy> <tolerations>
app_pod() {
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1, labels: {app: ois-app}}
spec:
  nodeName: $3
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$6]
  containers:
  - name: app
    image: $4
    imagePullPolicy: $5
    ports: [{containerPort: 8080}]
EOF
}

# push_pod <ns> <name> <node> <kind native|vm> <repo> <tolerations> <run> [<native-image>]
# A vm pod runs push.sh from the ConfigMap with the Linux image's curl; a native pod
# runs the push client from its own image (pusher_context), in memory, with no
# ConfigMap and no scratch volume.
push_pod() {
	local image cmd rc os arch mounts vols
	if [ "$4" = vm ]; then
		image="$VM_IMAGE" cmd='["sh", "/ois/push.sh"]' rc="  runtimeClassName: vm" os=linux arch=arm64
		mounts="    - {name: ois, mountPath: /ois}
    - {name: work, mountPath: /ois-work}
"
		vols="  - {name: ois, configMap: {name: ois-scripts}}
  - {name: work, emptyDir: {}}
"
	else
		image="$8" cmd='["/bin/ois-pusher"]' rc="" os=darwin arch=arm64 mounts="" vols=""
	fi
	cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1}
spec:
  nodeName: $3
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [$6]
$rc
  serviceAccountName: ois-pusher
  restartPolicy: Never
  containers:
  - name: push
    image: $image
    command: $cmd
    env:
    - {name: OIS_REPO, value: "$5"}
    - {name: OIS_TAG, value: "v1"}
    - {name: OIS_OS, value: "$os"}
    - {name: OIS_ARCH, value: "$arch"}
    - {name: OIS_RUN, value: "$7"}
    volumeMounts:
${mounts}    - {name: registry-token, mountPath: /var/run/secrets/registry, readOnly: true}
  volumes:
${vols}  - name: registry-token
    projected:
      sources:
      - serviceAccountToken: {audience: k3sm-registry, expirationSeconds: 600, path: token}
EOF
}

# ---- --plan -----------------------------------------------------------------------------

plan() {
	local row
	echo "one-image-store lab gate: PLAN ONLY (contacts nothing)"
	echo "legs (the first red leg ends the run):"
	for row in "${LEGS[@]}"; do
		printf '  %-7s %s\n' "${row%%|*}" "${row#*|}"
	done
	echo "required under K3SM_LAB=1: $REQUIRED_ENV"
	echo "seeding: K3SM_OIS_PREMIGRATE_REF before the upgrade; ois.8 makes its own aged prune seed in the run (see the header)"
	echo "exit: 0 every leg held, 1 a leg failed, 2 not run (K3SM_LAB unset: SKIP; a bad argument; a refused precondition)"
}

# ---- --self-test --------------------------------------------------------------------------

self_test() {
	local bad=0 row name names="" dup="" src t m tmp fake out code tol
	check() { if [ "$1" = ok ]; then echo "ok    $2"; else echo "FAIL  $2"; bad=1; fi; }

	if command -v shellcheck >/dev/null 2>&1; then
		if out="$(shellcheck -x "$SELF" 2>&1)"; then check ok "shellcheck: clean"; else
			printf '%s\n' "$out"
			check no "shellcheck: clean"
		fi
	else
		echo "skip  shellcheck (not installed)"
	fi
	if push_script | sh -n 2>/dev/null; then check ok "in-pod pusher parses (sh -n)"; else check no "in-pod pusher parses (sh -n)"; fi

	src="$(cat "$SELF")"
	for row in "${LEGS[@]}"; do
		name="${row%%|*}"
		case " $names " in *" $name "*) dup="$name" ;; esac
		names="$names $name"
		case "$src" in *"run_leg $name"$'\n'*) ;; *) check no "leg $name is run by a run_leg call" ;; esac
	done
	check "$([ -z "$dup" ] && echo ok)" "leg names unique (${#LEGS[@]}:${names})"
	t="$(printf '%s\n' "$src" | grep -oE '^run_leg ois\.[0-9]+$' | sed 's/^run_leg //' | tr '\n' ' ')"
	check "$([ " $t" = "$names " ] && echo ok)" "legs run in table order ($t)"

	# The JSON readers, against documents in the shape the CLI emits.
	t='{"schemaVersion":1,"images":[{"reference":"registry-k3sm:6450/r/app:v1","digest":"sha256:aa","platforms":["darwin/arm64"],"cachedOn":["a","b"]}],"cachedOnIncomplete":["c"]}'
	check "$([ "$(printf '%s' "$t" | ojson ls-digest registry-k3sm:6450/r/app:v1)" = sha256:aa ] && echo ok)" "ls-digest: the reference's digest"
	check "$([ -z "$(printf '%s' "$t" | ojson ls-digest registry-k3sm:6450/r/app:v2)" ] && echo ok)" "ls-digest: an absent reference is empty"
	check "$([ "$(printf '%s' "$t" | ojson ls-cached registry-k3sm:6450/r/app:v1)" = "a b" ] && echo ok)" "ls-cached: the nodes"
	check "$([ "$(printf '%s' "$t" | ojson ls-incomplete)" = c ] && echo ok)" "ls-incomplete: the capped nodes"
	t='{"dryRun":true,"registry":{"name":"registry-k3sm:6450","manifests":[{"repository":"r-pods/aged","digest":"sha256:01"}],"kept":[{"repository":"r-pods/native","digest":"sha256:02","reason":"younger than the grace period"}],"failed":[{"repository":"q","digest":"sha256:03","error":"e"}]},"cache":{"blobs":[],"reclaimedBytes":0}}'
	check "$([ "$(printf '%s' "$t" | ojson prune-dry)" = true ] && echo ok)" "prune-dry"
	check "$([ "$(printf '%s' "$t" | ojson prune-in manifests r-pods/aged sha256:01)" = listed ] && echo ok)" "prune-in: a manifest to delete"
	check "$([ "$(printf '%s' "$t" | ojson prune-in kept r-pods/native sha256:02)" = "younger than the grace period" ] && echo ok)" "prune-in: a kept manifest's reason"
	check "$([ -z "$(printf '%s' "$t" | ojson prune-in manifests r-pods/native sha256:02)" ] && echo ok)" "prune-in: kept is not listed for deletion"
	check "$([ "$(printf '%s' "$t" | ojson prune-digests)" = "sha256:01 sha256:02" ] && echo ok)" "prune-digests: every planned digest"
	check "$([ "$(printf '%s' "$t" | ojson prune-failed)" = 1 ] && echo ok)" "prune-failed: the count"
	t='{"schema":1,"complete":true,"images":[{"reference":"docker.io/library/ois-premig:v1","platforms":["darwin/arm64"],"sources":["sha256:0b","sha256:0a"],"outcome":"migrated","target":"registry-k3sm:6450/ois-premig:v1","digest":"sha256:0a"}]}'
	check "$([ "$(printf '%s' "$t" | ojson mig-complete)" = true ] && echo ok)" "mig-complete"
	check "$([ "$(printf '%s' "$t" | ojson mig-record ois-premig:v1)" = "$(printf 'migrated\tregistry-k3sm:6450/ois-premig:v1\tsha256:0a\tsha256:0b,sha256:0a')" ] && echo ok)" "mig-record: matched by its trailing reference"
	check "$([ -z "$(printf '%s' "$t" | ojson mig-record other:v1)" ] && echo ok)" "mig-record: an absent reference is empty"
	t="$(printf 'sha256:%064d' 0)"
	check "$([ "$(manifest_blob /r ois-1-pods/aged "$t")" = "/r/ois-1-pods/aged/blobs/sha256/${t#sha256:}" ] && echo ok)" "manifest_blob: <root>/<repository>/blobs/sha256/<hex>"
	check "$(if manifest_blob /r x "sha256:abc" >/dev/null; then echo no; else echo ok; fi)" "manifest_blob: a short digest is refused"
	check "$(if manifest_blob /r ../x "$t" >/dev/null; then echo no; else echo ok; fi)" "manifest_blob: a repository escaping the root is refused"
	check "$(if manifest_blob /r "" "$t" >/dev/null; then echo no; else echo ok; fi)" "manifest_blob: no repository is refused"
	case "$src" in *$'leg_push_native() {\n\tbuild_pusher || return 1'*) check ok "ois.4 builds the push client image before its push" ;; *) check no "ois.4 builds the push client image before its push" ;; esac
	case "$src" in *K3SM_OIS_PRUNE""_AGED*) check no "no operator-made aged seed is read" ;; *) check ok "no operator-made aged seed is read" ;; esac
	case "$src" in *$'leg_prune() {\n'*'seed_aged || return 1'*'ojson prune-dry'*) check ok "ois.8 makes its aged seed before the dry run" ;; *) check no "ois.8 makes its aged seed before the dry run" ;; esac
	t=$'OIS begin\nOIS manifest_status=401\nOIS manifest_status=201\nOIS end'
	check "$([ "$(probe_field "$t" manifest_status)" = 201 ] && echo ok)" "probe_field: the last report wins"
	t=$'k3sm.io/provider:NoSchedule\nexample.io/estate-off:NoExecute\nexample.io/soft:PreferNoSchedule'
	check "$([ "$(K3SM_LAB_TOLERATE_KEYS="" untolerated_keys "$t")" = example.io/estate-off ] && echo ok)" "untolerated_keys: an unnamed NoExecute key"
	check "$([ -z "$(K3SM_LAB_TOLERATE_KEYS="example.io/estate-off" untolerated_keys "$t")" ] && echo ok)" "untolerated_keys: a named key is tolerated"

	tol="$(K3SM_LAB_TOLERATE_KEYS="" lab_tolerations_yaml "")"
	for m in "$(app_pod ns-x ois-app-a node-a "$REG/r/app:v1" Always "$tol")" \
		"$(push_pod ns-x ois-push-native node-a native r-pods/native "$tol" r "$REG/r/pusher:v1")" \
		"$(push_pod ns-x ois-push-vm node-b vm r-pods/vm "$tol" r)"; do
		name="$(printf '%s\n' "$m" | sed -n 's/^metadata: {name: \([^,]*\),.*/\1/p')"
		case "$m" in *"nodeName: node-"*) check ok "$name: nodeName" ;; *) check no "$name: nodeName" ;; esac
		case "$m" in *"nodeSelector: {kubernetes.io/os: darwin}"*) check ok "$name: darwin nodeSelector" ;; *) check no "$name: darwin nodeSelector" ;; esac
		case "$m" in *"tolerations: [$tol]"*) check ok "$name: tolerations from the helper" ;; *) check no "$name: tolerations from the helper" ;; esac
		case "$m" in *"{operator"*) check no "$name: no key-less toleration" ;; *) check ok "$name: no key-less toleration" ;; esac
	done
	m="$(app_pod ns-x ois-app-a node-a "$REG/r/app:v1" IfNotPresent "$tol")"
	case "$m" in *"image: $REG/r/app:v1"*"imagePullPolicy: IfNotPresent"*) check ok "app pod: the flat name and the pull policy" ;; *) check no "app pod: the flat name and the pull policy" ;; esac
	m="$(push_pod ns-x ois-push-vm node-b vm r-pods/vm "$tol" r)"
	case "$m" in *"runtimeClassName: vm"*"image: $VM_IMAGE"*'command: ["sh", "/ois/push.sh"]'*) check ok "vm pusher: runtimeClassName vm, the Linux image, the ConfigMap script" ;; *) check no "vm pusher: runtimeClassName vm, the Linux image, the ConfigMap script" ;; esac
	case "$m" in *"audience: k3sm-registry"*"path: token"*) check ok "pusher: a projected k3sm-registry token" ;; *) check no "pusher: a projected k3sm-registry token" ;; esac
	case "$m" in *'mountPath: /ois}'*'mountPath: /ois-work}'*"configMap: {name: ois-scripts}"*"emptyDir: {}"*) check ok "vm pusher: the ConfigMap and the scratch volume" ;; *) check no "vm pusher: the ConfigMap and the scratch volume" ;; esac
	m="$(push_pod ns-x ois-push-native node-a native r-pods/native "$tol" r "$REG/r/pusher:v1")"
	case "$m" in *runtimeClassName*) check no "native pusher: no runtimeClassName" ;; *"image: $REG/r/pusher:v1"*'command: ["/bin/ois-pusher"]'*) check ok "native pusher: the client from its own image" ;; *) check no "native pusher: the client from its own image" ;; esac
	case "$m" in *push.sh* | *ois-scripts* | */ois-work* | */usr/bin/*) check no "native pusher: no ConfigMap script, scratch mount or platform binary" ;; *) check ok "native pusher: no ConfigMap script, scratch mount or platform binary" ;; esac
	case "$m" in *"mountPath: /var/run/secrets/registry"*"audience: k3sm-registry"*"path: token"*) check ok "native pusher: a projected k3sm-registry token" ;; *) check no "native pusher: a projected k3sm-registry token" ;; esac
	m="$(scripts_configmap ns-x)"
	case "$m" in *"  push.sh: |"*"    emit end"*) check ok "ConfigMap: the pusher, indented" ;; *) check no "ConfigMap: the pusher, indented" ;; esac
	m="$(push_rbac ns-x r-pods)"
	case "$m" in *'name: "k3sm:registry-pusher"'*"kind: ServiceAccount, name: ois-pusher"*) check ok "pusher RBAC: a RoleBinding to k3sm:registry-pusher" ;; *) check no "pusher RBAC: a RoleBinding to k3sm:registry-pusher" ;; esac

	# The exit contract, run as child processes with kubectl, ssh, scp and sudo
	# stand-ins that record any call: nothing may reach a host.
	tmp="$(mktemp -d "${TMPDIR:-/tmp}/ois-selftest.XXXXXX")"
	mkdir -p "$tmp/bin"
	for fake in kubectl ssh scp sudo go; do
		printf '#!/bin/sh\necho %s "$@" >>"%s/calls.log"\nexit 1\n' "$fake" "$tmp" >"$tmp/bin/$fake"
		chmod +x "$tmp/bin/$fake"
	done
	t="PATH=$tmp/bin:/usr/bin:/bin"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" 2>&1)" && code=0 || code=$?
	case "$out" in *SKIP*"NOT a pass"*) ;; *) code=99 ;; esac
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB unset: SKIP, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=0 /bin/bash "$SELF" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "K3SM_LAB=0: SKIP, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --plan 2>&1)" && code=0 || code=$?
	for row in "${LEGS[@]}"; do
		case "$out" in *"${row%%|*} "*) ;; *) code=98 ;; esac
	done
	check "$([ "$code" = 0 ] && echo ok)" "--plan: exit 0, every leg listed (got $code)"
	out="$(env -i "$t" HOME="$tmp" /bin/bash "$SELF" --bogus 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "an unknown option: exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 /bin/bash "$SELF" a b 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "two positional arguments: exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 /bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	case "$out" in *"K3SM_OIS_SERVER_NODE"*"K3SM_OIS_PREMIGRATE_REF"*) ;; *) code=97 ;; esac
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/evidence" ] && echo ok)" "K3SM_LAB=1, required variables unset: refused, exit 2, names them, no evidence dir (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 KUBECONFIG=/nonexistent K3SM_OIS_SERVER_NODE=a K3SM_OIS_WORKER_NODE=a \
		K3SM_OIS_SERVER_SSH=local K3SM_OIS_WORKER_SSH=local K3SM_OIS_PREMIGRATE_REF=x:v1 \
		/bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && echo ok)" "the same node as server and worker: refused, exit 2 (got $code)"
	out="$(env -i "$t" HOME="$tmp" K3SM_LAB=1 KUBECONFIG=/nonexistent K3SM_OIS_SERVER_NODE=a K3SM_OIS_WORKER_NODE=b \
		K3SM_OIS_SERVER_SSH=local K3SM_OIS_WORKER_SSH=local K3SM_OIS_PREMIGRATE_REF=x:v1 \
		/bin/bash "$SELF" "$tmp/evidence" 2>&1)" && code=0 || code=$?
	check "$([ "$code" = 2 ] && [ ! -e "$tmp/evidence" ] && echo ok)" "the cluster not serving: refused, exit 2, no evidence dir (got $code)"
	if grep -Eq '(^| )(apply|create|delete|label|patch|launchctl|build|push|untag|tag|prune|migrate)( |$)' "$tmp/calls.log" 2>/dev/null; then
		check no "no refused run made a write call: $(tr '\n' ';' <"$tmp/calls.log")"
	else
		check ok "no refused run made a write call"
	fi
	rm -rf "$tmp"

	if [ "$bad" = 0 ]; then echo "one-image-store self-test: green"; else echo "one-image-store self-test: RED"; fi
	return "$bad"
}

case "${1:-}" in
--plan)
	plan
	exit 0
	;;
--self-test)
	self_test
	exit $?
	;;
-h | --help)
	sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
	exit 0
	;;
-*)
	echo "one-image-store.sh: unknown option $1 (try --plan, --self-test)" >&2
	exit 2
	;;
esac

# ---- lab guard ---------------------------------------------------------------------------
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "one-image-store lab gate: SKIP (two Macs). Set K3SM_LAB=1 against the running two-node cluster to run it; this is NOT a pass."
	exit 2
fi

# ---- preconditions (exit 2, nothing created) ---------------------------------------------
refuse() {
	echo "one-image-store lab gate: REFUSED: $*" >&2
	exit 2
}
[ "$#" -le 1 ] || refuse "at most one argument, the evidence directory (got $#)"
missing=""
for v in $REQUIRED_ENV; do
	[ -n "${!v:-}" ] || missing="$missing $v"
done
[ -z "$missing" ] || refuse "required variable(s) unset:$missing (see the header of $SELF)"
SERVER="$K3SM_OIS_SERVER_NODE"
WORKER="$K3SM_OIS_WORKER_NODE"
[ "$SERVER" != "$WORKER" ] || refuse "K3SM_OIS_SERVER_NODE and K3SM_OIS_WORKER_NODE name the same node ($SERVER)"
SEED_NODE="${K3SM_OIS_PREMIGRATE_NODE:-$WORKER}"
VM_NODE="${K3SM_OIS_VM_NODE:-$WORKER}"
for n in "$SEED_NODE" "$VM_NODE"; do
	[ "$n" = "$SERVER" ] || [ "$n" = "$WORKER" ] || refuse "node $n is neither the server nor the worker"
done
KUBECTL="${KUBECTL:-kubectl}"
command -v "$KUBECTL" >/dev/null 2>&1 || refuse "kubectl not found ($KUBECTL)"
command -v python3 >/dev/null 2>&1 || refuse "python3 not found; the gate reads the CLI's JSON with it"
command -v go >/dev/null 2>&1 || refuse "go not found; the gate builds its app fixture here"
kc() { "$KUBECTL" "$@"; }
TOLERATIONS="$(lab_tolerations_yaml "")" || exit 2
kc get --raw /healthz >/dev/null 2>&1 || refuse "the cluster at \$KUBECONFIG is not serving (/healthz)"
for n in "$SERVER" "$WORKER"; do
	ready="$(kc get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
	[ "$ready" = True ] || refuse "node $n is not Ready (got '${ready:-absent}')"
	left="$(untolerated_keys "$(kc get node "$n" -o jsonpath='{range .spec.taints[*]}{.key}:{.effect}{"\n"}{end}')")" || exit 2
	[ -z "$left" ] || refuse "node $n carries taint key(s) this run does not tolerate: $left (name them in K3SM_LAB_TOLERATE_KEYS)"
done
kc get service registry-k3sm -n k3sm-registry >/dev/null 2>&1 || refuse "the registry-k3sm Service is not published in k3sm-registry"

# on <ssh-destination|local> <command>: run a command on a lab Mac in a login shell.
on() {
	local host="$1"
	shift
	if [ "$host" = local ]; then
		zsh -lc "$*"
	else
		ssh -o BatchMode=yes "$host" "zsh -lc $(printf '%q' "$*")"
	fi
}
on_server() { on "$K3SM_OIS_SERVER_SSH" "$@"; }
on_worker() { on "$K3SM_OIS_WORKER_SSH" "$@"; }
ssh_of() { if [ "$1" = "$SERVER" ]; then echo "$K3SM_OIS_SERVER_SSH"; else echo "$K3SM_OIS_WORKER_SSH"; fi; }
on_server 'k3sm version' >/dev/null 2>&1 || refuse "k3sm does not run on the server ($K3SM_OIS_SERVER_SSH)"
on_worker 'k3sm version' >/dev/null 2>&1 || refuse "k3sm does not run on the worker ($K3SM_OIS_WORKER_SSH)"
on_worker 'k3sm registry token --duration 10m >/dev/null' >/dev/null 2>&1 ||
	refuse "the worker's user cannot mint a registry token (write a user kubeconfig there: k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write)"
on_server 'sudo -n true' >/dev/null 2>&1 || refuse "passwordless sudo is not available on the server"
on "$(ssh_of "$SEED_NODE")" 'sudo -n true' >/dev/null 2>&1 || refuse "passwordless sudo is not available on $SEED_NODE"
on_worker 'sudo -n true' >/dev/null 2>&1 || refuse "passwordless sudo is not available on the worker"

EVIDENCE="${1:-}"
[ -n "$EVIDENCE" ] || EVIDENCE="$(mktemp -d "${TMPDIR:-/tmp}/one-image-store-evidence.XXXXXX")"
mkdir -p "$EVIDENCE"

# ---- the run ----------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR/../lab source=../lab/lib/runlog.sh
. "$REPO_ROOT/hack/lab/lib/runlog.sh"
RUN="ois-$(date -u +%m%d%H%M%S)"
NS="$RUN-lab"
APP_REPO="$RUN/app"
PUSH_PREFIX="$RUN-pods"
APP_V1="$REG/$APP_REPO:v1"
APP_SECOND="$REG/$APP_REPO:second"
APP_CONTROL="$REG/$APP_REPO:control"
APP_UNCACHED="$REG/$APP_REPO:uncached"
NATIVE_REF="$REG/$PUSH_PREFIX/native:v1"
AGED_REPO="$PUSH_PREFIX/aged"
AGED_REF="$REG/$AGED_REPO:v1"
VM_REF="$REG/$PUSH_PREFIX/vm:v1"
PUSHER_REF="$REG/$RUN/pusher:v1"
RUNLOG="$EVIDENCE/run.log"
emit_run_log_header FAIL >"$RUNLOG"
log() { printf '%s\n' "$*" | tee -a "$RUNLOG"; }

# Everything the trap undoes is recorded as it is created.
TAGS_CREATED=""
MIGRATED_TARGET=""
REMOTE_DIR=""
LOCAL_DIR=""
SERVER_DOWN=0
note_tag() { TAGS_CREATED="$TAGS_CREATED $1"; }

server_up() {
	on_server "sudo -n launchctl bootstrap system '$SERVER_PLIST'" >>"$EVIDENCE/server-restore.txt" 2>&1 || true
	local deadline=$((SECONDS + 300))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if kc get --raw /healthz >/dev/null 2>&1; then
			SERVER_DOWN=0
			return 0
		fi
		sleep 5
	done
	return 1
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	set +e
	if [ "$SERVER_DOWN" = 1 ]; then
		server_up || echo "cleanup: the server did not come back within 300s; restore io.k3sm.server by hand" >>"$RUNLOG"
	fi
	kc get pods -n "$NS" -o wide >"$EVIDENCE/final-pods.txt" 2>&1
	kc get events -n "$NS" -o wide >"$EVIDENCE/events.txt" 2>&1
	kc delete namespace "$NS" --wait=true --timeout=180s >/dev/null 2>&1
	kc get namespace "$NS" >/dev/null 2>&1 && echo "cleanup: namespace $NS is still terminating" >>"$RUNLOG"
	local ref
	for ref in $TAGS_CREATED $MIGRATED_TARGET; do
		on_server "sudo -n k3sm image untag '$ref'" >>"$EVIDENCE/cleanup-untag.txt" 2>&1
	done
	# The prune deletes only untagged manifests past the grace period and evicts only
	# cache entries no pod uses; the run's own manifests go on a later prune.
	on_server 'sudo -n k3sm image prune --force' >>"$EVIDENCE/cleanup-prune-server.txt" 2>&1
	on_worker 'sudo -n k3sm image prune --force' >>"$EVIDENCE/cleanup-prune-worker.txt" 2>&1
	[ -n "$REMOTE_DIR" ] && on_worker "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1
	[ -n "$LOCAL_DIR" ] && rm -rf "$LOCAL_DIR"
	kc get ns >"$EVIDENCE/final-namespaces.txt" 2>&1
}
trap cleanup EXIT

events_for() {
	local uid
	uid="$(kc get "$1" -n "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
	[ -n "$uid" ] || return 0
	echo "--- events for $1 (uid $uid)"
	kc get events -n "$NS" --field-selector "involvedObject.uid=$uid" -o wide 2>&1 || true
}
dump_failure() {
	local p
	for p in $(kc get pods -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null); do
		events_for "pod/$p" >>"$EVIDENCE/failure-events.txt"
		kc logs -n "$NS" "$p" >"$EVIDENCE/log-$p.txt" 2>&1 || true
	done
}

DETAIL=""
LEG=""
# Each leg is three statements: `run_leg <name>; <leg function> || leg_red; leg_pass`.
# run_leg opens it, leg_red ends the run on the first red leg, naming it.
run_leg() {
	local row desc=""
	LEG="$1"
	DETAIL=""
	for row in "${LEGS[@]}"; do [ "${row%%|*}" = "$LEG" ] && desc="${row#*|}"; done
	log "==> $LEG  $desc"
}
leg_pass() { log "PASS  $LEG  ${DETAIL}"; }
leg_red() {
	log "FAIL  $LEG  ${DETAIL}"
	dump_failure
	log "one-image-store: RED at leg $LEG (evidence $EVIDENCE)"
	emit_run_log_verdict FAIL >>"$RUNLOG"
	exit 1
}

# image_ls <evidence-name>: the server's `k3sm image ls -o json`, kept as evidence.
image_ls() { on_server 'k3sm image ls -o json' 2>"$EVIDENCE/$1.err" | tee "$EVIDENCE/$1.json"; }
wait_ready() {
	local deadline=$((SECONDS + $2))
	while [ "$SECONDS" -lt "$deadline" ]; do
		[ "$(kc get pod "$1" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && return 0
		sleep 3
	done
	return 1
}
wait_done() {
	local deadline=$((SECONDS + $2)) phase
	while [ "$SECONDS" -lt "$deadline" ]; do
		phase="$(kc get pod "$1" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)"
		case "$phase" in Succeeded | Failed)
			echo "$phase"
			return 0
			;;
		esac
		sleep 3
	done
	echo "${phase:-unknown}"
	return 1
}
# bounded <seconds> <command...>: run a command, killing it at the bound. Exit 124 on
# the bound (macOS has no timeout(1)).
bounded() {
	local secs="$1" pid killer rc=0
	shift
	"$@" &
	pid=$!
	(sleep "$secs" && kill "$pid") >/dev/null 2>&1 &
	killer=$!
	wait "$pid" || rc=$?
	if kill -0 "$killer" 2>/dev/null; then
		kill "$killer" 2>/dev/null
		wait "$killer" 2>/dev/null || true
	else
		rc=124
	fi
	return "$rc"
}

log "==> k3sm one-image-store lab gate: server $SERVER, worker $WORKER, run $RUN, namespace $NS, evidence $EVIDENCE"
log "    tolerations: [$TOLERATIONS]"

kc create namespace "$NS" >/dev/null
kc label namespace "$NS" "k3sm.io/registry-push=$PUSH_PREFIX" >/dev/null
scripts_configmap "$NS" >"$EVIDENCE/ois-scripts.yaml"
kc apply -f "$EVIDENCE/ois-scripts.yaml" >/dev/null
push_rbac "$NS" "$PUSH_PREFIX" >"$EVIDENCE/push-rbac.yaml"
kc apply -f "$EVIDENCE/push-rbac.yaml" >/dev/null

# ---- ois.1 build on the worker ----------------------------------------------------------
APP_DIGEST=""
leg_build() {
	LOCAL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ois-ctx.XXXXXX")"
	build_context "$LOCAL_DIR/ctx" || {
		DETAIL="could not build the hello-http fixture here"
		return 1
	}
	# shellcheck disable=SC2016 # expanded by the worker's shell
	REMOTE_DIR="$(on_worker 'mktemp -d "${TMPDIR:-/tmp}/ois-ctx.XXXXXX"' 2>/dev/null | tail -1)"
	[ -n "$REMOTE_DIR" ] || {
		DETAIL="could not make a work directory on the worker"
		return 1
	}
	if [ "$K3SM_OIS_WORKER_SSH" = local ]; then
		cp -R "$LOCAL_DIR/ctx" "$REMOTE_DIR/" || return 1
	else
		scp -q -r "$LOCAL_DIR/ctx" "$K3SM_OIS_WORKER_SSH:$REMOTE_DIR/" || {
			DETAIL="could not copy the build context to the worker"
			return 1
		}
	fi
	note_tag "$APP_V1"
	if ! on_worker "cd '$REMOTE_DIR/ctx' && k3sm build --tag '$APP_V1' ." >"$EVIDENCE/ois.1-build.txt" 2>&1; then
		DETAIL="k3sm build on the worker failed (ois.1-build.txt)"
		return 1
	fi
	APP_DIGEST="$(image_ls ois.1-image-ls | ojson ls-digest "$APP_V1" || true)"
	[[ "$APP_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || {
		DETAIL="image ls does not list $APP_V1 with a digest (got '${APP_DIGEST:-none}')"
		return 1
	}
	DETAIL="$APP_V1 @ $APP_DIGEST, built as the worker's user"
}
run_leg ois.1
leg_build || leg_red
leg_pass

# ---- ois.2 run on both nodes ------------------------------------------------------------
APP_PODS="ois-app-server-always ois-app-server-ifnp ois-app-worker-always ois-app-worker-ifnp"
pod_node() { case "$1" in *-server-*) echo "$SERVER" ;; *) echo "$WORKER" ;; esac }
pod_policy() { case "$1" in *-always) echo Always ;; *) echo IfNotPresent ;; esac }
leg_run_both() {
	local p id bad=""
	for p in $APP_PODS; do
		app_pod "$NS" "$p" "$(pod_node "$p")" "$APP_V1" "$(pod_policy "$p")" "$TOLERATIONS" >"$EVIDENCE/$p.yaml"
		kc apply -f "$EVIDENCE/$p.yaml" >/dev/null || return 1
	done
	for p in $APP_PODS; do
		if ! wait_ready "$p" 240; then
			bad="$bad $p(not Ready)"
			continue
		fi
		id="$(kc get pod "$p" -n "$NS" -o jsonpath='{.status.containerStatuses[0].imageID}')"
		case "$id" in *"$APP_DIGEST"*) ;; *) bad="$bad $p(imageID '$id')" ;; esac
	done
	[ -z "$bad" ] || {
		DETAIL="want Ready and imageID carrying $APP_DIGEST:$bad"
		return 1
	}
	DETAIL="4 pods Ready on $SERVER and $WORKER at $APP_DIGEST"
}
run_leg ois.2
leg_run_both || leg_red
leg_pass

# ---- ois.3 cached on both ---------------------------------------------------------------
leg_cached() {
	local deadline=$((SECONDS + 180)) doc cached inc n missing
	while :; do
		doc="$(image_ls ois.3-image-ls || true)"
		cached=" $(printf '%s' "$doc" | ojson ls-cached "$APP_V1" 2>/dev/null) "
		inc=" $(printf '%s' "$doc" | ojson ls-incomplete 2>/dev/null) "
		missing=""
		for n in "$SERVER" "$WORKER"; do
			case "$cached" in *" $n "*) continue ;; esac
			case "$inc" in *" $n "*) continue ;; esac
			missing="$missing $n"
		done
		[ -z "$missing" ] && break
		[ "$SECONDS" -ge "$deadline" ] && break
		sleep 10
	done
	[ -z "$missing" ] || {
		DETAIL="cachedOn lacks$missing (cachedOn:$cached)"
		return 1
	}
	DETAIL="cachedOn:${cached% }"
	case "$inc" in *" $SERVER "* | *" $WORKER "*) DETAIL="$DETAIL; NOTE over the status cap, not asserted:${inc% }" ;; esac
}
run_leg ois.3
leg_cached || leg_red
leg_pass

# ---- ois.4 / ois.5 pushes from pods -----------------------------------------------------
# push_leg <pod> <node> <native|vm> <repository> <reference>
push_leg() {
	local pod="$1" node="$2" kind="$3" repo="$4" ref="$5" phase logs status mine theirs listed err
	push_pod "$NS" "$pod" "$node" "$kind" "$repo" "$TOLERATIONS" "$RUN" "$PUSHER_REF" >"$EVIDENCE/$pod.yaml"
	note_tag "$ref"
	kc apply -f "$EVIDENCE/$pod.yaml" >/dev/null || return 1
	phase="$(wait_done "$pod" 300 || true)"
	logs="$(kc logs -n "$NS" "$pod" 2>&1 || true)"
	printf '%s\n' "$logs" >"$EVIDENCE/$pod.log"
	status="$(probe_field "$logs" manifest_status)"
	mine="$(probe_field "$logs" manifest_digest)"
	theirs="$(probe_field "$logs" registry_digest)"
	listed="$(image_ls "$pod-image-ls" | ojson ls-digest "$ref" || true)"
	err="$(probe_field "$logs" error)"
	DETAIL="$kind pod on $node: phase $phase, manifest PUT ${status:-none}, pod digest ${mine:-none}, registry ${theirs:-none}, image ls ${listed:-absent}${err:+, error $err}"
	[ "$phase" = Succeeded ] && [ "$status" = 201 ] && [ -n "$mine" ] && [ "$mine" = "$theirs" ] && [ "$listed" = "$mine" ]
}
# build_pusher: the worker builds the push client image the native pods run, from a
# context made here and copied beside ois.1's, as the worker's user (like ois.1).
build_pusher() {
	local got
	pusher_context "$LOCAL_DIR/pusher" || {
		DETAIL="could not build the ois-pusher fixture here"
		return 1
	}
	if [ "$K3SM_OIS_WORKER_SSH" = local ]; then
		cp -R "$LOCAL_DIR/pusher" "$REMOTE_DIR/" || return 1
	else
		scp -q -r "$LOCAL_DIR/pusher" "$K3SM_OIS_WORKER_SSH:$REMOTE_DIR/" || {
			DETAIL="could not copy the push client context to the worker"
			return 1
		}
	fi
	note_tag "$PUSHER_REF"
	if ! on_worker "cd '$REMOTE_DIR/pusher' && k3sm build --tag '$PUSHER_REF' ." >"$EVIDENCE/ois.4-build-pusher.txt" 2>&1; then
		DETAIL="k3sm build of the push client on the worker failed (ois.4-build-pusher.txt)"
		return 1
	fi
	got="$(image_ls ois.4-pusher-image-ls | ojson ls-digest "$PUSHER_REF" || true)"
	[[ "$got" =~ ^sha256:[0-9a-f]{64}$ ]] || {
		DETAIL="image ls does not list $PUSHER_REF with a digest (got '${got:-none}')"
		return 1
	}
}
NATIVE_DIGEST=""
leg_push_native() {
	build_pusher || return 1
	push_leg ois-push-native "$WORKER" native "$PUSH_PREFIX/native" "$NATIVE_REF" || return 1
	NATIVE_DIGEST="$(probe_field "$(cat "$EVIDENCE/ois-push-native.log")" manifest_digest)"
}
leg_push_vm() { push_leg ois-push-vm "$VM_NODE" vm "$PUSH_PREFIX/vm" "$VM_REF"; }
run_leg ois.4
leg_push_native || leg_red
leg_pass
run_leg ois.5
leg_push_vm || leg_red
leg_pass

# ---- ois.6 tag ---------------------------------------------------------------------------
leg_tag() {
	local ref doc got bad=""
	for ref in "$APP_SECOND" "$APP_CONTROL" "$APP_UNCACHED"; do
		note_tag "$ref"
		on_server "k3sm image tag '$APP_V1' '$ref'" >>"$EVIDENCE/ois.6-tag.txt" 2>&1 || bad="$bad $ref(tag failed)"
	done
	doc="$(image_ls ois.6-image-ls || true)"
	for ref in "$APP_SECOND" "$APP_CONTROL" "$APP_UNCACHED"; do
		got="$(printf '%s' "$doc" | ojson ls-digest "$ref" 2>/dev/null || true)"
		[ "$got" = "$APP_DIGEST" ] || bad="$bad $ref(@'${got:-absent}')"
	done
	[ -z "$bad" ] || {
		DETAIL="want each at $APP_DIGEST:$bad"
		return 1
	}
	DETAIL="second, control and uncached at $APP_DIGEST"
}
run_leg ois.6
leg_tag || leg_red
leg_pass

# ---- ois.7 untag -------------------------------------------------------------------------
leg_untag() {
	local doc v1 second native
	on_server "sudo -n k3sm image untag '$APP_SECOND'" >>"$EVIDENCE/ois.7-untag.txt" 2>&1 || {
		DETAIL="untag $APP_SECOND failed"
		return 1
	}
	on_server "sudo -n k3sm image untag '$NATIVE_REF'" >>"$EVIDENCE/ois.7-untag.txt" 2>&1 || {
		DETAIL="untag $NATIVE_REF failed"
		return 1
	}
	doc="$(image_ls ois.7-image-ls || true)"
	v1="$(printf '%s' "$doc" | ojson ls-digest "$APP_V1" 2>/dev/null || true)"
	second="$(printf '%s' "$doc" | ojson ls-digest "$APP_SECOND" 2>/dev/null || true)"
	native="$(printf '%s' "$doc" | ojson ls-digest "$NATIVE_REF" 2>/dev/null || true)"
	DETAIL="app:v1 @ ${v1:-absent}, app:second ${second:-gone}, native:v1 ${native:-gone}"
	[ "$v1" = "$APP_DIGEST" ] && [ -z "$second" ] && [ -z "$native" ]
}
run_leg ois.7
leg_untag || leg_red
leg_pass

# ---- ois.8 prune -------------------------------------------------------------------------
# seed_aged: the aged untagged manifest the prune must delete, made in the run because
# the registry's own garbage collection (zot, gcDelay 1h) sweeps untagged manifests
# older than an hour, so a seed made an hour ahead is usually gone. A native pod
# pushes a one-layer image carrying the run id (unique content per run) to
# <run>-pods/aged:v1, the server untags it, and the manifest blob's mtime, which
# prune reads as the manifest's age, is set two hours back as root. The ref is
# recorded for the trap like every run tag; a seed left behind is untagged and past
# the grace, so the trap's prune deletes it.
AGED_DIGEST=""
seed_aged() {
	local blob
	push_leg ois-push-aged "$WORKER" native "$AGED_REPO" "$AGED_REF" || {
		DETAIL="seed: the aged seed push failed: $DETAIL"
		return 1
	}
	AGED_DIGEST="$(probe_field "$(cat "$EVIDENCE/ois-push-aged.log")" manifest_digest)"
	blob="$(manifest_blob "$REGISTRY_ROOT" "$AGED_REPO" "$AGED_DIGEST")" || {
		DETAIL="seed: the pusher reported no usable digest ('${AGED_DIGEST:-none}')"
		return 1
	}
	on_server "sudo -n k3sm image untag '$AGED_REF'" >>"$EVIDENCE/ois.8-seed.txt" 2>&1 || {
		DETAIL="seed: untag $AGED_REF failed (ois.8-seed.txt)"
		return 1
	}
	# shellcheck disable=SC2016 # the date is the server's, expanded by its shell
	on_server 'sudo -n touch -t "$(date -v-2H +%Y%m%d%H%M)" '"'$blob'"' && sudo -n ls -lT '"'$blob'" >>"$EVIDENCE/ois.8-seed.txt" 2>&1 || {
		DETAIL="seed: could not backdate the manifest blob $blob on the server (ois.8-seed.txt)"
		return 1
	}
	if ! on_server "k3sm image inspect '$REG/$AGED_REPO@$AGED_DIGEST'" >"$EVIDENCE/ois.8-inspect-seed.txt" 2>&1; then
		DETAIL="seed: $AGED_REPO@$AGED_DIGEST is gone before the dry run; the registry's own garbage collection (zot gc) removed the untagged manifest, so prune had nothing aged to delete (ois.8-inspect-seed.txt)"
		return 1
	fi
}
leg_prune() {
	local dry force d digests p aged_after young_after
	seed_aged || return 1
	dry="$(on_server 'sudo -n k3sm image prune -o json' 2>"$EVIDENCE/ois.8-dry.err" | tee "$EVIDENCE/ois.8-dry.json")" || {
		DETAIL="the dry run failed"
		return 1
	}
	[ "$(printf '%s' "$dry" | ojson prune-dry)" = true ] || {
		DETAIL="the dry run did not report dryRun true"
		return 1
	}
	[ -n "$(printf '%s' "$dry" | ojson prune-in manifests "$AGED_REPO" "$AGED_DIGEST")" ] || {
		DETAIL="the dry run does not plan to delete $AGED_REPO@$AGED_DIGEST"
		return 1
	}
	[ "$(printf '%s' "$dry" | ojson prune-in kept "$PUSH_PREFIX/native" "$NATIVE_DIGEST")" = "younger than the grace period" ] || {
		DETAIL="the dry run does not keep the just-untagged $PUSH_PREFIX/native@$NATIVE_DIGEST as younger than the grace period"
		return 1
	}
	digests=" $(printf '%s' "$dry" | ojson prune-digests) "
	for d in "$APP_DIGEST" "$(image_ls ois.8-image-ls | ojson ls-digest "$VM_REF")"; do
		[ -n "$d" ] || continue
		case "$digests" in *" $d "*)
			DETAIL="the dry run names the tagged digest $d"
			return 1
			;;
		esac
	done
	force="$(on_server 'sudo -n k3sm image prune --force -o json' 2>"$EVIDENCE/ois.8-force.err" | tee "$EVIDENCE/ois.8-force.json")" || {
		DETAIL="prune --force failed"
		return 1
	}
	[ "$(printf '%s' "$force" | ojson prune-dry)" = false ] && [ "$(printf '%s' "$force" | ojson prune-failed)" = 0 ] || {
		DETAIL="prune --force reported a dry run or failed deletions"
		return 1
	}
	if on_server "k3sm image inspect '$REG/$AGED_REPO@$AGED_DIGEST'" >"$EVIDENCE/ois.8-inspect-aged.txt" 2>&1; then aged_after=present; else aged_after=gone; fi
	if on_server "k3sm image inspect '$REG/$PUSH_PREFIX/native@$NATIVE_DIGEST'" >"$EVIDENCE/ois.8-inspect-young.txt" 2>&1; then young_after=present; else young_after=gone; fi
	for p in $APP_PODS; do
		[ "$(kc get pod "$p" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] || {
			DETAIL="$p is not Ready after the prune"
			return 1
		}
	done
	DETAIL="aged $aged_after, young $young_after, every app pod Ready"
	[ "$aged_after" = gone ] && [ "$young_after" = present ]
}
run_leg ois.8
leg_prune || leg_red
leg_pass

# ---- ois.9 the upgrade migration --------------------------------------------------------
leg_migrate() {
	local seed_ssh first second rec outcome target digest sources listed images src found=""
	[ "$(on_server 'sudo -n k3sm image migrate --report -o json' 2>"$EVIDENCE/ois.9-server-report.err" | tee "$EVIDENCE/ois.9-server-report.json" | ojson mig-complete)" = true ] || {
		DETAIL="the server's own migration journal is not complete"
		return 1
	}
	seed_ssh="$(ssh_of "$SEED_NODE")"
	first="$(on "$seed_ssh" 'sudo -n k3sm image migrate -o json' 2>"$EVIDENCE/ois.9-first.err" | tee "$EVIDENCE/ois.9-first.json")" || {
		DETAIL="image migrate on $SEED_NODE failed"
		return 1
	}
	rec="$(printf '%s' "$first" | ojson mig-record "$K3SM_OIS_PREMIGRATE_REF")"
	IFS=$'\t' read -r outcome target digest sources <<<"${rec:-}"
	case "${outcome:-}" in migrated | present | renamed) ;; *)
		DETAIL="no migrated, present or renamed record for $K3SM_OIS_PREMIGRATE_REF (got '${rec:-none}')"
		return 1
		;;
	esac
	[ "$target" != - ] && [ "$digest" != - ] || {
		DETAIL="the record has no target or digest ($rec)"
		return 1
	}
	MIGRATED_TARGET="$target"
	listed="$(image_ls ois.9-image-ls | ojson ls-digest "$target" || true)"
	[ "$listed" = "$digest" ] || {
		DETAIL="image ls lists $target at '${listed:-absent}', the record says $digest"
		return 1
	}
	second="$(on "$seed_ssh" 'sudo -n k3sm image migrate -o json' 2>"$EVIDENCE/ois.9-second.err" | tee "$EVIDENCE/ois.9-second.json")" || {
		DETAIL="the re-run of image migrate failed"
		return 1
	}
	[ "$(printf '%s' "$second" | ojson mig-record "$K3SM_OIS_PREMIGRATE_REF" | cut -f1)" = present ] || {
		DETAIL="the re-run did not record $K3SM_OIS_PREMIGRATE_REF present"
		return 1
	}
	images="$(kc get node "$SEED_NODE" -o jsonpath='{range .status.images[*]}{.names}{"\n"}{end}' 2>/dev/null)"
	printf '%s\n' "$images" >"$EVIDENCE/ois.9-node-images.txt"
	for src in $(printf '%s' "$sources" | tr ',' ' '); do
		case "$images" in *"${src#sha256:}"*) found="$src" ;; esac
	done
	DETAIL="$K3SM_OIS_PREMIGRATE_REF $outcome -> $target @ $digest; re-run present; source ${found:-not in status.images}"
	if [ -z "$found" ]; then
		case " $(image_ls ois.9-image-ls-cap | ojson ls-incomplete) " in *" $SEED_NODE "*)
			DETAIL="$DETAIL (NOTE $SEED_NODE is over the 50-entry status cap, so the node store could not be read through it)"
			return 0
			;;
		esac
		return 1
	fi
}
run_leg ois.9
leg_migrate || leg_red
leg_pass

# ---- ois.10 server down -----------------------------------------------------------------
# worker_http <pod>: the pod's answer on its pod IP, asked from the worker host.
worker_http() {
	local ip
	ip="$(kc get pod "$1" -n "$NS" -o jsonpath='{.status.podIP}' 2>/dev/null)"
	[ -n "$ip" ] || return 1
	echo "$ip" >"$EVIDENCE/ois.10-$1.ip"
	on_worker "curl -fsS -m 5 http://$ip:8080/"
}
leg_server_down() {
	local p ips="" ip body bad="" pull_rc=0
	for p in ois-app-worker-always ois-app-worker-ifnp; do
		ip="$(kc get pod "$p" -n "$NS" -o jsonpath='{.status.podIP}')"
		body="$(worker_http "$p" 2>&1 || true)"
		case "$body" in *ois-app*) ips="$ips $ip" ;; *)
			DETAIL="control: $p at '${ip:-none}' did not answer before the server went down ('$body')"
			return 1
			;;
		esac
	done
	on_worker "sudo -n k3sm image pull '$APP_CONTROL'" >"$EVIDENCE/ois.10-pull-control.txt" 2>&1 || {
		DETAIL="control: a worker pull of $APP_CONTROL failed with the server up"
		return 1
	}
	SERVER_DOWN=1
	on_server 'sudo -n launchctl bootout system/io.k3sm.server' >"$EVIDENCE/ois.10-bootout.txt" 2>&1 || {
		DETAIL="could not boot out io.k3sm.server"
		return 1
	}
	local deadline=$((SECONDS + 60))
	while kc get --raw /healthz >/dev/null 2>&1; do
		[ "$SECONDS" -lt "$deadline" ] || {
			DETAIL="the apiserver still answers 60s after the bootout"
			return 1
		}
		sleep 3
	done
	sleep 30
	for ip in $ips; do
		body="$(on_worker "curl -fsS -m 5 http://$ip:8080/" 2>&1 || true)"
		printf '%s %s\n' "$ip" "$body" >>"$EVIDENCE/ois.10-down-http.txt"
		case "$body" in *ois-app*) ;; *) bad="$bad $ip(no answer)" ;; esac
	done
	bounded 180 on_worker "sudo -n k3sm image pull '$APP_UNCACHED'" >"$EVIDENCE/ois.10-pull-uncached.txt" 2>&1 || pull_rc=$?
	[ "$pull_rc" != 0 ] || bad="$bad pull-of-$APP_UNCACHED-succeeded"
	server_up || {
		DETAIL="the server did not serve again within 300s of the bootstrap"
		return 1
	}
	local n bound=""
	deadline=$((SECONDS + 300))
	for n in "$SERVER" "$WORKER"; do
		until [ "$(kc get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ]; do
			if [ "$SECONDS" -ge "$deadline" ]; then
				bad="$bad $n-not-Ready-after-restore"
				break
			fi
			sleep 5
		done
	done
	[ "$pull_rc" = 124 ] && bound=" (bounded at 180s)"
	DETAIL="cached worker pods answered:$ips; uncached pull exit $pull_rc$bound; server restored"
	[ -z "$bad" ] || {
		DETAIL="$DETAIL; failed:$bad"
		return 1
	}
}
run_leg ois.10
leg_server_down || leg_red
leg_pass

log "----------------------------------------"
log "one-image-store: ${#LEGS[@]} legs passed (evidence $EVIDENCE)"
log "================ ONE IMAGE STORE GREEN ================"
emit_run_log_verdict PASS >>"$RUNLOG"
exit 0
