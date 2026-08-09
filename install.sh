#!/bin/sh
# Copyright The k3sm Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# k3sm gen-1 installer:   curl -fsSL https://k3sm.io/install.sh | sh
#
# Canonical copy: github.com/k3sm-io/k3sm/install.sh. The served copy at
# https://k3sm.io/install.sh MUST stay byte-identical — the workspace
# hack/verify-install-sync.sh asserts it (m7-plan Res. 21).
#
# What it does: preflight (Apple silicon + macOS 26+) → fetch the release
# tarball + checksums from GitHub Releases → sha256-verify → print the
# pre-escalation banner → run `sudo k3sm install` (the first-class installer:
# creates /Library/k3sm, the _k3sm user, and the io.k3sm.netd + io.k3sm.server
# LaunchDaemons). Re-running upgrades in place (both daemons restart briefly);
# pin K3SM_INSTALL_VERSION to repair without jumping to latest.
#
# Configuration (env only):
#   K3SM_INSTALL_VERSION        release tag to install (v0.1.0 or 0.1.0); default: latest
#   K3SM_INSTALL_BASE_URL       default https://github.com/k3sm-io/k3sm/releases (https-only)
#   K3SM_INSTALL_DOWNLOAD_ONLY  =1: download + verify into the current dir; never runs sudo
#
# NOTE: external commands (sudo curl sysctl sw_vers uname shasum tar) are
# invoked by BARE NAME deliberately — the B137 acceptance gate substitutes them
# via PATH. Do not absolutize them "for hardening"; it breaks the gate.
#
# The checksum verify is same-origin INTEGRITY (the tarball matches the
# checksums file published beside it), not publisher identity. Provenance
# (Developer-ID + notarization) arrives with the .pkg generation — see
# https://k3sm.io/install/ for the install-channel ladder.

set -eu

info() { printf '[k3sm-install] %s\n' "$*"; }
fatal() {
	printf '[k3sm-install] ERROR: %s\n' "$*" >&2
	exit 1
}

require_darwin_arm64() {
	[ "$(uname -s)" = "Darwin" ] || fatal "k3sm is macOS-only (this host reports $(uname -s))"
	# sysctl is authoritative: under Rosetta `uname -m` lies (reports x86_64 on
	# Apple silicon), and on Intel the hw.optional.arm64 key does not exist at
	# all — so require the literal "1" and fail closed on anything else.
	arm64="$(sysctl -n hw.optional.arm64 2>/dev/null || true)"
	[ "$arm64" = "1" ] || fatal "k3sm requires Apple silicon (arm64)"
	osver="$(sw_vers -productVersion 2>/dev/null || true)"
	osmajor="${osver%%.*}"
	case "$osmajor" in
	'' | *[!0-9]*) fatal "cannot determine the macOS version (sw_vers said: '$osver')" ;;
	esac
	[ "$osmajor" -ge 26 ] || fatal "k3sm requires macOS 26 or newer (found $osver)"
}

check_base_url() {
	case "$BASE_URL" in
	https://*) ;;
	# Loopback http is the B137 mock-server seam; every other http URL is refused.
	http://127.0.0.1:* | http://127.0.0.1/* | 'http://[::1]:'* | 'http://[::1]/'*) ;;
	*) fatal "K3SM_INSTALL_BASE_URL must be https:// (got: $BASE_URL)" ;;
	esac
}

resolve_version() {
	if [ -n "${K3SM_INSTALL_VERSION:-}" ]; then
		TAG="$K3SM_INSTALL_VERSION"
	else
		eff="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$BASE_URL/latest" 2>/dev/null)" ||
			fatal "cannot resolve the latest release from $BASE_URL/latest — has a k3sm release been published yet?"
		case "$eff" in
		*/tag/*) TAG="${eff##*/}" ;;
		*) fatal "no release found at $BASE_URL/latest — has a k3sm release been published yet?" ;;
		esac
	fi
	# Normalize both directions: goreleaser's {{ .Version }} strips the leading
	# "v" (asset names carry 0.1.0), while the tag carries it (v0.1.0).
	case "$TAG" in
	v*) VERSION="${TAG#v}" ;;
	*)
		VERSION="$TAG"
		TAG="v$TAG"
		;;
	esac
	[ -n "$VERSION" ] || fatal "empty release version (K3SM_INSTALL_VERSION='$TAG'?)"
	ARCHIVE="k3sm_${VERSION}_darwin_arm64.tar.gz"
	CHECKSUMS="k3sm_${VERSION}_checksums.txt"
}

download_and_verify() {
	info "downloading $ARCHIVE ($TAG) from $BASE_URL"
	curl -fsSL -o "$STAGE/$ARCHIVE" "$BASE_URL/download/$TAG/$ARCHIVE" ||
		fatal "download failed: $BASE_URL/download/$TAG/$ARCHIVE — has that release been published yet?"
	curl -fsSL -o "$STAGE/$CHECKSUMS" "$BASE_URL/download/$TAG/$CHECKSUMS" ||
		fatal "checksums download failed: $BASE_URL/download/$TAG/$CHECKSUMS — has that release been published yet?"
	# Exact-field match (no regex, no substrings): the shasum -c line whose
	# second field IS the archive name. Hard-fail on a missing entry BEFORE
	# shasum ever runs — never rely on a tool's empty-input verdict.
	CHECKLINE="$(awk -v f="$ARCHIVE" '$2 == f' "$STAGE/$CHECKSUMS")"
	[ -n "$CHECKLINE" ] || fatal "checksums file has no entry for $ARCHIVE — refusing to install"
	(cd "$STAGE" && printf '%s\n' "$CHECKLINE" | shasum -a 256 -c - >/dev/null 2>&1) ||
		fatal "sha256 verification FAILED for $ARCHIVE — refusing to install"
	ARCHIVE_SHA256="${CHECKLINE%% *}"
	info "sha256 verified: $ARCHIVE_SHA256"
}

run_install() {
	tar -xzf "$STAGE/$ARCHIVE" -C "$STAGE" || fatal "cannot extract $ARCHIVE"
	[ -x "$STAGE/k3sm" ] || fatal "archive did not contain an executable k3sm binary"
	# The pre-escalation banner prints BEFORE any sudo invocation, so consent
	# never depends on the password prompt firing (a cached sudo timestamp
	# skips the prompt entirely).
	info "about to run: sudo $STAGE/k3sm install"
	info "  version:  $TAG"
	info "  sha256:   $ARCHIVE_SHA256"
	info "  installs: /Library/k3sm (root-owned), the _k3sm service user,"
	info "            LaunchDaemons io.k3sm.netd (root) + io.k3sm.server (_k3sm),"
	info "            and an admin kubeconfig in your home directory"
	# Under `curl … | sh` stdin is the script stream — never read from it.
	# sudo prompts on /dev/tty; require one unless credentials are cached.
	if ! sudo -n true 2>/dev/null; then
		(exec </dev/tty) 2>/dev/null || fatal "no terminal available for the sudo password prompt.
  Re-run in an interactive terminal, or download-and-verify only:
    curl -fsSL https://k3sm.io/install.sh | K3SM_INSTALL_DOWNLOAD_ONLY=1 sh"
	fi
	# install.go copies os.Executable() into /Library/k3sm, so deleting the
	# staging dir afterwards (the EXIT trap) is safe.
	if ! sudo "$STAGE/k3sm" install; then
		printf '[k3sm-install] ERROR: sudo k3sm install failed.\n' >&2
		printf '[k3sm-install]   A partial install is safe to retire: sudo %s/k3sm uninstall (idempotent).\n' "$STAGE" >&2
		printf '[k3sm-install]   Logs: /var/log/k3sm/ — diagnostics: k3sm doctor\n' >&2
		exit 1
	fi
	info "installed — try: k3sm kubectl get nodes"
}

main() {
	BASE_URL="${K3SM_INSTALL_BASE_URL:-https://github.com/k3sm-io/k3sm/releases}"
	require_darwin_arm64
	check_base_url
	resolve_version
	STAGE="$(mktemp -d "${TMPDIR:-/tmp}/k3sm-install.XXXXXX")"
	trap 'rm -rf "$STAGE"' EXIT INT TERM
	download_and_verify
	if [ "${K3SM_INSTALL_DOWNLOAD_ONLY:-0}" = "1" ]; then
		cp "$STAGE/$ARCHIVE" "$STAGE/$CHECKSUMS" "$PWD/"
		info "verified $ARCHIVE left in $PWD (sha256 $ARCHIVE_SHA256)"
		info "next: tar -xzf $ARCHIVE && sudo ./k3sm install"
		exit 0
	fi
	run_install
}

main "$@"
