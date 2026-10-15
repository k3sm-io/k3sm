#!/usr/bin/env bash
# shellcheck disable=SC2034 # a sourced library
#
# The one renderer of the tolerations a lab harness pod carries.
#
# Every lab pod tolerates the VK node taint k3sm.io/provider. A lab node can also
# carry taints another workload's controller put there (a NoExecute taint from an
# estate controller evicts a pod that does not tolerate it, mid-leg). The operator
# names those keys in K3SM_LAB_TOLERATE_KEYS (space-separated), and each becomes an
# Exists toleration of every effect on every lab pod. Unset or all-spaces adds none.
#
# Functions (bash 3.2, set -u safe; sourced, never executed):
#   lab_tolerations_yaml [provider-effect]   one line: the body of a YAML flow
#       sequence, for `tolerations: [<body>]`. provider-effect defaults to
#       NoSchedule; an empty argument renders the provider entry with no effect.
#   lab_tolerations_json [provider-effect]   the same as the body of a JSON array.
#   lab_tolerations_header                   `tolerate_keys: <keys or none>`, for
#       a run-log header.
#
# Each key must be a Kubernetes qualified name: an optional DNS-1123 subdomain
# prefix (at most 253 characters) and a `/`, then a name of at most 63 characters,
# alphanumeric at both ends with `-`, `_` or `.` inside. An invalid key prints a
# usage error to stderr and exits 2 with nothing on stdout; a toleration without a
# key (which would tolerate every taint) is never emitted.

# The character sets are spelled out rather than written as ranges, so the match
# does not depend on the locale's collation order.
LAB_TOL_LOWER_DIGIT='abcdefghijklmnopqrstuvwxyz0123456789'
LAB_TOL_ALNUM='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
LAB_TOL_LABEL_RE="^[$LAB_TOL_LOWER_DIGIT]([-$LAB_TOL_LOWER_DIGIT]*[$LAB_TOL_LOWER_DIGIT])?\$"
LAB_TOL_NAME_RE="^[$LAB_TOL_ALNUM]([-_.$LAB_TOL_ALNUM]*[$LAB_TOL_ALNUM])?\$"

# lab_tol_usage <message> — the usage error for an invalid key; exits 2.
lab_tol_usage() {
	echo "K3SM_LAB_TOLERATE_KEYS: $1" >&2
	echo "usage: K3SM_LAB_TOLERATE_KEYS='<key> [<key>...]', each key a qualified name ([prefix/]name, e.g. example.com/estate-off)" >&2
	exit 2
}

# lab_tol_valid_key <key> — 0 iff the key is a qualified name.
lab_tol_valid_key() {
	local key="$1" prefix name rest label
	case "$key" in
	*/*/*) return 1 ;;
	*/*)
		prefix="${key%%/*}"
		name="${key#*/}"
		;;
	*)
		prefix=""
		name="$key"
		;;
	esac
	case "$key" in */*) [ -n "$prefix" ] || return 1 ;; esac
	[ -n "$name" ] && [ "${#name}" -le 63 ] || return 1
	[[ "$name" =~ $LAB_TOL_NAME_RE ]] || return 1
	if [ -n "$prefix" ]; then
		[ "${#prefix}" -le 253 ] || return 1
		rest="$prefix"
		while :; do
			label="${rest%%.*}"
			[ "${#label}" -le 63 ] || return 1
			[[ "$label" =~ $LAB_TOL_LABEL_RE ]] || return 1
			case "$rest" in *.*) rest="${rest#*.}" ;; *) break ;; esac
		done
	fi
	return 0
}

# lab_tol_keys — the validated keys, one space between them (empty for none).
# Globbing is off while the variable is split, so a `*` is a key, not a file list.
lab_tol_keys() {
	local raw="${K3SM_LAB_TOLERATE_KEYS:-}" out="" key restore_glob=0 IFS=$' \t\n'
	case "$-" in *f*) ;; *)
		restore_glob=1
		set -f
		;;
	esac
	for key in $raw; do
		if ! lab_tol_valid_key "$key"; then
			[ "$restore_glob" = 1 ] && set +f
			lab_tol_usage "'$key' is not a qualified name"
		fi
		out="${out:+$out }$key"
	done
	[ "$restore_glob" = 1 ] && set +f
	printf '%s' "$out"
}

lab_tolerations_yaml() {
	local effect="NoSchedule" keys key line
	[ "$#" -ge 1 ] && effect="$1"
	keys="$(lab_tol_keys)" || exit 2
	line="{key: k3sm.io/provider, operator: Exists${effect:+, effect: $effect}}"
	for key in $keys; do line="$line, {key: $key, operator: Exists}"; done
	printf '%s\n' "$line"
}

lab_tolerations_json() {
	local effect="NoSchedule" keys key line
	[ "$#" -ge 1 ] && effect="$1"
	keys="$(lab_tol_keys)" || exit 2
	line="{\"key\": \"k3sm.io/provider\", \"operator\": \"Exists\"${effect:+, \"effect\": \"$effect\"}}"
	for key in $keys; do line="$line, {\"key\": \"$key\", \"operator\": \"Exists\"}"; done
	printf '%s\n' "$line"
}

lab_tolerations_header() {
	local keys
	keys="$(lab_tol_keys)" || exit 2
	printf 'tolerate_keys: %s\n' "${keys:-none}"
}
