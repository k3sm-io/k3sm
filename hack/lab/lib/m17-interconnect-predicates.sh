#!/usr/bin/env bash
# shellcheck disable=SC2034 # a sourced library
#
# The pure predicates of the M17 interconnect lab ladder (hack/lab/m17-interconnect.sh).
#
# Everything here reads its inputs from arguments or files and decides; nothing
# here runs ssh, kubectl, ifconfig or sudo. The ladder collects host state into
# files under EVIDENCE_DIR and hands them to these functions, and the ladder's
# --self-test drives each one against the fixtures in
# hack/lab/testdata/m17-interconnect/ with a green and at least one red input.
#
# It sources the interconnect spike's library for the shared helpers it already
# owns (IC_NETSTAT_AWK, norm_mac, stats, figure); sourcing that library requires
# nothing and touches no host.
#
# Address facts mirrored from apis net/v1alpha1 (interconnectaddr.go), and named
# here so a reader can check them against the source:
#   InterconnectSlotAddress(idx, slot) = 169.254.0.(8*idx + slot + 1)
#   MaxInterconnectNodeIndex = 30, MaxInterconnectSlot = 7
#   slot 0 is the node's address with a /24 netmask; slots 1..7 are /32 aliases.

ICP_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=../../spike/m17-interconnect/lib.sh
. "$ICP_LIB_DIR/../../spike/m17-interconnect/lib.sh"

ICP_MAX_NODE_INDEX=30
ICP_MAX_SLOT=7
# The two netd verbs the node may send (pkg/interconnect/desired.go and the
# provider): the closed verb set of k3sm_interconnect_netd_verb_results_total.
ICP_NETD_VERBS="EnsureInterconnectAlias RemoveInterconnectAlias"

# icp_ip_to_int <a.b.c.d> — the address as an unsigned 32-bit integer.
icp_ip_to_int() {
	local IFS=. a b c d
	read -r a b c d <<<"$1"
	case "$a$b$c$d" in '' | *[!0-9]*) return 1 ;; esac
	[ -n "$d" ] || return 1
	echo $(((a << 24) | (b << 16) | (c << 8) | d))
}

# icp_node_index <cluster CIDR> <node pod CIDR> — the node's cluster index (the
# darwin-net podnet.NodeIndex rule): the node /24's offset inside the cluster
# aggregate. Fails on a node CIDR that is not a /24 inside the aggregate.
icp_node_index() {
	local cbase cbits nbase nbits c n
	cbase="${1%/*}" cbits="${1#*/}" nbase="${2%/*}" nbits="${2#*/}"
	[ "$nbits" = 24 ] || return 1
	case "$cbits" in '' | *[!0-9]*) return 1 ;; esac
	[ "$cbits" -le 24 ] || return 1
	c="$(icp_ip_to_int "$cbase")" || return 1
	n="$(icp_ip_to_int "$nbase")" || return 1
	c=$((c & ~((1 << (32 - cbits)) - 1) & 0xffffffff))
	[ $((n & ~((1 << (32 - cbits)) - 1) & 0xffffffff)) = "$c" ] || return 1
	echo $(((n - c) >> 8))
}

# icp_slot_addr <idx> <slot> — InterconnectSlotAddress; fails outside the ranges.
icp_slot_addr() {
	case "$1$2" in '' | *[!0-9]*) return 1 ;; esac
	[ "$1" -le "$ICP_MAX_NODE_INDEX" ] && [ "$2" -le "$ICP_MAX_SLOT" ] || return 1
	echo "169.254.0.$((8 * $1 + $2 + 1))"
}

# icp_slot_of <idx> <address> — the slot the address is for node idx, or fail.
icp_slot_of() {
	local s
	for s in 0 1 2 3 4 5 6 7; do
		[ "$(icp_slot_addr "$1" "$s")" = "$2" ] && {
			echo "$s"
			return 0
		}
	done
	return 1
}

# icp_bridge_inets <ifconfig bridge0 file> — "<addr> <netmask>" per inet line.
icp_bridge_inets() { awk '$1=="inet"{m=""; for(i=1;i<NF;i++) if($i=="netmask") m=$(i+1); print $2, m}' "$1"; }

# icp_in_halves <addr> — inside 169.254.0.0/24 or 169.254.255.0/24.
icp_in_halves() { case "$1" in 169.254.0.* | 169.254.255.*) return 0 ;; esac; return 1; }

# icp_alias_policy <ifconfig bridge0 file> <idx> — every inet bridge0 carries in
# the reserved halves must be InterconnectSlotAddress(idx, s) for s in 0..7, slot
# 0 with netmask 0xffffff00 and every other slot 0xffffffff, and nothing may sit
# in 169.254.255.0/24. The self-assigned 169.254/16 address (third octet 1..254)
# is the host's own and is ignored. Prints one line per address; non-zero when
# any line is a VIOLATION.
icp_alias_policy() {
	local f="$1" idx="$2" a m s bad=0
	while read -r a m; do
		icp_in_halves "$a" || continue
		case "$a" in 169.254.255.*)
			echo "VIOLATION $a is in 169.254.255.0/24, which no interconnect address uses"
			bad=1
			continue
			;;
		esac
		if ! s="$(icp_slot_of "$idx" "$a")"; then
			echo "VIOLATION $a is not InterconnectSlotAddress($idx, 0..7)"
			bad=1
			continue
		fi
		if [ "$s" = 0 ] && [ "$m" != 0xffffff00 ]; then
			echo "VIOLATION $a is slot 0 with netmask $m, want 0xffffff00 (the one connected /24)"
			bad=1
		elif [ "$s" != 0 ] && [ "$m" != 0xffffffff ]; then
			echo "VIOLATION $a is slot $s with netmask $m, want 0xffffffff (a /32 pod alias)"
			bad=1
		else
			echo "OK $a slot $s netmask $m"
		fi
	done < <(icp_bridge_inets "$f")
	return "$bad"
}

# icp_halves_empty <ifconfig bridge0 file> — no inet in either reserved half.
icp_halves_empty() {
	local a m left=""
	while read -r a m; do
		icp_in_halves "$a" && left="$left $a"
	done < <(icp_bridge_inets "$1")
	[ -z "$left" ] || {
		echo "reserved-half inet left on bridge0:$left"
		return 1
	}
}

# icp_bridge_members <ifconfig bridge0 file> — the member list, sorted, one line.
icp_bridge_members() { awk '$1=="member:"{print $2}' "$1" | sort | tr '\n' ' ' | sed 's/ $//'; }

# icp_netstat_link_bytes <netstat -I <if> -b file> — "<ibytes> <obytes>" from the
# interface's <Link#n> row (the per-interface counters; address rows repeat them).
icp_netstat_link_bytes() {
	awk 'NR==1{for(i=1;i<=NF;i++){if($i=="Ibytes")ib=i; if($i=="Obytes")ob=i}; next}
	     $3 ~ /^<Link#/ {
	       # a Link row with no MAC address has one field fewer than the header
	       off = ($4 ~ /^[0-9a-f][0-9a-f]?:/) ? 0 : -1
	       print $(ib+off), $(ob+off); exit }' "$1"
}

# icp_counter_delta <before> <after> — after-before; fails on a non-number or a
# counter that went backwards (an interface reset invalidates the reading).
icp_counter_delta() {
	case "$1$2" in '' | *[!0-9]*) return 1 ;; esac
	[ "$2" -ge "$1" ] || return 1
	echo $(($2 - $1))
}

# icp_total_delta <before file> <after file> — (ibytes+obytes) delta between two
# netstat -I -b readings.
icp_total_delta() {
	local bi bo ai ao
	read -r bi bo < <(icp_netstat_link_bytes "$1")
	read -r ai ao < <(icp_netstat_link_bytes "$2")
	icp_counter_delta $((${bi:-0} + ${bo:-0})) $((${ai:-0} + ${ao:-0}))
}

# icp_cable_path_verdict <payload> <thunderbolt delta> <LAN delta> <slack> — the
# r3 counter half: the Thunderbolt member carried at least the payload and the
# default-route LAN interface stayed within the slack.
icp_cable_path_verdict() {
	local p="$1" tb="$2" lan="$3" slack="$4"
	if [ "$tb" -lt "$p" ]; then
		echo "FAIL the Thunderbolt member moved $tb bytes, less than the $p-byte payload"
		return 1
	fi
	if [ "$lan" -gt "$slack" ]; then
		echo "FAIL the LAN interface moved $lan bytes, beyond the $slack-byte slack (the payload left by the LAN)"
		return 1
	fi
	echo "PASS Thunderbolt member +$tb bytes >= payload $p; LAN +$lan bytes <= slack $slack"
}

# icp_mesh_path_verdict <payload> <utun delta> <LAN delta> <thunderbolt delta> <slack>
# — the r4 counter half: the mesh flow rode the tunnel and the LAN, never the cable.
icp_mesh_path_verdict() {
	local p="$1" ut="$2" lan="$3" tb="$4" slack="$5"
	if [ "$ut" -lt "$p" ] || [ "$lan" -lt "$p" ]; then
		echo "FAIL the mesh flow did not ride the tunnel and the LAN: utun +$ut, LAN +$lan bytes, payload $p"
		return 1
	fi
	if [ "$tb" -gt "$slack" ]; then
		echo "FAIL the Thunderbolt member moved $tb bytes during a mesh flow, beyond the $slack-byte slack"
		return 1
	fi
	echo "PASS utun +$ut and LAN +$lan bytes >= payload $p; Thunderbolt member +$tb bytes <= slack $slack"
}

# icp_ring_path_verdict <HTTP bytes> <thunderbolt delta> <utun delta> <slack> — the
# r5 counter half: the collective traffic rode the cable (more than the HTTP
# exchange) while the mesh carried only about the HTTP exchange.
icp_ring_path_verdict() {
	local h="$1" tb="$2" ut="$3" slack="$4"
	if [ "$tb" -le "$h" ]; then
		echo "FAIL the Thunderbolt member moved $tb bytes, not more than the $h-byte HTTP exchange (the ring did not use the cable)"
		return 1
	fi
	if [ "$ut" -gt $((h + slack)) ]; then
		echo "FAIL the mesh moved $ut bytes, more than the HTTP exchange $h plus the $slack-byte slack (the ring used the mesh)"
		return 1
	fi
	echo "PASS Thunderbolt member +$tb bytes > HTTP $h; mesh +$ut bytes <= HTTP + slack"
}

# icp_route_iface <route -n get output file> — the interface the route names.
icp_route_iface() { awk '$1=="interface:"{print $2; exit}' "$1"; }

# icp_arp_verdict <arp -n line> <local MACs> <peer MACs> — the ARP entry for a
# peer address must be one of the peer's MACs, never a local one, never permanent.
icp_arp_verdict() {
	local line="$1" mine=" $2 " theirs=" $3 " mac nm
	mac="$(printf '%s\n' "$line" | awk '{print $4; exit}')"
	nm="$(norm_mac "$mac")"
	if grep -q permanent <<<"$line"; then
		echo "FAIL a permanent ARP entry ($mac): the self-ARP trap"
		return 1
	fi
	case "$mac" in "" | "(incomplete)" | no | entry)
		echo "FAIL no resolved ARP entry ($line)"
		return 1
		;;
	esac
	if [[ "$mine" == *" $nm "* ]]; then
		echo "FAIL resolves to this Mac's own MAC $nm"
		return 1
	fi
	if [[ "$theirs" == *" $nm "* ]]; then
		echo "PASS resolves to the peer's MAC $nm"
		return 0
	fi
	echo "FAIL resolves to $nm, which is neither Mac's bridge0 or member MAC"
	return 1
}

# icp_reserved_routes <netstat -rn -f inet file> — the spike reader's normalized
# "<addr>/<mask> <flags> <netif> <gateway>" lines for the reserved halves.
icp_reserved_routes() { awk "$IC_NETSTAT_AWK" "$1"; }

# icp_route_residue <baseline netstat> <now netstat> <allowed dests> <own addrs> —
# every reserved-half route entry in now that is not in the baseline. ARP entries
# (flags with L) are skipped; a dest listed in allowed (for example the connected
# 169.254.0.0/24 while armed) is OK; a /32 for one of this Mac's own addresses
# that is a cloned, non-static entry (C without S) is RECORDED (the macOS 27
# undeletable clone, never passed silently); anything else is FAIL.
icp_route_residue() {
	local base="$1" now="$2" allowed=" $3 " own=" $4 " dest flags netif gw bad=0
	while read -r dest flags netif gw; do
		case "$flags" in *L*) continue ;; esac
		if grep -qxF "$dest $flags $netif $gw" <<<"$(icp_reserved_routes "$base")"; then
			continue
		fi
		if [[ "$allowed" == *" $dest "* ]]; then
			echo "OK $dest $flags $netif (allowed)"
			continue
		fi
		case "$dest:$flags" in */32:*C*)
			if [[ "$own" == *" ${dest%/32} "* ]] && [[ "$flags" != *S* ]]; then
				echo "RECORDED $dest $flags $netif $gw (a cloned entry for this Mac's own removed alias)"
				continue
			fi
			;;
		esac
		echo "FAIL $dest $flags $netif $gw (a reserved-half route beyond the baseline)"
		bad=1
	done < <(icp_reserved_routes "$now")
	return "$bad"
}

# icp_arp_permanent <arp -an file> — permanent ARP entries in the reserved halves.
icp_arp_permanent() {
	local hits
	hits="$(awk '/permanent/{a=$2; gsub(/[()]/,"",a); if (a ~ /^169\.254\.(0|255)\./) print a}' "$1")"
	[ -z "$hits" ] || {
		echo "permanent ARP entries in the reserved halves: $(echo "$hits" | tr '\n' ' ')"
		return 1
	}
}

# icp_i10_verdict <T0> <T1> <T2> — the unplug budget, seconds on one monotonic
# clock: the member is down within 20 s of the carrier drop and the MLX re-render
# starts within 30 s.
icp_i10_verdict() {
	awk -v t0="$1" -v t1="$2" -v t2="$3" 'BEGIN{
	  if (t0=="" || t1=="" || t2=="") { print "FAIL a timestamp is missing (T0=" t0 " T1=" t1 " T2=" t2 ")"; exit 1 }
	  d1=t1-t0; d2=t2-t0
	  if (d1 < 0 || d2 < 0) { printf "FAIL a timestamp precedes the carrier drop (T1-T0=%.1f s, T2-T0=%.1f s)\n", d1, d2; exit 1 }
	  if (d1 > 20) { printf "FAIL member down %.1f s after the carrier drop, budget 20 s\n", d1; exit 1 }
	  if (d2 > 30) { printf "FAIL MLX re-render %.1f s after the carrier drop, budget 30 s\n", d2; exit 1 }
	  printf "PASS member down %.1f s (<= 20) and MLX re-render %.1f s (<= 30) after the carrier drop\n", d1, d2 }'
}

# icp_uphold_verdict <carrier back> <member up> — UpHold: a member stays down for
# at least 60 s after its carrier returns.
icp_uphold_verdict() {
	awk -v r0="$1" -v r1="$2" 'BEGIN{
	  if (r0=="" || r1=="") { print "FAIL a replug timestamp is missing"; exit 1 }
	  d=r1-r0
	  if (d < 60) { printf "FAIL the member counted up %.1f s after the carrier returned, UpHold is 60 s\n", d; exit 1 }
	  printf "PASS the member stayed down %.1f s (>= 60) after the carrier returned\n", d }'
}

# icp_ping_max_gap <ping output file> — the longest run of lost replies between
# the first and last reply (consecutive icmp_seq gaps). No reply at all is 999999.
icp_ping_max_gap() {
	awk 'match($0, /icmp_seq=[0-9]+/){s=substr($0, RSTART+9, RLENGTH-9)+0
	       if (seen && s-prev-1 > g) g=s-prev-1; prev=s; seen=1}
	     END{ if (!seen) print 999999; else print g+0 }' "$1"
}

# icp_metric_sum <exposition file> <metric> [label fragment] — the sum of every
# sample of the metric whose label set contains the fragment (0 when none).
icp_metric_sum() {
	awk -v m="$2" -v l="${3:-}" '$1 ~ "^"m"([{]|$)" && index($1, l) {s += $NF} END{print s+0}' "$1"
}

# icp_netd_verbs_closed <exposition file> — every verb label on
# k3sm_interconnect_netd_verb_results_total is one of the two node verbs: no other
# verb, and so no address-carrying request, ever reached the helper.
icp_netd_verbs_closed() {
	local v bad=""
	while read -r v; do
		[ -n "$v" ] || continue
		[[ " $ICP_NETD_VERBS " == *" $v "* ]] || bad="$bad $v"
	done < <(awk '$1 ~ /^k3sm_interconnect_netd_verb_results_total[{]/ && match($1, /verb="[^"]*"/){print substr($1, RSTART+6, RLENGTH-7)}' "$1" | sort -u)
	[ -z "$bad" ] || {
		echo "unexpected netd verbs:$bad"
		return 1
	}
}

# icp_helper_verdict <netd Hello reply file> — the client's decision over the
# helper's reply (darwin-net wire Version.SupportsInterconnect): minor2 when the
# reply carries major 1 minor >= 2; HelperTooOld when it decodes with major 1
# and a lower minor (an old helper answers Hello "unknown verb" with its version);
# error otherwise. Always prints the verdict; non-zero unless minor2.
icp_helper_verdict() {
	local major minor
	major="$(grep -o '"major":[0-9]*' "$1" 2>/dev/null | sed -n 1p | cut -d: -f2)"
	minor="$(grep -o '"minor":[0-9]*' "$1" 2>/dev/null | sed -n 1p | cut -d: -f2)"
	if [ "$major" = 1 ] && [ -n "$minor" ]; then
		if [ "$minor" -ge 2 ]; then
			echo minor2
			return 0
		fi
		echo HelperTooOld
		return 1
	fi
	echo error
	return 1
}

# icp_netd_hello_frame — the exact bytes, as hex, of a minor-2 Hello request to
# the netd helper. The framing is darwin-net pkg/netd/wire/protocol.go's
# Frame/ReadFrame: a 4-byte big-endian length, then the JSON Request
# ({"version":{"major":1,"minor":2},"verb":"Hello"}; minor 2 is the wire
# package's MinorInterconnect). The ladder builds the frame here, on purpose
# independently of the k3sm client: the probe asks the helper what it speaks
# without trusting the code under test to frame the question, and the self-test
# pins these bytes against a fixture.
icp_netd_hello_frame() {
	local j='{"version":{"major":1,"minor":2},"verb":"Hello"}'
	printf '%08x' "${#j}"
	printf '%s' "$j" | od -An -tx1 | tr -d ' \n'
	echo
}

# icp_ledger_empty <netd interconnect ledger file> — absent, empty, or no aliases.
icp_ledger_empty() {
	[ -s "$1" ] || return 0
	python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1]))
a=d.get("aliases") or []
print("ledger holds %d alias(es)" % len(a)) if a else None
sys.exit(1 if a else 0)' "$1"
}

# icp_doctor_row_state <doctor --json file> <row name> — that row's state,
# "absent" when the report has no such row, or "unreadable" when the file is not
# a doctor report.
icp_doctor_row_state() {
	python3 -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    print("unreadable"); sys.exit(0)
for r in d.get("rows") or []:
    if r.get("name")==sys.argv[2]:
        print(r.get("state","")); sys.exit(0)
print("absent")' "$1" "$2"
}

# icp_ratio <a> <b> — a/b to two places ("-" when b is zero or missing).
icp_ratio() { awk -v a="$1" -v b="$2" 'BEGIN{ if (b+0==0) print "-"; else printf "%.2f\n", a/b }'; }

# icp_validate_rungs <rung table file> <required ids> <prerequisite set> — the
# --plan contract over a table of "id|summary|prereqs|assert fn|evidence|BI"
# lines: no duplicate id, every required id present, every prerequisite token in
# the closed set, and every rung's assertion named assert_<id> (dashes as
# underscores) and defined. Prints one line per
# problem; non-zero when there is any.
icp_validate_rungs() {
	local table="$1" required=" $2 " set=" $3 " id summary prereqs fn ev bi p seen=" " bad=0 r
	while IFS='|' read -r id summary prereqs fn ev bi; do
		id="$(echo "$id" | tr -d ' ')"
		[ -n "$id" ] || continue
		case "$id" in \#*) continue ;; esac
		fn="$(echo "$fn" | tr -d ' ')"
		if [[ "$seen" == *" $id "* ]]; then
			echo "duplicate rung id $id"
			bad=1
		fi
		seen="$seen$id "
		if [ "$fn" != "assert_${id//-/_}" ]; then
			echo "rung $id: assertion is '$fn', want assert_${id//-/_}"
			bad=1
		elif ! declare -F "$fn" >/dev/null; then
			echo "rung $id: assertion $fn is not defined"
			bad=1
		fi
		for p in ${prereqs//,/ }; do
			[[ "$set" == *" $p "* ]] || {
				echo "rung $id: unknown prerequisite '$p'"
				bad=1
			}
		done
	done <"$table"
	for r in $required; do
		[[ "$seen" == *" $r "* ]] || {
			echo "required rung $r is missing"
			bad=1
		}
	done
	return "$bad"
}

# icp_header_field <run log> <field> — the first value of "field: value".
icp_header_field() { awk -v f="$2: " 'index($0, f)==1{print substr($0, length(f)+1); exit}' "$1"; }

# icp_verify_twice <run dir A> <run dir B> <required ids> — the "green twice"
# check over two evidence directories, each holding run.log (the header and the
# transcript) and rungs.tsv ("<id>\t<verdict>"). Green only when every required
# rung is exactly PASS in both, both logs say gate m17-lab and end result PASS,
# artifact_sha256 is known and identical, every git_sha.<repo> is identical,
# and started_utc differs (which also rejects a copied log: identical bytes carry
# the same started_utc).
icp_verify_twice() {
	local a="$1" b="$2" required="$3" d r v f va vb bad=0
	for d in "$a" "$b"; do
		for f in run.log rungs.tsv; do
			[ -f "$d/$f" ] || {
				echo "FAIL $d/$f is missing"
				return 1
			}
		done
	done
	for d in "$a" "$b"; do
		[ "$(icp_header_field "$d/run.log" gate)" = m17-lab ] || {
			echo "FAIL $d/run.log does not carry gate: m17-lab"
			bad=1
		}
		[ "$(awk '/^result: /{r=$2} END{print r}' "$d/run.log")" = PASS ] || {
			echo "FAIL $d/run.log does not end with result: PASS"
			bad=1
		}
		for r in $required; do
			v="$(awk -F'\t' -v id="$r" '$1==id{print $2}' "$d/rungs.tsv")"
			[ "$v" = PASS ] || {
				echo "FAIL $d: rung $r is '${v:-absent}', not PASS"
				bad=1
			}
		done
	done
	va="$(icp_header_field "$a/run.log" artifact_sha256)"
	vb="$(icp_header_field "$b/run.log" artifact_sha256)"
	if [ -z "$va" ] || [ "$va" = unknown ] || [ "$va" != "$vb" ]; then
		echo "FAIL artifact_sha256 differs or is unknown ('$va' vs '$vb')"
		bad=1
	fi
	for r in apis runtimed darwin-net k3sm; do
		va="$(icp_header_field "$a/run.log" "git_sha.$r")"
		vb="$(icp_header_field "$b/run.log" "git_sha.$r")"
		if [ -z "$va" ] || [ "$va" != "$vb" ]; then
			echo "FAIL git_sha.$r differs or is missing ('$va' vs '$vb')"
			bad=1
		fi
	done
	va="$(icp_header_field "$a/run.log" started_utc)"
	vb="$(icp_header_field "$b/run.log" started_utc)"
	if [ -z "$va" ] || [ "$va" = "$vb" ]; then
		echo "FAIL started_utc is the same in both ('$va'): one run, not two"
		bad=1
	fi
	[ "$bad" = 0 ] && echo "PASS two distinct runs of the same artifact, every rung PASS in both"
	return "$bad"
}
