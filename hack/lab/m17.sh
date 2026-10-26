#!/usr/bin/env bash
#
# k3sm M17 lab gate shim: the former M17-lab gate path. The ladder itself, the
# two-Mac interconnect ladder, lives in one place,
# hack/lab/m17-interconnect.sh (the row's gate); this file only hands over to it, so
# every existing invocation of hack/lab/m17.sh keeps working.
#
# Row in hack/acceptance/phases.json:
#   M17-lab  gate hack/lab/m17-interconnect.sh, tier lab, requires two-macs +
#            thunderbolt-cable, manual: true, skeleton: false
#
# Exit contract (the ladder's): 0 PASS, 1 FAIL, 2 REFUSED, 3 K3SM_LAB unset
# ("LAB-PENDING: not a pass"). Arguments pass through (--plan, --self-test,
# --verify-twice <A> <B>).
#
# K3SM-GATE-SHIM: hack/lab/m17-interconnect.sh
exec "$(cd "$(dirname "$0")" && pwd)/m17-interconnect.sh" "$@"
