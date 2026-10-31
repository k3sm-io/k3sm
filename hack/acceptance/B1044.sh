#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# A joined node holds a sleep assertion and reports sleep and wake.
#
# Unit tier (always), in pkg/provider under -race, with a faked power host:
#   TestSleepAssertionHeldWhileJoined  the PreventSystemSleep assertion is taken
#                                      when the node starts, held while it runs,
#                                      released when its context ends (leave and
#                                      stop), and a refused assertion is reported
#   TestSleepAndWakeAreReported        a will-sleep notice raises Sleeping=True,
#                                      records a SystemSleep Event and publishes
#                                      before it is acknowledged; a wake lowers it
#                                      and records a SystemWake Event with the
#                                      wall-clock sleep length
#   TestNodeStatusPublishesSleeping    the published Node carries the Sleeping
#                                      condition, and a publish request is served
#   TestSleepRepeatedWillSleepIsAcknowledgedOnly  the will-sleep ending a dark
#                                      wake publishes nothing new
#   TestSleepConditionReportsPowerSource  the message says whether macOS honours
#                                      the assertion on the current power source
#   TestSleepConditionTransitionTimes  LastTransitionTime moves only on a flip
#   TestSleepLongDarkWakeIsServing     a dark wake past 60 s publishes
#                                      Sleeping=False, reason DarkWake (fake clock)
#   TestSleepShortDarkWakeIsNotPromoted  a shorter one leaves Sleeping=True
#   TestSleepUnclassifiedWakeWarnsOnce an unreadable wake capability warns once
#   TestSleepAckMatchesItsNotice       (darwin) a stale or foreign ack byte never
#                                      answers a will-sleep
#   TestSleepWakePredicateNeedsGraphics  (darwin) the C wake predicates: a
#                                      capability set without Graphics is not a
#                                      full wake
# Host tier (darwin, no privilege), integration build tag:
#   TestIOKitSleepAssertionHeldAndReleased  the real IOKit assertion is listed by
#                                      pmset while held and gone after release,
#                                      and the IOKit sleep watcher stops cleanly
#   TestIOKitSleepWatcherStopsAtOnce   200 start-then-stop rounds, each bounded:
#                                      a stop is never lost and shutdown never hangs
#   TestIOKitPowerSourceIsRead         the power source is read
#   TestIOKitSystemCapabilitiesCanary  the private "System Capabilities" key the
#                                      dark-wake check reads is a CFNumber with
#                                      the CPU bit on this macOS build
# Rig tier (K3SM_LAB=1 on a joined node, NODE=<node name>, kubectl configured):
#   pmset lists the node's assertion, and the Node carries a Sleeping condition.
#   A real sleep and wake is not driven here: it would suspend the machine
#   running the gate. The wake Event is proven at the unit tier.
#
# Usage: hack/acceptance/B1044.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
cd "$K3SM_ROOT"
export CGO_ENABLED=1

run_tests() { # <tags> <regex> <name>...
	local tags="$1" re="$2"; shift 2
	local out
	out="$(go test $tags -race -count=1 -v -run "$re" ./pkg/provider/ 2>&1)" || {
		printf '%s\n' "$out"; echo "B1044: FAIL: go test -run '$re'"; exit 1; }
	printf '%s\n' "$out" | grep -E '^(--- |    --- |ok|PASS)'
	# A test that does not run is not a pass.
	for t in "$@"; do
		printf '%s\n' "$out" | grep -q -- "--- PASS: $t" || { echo "B1044: FAIL: $t did not run"; exit 1; }
	done
}

run_tests "" '^(TestSleep.*|TestNodeStatusPublishesSleeping)$' \
	'TestSleepAssertionHeldWhileJoined' \
	'TestSleepAssertionHeldWhileJoined/held_while_the_node_runs' \
	'TestSleepAssertionHeldWhileJoined/released_when_the_node_stops' \
	'TestSleepAndWakeAreReported' \
	'TestNodeStatusPublishesSleeping' \
	'TestSleepRepeatedWillSleepIsAcknowledgedOnly' \
	'TestSleepConditionReportsPowerSource' \
	'TestSleepConditionTransitionTimes' \
	'TestSleepLongDarkWakeIsServing' \
	'TestSleepShortDarkWakeIsNotPromoted' \
	'TestSleepUnclassifiedWakeWarnsOnce'

if [ "$(uname -s)" = Darwin ]; then
	run_tests "" '^(TestSleepAckMatchesItsNotice|TestSleepWakePredicateNeedsGraphics)$' \
		'TestSleepAckMatchesItsNotice/a_stale_ack_is_drained_before_the_wait' \
		'TestSleepAckMatchesItsNotice/another_notice'"'"'s_byte_is_ignored' \
		'TestSleepWakePredicateNeedsGraphics'
	run_tests "-tags integration" '^TestIOKit' 'TestIOKitSleepAssertionHeldAndReleased' \
		'TestIOKitSleepWatcherStopsAtOnce' 'TestIOKitPowerSourceIsRead' \
		'TestIOKitSystemCapabilitiesCanary'
else
	echo "B1044: FAIL: the IOKit leg needs a Mac"; exit 1
fi

# The node wires the reporter into its status loop and its lifetime.
grep -q 'Sleep: *sleepReporter' cmd/k3sm/node.go && grep -q 'sleepReporter.Run(ctx)' cmd/k3sm/node.go || {
	echo "B1044: FAIL: cmd/k3sm/node.go does not run the sleep reporter"; exit 1; }

if [ "${K3SM_LAB:-}" = 1 ]; then
	: "${NODE:?K3SM_LAB=1 needs NODE=<this node's name>}"
	pmset -g assertions | grep 'PreventSystemSleep' | grep -q 'k3sm node: pods are scheduled on this Mac' || {
		echo "B1044: FAIL: the joined node holds no PreventSystemSleep assertion"; exit 1; }
	st="$(kubectl get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="Sleeping")].status}')"
	[ "$st" = False ] || { echo "B1044: FAIL: node $NODE Sleeping condition is '$st', want False while awake"; exit 1; }
	echo "B1044: rig leg PASS"
fi
echo "B1044: PASS"
