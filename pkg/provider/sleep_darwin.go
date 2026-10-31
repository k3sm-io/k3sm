//go:build darwin && cgo

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

package provider

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>

// k3sm_pm_hold takes a kIOPMAssertionTypePreventSystemSleep assertion
// (IOPMLib.h, IOPMAssertionCreateWithName). The assertion keeps the system
// from idle sleep while on AC power; the OS ignores it on battery and it never
// blocks a user-forced or clamshell sleep. It is tied to this process: the
// kernel releases it if the process exits. Returns an IOReturn.
static int k3sm_pm_hold(const char *name, uint32_t *out) {
	CFStringRef n = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);
	if (n == NULL) return kIOReturnNoMemory;
	IOPMAssertionID id = kIOPMNullAssertionID;
	IOReturn r = IOPMAssertionCreateWithName(kIOPMAssertionTypePreventSystemSleep, kIOPMAssertionLevelOn, n, &id);
	CFRelease(n);
	if (r == kIOReturnSuccess) *out = (uint32_t)id;
	return (int)r;
}

static int k3sm_pm_release(uint32_t id) { return (int)IOPMAssertionRelease((IOPMAssertionID)id); }

// k3sm_ps_source names the power source the Mac draws from, through
// IOPSCopyPowerSourcesInfo and IOPSGetProvidingPowerSourceType
// (IOPowerSources.h): 1 AC, 2 battery, 3 UPS, 0 unknown.
static int k3sm_ps_source(void) {
	CFTypeRef snap = IOPSCopyPowerSourcesInfo();
	if (snap == NULL) return 0;
	int r = 0;
	CFStringRef t = IOPSGetProvidingPowerSourceType(snap);
	if (t != NULL) {
		if (CFStringCompare(t, CFSTR(kIOPMACPowerKey), 0) == kCFCompareEqualTo) r = 1;
		else if (CFStringCompare(t, CFSTR(kIOPMBatteryPowerKey), 0) == kCFCompareEqualTo) r = 2;
		else if (CFStringCompare(t, CFSTR(kIOPMUPSPowerKey), 0) == kCFCompareEqualTo) r = 3;
	}
	CFRelease(snap);
	return r;
}

// k3sm_pw_full_wake reports whether a capability set is a full (user) wake:
// a dark wake (Power Nap, a maintenance wake) runs with the CPU but without
// kIOPMSystemCapabilityGraphics (IOPM.h).
static int k3sm_pw_full_wake(uint32_t caps) {
	return (caps & kIOPMSystemCapabilityCPU) && (caps & kIOPMSystemCapabilityGraphics);
}

// k3sm_pw_cap_change_full_wake reports whether a kIOMessageSystemCapabilityChange
// (IOPMSystemCapabilityChangeParameters, IOPM.h) is the completed gain of a
// full wake.
static int k3sm_pw_cap_change_full_wake(uint32_t flags, uint32_t from, uint32_t to) {
	return (flags & kIOPMSystemCapabilityDidChange) && !k3sm_pw_full_wake(from) && k3sm_pw_full_wake(to);
}

static int64_t k3sm_now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// k3sm_pw_drain discards every byte already in the non-blocking fd: an ack
// that arrived after its notice timed out must not answer the next one.
static void k3sm_pw_drain(int fd) {
	uint8_t b;
	while (read(fd, &b, 1) == 1) {}
}

// k3sm_pw_wait_ack waits up to ms for the byte seq on the non-blocking fd,
// ignoring any other byte. It returns 1 on the match, 0 on the timeout and
// -1 when the writer closed the pipe (the watcher is stopping).
static int k3sm_pw_wait_ack(int fd, uint8_t seq, int ms) {
	int64_t deadline = k3sm_now_ms() + ms;
	for (;;) {
		int64_t left = deadline - k3sm_now_ms();
		if (left <= 0) return 0;
		struct pollfd p = { .fd = fd, .events = POLLIN };
		int pr = poll(&p, 1, (int)left);
		if (pr < 0 && errno == EINTR) continue;
		if (pr <= 0) return 0;
		uint8_t b;
		ssize_t n = read(fd, &b, 1);
		if (n == 0) return -1;
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR) continue;
			return -1;
		}
		if (b == seq) return 1;
	}
}

// The sleep watcher: IORegisterForSystemPower (IOPMLib.h) on a dedicated
// thread running its own CFRunLoop. The callback never calls into Go; it
// writes one two-byte record per notice to evfd: {'S', seq} before sleep and
// {'W', 0} on a full wake. For will-sleep it waits on ackfd for seq (bounded
// by ack_ms) before IOAllowPowerChange, which the system requires for every
// kIOMessageCanSystemSleep and kIOMessageSystemWillSleep (it otherwise waits
// 30 s). Closing ackfd's write end ends the wait at once.
//
// Dark wakes. kIOMessageSystemHasPoweredOn also arrives for a dark wake
// (Power Nap, a maintenance wake), so it is not taken as a wake on its own:
// the watcher reads the root domain's "System Capabilities" registry property
// (kIOPMSystemCapabilitiesKey in xnu's IOPMPrivate.h; not in the public SDK)
// and reports a wake only when Graphics is present. In a dark wake it polls
// that property every 5 s, and takes a kIOMessageSystemCapabilityChange that
// gains Graphics too, so the promotion of a dark wake to a full one is seen.
// An unreadable property counts as a full wake. 'W' is written once per
// sleep (asleep gates it).
//
// Stopping is sticky. stopsrc is a version-0 CFRunLoopSource whose perform
// stops the loop; once signalled it stays pending until the loop runs it, so
// a stop can never be lost to the window before CFRunLoopRun. ready is set
// from readysrc's perform, inside the running loop, so k3sm_pw_start returns
// only once the loop is running.
typedef struct {
	int evfd, ackfd, ack_ms;
	io_connect_t root;
	io_service_t rootdomain;
	IONotificationPortRef port;
	io_object_t notifier;
	CFRunLoopRef rl;
	CFRunLoopSourceRef stopsrc, readysrc;
	CFRunLoopTimerRef darkpoll;
	pthread_t thread;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int ready, err;
	int asleep;
	uint8_t seq;
} k3sm_pw;

// k3sm_pw_caps reads the root domain's current capabilities, or returns
// UINT32_MAX when they cannot be read.
static uint32_t k3sm_pw_caps(k3sm_pw *w) {
	if (w->rootdomain == IO_OBJECT_NULL) return UINT32_MAX;
	CFTypeRef v = IORegistryEntryCreateCFProperty(w->rootdomain, CFSTR("System Capabilities"), kCFAllocatorDefault, 0);
	if (v == NULL) return UINT32_MAX;
	uint32_t caps = UINT32_MAX;
	if (CFGetTypeID(v) == CFNumberGetTypeID()) {
		int64_t n = 0;
		if (CFNumberGetValue((CFNumberRef)v, kCFNumberSInt64Type, &n)) caps = (uint32_t)n;
	}
	CFRelease(v);
	return caps;
}

static void k3sm_pw_emit(k3sm_pw *w, char kind, uint8_t seq) {
	uint8_t rec[2] = { (uint8_t)kind, seq };
	(void)write(w->evfd, rec, 2);
}

static void k3sm_pw_dark_disarm(k3sm_pw *w) {
	CFRunLoopTimerSetNextFireDate(w->darkpoll, CFAbsoluteTimeGetCurrent() + 1e9);
}

// k3sm_pw_woke reports a full wake once per sleep.
static void k3sm_pw_woke(k3sm_pw *w) {
	if (!w->asleep) return;
	w->asleep = 0;
	k3sm_pw_dark_disarm(w);
	k3sm_pw_emit(w, 'W', 0);
}

static void k3sm_pw_dark_tick(CFRunLoopTimerRef t, void *info) {
	k3sm_pw *w = (k3sm_pw *)info;
	if (!w->asleep) { k3sm_pw_dark_disarm(w); return; }
	uint32_t caps = k3sm_pw_caps(w);
	if (caps == UINT32_MAX || k3sm_pw_full_wake(caps)) k3sm_pw_woke(w);
}

static void k3sm_pw_cb(void *refcon, io_service_t svc, natural_t type, void *arg) {
	k3sm_pw *w = (k3sm_pw *)refcon;
	switch (type) {
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(w->root, (long)arg);
		break;
	case kIOMessageSystemWillSleep: {
		w->asleep = 1;
		k3sm_pw_dark_disarm(w);
		if (++w->seq == 0) w->seq = 1;
		k3sm_pw_drain(w->ackfd);
		k3sm_pw_emit(w, 'S', w->seq);
		(void)k3sm_pw_wait_ack(w->ackfd, w->seq, w->ack_ms);
		IOAllowPowerChange(w->root, (long)arg);
		break;
	}
	case kIOMessageSystemHasPoweredOn: {
		uint32_t caps = k3sm_pw_caps(w);
		if (caps == UINT32_MAX || k3sm_pw_full_wake(caps)) {
			k3sm_pw_woke(w);
		} else if (w->asleep) {
			CFRunLoopTimerSetNextFireDate(w->darkpoll, CFAbsoluteTimeGetCurrent() + 5.0);
		}
		break;
	}
	case kIOMessageSystemCapabilityChange: {
		const struct IOPMSystemCapabilityChangeParameters *p = arg;
		if (p != NULL && k3sm_pw_cap_change_full_wake(p->changeFlags, p->fromCapabilities, p->toCapabilities)) {
			k3sm_pw_woke(w);
		}
		break;
	}
	default:
		break;
	}
}

static void k3sm_pw_stop_perform(void *info) { CFRunLoopStop(CFRunLoopGetCurrent()); }

static void k3sm_pw_ready_perform(void *info) {
	k3sm_pw *w = (k3sm_pw *)info;
	pthread_mutex_lock(&w->mu);
	w->ready = 1;
	pthread_cond_signal(&w->cv);
	pthread_mutex_unlock(&w->mu);
}

static void k3sm_pw_fail(k3sm_pw *w) {
	pthread_mutex_lock(&w->mu);
	w->err = 1;
	w->ready = 1;
	pthread_cond_signal(&w->cv);
	pthread_mutex_unlock(&w->mu);
}

static void *k3sm_pw_main(void *p) {
	k3sm_pw *w = (k3sm_pw *)p;
	w->root = IORegisterForSystemPower(w, &w->port, k3sm_pw_cb, &w->notifier);
	if (w->root == MACH_PORT_NULL) {
		if (w->port != NULL) IONotificationPortDestroy(w->port);
		k3sm_pw_fail(w);
		return NULL;
	}
	w->rootdomain = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPMrootDomain"));
	w->rl = CFRunLoopGetCurrent();
	CFRetain(w->rl);
	CFRunLoopSourceContext sc = { .version = 0, .info = w, .perform = k3sm_pw_stop_perform };
	w->stopsrc = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &sc);
	CFRunLoopSourceContext rc = { .version = 0, .info = w, .perform = k3sm_pw_ready_perform };
	w->readysrc = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &rc);
	CFRunLoopTimerContext tc = { .version = 0, .info = w };
	w->darkpoll = CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + 1e9, 5.0, 0, 0, k3sm_pw_dark_tick, &tc);
	CFRunLoopAddSource(w->rl, IONotificationPortGetRunLoopSource(w->port), kCFRunLoopDefaultMode);
	CFRunLoopAddSource(w->rl, w->stopsrc, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(w->rl, w->readysrc, kCFRunLoopDefaultMode);
	CFRunLoopAddTimer(w->rl, w->darkpoll, kCFRunLoopDefaultMode);
	CFRunLoopSourceSignal(w->readysrc);
	CFRunLoopRun();
	CFRunLoopTimerInvalidate(w->darkpoll);
	CFRelease(w->darkpoll);
	CFRunLoopSourceInvalidate(w->stopsrc);
	CFRunLoopSourceInvalidate(w->readysrc);
	CFRunLoopRemoveSource(w->rl, IONotificationPortGetRunLoopSource(w->port), kCFRunLoopDefaultMode);
	IODeregisterForSystemPower(&w->notifier);
	IOServiceClose(w->root);
	IONotificationPortDestroy(w->port);
	if (w->rootdomain != IO_OBJECT_NULL) IOObjectRelease(w->rootdomain);
	return NULL;
}

// k3sm_pw_start returns a watcher whose run loop is running, or NULL when
// registration failed.
static k3sm_pw *k3sm_pw_start(int evfd, int ackfd, int ack_ms) {
	k3sm_pw *w = calloc(1, sizeof(*w));
	if (w == NULL) return NULL;
	w->evfd = evfd; w->ackfd = ackfd; w->ack_ms = ack_ms;
	int fl = fcntl(ackfd, F_GETFL);
	if (fl >= 0) fcntl(ackfd, F_SETFL, fl | O_NONBLOCK);
	pthread_mutex_init(&w->mu, NULL);
	pthread_cond_init(&w->cv, NULL);
	if (pthread_create(&w->thread, NULL, k3sm_pw_main, w) != 0) {
		pthread_mutex_destroy(&w->mu);
		pthread_cond_destroy(&w->cv);
		free(w);
		return NULL;
	}
	pthread_mutex_lock(&w->mu);
	while (!w->ready) pthread_cond_wait(&w->cv, &w->mu);
	int err = w->err;
	pthread_mutex_unlock(&w->mu);
	if (err) {
		pthread_join(w->thread, NULL);
		pthread_mutex_destroy(&w->mu);
		pthread_cond_destroy(&w->cv);
		free(w);
		return NULL;
	}
	return w;
}

// k3sm_pw_stop signals the sticky stop source, joins the thread and frees the
// watcher.
static void k3sm_pw_stop(k3sm_pw *w) {
	CFRunLoopSourceSignal(w->stopsrc);
	CFRunLoopWakeUp(w->rl);
	pthread_join(w->thread, NULL);
	CFRelease(w->stopsrc);
	CFRelease(w->readysrc);
	CFRelease(w->rl);
	pthread_mutex_destroy(&w->mu);
	pthread_cond_destroy(&w->cv);
	free(w);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"
)

// sleepAckTimeoutMillis bounds how long the watcher holds a will-sleep notice
// for the reporter's acknowledgement. It covers the reporter's publish bound
// and flush grace with margin, and stays under the system's 30 s limit.
const sleepAckTimeoutMillis = 10000

// iokitPowerHost is the darwin PowerHost over IOKit's IOPMLib.
type iokitPowerHost struct{}

func newPowerHost() PowerHost { return iokitPowerHost{} }

// PreventSleep implements PowerHost with IOPMAssertionCreateWithName.
func (iokitPowerHost) PreventSleep(name string) (func() error, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var id C.uint32_t
	if r := C.k3sm_pm_hold(cname, &id); r != 0 {
		return nil, fmt.Errorf("IOPMAssertionCreateWithName(PreventSystemSleep): IOReturn %#x", uint32(r))
	}
	var once sync.Once
	var err error
	return func() error {
		once.Do(func() {
			if r := C.k3sm_pm_release(id); r != 0 {
				err = fmt.Errorf("IOPMAssertionRelease: IOReturn %#x", uint32(r))
			}
		})
		return err
	}, nil
}

// PowerSource implements PowerHost with IOPSGetProvidingPowerSourceType.
func (iokitPowerHost) PowerSource() PowerSource {
	switch C.k3sm_ps_source() {
	case 1:
		return PowerSourceAC
	case 2:
		return PowerSourceBattery
	case 3:
		return PowerSourceUPS
	}
	return PowerSourceUnknown
}

// WatchSleep implements PowerHost with IORegisterForSystemPower.
//
// File descriptors: Fd() puts evW and ackR into blocking mode, and that is
// intended: the C callback writes evW from its own thread and must not see
// EAGAIN, and k3sm_pw_start sets ackR non-blocking itself for its drain. The
// stop order below is load-bearing: ackW closes first, which ends a callback
// waiting for an ack; the watcher thread is then stopped and joined, so no
// callback can write evW after it closes; evW closes last, which ends the
// reader with EOF. Closing evW or ackR while the thread runs would hand the
// callback a closed, possibly reused, descriptor.
func (iokitPowerHost) WatchSleep(ctx context.Context) (<-chan PowerNotice, error) {
	evR, evW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("sleep watcher pipe: %w", err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		_ = evR.Close()
		_ = evW.Close()
		return nil, fmt.Errorf("sleep watcher pipe: %w", err)
	}
	w := C.k3sm_pw_start(C.int(evW.Fd()), C.int(ackR.Fd()), C.int(sleepAckTimeoutMillis))
	if w == nil {
		for _, f := range []*os.File{evR, evW, ackR, ackW} {
			_ = f.Close()
		}
		return nil, errors.New("IORegisterForSystemPower failed")
	}
	out := make(chan PowerNotice)
	go func() {
		<-ctx.Done()
		_ = ackW.Close()
		C.k3sm_pw_stop(w)
		_ = evW.Close()
		_ = ackR.Close()
	}()
	go func() {
		defer close(out)
		defer evR.Close()
		rec := make([]byte, 2)
		for {
			if _, err := io.ReadFull(evR, rec); err != nil {
				return
			}
			n := PowerNotice{Kind: PowerDidWake}
			if rec[0] == 'S' {
				seq := rec[1]
				var once sync.Once
				n = PowerNotice{Kind: PowerWillSleep, Ack: func() {
					once.Do(func() { _, _ = ackW.Write([]byte{seq}) })
				}}
			}
			select {
			case out <- n:
			case <-ctx.Done():
				if n.Ack != nil {
					n.Ack()
				}
			}
		}
	}()
	return out, nil
}

// waitAck runs the watcher's ack wait over fd, for the tests.
//
//lint:ignore U1000 test hook: cgo cannot appear in a _test.go file
func waitAck(fd uintptr, seq byte, ms int) int {
	return int(C.k3sm_pw_wait_ack(C.int(fd), C.uint8_t(seq), C.int(ms)))
}

// drainAck runs the watcher's stale-ack drain over fd, for the tests.
//
//lint:ignore U1000 test hook: cgo cannot appear in a _test.go file
func drainAck(fd uintptr) { C.k3sm_pw_drain(C.int(fd)) }

// isFullWake and capChangeIsFullWake run the watcher's wake classification,
// for the tests.
//
//lint:ignore U1000 test hook: cgo cannot appear in a _test.go file
func isFullWake(caps uint32) bool { return C.k3sm_pw_full_wake(C.uint32_t(caps)) != 0 }

//lint:ignore U1000 test hook: cgo cannot appear in a _test.go file
func capChangeIsFullWake(flags, from, to uint32) bool {
	return C.k3sm_pw_cap_change_full_wake(C.uint32_t(flags), C.uint32_t(from), C.uint32_t(to)) != 0
}
