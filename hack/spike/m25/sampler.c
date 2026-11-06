// Samples a process's physical footprint, the figure a memory limit is judged
// on: proc_pid_rusage(RUSAGE_INFO_V2).ri_phys_footprint, beside the resident
// size. A file mapping that is not dirty is in the resident size and not in the
// footprint, which is why the two columns differ for a mapped model.
//
// Build: cc -O1 -o sampler sampler.c
// Usage: sampler PID INTERVAL_MS COUNT   (stops early if the process is gone)
// Output: CSV with a header, one row per sample.
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "usage: sampler PID INTERVAL_MS COUNT\n");
		return 2;
	}
	int pid = atoi(argv[1]), ms = atoi(argv[2]), n = atoi(argv[3]);
	struct rusage_info_v2 ri;
	puts("t_ms,footprint_mib,resident_mib");
	long t0 = now_ms();
	for (int i = 0; i < n; i++) {
		if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&ri)) {
			return 0;
		}
		printf("%ld,%.1f,%.1f\n", now_ms() - t0, ri.ri_phys_footprint / 1048576.0,
		       ri.ri_resident_size / 1048576.0);
		fflush(stdout);
		usleep(ms * 1000);
	}
	return 0;
}
