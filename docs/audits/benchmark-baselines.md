# Benchmark baselines

Established 2026-09-08 (A2 pass) on `main` at `69cd04a`. Before this the tree
carried **zero benchmarks**, so no allocation claim about it could be falsified.

Apple M2 Pro, `go1.27.0 darwin/arm64`, `-benchmem`. **Read `allocs/op`** — it is
deterministic across runs and is what these guard. `ns/op` varies ~10% on this
hardware and is indicative only. `MB/s` on the tar benchmarks is context bytes
processed, not I/O.

Reproduce:

    go test ./pkg/netserve/ -run '^$' -bench 'Respond|FindOPT|Normalize' -benchmem
    go test ./pkg/oci/      -run '^$' -bench 'WriteTar' -benchmem -benchtime=5x

## pkg/netserve — per DNS query

`r.respond` is the per-query core: every lookup from every Pod on the node lands
there. The shapes differ by an order of magnitude and an average over them would
describe no real workload, so each is named for the query it models.

```
BenchmarkRespondClusterA-10                    	 1799763	       655.1 ns/op	     888 B/op	       7 allocs/op
BenchmarkRespondClusterA_EDNS-10               	 1747184	       686.5 ns/op	     888 B/op	       7 allocs/op
BenchmarkRespondNXDOMAIN-10                    	 1965007	       769.0 ns/op	     864 B/op	       6 allocs/op
BenchmarkRespondOffCluster-10                  	 2013307	       559.4 ns/op	     800 B/op	       5 allocs/op
BenchmarkRespondSearchListMiss-10              	 2004250	       581.1 ns/op	     832 B/op	       6 allocs/op
BenchmarkRespondHeadlessA-10                   	  323326	      3840 ns/op	    4210 B/op	      60 allocs/op
BenchmarkRespondReversePTR-10                  	  217880	      6268 ns/op	    4843 B/op	      65 allocs/op
BenchmarkFindOPT-10                            	21993310	        55.52 ns/op	       0 B/op	       0 allocs/op
BenchmarkNormalizeDNSName-10                   	56115189	        21.52 ns/op	       0 B/op	       0 allocs/op
BenchmarkRespondReversePTRByServiceCount/services=1-10         	  572864	      2038 ns/op	    2481 B/op	      32 allocs/op
BenchmarkRespondReversePTRByServiceCount/services=10-10        	   70081	     16665 ns/op	   18212 B/op	     243 allocs/op
BenchmarkRespondReversePTRByServiceCount/services=50-10        	    7796	    152723 ns/op	  124109 B/op	    1165 allocs/op
BenchmarkRespondReversePTRByServiceCount/services=200-10       	     661	   1751340 ns/op	 1007012 B/op	    4620 allocs/op
```

`FindOPT` and `NormalizeDNSName` are recorded at **0 allocs** deliberately: both
were hypothesised to allocate and both were refuted by measurement. They are
baselines against regression, not targets.

`RespondReversePTRByServiceCount` is the one that falsifies a documented premise
— `LookupPTR`'s "the Service set is dev-scale". It scales linearly in allocation
and superlinearly in time:

| Services | ns/op | B/op | allocs/op |
|---|---|---|---|
| 1 | 2,236 | 2,481 | 32 |
| 10 | 17,151 | 18,212 | 243 |
| 50 | 152,196 | 124,106 | 1,165 |
| 200 | 1,772,807 | 1,007,011 | 4,620 |

At 200 Services one PTR query costs **1.77 ms and ~1 MB**.

## pkg/oci — per tar entry

`writeTar` runs once per COPY/ADD and once per file within it. `MaxContextBytes`
caps a context at 2 GiB but nothing caps the entry count, so per-entry cost is
the unit that matters. The small-file row is load-bearing: `io.Copy` sizes its
scratch buffer to `min(32KiB, remaining)` for a `*io.LimitedReader`, so below
32 KiB the buffer equals the file and buffer garbage tracks total bytes.

Post-fix (#363), with the pre-fix figures for contrast:

| Benchmark | B/op before | B/op after | allocs before | allocs after |
|---|---|---|---|---|
| WriteTarSmallFiles (3000 × 6 KiB, depth 6) | 21,484,544 | 2,244,851 | 57,057 | 33,055 |
| WriteTarLargeFiles (500 × 256 KiB, depth 6) | 16,916,313 | 421,024 | 9,542 | 5,543 |
| WriteTarDeepTree (3000 × 64 B, depth 10) | 4,204,697 | 2,377,449 | 69,074 | 33,075 |

The emitted tar bytes are unchanged across that fix, which is load-bearing —
this package's determinism contract makes the layer digest observable, and
`TestBuildFromScratchDigestUnchanged` gates it on a golden sha256.
