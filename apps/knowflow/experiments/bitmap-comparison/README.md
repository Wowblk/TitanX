# Bitmap storage experiment

This isolated prototype compares KnowFlow's current 32,768-bit-per-key layout
with the redis-roaring module. It does not change production counter wiring.
Base: KnowFlow commit `103f84d`.

## Contract

Keep the entity-centric layout, like/fav namespace separation, and atomic
state-transition behavior: add/remove returns 1 only when membership changes.
The standalone Lua uses numeric desired state rather than Java's add/remove
strings, but preserves the GETBIT/check/SETBIT operations. No Kafka, database,
HTTP, or Spring timings are included. Both metrics use the same storage path;
the benchmark measures one representative entity/metric.

Variants:
- native-sharded: original Redis GETBIT/SETBIT, userId / 32768 and userId % 32768.
- roaring-sharded: same keys/offsets, R.GETBIT/R.SETBIT.
- roaring-single: one 32-bit Roaring key per entity (32-bit scenarios only).
- roaring64-single: one 64-bit Roaring key per entity.

Cases: 60,000 consecutive IDs; 10,000 random IDs below 1 billion; 100 clusters
of 100 consecutive IDs; 10,000 sparse IDs above 2^55. Seed is fixed.

## Run

Requires Python 3, redis-server and a compatible compiled redis-roaring module.
Module source: https://github.com/aviggiano/redis-roaring
Pinned module commit: 360327e0ae79cf87a4fc8e912e28590efd8c2f4c

```bash
git clone https://github.com/aviggiano/redis-roaring.git /tmp/knowflow-redis-roaring
git -C /tmp/knowflow-redis-roaring checkout 360327e0ae79cf87a4fc8e912e28590efd8c2f4c
git -C /tmp/knowflow-redis-roaring submodule update --init --recursive
(cd /tmp/knowflow-redis-roaring/src && ../deps/CRoaring/amalgamation.sh)
cmake -S /tmp/knowflow-redis-roaring -B /tmp/knowflow-redis-roaring/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build /tmp/knowflow-redis-roaring/build --target redis-roaring unit -j 4
python3 experiments/bitmap-comparison/bench.py --module /tmp/knowflow-redis-roaring/build/libredis-roaring.dylib --output experiments/bitmap-comparison/results.json
```

Linux builds use `.so` instead of `.dylib`. All Redis processes are temporary,
use private Unix sockets and port 0, and disable RDB/AOF. The harness cannot
connect to an existing Redis instance. Each case/variant uses a fresh process.

## Verification and interpretation

Every inserted ID is read back; sampled absent IDs must return 0; BITCOUNT must
match the input cardinality. Timed toggles check remove/remove/add/add ->
1/0/1/0 and final cardinality. Each timing has three rounds after warmup.
Latency includes Python serialization and local socket round trips, single
client, no pipelining. Loading uses 256-command pipelines. Do not interpret
these numbers as production throughput, server-only timings or concurrency tests.

Memory includes summed MEMORY USAGE and process used_memory delta after subtracting mem_clients_normal. Both snapshots wait 0.5 seconds for serverCron accounting to settle. The module reports serialized size in its MEMORY USAGE callback, rather than
actual allocation size; use process used_memory delta as the primary comparison
when Redis allocator hooks are enabled. Server memory delta can include bookkeeping noise. Compare both.
No R.OPTIMIZE is called: this measures the online SETBIT update path.

Production integration would additionally require migration from existing keys,
atomic event-delivery design, module persistence/replication and restart testing,
concurrent load tests, and real user-ID distributions. Consolidating keys changes
cluster distribution and hot-key behavior, which this single-process test cannot
measure. Preserve user IDs as decimal strings in Lua: tonumber on IDs above 2^53
can lose precision. This harness only converts the 0/1 desired state.

Generate the report after a complete run:

```bash
python3 experiments/bitmap-comparison/report.py
```
