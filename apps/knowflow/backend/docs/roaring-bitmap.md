# Roaring bitmap storage contract

## Scope and layout

`counter.bitmap.storage` / `COUNTER_BITMAP_STORAGE` accepts `native` (default,
compatible with existing deployments) or `roaring`. The opt-in Compose overlay
sets `roaring`. API responses and Kafka/local counter events are unchanged.

Both strategies retain entity-centric 32,768-position shards:
- Native: `bm:{metric}:{entityType}:{entityId}:{userId / 32768}`.
- Roaring: `rbm:{metric}:{entityType}:{entityId}:{userId / 32768}`.
- Offset: `userId % 32768`; full signed-positive Java long IDs remain lossless.
- Metrics: `like` and `fav` use separate keys. Negative user IDs are rejected.

`BitmapStore.set(metric,type,id,userId,enabled)` returns true only for a real
transition. The Lua script reads and writes a single key atomically. The service
publishes +1/-1 events only for true. A module error is propagated, never treated
as a missing user state. Redis mutation and Kafka publication are still separate
operations; this change does not solve that existing consistency gap.

`contains` reads the selected strategy only; there is no stale fallback to old
native keys. `count` scans only the selected namespace, deduplicates SCAN results
and sums shard cardinalities. Count rebuild is not a snapshot under concurrent
writes, as in the existing implementation. It does not sum native and roaring.

## Startup and migration

Startup requires Redis connectivity. Roaring also requires the module commands
and `counter:bitmap:storage-mode=roaring`. A migration marker blocks native startup
so an accidental configuration rollback cannot silently expose old data.
Existing running processes are NOT fenced by the marker: all writers MUST stop.

1. Back up Redis and verify restore procedures. Stop every backend instance and
   any external bitmap writers. Drain in-flight writes/events before migration.
2. Build/start the module-enabled Redis. The Compose overlay is
   `deploy/docker-compose.roaring.yml`; do not start backend yet. Existing Redis
   version upgrades must be checked independently against deployment policy.
3. Run `python3 backend/scripts/migrate-bitmaps.py --host HOST --port PORT --db DB`
   for a read-only preflight. It requires access to the same DB as Spring Redis.
   Authentication uses REDIS_USERNAME/REDIS_PASSWORD environment variables.
4. Run again with `--apply --writers-stopped`. Even empty installations need this
   initialization. The tool preserves old keys, converts bits in MSB-first order,
   verifies every target member and cardinality, rechecks sources, and only then
   writes the ready marker. Failed migrations retain `migrating` and fail closed.
5. Start every backend with `COUNTER_BITMAP_STORAGE=roaring`. Confirm like/fav,
   cancellation, duplicate requests and count reconstruction before resuming traffic.

Migration requires persistent (no TTL), <=4096-byte native shards. Unexpected
names, conflicting targets, unknown markers and unrelated `rbm:*` keys fail
closed. Restart after interruption verifies already-written targets; it never
silently overwrites conflicting data. It holds native snapshots in client RAM;
large installations need a separately planned batched maintenance migration.
The tool targets a standalone Redis endpoint, not Redis Cluster/TLS deployments.

Do not flip to native after accepting Roaring writes: old keys are stale. A reverse
migration or restoring a consistent backup with appropriate write recovery is
required. Source keys are deliberately retained; removing them after acceptance
is an explicit operator action, not part of this script.

## Validation matrix

| Case | Expected |
|---|---|
| First like/fav | true, one +1 event |
| Duplicate like/fav | false, no event |
| First cancellation | true, one -1 event |
| Duplicate cancellation | false, no event |
| ID 32767 / 32768 | distinct shard boundaries |
| ID >2^53 and Long.MAX_VALUE | exact chunk/offset mapping |
| Like vs fav / different entities | isolated |
| Missing module or migration marker | startup fails |
| Conflicting target / active marker | migration fails closed |
| Existing native data | exact members after offline conversion |

Run real Redis integration tests with Java 21:

```bash
ROARING_MODULE_PATH=/absolute/path/libredis-roaring.so \
  mvn -f backend/pom.xml -Dtest=BitmapStoreIntegrationTest test
```

Without ROARING_MODULE_PATH the integration class is explicitly skipped. It
starts its own loopback Redis and never connects to application data. Module
build and synthetic memory benchmark instructions/results live in
`experiments/bitmap-comparison/`. The Linux Docker build must be verified on a
Docker-enabled host; local macOS module execution is a separate validation.

## Compose activation example

The maintenance service runs inside the Compose network; Redis need not publish a
host port. From `deploy/`, after stopping every external writer as well:

```bash
docker compose -f docker-compose.yml -f docker-compose.roaring.yml stop backend
docker compose -f docker-compose.yml -f docker-compose.roaring.yml build redis
docker compose -f docker-compose.yml -f docker-compose.roaring.yml up -d redis
docker compose -f docker-compose.yml -f docker-compose.roaring.yml run --rm bitmap-migrate
docker compose -f docker-compose.yml -f docker-compose.roaring.yml run --rm bitmap-migrate --apply --writers-stopped
docker compose -f docker-compose.yml -f docker-compose.roaring.yml up -d --build backend
```

## Local validation (2026-09-28)

- Full existing backend suite plus real-module integration: passed; added final
  targeted assertions also passed (4 Redis integration cases, 2 service/startup tests).
- Six migration tests passed: dry run, exact conversion, RDB restart, AOF rewrite
  and restart, resumability, conflict protection, TTL/oversize rejection and empty DB.
- Java 21, Redis 8.6.2 on macOS arm64, pinned module compiled locally.
- Docker is unavailable on this machine: image/Compose deployment has not been run.
- Existing application Redis data has not been migrated or altered.
