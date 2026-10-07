package com.tongji.counter.storage;

import com.tongji.counter.schema.BitmapShard;
import com.tongji.counter.schema.CounterKeys;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Entity-centric bitmap storage; shard offsets always fit the module's 32-bit API. */
@Component
public class BitmapStore implements InitializingBean {
    public static final String MODE_KEY = "counter:bitmap:storage-mode";
    private final StringRedisTemplate redis;
    private final boolean roaring;
    private final DefaultRedisScript<Long> toggle = new DefaultRedisScript<>();
    private final DefaultRedisScript<Long> read = new DefaultRedisScript<>();

    public BitmapStore(StringRedisTemplate redis,
                       @Value("${counter.bitmap.storage:native}") String storage) {
        if (!List.of("native", "roaring").contains(storage)) {
            throw new IllegalArgumentException("counter.bitmap.storage must be native or roaring");
        }
        this.redis = redis;
        this.roaring = storage.equals("roaring");
        toggle.setLocation(new ClassPathResource("lua/counter-bitmap-toggle.lua"));
        toggle.setResultType(Long.class);
        read.setScriptText("return redis.call(ARGV[1], KEYS[1], ARGV[2])");
        read.setResultType(Long.class);
    }

    @Override
    public void afterPropertiesSet() {
        // Native mode remains compatible with the existing deployment. Roaring must
        // be explicitly prepared by the offline migration tool, even for an empty DB.
        String mode = redis.opsForValue().get(MODE_KEY);
        if (roaring) {
            if (!"roaring".equals(mode)) {
                throw new IllegalStateException("Run migrate-bitmaps.py with all writers stopped before enabling roaring");
            }
            DefaultRedisScript<Long> probe = new DefaultRedisScript<>(
                    "local c=redis.call('COMMAND','INFO','R.GETBIT','R.SETBIT','R.BITCOUNT'); "
                    + "for i=1,3 do if not c[i] then return 0 end end; return 1", Long.class);
            if (!Long.valueOf(1).equals(redis.execute(probe, List.of()))) {
                throw new IllegalStateException("Redis Roaring module is missing required commands");
            }
        } else if (mode != null) {
            throw new IllegalStateException("Bitmap migration marker exists: native mode could read stale state");
        }
    }

    public boolean set(String metric, String type, String id, long userId, boolean enabled) {
        String key = key(metric, type, id, userId);
        Long changed = redis.execute(toggle, List.of(key), command("GETBIT"), command("SETBIT"),
                Long.toString(BitmapShard.bitOf(userId)), enabled ? "1" : "0");
        if (changed == null) throw new IllegalStateException("Bitmap mutation returned no result");
        return changed == 1;
    }

    public boolean contains(String metric, String type, String id, long userId) {
        Long result = redis.execute(read, List.of(key(metric, type, id, userId)), command("GETBIT"),
                Long.toString(BitmapShard.bitOf(userId)));
        if (result == null) throw new IllegalStateException("Bitmap read returned no result");
        return result == 1;
    }

    public long count(String metric, String type, String id) {
        String pattern = CounterKeys.bitmapKey(prefix(), metric, type, id, 0);
        pattern = pattern.substring(0, pattern.lastIndexOf(':') + 1) + "*";
        Set<String> visited = new HashSet<>(); // SCAN may return a key more than once.
        long total = 0;
        List<String> batch = new ArrayList<>(256);
        try (Cursor<String> cursor = redis.scan(ScanOptions.scanOptions().match(pattern).count(256).build())) {
            while (cursor.hasNext()) {
                String key = cursor.next();
                if (visited.add(key)) batch.add(key);
                if (batch.size() == 256) {
                    total = Math.addExact(total, countBatch(batch));
                    batch.clear();
                }
            }
        }
        return Math.addExact(total, countBatch(batch));
    }

    private long countBatch(List<String> keys) {
        if (keys.isEmpty()) return 0;
        List<Object> results = redis.executePipelined((RedisCallback<Object>) connection -> {
            for (String key : keys) {
                if (roaring) {
                    // Explicit INTEGER decoding: Lettuce's generic execute assumes a
                    // byte-array response for unknown module commands.
                    connection.scriptingCommands().eval(
                            "return redis.call('R.BITCOUNT', KEYS[1])".getBytes(StandardCharsets.UTF_8),
                            ReturnType.INTEGER, 1, key.getBytes(StandardCharsets.UTF_8));
                } else {
                    connection.stringCommands().bitCount(key.getBytes(StandardCharsets.UTF_8));
                }
            }
            return null;
        });
        long total = 0;
        for (Object result : results) {
            if (!(result instanceof Number n)) throw new IllegalStateException("Invalid bitmap count result");
            total = Math.addExact(total, n.longValue());
        }
        return total;
    }

    private String key(String metric, String type, String id, long userId) {
        if (userId < 0) throw new IllegalArgumentException("userId must be non-negative");
        return CounterKeys.bitmapKey(prefix(), metric, type, id, BitmapShard.chunkOf(userId));
    }

    private String prefix() { return roaring ? "rbm" : "bm"; }
    private String command(String name) { return roaring ? "R." + name : name; }
}
