package com.tongji.counter.storage;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.*;
import java.util.stream.IntStream;
import static org.junit.jupiter.api.Assertions.*;

@EnabledIfEnvironmentVariable(named = "ROARING_MODULE_PATH", matches = ".+")
class BitmapStoreIntegrationTest {
    static Process process;
    static LettuceConnectionFactory factory;
    static StringRedisTemplate redis;
    static Path directory;

    @BeforeAll static void start() throws Exception {
        directory = Files.createTempDirectory("knowflow-bitmap-test-");
        int port;
        try (ServerSocket socket = new ServerSocket(0)) { port = socket.getLocalPort(); }
        process = new ProcessBuilder("redis-server", "--bind", "127.0.0.1", "--port", "" + port,
                "--save", "", "--appendonly", "no", "--dir", directory.toString(),
                "--loadmodule", System.getenv("ROARING_MODULE_PATH"))
                .redirectErrorStream(true).redirectOutput(directory.resolve("redis.log").toFile()).start();
        factory = new LettuceConnectionFactory("127.0.0.1", port);
        factory.afterPropertiesSet(); factory.start();
        redis = new StringRedisTemplate(factory);
        boolean ready = false;
        for (int i = 0; i < 100; i++) {
            try (var connection = factory.getConnection()) {
                if ("PONG".equals(connection.ping())) { ready = true; break; }
            } catch (Exception ignored) { Thread.sleep(50); }
        }
        assertTrue(ready, () -> "Redis did not start: " + directory);
    }
    @AfterAll static void stop() throws Exception {
        if (factory != null) factory.destroy();
        if (process != null) { process.destroy(); process.waitFor(10, TimeUnit.SECONDS); }
    }
    @BeforeEach void clean() {
        try (var connection = factory.getConnection()) { connection.serverCommands().flushDb(); }
    }
    BitmapStore store(String mode) {
        if (mode.equals("roaring")) redis.opsForValue().set(BitmapStore.MODE_KEY, "roaring");
        BitmapStore store = new BitmapStore(redis, mode); store.afterPropertiesSet(); return store;
    }
    @Test void bothFormatsPreserveMembershipAndCounts() {
        for (String mode : new String[]{"native", "roaring"}) {
            clean(); var s = store(mode);
            long[] ids = {0, 32767, 32768, 65535, (1L << 55) + 1, Long.MAX_VALUE};
            for (long id : ids) {
                assertFalse(s.contains("like", "knowpost", "123", id));
                assertFalse(s.set("like", "knowpost", "123", id, false));
                assertTrue(s.set("like", "knowpost", "123", id, true));
                assertFalse(s.set("like", "knowpost", "123", id, true));
                assertTrue(s.contains("like", "knowpost", "123", id));
                assertFalse(s.contains("fav", "knowpost", "123", id));
                assertTrue(s.set("fav", "knowpost", "123", id, true));
            }
            assertEquals(ids.length, s.count("like", "knowpost", "123"));
            assertEquals(ids.length, s.count("fav", "knowpost", "123"));
            assertEquals(0, s.count("like", "knowpost", "999"));
            for (long id : ids) {
                assertTrue(s.set("like", "knowpost", "123", id, false));
                assertFalse(s.set("like", "knowpost", "123", id, false));
            }
            assertEquals(0, s.count("like", "knowpost", "123"));
            assertEquals(ids.length, s.count("fav", "knowpost", "123"));
            assertThrows(IllegalArgumentException.class, () -> s.set("like", "knowpost", "123", -1, true));
        }
    }
    @Test void countSpansMultipleScanAndPipelineBatches() {
        var s = store("roaring");
        for (int i = 0; i < 600; i++) s.set("like", "knowpost", "batch", i * 32768L, true);
        assertEquals(600, s.count("like", "knowpost", "batch"));
    }
    @Test void concurrentDuplicatesOnlyChangeOnce() throws Exception {
        var s = store("roaring");
        try (var pool = Executors.newFixedThreadPool(8)) {
            var jobs = IntStream.range(0, 64).<Callable<Boolean>>mapToObj(i ->
                    () -> s.set("fav", "knowpost", "123", 40000, true)).toList();
            long changes = 0;
            for (var result : pool.invokeAll(jobs)) if (result.get()) changes++;
            assertEquals(1, changes);
            assertEquals(1, s.count("fav", "knowpost", "123"));
        }
    }
    @Test void modeSwitchRequiresMigrationAndRejectsStaleNativeReads() {
        assertThrows(IllegalStateException.class, () -> new BitmapStore(redis, "roaring").afterPropertiesSet());
        redis.opsForValue().set(BitmapStore.MODE_KEY, "migrating");
        assertThrows(IllegalStateException.class, () -> new BitmapStore(redis, "native").afterPropertiesSet());
        assertThrows(IllegalStateException.class, () -> new BitmapStore(redis, "roaring").afterPropertiesSet());
        redis.opsForValue().set(BitmapStore.MODE_KEY, "roaring");
        assertDoesNotThrow(() -> new BitmapStore(redis, "roaring").afterPropertiesSet());
        assertThrows(IllegalStateException.class, () -> new BitmapStore(redis, "native").afterPropertiesSet());
        assertThrows(IllegalArgumentException.class, () -> new BitmapStore(redis, "typo"));
    }
}
