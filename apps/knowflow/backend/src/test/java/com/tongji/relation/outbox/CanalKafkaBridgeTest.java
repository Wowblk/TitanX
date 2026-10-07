package com.tongji.relation.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskExecutor;

import static org.assertj.core.api.Assertions.assertThat;

class CanalKafkaBridgeTest {

    @Test
    void disabledBridgeDoesNotStartWorker() {
        TaskExecutor failOnExecute = command -> {
            throw new AssertionError("Disabled Canal bridge must not start a worker");
        };

        CanalKafkaBridge bridge = new CanalKafkaBridge(
                null,
                new ObjectMapper(),
                failOnExecute,
                false,
                "127.0.0.1",
                11111,
                "example",
                "",
                "",
                ".*\\..*",
                100,
                1000
        );

        bridge.start();

        assertThat(bridge.isAutoStartup()).isFalse();
        assertThat(bridge.isRunning()).isFalse();
    }
}
