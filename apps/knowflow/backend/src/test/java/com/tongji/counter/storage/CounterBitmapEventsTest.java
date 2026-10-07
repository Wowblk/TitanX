package com.tongji.counter.storage;

import com.tongji.counter.event.CounterEventProducer;
import com.tongji.counter.event.CounterEvent;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.ValueOperations;
import com.tongji.counter.service.impl.CounterServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.redisson.api.RedissonClient;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CounterBitmapEventsTest {
    @Test void missingModuleFailsStartup() {
        var redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.get(BitmapStore.MODE_KEY)).thenReturn("roaring");
        // An unavailable command probe must not silently select the native path.
        assertThrows(IllegalStateException.class, () -> new BitmapStore(redis, "roaring").afterPropertiesSet());
    }
    @Test void onlyRealTransitionsPublishEventsForBothMetrics() {
        var storage = mock(BitmapStore.class);
        var producer = mock(CounterEventProducer.class);
        var publisher = mock(ApplicationEventPublisher.class);
        var service = new CounterServiceImpl(mock(StringRedisTemplate.class), producer,
                publisher, mock(RedissonClient.class), storage);
        for (String metric : new String[]{"like", "fav"}) {
            when(storage.set(metric, "knowpost", "123", 40000, true)).thenReturn(true, false);
            when(storage.set(metric, "knowpost", "123", 40000, false)).thenReturn(true, false);
        }
        assertTrue(service.like("knowpost", "123", 40000));
        assertFalse(service.like("knowpost", "123", 40000));
        assertTrue(service.unlike("knowpost", "123", 40000));
        assertFalse(service.unlike("knowpost", "123", 40000));
        assertTrue(service.fav("knowpost", "123", 40000));
        assertFalse(service.fav("knowpost", "123", 40000));
        assertTrue(service.unfav("knowpost", "123", 40000));
        assertFalse(service.unfav("knowpost", "123", 40000));
        var events = ArgumentCaptor.forClass(CounterEvent.class);
        verify(producer, times(4)).publish(events.capture());
        assertEquals(java.util.List.of(1, -1, 1, -1), events.getAllValues().stream().map(CounterEvent::getDelta).toList());
        assertEquals(java.util.List.of("like", "like", "fav", "fav"), events.getAllValues().stream().map(CounterEvent::getMetric).toList());
        verify(publisher, times(4)).publishEvent(any(Object.class));
        when(storage.set("like", "knowpost", "123", 40000, true)).thenThrow(new IllegalStateException("module error"));
        assertThrows(IllegalStateException.class, () -> service.like("knowpost", "123", 40000));
        verifyNoMoreInteractions(producer, publisher);
    }
}
