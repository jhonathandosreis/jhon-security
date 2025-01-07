package io.jhonathan.security.prevention;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.jhonathan.security.core.SecurityConfig;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Implementa limitação de taxa de requisições.
 */
public class RateLimiter {
    private final LoadingCache<String, AtomicInteger> requestCounts;
    private final int maxRequestsPerMinute;

    public RateLimiter(SecurityConfig config) {
        this.maxRequestsPerMinute = config.getMaxRequestsPerMinute();

        this.requestCounts = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(key -> new AtomicInteger(0));
    }

    public boolean isRateLimited(String ipAddress) {
        AtomicInteger count = requestCounts.get(ipAddress);
        return count.incrementAndGet() > maxRequestsPerMinute;
    }
}
