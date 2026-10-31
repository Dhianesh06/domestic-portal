package com.mobiversa.merchant.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe sliding-window Rate Limiter:
 * - Rate limit by username AND IP (max 3 requests per 300,000 ms window)
 * - 60-second resend cooldown per identifier
 * - In-memory implementation with concurrent data structures (cluster-friendly interface)
 */
@Slf4j
@Service
public class RateLimitService {

    @Value("${otp.rate-limit.max-requests:3}")
    private int maxRequests;

    @Value("${otp.rate-limit.window-ms:300000}")
    private long windowMs; // 5 minutes

    @Value("${otp.rate-limit.cooldown-ms:60000}")
    private long cooldownMs; // 60 seconds

    // Key -> queue of request timestamps
    private final ConcurrentHashMap<String, Deque<Long>> requestHistory = new ConcurrentHashMap<>();
    // Key -> last request timestamp
    private final ConcurrentHashMap<String, Long> lastRequestTime = new ConcurrentHashMap<>();

    /**
     * Checks whether an OTP request is permitted for the given IP and username.
     * Both IP and Username must satisfy:
     * 1. Minimum 60-second cooldown since last send
     * 2. Max 3 requests in the 300,000 ms window
     *
     * @return null if permitted, or error message if rejected
     */
    public synchronized RateLimitResult checkRateLimit(String ip, String username) {
        long now = Instant.now().toEpochMilli();
        String normalizedUsername = username != null ? username.trim().toLowerCase() : "anonymous";
        String ipKey = "IP:" + ip;
        String userKey = "USER:" + normalizedUsername;

        // Check 1: 60s cooldown
        Long lastIpTime = lastRequestTime.get(ipKey);
        if (lastIpTime != null && (now - lastIpTime) < cooldownMs) {
            long waitSec = (cooldownMs - (now - lastIpTime)) / 1000 + 1;
            return new RateLimitResult(false, "Please wait " + waitSec + " seconds before requesting another OTP.");
        }

        Long lastUserTime = lastRequestTime.get(userKey);
        if (lastUserTime != null && (now - lastUserTime) < cooldownMs) {
            long waitSec = (cooldownMs - (now - lastUserTime)) / 1000 + 1;
            return new RateLimitResult(false, "Please wait " + waitSec + " seconds before requesting another OTP.");
        }

        // Check 2: Max requests in window
        if (!isWithinSlidingWindow(ipKey, now) || !isWithinSlidingWindow(userKey, now)) {
            return new RateLimitResult(false, "Too many OTP requests. Please try again after 5 minutes.");
        }

        return new RateLimitResult(true, null);
    }

    /**
     * Records a successful OTP request dispatch for both IP and username.
     */
    public synchronized void recordOtpSent(String ip, String username) {
        long now = Instant.now().toEpochMilli();
        String normalizedUsername = username != null ? username.trim().toLowerCase() : "anonymous";
        String ipKey = "IP:" + ip;
        String userKey = "USER:" + normalizedUsername;

        lastRequestTime.put(ipKey, now);
        lastRequestTime.put(userKey, now);

        recordWindowRequest(ipKey, now);
        recordWindowRequest(userKey, now);
    }

    private boolean isWithinSlidingWindow(String key, long now) {
        Deque<Long> queue = requestHistory.computeIfAbsent(key, k -> new ArrayDeque<>());
        // Remove timestamps outside window
        while (!queue.isEmpty() && (now - queue.peekFirst()) > windowMs) {
            queue.pollFirst();
        }
        return queue.size() < maxRequests;
    }

    private void recordWindowRequest(String key, long now) {
        Deque<Long> queue = requestHistory.computeIfAbsent(key, k -> new ArrayDeque<>());
        queue.addLast(now);
    }

    public record RateLimitResult(boolean allowed, String message) {}
}

