package com.mobiversa.merchant.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service managing single-use password reset tokens:
 * - 256 bits of cryptographically secure randomness
 * - 10-minute TTL (configurable)
 * - Bound to merchant ID
 * - Stored server-side ONLY as SHA-256 hash
 * - Single-use: invalidated immediately upon consumption or expiry
 */
@Slf4j
@Service
public class ResetTokenService {

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${password.reset.token-ttl-seconds:600}")
    private long tokenTtlSeconds; // 10 minutes default

    // tokenHash -> ResetTokenData
    private final ConcurrentHashMap<String, ResetTokenData> tokenStore = new ConcurrentHashMap<>();

    /**
     * Issues a new single-use reset token for the merchant.
     *
     * @param merchantId ID of the verified merchant
     * @return plaintext token string to send to client
     */
    public String issueResetToken(Long merchantId) {
        // Invalidate any previous reset tokens for this merchant
        invalidateTokensForMerchant(merchantId);

        byte[] randomBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(randomBytes);
        String plaintextToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String tokenHash = hashToken(plaintextToken);
        Instant expiresAt = Instant.now().plusSeconds(tokenTtlSeconds);

        tokenStore.put(tokenHash, new ResetTokenData(merchantId, expiresAt));
        log.debug("Issued password reset token for merchantId={}, expiresAt={}", merchantId, expiresAt);

        return plaintextToken;
    }

    /**
     * Validates and consumes the reset token.
     *
     * @param plaintextToken token from request
     * @return Merchant ID if valid, or null if invalid/expired
     */
    public Long consumeResetToken(String plaintextToken) {
        if (plaintextToken == null || plaintextToken.isBlank()) {
            return null;
        }

        String tokenHash = hashToken(plaintextToken);
        ResetTokenData data = tokenStore.remove(tokenHash); // Single-use consumption

        if (data == null) {
            log.warn("Attempt to use invalid or already consumed reset token");
            return null;
        }

        if (Instant.now().isAfter(data.expiresAt())) {
            log.warn("Attempt to use expired reset token for merchantId={}", data.merchantId());
            return null;
        }

        return data.merchantId();
    }

    /**
     * Checks if a token is valid without consuming it (useful for rendering the reset page).
     */
    public boolean isTokenValid(String plaintextToken) {
        if (plaintextToken == null || plaintextToken.isBlank()) {
            return false;
        }
        String tokenHash = hashToken(plaintextToken);
        ResetTokenData data = tokenStore.get(tokenHash);
        if (data == null) {
            return false;
        }
        if (Instant.now().isAfter(data.expiresAt())) {
            tokenStore.remove(tokenHash);
            return false;
        }
        return true;
    }

    public void invalidateTokensForMerchant(Long merchantId) {
        tokenStore.entrySet().removeIf(entry -> entry.getValue().merchantId().equals(merchantId));
    }

    private String hashToken(String plaintextToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(plaintextToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }

    private record ResetTokenData(Long merchantId, Instant expiresAt) {}
}

