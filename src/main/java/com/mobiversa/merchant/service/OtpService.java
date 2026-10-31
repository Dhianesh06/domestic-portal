package com.mobiversa.merchant.service;

import com.mobiversa.merchant.dao.MerchantOtpDao;
import com.mobiversa.merchant.dto.ExternalPaymentOtpRequest;
import com.mobiversa.merchant.dto.MerchantInfoRecord;
import com.mobiversa.merchant.dto.MerchantRecord;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service managing OTP generation, external provider dispatch, HMAC hashing, and verification.
 * Adheres strictly to security requirements:
 * - Plaintext OTP is NEVER stored server-side.
 * - Only HMAC-SHA256 hash is kept in server-side session/cache.
 * - Expiry is stored in MERCHANT_INFO.OTP_EXPIRY_TIME formatted with UTC ISO-8601 string.
 * - Max 5 attempts tracked with lockout.
 * - Constant-time comparison using MessageDigest.isEqual.
 * - OTP data and expiry cleared on verification success.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final MerchantOtpDao merchantOtpDao;
    private final OtpProvider otpProvider;
    private final AuditService auditService;

    @Value("${otp.ttl-seconds:70}")
    private long otpTtlSeconds;

    @Value("${otp.max-attempts:5}")
    private int maxAttempts;

    @Value("${otp.hmac.secret:${OTP_HMAC_SECRET:DefaultSecureHmacSecretKeyForOtpVerificationMustBeLongEnough123!}}")
    private String hmacSecret;

    // merchantId -> ServerOtpState
    private final ConcurrentHashMap<Long, ServerOtpState> otpSessionStore = new ConcurrentHashMap<>();

    /**
     * Initiates the OTP sending flow for the verified active merchant.
     *
     * @param merchant the active merchant record
     * @return true if OTP successfully requested and saved
     */
    @Transactional
    public boolean sendOtpForMerchant(MerchantRecord merchant) {
        String contactName = merchant.getContactPersonName();
        if (contactName == null || contactName.isBlank()) {
            contactName = merchant.getFirstName();
        }

        ExternalPaymentOtpRequest otpRequest = ExternalPaymentOtpRequest.builder()
                .service("WEB_REQ_FORGET_PASSWORD_OTP")
                .username(merchant.getUsername())
                .mobileNo(merchant.getContactPersonPhoneNumber())
                .email(merchant.getEmail())
                .salutation(merchant.getSalutation() != null ? merchant.getSalutation() : "")
                .firstName(contactName)
                .build();

        boolean apiSuccess = otpProvider.sendPaymentOtp(otpRequest);
        if (!apiSuccess) {
            log.warn("Payment OTP API returned failure for merchant username: {}", merchant.getUsername());
            return false;
        }

        // Read the OTP from MOBILE_OPT table by mobileNo
        String mobileNo = merchant.getContactPersonPhoneNumber();
        Optional<String> latestOtpOpt = merchantOtpDao.findLatestOtpByMobile(mobileNo);
        if (latestOtpOpt.isEmpty() || latestOtpOpt.get().isBlank()) {
            log.error("Payment OTP API succeeded but no OTP found in MOBILE_OPT for mobile: {}",
                    AuditService.maskMobile(mobileNo));
            return false;
        }

        String plaintextOtp = latestOtpOpt.get().trim();

        // Calculate HMAC-SHA256 hash
        String otpHmac = computeHmacSha256(plaintextOtp, hmacSecret);

        // Calculate UTC expiry
        Instant nowUtc = Instant.now();
        Instant expiryUtc = nowUtc.plusSeconds(otpTtlSeconds);
        String formattedExpiry = DateTimeFormatter.ISO_INSTANT.format(expiryUtc);

        // Write UTC expiry to MERCHANT_INFO.OTP_EXPIRY_TIME
        merchantOtpDao.saveOrUpdateOtpExpiry(merchant.getId(), formattedExpiry);

        // Keep ONLY the HMAC-SHA256 in server-side state
        otpSessionStore.put(merchant.getId(), new ServerOtpState(otpHmac, expiryUtc, 0));

        log.info("OTP generated and stored for merchantId={}. Expiry: {} UTC (TTL {}s)",
                merchant.getId(), formattedExpiry, otpTtlSeconds);
        return true;
    }

    /**
     * Verifies the OTP provided by the user.
     */
    @Transactional
    public OtpVerifyResult verifyOtp(Long merchantId, String userSubmittedOtp, String clientIp) {
        ServerOtpState state = otpSessionStore.get(merchantId);
        if (state == null) {
            auditService.logOtpVerificationFailed(merchantId, clientIp, 0, "No active OTP session found");
            return new OtpVerifyResult(false, "OTP session expired or not found. Please request a new OTP.", false);
        }

        // Check attempts limit
        if (state.attempts() >= maxAttempts) {
            otpSessionStore.remove(merchantId);
            merchantOtpDao.clearOtpExpiry(merchantId);
            auditService.logOtpMaxAttemptsExceeded(merchantId, clientIp);
            return new OtpVerifyResult(false, "Too many failed attempts. You have been locked out. Please request a new OTP.", true);
        }

        // Check DB and State Expiry
        Instant now = Instant.now();
        if (now.isAfter(state.expiresAt())) {
            otpSessionStore.remove(merchantId);
            merchantOtpDao.clearOtpExpiry(merchantId);
            auditService.logOtpVerificationFailed(merchantId, clientIp, 0, "OTP expired");
            return new OtpVerifyResult(false, "The OTP has expired. Please request a new one.", false);
        }

        // Double check MERCHANT_INFO table expiry
        Optional<MerchantInfoRecord> infoRecord = merchantOtpDao.findMerchantInfoByFk(merchantId);
        if (infoRecord.isEmpty() || infoRecord.get().getOtpExpiryTime() == null) {
            otpSessionStore.remove(merchantId);
            auditService.logOtpVerificationFailed(merchantId, clientIp, 0, "No expiry in database");
            return new OtpVerifyResult(false, "OTP session is invalid. Please request a new OTP.", false);
        }

        try {
            Instant dbExpiry = Instant.parse(infoRecord.get().getOtpExpiryTime());
            if (now.isAfter(dbExpiry)) {
                otpSessionStore.remove(merchantId);
                merchantOtpDao.clearOtpExpiry(merchantId);
                auditService.logOtpVerificationFailed(merchantId, clientIp, 0, "DB OTP expired");
                return new OtpVerifyResult(false, "The OTP has expired. Please request a new one.", false);
            }
        } catch (Exception ex) {
            log.warn("Could not parse DB expiry '{}': {}", infoRecord.get().getOtpExpiryTime(), ex.getMessage());
        }

        // Constant-time compare HMAC of submitted OTP against stored HMAC
        String submittedHmac = computeHmacSha256(userSubmittedOtp != null ? userSubmittedOtp.trim() : "", hmacSecret);
        boolean isMatch = MessageDigest.isEqual(
                submittedHmac.getBytes(StandardCharsets.UTF_8),
                state.otpHmac().getBytes(StandardCharsets.UTF_8)
        );

        if (isMatch) {
            // Success: clear server-side OTP state and DB expiry
            otpSessionStore.remove(merchantId);
            merchantOtpDao.clearOtpExpiry(merchantId);
            auditService.logOtpVerifiedSuccess(merchantId, clientIp);
            return new OtpVerifyResult(true, null, false);
        } else {
            int newAttempts = state.attempts() + 1;
            int remaining = maxAttempts - newAttempts;

            if (newAttempts >= maxAttempts) {
                otpSessionStore.remove(merchantId);
                merchantOtpDao.clearOtpExpiry(merchantId);
                auditService.logOtpMaxAttemptsExceeded(merchantId, clientIp);
                return new OtpVerifyResult(false, "Maximum attempts exceeded. Please request a new OTP.", true);
            } else {
                otpSessionStore.put(merchantId, new ServerOtpState(state.otpHmac(), state.expiresAt(), newAttempts));
                auditService.logOtpVerificationFailed(merchantId, clientIp, remaining, "Invalid OTP digit match");
                return new OtpVerifyResult(false, "Invalid OTP code. " + remaining + " attempts remaining.", false);
            }
        }
    }

    /**
     * Clears any active OTP state for merchant.
     */
    public void clearOtpSession(Long merchantId) {
        otpSessionStore.remove(merchantId);
        merchantOtpDao.clearOtpExpiry(merchantId);
    }

    private String computeHmacSha256(String data, String key) {
        try {
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256Hmac.init(secretKey);
            byte[] hash = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA256", e);
        }
    }

    public record ServerOtpState(String otpHmac, Instant expiresAt, int attempts) {}
    public record OtpVerifyResult(boolean success, String message, boolean lockedOut) {}
}

