package com.mobiversa.merchant.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Audit Service recording security events without sensitive credentials.
 * Masks email and mobile numbers to prevent PII leakage.
 */
@Slf4j
@Service
public class AuditService {

    public void logPasswordResetRequested(String username, String ip, boolean userFound) {
        log.info("[AUDIT] Password reset OTP requested for user '{}' from IP '{}'. Account exists & active: {}",
                maskUsername(username), ip, userFound);
    }

    public void logOtpVerifiedSuccess(Long merchantId, String ip) {
        log.info("[AUDIT] OTP verification successful for merchantId={} from IP '{}'", merchantId, ip);
    }

    public void logOtpVerificationFailed(Long merchantId, String ip, int attemptsLeft, String reason) {
        log.warn("[AUDIT] OTP verification failed for merchantId={} from IP '{}'. Reason: {}, attempts left: {}",
                merchantId, ip, reason, attemptsLeft);
    }

    public void logOtpMaxAttemptsExceeded(Long merchantId, String ip) {
        log.warn("[AUDIT] Maximum OTP verification attempts exceeded for merchantId={} from IP '{}'. Locked out.",
                merchantId, ip);
    }

    public void logPasswordResetSuccess(Long merchantId, String username, String ip) {
        log.info("[AUDIT] Password reset completed successfully for merchantId={}, username='{}' from IP '{}'",
                merchantId, maskUsername(username), ip);
    }

    public void logPasswordResetFailure(String reason, String ip) {
        log.warn("[AUDIT] Password reset attempt failed from IP '{}'. Reason: {}", ip, reason);
    }

    public void logPasswordChangedEmailSent(Long merchantId, String email) {
        log.info("[AUDIT] Password changed notification dispatched to merchantId={} email='{}'",
                merchantId, maskEmail(email));
    }

    public static String maskUsername(String username) {
        if (username == null || username.length() < 3) return "***";
        return username.substring(0, 2) + "***" + username.substring(username.length() - 1);
    }

    public static String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***@***";
        String[] parts = email.split("@", 2);
        String name = parts[0];
        String domain = parts[1];
        String maskedName = name.length() > 2 ? name.substring(0, 2) + "***" : "***";
        return maskedName + "@" + domain;
    }

    public static String maskMobile(String mobile) {
        if (mobile == null || mobile.length() < 4) return "****";
        return mobile.substring(0, Math.min(3, mobile.length())) + "****" + mobile.substring(mobile.length() - 2);
    }
}

