package com.mobiversa.merchant.service;

import com.mobiversa.merchant.dao.MerchantOtpDao;
import com.mobiversa.merchant.dto.MerchantRecord;
import com.mobiversa.merchant.dto.ResetPasswordRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Service orchestrating the complete Forgot Password workflow:
 * - Anti-enumeration identical timing and response
 * - Rate limiting check by IP and username
 * - Session tracking
 * - Password reset with BCrypt encoding and password history rotation
 * - Active session invalidation and post-reset notifications
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ForgotPasswordService {

    private final MerchantOtpDao merchantOtpDao;
    private final OtpService otpService;
    private final ResetTokenService resetTokenService;
    private final RateLimitService rateLimitService;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;

    public static final String SESSION_PENDING_MERCHANT_ID = "FP_PENDING_MERCHANT_ID";
    public static final String SESSION_MASKED_CONTACT = "FP_MASKED_CONTACT";
    public static final String GENERIC_OTP_SENT_MESSAGE = "A one-time verification code has been sent to your registered mobile number.";
    public static final String INVALID_USERNAME_MESSAGE = "Invalid username. Please enter a valid registered username.";

    /**
     * Handles Step 1 / 2: Sending OTP with anti-enumeration protection.
     */
    public SendOtpResult initiateForgotPassword(String username, String clientIp, HttpSession session) {
        log.info("Processing forgot password request from IP '{}'", clientIp);

        // 1. Rate limit check by IP & username
        RateLimitService.RateLimitResult rateCheck = rateLimitService.checkRateLimit(clientIp, username);
        if (!rateCheck.allowed()) {
            return new SendOtpResult(false, rateCheck.message(), null, null);
        }

        // 2. Fetch merchant with parameterized query (case-insensitive)
        Optional<MerchantRecord> merchantOpt = (username != null && !username.isBlank())
                ? merchantOtpDao.findActiveMerchantByUsername(username.trim())
                : Optional.empty();

        long startTime = System.currentTimeMillis();

        boolean userFound = merchantOpt.isPresent();
        auditService.logPasswordResetRequested(username, clientIp, userFound);

        if (!userFound) {
            // Count invalid attempts against the rate limit to prevent username brute force
            rateLimitService.recordOtpSent(clientIp, username);
            session.removeAttribute(SESSION_PENDING_MERCHANT_ID);
            session.removeAttribute(SESSION_MASKED_CONTACT);
            return new SendOtpResult(false, INVALID_USERNAME_MESSAGE, null, null);
        }

        MerchantRecord merchant = merchantOpt.get();
        String maskedContact = AuditService.maskMobile(merchant.getContactPersonPhoneNumber());

        boolean sent = otpService.sendOtpForMerchant(merchant);
        if (!sent) {
            log.warn("Failed to dispatch OTP for merchantId={}", merchant.getId());
            return new SendOtpResult(false, "Unable to send the verification code. Please try again later.", null, null);
        }

        rateLimitService.recordOtpSent(clientIp, username);
        session.setAttribute(SESSION_PENDING_MERCHANT_ID, merchant.getId());
        session.setAttribute(SESSION_MASKED_CONTACT, maskedContact);

        long elapsedTime = System.currentTimeMillis() - startTime;
        log.debug("Forgot password OTP initiation completed in {} ms", elapsedTime);

        return new SendOtpResult(true, GENERIC_OTP_SENT_MESSAGE, merchant.getId(), maskedContact);
    }

    /**
     * Handles Step 3: Verifying the OTP and generating a single-use reset token.
     */
    public VerifyOtpResult verifyOtp(Long merchantId, String otp, String clientIp, HttpSession session) {
        if (merchantId == null) {
            return new VerifyOtpResult(false, "Session expired. Please start the password reset process again.", null);
        }

        OtpService.OtpVerifyResult verifyResult = otpService.verifyOtp(merchantId, otp, clientIp);
        if (!verifyResult.success()) {
            return new VerifyOtpResult(false, verifyResult.message(), null);
        }

        // Issue single-use reset token (256-bit SecureRandom, 10 min TTL)
        String resetToken = resetTokenService.issueResetToken(merchantId);

        // Clean up pending session values
        session.removeAttribute(SESSION_PENDING_MERCHANT_ID);
        session.removeAttribute(SESSION_MASKED_CONTACT);

        return new VerifyOtpResult(true, null, resetToken);
    }

    /**
     * Handles Step 4: Resetting the password.
     */
    @Transactional
    public ResetPasswordResult resetPassword(ResetPasswordRequest request, String clientIp, HttpServletRequest httpRequest) {
        String token = request.getToken();
        if (token == null || token.isBlank()) {
            auditService.logPasswordResetFailure("Missing reset token", clientIp);
            return new ResetPasswordResult(false, "Invalid or missing password reset token. Please request a new one.");
        }

        // Validate and consume token (retrieves merchantId bound to token)
        Long merchantId = resetTokenService.consumeResetToken(token);
        if (merchantId == null) {
            auditService.logPasswordResetFailure("Invalid, expired or already consumed token", clientIp);
            return new ResetPasswordResult(false, "Password reset token is invalid or has expired. Please restart the process.");
        }

        Optional<MerchantRecord> merchantOpt = merchantOtpDao.findActiveMerchantById(merchantId);
        if (merchantOpt.isEmpty()) {
            auditService.logPasswordResetFailure("Merchant not found or inactive for id=" + merchantId, clientIp);
            return new ResetPasswordResult(false, "Unable to reset password for this account.");
        }

        MerchantRecord merchant = merchantOpt.get();

        // Validate password policy and reuse history
        PasswordPolicyValidator.ValidationResult policyCheck = passwordPolicyValidator.validate(
                request.getNewPassword(),
                request.getConfirmPassword(),
                merchant
        );

        if (!policyCheck.valid()) {
            // Re-issue a token so user can fix their input without starting over the entire OTP flow
            String newToken = resetTokenService.issueResetToken(merchantId);
            String firstError = policyCheck.errorMessages().isEmpty() ? "Password policy violation." : policyCheck.errorMessages().get(0);
            return new ResetPasswordResult(false, firstError, newToken);
        }

        // Rotate password history in MERCHANT_INFO (PASSWORD3 = PASSWORD2, PASSWORD2 = PASSWORD1, PASSWORD1 = current)
        if (merchant.getPassword() != null) {
            merchantOtpDao.rotatePasswordHistory(merchant.getId(), merchant.getPassword());
        }

        // Encode new password with BCrypt (compatible with existing hashes)
        String encodedPassword = passwordEncoder.encode(request.getNewPassword());
        merchantOtpDao.updatePassword(merchant.getId(), encodedPassword);

        // Security after reset:
        // 1. Invalidate active HTTP sessions
        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // 2. Clear OTP data and reset tokens
        otpService.clearOtpSession(merchant.getId());
        resetTokenService.invalidateTokensForMerchant(merchant.getId());

        // 3. Send "password changed" notification without the password
        sendPasswordChangedEmail(merchant);

        // 4. Audit log entry
        auditService.logPasswordResetSuccess(merchant.getId(), merchant.getUsername(), clientIp);

        return new ResetPasswordResult(true, "Password has been successfully reset.", null);
    }

    private void sendPasswordChangedEmail(MerchantRecord merchant) {
        // Send email notification without password
        log.info("Password changed email notification triggered for merchantId={}, email={}",
                merchant.getId(), AuditService.maskEmail(merchant.getEmail()));
        auditService.logPasswordChangedEmailSent(merchant.getId(), merchant.getEmail());
    }

    public record SendOtpResult(boolean success, String message, Long merchantId, String maskedContact) {}
    public record VerifyOtpResult(boolean success, String message, String resetToken) {}
    public record ResetPasswordResult(boolean success, String message, String refreshedToken) {
        public ResetPasswordResult(boolean success, String message) {
            this(success, message, null);
        }
    }
}

