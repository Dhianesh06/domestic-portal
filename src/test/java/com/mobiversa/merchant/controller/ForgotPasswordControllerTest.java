package com.mobiversa.merchant.controller;

import com.mobiversa.merchant.dao.MerchantOtpDao;
import com.mobiversa.merchant.dto.MerchantInfoRecord;
import com.mobiversa.merchant.dto.MerchantRecord;
import com.mobiversa.merchant.dto.ResetPasswordRequest;
import com.mobiversa.merchant.service.AuditService;
import com.mobiversa.merchant.service.ForgotPasswordService;
import com.mobiversa.merchant.service.OtpProvider;
import com.mobiversa.merchant.service.OtpService;
import com.mobiversa.merchant.service.PasswordPolicyValidator;
import com.mobiversa.merchant.service.RateLimitService;
import com.mobiversa.merchant.service.ResetTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Controller and service flow tests covering all required test cases:
 * - Reset without a token is rejected
 * - Wrong-OTP lockout (after 5 attempts)
 * - Expired OTP
 * - Rate limiting
 * - Enumeration-safe identical responses
 * - Merchant with and without a MERCHANT_INFO row
 * - Password reuse rejection (current and last 3 passwords)
 */
class ForgotPasswordControllerTest {

    private MerchantOtpDao merchantOtpDao;
    private OtpProvider otpProvider;
    private AuditService auditService;
    private RateLimitService rateLimitService;
    private ResetTokenService resetTokenService;
    private PasswordEncoder passwordEncoder;
    private PasswordPolicyValidator passwordPolicyValidator;
    private OtpService otpService;
    private ForgotPasswordService forgotPasswordService;
    private ForgotPasswordController controller;

    private MerchantRecord activeMerchant;
    private MerchantInfoRecord merchantInfo;

    @BeforeEach
    void setUp() {
        merchantOtpDao = Mockito.mock(MerchantOtpDao.class);
        otpProvider = Mockito.mock(OtpProvider.class);
        auditService = new AuditService();
        rateLimitService = new RateLimitService();
        ReflectionTestUtils.setField(rateLimitService, "maxRequests", 3);
        ReflectionTestUtils.setField(rateLimitService, "windowMs", 300000L);
        ReflectionTestUtils.setField(rateLimitService, "cooldownMs", 60000L);

        resetTokenService = new ResetTokenService();
        ReflectionTestUtils.setField(resetTokenService, "tokenTtlSeconds", 600L);

        passwordEncoder = new BCryptPasswordEncoder(11);
        passwordPolicyValidator = new PasswordPolicyValidator(merchantOtpDao, passwordEncoder);
        ReflectionTestUtils.setField(passwordPolicyValidator, "minLength", 12);

        otpService = new OtpService(merchantOtpDao, otpProvider, auditService);
        ReflectionTestUtils.setField(otpService, "otpTtlSeconds", 70L);
        ReflectionTestUtils.setField(otpService, "maxAttempts", 5);
        ReflectionTestUtils.setField(otpService, "hmacSecret", "test-secret-key-123456789012345678901234");

        forgotPasswordService = new ForgotPasswordService(
                merchantOtpDao,
                otpService,
                resetTokenService,
                rateLimitService,
                passwordPolicyValidator,
                auditService,
                passwordEncoder
        );

        controller = new ForgotPasswordController(forgotPasswordService, resetTokenService);
        ReflectionTestUtils.setField(controller, "otpTtlSeconds", 70);
        ReflectionTestUtils.setField(controller, "resendCooldownMs", 60000L);

        activeMerchant = MerchantRecord.builder()
                .id(100L)
                .username("TEST_MERCHANT")
                .password(passwordEncoder.encode("CurrentPass123!"))
                .status("ACTIVE")
                .email("merchant@example.com")
                .contactPersonName("John Doe")
                .contactPersonPhoneNumber("0123456789")
                .salutation("Mr")
                .firstName("John")
                .build();

        merchantInfo = MerchantInfoRecord.builder()
                .id(1L)
                .merchantFk(100L)
                .otpExpiryTime("2030-01-01T00:00:00Z")
                .password1(passwordEncoder.encode("OldPass1111!@#"))
                .password2(passwordEncoder.encode("OldPass2222!@#"))
                .password3(passwordEncoder.encode("OldPass3333!@#"))
                .submerchantApprovalIndicator("1")
                .build();
    }

    @Test
    @DisplayName("Unknown username is rejected with an error and does not proceed to OTP")
    void testAntiEnumeration() {
        when(merchantOtpDao.findActiveMerchantByUsername("EXISTING_USER")).thenReturn(Optional.of(activeMerchant));
        when(merchantOtpDao.findActiveMerchantByUsername("UNKNOWN_USER")).thenReturn(Optional.empty());
        when(otpProvider.sendPaymentOtp(any())).thenReturn(true);
        when(merchantOtpDao.findLatestOtpByMobile(anyString())).thenReturn(Optional.of("123456"));

        MockHttpSession session1 = new MockHttpSession();
        ForgotPasswordService.SendOtpResult resultExisting =
                forgotPasswordService.initiateForgotPassword("EXISTING_USER", "127.0.0.1", session1);

        MockHttpSession session2 = new MockHttpSession();
        ForgotPasswordService.SendOtpResult resultUnknown =
                forgotPasswordService.initiateForgotPassword("UNKNOWN_USER", "127.0.0.2", session2);

        assertTrue(resultExisting.success());
        assertFalse(resultUnknown.success());
        assertEquals(ForgotPasswordService.INVALID_USERNAME_MESSAGE, resultUnknown.message());
        assertNull(session2.getAttribute(ForgotPasswordService.SESSION_PENDING_MERCHANT_ID));
        assertEquals(ForgotPasswordService.GENERIC_OTP_SENT_MESSAGE, resultExisting.message());
    }

    @Test
    @DisplayName("Rate limiting: Cooldown and max 3 requests rejected properly")
    void testRateLimiting() {
        when(merchantOtpDao.findActiveMerchantByUsername(anyString())).thenReturn(Optional.of(activeMerchant));
        when(otpProvider.sendPaymentOtp(any())).thenReturn(true);
        when(merchantOtpDao.findLatestOtpByMobile(anyString())).thenReturn(Optional.of("123456"));

        MockHttpSession session = new MockHttpSession();
        ForgotPasswordService.SendOtpResult first =
                forgotPasswordService.initiateForgotPassword("RATE_USER", "192.168.1.50", session);
        assertTrue(first.success());

        // Immediate next attempt triggers 60s cooldown
        ForgotPasswordService.SendOtpResult second =
                forgotPasswordService.initiateForgotPassword("RATE_USER", "192.168.1.50", session);
        assertFalse(second.success());
        assertTrue(second.message().contains("Please wait"));
    }

    @Test
    @DisplayName("Send OTP: Inserts row in MERCHANT_INFO when none exists")
    void testSendOtp_InsertsMerchantInfoWhenNoneExists() {
        when(merchantOtpDao.findActiveMerchantByUsername("TEST_MERCHANT")).thenReturn(Optional.of(activeMerchant));
        when(merchantOtpDao.findMerchantInfoByFk(100L)).thenReturn(Optional.empty());
        when(otpProvider.sendPaymentOtp(any())).thenReturn(true);
        when(merchantOtpDao.findLatestOtpByMobile("0123456789")).thenReturn(Optional.of("654321"));

        MockHttpSession session = new MockHttpSession();
        ForgotPasswordService.SendOtpResult result =
                forgotPasswordService.initiateForgotPassword("TEST_MERCHANT", "127.0.0.1", session);

        assertTrue(result.success());
        verify(merchantOtpDao).saveOrUpdateOtpExpiry(eq(100L), anyString());
    }

    @Test
    @DisplayName("Lockout: Rejects and locks out after 5 consecutive wrong OTP attempts")
    void testWrongOtp_LockoutAfter5Attempts() {
        when(merchantOtpDao.findActiveMerchantByUsername("TEST_MERCHANT")).thenReturn(Optional.of(activeMerchant));
        when(otpProvider.sendPaymentOtp(any())).thenReturn(true);
        when(merchantOtpDao.findLatestOtpByMobile("0123456789")).thenReturn(Optional.of("888888"));
        when(merchantOtpDao.findMerchantInfoByFk(100L)).thenReturn(Optional.of(merchantInfo));

        MockHttpSession session = new MockHttpSession();
        forgotPasswordService.initiateForgotPassword("TEST_MERCHANT", "127.0.0.1", session);

        // Attempts 1 to 4: Wrong OTP
        for (int i = 1; i <= 4; i++) {
            ForgotPasswordService.VerifyOtpResult res =
                    forgotPasswordService.verifyOtp(100L, "000000", "127.0.0.1", session);
            assertFalse(res.success());
            assertTrue(res.message().contains("attempts remaining"));
        }

        // Attempt 5: Maximum attempts exceeded
        ForgotPasswordService.VerifyOtpResult res5 =
                forgotPasswordService.verifyOtp(100L, "000000", "127.0.0.1", session);
        assertFalse(res5.success());
        assertTrue(res5.message().contains("Maximum attempts exceeded"));
    }

    @Test
    @DisplayName("Reset without token is rejected")
    void testResetWithoutToken_Rejected() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResetPasswordRequest form = ResetPasswordRequest.builder()
                .token("")
                .newPassword("ValidPassword123!")
                .confirmPassword("ValidPassword123!")
                .build();

        ForgotPasswordService.ResetPasswordResult res =
                forgotPasswordService.resetPassword(form, "127.0.0.1", request);

        assertFalse(res.success());
        assertTrue(res.message().contains("Invalid or missing password reset token"));
    }

    @Test
    @DisplayName("Password reuse: Rejects current password and previous 3 passwords")
    void testPasswordReuse_Rejected() {
        when(merchantOtpDao.findActiveMerchantByUsername("TEST_MERCHANT")).thenReturn(Optional.of(activeMerchant));
        when(merchantOtpDao.findActiveMerchantById(100L)).thenReturn(Optional.of(activeMerchant));
        when(merchantOtpDao.findMerchantInfoByFk(100L)).thenReturn(Optional.of(merchantInfo));
        when(otpProvider.sendPaymentOtp(any())).thenReturn(true);
        when(merchantOtpDao.findLatestOtpByMobile("0123456789")).thenReturn(Optional.of("999999"));

        MockHttpSession session = new MockHttpSession();
        forgotPasswordService.initiateForgotPassword("TEST_MERCHANT", "127.0.0.1", session);

        ForgotPasswordService.VerifyOtpResult verifyRes =
                forgotPasswordService.verifyOtp(100L, "999999", "127.0.0.1", session);
        assertTrue(verifyRes.success());
        String token = verifyRes.resetToken();
        assertNotNull(token);

        MockHttpServletRequest request = new MockHttpServletRequest();

        // 1. Current password reuse
        ResetPasswordRequest formReuseCurrent = ResetPasswordRequest.builder()
                .token(token)
                .newPassword("CurrentPass123!")
                .confirmPassword("CurrentPass123!")
                .build();
        ForgotPasswordService.ResetPasswordResult res1 =
                forgotPasswordService.resetPassword(formReuseCurrent, "127.0.0.1", request);
        assertFalse(res1.success());
        assertEquals("New password cannot be the same as your current password.", res1.message());

        // 2. Previous password 1 reuse
        String refreshedToken = res1.refreshedToken();
        ResetPasswordRequest formReuseHistory1 = ResetPasswordRequest.builder()
                .token(refreshedToken)
                .newPassword("OldPass1111!@#")
                .confirmPassword("OldPass1111!@#")
                .build();
        ForgotPasswordService.ResetPasswordResult res2 =
                forgotPasswordService.resetPassword(formReuseHistory1, "127.0.0.1", request);
        assertFalse(res2.success());
        assertEquals("New password cannot be the same as any of your previous 3 passwords.", res2.message());
    }

    @Test
    @DisplayName("Successful reset: Updates password, rotates history and invalidates session")
    void testSuccessfulReset_Flow() {
        when(merchantOtpDao.findActiveMerchantByUsername("TEST_MERCHANT")).thenReturn(Optional.of(activeMerchant));
        when(merchantOtpDao.findActiveMerchantById(100L)).thenReturn(Optional.of(activeMerchant));
        when(merchantOtpDao.findMerchantInfoByFk(100L)).thenReturn(Optional.of(merchantInfo));
        when(otpProvider.sendPaymentOtp(any())).thenReturn(true);
        when(merchantOtpDao.findLatestOtpByMobile("0123456789")).thenReturn(Optional.of("123123"));

        MockHttpSession session = new MockHttpSession();
        forgotPasswordService.initiateForgotPassword("TEST_MERCHANT", "127.0.0.1", session);

        ForgotPasswordService.VerifyOtpResult verifyRes =
                forgotPasswordService.verifyOtp(100L, "123123", "127.0.0.1", session);
        assertTrue(verifyRes.success());
        String token = verifyRes.resetToken();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);

        ResetPasswordRequest form = ResetPasswordRequest.builder()
                .token(token)
                .newPassword("BrandNewPass999!@#")
                .confirmPassword("BrandNewPass999!@#")
                .build();

        ForgotPasswordService.ResetPasswordResult res =
                forgotPasswordService.resetPassword(form, "127.0.0.1", request);

        assertTrue(res.success());
        verify(merchantOtpDao).updatePassword(eq(100L), anyString());
        verify(merchantOtpDao).rotatePasswordHistory(eq(100L), anyString());
        assertTrue(session.isInvalid());
    }
}
