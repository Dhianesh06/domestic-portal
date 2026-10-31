package com.mobiversa.merchant.controller;

import com.mobiversa.merchant.dto.ForgotPasswordRequest;
import com.mobiversa.merchant.dto.ResetPasswordRequest;
import com.mobiversa.merchant.dto.VerifyOtpRequest;
import com.mobiversa.merchant.service.ForgotPasswordService;
import com.mobiversa.merchant.service.ResetTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@Controller
@RequestMapping("/v1/forgot-password")
@RequiredArgsConstructor
public class ForgotPasswordController {

    private final ForgotPasswordService forgotPasswordService;
    private final ResetTokenService resetTokenService;

    @Value("${otp.ttl-seconds:70}")
    private int otpTtlSeconds;

    @Value("${otp.rate-limit.cooldown-ms:60000}")
    private long resendCooldownMs;

    /**
     * 1. GET /v1/forgot-password - Displays the username entry form.
     */
    @GetMapping
    public String showForgotPasswordForm(Model model) {
        if (!model.containsAttribute("forgotPasswordRequest")) {
            model.addAttribute("forgotPasswordRequest", new ForgotPasswordRequest());
        }
        return "forgot-password";
    }

    /**
     * 2. POST /v1/forgot-password/send-otp - Sends payment OTP, updates DB expiry, redirects to verify.
     */
    @PostMapping("/send-otp")
    public String sendOtp(
            @Valid @ModelAttribute("forgotPasswordRequest") ForgotPasswordRequest request,
            BindingResult bindingResult,
            HttpServletRequest httpRequest,
            HttpSession session,
            RedirectAttributes redirectAttributes,
            Model model) {

        if (bindingResult.hasErrors()) {
            return "forgot-password";
        }

        String clientIp = getClientIp(httpRequest);
        ForgotPasswordService.SendOtpResult result =
                forgotPasswordService.initiateForgotPassword(request.getUsername(), clientIp, session);

        if (!result.success()) {
            model.addAttribute("errorMessage", result.message());
            return "forgot-password";
        }

        redirectAttributes.addFlashAttribute("infoMessage", result.message());
        return "redirect:/v1/forgot-password/verify-otp";
    }

    /**
     * GET /v1/forgot-password/verify-otp - Renders the OTP verification screen.
     */
    @GetMapping("/verify-otp")
    public String showVerifyOtpForm(HttpSession session, Model model) {
        Long merchantId = (Long) session.getAttribute(ForgotPasswordService.SESSION_PENDING_MERCHANT_ID);
        String maskedContact = (String) session.getAttribute(ForgotPasswordService.SESSION_MASKED_CONTACT);

        if (merchantId == null) {
            // Either unknown user or session expired; provide generic verify screen or redirect
            model.addAttribute("maskedContact", "your registered phone");
        } else {
            model.addAttribute("maskedContact", maskedContact != null ? maskedContact : "your registered phone");
        }

        if (!model.containsAttribute("verifyOtpRequest")) {
            model.addAttribute("verifyOtpRequest", new VerifyOtpRequest());
        }

        model.addAttribute("otpTtlSeconds", otpTtlSeconds);
        model.addAttribute("resendCooldownSeconds", resendCooldownMs / 1000);

        return "verify-otp";
    }

    /**
     * 3. POST /v1/forgot-password/verify-otp - Verifies OTP and redirects to reset screen with token.
     */
    @PostMapping("/verify-otp")
    public String verifyOtp(
            @Valid @ModelAttribute("verifyOtpRequest") VerifyOtpRequest request,
            BindingResult bindingResult,
            HttpServletRequest httpRequest,
            HttpSession session,
            RedirectAttributes redirectAttributes,
            Model model) {

        if (bindingResult.hasErrors()) {
            model.addAttribute("otpTtlSeconds", otpTtlSeconds);
            model.addAttribute("resendCooldownSeconds", resendCooldownMs / 1000);
            return "verify-otp";
        }

        Long merchantId = (Long) session.getAttribute(ForgotPasswordService.SESSION_PENDING_MERCHANT_ID);
        String clientIp = getClientIp(httpRequest);

        ForgotPasswordService.VerifyOtpResult result =
                forgotPasswordService.verifyOtp(merchantId, request.getOtp(), clientIp, session);

        if (!result.success()) {
            model.addAttribute("errorMessage", result.message());
            model.addAttribute("otpTtlSeconds", otpTtlSeconds);
            model.addAttribute("resendCooldownSeconds", resendCooldownMs / 1000);
            return "verify-otp";
        }

        // On success, redirect to reset-password form with the issued single-use token
        redirectAttributes.addAttribute("token", result.resetToken());
        return "redirect:/v1/forgot-password/reset";
    }

    /**
     * GET /v1/forgot-password/reset - Renders the reset password form.
     */
    @GetMapping("/reset")
    public String showResetPasswordForm(@RequestParam(value = "token", required = false) String token, Model model) {
        if (token == null || !resetTokenService.isTokenValid(token)) {
            model.addAttribute("errorMessage", "Invalid, expired, or missing password reset link.");
            return "forgot-password";
        }

        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken(token);
        model.addAttribute("resetPasswordRequest", request);
        return "reset-password";
    }

    /**
     * 4. POST /v1/forgot-password/reset - Validates token, applies policy & rotates history.
     */
    @PostMapping("/reset")
    public String resetPassword(
            @Valid @ModelAttribute("resetPasswordRequest") ResetPasswordRequest request,
            BindingResult bindingResult,
            HttpServletRequest httpRequest,
            Model model,
            RedirectAttributes redirectAttributes) {

        if (bindingResult.hasErrors()) {
            return "reset-password";
        }

        String clientIp = getClientIp(httpRequest);
        ForgotPasswordService.ResetPasswordResult result =
                forgotPasswordService.resetPassword(request, clientIp, httpRequest);

        if (!result.success()) {
            model.addAttribute("errorMessage", result.message());
            if (result.refreshedToken() != null) {
                request.setToken(result.refreshedToken());
            }
            return "reset-password";
        }

        redirectAttributes.addFlashAttribute("successMessage", "Password has been successfully updated. Please log in.");
        return "redirect:/v1/forgot-password/success";
    }

    /**
     * GET /v1/forgot-password/success - Displays password reset success page.
     */
    @GetMapping("/success")
    public String showSuccessPage() {
        return "reset-success";
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isBlank() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}

