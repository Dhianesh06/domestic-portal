package com.mobiversa.merchant.service;

import com.mobiversa.merchant.dto.ExternalPaymentOtpRequest;

/**
 * Interface hiding the external payment OTP API call so it can be easily mocked in tests.
 */
public interface OtpProvider {
    /**
     * Sends OTP request to the external payment OTP gateway.
     *
     * @param request OTP request payload
     * @return true if responseCode is "0000", false otherwise
     */
    boolean sendPaymentOtp(ExternalPaymentOtpRequest request);
}

