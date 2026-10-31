package com.mobiversa.merchant.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mobiversa.merchant.dto.ExternalPaymentOtpRequest;
import com.mobiversa.merchant.dto.ExternalPaymentOtpResponse;
import com.mobiversa.merchant.service.OtpProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * OtpProvider that POSTs a JSON request to PAYMENT_API_URL using HttpURLConnection.
 * Enforces:
 * - 5-second connect & read timeout
 * - Standard HTTPS certificate validation (default JVM truststore)
 * - Disabled HTTP redirects
 */
@Slf4j
@Service
public class HttpPaymentOtpProvider implements OtpProvider {

    private static final int TIMEOUT_MS = 5000;
    private static final String SUCCESS_CODE = "0000";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String paymentApiUrl;

    public HttpPaymentOtpProvider(
            @Value("${payment.api.url:${PAYMENT_API_URL:https://api.mobiversa.com/payment/otp}}") String paymentApiUrl) {
        this.paymentApiUrl = paymentApiUrl;
    }

    @Override
    public boolean sendPaymentOtp(ExternalPaymentOtpRequest request) {
        log.info("Sending payment OTP request for username: {}", request.getUsername());

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(paymentApiUrl).openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false);
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");

            byte[] payload = objectMapper.writeValueAsBytes(request);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload);
                os.flush();
            }

            int status = conn.getResponseCode();
            if (status < 200 || status >= 300) {
                log.warn("Payment OTP API returned HTTP status: {}", status);
                return false;
            }

            String output = readBody(conn.getInputStream());
            ExternalPaymentOtpResponse body;
            try {
                body = objectMapper.readValue(output, ExternalPaymentOtpResponse.class);
            } catch (IOException e) {
                log.warn("Payment OTP API returned an unparseable response: {}", e.getMessage());
                return false;
            }

            if (body == null) {
                log.warn("Payment OTP API returned an empty response");
                return false;
            }

            log.info("Payment OTP API responseCode: {}", body.getResponseCode());
            return SUCCESS_CODE.equals(body.getResponseCode());
        } catch (Exception e) {
            log.error("Failed to call payment OTP API at {}: {}", paymentApiUrl, e.getMessage(), e);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static String readBody(InputStream in) throws IOException {
        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }
}
